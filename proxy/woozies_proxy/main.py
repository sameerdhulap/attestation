"""Woozies proxy: attests iOS and Android apps, then forwards Woosmap API calls.

The app proves it's genuine (App Attest, a debug token in the simulator, or
Firebase App Check for apps that use it), receives a short-lived app token, and
calls a Woosmap API path here, such as `GET /localities/nearby`, with its Woosmap
key (X-Api-Key) and bundle ID (X-iOS-Identifier). The proxy checks the token and
that the path is in ALLOWED_APIS, drops any key or private_key query parameter,
and forwards the call with those two headers to https://api.woosmap.com/<path>.
The proxy holds no Woosmap key.

One proxy serves every app in IOS_BUNDLE_IDS and ANDROID_PACKAGES. App Attest
proofs are matched against each bundle ID; Android apps name their package in
X-Android-Identifier.

Run with:  uvicorn woozies_proxy.main:build_app --factory --reload
"""

from __future__ import annotations

import hashlib
import logging
import re
from contextlib import asynccontextmanager

import httpx
from cryptography import x509
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

from attestation.app_attest import AppAttestVerifier, load_apple_root
from attestation.config import AttestationError, KeyRegistry
from attestation.firebase_app_check import (
    FirebaseAppCheckVerifier,
    platform_from_app_id,
)
from attestation.gateway import AppTokenGate
from attestation.play_integrity import GooglePlayDecoder, PlayIntegrityVerifier
from attestation.store import ChallengeService, InMemoryStore
from attestation.tokens import (
    IssuedToken,
    TokenIssuer,
    TokenVerifier,
    load_or_generate_signing_key,
)

from .settings import ProxySettings

log = logging.getLogger("woozies_proxy")

CLIENT_HEADER = "X-Client-Id"
# Apple Team IDs are 10 uppercase letters or digits.
TEAM_ID_PATTERN = re.compile(r"[A-Z0-9]{10}")
# Query parameters never forwarded: the key travels only in the X-Api-Key header.
DROPPED_PARAMS = ("key", "private_key")
# App headers recorded in the logs for each forwarded call.
CAPTURED_HEADERS = (
    "x-client-id",
    "x-ios-identifier",
    "x-android-identifier",
    "x-app-version",
    "user-agent",
)
FORWARDED_HEADERS = ("accept-language", "content-type")
# Headers Woosmap uses to check the key's app restriction; the app sends one platform's set.
PLATFORM_HEADERS = ("x-ios-identifier", "x-android-identifier", "x-android-fingerprint")


class IosRegisterBody(BaseModel):
    key_id: str
    attestation: str
    challenge: str


class IosTokenBody(BaseModel):
    key_id: str
    assertion: str
    challenge: str


class DebugTokenBody(BaseModel):
    debug_token: str


class FirebaseTokenBody(BaseModel):
    app_check_token: str


class AndroidTokenBody(BaseModel):
    integrity_token: str
    challenge: str


def _bundle_id(app_id: str) -> str:
    """The bundle ID part of an App Attest App ID ("TEAMID.bundle.id")."""
    return app_id.split(".", 1)[1]


def _token_body(issued: IssuedToken) -> dict:
    return {
        "token": issued.token,
        "token_type": "woosmap-app-token",
        "expires_in": issued.expires_in,
    }


def create_app(
    settings: ProxySettings,
    *,
    apple_root: x509.Certificate | None = None,
    upstream_transport: httpx.AsyncBaseTransport | None = None,
    firebase_verifier: FirebaseAppCheckVerifier | None = None,
    play_integrity: PlayIntegrityVerifier | None = None,
) -> FastAPI:
    key = settings.key_config()
    registry = KeyRegistry([key])
    store = InMemoryStore()
    challenges = ChallengeService(store)
    issuer = TokenIssuer(
        load_or_generate_signing_key(settings.signing_key_path),
        settings.signing_key_id,
        settings.issuer,
        settings.audience,
    )
    gate = AppTokenGate(
        TokenVerifier.from_jwks(issuer.public_jwks(), issuer.issuer, issuer.audience),
        registry,
        store,
        client_header=CLIENT_HEADER,
    )

    if apple_root is None and settings.apple_root_ca_path:
        apple_root = load_apple_root(settings.apple_root_ca_path)
    app_attest = AppAttestVerifier(apple_root) if apple_root else None
    if app_attest is None:
        log.warning("App Attest disabled: add Apple's root CA to certs/")

    if firebase_verifier is None and settings.firebase_project_number:
        firebase_verifier = FirebaseAppCheckVerifier()
    if play_integrity is None and settings.play_integrity_credentials:
        play_integrity = PlayIntegrityVerifier(
            GooglePlayDecoder(settings.play_integrity_credentials)
        )
    if play_integrity is None:
        log.warning("Play Integrity disabled: set PLAY_INTEGRITY_CREDENTIALS")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.upstream = httpx.AsyncClient(
            base_url=settings.woosmap_api_base,
            timeout=settings.upstream_timeout_seconds,
            transport=upstream_transport,
        )
        yield
        await app.state.upstream.aclose()

    app = FastAPI(title="Woozies attestation proxy", version="0.1.0", lifespan=lifespan)

    def client_for(client_id: str | None):
        found = registry.get(client_id)
        if found is None:
            raise AttestationError("unknown_client", status=403)
        return found

    @app.exception_handler(AttestationError)
    async def _attestation_error(_: Request, err: AttestationError):
        log.info("attestation_error code=%s detail=%s", err.code, err.detail)
        return JSONResponse(status_code=err.status, content={"error": err.code})

    # Attestation ---------------------------------------------------------------
    @app.post("/attest/challenge")
    def challenge(x_client_id: str = Header(...)):
        client_for(x_client_id)
        value, ttl = challenges.issue(x_client_id)
        return {"challenge": value, "expires_in": ttl}

    @app.post("/attest/ios/register")
    def ios_register(
        body: IosRegisterBody,
        x_client_id: str = Header(...),
        x_apple_team_id: str | None = Header(None),
    ):
        cfg = client_for(x_client_id)
        if app_attest is None:
            raise AttestationError("app_attest_not_configured", status=503)
        # The app sends its Team ID; the attestation must match TEAMID.<one of IOS_BUNDLE_IDS>.
        if not x_apple_team_id:
            raise AttestationError("apple_team_id_missing", status=400)
        if not TEAM_ID_PATTERN.fullmatch(x_apple_team_id):
            raise AttestationError("apple_team_id_invalid", status=400)
        challenges.consume(body.challenge, x_client_id)
        record = app_attest.verify_attestation(
            key_id=body.key_id,
            attestation_b64=body.attestation,
            client_data=body.challenge.encode(),
            api_key=x_client_id,
            allowed_app_ids=tuple(
                f"{x_apple_team_id}.{bundle_id}" for bundle_id in settings.ios_bundle_ids
            ),
            allow_development=cfg.ios_allow_development,
        )
        store.save_ios_key(record)
        log.info(
            "ios_registered key_id=%s app=%s env=%s",
            record.key_id,
            record.app_id,
            record.environment,
        )
        return _token_body(
            issuer.issue(
                key=cfg,
                app=_bundle_id(record.app_id),
                platform="ios",
                method="app_attest",
                subject=record.key_id,
            )
        )

    @app.post("/attest/ios/token")
    def ios_token(body: IosTokenBody, x_client_id: str = Header(...)):
        cfg = client_for(x_client_id)
        if app_attest is None:
            raise AttestationError("app_attest_not_configured", status=503)
        challenges.consume(body.challenge, x_client_id)
        record = store.get_ios_key(body.key_id)
        if record is None or record.api_key != x_client_id:
            raise AttestationError("app_attest_unknown_key", "register the key first")
        new_count = app_attest.verify_assertion(
            record=record,
            assertion_b64=body.assertion,
            client_data=body.challenge.encode(),
        )
        store.update_sign_count(record.key_id, record.sign_count, new_count)
        return _token_body(
            issuer.issue(
                key=cfg,
                app=_bundle_id(record.app_id),
                platform="ios",
                method="app_attest",
                subject=record.key_id,
            )
        )

    @app.post("/attest/debug/token")
    def debug_token(
        body: DebugTokenBody,
        x_client_id: str = Header(...),
        x_ios_identifier: str | None = Header(None),
        x_android_identifier: str | None = Header(None),
    ):
        """Simulator and CI only. Disabled unless ATTEST_DEBUG_TOKENS is set."""
        cfg = client_for(x_client_id)
        if body.debug_token not in settings.debug_tokens:
            raise AttestationError("debug_token_invalid")
        # The app names itself with its platform header; without one, the first iOS app.
        if x_android_identifier:
            app_id, platform = x_android_identifier, "android"
        else:
            app_id, platform = x_ios_identifier or settings.ios_bundle_ids[0], "ios"
        if app_id not in cfg.allowed_apps:
            raise AttestationError("app_not_allowed", app_id, status=403)
        log.warning(
            "debug token used client=%s app=%s (development only)", x_client_id, app_id
        )
        subject = "debug-" + hashlib.sha256(body.debug_token.encode()).hexdigest()[:12]
        return _token_body(
            issuer.issue(
                key=cfg,
                app=app_id,
                platform=platform,
                method="debug",
                subject=subject,
            )
        )

    @app.post("/attest/firebase/token")
    def firebase_token(body: FirebaseTokenBody, x_client_id: str = Header(...)):
        """Optional path for apps that use Firebase App Check (the Woozies app does not)."""
        cfg = client_for(x_client_id)
        if firebase_verifier is None:
            raise AttestationError("firebase_not_configured", status=503)
        app_id = firebase_verifier.verify(token=body.app_check_token, key=cfg)
        return _token_body(
            issuer.issue(
                key=cfg,
                app=app_id,
                platform=platform_from_app_id(app_id),
                method="firebase_app_check",
                subject=app_id,
            )
        )

    @app.post("/attest/android/token")
    def android_token(
        body: AndroidTokenBody,
        x_client_id: str = Header(...),
        x_android_identifier: str | None = Header(None),
    ):
        """Android: the app requests a Play Integrity token with the challenge as its nonce.

        The app names its package in X-Android-Identifier; Google decodes the token
        for that package, and the verdict must match it.
        """
        cfg = client_for(x_client_id)
        if play_integrity is None:
            raise AttestationError("play_integrity_not_configured", status=503)
        if not x_android_identifier:
            raise AttestationError("app_identifier_missing", status=400)
        challenges.consume(body.challenge, x_client_id)
        level = play_integrity.verify(
            token=body.integrity_token,
            challenge=body.challenge,
            package=x_android_identifier,
            key=cfg,
        )
        subject = (
            "android-" + hashlib.sha256(body.integrity_token.encode()).hexdigest()[:12]
        )
        log.info(
            "android_verified app=%s sub=%s level=%s", x_android_identifier, subject, level
        )
        return _token_body(
            issuer.issue(
                key=cfg,
                app=x_android_identifier,
                platform="android",
                method="play_integrity",
                subject=subject,
                level=level,
            )
        )

    @app.get("/.well-known/jwks.json")
    def jwks():
        return issuer.public_jwks()

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "app_attest": app_attest is not None,
            "firebase": firebase_verifier is not None,
            "play_integrity": play_integrity is not None,
            "debug_tokens": bool(settings.debug_tokens),
            "mode": key.mode.value,
        }

    # Woosmap proxy ----------------------------------------------------------------
    # Registered last so the attestation routes above take precedence.
    @app.api_route("/{api_path:path}", methods=["GET", "POST"])
    async def woosmap_api(api_path: str, request: Request):
        decision = gate.evaluate(request.headers)
        captured = {
            h: request.headers.get(h)
            for h in CAPTURED_HEADERS
            if request.headers.get(h)
        }
        if not decision.allowed:
            log.info(
                "api rejected path=%s code=%s headers=%s",
                api_path,
                decision.error_code,
                captured,
            )
            return JSONResponse(status_code=401, content={"error": decision.error_code})
        # Exact match only, so "..", extra segments or other products never get through.
        if api_path.strip("/") not in settings.allowed_apis:
            log.info("api not allowed path=%s", api_path)
            return JSONResponse(status_code=404, content={"error": "api_not_allowed"})

        params = [
            (name, value)
            for name, value in request.query_params.multi_items()
            if name not in DROPPED_PARAMS
        ]
        dropped = sorted(
            {n for n, _ in request.query_params.multi_items()} & set(DROPPED_PARAMS)
        )
        # The app sends its own Woosmap key and bundle ID; only attested apps get this far.
        app_key = request.headers.get("x-api-key")
        if not app_key:
            return JSONResponse(
                status_code=400, content={"error": "woosmap_key_missing"}
            )
        if not (
            request.headers.get("x-ios-identifier")
            or request.headers.get("x-android-identifier")
        ):
            return JSONResponse(
                status_code=400, content={"error": "app_identifier_missing"}
            )
        headers = {"X-Api-Key": app_key}
        headers.update(
            {h: request.headers[h] for h in PLATFORM_HEADERS if request.headers.get(h)}
        )
        headers.update(
            {h: request.headers[h] for h in FORWARDED_HEADERS if h in request.headers}
        )

        claims = decision.claims or {}
        log.info(
            "api forward %s path=%s status=%s att=%s sub=%s params=%s dropped=%s headers=%s",
            request.method,
            api_path,
            decision.status,
            claims.get("att"),
            claims.get("sub"),
            params,
            dropped,
            captured,
        )
        try:
            upstream = await request.app.state.upstream.request(
                request.method,
                "/" + api_path.strip("/"),
                params=params,
                headers=headers,
                content=await request.body() if request.method == "POST" else None,
            )
        except httpx.HTTPError as exc:
            log.error("upstream error: %s", exc)
            return JSONResponse(
                status_code=502, content={"error": "upstream_unavailable"}
            )

        if upstream.status_code in (401, 403):
            # A Woosmap auth error means the proxy's key is wrong or restricted; don't
            # let the app confuse it with its own token being rejected.
            log.error(
                "upstream auth failed %s: %s", upstream.status_code, upstream.text[:200]
            )
            return JSONResponse(
                status_code=502, content={"error": "upstream_auth_failed"}
            )

        passthrough = {
            k: v
            for k, v in upstream.headers.items()
            if k.lower() in ("content-type", "cache-control")
        }
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers=passthrough,
        )

    return app


def build_app() -> FastAPI:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    return create_app(ProxySettings.from_env())
