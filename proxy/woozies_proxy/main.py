"""Woozies proxy: attests the iOS app, then forwards Localities calls to Woosmap.

The app proves it's genuine (App Attest, a debug token in the simulator, or
Firebase App Check for apps that use it), receives a short-lived app token, and
calls `GET /localities/nearby` here with its Woosmap key (X-Api-Key) and bundle ID
(X-iOS-Identifier). The proxy checks the token, keeps only the allowed query
parameters, and forwards the call with those two headers to
https://api.woosmap.com/localities/nearby. The proxy holds no Woosmap key.

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
# Only these query parameters reach Woosmap; anything else (including a key or
# private_key query parameter) is dropped. The key travels in the X-Api-Key header.
NEARBY_PARAMS = ("types", "location", "radius", "page", "limit", "excluded_types")
# App headers recorded in the logs for each forwarded call.
CAPTURED_HEADERS = ("x-client-id", "x-ios-identifier", "x-app-version", "user-agent")
FORWARDED_HEADERS = ("accept-language",)


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
        # The app sends its Team ID; the attestation must match TEAMID.<configured bundle ID>.
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
            allowed_app_ids=(f"{x_apple_team_id}.{settings.ios_bundle_id}",),
            allow_development=cfg.ios_allow_development,
        )
        store.save_ios_key(record)
        log.info("ios_registered key_id=%s env=%s", record.key_id, record.environment)
        return _token_body(
            issuer.issue(
                key=cfg,
                app=settings.ios_bundle_id,
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
                app=settings.ios_bundle_id,
                platform="ios",
                method="app_attest",
                subject=record.key_id,
            )
        )

    @app.post("/attest/debug/token")
    def debug_token(body: DebugTokenBody, x_client_id: str = Header(...)):
        """Simulator and CI only. Disabled unless ATTEST_DEBUG_TOKENS is set."""
        cfg = client_for(x_client_id)
        if body.debug_token not in settings.debug_tokens:
            raise AttestationError("debug_token_invalid")
        log.warning("debug token used client=%s (development only)", x_client_id)
        subject = "debug-" + hashlib.sha256(body.debug_token.encode()).hexdigest()[:12]
        return _token_body(
            issuer.issue(
                key=cfg,
                app=settings.ios_bundle_id,
                platform="ios",
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

    @app.get("/.well-known/jwks.json")
    def jwks():
        return issuer.public_jwks()

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "app_attest": app_attest is not None,
            "firebase": firebase_verifier is not None,
            "debug_tokens": bool(settings.debug_tokens),
            "mode": key.mode.value,
        }

    # Localities proxy -------------------------------------------------------------
    @app.get("/localities/nearby")
    async def localities_nearby(request: Request):
        decision = gate.evaluate(request.headers)
        captured = {
            h: request.headers.get(h)
            for h in CAPTURED_HEADERS
            if request.headers.get(h)
        }
        if not decision.allowed:
            log.info(
                "nearby rejected code=%s headers=%s", decision.error_code, captured
            )
            return JSONResponse(status_code=401, content={"error": decision.error_code})

        params = [
            (name, value)
            for name, value in request.query_params.multi_items()
            if name in NEARBY_PARAMS
        ]
        dropped = sorted(
            {n for n, _ in request.query_params.multi_items()} - set(NEARBY_PARAMS)
        )
        # The app sends its own Woosmap key and bundle ID; only attested apps get this far.
        app_key = request.headers.get("x-api-key")
        ios_identifier = request.headers.get("x-ios-identifier")
        if not app_key:
            return JSONResponse(
                status_code=400, content={"error": "woosmap_key_missing"}
            )
        if not ios_identifier:
            return JSONResponse(
                status_code=400, content={"error": "ios_identifier_missing"}
            )
        headers = {"X-Api-Key": app_key, "X-iOS-Identifier": ios_identifier}
        headers.update(
            {h: request.headers[h] for h in FORWARDED_HEADERS if h in request.headers}
        )

        claims = decision.claims or {}
        log.info(
            "nearby forward status=%s att=%s sub=%s params=%s dropped=%s headers=%s",
            decision.status,
            claims.get("att"),
            claims.get("sub"),
            params,
            dropped,
            captured,
        )
        try:
            upstream = await request.app.state.upstream.get(
                "/localities/nearby", params=params, headers=headers
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
