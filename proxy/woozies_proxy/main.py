"""Woozies proxy: attests iOS and Android apps, then forwards Woosmap API calls.

The app proves it's genuine (App Attest, a debug token in the simulator, or
Firebase App Check for apps that use it), receives a short-lived app token, and
calls a Woosmap API path here, such as `GET /localities/nearby`, with its bundle
ID (X-iOS-Identifier). The app sends its Woosmap key (X-Api-Key) only while it
attests; the proxy seals it, encrypted, inside the app token. On each call the
proxy checks the token and that the path is in ALLOWED_APIS, drops any key or
private_key query parameter, and forwards the call with the key from the token
and the bundle ID to https://api.woosmap.com/<path>. An X-Api-Key header on an
API call is never used. The proxy holds no Woosmap key.

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
from fastapi import FastAPI, Header, Request, Security
from fastapi.responses import JSONResponse, Response
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

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
    KeySealer,
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


# OpenAPI text, shown in /redoc and /docs ----------------------------------------
API_DESCRIPTION = """
Lets genuine mobile apps call Woosmap APIs without the Woosmap key travelling on each call.

**How an app uses it**

1. `POST /attest/challenge` for a one-time challenge (valid 5 minutes, single use).
2. Prove the app is genuine with that challenge: App Attest (`/attest/ios/register`,
   then `/attest/ios/token` to refresh), Play Integrity (`/attest/android/token`) or
   Firebase App Check (`/attest/firebase/token`). Send the Woosmap key as `X-Api-Key`
   on this call only.
3. The proxy returns an **app token**. Send it as `X-App-Token` on every Woosmap API
   call until it expires (`expires_in`, 30 minutes by default); refresh at about 80%.
4. Call a Woosmap API path here, such as `GET /localities/nearby`. The proxy checks
   the token and forwards the call to `https://api.woosmap.com` with the Woosmap key
   taken from the token.

On a `401` whose code starts with `app_token_`, get a new token and retry once.
Errors are JSON: `{"error": "<code>"}`.

# Authentication

<!-- ReDoc-Inject: <security-definitions> -->
"""
APP_TOKEN_DOC = """
The app token returned by an `/attest/*` endpoint. Required on every Woosmap API call.

It's a JWT signed by this proxy (ES256), valid 30 minutes by default. It carries the
client ID, the app (bundle ID or package), the platform, how the app was verified, a
device identifier, and the app's Woosmap key, encrypted (AES-256-GCM) so the token
can't be read for it. The proxy checks it locally, with no network call. It's never
sent to Woosmap.

Errors: `401 app_token_missing`, `app_token_invalid`, `app_token_expired` or
`app_token_revoked`. Get a new token and retry once.
"""
CLIENT_ID_DOC = "Identifies the app's client to this proxy (`CLIENT_ID`). Not a secret."
WOOSMAP_KEY_DOC = (
    "The app's Woosmap key. Sent only while attesting: the proxy seals it, encrypted, "
    "into the app token. Never read on Woosmap API calls."
)
IOS_ID_DOC = "The iOS bundle ID; must be in `IOS_BUNDLE_IDS`."
ANDROID_ID_DOC = "The Android package; must be in `ANDROID_PACKAGES`."
OPENAPI_TAGS = [
    {"name": "Attestation", "description": "Prove the app is genuine and get an app token."},
    {"name": "Woosmap API", "description": "Allow-listed Woosmap API paths, called with an app token."},
    {"name": "Operational", "description": "Health and token-verification keys."},
]

app_token_header = APIKeyHeader(
    name="X-App-Token", scheme_name="AppToken", description=APP_TOKEN_DOC, auto_error=False
)


class IosRegisterBody(BaseModel):
    key_id: str = Field(description="Key ID from `DCAppAttestService.generateKey()`.")
    attestation: str = Field(
        description="Base64 attestation from `attestKey`, over SHA-256 of `challenge`."
    )
    challenge: str = Field(description="The challenge from `/attest/challenge`.")


class IosTokenBody(BaseModel):
    key_id: str = Field(description="The key ID registered with `/attest/ios/register`.")
    assertion: str = Field(
        description="Base64 assertion from `generateAssertion`, over SHA-256 of `challenge`."
    )
    challenge: str = Field(description="A new challenge from `/attest/challenge`.")


class DebugTokenBody(BaseModel):
    debug_token: str = Field(description="A token listed in `ATTEST_DEBUG_TOKENS`.")


class FirebaseTokenBody(BaseModel):
    app_check_token: str = Field(description="A Firebase App Check token.")


class AndroidTokenBody(BaseModel):
    integrity_token: str = Field(
        description="Play Integrity token requested with `challenge` as its nonce."
    )
    challenge: str = Field(description="The challenge from `/attest/challenge`.")


class ChallengeResponse(BaseModel):
    challenge: str = Field(description="One-time challenge (base64url).")
    expires_in: int = Field(description="Seconds until the challenge expires.")


class AppTokenResponse(BaseModel):
    token: str = Field(description="The app token. Send it as `X-App-Token`.")
    token_type: str = Field(description='Always `"app-token"`.')
    expires_in: int = Field(description="Seconds until the token expires.")


def _bundle_id(app_id: str) -> str:
    """The bundle ID part of an App Attest App ID ("TEAMID.bundle.id")."""
    return app_id.split(".", 1)[1]


def _token_body(issued: IssuedToken) -> dict:
    return {
        "token": issued.token,
        "token_type": "app-token",
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
    sealer = KeySealer.from_setting(settings.key_encryption_key)
    issuer = TokenIssuer(
        load_or_generate_signing_key(settings.signing_key_path),
        settings.signing_key_id,
        settings.issuer,
        settings.audience,
        sealer=sealer,
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

    app = FastAPI(
        title="Woozies attestation proxy",
        version="0.1.0",
        description=API_DESCRIPTION,
        openapi_tags=OPENAPI_TAGS,
        lifespan=lifespan,
    )

    def client_for(client_id: str | None):
        found = registry.get(client_id)
        if found is None:
            raise AttestationError("unknown_client", status=403)
        return found

    def require_woosmap_key(x_api_key: str | None) -> None:
        """Every app token carries the app's key, so attestation needs X-Api-Key."""
        if not x_api_key:
            raise AttestationError("woosmap_key_missing", status=400)

    @app.exception_handler(AttestationError)
    async def _attestation_error(_: Request, err: AttestationError):
        log.info("attestation_error code=%s detail=%s", err.code, err.detail)
        return JSONResponse(status_code=err.status, content={"error": err.code})

    # Attestation ---------------------------------------------------------------
    @app.post(
        "/attest/challenge",
        tags=["Attestation"],
        summary="Get a one-time challenge",
        response_model=ChallengeResponse,
    )
    def challenge(x_client_id: str = Header(..., description=CLIENT_ID_DOC)):
        """Single use, valid 5 minutes, bound to the client. Prove the app with it next."""
        client_for(x_client_id)
        value, ttl = challenges.issue(x_client_id)
        return {"challenge": value, "expires_in": ttl}

    @app.post(
        "/attest/ios/register",
        tags=["Attestation"],
        summary="iOS: register an App Attest key",
        response_model=AppTokenResponse,
    )
    def ios_register(
        body: IosRegisterBody,
        x_client_id: str = Header(..., description=CLIENT_ID_DOC),
        x_apple_team_id: str | None = Header(
            None, description="Apple Team ID (10 characters) the app is signed with."
        ),
        x_api_key: str | None = Header(None, description=WOOSMAP_KEY_DOC),
    ):
        """First run on a device: verifies the attestation with Apple's root CA against
        `<X-Apple-Team-Id>.<bundle ID>` and stores the key for later refreshes."""
        cfg = client_for(x_client_id)
        require_woosmap_key(x_api_key)
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
                woosmap_key=x_api_key,
                app=_bundle_id(record.app_id),
                platform="ios",
                method="app_attest",
                subject=record.key_id,
            )
        )

    @app.post(
        "/attest/ios/token",
        tags=["Attestation"],
        summary="iOS: refresh with an App Attest assertion",
        response_model=AppTokenResponse,
    )
    def ios_token(
        body: IosTokenBody,
        x_client_id: str = Header(..., description=CLIENT_ID_DOC),
        x_api_key: str | None = Header(None, description=WOOSMAP_KEY_DOC),
    ):
        """Later runs: checks the assertion with the registered key. `401
        app_attest_unknown_key` means register again."""
        cfg = client_for(x_client_id)
        require_woosmap_key(x_api_key)
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
                woosmap_key=x_api_key,
                app=_bundle_id(record.app_id),
                platform="ios",
                method="app_attest",
                subject=record.key_id,
            )
        )

    @app.post(
        "/attest/debug/token",
        tags=["Attestation"],
        summary="Simulator and emulator: debug token",
        response_model=AppTokenResponse,
    )
    def debug_token(
        body: DebugTokenBody,
        x_client_id: str = Header(..., description=CLIENT_ID_DOC),
        x_ios_identifier: str | None = Header(None, description=IOS_ID_DOC),
        x_android_identifier: str | None = Header(None, description=ANDROID_ID_DOC),
        x_api_key: str | None = Header(None, description=WOOSMAP_KEY_DOC),
    ):
        """Simulator and CI only. Disabled unless ATTEST_DEBUG_TOKENS is set."""
        cfg = client_for(x_client_id)
        require_woosmap_key(x_api_key)
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
                woosmap_key=x_api_key,
                app=app_id,
                platform=platform,
                method="debug",
                subject=subject,
            )
        )

    @app.post(
        "/attest/firebase/token",
        tags=["Attestation"],
        summary="Firebase App Check",
        response_model=AppTokenResponse,
    )
    def firebase_token(
        body: FirebaseTokenBody,
        x_client_id: str = Header(..., description=CLIENT_ID_DOC),
        x_api_key: str | None = Header(None, description=WOOSMAP_KEY_DOC),
    ):
        """Optional path for apps that use Firebase App Check (the Woozies app does not)."""
        cfg = client_for(x_client_id)
        require_woosmap_key(x_api_key)
        if firebase_verifier is None:
            raise AttestationError("firebase_not_configured", status=503)
        app_id = firebase_verifier.verify(token=body.app_check_token, key=cfg)
        return _token_body(
            issuer.issue(
                key=cfg,
                woosmap_key=x_api_key,
                app=app_id,
                platform=platform_from_app_id(app_id),
                method="firebase_app_check",
                subject=app_id,
            )
        )

    @app.post(
        "/attest/android/token",
        tags=["Attestation"],
        summary="Android: Play Integrity",
        response_model=AppTokenResponse,
    )
    def android_token(
        body: AndroidTokenBody,
        x_client_id: str = Header(..., description=CLIENT_ID_DOC),
        x_android_identifier: str | None = Header(None, description=ANDROID_ID_DOC),
        x_api_key: str | None = Header(None, description=WOOSMAP_KEY_DOC),
    ):
        """Android: the app requests a Play Integrity token with the challenge as its nonce.

        The app names its package in X-Android-Identifier; Google decodes the token
        for that package, and the verdict must match it.
        """
        cfg = client_for(x_client_id)
        require_woosmap_key(x_api_key)
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
                woosmap_key=x_api_key,
                app=x_android_identifier,
                platform="android",
                method="play_integrity",
                subject=subject,
                level=level,
            )
        )

    @app.get("/.well-known/jwks.json", tags=["Operational"], summary="Token signing key")
    def jwks():
        """Public key (JWKS) that verifies app tokens."""
        return issuer.public_jwks()

    @app.get("/health", tags=["Operational"], summary="Health and configuration")
    def health():
        """Which verifiers are enabled, whether debug tokens are on, and the mode."""
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
    woosmap_route = dict(
        path="/{api_path:path}",
        tags=["Woosmap API"],
        summary="Call a Woosmap API",
        description=(
            "Forwards the call to `https://api.woosmap.com/{api_path}` with the Woosmap "
            "key from the app token. Allowed paths: "
            + ", ".join(f"`{path}`" for path in settings.allowed_apis)
            + ". Others get `404 api_not_allowed`.\n\n"
            "Send `X-Client-Id`, `X-App-Token`, and `X-iOS-Identifier` or "
            "`X-Android-Identifier` (with `X-Android-Fingerprint`). The query string and, "
            "for POST, the body are passed on; `key` and `private_key` parameters are "
            "dropped. Woosmap's status and JSON come back unchanged, except a Woosmap 401 "
            "or 403, which becomes `502 upstream_auth_failed`."
        ),
        dependencies=[Security(app_token_header)],
        # Read from the request in the handler, so declared here for the docs only.
        openapi_extra={
            "parameters": [
                {"name": name, "in": "header", "required": required,
                 "schema": {"type": "string"}, "description": doc}
                for name, required, doc in (
                    ("X-Client-Id", True, CLIENT_ID_DOC),
                    ("X-iOS-Identifier", False, "iOS apps: the bundle ID."),
                    ("X-Android-Identifier", False, "Android apps: the package."),
                    ("X-Android-Fingerprint", False,
                     "Android apps: SHA-1 of the signing certificate (`AA:BB:…`)."),
                )
            ]
        },
    )

    # GET and POST registered separately so each gets its own OpenAPI operation ID.
    @app.post(**woosmap_route, operation_id="woosmap_api_post")
    @app.get(**woosmap_route, operation_id="woosmap_api_get")
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
        # The app's Woosmap key comes only from its token, where it was sealed when the
        # app attested; an X-Api-Key header is never used.
        claims = decision.claims or {}
        sealed_key = claims.get("ek")
        if not sealed_key:
            return JSONResponse(
                status_code=400, content={"error": "woosmap_key_missing"}
            )
        app_key = sealer.open(sealed_key, claims.get("jti", ""))
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
