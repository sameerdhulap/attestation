"""Google Play Integrity: verify an Android app's integrity token.

Integrity tokens are encrypted with keys Google manages, so the server sends each
token to Google's decodeIntegrityToken API and checks the verdict it gets back.
"""

from __future__ import annotations

import time
from collections.abc import Callable

import httpx

from .config import AttestationError, KeyConfig, normalize_fingerprint

DECODE_URL = "https://playintegrity.googleapis.com/v1/{package}:decodeIntegrityToken"
SCOPE = "https://www.googleapis.com/auth/playintegrity"
# How old a verdict may be. The challenge is single-use, so this only bounds replay of a fresh one.
MAX_AGE_SECONDS = 300

# (package name, integrity token) -> tokenPayloadExternal
Decoder = Callable[[str, str], dict]


class GooglePlayDecoder:
    """Decodes tokens with Google's API, authenticated as a service account with Play Integrity access."""

    def __init__(self, credentials_path: str, timeout: float = 10.0):
        from google.oauth2 import (
            service_account,
        )  # optional dependency, only needed in production

        self._credentials = service_account.Credentials.from_service_account_file(
            credentials_path, scopes=[SCOPE]
        )
        self._timeout = timeout

    def __call__(self, package: str, token: str) -> dict:
        from google.auth.transport.requests import Request

        if not self._credentials.valid:
            self._credentials.refresh(Request())
        try:
            resp = httpx.post(
                DECODE_URL.format(package=package),
                json={"integrity_token": token},
                headers={"Authorization": f"Bearer {self._credentials.token}"},
                timeout=self._timeout,
            )
        except httpx.HTTPError as exc:
            raise AttestationError(
                "play_integrity_unavailable", str(exc), status=503
            ) from exc
        if resp.status_code != 200:
            raise AttestationError("play_integrity_invalid", resp.text[:200])
        return resp.json()["tokenPayloadExternal"]


class PlayIntegrityVerifier:
    def __init__(self, decoder: Decoder, clock: Callable[[], float] = time.time):
        self._decode = decoder
        self._clock = clock

    def verify(
        self, *, token: str, challenge: str, package: str, key: KeyConfig
    ) -> str:
        """Check the verdict for `package` and return the device level: "device" or "strong"."""
        if package not in key.android_packages:
            raise AttestationError(
                "play_integrity_wrong_app", f"{package} not allowed for this key"
            )
        verdict = self._decode(package, token)
        request = verdict.get("requestDetails", {})
        app = verdict.get("appIntegrity", {})

        if request.get("nonce") != challenge:
            raise AttestationError("play_integrity_nonce_mismatch")
        if (
            request.get("requestPackageName") != package
            or app.get("packageName") != package
        ):
            raise AttestationError("play_integrity_wrong_app", "package name mismatch")
        age = self._clock() - int(request.get("timestampMillis", 0)) / 1000
        if age > MAX_AGE_SECONDS:
            raise AttestationError("play_integrity_stale", f"verdict is {age:.0f}s old")
        if app.get("appRecognitionVerdict") != "PLAY_RECOGNIZED":
            raise AttestationError(
                "play_integrity_app_not_recognized",
                app.get("appRecognitionVerdict", ""),
            )
        if key.android_cert_sha256 and not self._cert_allowed(app, key):
            raise AttestationError("play_integrity_wrong_cert")

        device = verdict.get("deviceIntegrity", {}).get("deviceRecognitionVerdict", [])
        level = "strong" if "MEETS_STRONG_INTEGRITY" in device else "device"
        if "MEETS_DEVICE_INTEGRITY" not in device or (
            key.android_min_device_level == "strong" and level != "strong"
        ):
            raise AttestationError("play_integrity_device_failed", ",".join(device))
        if (
            key.android_require_licensed
            and verdict.get("accountDetails", {}).get("appLicensingVerdict")
            != "LICENSED"
        ):
            raise AttestationError("play_integrity_unlicensed")
        return level

    @staticmethod
    def _cert_allowed(app: dict, key: KeyConfig) -> bool:
        for digest in app.get("certificateSha256Digest", []):
            try:
                if normalize_fingerprint(digest) in key.android_cert_sha256:
                    return True
            except ValueError:
                continue
        return False
