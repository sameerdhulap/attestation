"""Service settings and per-key attestation configuration."""

from __future__ import annotations

import base64
import binascii
import json
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class AttestationError(Exception):
    """Raised when a proof or token fails verification.

    `code` is machine-readable and safe to return to clients; `detail` is for logs.
    """

    def __init__(self, code: str, detail: str = "", status: int = 401):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail
        self.status = status


class Mode(str, Enum):
    OFF = "off"
    MONITOR = "monitor"
    ENFORCE = "enforce"


def normalize_fingerprint(value: str) -> str:
    """Return a SHA-256 fingerprint as lowercase hex.

    Accepts colon-separated hex (keytool / Play Console style), plain hex, or the
    base64url digest that Play Integrity returns in `certificateSha256Digest`.
    """
    cleaned = value.strip().replace(":", "")
    if len(cleaned) == 64:
        try:
            bytes.fromhex(cleaned)
            return cleaned.lower()
        except ValueError:
            pass
    try:
        raw = base64.urlsafe_b64decode(cleaned + "=" * (-len(cleaned) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"Unrecognized fingerprint format: {value!r}") from exc
    if len(raw) != 32:
        raise ValueError(f"Fingerprint is not a SHA-256 digest: {value!r}")
    return raw.hex()


@dataclass(frozen=True)
class KeyConfig:
    """Attestation settings for one Woosmap mobile API key."""

    api_key: str
    project_id: str
    mode: Mode = Mode.OFF
    # iOS: App IDs in the form "TEAMID.bundle.identifier"
    ios_app_ids: tuple[str, ...] = ()
    # iOS bundle IDs allowed when the team ID is supplied per request instead
    ios_bundle_ids: tuple[str, ...] = ()
    ios_allow_development: bool = False
    # Android
    android_packages: tuple[str, ...] = ()
    android_cert_sha256: tuple[str, ...] = ()
    android_min_device_level: str = "device"  # "device" or "strong"
    android_require_licensed: bool = False
    # Firebase App Check
    firebase_project_number: str | None = None
    firebase_app_ids: tuple[str, ...] = ()
    # Woosmap token lifetime
    token_ttl_seconds: int = 1800

    def __post_init__(self) -> None:
        if not 300 <= self.token_ttl_seconds <= 3600:
            raise ValueError("token_ttl_seconds must be between 300 and 3600")
        if self.android_min_device_level not in ("device", "strong"):
            raise ValueError("android_min_device_level must be 'device' or 'strong'")
        object.__setattr__(
            self,
            "android_cert_sha256",
            tuple(normalize_fingerprint(f) for f in self.android_cert_sha256),
        )

    @property
    def allowed_apps(self) -> frozenset[str]:
        """Every app identifier a token for this key may carry."""
        bundle_ids = {app_id.split(".", 1)[1] for app_id in self.ios_app_ids}
        bundle_ids |= set(self.ios_bundle_ids)
        return frozenset(
            bundle_ids | set(self.android_packages) | set(self.firebase_app_ids)
        )

    @classmethod
    def from_dict(cls, data: dict) -> "KeyConfig":
        data = dict(data)
        data["mode"] = Mode(data.get("mode", "off"))
        for name in (
            "ios_app_ids",
            "ios_bundle_ids",
            "android_packages",
            "android_cert_sha256",
            "firebase_app_ids",
        ):
            data[name] = tuple(data.get(name, ()))
        return cls(**data)


class KeyRegistry:
    """Lookup of key configs by API key. Back this with the Console's database in production."""

    def __init__(self, configs: list[KeyConfig] | None = None):
        self._by_key = {c.api_key: c for c in configs or []}

    def get(self, api_key: str | None) -> KeyConfig | None:
        return self._by_key.get(api_key) if api_key else None

    def add(self, config: KeyConfig) -> None:
        self._by_key[config.api_key] = config

    @classmethod
    def from_file(cls, path: str | Path) -> "KeyRegistry":
        entries = json.loads(Path(path).read_text())
        return cls([KeyConfig.from_dict(entry) for entry in entries])


@dataclass(frozen=True)
class Settings:
    issuer: str = "https://attest.woosmap.com"
    audience: str = "woosmap-api"
    challenge_ttl_seconds: int = 300
    signing_key_path: str | None = None
    signing_key_id: str = "dev-1"
    apple_root_ca_path: str | None = None
    keys_file: str | None = None
    google_credentials_path: str | None = None
    extra: dict = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            issuer=os.getenv("ATTEST_ISSUER", cls.issuer),
            audience=os.getenv("ATTEST_AUDIENCE", cls.audience),
            challenge_ttl_seconds=int(os.getenv("ATTEST_CHALLENGE_TTL", "300")),
            signing_key_path=os.getenv("ATTEST_SIGNING_KEY"),
            signing_key_id=os.getenv("ATTEST_SIGNING_KID", "dev-1"),
            apple_root_ca_path=os.getenv("ATTEST_APPLE_ROOT_CA"),
            keys_file=os.getenv("ATTEST_KEYS_FILE"),
            google_credentials_path=os.getenv("GOOGLE_APPLICATION_CREDENTIALS"),
        )
