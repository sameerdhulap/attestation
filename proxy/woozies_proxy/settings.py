"""Proxy settings, read from environment variables (and `.env` if present)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from attestation.config import KeyConfig, Mode

PROXY_ROOT = Path(__file__).resolve().parent.parent
# Woosmap API paths the proxy serves unless ALLOWED_APIS overrides them.
DEFAULT_ALLOWED_APIS = (
    "localities/autocomplete",
    "localities/details",
    "localities/geocode",
    "localities/nearby",
)


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader: KEY=VALUE lines, no overriding of real environment variables."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        os.environ.setdefault(name.strip(), value.strip().strip('"').strip("'"))


def _csv(value: str | None) -> tuple[str, ...]:
    return tuple(v.strip() for v in (value or "").split(",") if v.strip())


def _bool(value: str | None, default: bool = False) -> bool:
    return (
        default
        if value is None
        else value.strip().lower() in ("1", "true", "yes", "on")
    )


@dataclass(frozen=True)
class ProxySettings:
    woosmap_api_base: str = "https://api.woosmap.com"
    client_id: str = "woozies-ios"
    ios_bundle_id: str = "com.woosmap.app.woozies"
    ios_allow_development: bool = True
    attest_mode: Mode = Mode.ENFORCE
    apple_root_ca_path: str | None = None
    signing_key_path: str | None = None
    signing_key_id: str = "woozies-1"
    issuer: str = "https://woozies-proxy.local"
    audience: str = "woozies-proxy"
    token_ttl_seconds: int = 1800
    debug_tokens: tuple[str, ...] = ()
    firebase_project_number: str | None = None
    firebase_app_ids: tuple[str, ...] = ()
    upstream_timeout_seconds: float = 10.0
    allowed_apis: tuple[str, ...] = DEFAULT_ALLOWED_APIS
    extra: dict = field(default_factory=dict)

    def key_config(self) -> KeyConfig:
        """The attestation rules for the one client this proxy serves."""
        return KeyConfig(
            api_key=self.client_id,
            project_id=self.client_id,
            mode=self.attest_mode,
            ios_bundle_ids=(self.ios_bundle_id,),
            ios_allow_development=self.ios_allow_development,
            firebase_project_number=self.firebase_project_number,
            firebase_app_ids=self.firebase_app_ids,
            token_ttl_seconds=self.token_ttl_seconds,
        )

    @classmethod
    def from_env(cls, env_file: Path | None = PROXY_ROOT / ".env") -> "ProxySettings":
        if env_file:
            _load_dotenv(env_file)
        default_root = PROXY_ROOT / "certs" / "Apple_App_Attestation_Root_CA.pem"
        return cls(
            woosmap_api_base=os.getenv("WOOSMAP_API_BASE", cls.woosmap_api_base),
            client_id=os.getenv("CLIENT_ID", cls.client_id),
            ios_bundle_id=os.getenv("IOS_BUNDLE_ID", cls.ios_bundle_id),
            ios_allow_development=_bool(os.getenv("IOS_ALLOW_DEVELOPMENT"), True),
            attest_mode=Mode(os.getenv("ATTEST_MODE", "enforce")),
            apple_root_ca_path=os.getenv("APPLE_ROOT_CA_PATH")
            or (str(default_root) if default_root.exists() else None),
            signing_key_path=os.getenv("ATTEST_SIGNING_KEY") or None,
            signing_key_id=os.getenv("ATTEST_SIGNING_KID", cls.signing_key_id),
            token_ttl_seconds=int(os.getenv("TOKEN_TTL_SECONDS", "1800")),
            debug_tokens=_csv(os.getenv("ATTEST_DEBUG_TOKENS")),
            firebase_project_number=os.getenv("FIREBASE_PROJECT_NUMBER") or None,
            firebase_app_ids=_csv(os.getenv("FIREBASE_APP_IDS")),
            allowed_apis=tuple(p.strip("/") for p in _csv(os.getenv("ALLOWED_APIS")))
            or DEFAULT_ALLOWED_APIS,
        )
