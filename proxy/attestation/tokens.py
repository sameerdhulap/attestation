"""Woosmap app tokens: short-lived ES256 JWTs issued after a successful attestation."""
from __future__ import annotations

import json
import logging
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .config import AttestationError, KeyConfig

log = logging.getLogger(__name__)

ALGORITHM = "ES256"


def load_or_generate_signing_key(path: str | None) -> ec.EllipticCurvePrivateKey:
    """Load a P-256 private key from PEM, or generate a throwaway one for development.

    In production, keep the key in a KMS/HSM and sign through it instead.
    """
    if path:
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
            raise ValueError("Signing key must be an EC P-256 private key")
        return key
    log.warning("No ATTEST_SIGNING_KEY set: generating an ephemeral signing key (dev only)")
    return ec.generate_private_key(ec.SECP256R1())


@dataclass(frozen=True)
class IssuedToken:
    token: str
    expires_in: int
    claims: dict


class TokenIssuer:
    def __init__(self, private_key: ec.EllipticCurvePrivateKey, kid: str,
                 issuer: str, audience: str, clock: Callable[[], float] = time.time):
        self._key = private_key
        self.kid = kid
        self.issuer = issuer
        self.audience = audience
        self._clock = clock

    def issue(self, *, key: KeyConfig, app: str, platform: str, method: str,
              subject: str, level: str = "device") -> IssuedToken:
        now = int(self._clock())
        claims = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": subject,
            "wk": key.api_key,
            "prj": key.project_id,
            "app": app,
            "plt": platform,
            "att": method,
            "lvl": level,
            "iat": now,
            "exp": now + key.token_ttl_seconds,
            "jti": secrets.token_hex(12),
        }
        token = jwt.encode(claims, self._key, algorithm=ALGORITHM, headers={"kid": self.kid})
        return IssuedToken(token=token, expires_in=key.token_ttl_seconds, claims=claims)

    def public_jwks(self) -> dict:
        jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(self._key.public_key()))
        jwk.update({"kid": self.kid, "use": "sig", "alg": ALGORITHM})
        return {"keys": [jwk]}


class TokenVerifier:
    """Verifies Woosmap app tokens locally against cached public keys (by `kid`).

    The gateway would refresh `keys` from the published JWKS on a timer, keeping
    old keys until their tokens have expired.
    """

    def __init__(self, keys: dict[str, ec.EllipticCurvePublicKey], issuer: str,
                 audience: str, leeway_seconds: int = 60):
        self._keys = dict(keys)
        self._issuer = issuer
        self._audience = audience
        self._leeway = leeway_seconds

    @classmethod
    def from_jwks(cls, jwks: dict, issuer: str, audience: str, **kw) -> "TokenVerifier":
        keys = {k["kid"]: jwt.algorithms.ECAlgorithm.from_jwk(json.dumps(k)) for k in jwks["keys"]}
        return cls(keys, issuer, audience, **kw)

    def verify(self, token: str) -> dict:
        try:
            kid = jwt.get_unverified_header(token).get("kid")
        except jwt.PyJWTError as exc:
            raise AttestationError("app_token_invalid", f"bad header: {exc}") from exc
        key = self._keys.get(kid)
        if key is None:
            raise AttestationError("app_token_invalid", f"unknown kid {kid!r}")
        try:
            return jwt.decode(
                token, key, algorithms=[ALGORITHM], issuer=self._issuer,
                audience=self._audience, leeway=self._leeway,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "wk", "app"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise AttestationError("app_token_expired") from exc
        except jwt.PyJWTError as exc:
            raise AttestationError("app_token_invalid", str(exc)) from exc
