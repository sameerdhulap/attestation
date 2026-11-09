"""App tokens: short-lived ES256 JWTs issued after a successful attestation."""
from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import jwt
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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


class KeySealer:
    """Encrypts the app's Woosmap key into its app token (AES-256-GCM).

    The token's payload is only base64, so a plain claim would be readable by
    anyone holding the token. Each sealed key is bound to its token's `jti`.
    """

    NONCE_BYTES = 12

    def __init__(self, secret: bytes):
        if len(secret) != 32:
            raise ValueError("Key encryption secret must be 32 bytes")
        self._aead = AESGCM(secret)

    @classmethod
    def from_setting(cls, value: str | None) -> "KeySealer":
        """Build from a base64 (or base64url) 32-byte secret, or generate a throwaway one."""
        if not value:
            log.warning(
                "No ATTEST_ENCRYPTION_KEY set: generating an ephemeral key (dev only)"
            )
            return cls(AESGCM.generate_key(bit_length=256))
        normalized = value.strip().replace("-", "+").replace("_", "/")
        try:
            secret = base64.b64decode(normalized + "=" * (-len(normalized) % 4), validate=True)
        except binascii.Error as exc:
            raise ValueError("ATTEST_ENCRYPTION_KEY must be base64") from exc
        return cls(secret)

    def seal(self, value: str, token_id: str) -> str:
        nonce = os.urandom(self.NONCE_BYTES)
        sealed = nonce + self._aead.encrypt(nonce, value.encode(), token_id.encode())
        return base64.urlsafe_b64encode(sealed).rstrip(b"=").decode()

    def open(self, sealed: str, token_id: str) -> str:
        try:
            raw = base64.urlsafe_b64decode(sealed + "=" * (-len(sealed) % 4))
            nonce, ciphertext = raw[: self.NONCE_BYTES], raw[self.NONCE_BYTES :]
            return self._aead.decrypt(nonce, ciphertext, token_id.encode()).decode()
        except (InvalidTag, ValueError) as exc:
            raise AttestationError("app_token_invalid", "sealed key unreadable") from exc


@dataclass(frozen=True)
class IssuedToken:
    token: str
    expires_in: int
    claims: dict


class TokenIssuer:
    def __init__(self, private_key: ec.EllipticCurvePrivateKey, kid: str,
                 issuer: str, audience: str, clock: Callable[[], float] = time.time,
                 sealer: KeySealer | None = None):
        self._key = private_key
        self.kid = kid
        self.issuer = issuer
        self.audience = audience
        self._clock = clock
        self._sealer = sealer

    def issue(self, *, key: KeyConfig, app: str, platform: str, method: str,
              subject: str, level: str = "device",
              woosmap_key: str | None = None) -> IssuedToken:
        """Sign an app token; `woosmap_key`, if given, travels sealed in the `ek` claim."""
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
        if woosmap_key:
            if self._sealer is None:
                raise ValueError("A KeySealer is needed to put a Woosmap key in a token")
            claims["ek"] = self._sealer.seal(woosmap_key, claims["jti"])
        token = jwt.encode(claims, self._key, algorithm=ALGORITHM, headers={"kid": self.kid})
        return IssuedToken(token=token, expires_in=key.token_ttl_seconds, claims=claims)

    def public_jwks(self) -> dict:
        jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(self._key.public_key()))
        jwk.update({"kid": self.kid, "use": "sig", "alg": ALGORITHM})
        return {"keys": [jwk]}


class TokenVerifier:
    """Verifies app tokens locally against cached public keys (by `kid`).

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
