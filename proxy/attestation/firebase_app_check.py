"""Firebase App Check: verify a customer's App Check token (RS256 JWT signed by Firebase)."""
from __future__ import annotations

import jwt

from .config import AttestationError, KeyConfig

FIREBASE_JWKS_URL = "https://firebaseappcheck.googleapis.com/v1/jwks"
FIREBASE_ISSUER_PREFIX = "https://firebaseappcheck.googleapis.com/"


def platform_from_app_id(app_id: str) -> str:
    """Firebase app IDs look like '1:1234567890:ios:abc123'."""
    parts = app_id.split(":")
    return parts[2] if len(parts) >= 4 and parts[2] in ("ios", "android", "web") else "unknown"


class FirebaseAppCheckVerifier:
    def __init__(self, jwks_client: jwt.PyJWKClient | None = None):
        # PyJWKClient caches the key set; Firebase rotates keys, so don't pin them.
        self._jwks = jwks_client or jwt.PyJWKClient(FIREBASE_JWKS_URL, cache_keys=True, lifespan=3600)

    def verify(self, *, token: str, key: KeyConfig) -> str:
        """Return the verified Firebase app ID."""
        if not key.firebase_project_number:
            raise AttestationError("firebase_not_configured", status=400)
        project = key.firebase_project_number
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or header.get("typ") != "JWT":
                raise AttestationError("firebase_token_invalid", "unexpected header")
            signing_key = self._jwks.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token, signing_key.key, algorithms=["RS256"],
                audience=f"projects/{project}",
                issuer=f"{FIREBASE_ISSUER_PREFIX}{project}",
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except AttestationError:
            raise
        except jwt.PyJWTError as exc:
            raise AttestationError("firebase_token_invalid", str(exc)) from exc
        if claims["sub"] not in key.firebase_app_ids:
            raise AttestationError("firebase_token_invalid", "Firebase app not allowed for this key")
        return claims["sub"]
