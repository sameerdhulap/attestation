"""Gateway-side check of app tokens, applied before a request is forwarded upstream.

Framework-free, so the same logic can run in a proxy, an API gateway or an edge function.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Mapping

from .config import AttestationError, KeyConfig, KeyRegistry, Mode
from .store import InMemoryStore
from .tokens import TokenVerifier

log = logging.getLogger(__name__)

HEADER_APP_TOKEN = "x-woosmap-app-token"


@dataclass(frozen=True)
class GatewayDecision:
    allowed: bool
    status: str               # "verified", "unverified" or "rejected"
    error_code: str | None = None
    claims: dict | None = None


class AppTokenGate:
    def __init__(self, verifier: TokenVerifier, registry: KeyRegistry, store: InMemoryStore,
                 client_header: str = "x-api-key"):
        self._verifier = verifier
        self._registry = registry
        self._store = store
        self._client_header = client_header.lower()

    def evaluate(self, headers: Mapping[str, str]) -> GatewayDecision:
        h = {k.lower(): v for k, v in headers.items()}
        client_id = h.get(self._client_header)
        key = self._registry.get(client_id)
        if key is None:
            return GatewayDecision(False, "rejected", "unknown_client")
        if key.mode is Mode.OFF:
            return GatewayDecision(True, "unverified")
        try:
            claims = self._check(h.get(HEADER_APP_TOKEN), client_id, key)
        except AttestationError as err:
            monitor = key.mode is Mode.MONITOR
            log.info("app_token client=%s mode=%s result=%s code=%s", client_id, key.mode.value,
                     "unverified" if monitor else "rejected", err.code)
            return GatewayDecision(monitor, "unverified" if monitor else "rejected", err.code)
        return GatewayDecision(True, "verified", claims=claims)

    def _check(self, token: str | None, client_id: str, key: KeyConfig) -> dict:
        if not token:
            raise AttestationError("app_token_missing")
        claims = self._verifier.verify(token)
        if claims["wk"] != client_id:
            raise AttestationError("app_token_invalid", "token bound to another client")
        if claims["app"] not in key.allowed_apps and claims.get("att") != "debug":
            raise AttestationError("app_token_revoked", "app no longer allowed")
        for kind in ("wk", "app", "sub"):
            if self._store.is_denied(kind, claims[kind]):
                raise AttestationError("app_token_revoked", f"{kind} on deny list")
        return claims
