"""State the attestation service keeps: challenges, App Attest keys and the deny list.

`InMemoryStore` is for development and tests. Production needs a shared store
(Redis for challenges and the deny list, a database for App Attest keys) so every
instance sees the same state.
"""
from __future__ import annotations

import base64
import secrets
import threading
import time
from dataclasses import dataclass, replace
from typing import Callable

from .config import AttestationError


@dataclass(frozen=True)
class IosKeyRecord:
    key_id: str            # base64 keyId as sent by the app
    api_key: str
    app_id: str            # "TEAMID.bundle.identifier"
    public_key_pem: bytes
    sign_count: int
    environment: str       # "production" or "development"
    receipt: bytes


class InMemoryStore:
    def __init__(self, clock: Callable[[], float] = time.time):
        self._clock = clock
        self._lock = threading.Lock()
        self._challenges: dict[str, tuple[str, float]] = {}
        self._ios_keys: dict[str, IosKeyRecord] = {}
        self._denied: set[tuple[str, str]] = set()

    # Challenges -----------------------------------------------------------
    def put_challenge(self, challenge: str, api_key: str, expires_at: float) -> None:
        with self._lock:
            self._challenges[challenge] = (api_key, expires_at)

    def consume_challenge(self, challenge: str, api_key: str) -> bool:
        """Remove the challenge and report whether it was valid for this key."""
        with self._lock:
            entry = self._challenges.pop(challenge, None)
        if entry is None:
            return False
        owner, expires_at = entry
        return owner == api_key and self._clock() < expires_at

    # App Attest keys --------------------------------------------------------
    def get_ios_key(self, key_id: str) -> IosKeyRecord | None:
        return self._ios_keys.get(key_id)

    def save_ios_key(self, record: IosKeyRecord) -> None:
        with self._lock:
            if record.key_id in self._ios_keys:
                raise AttestationError("key_already_registered", status=409)
            self._ios_keys[record.key_id] = record

    def update_sign_count(self, key_id: str, expected_old: int, new_count: int) -> None:
        """Compare-and-set, so two concurrent assertions can't both pass."""
        with self._lock:
            record = self._ios_keys.get(key_id)
            if record is None or record.sign_count != expected_old:
                raise AttestationError("assertion_counter_race", "counter changed concurrently")
            self._ios_keys[key_id] = replace(record, sign_count=new_count)

    # Deny list --------------------------------------------------------------
    def deny(self, kind: str, value: str) -> None:
        with self._lock:
            self._denied.add((kind, value))

    def is_denied(self, kind: str, value: str) -> bool:
        return (kind, value) in self._denied


class ChallengeService:
    """Issues single-use challenges bound to one API key."""

    def __init__(self, store: InMemoryStore, ttl_seconds: int = 300,
                 clock: Callable[[], float] = time.time):
        self._store = store
        self._ttl = ttl_seconds
        self._clock = clock

    def issue(self, api_key: str) -> tuple[str, int]:
        challenge = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
        self._store.put_challenge(challenge, api_key, self._clock() + self._ttl)
        return challenge, self._ttl

    def consume(self, challenge: str, api_key: str) -> None:
        if not challenge or not self._store.consume_challenge(challenge, api_key):
            raise AttestationError("challenge_invalid", "unknown, expired, reused or wrong key")
