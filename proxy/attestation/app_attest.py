"""Apple App Attest: verify the one-time attestation and per-session assertions.

Follows Apple's "Validating apps that connect to your server" steps. The client
computes clientDataHash = SHA256(client_data) and passes it to attestKey /
generateAssertion; here `client_data` is the UTF-8 challenge string.
"""
from __future__ import annotations

import base64
import hashlib
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .config import AttestationError
from .store import IosKeyRecord

NONCE_EXTENSION_OID = x509.ObjectIdentifier("1.2.840.113635.100.8.2")
AAGUID_PRODUCTION = b"appattest" + b"\x00" * 7
AAGUID_DEVELOPMENT = b"appattestdevelop"
FLAG_ATTESTED_CREDENTIAL_DATA = 0x40


def load_apple_root(path: str | Path) -> x509.Certificate:
    """Load Apple's App Attestation Root CA (download it from Apple, never from a third party)."""
    cert = x509.load_pem_x509_certificate(Path(path).read_bytes())
    cert.verify_directly_issued_by(cert)  # must be self-signed
    return cert


@dataclass(frozen=True)
class AuthenticatorData:
    rp_id_hash: bytes
    flags: int
    sign_count: int
    aaguid: bytes | None = None
    credential_id: bytes | None = None


def parse_authenticator_data(data: bytes) -> AuthenticatorData:
    if len(data) < 37:
        raise AttestationError("app_attest_invalid", "authenticator data too short")
    rp_id_hash, flags, sign_count = data[:32], data[32], struct.unpack(">I", data[33:37])[0]
    if not flags & FLAG_ATTESTED_CREDENTIAL_DATA:
        return AuthenticatorData(rp_id_hash, flags, sign_count)
    if len(data) < 55:
        raise AttestationError("app_attest_invalid", "attested credential data truncated")
    aaguid = data[37:53]
    (cred_len,) = struct.unpack(">H", data[53:55])
    credential_id = data[55:55 + cred_len]
    if len(credential_id) != cred_len:
        raise AttestationError("app_attest_invalid", "credential id truncated")
    return AuthenticatorData(rp_id_hash, flags, sign_count, aaguid, credential_id)


def _der_tlv(buf: bytes) -> tuple[int, bytes]:
    """Read the first DER TLV in `buf`; return (tag, value)."""
    if len(buf) < 2:
        raise ValueError("DER too short")
    tag, length, pos = buf[0], buf[1], 2
    if length & 0x80:
        n = length & 0x7F
        length, pos = int.from_bytes(buf[2:2 + n], "big"), 2 + n
    value = buf[pos:pos + length]
    if len(value) != length:
        raise ValueError("DER length mismatch")
    return tag, value


def extract_nonce(cert: x509.Certificate) -> bytes:
    """The leaf cert carries SEQUENCE { [1] EXPLICIT OCTET STRING nonce }."""
    try:
        ext = cert.extensions.get_extension_for_oid(NONCE_EXTENSION_OID).value
        tag, seq = _der_tlv(ext.value)
        assert tag == 0x30
        tag, explicit = _der_tlv(seq)
        assert tag == 0xA1
        tag, nonce = _der_tlv(explicit)
        assert tag == 0x04
        return nonce
    except (x509.ExtensionNotFound, ValueError, AssertionError) as exc:
        raise AttestationError("app_attest_invalid", "nonce extension missing or malformed") from exc


def _b64decode(value: str) -> bytes:
    return base64.b64decode(value + "=" * (-len(value) % 4))


class AppAttestVerifier:
    def __init__(self, root_cert: x509.Certificate,
                 now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        self._root = root_cert
        self._now = now

    # Registration -----------------------------------------------------------
    def verify_attestation(self, *, key_id: str, attestation_b64: str, client_data: bytes,
                           api_key: str, allowed_app_ids: tuple[str, ...],
                           allow_development: bool) -> IosKeyRecord:
        try:
            obj = cbor2.loads(_b64decode(attestation_b64))
            fmt, att_stmt, auth_data_raw = obj["fmt"], obj["attStmt"], obj["authData"]
            x5c = att_stmt["x5c"]
        except Exception as exc:  # noqa: BLE001 - any decoding failure is a bad proof
            raise AttestationError("app_attest_invalid", f"cannot decode attestation: {exc}") from exc
        if fmt != "apple-appattest" or len(x5c) < 2:
            raise AttestationError("app_attest_invalid", "unexpected format or chain")

        # 1. Certificate chain: leaf -> intermediate -> Apple root
        leaf = x509.load_der_x509_certificate(x5c[0])
        intermediate = x509.load_der_x509_certificate(x5c[1])
        self._verify_chain(leaf, intermediate)

        # 2-4. Nonce = SHA256(authData || SHA256(clientData)) must match the leaf extension
        client_data_hash = hashlib.sha256(client_data).digest()
        expected_nonce = hashlib.sha256(auth_data_raw + client_data_hash).digest()
        if extract_nonce(leaf) != expected_nonce:
            raise AttestationError("app_attest_invalid", "nonce mismatch")

        # 5. keyId = SHA256 of the leaf's uncompressed public key point
        public_key = leaf.public_key()
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise AttestationError("app_attest_invalid", "leaf key is not EC")
        point = public_key.public_bytes(serialization.Encoding.X962,
                                        serialization.PublicFormat.UncompressedPoint)
        key_id_bytes = _b64decode(key_id)
        if hashlib.sha256(point).digest() != key_id_bytes:
            raise AttestationError("app_attest_invalid", "keyId does not match certificate")

        # 6-9. Authenticator data: App ID, counter, environment, credential id
        auth = parse_authenticator_data(auth_data_raw)
        app_id = self._match_app_id(auth.rp_id_hash, allowed_app_ids)
        if auth.sign_count != 0:
            raise AttestationError("app_attest_invalid", "counter must be 0 at attestation")
        if auth.aaguid == AAGUID_PRODUCTION:
            environment = "production"
        elif auth.aaguid == AAGUID_DEVELOPMENT and allow_development:
            environment = "development"
        else:
            raise AttestationError("app_attest_invalid", "environment not allowed for this key")
        if auth.credential_id != key_id_bytes:
            raise AttestationError("app_attest_invalid", "credential id mismatch")

        return IosKeyRecord(
            key_id=key_id, api_key=api_key, app_id=app_id,
            public_key_pem=public_key.public_bytes(serialization.Encoding.PEM,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo),
            sign_count=0, environment=environment, receipt=att_stmt.get("receipt", b""),
        )

    # Session refresh ----------------------------------------------------------
    def verify_assertion(self, *, record: IosKeyRecord, assertion_b64: str,
                         client_data: bytes) -> int:
        """Verify an assertion and return its counter (caller persists it)."""
        try:
            obj = cbor2.loads(_b64decode(assertion_b64))
            signature, auth_data_raw = obj["signature"], obj["authenticatorData"]
        except Exception as exc:  # noqa: BLE001
            raise AttestationError("app_attest_invalid", f"cannot decode assertion: {exc}") from exc

        client_data_hash = hashlib.sha256(client_data).digest()
        nonce = hashlib.sha256(auth_data_raw + client_data_hash).digest()
        public_key = serialization.load_pem_public_key(record.public_key_pem)
        try:
            public_key.verify(signature, nonce, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as exc:
            raise AttestationError("app_attest_invalid", "assertion signature invalid") from exc

        auth = parse_authenticator_data(auth_data_raw)
        if auth.rp_id_hash != hashlib.sha256(record.app_id.encode()).digest():
            raise AttestationError("app_attest_invalid", "App ID mismatch")
        if auth.sign_count <= record.sign_count:
            raise AttestationError("app_attest_invalid", "counter did not increase (replay?)")
        return auth.sign_count

    # Helpers -------------------------------------------------------------------
    def _verify_chain(self, leaf: x509.Certificate, intermediate: x509.Certificate) -> None:
        now = self._now()
        try:
            leaf.verify_directly_issued_by(intermediate)
            intermediate.verify_directly_issued_by(self._root)
        except (ValueError, TypeError, InvalidSignature) as exc:
            raise AttestationError("app_attest_invalid", "certificate chain invalid") from exc
        for cert in (leaf, intermediate, self._root):
            if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
                raise AttestationError("app_attest_invalid", "certificate outside validity period")

    @staticmethod
    def _match_app_id(rp_id_hash: bytes, allowed: tuple[str, ...]) -> str:
        for app_id in allowed:
            if hashlib.sha256(app_id.encode()).digest() == rp_id_hash:
                return app_id
        raise AttestationError("app_attest_invalid", "App ID not allowed for this key")
