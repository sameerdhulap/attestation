"""Fixtures: proxy settings, a fake Apple App Attest authority and a mock Woosmap API."""

from __future__ import annotations

import base64
import hashlib
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import cbor2
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from attestation.app_attest import AAGUID_PRODUCTION, NONCE_EXTENSION_OID
from attestation.config import Mode
from woozies_proxy.main import create_app
from woozies_proxy.settings import ProxySettings

CLIENT_ID = "woozies-ios"
TEAM_ID = "ABCDE12345"
BUNDLE_ID = "com.woosmap.app.woozies"
APP_ID = f"{TEAM_ID}.{BUNDLE_ID}"
WOOSMAP_KEY = "test-app-key"
DEBUG_TOKEN = "debug-123"
H = {"X-Client-Id": CLIENT_ID}


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, issuer, public_key, signing_key, ca: bool, extensions=()):
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    for ext in extensions:
        builder = builder.add_extension(ext, critical=False)
    return builder.sign(signing_key, hashes.SHA256())


def _nonce_extension(nonce: bytes) -> x509.UnrecognizedExtension:
    octet = b"\x04" + bytes([len(nonce)]) + nonce
    explicit = b"\xa1" + bytes([len(octet)]) + octet
    seq = b"\x30" + bytes([len(explicit)]) + explicit
    return x509.UnrecognizedExtension(NONCE_EXTENSION_OID, seq)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


@dataclass
class FakeDevice:
    """One app install: a Secure Enclave key and its attestation."""

    authority: "FakeAppleAuthority"
    private_key: ec.EllipticCurvePrivateKey
    key_id: str
    counter: int = 0

    def attestation(
        self,
        challenge: str,
        app_id: str = APP_ID,
        aaguid: bytes = AAGUID_PRODUCTION,
        key_id_override: bytes | None = None,
    ) -> str:
        key_id_bytes = base64.b64decode(self.key_id)
        cred_id = key_id_override or key_id_bytes
        auth_data = (
            hashlib.sha256(app_id.encode()).digest()
            + bytes([0x40])
            + struct.pack(">I", 0)
            + aaguid
            + struct.pack(">H", len(cred_id))
            + cred_id
        )
        nonce = hashlib.sha256(
            auth_data + hashlib.sha256(challenge.encode()).digest()
        ).digest()
        leaf = _cert(
            _name(self.key_id),
            self.authority.intermediate.subject,
            self.private_key.public_key(),
            self.authority.intermediate_key,
            ca=False,
            extensions=[_nonce_extension(nonce)],
        )
        der = lambda c: c.public_bytes(serialization.Encoding.DER)  # noqa: E731
        obj = {
            "fmt": "apple-appattest",
            "authData": auth_data,
            "attStmt": {
                "x5c": [der(leaf), der(self.authority.intermediate)],
                "receipt": b"r",
            },
        }
        return b64(cbor2.dumps(obj))

    def assertion(
        self, challenge: str, app_id: str = APP_ID, counter: int | None = None
    ) -> str:
        self.counter = self.counter + 1 if counter is None else counter
        auth_data = (
            hashlib.sha256(app_id.encode()).digest()
            + bytes([0x00])
            + struct.pack(">I", self.counter)
        )
        nonce = hashlib.sha256(
            auth_data + hashlib.sha256(challenge.encode()).digest()
        ).digest()
        signature = self.private_key.sign(nonce, ec.ECDSA(hashes.SHA256()))
        return b64(
            cbor2.dumps({"signature": signature, "authenticatorData": auth_data})
        )


class FakeAppleAuthority:
    def __init__(self):
        self.root_key = ec.generate_private_key(ec.SECP384R1())
        self.root = _cert(
            _name("Fake App Attestation Root CA"),
            _name("Fake App Attestation Root CA"),
            self.root_key.public_key(),
            self.root_key,
            ca=True,
        )
        self.intermediate_key = ec.generate_private_key(ec.SECP384R1())
        self.intermediate = _cert(
            _name("Fake App Attestation CA 1"),
            self.root.subject,
            self.intermediate_key.public_key(),
            self.root_key,
            ca=True,
        )

    def new_device(self) -> FakeDevice:
        key = ec.generate_private_key(ec.SECP256R1())
        point = key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        return FakeDevice(self, key, b64(hashlib.sha256(point).digest()))


class MockWoosmap:
    """Records forwarded requests and answers like the Localities API."""

    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.status = 200
        self.body = {
            "results": [
                {
                    "public_id": "abc",
                    "name": "Louvre",
                    "types": ["point_of_interest"],
                    "geometry": {"location": {"lat": 48.8606, "lng": 2.3376}},
                }
            ]
        }

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self.status, json=self.body)


def make_settings(**overrides) -> ProxySettings:
    base = dict(
        ios_allow_development=False,
        attest_mode=Mode.ENFORCE,
        debug_tokens=(DEBUG_TOKEN,),
    )
    base.update(overrides)
    return ProxySettings(**base)


@pytest.fixture
def apple():
    return FakeAppleAuthority()


@pytest.fixture
def woosmap():
    return MockWoosmap()


@pytest.fixture
def make_client(apple, woosmap):
    def _make(firebase_verifier=None, **overrides):
        app = create_app(
            make_settings(**overrides),
            apple_root=apple.root,
            upstream_transport=httpx.MockTransport(woosmap.handler),
            firebase_verifier=firebase_verifier,
        )
        return TestClient(app)

    return _make


@pytest.fixture
def client(make_client):
    with make_client() as c:
        yield c


def get_challenge(client) -> str:
    resp = client.post("/attest/challenge", headers=H)
    assert resp.status_code == 200, resp.text
    return resp.json()["challenge"]


def register(client, device, team_id: str | None = TEAM_ID):
    """Registers the device's App Attest key, sending team_id as X-Apple-Team-Id."""
    challenge = get_challenge(client)
    headers = {**H, "X-Apple-Team-Id": team_id} if team_id is not None else H
    return client.post(
        "/attest/ios/register",
        headers=headers,
        json={
            "key_id": device.key_id,
            "challenge": challenge,
            "attestation": device.attestation(challenge),
        },
    )


def attest(client, device) -> str:
    resp = register(client, device)
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]
