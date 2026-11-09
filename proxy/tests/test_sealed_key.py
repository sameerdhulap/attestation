"""The app's Woosmap key sealed inside its app token."""

import base64
import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from attestation.config import AttestationError, KeyConfig, Mode
from attestation.tokens import KeySealer, TokenIssuer, load_or_generate_signing_key
from conftest import (
    BUNDLE_ID,
    CLIENT_ID,
    DEBUG_TOKEN,
    H,
    WOOSMAP_KEY,
    make_settings,
    register,
    token_claims,
)
from woozies_proxy.settings import ProxySettings

NEARBY = "/localities/nearby?types=point_of_interest&location=19.13,72.93"
SECRET = os.urandom(32)
# What the app sends on API calls: no X-Api-Key, the key comes from the token.
CALL_HEADERS = {"X-Client-Id": CLIENT_ID, "X-iOS-Identifier": BUNDLE_ID}


def debug_token(client) -> str:
    resp = client.post(
        "/attest/debug/token",
        headers={**H, "X-iOS-Identifier": BUNDLE_ID},
        json={"debug_token": DEBUG_TOKEN},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]


def write_signing_key(tmp_path) -> str:
    path = tmp_path / "signing-key.pem"
    path.write_bytes(
        ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(path)


# KeySealer ------------------------------------------------------------------------


def test_sealed_key_round_trips():
    sealer = KeySealer(SECRET)
    assert sealer.open(sealer.seal(WOOSMAP_KEY, "jti-1"), "jti-1") == WOOSMAP_KEY


def test_sealed_key_hides_the_key():
    sealed = KeySealer(SECRET).seal(WOOSMAP_KEY, "jti-1")
    assert WOOSMAP_KEY not in base64.urlsafe_b64decode(sealed + "==").decode("latin-1")


@pytest.mark.parametrize(
    "sealer, token_id",
    [(KeySealer(os.urandom(32)), "jti-1"), (KeySealer(SECRET), "jti-2")],
    ids=["other secret", "other token"],
)
def test_sealed_key_rejected_outside_its_token(sealer, token_id):
    sealed = KeySealer(SECRET).seal(WOOSMAP_KEY, "jti-1")
    with pytest.raises(AttestationError) as err:
        sealer.open(sealed, token_id)
    assert err.value.code == "app_token_invalid"


def test_sealer_from_base64_and_base64url_settings():
    standard = base64.b64encode(SECRET).decode()
    url_safe = base64.urlsafe_b64encode(SECRET).rstrip(b"=").decode()
    sealed = KeySealer.from_setting(standard).seal(WOOSMAP_KEY, "jti-1")
    assert KeySealer.from_setting(url_safe).open(sealed, "jti-1") == WOOSMAP_KEY


@pytest.mark.parametrize("value", ["not base64!", base64.b64encode(b"short").decode()])
def test_sealer_rejects_bad_settings(value):
    with pytest.raises(ValueError):
        KeySealer.from_setting(value)


def test_sealer_generated_when_not_configured():
    sealer = KeySealer.from_setting(None)
    assert sealer.open(sealer.seal(WOOSMAP_KEY, "jti-1"), "jti-1") == WOOSMAP_KEY


def test_issuer_needs_a_sealer_for_keys():
    issuer = TokenIssuer(ec.generate_private_key(ec.SECP256R1()), "k", "iss", "aud")
    key = KeyConfig(api_key=CLIENT_ID, project_id=CLIENT_ID, mode=Mode.ENFORCE)
    with pytest.raises(ValueError):
        issuer.issue(
            key=key, app=BUNDLE_ID, platform="ios", method="debug",
            subject="s", woosmap_key=WOOSMAP_KEY,
        )


def test_encryption_key_read_from_env(monkeypatch):
    monkeypatch.setenv("ATTEST_ENCRYPTION_KEY", "c2VjcmV0")
    assert ProxySettings.from_env(env_file=None).key_encryption_key == "c2VjcmV0"


# Through the proxy -----------------------------------------------------------------


def test_debug_token_carries_sealed_key(client):
    token = debug_token(client)
    assert WOOSMAP_KEY not in token
    assert token_claims(token)["ek"]


def test_api_call_uses_sealed_key(client, woosmap):
    token = debug_token(client)
    resp = client.get(NEARBY, headers={**CALL_HEADERS, "X-App-Token": token})
    assert resp.status_code == 200, resp.text
    assert woosmap.requests[-1].headers["X-Api-Key"] == WOOSMAP_KEY


def test_sealed_key_wins_over_header(client, woosmap):
    token = debug_token(client)
    client.get(
        NEARBY,
        headers={**CALL_HEADERS, "X-App-Token": token, "X-Api-Key": "other"},
    )
    assert woosmap.requests[-1].headers["X-Api-Key"] == WOOSMAP_KEY


def test_header_key_never_used(make_client, woosmap, tmp_path):
    # A genuine token without a sealed key: the X-Api-Key header doesn't stand in for it.
    signing_key = write_signing_key(tmp_path)
    settings = make_settings(signing_key_path=signing_key)
    token = TokenIssuer(
        load_or_generate_signing_key(signing_key),
        settings.signing_key_id,
        settings.issuer,
        settings.audience,
    ).issue(
        key=settings.key_config(), app=BUNDLE_ID, platform="ios",
        method="debug", subject="s",
    ).token
    with make_client(signing_key_path=signing_key) as c:
        resp = c.get(
            NEARBY,
            headers={**CALL_HEADERS, "X-App-Token": token, "X-Api-Key": "k"},
        )
    assert resp.status_code == 400
    assert resp.json() == {"error": "woosmap_key_missing"}
    assert woosmap.requests == []


def test_app_attest_token_carries_sealed_key(client, apple, woosmap):
    resp = register(client, apple.new_device())
    assert resp.status_code == 200, resp.text
    token = resp.json()["token"]
    assert client.get(
        NEARBY, headers={**CALL_HEADERS, "X-App-Token": token}
    ).status_code == 200
    assert woosmap.requests[-1].headers["X-Api-Key"] == WOOSMAP_KEY


def test_rotated_encryption_key_rejects_old_tokens(make_client, woosmap, tmp_path):
    signing_key = write_signing_key(tmp_path)
    old, new = (base64.b64encode(os.urandom(32)).decode() for _ in range(2))
    with make_client(signing_key_path=signing_key, key_encryption_key=old) as c:
        token = debug_token(c)
    with make_client(signing_key_path=signing_key, key_encryption_key=new) as c:
        resp = c.get(NEARBY, headers={**CALL_HEADERS, "X-App-Token": token})
    assert resp.status_code == 401
    assert resp.json() == {"error": "app_token_invalid"}
    assert woosmap.requests == []
