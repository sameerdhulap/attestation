import base64
import hashlib
import time

import httpx
import pytest

from attestation.config import AttestationError, KeyConfig, Mode
from attestation.play_integrity import PlayIntegrityVerifier
from conftest import CLIENT_ID, H, WOOSMAP_KEY, get_challenge, token_claims

PACKAGE = "com.woosmap.app.woozies"
CERT = hashlib.sha256(b"release-cert").digest()
CERT_B64 = base64.urlsafe_b64encode(CERT).rstrip(b"=").decode()
OTHER_CERT_B64 = (
    base64.urlsafe_b64encode(hashlib.sha256(b"other-cert").digest())
    .rstrip(b"=")
    .decode()
)
OTHER_PACKAGE = "com.woosmap.app.other"
# Android apps name their package when they ask the proxy for a token.
AH = {**H, "X-Android-Identifier": PACKAGE}
SHA1 = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"


def payload(nonce: str, package: str = PACKAGE, **overrides) -> dict:
    """A Play Integrity verdict as Google's decodeIntegrityToken returns it."""
    verdict = {
        "requestDetails": {
            "requestPackageName": package,
            "nonce": nonce,
            "timestampMillis": str(int(time.time() * 1000)),
        },
        "appIntegrity": {
            "appRecognitionVerdict": "PLAY_RECOGNIZED",
            "packageName": package,
            "certificateSha256Digest": [CERT_B64],
        },
        "deviceIntegrity": {"deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"]},
        "accountDetails": {"appLicensingVerdict": "LICENSED"},
    }
    for section, values in overrides.items():
        verdict[section] = {**verdict[section], **values}
    return verdict


class FakeDecoder:
    """Stands in for Google's decode API: returns whatever verdict the test sets."""

    def __init__(self):
        self.verdict: dict | None = None
        self.calls: list[tuple[str, str]] = []

    def __call__(self, package: str, token: str) -> dict:
        self.calls.append((package, token))
        return self.verdict


def key(**overrides) -> KeyConfig:
    base = dict(
        api_key=CLIENT_ID,
        project_id=CLIENT_ID,
        mode=Mode.ENFORCE,
        android_packages=(PACKAGE,),
        android_cert_sha256=(CERT.hex(),),
    )
    base.update(overrides)
    return KeyConfig(**base)


def verify(verdict: dict, challenge: str = "challenge-123", **key_overrides):
    decoder = FakeDecoder()
    decoder.verdict = verdict
    return PlayIntegrityVerifier(decoder).verify(
        token="integrity-token",
        challenge=challenge,
        package=PACKAGE,
        key=key(**key_overrides),
    )


def test_genuine_app_accepted():
    assert verify(payload("challenge-123")) == "device"


def test_strong_integrity_reported():
    verdict = payload(
        "challenge-123",
        deviceIntegrity={
            "deviceRecognitionVerdict": [
                "MEETS_DEVICE_INTEGRITY",
                "MEETS_STRONG_INTEGRITY",
            ]
        },
    )
    assert verify(verdict) == "strong"


@pytest.mark.parametrize(
    "verdict, code",
    [
        (payload("other-challenge"), "play_integrity_nonce_mismatch"),
        (
            payload("challenge-123", requestDetails={"requestPackageName": "com.evil"}),
            "play_integrity_wrong_app",
        ),
        (
            payload("challenge-123", appIntegrity={"packageName": "com.evil"}),
            "play_integrity_wrong_app",
        ),
        (
            payload(
                "challenge-123",
                appIntegrity={"appRecognitionVerdict": "UNRECOGNIZED_VERSION"},
            ),
            "play_integrity_app_not_recognized",
        ),
        (
            payload(
                "challenge-123",
                appIntegrity={"certificateSha256Digest": [OTHER_CERT_B64]},
            ),
            "play_integrity_wrong_cert",
        ),
        (
            payload("challenge-123", deviceIntegrity={"deviceRecognitionVerdict": []}),
            "play_integrity_device_failed",
        ),
        (
            payload("challenge-123", requestDetails={"timestampMillis": "1000"}),
            "play_integrity_stale",
        ),
    ],
)
def test_bad_verdicts_rejected(verdict, code):
    with pytest.raises(AttestationError) as err:
        verify(verdict)
    assert err.value.code == code


def test_strong_level_required():
    with pytest.raises(AttestationError) as err:
        verify(payload("challenge-123"), android_min_device_level="strong")
    assert err.value.code == "play_integrity_device_failed"


def test_licence_required():
    verdict = payload(
        "challenge-123", accountDetails={"appLicensingVerdict": "UNLICENSED"}
    )
    assert verify(verdict) == "device"
    with pytest.raises(AttestationError) as err:
        verify(verdict, android_require_licensed=True)
    assert err.value.code == "play_integrity_unlicensed"


def test_cert_check_skipped_when_not_configured():
    verdict = payload(
        "challenge-123", appIntegrity={"certificateSha256Digest": [OTHER_CERT_B64]}
    )
    assert verify(verdict, android_cert_sha256=()) == "device"


# Through the proxy ------------------------------------------------------------------


def test_android_token_exchanged_and_used(make_client, woosmap):
    decoder = FakeDecoder()
    with make_client(play_integrity=PlayIntegrityVerifier(decoder)) as c:
        challenge = get_challenge(c)
        decoder.verdict = payload(challenge)
        resp = c.post(
            "/attest/android/token",
            headers=AH,
            json={"integrity_token": "integrity-token", "challenge": challenge},
        )
        assert resp.status_code == 200, resp.text
        assert decoder.calls == [(PACKAGE, "integrity-token")]

        nearby = c.get(
            "/localities/nearby?types=point_of_interest&location=19.13,72.93",
            headers={
                **H,
                "X-Woosmap-App-Token": resp.json()["token"],
                "X-Api-Key": WOOSMAP_KEY,
                "X-Android-Identifier": PACKAGE,
                "X-Android-Fingerprint": SHA1,
            },
        )
    assert nearby.status_code == 200
    sent = woosmap.requests[-1]
    assert sent.headers["X-Android-Identifier"] == PACKAGE
    assert sent.headers["X-Android-Fingerprint"] == SHA1
    assert "X-iOS-Identifier" not in sent.headers


def test_android_challenge_single_use(make_client):
    decoder = FakeDecoder()
    with make_client(play_integrity=PlayIntegrityVerifier(decoder)) as c:
        challenge = get_challenge(c)
        decoder.verdict = payload(challenge)
        body = {"integrity_token": "integrity-token", "challenge": challenge}
        assert c.post("/attest/android/token", headers=AH, json=body).status_code == 200
        assert (
            c.post("/attest/android/token", headers=AH, json=body).json()["error"]
            == "challenge_invalid"
        )


def test_second_android_app_gets_its_own_token(make_client):
    decoder = FakeDecoder()
    with make_client(
        play_integrity=PlayIntegrityVerifier(decoder),
        android_packages=(PACKAGE, OTHER_PACKAGE),
    ) as c:
        challenge = get_challenge(c)
        decoder.verdict = payload(challenge, package=OTHER_PACKAGE)
        resp = c.post(
            "/attest/android/token",
            headers={**H, "X-Android-Identifier": OTHER_PACKAGE},
            json={"integrity_token": "integrity-token", "challenge": challenge},
        )
    assert resp.status_code == 200, resp.text
    assert decoder.calls == [(OTHER_PACKAGE, "integrity-token")]
    assert token_claims(resp.json()["token"])["app"] == OTHER_PACKAGE


def test_android_package_missing_rejected(make_client):
    with make_client(play_integrity=PlayIntegrityVerifier(FakeDecoder())) as c:
        resp = c.post(
            "/attest/android/token",
            headers=H,
            json={"integrity_token": "x", "challenge": get_challenge(c)},
        )
    assert resp.status_code == 400
    assert resp.json() == {"error": "app_identifier_missing"}


def test_unlisted_android_package_rejected(make_client):
    decoder = FakeDecoder()
    with make_client(play_integrity=PlayIntegrityVerifier(decoder)) as c:
        resp = c.post(
            "/attest/android/token",
            headers={**H, "X-Android-Identifier": OTHER_PACKAGE},
            json={"integrity_token": "x", "challenge": get_challenge(c)},
        )
    assert resp.json() == {"error": "play_integrity_wrong_app"}
    assert decoder.calls == []


def test_play_integrity_disabled_unless_configured(client):
    resp = client.post(
        "/attest/android/token",
        headers=H,
        json={"integrity_token": "x", "challenge": "y"},
    )
    assert resp.status_code == 503
    assert resp.json()["error"] == "play_integrity_not_configured"


# Google decoder -------------------------------------------------------------------


class FakeCredentials:
    valid = True
    token = "access-token"


@pytest.fixture
def google_decoder(monkeypatch):
    from google.oauth2 import service_account

    from attestation.play_integrity import GooglePlayDecoder

    monkeypatch.setattr(service_account.Credentials, "from_service_account_file",
                        lambda path, scopes: FakeCredentials())
    return GooglePlayDecoder("service-account.json")


def test_google_decoder_returns_payload(monkeypatch, google_decoder):
    seen = {}

    def fake_post(url, json, headers, timeout):
        seen.update(url=url, json=json, auth=headers["Authorization"])
        return httpx.Response(200, json={"tokenPayloadExternal": {"ok": True}})

    monkeypatch.setattr("attestation.play_integrity.httpx.post", fake_post)
    assert google_decoder(PACKAGE, "integrity-token") == {"ok": True}
    assert seen == {
        "url": f"https://playintegrity.googleapis.com/v1/{PACKAGE}:decodeIntegrityToken",
        "json": {"integrity_token": "integrity-token"},
        "auth": "Bearer access-token",
    }


def test_google_decoder_rejects_bad_token(monkeypatch, google_decoder):
    monkeypatch.setattr("attestation.play_integrity.httpx.post",
                        lambda *a, **k: httpx.Response(400, text="bad token"))
    with pytest.raises(AttestationError) as err:
        google_decoder(PACKAGE, "integrity-token")
    assert err.value.code == "play_integrity_invalid"


def test_google_decoder_unavailable(monkeypatch, google_decoder):
    def fail(*a, **k):
        raise httpx.ConnectError("down")

    monkeypatch.setattr("attestation.play_integrity.httpx.post", fail)
    with pytest.raises(AttestationError) as err:
        google_decoder(PACKAGE, "integrity-token")
    assert (err.value.code, err.value.status) == ("play_integrity_unavailable", 503)
