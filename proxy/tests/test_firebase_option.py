import time

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from attestation.firebase_app_check import FirebaseAppCheckVerifier
from conftest import BUNDLE_ID, H, WOOSMAP_KEY

PROJECT = "123456789012"
APP_ID = "1:123456789012:ios:abc123"


class FakeJwks:
    def __init__(self, key):
        self.key = key

    def get_signing_key_from_jwt(self, token):
        return self


def test_firebase_token_exchanged_and_accepted(make_client):
    signing = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = FirebaseAppCheckVerifier(jwks_client=FakeJwks(signing.public_key()))
    now = int(time.time())
    app_check = jwt.encode(
        {
            "iss": f"https://firebaseappcheck.googleapis.com/{PROJECT}",
            "aud": [f"projects/{PROJECT}"],
            "sub": APP_ID,
            "iat": now,
            "exp": now + 3600,
        },
        signing,
        algorithm="RS256",
        headers={"typ": "JWT", "kid": "k"},
    )
    with make_client(
        firebase_verifier=verifier,
        firebase_project_number=PROJECT,
        firebase_app_ids=(APP_ID,),
    ) as c:
        resp = c.post(
            "/attest/firebase/token", headers=H, json={"app_check_token": app_check}
        )
        assert resp.status_code == 200, resp.text
        nearby = c.get(
            "/localities/nearby?types=point_of_interest&location=1,2",
            headers={
                **H,
                "X-Woosmap-App-Token": resp.json()["token"],
                "X-Api-Key": WOOSMAP_KEY,
                "X-iOS-Identifier": BUNDLE_ID,
            },
        )
        assert nearby.status_code == 200


def test_firebase_token_for_other_app_rejected(make_client):
    signing = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = FirebaseAppCheckVerifier(jwks_client=FakeJwks(signing.public_key()))
    now = int(time.time())
    app_check = jwt.encode(
        {
            "iss": f"https://firebaseappcheck.googleapis.com/{PROJECT}",
            "aud": [f"projects/{PROJECT}"],
            "sub": "1:1:ios:other",
            "iat": now,
            "exp": now + 3600,
        },
        signing,
        algorithm="RS256",
        headers={"typ": "JWT"},
    )
    with make_client(
        firebase_verifier=verifier,
        firebase_project_number=PROJECT,
        firebase_app_ids=(APP_ID,),
    ) as c:
        resp = c.post(
            "/attest/firebase/token", headers=H, json={"app_check_token": app_check}
        )
        assert resp.status_code == 401
