from urllib.parse import parse_qsl

from attestation.config import Mode
from conftest import CLIENT_ID, DEBUG_TOKEN, H, PRIVATE_KEY, attest, get_challenge

NEARBY = "/localities/nearby?types=point_of_interest&location=48.863469,2.330941&radius=1000"


def call(client, token=None, url=NEARBY, extra=None):
    headers = {**H, "X-iOS-Identifier": "com.woosmap.app.woozies", "X-App-Version": "1.0"}
    if token:
        headers["X-Woosmap-App-Token"] = token
    headers.update(extra or {})
    return client.get(url, headers=headers)


def test_attested_app_gets_real_results(client, apple, woosmap):
    resp = call(client, attest(client, apple.new_device()))
    assert resp.status_code == 200
    assert resp.json()["results"][0]["name"] == "Louvre"


def test_query_and_key_forwarded_correctly(client, apple, woosmap):
    token = attest(client, apple.new_device())
    call(client, token, NEARBY + "&key=stolen&private_key=stolen&foo=bar",
         extra={"Accept-Language": "fr"})
    sent = woosmap.requests[-1]
    assert sent.url.path == "/localities/nearby"
    assert dict(parse_qsl(sent.url.query.decode())) == {
        "types": "point_of_interest", "location": "48.863469,2.330941", "radius": "1000"}
    assert sent.headers["X-Api-Key"] == PRIVATE_KEY
    assert sent.headers["Accept-Language"] == "fr"
    assert "X-Woosmap-App-Token" not in sent.headers


def test_curl_with_spoofed_bundle_id_is_rejected(client, woosmap):
    resp = call(client)
    assert resp.status_code == 401
    assert resp.json() == {"error": "app_token_missing"}
    assert woosmap.requests == []


def test_unknown_client_rejected(client):
    resp = call(client, extra={"X-Client-Id": "someone-else"})
    assert resp.status_code == 401
    assert resp.json()["error"] == "unknown_client"


def test_garbage_token_rejected(client, woosmap):
    assert call(client, "not-a-token").json()["error"] == "app_token_invalid"
    assert woosmap.requests == []


def test_monitor_mode_forwards_but_flags(make_client, woosmap):
    with make_client(attest_mode=Mode.MONITOR) as c:
        assert call(c).status_code == 200
    assert len(woosmap.requests) == 1


def test_debug_token_for_simulator(client):
    resp = client.post("/attest/debug/token", headers=H, json={"debug_token": DEBUG_TOKEN})
    assert resp.status_code == 200
    assert call(client, resp.json()["token"]).status_code == 200


def test_debug_tokens_disabled_by_default(make_client):
    with make_client(debug_tokens=()) as c:
        resp = c.post("/attest/debug/token", headers=H, json={"debug_token": DEBUG_TOKEN})
        assert resp.status_code == 401


def test_ios_refresh_with_assertion(client, apple):
    device = apple.new_device()
    attest(client, device)
    challenge = get_challenge(client)
    resp = client.post("/attest/ios/token", headers=H, json={
        "key_id": device.key_id, "challenge": challenge, "assertion": device.assertion(challenge)})
    assert resp.status_code == 200
    assert call(client, resp.json()["token"]).status_code == 200


def test_wrong_team_id_rejected(make_client, apple):
    with make_client(apple_team_id="ZZZZZ99999") as c:
        challenge = get_challenge(c)
        device = apple.new_device()
        resp = c.post("/attest/ios/register", headers=H, json={
            "key_id": device.key_id, "challenge": challenge,
            "attestation": device.attestation(challenge)})
        assert resp.status_code == 401


def test_upstream_auth_error_mapped_to_502(client, apple, woosmap):
    token = attest(client, apple.new_device())
    woosmap.status, woosmap.body = 403, {"detail": "This Woosmap API is not enabled for this project."}
    resp = call(client, token)
    assert resp.status_code == 502
    assert resp.json() == {"error": "upstream_auth_failed"}


def test_upstream_validation_error_passed_through(client, apple, woosmap):
    token = attest(client, apple.new_device())
    woosmap.status, woosmap.body = 400, {"detail": "types is required"}
    resp = call(client, token)
    assert resp.status_code == 400
    assert resp.json()["detail"] == "types is required"


def test_firebase_disabled_unless_configured(client):
    resp = client.post("/attest/firebase/token", headers=H, json={"app_check_token": "x"})
    assert resp.status_code == 503
    assert resp.json()["error"] == "firebase_not_configured"


def test_health(client):
    assert client.get("/health").json()["app_attest"] is True
