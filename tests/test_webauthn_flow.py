from __future__ import annotations

import base64
import json
import threading

from fastapi.testclient import TestClient

from app.webauthn import b64url_decode
from tests.soft_authenticator import SoftAuthenticator


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _register(client: TestClient, authenticator: SoftAuthenticator, origin: str,
              username: str):
    opts = client.post("/register/options", json={"username": username}).json()
    body = authenticator.register(opts, origin)
    resp = client.post("/register/finish", json=body)
    assert resp.status_code == 200, resp.text
    return opts, resp.json()


def test_full_register_login_me_logout(client, rp_id_origin):
    rp_id, origin = rp_id_origin
    auth = SoftAuthenticator(rp_id)

    reg_opts, reg_info = _register(client, auth, origin, "alice")
    assert reg_opts["rp"] == {"id": "localhost", "name": "WebAuthn Demo"}
    assert reg_opts["attestation"] == "none"
    assert reg_opts["pubKeyCredParams"] == [{"type": "public-key", "alg": -7}]
    assert b64url_decode(reg_info["credentialId"]) == auth.credential_id

    assert client.post("/register/options", json={"username": "alice"}).status_code == 409

    login_opts = client.post("/login/options", json={"username": "alice"}).json()
    assert [c["id"] for c in login_opts["allowCredentials"]] == [reg_info["credentialId"]]
    assert login_opts["rpId"] == "localhost"
    assert login_opts["userVerification"] == "required"

    body = auth.login("alice", login_opts, reg_opts["user"]["id"], origin)
    resp = client.post("/login/finish", json=body)
    assert resp.status_code == 200, resp.text
    assert resp.json()["expiresIn"] == 1800
    token = resp.json()["token"]

    me = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200 and me.json()["username"] == "alice"

    assert client.post("/logout", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    assert client.get("/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    # Logout leaves the token unusable; a second logout reports it as invalid.
    assert client.post("/logout", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    assert client.get("/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_unknown_user_and_missing_token(client):
    assert client.post("/login/options", json={"username": "ghost"}).status_code == 404
    assert client.get("/me").status_code == 401
    assert client.post("/logout", headers={"Authorization": "Bearer x"}).status_code == 401


def test_login_challenge_consumed_at_most_once_under_concurrency(client, rp_id_origin):
    rp_id, origin = rp_id_origin
    auth = SoftAuthenticator(rp_id)
    reg_opts, _ = _register(client, auth, origin, "bob")

    login_opts = client.post("/login/options", json={"username": "bob"}).json()
    body = auth.login("bob", login_opts, reg_opts["user"]["id"], origin)

    results = []
    barrier = threading.Barrier(8)
    lock = threading.Lock()

    def fire():
        barrier.wait()
        status = client.post("/login/finish", json=body).status_code
        with lock:
            results.append(status)

    threads = [threading.Thread(target=fire) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(200) == 1
    assert results.count(400) == 7


def test_registration_challenge_replay_fails(client, rp_id_origin):
    rp_id, origin = rp_id_origin
    auth = SoftAuthenticator(rp_id)
    opts = client.post("/register/options", json={"username": "zoe"}).json()
    body = auth.register(opts, origin)
    assert client.post("/register/finish", json=body).status_code == 200
    assert client.post("/register/finish", json=body).status_code == 409


def test_sign_count_zero_zero_allowed_then_must_increase(client, rp_id_origin):
    rp_id, origin = rp_id_origin
    auth = SoftAuthenticator(rp_id, sign_count_start=0)
    reg_opts, _ = _register(client, auth, origin, "dave")

    opts = client.post("/login/options", json={"username": "dave"}).json()
    body = auth.login("dave", opts, reg_opts["user"]["id"], origin, bump=False)
    assert client.post("/login/finish", json=body).status_code == 200

    auth.sign_count = 3
    opts = client.post("/login/options", json={"username": "dave"}).json()
    body = auth.login("dave", opts, reg_opts["user"]["id"], origin, bump=False)
    assert client.post("/login/finish", json=body).status_code == 200

    opts = client.post("/login/options", json={"username": "dave"}).json()
    body = auth.login("dave", opts, reg_opts["user"]["id"], origin, bump=False)
    r = client.post("/login/finish", json=body)
    assert r.status_code == 400 and "sign count" in r.json()["error"]


def test_rejects_wrong_origin_and_cross_origin(client, rp_id_origin):
    rp_id, origin = rp_id_origin
    auth = SoftAuthenticator(rp_id)
    opts = client.post("/register/options", json={"username": "erin"}).json()
    r = client.post("/register/finish", json=auth.register(opts, "http://evil.example"))
    assert r.status_code == 400 and "origin mismatch" in r.json()["error"]

    r = client.post("/register/finish", json=auth.register(opts, origin, cross_origin=True))
    assert r.status_code == 400 and "cross-origin" in r.json()["error"]


def test_rejects_wrong_rp_id_hash(client, rp_id_origin):
    rp_id, origin = rp_id_origin
    auth = SoftAuthenticator("evil.example")
    opts = client.post("/register/options", json={"username": "frank"}).json()
    r = client.post("/register/finish", json=auth.register(opts, origin))
    assert r.status_code == 400 and "rpIdHash" in r.json()["error"]


def test_rejects_tampered_signature(client, rp_id_origin):
    rp_id, origin = rp_id_origin
    auth = SoftAuthenticator(rp_id)
    reg_opts, _ = _register(client, auth, origin, "grace")

    login_opts = client.post("/login/options", json={"username": "grace"}).json()
    body = auth.login("grace", login_opts, reg_opts["user"]["id"], origin)
    raw = bytearray(b64url_decode(body["signature"]))
    raw[0] ^= 0xFF
    body["signature"] = _b64url(bytes(raw))
    r = client.post("/login/finish", json=body)
    assert r.status_code == 400 and "signature" in r.json()["error"]

    # A failed finish must not consume the challenge; a fresh valid body works,
    # and replaying that successful body fails because the challenge was consumed.
    good = auth.login("grace", login_opts, reg_opts["user"]["id"], origin)
    assert client.post("/login/finish", json=good).status_code == 200
    r = client.post("/login/finish", json=good)
    assert r.status_code == 400 and "challenge" in r.json()["error"]


def test_rejects_reserialized_client_data(client, rp_id_origin):
    """Assertion signature is over the exact original clientDataJSON bytes."""
    rp_id, origin = rp_id_origin
    auth = SoftAuthenticator(rp_id)
    reg_opts, _ = _register(client, auth, origin, "heidi")
    login_opts = client.post("/login/options", json={"username": "heidi"}).json()
    body = auth.login("heidi", login_opts, reg_opts["user"]["id"], origin)
    parsed = json.loads(b64url_decode(body["clientDataJSON"]))
    body["clientDataJSON"] = _b64url(json.dumps(parsed, indent=2).encode())
    r = client.post("/login/finish", json=body)
    assert r.status_code == 400 and "signature" in r.json()["error"]


def test_challenge_expiry(client, rp_id_origin):
    rp_id, origin = rp_id_origin
    auth = SoftAuthenticator(rp_id)
    reg_opts, _ = _register(client, auth, origin, "ivan")

    login_opts = client.post("/login/options", json={"username": "ivan"}).json()
    from app.config import get_settings
    from app.db import connect
    conn = connect(get_settings().db_path)
    conn.execute("UPDATE challenges SET expires_at = 1")
    conn.close()
    body = auth.login("ivan", login_opts, reg_opts["user"]["id"], origin)
    r = client.post("/login/finish", json=body)
    assert r.status_code == 400 and "challenge" in r.json()["error"]


def test_credential_not_allowed_for_other_user(client, rp_id_origin):
    rp_id, origin = rp_id_origin
    auth = SoftAuthenticator(rp_id)
    reg_opts, _ = _register(client, auth, origin, "judy")
    _register(client, SoftAuthenticator(rp_id), origin, "mallory")
    opts = client.post("/login/options", json={"username": "mallory"}).json()
    body = auth.login("mallory", opts, reg_opts["user"]["id"], origin)
    r = client.post("/login/finish", json=body)
    assert r.status_code == 403
