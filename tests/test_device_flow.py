"""Tests for the OAuth 2.0 Device Authorization Grant (RFC 8628)."""

from __future__ import annotations

import threading
import time

from fastapi.testclient import TestClient

from tests.soft_authenticator import SoftAuthenticator


def _register_and_login(client: TestClient, origin: str, rp_id: str, username: str):
    auth = SoftAuthenticator(rp_id)
    opts = client.post("/register/options", json={"username": username}).json()
    body = auth.register(opts, origin)
    assert client.post("/register/finish", json=body).status_code == 200
    login_opts = client.post("/login/options", json={"username": username}).json()
    login_body = auth.login(username, login_opts, opts["user"]["id"], origin)
    resp = client.post("/login/finish", json=login_body)
    assert resp.status_code == 200, resp.text
    return auth, resp.json()["token"]


def _device_request(client: TestClient, data: dict):
    return client.post("/oauth/device_authorization", data=data)


def test_device_full_flow_approve_exchange_profile_revoke(client, rp_id_origin):
    rp_id, origin = rp_id_origin
    _, token = _register_and_login(client, origin, rp_id, "alice")

    r = _device_request(client, {"client_id": "device-public", "scope": "profile"})
    assert r.status_code == 200, r.text
    dev = r.json()
    assert dev["expires_in"] == 600
    assert dev["interval"] == 5
    assert "verification_uri" in dev and "user_code" in dev
    assert len(dev["device_code"]) > 20

    # Before approval: pending.
    r = client.post("/oauth/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": dev["device_code"],
        "client_id": "device-public",
    })
    assert r.status_code == 400 and r.json()["error"] == "authorization_pending"

    # User inspects the code via the login session.
    r = client.get(f"/device/consent?user_code={dev['user_code']}",
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    info = r.json()
    assert info["client_id"] == "device-public"
    assert info["scope"] == "profile" and info["status"] == "pending"

    r = client.post("/device/decision",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"user_code": dev["user_code"], "approve": True})
    assert r.status_code == 200 and r.json()["status"] == "approved"

    time.sleep(5.01)
    r = client.post("/oauth/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": dev["device_code"],
        "client_id": "device-public",
    })
    assert r.status_code == 200, r.text
    issued = r.json()
    assert issued["token_type"] == "Bearer"
    assert issued["expires_in"] == 1800 and issued["scope"] == "profile"
    access = issued["access_token"]

    # Device code is single use.
    time.sleep(0.01)
    r = client.post("/oauth/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": dev["device_code"],
        "client_id": "device-public",
    })
    assert r.status_code == 400 and r.json()["error"] in (
        "invalid_grant", "slow_down")

    # Device token reads own profile only.
    r = client.get("/oauth/profile", headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 200 and r.json()["username"] == "alice"

    # Device token cannot approve/consent or manage grants.
    r = client.get("/device/consent?user_code=AAAA-BBBB",
                   headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 401
    r = client.get("/oauth/grants", headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 401

    # Owner lists and revokes.
    r = client.get("/oauth/grants", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    grants = r.json()["grants"]
    assert len(grants) == 1 and grants[0]["scope"] == "profile"
    grant_id = grants[0]["id"]
    r = client.delete(f"/oauth/grants/{grant_id}",
                      headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    r = client.get("/oauth/profile", headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 401

    # Revocation does not touch the original login session.
    assert client.get("/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_rejects_unknown_client_and_excessive_scope(client):
    r = _device_request(client, {"client_id": "attacker"})
    assert r.status_code == 401 and r.json()["error"] == "invalid_client"
    r = _device_request(client, {"client_id": "device-public", "scope": "openid profile"})
    assert r.status_code == 400 and r.json()["error"] == "invalid_scope"
    r = _device_request(client, {"client_id": "device-public", "scope": "admin"})
    assert r.status_code == 400 and r.json()["error"] == "invalid_scope"


def test_denied_and_poll_interval_slowdown(client, rp_id_origin):
    rp_id, origin = rp_id_origin
    _, token = _register_and_login(client, origin, rp_id, "bob")
    dev = _device_request(client, {"client_id": "device-public"}).json()

    # Immediate second poll => slow_down, interval grows by 5.
    client.post("/oauth/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": dev["device_code"], "client_id": "device-public"})
    r = client.post("/oauth/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": dev["device_code"], "client_id": "device-public"})
    assert r.status_code == 400 and r.json()["error"] == "slow_down"

    client.post("/device/decision",
                headers={"Authorization": f"Bearer {token}"},
                json={"user_code": dev["user_code"], "approve": False})
    from app.config import get_settings
    from app.db import connect
    conn = connect(get_settings().db_path)
    conn.execute("UPDATE device_authorizations SET last_poll_at = 0")
    conn.close()
    r = client.post("/oauth/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": dev["device_code"], "client_id": "device-public"})
    assert r.status_code == 400 and r.json()["error"] == "access_denied"


def test_slow_down_interval_accumulates(client, rp_id_origin):
    from app.config import get_settings
    from app.db import connect
    rp_id, origin = rp_id_origin
    _register_and_login(client, origin, rp_id, "carol")
    dev = _device_request(client, {"client_id": "device-public"}).json()
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": dev["device_code"], "client_id": "device-public"}
    client.post("/oauth/token", data=data)  # pending
    client.post("/oauth/token", data=data)  # slow_down -> interval 10
    conn = connect(get_settings().db_path)
    row = conn.execute(
        "SELECT interval_seconds FROM device_authorizations").fetchone()
    conn.close()
    assert row["interval_seconds"] == 10


def test_expired_device_code(client, rp_id_origin):
    from app.config import get_settings
    from app.db import connect
    rp_id, origin = rp_id_origin
    _register_and_login(client, origin, rp_id, "dave")
    dev = _device_request(client, {"client_id": "device-public"}).json()
    conn = connect(get_settings().db_path)
    conn.execute("UPDATE device_authorizations SET expires_at = 1")
    conn.close()
    r = client.post("/oauth/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": dev["device_code"], "client_id": "device-public"})
    assert r.status_code == 400 and r.json()["error"] == "expired_token"


def test_wrong_client_cannot_change_request(client, rp_id_origin):
    rp_id, origin = rp_id_origin
    _register_and_login(client, origin, rp_id, "erin")
    dev = _device_request(client, {"client_id": "device-public"}).json()
    r = client.post("/oauth/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": dev["device_code"], "client_id": "other"})
    assert r.status_code == 401 and r.json()["error"] == "invalid_client"
    r = client.post("/oauth/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": "made-up", "client_id": "device-public"})
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


def test_terminal_decision_cannot_be_overwritten_and_code_not_redeemable(
        client, rp_id_origin):
    rp_id, origin = rp_id_origin
    _, token = _register_and_login(client, origin, rp_id, "frank")
    dev = _device_request(client, {"client_id": "device-public"}).json()
    h = {"Authorization": f"Bearer {token}"}
    client.post("/device/decision", headers=h,
                json={"user_code": dev["user_code"], "approve": True})
    # Attempt to flip to denied: stays approved/consumed semantics win.
    r = client.post("/device/decision", headers=h,
                    json={"user_code": dev["user_code"], "approve": False})
    assert r.json()["status"] in ("approved", "consumed")
    # The user code itself can never be exchanged for a token.
    r = client.post("/oauth/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": dev["user_code"], "client_id": "device-public"})
    assert r.status_code == 400


def test_user_code_guess_rate_limit(client, rp_id_origin):
    rp_id, origin = rp_id_origin
    _, token = _register_and_login(client, origin, rp_id, "grace")
    h = {"Authorization": f"Bearer {token}"}
    statuses = []
    for _ in range(7):
        statuses.append(client.get("/device/consent?user_code=ZZZZ-ZZZZ",
                                   headers=h).status_code)
    assert statuses[-1] == 429 and statuses.count(429) >= 1
    # Consent endpoints require a login session.
    assert client.get("/device/consent?user_code=ZZZZ-ZZZZ").status_code == 401


def test_concurrent_token_exchange_succeeds_once(client, rp_id_origin):
    rp_id, origin = rp_id_origin
    _, token = _register_and_login(client, origin, rp_id, "heidi")
    dev = _device_request(client, {"client_id": "device-public"}).json()
    client.post("/device/decision",
                headers={"Authorization": f"Bearer {token}"},
                json={"user_code": dev["user_code"], "approve": True})
    # Clear polling throttle so all threads can race at once.
    from app.config import get_settings
    from app.db import connect
    conn = connect(get_settings().db_path)
    conn.execute("UPDATE device_authorizations SET last_poll_at = 0, "
                 "interval_seconds = 5")
    conn.close()

    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": dev["device_code"], "client_id": "device-public"}
    results = []
    barrier = threading.Barrier(8)
    lock = threading.Lock()

    def fire():
        barrier.wait()
        s = client.post("/oauth/token", data=data).status_code
        with lock:
            results.append(s)

    threads = [threading.Thread(target=fire) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(200) == 1, results
