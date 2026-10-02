"""Regression: initial sign_count persistence; device flow survives restart."""

from __future__ import annotations

import time

from fastapi.testclient import TestClient

from app.config import get_settings
from app.db import connect
from tests.soft_authenticator import SoftAuthenticator


def test_initial_sign_count_is_persisted(client, rp_id_origin):
    rp_id, origin = rp_id_origin
    auth = SoftAuthenticator(rp_id, sign_count_start=7)
    opts = client.post("/register/options", json={"username": "sam"}).json()
    body = auth.register(opts, origin)
    assert client.post("/register/finish", json=body).status_code == 200

    conn = connect(get_settings().db_path)
    row = conn.execute("SELECT sign_count FROM credentials").fetchone()
    conn.close()
    assert row["sign_count"] == 7


def test_device_authorization_survives_restart(client, rp_id_origin):
    rp_id, origin = rp_id_origin
    auth = SoftAuthenticator(rp_id)
    opts = client.post("/register/options", json={"username": "nora"}).json()
    client.post("/register/finish", json=auth.register(opts, origin))
    lo = client.post("/login/options", json={"username": "nora"}).json()
    token = client.post(
        "/login/finish",
        json=auth.login("nora", lo, opts["user"]["id"], origin),
    ).json()["token"]

    dev = client.post("/oauth/device_authorization",
                      data={"client_id": "device-public"}).json()

    # Simulate a server restart: a fresh TestClient/app instance on the same DB.
    from importlib import reload
    import app.config as config
    import app.db as db
    import app.service as service
    import app.device_service as device_service
    import app.http_api as http_api
    reload(config)
    reload(db)
    reload(service)
    reload(device_service)
    reload(http_api)
    with TestClient(http_api.app) as c2:
        r = c2.post("/device/decision",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"user_code": dev["user_code"], "approve": True})
        assert r.status_code == 200 and r.json()["status"] == "approved"
        time.sleep(5.01)
        r = c2.post("/oauth/token", data={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": dev["device_code"],
            "client_id": "device-public"})
        assert r.status_code == 200, r.text
        access = r.json()["access_token"]
        assert c2.get("/oauth/profile",
                     headers={"Authorization": f"Bearer {access}"}).status_code == 200
