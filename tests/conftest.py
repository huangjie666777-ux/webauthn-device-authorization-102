from __future__ import annotations

import os
import tempfile

import pytest

# Fixed server-side RP configuration for the whole test suite.
os.environ["WEBAUTHN_RP_ID"] = "localhost"
os.environ["WEBAUTHN_ORIGIN"] = "http://localhost:8000"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db = tmp_path / "test.sqlite"
    monkeypatch.setenv("WEBAUTHN_DB", str(db))
    from fastapi.testclient import TestClient
    from app.http_api import app
    from app.db import init_db
    init_db(str(db))
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def rp_id_origin():
    return "localhost", "http://localhost:8000"
