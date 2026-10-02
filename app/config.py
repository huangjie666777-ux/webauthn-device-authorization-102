"""Server-side configuration. RP ID and origin never come from requests."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _env(name: str, default: str) -> str:
    value = os.environ.get(name)
    return value if value else default


@dataclass(frozen=True)
class Settings:
    rp_id: str
    rp_name: str
    origin: str
    db_path: str
    challenge_ttl_seconds: int = 300
    token_ttl_seconds: int = 1800


def get_settings() -> Settings:
    return Settings(
        rp_id=_env("WEBAUTHN_RP_ID", "localhost"),
        rp_name=_env("WEBAUTHN_RP_NAME", "WebAuthn Demo"),
        origin=_env("WEBAUTHN_ORIGIN", "http://localhost:8000"),
        db_path=_env("WEBAUTHN_DB", os.path.join(os.getcwd(), "webauthn.sqlite")),
    )
