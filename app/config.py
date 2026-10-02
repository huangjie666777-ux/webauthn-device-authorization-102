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
    # RFC 8628 device authorization grant settings.
    device_client_id: str = "device-browser"
    device_client_name: str = "Browserless Device Client"
    device_allowed_scope: str = "profile"
    device_code_ttl_seconds: int = 600
    device_poll_interval_seconds: int = 5
    device_token_ttl_seconds: int = 1800
    verification_uri: str = "/device"
    # user_code lookup rate limiting: max failed lookups per window/source.
    user_code_rate_limit: int = 5
    user_code_rate_window_seconds: int = 300


def get_settings() -> Settings:
    return Settings(
        rp_id=_env("WEBAUTHN_RP_ID", "localhost"),
        rp_name=_env("WEBAUTHN_RP_NAME", "WebAuthn Demo"),
        origin=_env("WEBAUTHN_ORIGIN", "http://localhost:8000"),
        db_path=_env("WEBAUTHN_DB", os.path.join(os.getcwd(), "webauthn.sqlite")),
        device_client_id=_env("OAUTH_DEVICE_CLIENT_ID", "device-browser"),
        device_client_name=_env("OAUTH_DEVICE_CLIENT_NAME", "Browserless Device Client"),
        device_allowed_scope=_env("OAUTH_DEVICE_ALLOWED_SCOPE", "profile"),
        verification_uri=_env("OAUTH_VERIFICATION_URI", "/device"),
    )
