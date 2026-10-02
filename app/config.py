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
    device_code_ttl_seconds: int = 600
    device_poll_interval_seconds: int = 5
    device_token_ttl_seconds: int = 1800
    device_client_id: str = "device-public"
    device_client_name: str = "Device Client (Public)"
    device_client_scopes: str = "profile"
    user_code_max_attempts: int = 5
    user_code_window_seconds: int = 600


def get_settings() -> Settings:
    return Settings(
        rp_id=_env("WEBAUTHN_RP_ID", "localhost"),
        rp_name=_env("WEBAUTHN_RP_NAME", "WebAuthn Demo"),
        origin=_env("WEBAUTHN_ORIGIN", "http://localhost:8000"),
        db_path=_env("WEBAUTHN_DB", os.path.join(os.getcwd(), "webauthn.sqlite")),
        device_code_ttl_seconds=int(_env("OAUTH_DEVICE_CODE_TTL", "600")),
        device_poll_interval_seconds=int(_env("OAUTH_DEVICE_INTERVAL", "5")),
        device_token_ttl_seconds=int(_env("OAUTH_DEVICE_TOKEN_TTL", "1800")),
        device_client_id=_env("OAUTH_DEVICE_CLIENT_ID", "device-public"),
        device_client_name=_env("OAUTH_DEVICE_CLIENT_NAME", "Device Client (Public)"),
        device_client_scopes=_env("OAUTH_DEVICE_CLIENT_SCOPES", "profile"),
        user_code_max_attempts=int(_env("OAUTH_USER_CODE_MAX_ATTEMPTS", "5")),
        user_code_window_seconds=int(_env("OAUTH_USER_CODE_WINDOW", "600")),
    )


class OAuthClient:
    def __init__(self, client_id: str, name: str, scopes: frozenset[str]) -> None:
        self.client_id = client_id
        self.name = name
        self.scopes = scopes

    def allows(self, scopes: list[str]) -> bool:
        return bool(scopes) and set(scopes) <= self.scopes


def get_public_device_client(settings: Settings | None = None) -> OAuthClient:
    settings = settings or get_settings()
    scopes = frozenset(
        s for s in settings.device_client_scopes.split() if s
    ) or frozenset({"profile"})
    return OAuthClient(settings.device_client_id, settings.device_client_name, scopes)
