"""OAuth 2.0 Device Authorization Grant (RFC 8628) services."""

from __future__ import annotations

import hashlib
import secrets

from .config import OAuthClient, Settings, get_public_device_client
from .db import transaction
from .repository import Repo, now_ms
from .service import FinishError, hash_token
from .webauthn import b64url_encode


class OAuthError(Exception):
    """Error carrying an RFC 6749/8628 error code and HTTP status."""

    def __init__(self, code: str, status_code: int = 400, message: str | None = None) -> None:
        super().__init__(message or code)
        self.code = code
        self.status_code = status_code


_USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ"


def _generate_user_code() -> str:
    raw = "".join(secrets.choice(_USER_CODE_ALPHABET) for _ in range(8))
    return f"{raw[:4]}-{raw[4:]}"


class DeviceService:
    def __init__(self, conn, settings: Settings) -> None:
        self.conn = conn
        self.settings = settings
        self.client = get_public_device_client(settings)

    def _validate_client(self, client_id: str | None) -> OAuthClient:
        if not client_id or client_id != self.client.client_id:
            raise OAuthError("invalid_client", 401, "unknown client")
        return self.client

    @staticmethod
    def _parse_scope(scope: str | None) -> list[str]:
        if scope is None:
            return []
        return [s for s in scope.split() if s]

    # ---- device endpoint: /oauth/device_authorization ----

    def authorize_device(self, client_id: str | None, scope: str | None) -> dict:
        client = self._validate_client(client_id)
        scopes = self._parse_scope(scope)
        if scope is None:
            # Omitted scope: use the client's registered default scopes.
            scopes = sorted(client.scopes)
        elif not client.allows(scopes):
            raise OAuthError("invalid_scope", 400, "only the profile scope is allowed")

        device_code = secrets.token_urlsafe(32)
        device_code_hash = hashlib.sha256(device_code.encode()).digest()
        for _ in range(10):
            user_code = _generate_user_code()
            try:
                with transaction(self.conn) as c:
                    Repo(c).create_device_authorization(
                        device_code_hash=device_code_hash,
                        user_code=user_code,
                        client_id=client.client_id,
                        scope=" ".join(scopes),
                        ttl_seconds=self.settings.device_code_ttl_seconds,
                        interval_seconds=self.settings.device_poll_interval_seconds,
                    )
                break
            except Exception:
                # Vanishingly unlikely user-code collision; retry with a fresh code.
                continue
        else:
            raise FinishError("could not allocate user code, try again", 503)

        return {
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": "/device",
            "verification_uri_complete": f"/device?user_code={user_code}",
            "expires_in": self.settings.device_code_ttl_seconds,
            "interval": self.settings.device_poll_interval_seconds,
        }

    # ---- user consent endpoints (login session required) ----

    def _check_user_code_rate_limit(self, repo: Repo, user_code: str) -> None:
        attempts = repo.count_user_code_attempts(
            user_code, self.settings.user_code_window_seconds
        )
        if attempts >= self.settings.user_code_max_attempts:
            raise OAuthError(
                "access_denied", 429, "too many attempts for this user code"
            )
        repo.purge_old_user_code_attempts(self.settings.user_code_window_seconds)

    def lookup_user_code(self, user_code: str) -> dict:
        normalized = self._normalize_user_code(user_code)
        # Persist the failed/successful guess before any later error would
        # roll the bookkeeping back; rate limiting must survive raises.
        with transaction(self.conn) as c:
            repo = Repo(c)
            self._check_user_code_rate_limit(repo, normalized)
            repo.record_user_code_attempt(normalized)
        with transaction(self.conn) as c:
            repo = Repo(c)
            row = repo.find_active_device_authorization_by_user_code(normalized)
            if row is None:
                raise OAuthError("access_denied", 404, "user code not found or expired")
            # A lookup never grants consent; terminal status is reported, not changed.
            return {
                "user_code": row["user_code"],
                "client_id": row["client_id"],
                "client_name": self.client.name,
                "scope": row["scope"],
                "status": row["status"],
                "expires_in": max(
                    0, (row["expires_at"] - now_ms() + 999) // 1000
                ),
            }

    def decide_user_code(self, user_code: str, approve: bool, user_rowid: int) -> dict:
        normalized = self._normalize_user_code(user_code)
        with transaction(self.conn) as c:
            repo = Repo(c)
            row = repo.find_active_device_authorization_by_user_code(normalized)
            if row is None:
                raise OAuthError("access_denied", 404, "user code not found or expired")
            if row["status"] != "pending":
                # Terminal decisions (approved/denied/consumed) cannot be overwritten.
                return {"user_code": normalized, "status": row["status"]}
            changed = repo.set_device_authorization_decision(
                normalized, approve, user_rowid
            )
            if not changed:
                row = repo.find_active_device_authorization_by_user_code(normalized)
                status = row["status"] if row is not None else "expired"
                return {"user_code": normalized, "status": status}
        return {
            "user_code": normalized,
            "status": "approved" if approve else "denied",
        }

    @staticmethod
    def _normalize_user_code(user_code: str) -> str:
        if not isinstance(user_code, str):
            raise OAuthError("invalid_request", 400, "user_code required")
        chars = user_code.strip().upper().replace(" ", "")
        if len(chars) != 9 or chars[4] != "-":
            raise OAuthError("invalid_request", 400, "malformed user code")
        head, tail = chars.split("-")
        if not all(ch in _USER_CODE_ALPHABET for ch in head + tail):
            raise OAuthError("invalid_request", 400, "malformed user code")
        return f"{head}-{tail}"

    # ---- token endpoint: /oauth/token ----

    def poll_token(self, grant_type: str | None, device_code: str | None,
                   client_id: str | None) -> dict:
        if grant_type != "urn:ietf:params:oauth:grant-type:device_code":
            raise OAuthError("unsupported_grant_type", 400)
        self._validate_client(client_id)
        if not device_code:
            raise OAuthError("invalid_request", 400, "device_code required")
        device_code_hash = hashlib.sha256(device_code.encode()).digest()

        # Phase 1: read state and persist any interval bookkeeping in its own
        # transaction so it survives the subsequent RFC 8628 error response.
        with transaction(self.conn) as c:
            repo = Repo(c)
            row = repo.get_device_authorization_by_device_code(device_code_hash)
            if row is None:
                raise OAuthError("invalid_grant", 400, "unknown device code")
            status, interval, last_poll, expires_at = (
                row["status"],
                row["interval_seconds"],
                row["last_poll_at"],
                row["expires_at"],
            )

        now = now_ms()
        if expires_at <= now:
            raise OAuthError("expired_token", 400, "device code expired")
        if status == "denied":
            raise OAuthError("access_denied", 400, "user denied the request")
        if status == "consumed":
            raise OAuthError("invalid_grant", 400, "device code already used")

        if status in ("pending", "approved"):
            interval_ms = interval * 1000
            if last_poll != 0 and last_poll + interval_ms > now:
                new_interval = interval + 5
                with transaction(self.conn) as c:
                    Repo(c).touch_poll(device_code_hash, new_interval)
                raise OAuthError("slow_down", 400, "polling too frequently")

        if status == "pending":
            # Timely poll: record it, then keep waiting for user approval.
            with transaction(self.conn) as c:
                Repo(c).touch_poll(device_code_hash, interval)
            raise OAuthError("authorization_pending", 400, "awaiting user approval")

        # Phase 2 (approved): consume code and write the token atomically.
        with transaction(self.conn) as c:
            repo = Repo(c)
            consumed = repo.consume_device_authorization(device_code_hash)
            if consumed is None:
                raise OAuthError("invalid_grant", 400, "device code not exchangeable")

            token = secrets.token_urlsafe(32)
            repo.create_device_grant(
                user_rowid=consumed["user_rowid"],
                client_id=consumed["client_id"],
                scope=consumed["scope"],
                token_hash=hash_token(token),
                device_code_hash=device_code_hash,
                ttl_seconds=self.settings.device_token_ttl_seconds,
            )

        return {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": self.settings.device_token_ttl_seconds,
            "scope": consumed["scope"],
        }

    # ---- device token usage and grant management ----

    def device_profile(self, token: str) -> dict:
        with transaction(self.conn) as c:
            row = Repo(c).active_device_grant_for_token(hash_token(token))
        if row is None:
            raise FinishError("invalid or expired device token", 401)
        scopes = set(row["scope"].split())
        if "profile" not in scopes:
            raise FinishError("insufficient scope", 403)
        return {
            "username": row["username"],
            "userId": b64url_encode(row["user_id"]),
            "client_id": row["client_id"],
            "scope": row["scope"],
        }

    def list_grants(self, user_rowid: int) -> list[dict]:
        with transaction(self.conn) as c:
            rows = Repo(c).list_device_grants_for_user(user_rowid)
        return [
            {
                "id": row["rid"],
                "client_id": row["client_id"],
                "scope": row["scope"],
                "created_at": row["created_at"],
                "expires_at": row["expires_at"],
                "revoked": bool(row["revoked"]),
            }
            for row in rows
        ]

    def revoke_grant(self, grant_id: int, user_rowid: int) -> bool:
        with transaction(self.conn) as c:
            return Repo(c).revoke_device_grant(grant_id, user_rowid)
