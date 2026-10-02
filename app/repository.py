"""Transactional persistence helpers for users, credentials, challenges, sessions."""

from __future__ import annotations

import sqlite3
import time


def now_ms() -> int:
    return int(time.time() * 1000)


class UserExistsError(Exception):
    pass


class Repo:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def find_user_by_name(self, username: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT rowid AS rid, id, username FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    def create_user(self, user_id: bytes, username: str) -> int:
        try:
            cur = self.conn.execute(
                "INSERT INTO users (id, username, created_at) VALUES (?, ?, ?)",
                (user_id, username, now_ms()),
            )
        except sqlite3.IntegrityError as exc:
            raise UserExistsError(username) from exc
        return int(cur.lastrowid)

    def add_credential(
        self,
        credential_id: bytes,
        user_rowid: int,
        public_key: bytes,
        sign_count: int = 0,
    ) -> None:
        self.conn.execute(
            "INSERT INTO credentials "
            "(credential_id, user_rowid, public_key, sign_count, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (credential_id, user_rowid, public_key, sign_count, now_ms()),
        )

    def credential_belonging_to_user(
        self, username: str, credential_id: bytes
    ) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT c.credential_id, c.public_key, c.sign_count, c.user_rowid, u.username "
            "FROM credentials c JOIN users u ON u.rowid = c.user_rowid "
            "WHERE u.username = ? AND c.credential_id = ?",
            (username, credential_id),
        ).fetchone()

    def list_credentials_for_user(self, user_rowid: int) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                "SELECT credential_id FROM credentials WHERE user_rowid = ?",
                (user_rowid,),
            )
        )

    def store_challenge(
        self,
        challenge_id: bytes,
        username: str,
        operation: str,
        challenge: bytes,
        ttl_seconds: int,
        user_rowid: int | None = None,
        user_handle: bytes | None = None,
    ) -> None:
        self.conn.execute(
            "INSERT INTO challenges "
            "(id, user_rowid, user_handle, username, operation, challenge, expires_at, consumed) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
            (
                challenge_id,
                user_rowid,
                user_handle,
                username,
                operation,
                challenge,
                now_ms() + ttl_seconds * 1000,
            ),
        )

    def take_challenge(
        self, username: str, operation: str, challenge: bytes
    ) -> sqlite3.Row | None:
        """Atomically consume one matching, unexpired challenge.

        Returns None if no valid challenge exists. Concurrent callers can at most
        # succeed once because the UPDATE ... WHERE consumed=0 is atomic.
        """
        cur = self.conn.execute(
            "UPDATE challenges SET consumed = 1 "
            "WHERE id = ("
            "  SELECT id FROM challenges "
            "  WHERE username = ? AND operation = ? AND challenge = ? "
            "    AND consumed = 0 AND expires_at > ? "
            "  ORDER BY expires_at DESC LIMIT 1"
            ") RETURNING id, user_rowid, user_handle",
            (username, operation, challenge, now_ms()),
        )
        return cur.fetchone()

    def bump_sign_count(self, credential_id: bytes, new_count: int) -> None:
        self.conn.execute(
            "UPDATE credentials SET sign_count = ? WHERE credential_id = ?",
            (new_count, credential_id),
        )

    def create_session(self, token_hash: bytes, user_rowid: int, ttl_seconds: int) -> None:
        self.conn.execute(
            "INSERT INTO sessions (token_hash, user_rowid, expires_at) VALUES (?, ?, ?)",
            (token_hash, user_rowid, now_ms() + ttl_seconds * 1000),
        )

    def session_user(self, token_hash: bytes) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT u.rowid AS rid, u.username, u.id AS user_id, s.expires_at "
            "FROM sessions s JOIN users u ON u.rowid = s.user_rowid "
            "WHERE s.token_hash = ? AND s.expires_at > ?",
            (token_hash, now_ms()),
        ).fetchone()

    def delete_session(self, token_hash: bytes) -> None:
        self.conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))

    def purge_expired(self) -> None:
        self.conn.execute("DELETE FROM challenges WHERE expires_at <= ?", (now_ms(),))
        self.conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now_ms(),))

    # ---- OAuth 2.0 device authorization grant ----

    def create_device_authorization(
        self,
        device_code_hash: bytes,
        user_code: str,
        client_id: str,
        scope: str,
        ttl_seconds: int,
        interval_seconds: int,
    ) -> None:
        now = now_ms()
        self.conn.execute(
            "INSERT INTO device_authorizations "
            "(device_code_hash, user_code, client_id, scope, status, "
            " expires_at, created_at, interval_seconds, last_poll_at) "
            "VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, 0)",
            (
                device_code_hash,
                user_code,
                client_id,
                scope,
                now + ttl_seconds * 1000,
                now,
                interval_seconds,
            ),
        )

    def get_device_authorization_by_device_code(
        self, device_code_hash: bytes
    ) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM device_authorizations WHERE device_code_hash = ?",
            (device_code_hash,),
        ).fetchone()

    def find_active_device_authorization_by_user_code(
        self, user_code: str
    ) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM device_authorizations "
            "WHERE user_code = ? AND expires_at > ?",
            (user_code, now_ms()),
        ).fetchone()

    def set_device_authorization_decision(
        self,
        user_code: str,
        approved: bool,
        user_rowid: int,
    ) -> bool:
        """Approve/deny only a pending, unexpired request. Terminal states win."""
        status = "approved" if approved else "denied"
        cur = self.conn.execute(
            "UPDATE device_authorizations "
            "SET status = ?, user_rowid = ?, approved_at = ? "
            "WHERE user_code = ? AND status = 'pending' AND expires_at > ?",
            (status, user_rowid, now_ms(), user_code, now_ms()),
        )
        return cur.rowcount == 1

    def touch_poll(self, device_code_hash: bytes, interval_seconds: int) -> None:
        self.conn.execute(
            "UPDATE device_authorizations SET last_poll_at = ?, interval_seconds = ? "
            "WHERE device_code_hash = ?",
            (now_ms(), interval_seconds, device_code_hash),
        )

    def consume_device_authorization(self, device_code_hash: bytes) -> sqlite3.Row | None:
        """Atomically flip approved -> consumed; only one poll can succeed."""
        cur = self.conn.execute(
            "UPDATE device_authorizations SET status = 'consumed' "
            "WHERE device_code_hash = ? AND status = 'approved' "
            "  AND expires_at > ? RETURNING device_code_hash, user_rowid, client_id, scope",
            (device_code_hash, now_ms()),
        )
        return cur.fetchone()

    def create_device_grant(
        self,
        user_rowid: int,
        client_id: str,
        scope: str,
        token_hash: bytes,
        device_code_hash: bytes,
        ttl_seconds: int,
    ) -> None:
        self.conn.execute(
            "INSERT INTO device_grants "
            "(user_rowid, client_id, scope, token_hash, expires_at, "
            " created_at, revoked, device_code_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
            (
                user_rowid,
                client_id,
                scope,
                token_hash,
                now_ms() + ttl_seconds * 1000,
                now_ms(),
                device_code_hash,
            ),
        )

    def active_device_grant_for_token(self, token_hash: bytes) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT g.rowid AS rid, g.user_rowid, g.client_id, g.scope, "
            "       u.username, u.id AS user_id, g.expires_at "
            "FROM device_grants g JOIN users u ON u.rowid = g.user_rowid "
            "WHERE g.token_hash = ? AND g.revoked = 0 AND g.expires_at > ?",
            (token_hash, now_ms()),
        ).fetchone()

    def list_device_grants_for_user(self, user_rowid: int) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                "SELECT rowid AS rid, client_id, scope, created_at, expires_at, revoked "
                "FROM device_grants WHERE user_rowid = ? ORDER BY created_at DESC",
                (user_rowid,),
            )
        )

    def revoke_device_grant(self, grant_rowid: int, user_rowid: int) -> bool:
        cur = self.conn.execute(
            "UPDATE device_grants SET revoked = 1 "
            "WHERE rowid = ? AND user_rowid = ?",
            (grant_rowid, user_rowid),
        )
        return cur.rowcount == 1

    def record_user_code_attempt(self, user_code: str) -> None:
        self.conn.execute(
            "INSERT INTO user_code_attempts (user_code, attempted_at) VALUES (?, ?)",
            (user_code, now_ms()),
        )

    def count_user_code_attempts(self, user_code: str, window_seconds: int) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS n FROM user_code_attempts "
            "WHERE user_code = ? AND attempted_at > ?",
            (user_code, now_ms() - window_seconds * 1000),
        ).fetchone()
        return int(row["n"])

    def purge_old_user_code_attempts(self, window_seconds: int) -> None:
        self.conn.execute(
            "DELETE FROM user_code_attempts WHERE attempted_at <= ?",
            (now_ms() - window_seconds * 1000,),
        )
