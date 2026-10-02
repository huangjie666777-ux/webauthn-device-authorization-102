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
            "SELECT u.username, u.id AS user_id, s.expires_at "
            "FROM sessions s JOIN users u ON u.rowid = s.user_rowid "
            "WHERE s.token_hash = ? AND s.expires_at > ?",
            (token_hash, now_ms()),
        ).fetchone()

    def delete_session(self, token_hash: bytes) -> None:
        self.conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))

    def purge_expired(self) -> None:
        self.conn.execute("DELETE FROM challenges WHERE expires_at <= ?", (now_ms(),))
        self.conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now_ms(),))
        self.conn.execute(
            "DELETE FROM user_code_rate_hits WHERE hit_at < ?",
            (now_ms() - 300 * 1000,),
        )

    # ---- RFC 8628 device authorization grant ----

    def insert_device_authorization(
        self,
        device_code_hash: bytes,
        user_code_hash: bytes,
        user_code_display: str,
        client_id: str,
        scope: str,
        ttl_seconds: int,
        poll_interval_seconds: int,
    ) -> None:
        ts = now_ms()
        self.conn.execute(
            "INSERT INTO device_authorizations "
            "(device_code_hash, user_code_hash, user_code_display, client_id, scope, "
            " status, created_at, expires_at, poll_interval_seconds) "
            "VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?)",
            (
                device_code_hash,
                user_code_hash,
                user_code_display,
                client_id,
                scope,
                ts,
                ts + ttl_seconds * 1000,
                poll_interval_seconds,
            ),
        )

    def get_device_authorization_by_user_code(
        self, user_code_hash: bytes
    ) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM device_authorizations WHERE user_code_hash = ?",
            (user_code_hash,),
        ).fetchone()

    def get_device_authorization(self, device_code_hash: bytes) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM device_authorizations WHERE device_code_hash = ?",
            (device_code_hash,),
        ).fetchone()

    def approve_device_authorization(
        self, user_code_hash: bytes, user_rowid: int
    ) -> sqlite3.Row | None:
        """Move a pending, unrevoked authorization to approved. Terminal otherwise."""
        cur = self.conn.execute(
            "UPDATE device_authorizations "
            "SET status = 'approved', user_rowid = ?, decided_at = ? "
            "WHERE user_code_hash = ? AND status = 'pending' "
            "  AND revoked_at IS NULL AND expires_at > ? "
            "RETURNING device_code_hash, status",
            (user_rowid, now_ms(), user_code_hash, now_ms()),
        )
        return cur.fetchone()

    def deny_device_authorization(self, user_code_hash: bytes) -> sqlite3.Row | None:
        cur = self.conn.execute(
            "UPDATE device_authorizations "
            "SET status = 'denied', decided_at = ? "
            "WHERE user_code_hash = ? AND status = 'pending' "
            "  AND revoked_at IS NULL AND expires_at > ? "
            "RETURNING device_code_hash, status",
            (now_ms(), user_code_hash, now_ms()),
        )
        return cur.fetchone()

    def touch_device_poll(
        self, device_code_hash: bytes, polled_at_ms: int, interval_seconds: int
    ) -> None:
        self.conn.execute(
            "UPDATE device_authorizations "
            "SET last_poll_at = ?, poll_interval_seconds = ? "
            "WHERE device_code_hash = ?",
            (polled_at_ms, interval_seconds, device_code_hash),
        )

    def insert_device_token(
        self,
        token_hash: bytes,
        user_rowid: int,
        client_id: str,
        scope: str,
        device_code_hash: bytes,
        ttl_seconds: int,
    ) -> None:
        ts = now_ms()
        self.conn.execute(
            "INSERT INTO device_tokens "
            "(token_hash, user_rowid, client_id, scope, device_code_hash, "
            " expires_at, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                token_hash,
                user_rowid,
                client_id,
                scope,
                device_code_hash,
                ts + ttl_seconds * 1000,
                ts,
            ),
        )

    def get_device_token(self, token_hash: bytes) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT t.user_rowid, t.client_id, t.scope, t.expires_at, "
            "       t.revoked_at, u.username, u.id AS user_id, "
            "       a.revoked_at AS grant_revoked_at "
            "FROM device_tokens t "
            "JOIN users u ON u.rowid = t.user_rowid "
            "JOIN device_authorizations a ON a.device_code_hash = t.device_code_hash "
            "WHERE t.token_hash = ?",
            (token_hash,),
        ).fetchone()

    def list_user_device_grants(self, user_rowid: int) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                "SELECT a.user_code_display, a.client_id, a.scope, a.status, "
                "       a.created_at, a.expires_at, a.decided_at, a.revoked_at, "
                "       t.expires_at AS token_expires_at, "
                "       t.revoked_at AS token_revoked_at, "
                "       (a.status = 'approved' AND a.revoked_at IS NULL "
                "        AND (t.rowid IS NULL OR (t.revoked_at IS NULL "
                "             AND t.expires_at > ?))) AS active "
                "FROM device_authorizations a "
                "LEFT JOIN device_tokens t ON t.device_code_hash = a.device_code_hash "
                "WHERE a.user_rowid = ? ORDER BY a.created_at DESC",
                (now_ms(), user_rowid),
            )
        )

    def revoke_user_device_grant(self, user_rowid: int, user_code_hash: bytes) -> bool:
        """Revoke one of the user's grants and any token bound to it. One tx."""
        ts = now_ms()
        cur = self.conn.execute(
            "UPDATE device_authorizations SET revoked_at = ? "
            "WHERE user_code_hash = ? AND user_rowid = ? AND revoked_at IS NULL "
            "RETURNING device_code_hash",
            (ts, user_code_hash, user_rowid),
        )
        row = cur.fetchone()
        if row is None:
            return False
        self.conn.execute(
            "UPDATE device_tokens SET revoked_at = ? WHERE device_code_hash = ?",
            (ts, row["device_code_hash"]),
        )
        return True

    # ---- user_code lookup rate limiting ----

    def rate_limit_check_and_record(
        self, source: str, limit: int, window_seconds: int
    ) -> tuple[bool, int]:
        """Register one failed lookup. Returns (allowed, retry_after_seconds)."""
        ts = now_ms()
        window_start = ts - window_seconds * 1000
        self.conn.execute(
            "DELETE FROM user_code_rate_hits WHERE source = ? AND hit_at < ?",
            (source, window_start),
        )
        count_row = self.conn.execute(
            "SELECT COUNT(*) AS n, MIN(hit_at) AS oldest "
            "FROM user_code_rate_hits WHERE source = ? AND hit_at >= ?",
            (source, window_start),
        ).fetchone()
        count = int(count_row["n"])
        if count >= limit:
            oldest = int(count_row["oldest"])
            retry_after = max(
                1, (oldest + window_seconds * 1000 - ts + 999) // 1000
            )
            return False, int(retry_after)
        self.conn.execute(
            "INSERT INTO user_code_rate_hits (source, hit_at) VALUES (?, ?)",
            (source, ts),
        )
        return True, 0

    def rate_limit_reset(self, source: str) -> None:
        self.conn.execute(
            "DELETE FROM user_code_rate_hits WHERE source = ?", (source,)
        )
