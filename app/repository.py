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
        self, credential_id: bytes, user_rowid: int, public_key: bytes
    ) -> None:
        self.conn.execute(
            "INSERT INTO credentials "
            "(credential_id, user_rowid, public_key, sign_count, created_at) "
            "VALUES (?, ?, ?, 0, ?)",
            (credential_id, user_rowid, public_key, now_ms()),
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
