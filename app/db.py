"""SQLite connection and schema management."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from typing import Iterator

from .config import get_settings


def connect(db_path: str | None = None) -> sqlite3.Connection:
    path = db_path or get_settings().db_path
    # check_same_thread=False: each request owns a private connection, while
    # BEGIN IMMEDIATE serializes write transactions across threads/processes.
    conn = sqlite3.connect(path, timeout=30, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    rowid INTEGER PRIMARY KEY AUTOINCREMENT,
    id BLOB NOT NULL UNIQUE,
    username TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    credential_id BLOB PRIMARY KEY,
    user_rowid INTEGER NOT NULL,
    public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user_rowid) REFERENCES users(rowid)
);

CREATE TABLE IF NOT EXISTS challenges (
    id BLOB PRIMARY KEY,
    user_rowid INTEGER,
    user_handle BLOB,
    username TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('register', 'login')),
    challenge BLOB NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash BLOB PRIMARY KEY,
    user_rowid INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (user_rowid) REFERENCES users(rowid)
);

CREATE INDEX IF NOT EXISTS idx_challenges_lookup
    ON challenges(username, operation, consumed);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

-- RFC 8628 device authorization requests.
CREATE TABLE IF NOT EXISTS device_authorizations (
    device_code_hash BLOB PRIMARY KEY,
    user_code_hash BLOB NOT NULL UNIQUE,
    user_code_display TEXT NOT NULL,
    client_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'denied')),
    user_rowid INTEGER,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    last_poll_at INTEGER,
    poll_interval_seconds INTEGER NOT NULL,
    decided_at INTEGER,
    revoked_at INTEGER,
    FOREIGN KEY (user_rowid) REFERENCES users(rowid)
);

CREATE INDEX IF NOT EXISTS idx_device_user_code
    ON device_authorizations(user_code_hash);
CREATE INDEX IF NOT EXISTS idx_device_user_grants
    ON device_authorizations(user_rowid, status);

-- Device access tokens: only a digest is stored, bound to the grant.
CREATE TABLE IF NOT EXISTS device_tokens (
    token_hash BLOB PRIMARY KEY,
    user_rowid INTEGER NOT NULL,
    client_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    device_code_hash BLOB NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER,
    FOREIGN KEY (user_rowid) REFERENCES users(rowid),
    FOREIGN KEY (device_code_hash) REFERENCES device_authorizations(device_code_hash)
);

CREATE INDEX IF NOT EXISTS idx_device_tokens_expiry ON device_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_device_tokens_user ON device_tokens(user_rowid);

-- Rate limiting for user_code guessing (lookup and decision endpoints).
CREATE TABLE IF NOT EXISTS user_code_rate_hits (
    source TEXT NOT NULL,
    hit_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_user_code_rate
    ON user_code_rate_hits(source, hit_at);
"""


def init_db(db_path: str | None = None) -> None:
    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA)
    finally:
        conn.close()


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    else:
        conn.commit()
