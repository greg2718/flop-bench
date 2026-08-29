from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .exceptions import SafetyError

SCHEMA_VERSION = 2


def connect_state(state_dir: Path) -> sqlite3.Connection:
    state_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(state_dir / "state.sqlite")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    migrate(conn)
    return conn


def migrate(conn: sqlite3.Connection) -> None:
    conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)")
    current = conn.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").fetchone()[0]
    if current < 1:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id TEXT NOT NULL UNIQUE,
                claim_id TEXT NOT NULL,
                result TEXT NOT NULL,
                evidence_path TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            INSERT OR IGNORE INTO schema_migrations(version) VALUES (1);
            """
        )
    if current < 2:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS bench_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL UNIQUE,
                sender_did TEXT NOT NULL,
                nonce INTEGER NOT NULL UNIQUE,
                received_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                processing_status TEXT NOT NULL,
                evidence_id TEXT,
                response_status TEXT
            );
            INSERT OR IGNORE INTO schema_migrations(version) VALUES (2);
            """
        )
    conn.commit()


def insert_run(
    conn: sqlite3.Connection,
    *,
    evidence_id: str,
    claim_id: str,
    result: str,
    evidence_path: Path,
    created_at: str,
) -> None:
    conn.execute(
        """
        INSERT OR REPLACE INTO runs(evidence_id, claim_id, result, evidence_path, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (evidence_id, claim_id, result, str(evidence_path), created_at),
    )
    conn.commit()


def reserve_request(
    conn: sqlite3.Connection,
    *,
    request_id: str,
    sender_did: str,
    nonce: int,
    expires_at: str,
) -> dict[str, Any]:
    received_at = datetime.now(UTC).isoformat()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """
            INSERT INTO bench_requests(
                request_id, sender_did, nonce, received_at, expires_at,
                processing_status, evidence_id, response_status
            )
            VALUES (?, ?, ?, ?, ?, 'verified', NULL, NULL)
            """,
            (request_id, sender_did, nonce, received_at, expires_at),
        )
        conn.commit()
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        raise SafetyError("duplicate request_id or nonce refused by replay protection") from exc
    except sqlite3.Error:
        conn.rollback()
        raise
    return {
        "request_id": request_id,
        "sender_did": sender_did,
        "nonce": nonce,
        "received_at": received_at,
        "expires_at": expires_at,
        "processing_status": "verified",
        "evidence_id": None,
        "response_status": None,
    }
