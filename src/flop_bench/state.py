from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_VERSION = 1


def connect_state(state_dir: Path) -> sqlite3.Connection:
    state_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(state_dir / "state.sqlite")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
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
            INSERT INTO schema_migrations(version) VALUES (1);
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
