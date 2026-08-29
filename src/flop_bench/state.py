from __future__ import annotations

import os
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .exceptions import SafetyError

SCHEMA_VERSION = 4
STATE_DB = "state.sqlite"
PRIVATE_FILE_MODE = 0o600
PRIVATE_DIR_MODE = 0o700
PRIVATE_STATE_FILENAMES = (
    STATE_DB,
    f"{STATE_DB}-wal",
    f"{STATE_DB}-shm",
    "ledger.jsonl",
    "observer.sqlite",
    "activity.jsonl",
)


def private_state_paths(state_dir: Path) -> list[Path]:
    return [state_dir / filename for filename in PRIVATE_STATE_FILENAMES]


def ensure_private_state_permissions(state_dir: Path) -> None:
    if state_dir.exists():
        state_dir.chmod(PRIVATE_DIR_MODE)
    for path in private_state_paths(state_dir):
        if path.exists():
            path.chmod(PRIVATE_FILE_MODE)


def permission_issues(state_dir: Path) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    resolved = state_dir.expanduser().resolve(strict=False)
    for path in private_state_paths(resolved):
        if not path.exists():
            continue
        mode = path.stat().st_mode & 0o777
        if mode != PRIVATE_FILE_MODE:
            issues.append(
                {
                    "path": str(path),
                    "mode": f"{mode:04o}",
                    "expected_mode": f"{PRIVATE_FILE_MODE:04o}",
                }
            )
    return issues


def precreate_private_file(path: Path) -> None:
    if path.exists():
        path.chmod(PRIVATE_FILE_MODE)
        return
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, PRIVATE_FILE_MODE)
    except FileExistsError:
        path.chmod(PRIVATE_FILE_MODE)
        return
    os.close(fd)


def connect_state(state_dir: Path) -> sqlite3.Connection:
    conn, _applied = connect_state_with_migrations(state_dir)
    return conn


def connect_state_with_migrations(state_dir: Path) -> tuple[sqlite3.Connection, list[int]]:
    state_dir.mkdir(parents=True, exist_ok=True)
    state_dir.chmod(PRIVATE_DIR_MODE)
    precreate_private_file(state_dir / STATE_DB)
    precreate_private_file(state_dir / f"{STATE_DB}-wal")
    precreate_private_file(state_dir / f"{STATE_DB}-shm")
    deadline = time.monotonic() + 10.0
    while True:
        conn = sqlite3.connect(state_dir / STATE_DB, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA busy_timeout = 10000")
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            applied = migrate(conn)
            ensure_private_state_permissions(state_dir)
            return conn, applied
        except sqlite3.OperationalError as exc:
            conn.close()
            if "locked" not in str(exc).casefold() or time.monotonic() >= deadline:
                raise
            time.sleep(0.05)


def migration_status(state_dir: Path) -> dict[str, Any]:
    resolved = state_dir.expanduser().resolve(strict=False)
    db_path = resolved / STATE_DB
    if not resolved.exists() or not db_path.exists():
        return {
            "state_dir_exists": resolved.exists(),
            "database_exists": False,
            "schema_migrations": [],
            "pending_migrations": list(range(1, SCHEMA_VERSION + 1)),
            "permission_issues": permission_issues(resolved),
        }
    uri = f"file:{db_path.as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        table_exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'"
        ).fetchone()
        if table_exists is None:
            migrations: list[int] = []
        else:
            migrations = [
                int(row[0])
                for row in conn.execute("SELECT version FROM schema_migrations ORDER BY version")
            ]
    applied = set(migrations)
    pending = [version for version in range(1, SCHEMA_VERSION + 1) if version not in applied]
    return {
        "state_dir_exists": True,
        "database_exists": True,
        "schema_migrations": migrations,
        "pending_migrations": pending,
        "permission_issues": permission_issues(resolved),
    }


def activation_history(state_dir: Path, *, limit: int) -> dict[str, Any]:
    if limit < 1 or limit > 100:
        raise SafetyError("activation history limit must be between 1 and 100")
    resolved = state_dir.expanduser().resolve(strict=False)
    status = migration_status(resolved)
    if not status["database_exists"]:
        return {
            "ok": True,
            "state_dir": str(resolved),
            "state_write": False,
            "network_action": False,
            "limit": limit,
            "activations": [],
            "permission_issues": status["permission_issues"],
        }
    uri = f"file:{(resolved / STATE_DB).as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        conn.row_factory = sqlite3.Row
        table_exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'service_activations'"
        ).fetchone()
        if table_exists is None:
            rows: list[sqlite3.Row] = []
        else:
            rows = list(
                conn.execute(
                    """
                    SELECT id, service_type, service_name, expected_owner_did,
                           observed_owner_did, activation_status, request_timestamp,
                           response_status, nonce_used, failure_classification
                    FROM service_activations
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                )
            )
    return {
        "ok": True,
        "state_dir": str(resolved),
        "state_write": False,
        "network_action": False,
        "limit": limit,
        "activations": [dict(row) for row in rows],
        "permission_issues": status["permission_issues"],
    }


def post_history(state_dir: Path, *, limit: int) -> dict[str, Any]:
    if limit < 1 or limit > 100:
        raise SafetyError("post history limit must be between 1 and 100")
    resolved = state_dir.expanduser().resolve(strict=False)
    status = migration_status(resolved)
    if not status["database_exists"]:
        return {
            "ok": True,
            "state_dir": str(resolved),
            "state_write": False,
            "network_action": False,
            "limit": limit,
            "posts": [],
            "permission_issues": status["permission_issues"],
        }
    uri = f"file:{(resolved / STATE_DB).as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        conn.row_factory = sqlite3.Row
        table_exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'post_attempts'"
        ).fetchone()
        if table_exists is None:
            rows: list[sqlite3.Row] = []
        else:
            rows = list(
                conn.execute(
                    """
                    SELECT id, room, expected_owner_did, message_hash, post_status,
                           request_timestamp, response_status, nonce_used, seq,
                           failure_classification
                    FROM post_attempts
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                )
            )
    return {
        "ok": True,
        "state_dir": str(resolved),
        "state_write": False,
        "network_action": False,
        "limit": limit,
        "posts": [dict(row) for row in rows],
        "permission_issues": status["permission_issues"],
    }


def migrate(conn: sqlite3.Connection) -> list[int]:
    applied: list[int] = []
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
        applied.append(1)
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
        applied.append(2)
    if current < 3:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS service_activations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_type TEXT NOT NULL,
                service_name TEXT NOT NULL,
                expected_owner_did TEXT NOT NULL,
                observed_owner_did TEXT,
                activation_status TEXT NOT NULL,
                request_timestamp TEXT NOT NULL,
                response_status INTEGER,
                nonce_used INTEGER,
                response_hash TEXT,
                failure_classification TEXT
            );
            INSERT OR IGNORE INTO schema_migrations(version) VALUES (3);
            """
        )
        applied.append(3)
    if current < 4:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS post_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room TEXT NOT NULL,
                expected_owner_did TEXT NOT NULL,
                message_hash TEXT NOT NULL,
                post_status TEXT NOT NULL,
                request_timestamp TEXT NOT NULL,
                response_status INTEGER,
                nonce_used INTEGER,
                seq INTEGER,
                failure_classification TEXT
            );
            INSERT OR IGNORE INTO schema_migrations(version) VALUES (4);
            """
        )
        applied.append(4)
    conn.commit()
    return applied


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


def record_service_activation(
    conn: sqlite3.Connection,
    *,
    service_type: str,
    service_name: str,
    expected_owner_did: str,
    observed_owner_did: str | None,
    activation_status: str,
    response_status: int | None,
    nonce_used: int | None,
    response_hash: str | None,
    failure_classification: str | None,
) -> int:
    cursor = conn.execute(
        """
        INSERT INTO service_activations(
            service_type, service_name, expected_owner_did, observed_owner_did,
            activation_status, request_timestamp, response_status, nonce_used,
            response_hash, failure_classification
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            service_type,
            service_name,
            expected_owner_did,
            observed_owner_did,
            activation_status,
            datetime.now(UTC).isoformat(),
            response_status,
            nonce_used,
            response_hash,
            failure_classification,
        ),
    )
    conn.commit()
    if cursor.lastrowid is None:
        raise SafetyError("activation audit insert did not return an id")
    return int(cursor.lastrowid)


def update_service_activation(
    conn: sqlite3.Connection,
    *,
    activation_id: int,
    observed_owner_did: str | None,
    activation_status: str,
    response_status: int | None,
    nonce_used: int | None,
    response_hash: str | None,
    failure_classification: str | None,
) -> None:
    conn.execute(
        """
        UPDATE service_activations
        SET observed_owner_did = ?,
            activation_status = ?,
            response_status = ?,
            nonce_used = ?,
            response_hash = ?,
            failure_classification = ?
        WHERE id = ?
        """,
        (
            observed_owner_did,
            activation_status,
            response_status,
            nonce_used,
            response_hash,
            failure_classification,
            activation_id,
        ),
    )
    conn.commit()


def next_post_nonce(conn: sqlite3.Connection) -> int:
    now_ms = int(time.time() * 1000)
    conn.execute("BEGIN IMMEDIATE")
    row = conn.execute("SELECT value FROM metadata WHERE key = 'last_post_nonce'").fetchone()
    try:
        previous = int(row["value"]) if row is not None else 0
    except (TypeError, ValueError):
        previous = 0
    nonce = max(now_ms, previous + 1)
    conn.execute(
        """
        INSERT INTO metadata(key, value, updated_at)
        VALUES ('last_post_nonce', ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        """,
        (str(nonce), datetime.now(UTC).isoformat()),
    )
    conn.commit()
    return nonce


def record_post_attempt(
    conn: sqlite3.Connection,
    *,
    room: str,
    expected_owner_did: str,
    message_hash: str,
    post_status: str,
    response_status: int | None,
    nonce_used: int | None,
    seq: int | None,
    failure_classification: str | None,
) -> int:
    cursor = conn.execute(
        """
        INSERT INTO post_attempts(
            room, expected_owner_did, message_hash, post_status, request_timestamp,
            response_status, nonce_used, seq, failure_classification
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            room,
            expected_owner_did,
            message_hash,
            post_status,
            datetime.now(UTC).isoformat(),
            response_status,
            nonce_used,
            seq,
            failure_classification,
        ),
    )
    conn.commit()
    if cursor.lastrowid is None:
        raise SafetyError("post audit insert did not return an id")
    return int(cursor.lastrowid)


def update_post_attempt(
    conn: sqlite3.Connection,
    *,
    post_id: int,
    post_status: str,
    response_status: int | None,
    nonce_used: int | None,
    seq: int | None,
    failure_classification: str | None,
) -> None:
    conn.execute(
        """
        UPDATE post_attempts
        SET post_status = ?,
            response_status = ?,
            nonce_used = ?,
            seq = ?,
            failure_classification = ?
        WHERE id = ?
        """,
        (post_status, response_status, nonce_used, seq, failure_classification, post_id),
    )
    conn.commit()
