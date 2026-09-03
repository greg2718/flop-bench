from __future__ import annotations

import json
import os
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from .exceptions import SafetyError

SCHEMA_VERSION = 13
STATE_DB = "state.sqlite"
SQLITE_SIGNED_64_MAX = 9_223_372_036_854_775_807
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
MAILBOX_CURSOR_KEY = "mailbox:mb-flop-bench:cursor"
MAILBOX_INTAKE_ACTIVATION_TABLE = "mailbox_intake_activation"
MAILBOX_EXECUTION_TABLE = "mailbox_request_executions"
RESULT_DELIVERY_TABLE = "mailbox_result_deliveries"
VERIFICATION_RESULT_IMPORT_TABLE = "verification_result_imports"
MAILBOX_WORKER_TABLE = "mailbox_intake_worker"


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


def post_attempt(state_dir: Path, *, attempt_id: int) -> dict[str, Any]:
    if attempt_id < 1:
        raise SafetyError("post attempt id must be positive")
    resolved = state_dir.expanduser().resolve(strict=False)
    status = migration_status(resolved)
    if not status["database_exists"]:
        raise SafetyError("post attempt state database does not exist")
    uri = f"file:{(resolved / STATE_DB).as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT id, room, expected_owner_did, message_hash, post_status,
                   request_timestamp, response_status, nonce_used, seq,
                   failure_classification
            FROM post_attempts
            WHERE id = ?
            """,
            (attempt_id,),
        ).fetchone()
    if row is None:
        raise SafetyError("post attempt not found")
    return dict(row)


def result_delivery_history(state_dir: Path, *, limit: int) -> dict[str, Any]:
    if limit < 1 or limit > 100:
        raise SafetyError("result delivery history limit must be between 1 and 100")
    resolved = state_dir.expanduser().resolve(strict=False)
    status = migration_status(resolved)
    if not status["database_exists"]:
        return {
            "ok": True,
            "state_dir": str(resolved),
            "state_write": False,
            "network_action": False,
            "limit": limit,
            "deliveries": [],
            "permission_issues": status["permission_issues"],
        }
    uri = f"file:{(resolved / STATE_DB).as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        conn.row_factory = sqlite3.Row
        table_exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (RESULT_DELIVERY_TABLE,),
        ).fetchone()
        if table_exists is None:
            rows: list[sqlite3.Row] = []
        else:
            rows = list(
                conn.execute(
                    """
                    SELECT id, request_id, destination, bench_did, target_did,
                           message_hash, delivery_status, request_timestamp,
                           response_status, nonce_used, seq, failure_classification
                    FROM mailbox_result_deliveries
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
        "deliveries": [dict(row) for row in rows],
        "permission_issues": status["permission_issues"],
    }


def result_delivery_attempt(state_dir: Path, *, delivery_id: int) -> dict[str, Any]:
    if delivery_id < 1:
        raise SafetyError("result delivery id must be positive")
    resolved = state_dir.expanduser().resolve(strict=False)
    status = migration_status(resolved)
    if not status["database_exists"]:
        raise SafetyError("result delivery state database does not exist")
    uri = f"file:{(resolved / STATE_DB).as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        conn.row_factory = sqlite3.Row
        table_exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (RESULT_DELIVERY_TABLE,),
        ).fetchone()
        if table_exists is None:
            row = None
        else:
            row = conn.execute(
                """
                SELECT id, request_id, destination, bench_did, target_did,
                       message_hash, delivery_status, request_timestamp,
                       response_status, nonce_used, seq, failure_classification
                FROM mailbox_result_deliveries
                WHERE id = ?
                """,
                (delivery_id,),
            ).fetchone()
    if row is None:
        raise SafetyError("result delivery not found")
    return dict(row)


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row["name"]) for row in conn.execute(f"PRAGMA table_info({table})")}


def _migrate_mailbox_nonce_text(conn: sqlite3.Connection) -> None:
    table = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'mailbox_messages'"
    ).fetchone()
    if table is None:
        return
    columns = _table_columns(conn, "mailbox_messages")
    if "nonce_text" not in columns:
        try:
            conn.execute("ALTER TABLE mailbox_messages ADD COLUMN nonce_text TEXT")
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc).casefold():
                raise
    conn.execute(
        """
        UPDATE mailbox_messages
        SET nonce_text = CAST(nonce AS TEXT)
        WHERE nonce_text IS NULL AND nonce IS NOT NULL
        """
    )


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
    if current < 5:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS mailbox_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT NOT NULL UNIQUE,
                room TEXT NOT NULL,
                seq INTEGER NOT NULL,
                sender_did TEXT,
                nonce INTEGER,
                message_hash TEXT NOT NULL,
                untrusted_text TEXT NOT NULL,
                remote_ts TEXT,
                authentication_level TEXT NOT NULL,
                request_id TEXT,
                requested_capability TEXT,
                classification TEXT NOT NULL,
                review_status TEXT NOT NULL,
                received_at TEXT NOT NULL,
                expires_at TEXT,
                provenance_json TEXT,
                evidence_id TEXT,
                result_link TEXT,
                UNIQUE(room, seq)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_mailbox_messages_request_id
                ON mailbox_messages(request_id)
                WHERE request_id IS NOT NULL;
            INSERT OR IGNORE INTO schema_migrations(version) VALUES (5);
            """
        )
        applied.append(5)
    if current < 6:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS did_note_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                namespace TEXT NOT NULL,
                key TEXT NOT NULL,
                expected_hash TEXT NOT NULL,
                observed_hash TEXT,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                response_status INTEGER,
                timestamp TEXT NOT NULL,
                failure_classification TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_did_note_observations_path
                ON did_note_observations(namespace, key, id);
            INSERT OR IGNORE INTO schema_migrations(version) VALUES (6);
            """
        )
        applied.append(6)
    if current < 7:
        _migrate_mailbox_nonce_text(conn)
        conn.execute("INSERT OR IGNORE INTO schema_migrations(version) VALUES (7)")
        applied.append(7)
    if current < 8:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS mailbox_intake_activation (
                mailbox TEXT PRIMARY KEY,
                protocol_version TEXT NOT NULL,
                activation_status TEXT NOT NULL,
                activated_at TEXT NOT NULL,
                activated_by TEXT NOT NULL,
                execution_mode TEXT NOT NULL,
                autonomous_polling INTEGER NOT NULL,
                autonomous_execution INTEGER NOT NULL,
                autonomous_reply INTEGER NOT NULL,
                router_updates INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            );
            INSERT OR IGNORE INTO schema_migrations(version) VALUES (8);
            """
        )
        applied.append(8)
    if current < 9:
        table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'mailbox_messages'"
        ).fetchone()
        if table is not None and "request_json" not in _table_columns(conn, "mailbox_messages"):
            try:
                conn.execute("ALTER TABLE mailbox_messages ADD COLUMN request_json TEXT")
            except sqlite3.OperationalError as exc:
                if "duplicate column name" not in str(exc).casefold():
                    raise
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS mailbox_request_executions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL UNIQUE,
                execution_status TEXT NOT NULL,
                reserved_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                updated_at TEXT NOT NULL,
                evidence_id TEXT,
                evidence_path TEXT,
                evidence_hash TEXT,
                result TEXT,
                failure_classification TEXT,
                confirmation_recorded INTEGER NOT NULL,
                CHECK (
                    execution_status IN (
                        'reserved', 'running', 'completed', 'failed_internal'
                    )
                )
            );
            CREATE INDEX IF NOT EXISTS idx_mailbox_request_executions_status
                ON mailbox_request_executions(execution_status, id);
            INSERT OR IGNORE INTO schema_migrations(version) VALUES (9);
            """
        )
        applied.append(9)
    if current < 10:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS mailbox_result_deliveries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL,
                destination TEXT NOT NULL,
                bench_did TEXT NOT NULL,
                target_did TEXT NOT NULL,
                message_hash TEXT NOT NULL,
                delivery_status TEXT NOT NULL,
                request_timestamp TEXT NOT NULL,
                response_status INTEGER,
                nonce_used INTEGER,
                seq INTEGER,
                failure_classification TEXT,
                CHECK (
                    delivery_status IN (
                        'started',
                        'failed_preflight',
                        'posted',
                        'already-posted',
                        'failed',
                        'failed_pre_transmission',
                        'unknown_outcome',
                        'confirmed_rejected',
                        'reconciled_posted',
                        'reconciled_absent'
                    )
                )
            );
            CREATE INDEX IF NOT EXISTS idx_mailbox_result_deliveries_request_id
                ON mailbox_result_deliveries(request_id, id);
            CREATE INDEX IF NOT EXISTS idx_mailbox_result_deliveries_hash
                ON mailbox_result_deliveries(destination, bench_did, message_hash, id);
            INSERT OR IGNORE INTO schema_migrations(version) VALUES (10);
            """
        )
        applied.append(10)
    if current < 11:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS verification_result_imports (
                request_id TEXT PRIMARY KEY,
                schema_version TEXT NOT NULL,
                bench_did TEXT NOT NULL,
                routing_decision_id TEXT NOT NULL,
                routing_decision_hash TEXT NOT NULL,
                task_hash TEXT NOT NULL,
                verification_mode TEXT NOT NULL,
                status TEXT NOT NULL,
                score INTEGER NOT NULL,
                findings_json TEXT NOT NULL,
                checks_json TEXT NOT NULL,
                reproducibility TEXT NOT NULL,
                same_operator INTEGER NOT NULL,
                independent_reputation INTEGER NOT NULL,
                operator_group TEXT NOT NULL,
                evidence_classification TEXT,
                result_hash TEXT NOT NULL,
                artifact_hashes_json TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                imported_at TEXT NOT NULL
            );
            INSERT OR IGNORE INTO schema_migrations(version) VALUES (11);
            """
        )
        applied.append(11)
    if current < 12:
        columns = _table_columns(conn, VERIFICATION_RESULT_IMPORT_TABLE)
        if "reply_room" not in columns:
            try:
                conn.execute("ALTER TABLE verification_result_imports ADD COLUMN reply_room TEXT")
            except sqlite3.OperationalError as exc:
                if "duplicate column name" not in str(exc).casefold():
                    raise
        if "target_did" not in columns:
            try:
                conn.execute("ALTER TABLE verification_result_imports ADD COLUMN target_did TEXT")
            except sqlite3.OperationalError as exc:
                if "duplicate column name" not in str(exc).casefold():
                    raise
        conn.execute("INSERT OR IGNORE INTO schema_migrations(version) VALUES (12)")
        applied.append(12)
    if current < 13:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS mailbox_intake_worker (
                mailbox TEXT PRIMARY KEY,
                worker_status TEXT NOT NULL,
                instance_id TEXT,
                started_at TEXT,
                last_heartbeat_at TEXT,
                last_poll_started_at TEXT,
                last_successful_poll_at TEXT,
                consecutive_failures INTEGER NOT NULL DEFAULT 0,
                current_backoff_seconds REAL NOT NULL DEFAULT 0,
                last_failure_classification TEXT,
                lease_expires_at TEXT,
                poll_interval_seconds REAL NOT NULL DEFAULT 30
            );
            INSERT OR IGNORE INTO schema_migrations(version) VALUES (13);
            """
        )
        applied.append(13)
    conn.commit()
    return applied


def record_verification_result_import(
    conn: sqlite3.Connection,
    *,
    result: dict[str, Any],
    reply_room: str,
    target_did: str,
) -> bool:
    """Persist a validated Router-linked result once, without legacy evidence coercion."""
    now = datetime.now(UTC).isoformat()
    cur = conn.execute(
        """
        INSERT OR IGNORE INTO verification_result_imports(
            request_id, schema_version, bench_did, routing_decision_id,
            routing_decision_hash, task_hash, verification_mode, status, score,
            findings_json, checks_json, reproducibility, same_operator,
            independent_reputation, operator_group, evidence_classification,
            result_hash, artifact_hashes_json, completed_at, imported_at, reply_room, target_did
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            result["request_id"],
            result["schema_version"],
            result["bench_did"],
            result["routing_decision_id"],
            result["routing_decision_hash"],
            result["task_hash"],
            result["verification_mode"],
            result["status"],
            result["score"],
            json.dumps(result["findings"], sort_keys=True, separators=(",", ":")),
            json.dumps(result["checks"], sort_keys=True, separators=(",", ":")),
            result["reproducibility"],
            int(result["same_operator"]),
            int(result["independent_reputation"]),
            result["operator_group"],
            result.get("evidence_classification"),
            result["result_hash"],
            json.dumps(result["artifact_hashes"], sort_keys=True, separators=(",", ":")),
            result["completed_at"],
            now,
            reply_room,
            target_did,
        ),
    )
    conn.commit()
    return cur.rowcount == 1


def set_verification_result_import_routing(
    conn: sqlite3.Connection, *, request_id: str, reply_room: str, target_did: str
) -> bool:
    cur = conn.execute(
        """
        UPDATE verification_result_imports
        SET reply_room = ?, target_did = ?
        WHERE request_id = ? AND reply_room IS NULL AND target_did IS NULL
        """,
        (reply_room, target_did, request_id),
    )
    conn.commit()
    return cur.rowcount == 1


def verification_result_import(state_dir: Path, *, request_id: str) -> dict[str, Any] | None:
    with readonly_state_connection(state_dir) as conn:
        table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (VERIFICATION_RESULT_IMPORT_TABLE,),
        ).fetchone()
        if table is None:
            return None
        row = conn.execute(
            "SELECT * FROM verification_result_imports WHERE request_id = ?", (request_id,)
        ).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["findings"] = json.loads(result.pop("findings_json"))
    result["checks"] = json.loads(result.pop("checks_json"))
    result["artifact_hashes"] = json.loads(result.pop("artifact_hashes_json"))
    result["same_operator"] = bool(result["same_operator"])
    result["independent_reputation"] = bool(result["independent_reputation"])
    return result


def acquire_mailbox_worker_lease(
    conn: sqlite3.Connection,
    *,
    mailbox: str,
    instance_id: str,
    now: datetime,
    lease_seconds: float,
    poll_interval_seconds: float,
) -> bool:
    now_text = now.isoformat()
    expiry = datetime.fromtimestamp(now.timestamp() + lease_seconds, UTC).isoformat()
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT instance_id, lease_expires_at FROM mailbox_intake_worker WHERE mailbox = ?",
            (mailbox,),
        ).fetchone()
        valid_other = False
        if row is not None and row["instance_id"] is not None and row["instance_id"] != instance_id:
            try:
                valid_other = datetime.fromisoformat(str(row["lease_expires_at"])) > now
            except (TypeError, ValueError):
                valid_other = True
        if valid_other:
            conn.rollback()
            return False
        conn.execute(
            """
            INSERT INTO mailbox_intake_worker(
                mailbox, worker_status, instance_id, started_at, last_heartbeat_at,
                consecutive_failures, current_backoff_seconds, lease_expires_at,
                poll_interval_seconds
            ) VALUES (?, 'running', ?, ?, ?, 0, 0, ?, ?)
            ON CONFLICT(mailbox) DO UPDATE SET
                worker_status = 'running', instance_id = excluded.instance_id,
                started_at = excluded.started_at, last_heartbeat_at = excluded.last_heartbeat_at,
                lease_expires_at = excluded.lease_expires_at,
                poll_interval_seconds = excluded.poll_interval_seconds
            """,
            (mailbox, instance_id, now_text, now_text, expiry, poll_interval_seconds),
        )
        conn.commit()
        return True
    except sqlite3.Error:
        conn.rollback()
        raise


def update_mailbox_worker(
    conn: sqlite3.Connection,
    *,
    mailbox: str,
    instance_id: str,
    now: datetime,
    lease_seconds: float,
    poll_started: bool = False,
    successful: bool | None = None,
    backoff_seconds: float | None = None,
    failure_classification: str | None = None,
) -> bool:
    expiry = datetime.fromtimestamp(now.timestamp() + lease_seconds, UTC).isoformat()
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT instance_id, consecutive_failures FROM mailbox_intake_worker WHERE mailbox = ?",
            (mailbox,),
        ).fetchone()
        if row is None or row["instance_id"] != instance_id:
            conn.rollback()
            return False
        conn.execute(
            """
            UPDATE mailbox_intake_worker
            SET last_heartbeat_at = ?, lease_expires_at = ?,
                last_poll_started_at = CASE WHEN ? THEN ? ELSE last_poll_started_at END,
                last_successful_poll_at = CASE WHEN ? THEN ? ELSE last_successful_poll_at END,
                consecutive_failures = CASE WHEN ? THEN 0 WHEN ? THEN
                    consecutive_failures + 1 ELSE consecutive_failures END,
                current_backoff_seconds = CASE WHEN ? THEN 0 WHEN ? THEN ?
                    ELSE current_backoff_seconds END,
                last_failure_classification = CASE WHEN ? THEN NULL WHEN ? THEN ?
                    ELSE last_failure_classification END
            WHERE mailbox = ? AND instance_id = ?
            """,
            (
                now.isoformat(),
                expiry,
                poll_started,
                now.isoformat(),
                successful is True,
                now.isoformat(),
                successful is True,
                successful is False,
                successful is True,
                successful is False,
                backoff_seconds or 0,
                successful is True,
                successful is False,
                failure_classification,
                mailbox,
                instance_id,
            ),
        )
        conn.commit()
        return True
    except sqlite3.Error:
        conn.rollback()
        raise


def release_mailbox_worker_lease(
    conn: sqlite3.Connection, *, mailbox: str, instance_id: str
) -> None:
    conn.execute(
        """
        UPDATE mailbox_intake_worker
        SET worker_status = 'stopped', instance_id = NULL, lease_expires_at = NULL
        WHERE mailbox = ? AND instance_id = ?
        """,
        (mailbox, instance_id),
    )
    conn.commit()


def mailbox_worker_state(state_dir: Path, *, mailbox: str) -> dict[str, Any] | None:
    resolved = state_dir.expanduser().resolve(strict=False)
    if not (resolved / STATE_DB).exists():
        return None
    uri = f"file:{(resolved / STATE_DB).as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        conn.row_factory = sqlite3.Row
        table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (MAILBOX_WORKER_TABLE,)
        ).fetchone()
        row = (
            None
            if table is None
            else conn.execute(
                "SELECT * FROM mailbox_intake_worker WHERE mailbox = ?", (mailbox,)
            ).fetchone()
        )
    return None if row is None else dict(row)


def mailbox_worker_snapshot(state_dir: Path, *, mailbox: str) -> dict[str, Any] | None:
    """Read worker state and mailbox counters from one read-only SQLite snapshot."""
    resolved = state_dir.expanduser().resolve(strict=False)
    db_path = resolved / STATE_DB
    if not db_path.exists():
        return None
    uri = f"file:{db_path.as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        conn.row_factory = sqlite3.Row
        worker_table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (MAILBOX_WORKER_TABLE,),
        ).fetchone()
        row = (
            None
            if worker_table is None
            else conn.execute(
                "SELECT * FROM mailbox_intake_worker WHERE mailbox = ?", (mailbox,)
            ).fetchone()
        )
        message_table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'mailbox_messages'"
        ).fetchone()
        cursor_row = conn.execute(
            "SELECT value FROM metadata WHERE key = ?", (f"mailbox:{mailbox}:cursor",)
        ).fetchone()
        pending = (
            0
            if message_table is None
            else int(
                conn.execute(
                    "SELECT COUNT(*) FROM mailbox_messages "
                    "WHERE review_status = 'pending_human_review'"
                ).fetchone()[0]
            )
        )
    if row is None:
        return None
    result = dict(row)
    try:
        result["cursor"] = int(cursor_row["value"]) if cursor_row is not None else 0
    except (TypeError, ValueError):
        result["cursor"] = 0
    result["pending_human_review"] = pending
    return result


def _mailbox_activation_row_dict(row: sqlite3.Row | None, *, mailbox: str) -> dict[str, Any]:
    defaults: dict[str, Any] = {
        "protocol_version": "flop-bench.mailbox-request.v0.1",
        "mailbox": mailbox,
        "activation_status": "inactive",
        "activated_at": None,
        "activated_by": "human_operator",
        "execution_mode": "manual_only",
        "autonomous_polling": False,
        "autonomous_execution": False,
        "autonomous_reply": False,
        "router_updates": False,
        "updated_at": None,
        "active": False,
    }
    if row is None:
        return defaults
    result = dict(row)
    for key in (
        "autonomous_polling",
        "autonomous_execution",
        "autonomous_reply",
        "router_updates",
    ):
        result[key] = bool(result[key])
    result["active"] = result["activation_status"] == "active"
    return {**defaults, **result}


def mailbox_activation_state(state_dir: Path, *, mailbox: str) -> dict[str, Any]:
    resolved = state_dir.expanduser().resolve(strict=False)
    status = migration_status(resolved)
    if not status["database_exists"]:
        return {
            **_mailbox_activation_row_dict(None, mailbox=mailbox),
            "state_dir": str(resolved),
            "database_exists": False,
            "state_write": False,
            "network_action": False,
            "permission_issues": status["permission_issues"],
        }
    uri = f"file:{(resolved / STATE_DB).as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        conn.row_factory = sqlite3.Row
        table_exists = conn.execute(
            """
            SELECT 1 FROM sqlite_master
            WHERE type = 'table' AND name = 'mailbox_intake_activation'
            """
        ).fetchone()
        row = None
        if table_exists is not None:
            row = conn.execute(
                """
                SELECT protocol_version, mailbox, activation_status, activated_at,
                       activated_by, execution_mode, autonomous_polling,
                       autonomous_execution, autonomous_reply, router_updates, updated_at
                FROM mailbox_intake_activation
                WHERE mailbox = ?
                """,
                (mailbox,),
            ).fetchone()
    return {
        **_mailbox_activation_row_dict(row, mailbox=mailbox),
        "state_dir": str(resolved),
        "database_exists": True,
        "state_write": False,
        "network_action": False,
        "permission_issues": status["permission_issues"],
    }


def record_mailbox_activation(
    conn: sqlite3.Connection,
    *,
    mailbox: str,
    protocol_version: str,
) -> dict[str, Any]:
    now = datetime.now(UTC).isoformat()
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            """
            SELECT activation_status, activated_at
            FROM mailbox_intake_activation
            WHERE mailbox = ?
            """,
            (mailbox,),
        ).fetchone()
        activated_at = (
            str(row["activated_at"])
            if row is not None and row["activation_status"] == "active"
            else now
        )
        conn.execute(
            """
            INSERT INTO mailbox_intake_activation(
                mailbox, protocol_version, activation_status, activated_at,
                activated_by, execution_mode, autonomous_polling, autonomous_execution,
                autonomous_reply, router_updates, updated_at
            )
            VALUES (?, ?, 'active', ?, 'human_operator', 'manual_only', 0, 0, 0, 0, ?)
            ON CONFLICT(mailbox) DO UPDATE SET
                protocol_version = excluded.protocol_version,
                activation_status = 'active',
                activated_at = ?,
                activated_by = 'human_operator',
                execution_mode = 'manual_only',
                autonomous_polling = 0,
                autonomous_execution = 0,
                autonomous_reply = 0,
                router_updates = 0,
                updated_at = excluded.updated_at
            """,
            (mailbox, protocol_version, activated_at, now, activated_at),
        )
        result = conn.execute(
            """
            SELECT protocol_version, mailbox, activation_status, activated_at,
                   activated_by, execution_mode, autonomous_polling,
                   autonomous_execution, autonomous_reply, router_updates, updated_at
            FROM mailbox_intake_activation
            WHERE mailbox = ?
            """,
            (mailbox,),
        ).fetchone()
        conn.commit()
    except sqlite3.Error:
        conn.rollback()
        raise
    return _mailbox_activation_row_dict(result, mailbox=mailbox)


def record_mailbox_deactivation(conn: sqlite3.Connection, *, mailbox: str) -> dict[str, Any]:
    now = datetime.now(UTC).isoformat()
    conn.execute("BEGIN IMMEDIATE")
    try:
        existing = conn.execute(
            """
            SELECT activated_at
            FROM mailbox_intake_activation
            WHERE mailbox = ?
            """,
            (mailbox,),
        ).fetchone()
        activated_at = str(existing["activated_at"]) if existing is not None else now
        conn.execute(
            """
            INSERT INTO mailbox_intake_activation(
                mailbox, protocol_version, activation_status, activated_at,
                activated_by, execution_mode, autonomous_polling, autonomous_execution,
                autonomous_reply, router_updates, updated_at
            )
            VALUES (
                ?, 'flop-bench.mailbox-request.v0.1', 'inactive', ?,
                'human_operator', 'manual_only', 0, 0, 0, 0, ?
            )
            ON CONFLICT(mailbox) DO UPDATE SET
                activation_status = 'inactive',
                activated_by = 'human_operator',
                execution_mode = 'manual_only',
                autonomous_polling = 0,
                autonomous_execution = 0,
                autonomous_reply = 0,
                router_updates = 0,
                updated_at = excluded.updated_at
            """,
            (mailbox, activated_at, now),
        )
        result = conn.execute(
            """
            SELECT protocol_version, mailbox, activation_status, activated_at,
                   activated_by, execution_mode, autonomous_polling,
                   autonomous_execution, autonomous_reply, router_updates, updated_at
            FROM mailbox_intake_activation
            WHERE mailbox = ?
            """,
            (mailbox,),
        ).fetchone()
        conn.commit()
    except sqlite3.Error:
        conn.rollback()
        raise
    return _mailbox_activation_row_dict(result, mailbox=mailbox)


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


def record_result_delivery_attempt(
    conn: sqlite3.Connection,
    *,
    request_id: str,
    destination: str,
    bench_did: str,
    target_did: str,
    message_hash: str,
    delivery_status: str,
    response_status: int | None,
    nonce_used: int | None,
    seq: int | None,
    failure_classification: str | None,
) -> int:
    cursor = conn.execute(
        """
        INSERT INTO mailbox_result_deliveries(
            request_id, destination, bench_did, target_did, message_hash,
            delivery_status, request_timestamp, response_status, nonce_used,
            seq, failure_classification
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            request_id,
            destination,
            bench_did,
            target_did,
            message_hash,
            delivery_status,
            datetime.now(UTC).isoformat(),
            response_status,
            nonce_used,
            seq,
            failure_classification,
        ),
    )
    conn.commit()
    if cursor.lastrowid is None:
        raise SafetyError("result delivery audit insert did not return an id")
    return int(cursor.lastrowid)


def update_result_delivery_attempt(
    conn: sqlite3.Connection,
    *,
    delivery_id: int,
    delivery_status: str,
    response_status: int | None,
    nonce_used: int | None,
    seq: int | None,
    failure_classification: str | None,
) -> None:
    conn.execute(
        """
        UPDATE mailbox_result_deliveries
        SET delivery_status = ?,
            response_status = ?,
            nonce_used = ?,
            seq = ?,
            failure_classification = ?
        WHERE id = ?
        """,
        (
            delivery_status,
            response_status,
            nonce_used,
            seq,
            failure_classification,
            delivery_id,
        ),
    )
    conn.commit()


def mailbox_cursor(conn: sqlite3.Connection, *, room: str) -> int:
    row = conn.execute(
        "SELECT value FROM metadata WHERE key = ?",
        (f"mailbox:{room}:cursor",),
    ).fetchone()
    try:
        return int(row["value"]) if row is not None else 0
    except (TypeError, ValueError):
        return 0


def store_mailbox_poll(
    conn: sqlite3.Connection,
    *,
    room: str,
    messages: list[dict[str, Any]],
    new_cursor: int,
) -> dict[str, Any]:
    now = datetime.now(UTC).isoformat()
    inserted = 0
    duplicates = 0
    duplicate_request_ids = 0
    conn.execute("BEGIN IMMEDIATE")
    try:
        for item in messages:
            nonce_text = item.get("nonce_text")
            nonce_integer: int | None = None
            if isinstance(nonce_text, str):
                nonce_value = int(nonce_text)
                if nonce_value <= SQLITE_SIGNED_64_MAX:
                    nonce_integer = nonce_value
            before = conn.total_changes
            try:
                conn.execute(
                    """
                    INSERT INTO mailbox_messages(
                        message_id, room, seq, sender_did, nonce, nonce_text, message_hash,
                        untrusted_text, remote_ts, authentication_level, request_id,
                        requested_capability, classification, review_status,
                        received_at, expires_at, provenance_json, evidence_id, result_link,
                        request_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)
                    """,
                    (
                        item["message_id"],
                        room,
                        item["seq"],
                        item.get("sender_did"),
                        nonce_integer,
                        nonce_text,
                        item["message_hash"],
                        item["untrusted_text"],
                        item.get("remote_ts"),
                        item["authentication_level"],
                        item.get("request_id"),
                        item.get("requested_capability"),
                        item["classification"],
                        item["review_status"],
                        now,
                        item.get("expires_at"),
                        item.get("provenance_json"),
                        item.get("request_json"),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                message = str(exc).casefold()
                if "request_id" in message:
                    duplicate_request_ids += 1
                    fallback = dict(item)
                    fallback["request_id"] = None
                    fallback["requested_capability"] = item.get("requested_capability")
                    fallback["classification"] = "duplicate_request_id"
                    fallback["review_status"] = "rejected"
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO mailbox_messages(
                            message_id, room, seq, sender_did, nonce, nonce_text, message_hash,
                            untrusted_text, remote_ts, authentication_level, request_id,
                            requested_capability, classification, review_status,
                            received_at, expires_at, provenance_json, evidence_id, result_link,
                            request_json
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)
                        """,
                        (
                            fallback["message_id"],
                            room,
                            fallback["seq"],
                            fallback.get("sender_did"),
                            nonce_integer,
                            nonce_text,
                            fallback["message_hash"],
                            fallback["untrusted_text"],
                            fallback.get("remote_ts"),
                            fallback["authentication_level"],
                            fallback.get("requested_capability"),
                            fallback["classification"],
                            fallback["review_status"],
                            now,
                            fallback.get("expires_at"),
                            fallback.get("provenance_json"),
                            fallback.get("request_json"),
                        ),
                    )
                else:
                    duplicates += 1
            if conn.total_changes > before:
                inserted += 1
        conn.execute(
            """
            INSERT INTO metadata(key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (f"mailbox:{room}:cursor", str(new_cursor), now),
        )
        conn.commit()
    except sqlite3.Error:
        conn.rollback()
        raise
    return {
        "inserted": inserted,
        "duplicates": duplicates,
        "duplicate_request_ids": duplicate_request_ids,
        "cursor": new_cursor,
    }


def _mailbox_row_dict(row: sqlite3.Row) -> dict[str, Any]:
    result = dict(row)
    nonce_text = result.pop("nonce_text", None)
    if nonce_text is not None:
        result["nonce_decimal"] = str(nonce_text)
        if result.get("nonce") is None:
            result["nonce"] = str(nonce_text)
    elif result.get("nonce") is not None:
        result["nonce_decimal"] = str(result["nonce"])
    return result


def _execution_row_dict(row: sqlite3.Row) -> dict[str, Any]:
    result = dict(row)
    if "confirmation_recorded" in result:
        result["confirmation_recorded"] = bool(result["confirmation_recorded"])
    return result


def readonly_state_connection(state_dir: Path) -> sqlite3.Connection:
    resolved = state_dir.expanduser().resolve(strict=False)
    db_path = resolved / STATE_DB
    if not db_path.exists():
        raise SafetyError("state database does not exist")
    uri = f"file:{db_path.as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def mailbox_request_for_execution(state_dir: Path, *, request_id: str) -> dict[str, Any] | None:
    with readonly_state_connection(state_dir) as conn:
        has_table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'mailbox_messages'"
        ).fetchone()
        if has_table is None:
            return None
        columns = _table_columns(conn, "mailbox_messages")
        if "request_json" in columns:
            row = conn.execute(
                """
                SELECT message_id, room, seq, sender_did, nonce_text, message_hash,
                       remote_ts, authentication_level, request_id, requested_capability,
                       classification, review_status, received_at, expires_at,
                       provenance_json, evidence_id, result_link, request_json
                FROM mailbox_messages
                WHERE request_id = ?
                """,
                (request_id,),
            ).fetchone()
        else:
            row = conn.execute(
                """
                SELECT message_id, room, seq, sender_did, nonce_text, message_hash,
                       remote_ts, authentication_level, request_id, requested_capability,
                       classification, review_status, received_at, expires_at,
                       provenance_json, evidence_id, result_link, NULL AS request_json
                FROM mailbox_messages
                WHERE request_id = ?
                """,
                (request_id,),
            ).fetchone()
        if row is None:
            return None
        execution_table = conn.execute(
            """
            SELECT 1 FROM sqlite_master
            WHERE type = 'table' AND name = 'mailbox_request_executions'
            """
        ).fetchone()
        execution = None
        if execution_table is not None:
            execution_row = conn.execute(
                """
                SELECT id, request_id, execution_status, reserved_at, started_at,
                       completed_at, updated_at, evidence_id, evidence_path,
                       evidence_hash, result, failure_classification,
                       confirmation_recorded
                FROM mailbox_request_executions
                WHERE request_id = ?
                """,
                (request_id,),
            ).fetchone()
            execution = None if execution_row is None else _execution_row_dict(execution_row)
    return {**_mailbox_row_dict(row), "execution": execution}


def mailbox_execution_history(state_dir: Path, *, limit: int) -> dict[str, Any]:
    if limit < 1 or limit > 100:
        raise SafetyError("execution history limit must be between 1 and 100")
    resolved = state_dir.expanduser().resolve(strict=False)
    status = migration_status(resolved)
    if not status["database_exists"]:
        return {
            "ok": True,
            "state_dir": str(resolved),
            "limit": limit,
            "executions": [],
            "state_write": False,
            "network_action": False,
        }
    with readonly_state_connection(resolved) as conn:
        has_table = conn.execute(
            """
            SELECT 1 FROM sqlite_master
            WHERE type = 'table' AND name = 'mailbox_request_executions'
            """
        ).fetchone()
        if has_table is None:
            rows: list[sqlite3.Row] = []
        else:
            rows = list(
                conn.execute(
                    """
                    SELECT id, request_id, execution_status, reserved_at, started_at,
                           completed_at, updated_at, evidence_id, evidence_path,
                           evidence_hash, result, failure_classification,
                           confirmation_recorded
                    FROM mailbox_request_executions
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                )
            )
    return {
        "ok": True,
        "state_dir": str(resolved),
        "limit": limit,
        "executions": [_execution_row_dict(row) for row in rows],
        "state_write": False,
        "network_action": False,
    }


def reserve_mailbox_execution(conn: sqlite3.Connection, *, request_id: str) -> dict[str, Any]:
    now = datetime.now(UTC).isoformat()
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            """
            SELECT id, request_id, execution_status, reserved_at, started_at,
                   completed_at, updated_at, evidence_id, evidence_path,
                   evidence_hash, result, failure_classification,
                   confirmation_recorded
            FROM mailbox_request_executions
            WHERE request_id = ?
            """,
            (request_id,),
        ).fetchone()
        if row is not None:
            conn.commit()
            return {"created": False, **_execution_row_dict(row)}
        cur = conn.execute(
            """
            INSERT INTO mailbox_request_executions(
                request_id, execution_status, reserved_at, updated_at,
                confirmation_recorded
            )
            VALUES (?, 'reserved', ?, ?, 1)
            """,
            (request_id, now, now),
        )
        row = conn.execute(
            """
            SELECT id, request_id, execution_status, reserved_at, started_at,
                   completed_at, updated_at, evidence_id, evidence_path,
                   evidence_hash, result, failure_classification,
                   confirmation_recorded
            FROM mailbox_request_executions
            WHERE id = ?
            """,
            (cur.lastrowid,),
        ).fetchone()
        conn.commit()
    except sqlite3.Error:
        conn.rollback()
        raise
    return {"created": True, **_execution_row_dict(row)}


def mark_mailbox_execution_running(conn: sqlite3.Connection, *, request_id: str) -> None:
    now = datetime.now(UTC).isoformat()
    conn.execute(
        """
        UPDATE mailbox_request_executions
        SET execution_status = 'running', started_at = COALESCE(started_at, ?), updated_at = ?
        WHERE request_id = ? AND execution_status = 'reserved'
        """,
        (now, now, request_id),
    )
    conn.commit()


def complete_mailbox_execution(
    conn: sqlite3.Connection,
    *,
    request_id: str,
    evidence_id: str,
    evidence_path: Path,
    evidence_hash: str,
    result: str,
) -> dict[str, Any]:
    now = datetime.now(UTC).isoformat()
    cur = conn.execute(
        """
        UPDATE mailbox_request_executions
        SET execution_status = 'completed',
            completed_at = COALESCE(completed_at, ?),
            updated_at = ?,
            evidence_id = COALESCE(evidence_id, ?),
            evidence_path = COALESCE(evidence_path, ?),
            evidence_hash = COALESCE(evidence_hash, ?),
            result = COALESCE(result, ?),
            failure_classification = NULL
        WHERE request_id = ? AND execution_status = 'running'
        """,
        (now, now, evidence_id, str(evidence_path), evidence_hash, result, request_id),
    )
    if cur.rowcount != 1:
        conn.rollback()
        raise SafetyError("execution completion refused because reservation state changed")
    conn.execute(
        """
        UPDATE mailbox_messages
        SET evidence_id = COALESCE(evidence_id, ?),
            result_link = COALESCE(result_link, ?)
        WHERE request_id = ?
        """,
        (evidence_id, evidence_hash, request_id),
    )
    row = conn.execute(
        """
        SELECT id, request_id, execution_status, reserved_at, started_at,
               completed_at, updated_at, evidence_id, evidence_path,
               evidence_hash, result, failure_classification, confirmation_recorded
        FROM mailbox_request_executions
        WHERE request_id = ?
        """,
        (request_id,),
    ).fetchone()
    conn.commit()
    return _execution_row_dict(row)


def mailbox_messages_history(state_dir: Path, *, limit: int) -> dict[str, Any]:
    if limit < 1 or limit > 100:
        raise SafetyError("mailbox message limit must be between 1 and 100")
    resolved = state_dir.expanduser().resolve(strict=False)
    status = migration_status(resolved)
    if not status["database_exists"]:
        return {
            "ok": True,
            "state_dir": str(resolved),
            "state_write": False,
            "network_action": False,
            "limit": limit,
            "messages": [],
            "permission_issues": status["permission_issues"],
        }
    uri = f"file:{(resolved / STATE_DB).as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        conn.row_factory = sqlite3.Row
        table_exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'mailbox_messages'"
        ).fetchone()
        if table_exists is None:
            rows: list[sqlite3.Row] = []
        else:
            rows = list(
                conn.execute(
                    """
                    SELECT message_id, room, seq, sender_did, nonce, nonce_text, message_hash,
                           authentication_level, request_id, requested_capability,
                           classification, review_status, received_at, expires_at,
                           evidence_id, result_link
                    FROM mailbox_messages
                    ORDER BY seq DESC
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
        "messages": [_mailbox_row_dict(row) for row in rows],
        "permission_issues": status["permission_issues"],
    }


def mailbox_message_detail(state_dir: Path, *, message_id: str) -> dict[str, Any]:
    resolved = state_dir.expanduser().resolve(strict=False)
    status = migration_status(resolved)
    if not status["database_exists"]:
        raise SafetyError("mailbox state database does not exist")
    uri = f"file:{(resolved / STATE_DB).as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT message_id, room, seq, sender_did, nonce, nonce_text, message_hash,
                   untrusted_text, remote_ts, authentication_level, request_id,
                   requested_capability, classification, review_status,
                   received_at, expires_at, provenance_json, evidence_id, result_link
            FROM mailbox_messages
            WHERE message_id = ?
            """,
            (message_id,),
        ).fetchone()
    if row is None:
        raise SafetyError("mailbox message not found")
    result = _mailbox_row_dict(row)
    if result["provenance_json"]:
        result["provenance"] = json.loads(result.pop("provenance_json"))
    return result


STRONG_DID_NOTE_STATUS = "already-matching"
WEAKER_DID_NOTE_STATUSES = {
    "absent",
    "conflict",
    "remote_unavailable",
    "reconciliation_incomplete",
    "publish_unknown",
}


def _latest_did_note_row(
    conn: sqlite3.Connection,
    *,
    namespace: str,
    key: str,
) -> sqlite3.Row | None:
    return cast(
        sqlite3.Row | None,
        conn.execute(
            """
        SELECT id, namespace, key, expected_hash, observed_hash, action, status,
               response_status, timestamp, failure_classification
        FROM did_note_observations
        WHERE namespace = ? AND key = ?
        ORDER BY id DESC
        LIMIT 1
        """,
            (namespace, key),
        ).fetchone(),
    )


def record_did_note_observation(
    conn: sqlite3.Connection,
    *,
    namespace: str,
    key: str,
    expected_hash: str,
    observed_hash: str | None,
    action: str,
    status: str,
    response_status: int | None,
    failure_classification: str | None,
) -> dict[str, Any]:
    latest = _latest_did_note_row(conn, namespace=namespace, key=key)
    if (
        latest is not None
        and latest["status"] == STRONG_DID_NOTE_STATUS
        and latest["expected_hash"] == expected_hash
        and status in WEAKER_DID_NOTE_STATUSES
    ):
        return {
            "state_write": False,
            "audit_transition": "preserved",
            "latest": dict(latest),
        }
    timestamp = datetime.now(UTC).isoformat()
    cursor = conn.execute(
        """
        INSERT INTO did_note_observations(
            namespace, key, expected_hash, observed_hash, action, status,
            response_status, timestamp, failure_classification
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            namespace,
            key,
            expected_hash,
            observed_hash,
            action,
            status,
            response_status,
            timestamp,
            failure_classification,
        ),
    )
    conn.commit()
    row = _latest_did_note_row(conn, namespace=namespace, key=key)
    return {
        "state_write": True,
        "audit_transition": "updated",
        "id": cursor.lastrowid,
        "latest": dict(row) if row is not None else None,
    }


def latest_did_note_observation(
    state_dir: Path,
    *,
    namespace: str,
    key: str,
) -> dict[str, Any] | None:
    resolved = state_dir.expanduser().resolve(strict=False)
    status = migration_status(resolved)
    if not status["database_exists"]:
        return None
    uri = f"file:{(resolved / STATE_DB).as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        conn.row_factory = sqlite3.Row
        table_exists = conn.execute(
            """
            SELECT 1 FROM sqlite_master
            WHERE type = 'table' AND name = 'did_note_observations'
            """
        ).fetchone()
        if table_exists is None:
            return None
        row = _latest_did_note_row(conn, namespace=namespace, key=key)
    return dict(row) if row is not None else None
