from __future__ import annotations

import math
import re
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .activation import ActivationTransport
from .config import BENCH_DID, MAILBOX, BenchConfig, assert_isolated
from .exceptions import SafetyError
from .mailbox import poll_mailbox
from .state import (
    acquire_mailbox_worker_lease,
    connect_state,
    mailbox_activation_state,
    mailbox_worker_snapshot,
    mailbox_worker_state,
    migration_status,
    record_mailbox_activation,
    record_mailbox_deactivation,
    release_mailbox_worker_lease,
    update_mailbox_worker,
)

DEFAULT_POLL_INTERVAL_SECONDS = 30.0
DEFAULT_MAX_BACKOFF_SECONDS = 300.0
MAX_INTERVAL_SECONDS = 3600.0
_SAFE_FAILURE_RE = re.compile(r"^[a-z0-9_]{1,64}$")
WORKER_ACTIVATE_CONFIRMATION = "ENABLE-SUPERVISED-BENCH-POLLING"
WORKER_DEACTIVATE_CONFIRMATION = "DISABLE-SUPERVISED-BENCH-POLLING"
SUPERVISED_POLLING_ACTIVATION_KEY = f"{MAILBOX}:supervised-continuous-polling"
SUPERVISED_POLLING_PROTOCOL_VERSION = "flop-bench.supervised-continuous-polling.v0.1"


def _now() -> datetime:
    return datetime.now(UTC)


def validate_worker_timing(*, poll_interval: float, max_backoff: float) -> None:
    for value, name in ((poll_interval, "poll interval"), (max_backoff, "max backoff")):
        if not math.isfinite(value) or value <= 0 or value > MAX_INTERVAL_SECONDS:
            raise SafetyError(
                f"{name} must be a finite value between 0 and {MAX_INTERVAL_SECONDS:g}"
            )
    if max_backoff < poll_interval:
        raise SafetyError("max backoff must not be less than poll interval")


def _safe_failure(result: dict[str, Any]) -> str:
    value = result.get("failure_classification")
    return (
        value
        if isinstance(value, str) and _SAFE_FAILURE_RE.fullmatch(value)
        else "worker_poll_incomplete"
    )


def worker_stop_handler(stop: Callable[[], None]) -> Callable[[int, Any], None]:
    def handler(_signum: int, _frame: Any) -> None:
        stop()

    return handler


def _supervised_polling_activation(state_dir: Path) -> dict[str, Any]:
    return mailbox_activation_state(state_dir, mailbox=SUPERVISED_POLLING_ACTIVATION_KEY)


def _supervised_polling_active(state_dir: Path) -> bool:
    return bool(_supervised_polling_activation(state_dir)["active"])


def worker_activation_preview(*, state_dir: Path) -> dict[str, Any]:
    assert_isolated(BenchConfig(state_dir=state_dir, subject_did=BENCH_DID))
    resolved = state_dir.expanduser().resolve(strict=False)
    status = migration_status(resolved)
    mailbox_activation = mailbox_activation_state(resolved, mailbox=MAILBOX)
    polling_activation = _supervised_polling_activation(resolved)
    blockers = []
    if not status["database_exists"]:
        blockers.append("state_database_missing")
    if status["pending_migrations"]:
        blockers.append("state_schema_migration_required")
    if mailbox_activation["permission_issues"]:
        blockers.append("private_state_permission_issue")
    if not mailbox_activation["active"]:
        blockers.append("mailbox_intake_inactive")
    return {
        "ok": True,
        "state_dir": str(resolved),
        "mailbox": MAILBOX,
        "activation": polling_activation,
        "mailbox_intake_active": mailbox_activation["active"],
        "supervised_continuous_polling": polling_activation["active"],
        "activation_blockers": blockers,
        "can_activate": not blockers,
        "required_confirmation": WORKER_ACTIVATE_CONFIRMATION,
        "activation_consequences": [
            "worker run without --once may continuously poll the mailbox "
            "under an external supervisor",
            "polling remains bounded read-only intake",
            "valid signed requests enter pending_human_review only",
        ],
        "disabled_behaviors": {
            "state_creation": False,
            "migration": False,
            "network": False,
            "identity_loading": False,
            "approval": False,
            "execution": False,
            "signing": False,
            "result_delivery": False,
            "reply": False,
            "posting": False,
            "router_updates": False,
            "wallets": False,
            "flop_transfers": False,
        },
        "state_write": False,
        "network_action": False,
        "will_poll": False,
        "will_sign": False,
        "will_post": False,
        "will_execute": False,
        "will_reply": False,
        "will_update_router": False,
    }


def worker_activate(*, state_dir: Path, confirm: str) -> dict[str, Any]:
    if confirm != WORKER_ACTIVATE_CONFIRMATION:
        raise SafetyError("worker activation requires exact confirmation")
    preview = worker_activation_preview(state_dir=state_dir)
    if preview["activation_blockers"]:
        raise SafetyError(
            "worker activation is blocked: " + ", ".join(preview["activation_blockers"])
        )
    resolved = state_dir.expanduser().resolve(strict=False)
    with connect_state(resolved) as conn:
        activation = record_mailbox_activation(
            conn,
            mailbox=SUPERVISED_POLLING_ACTIVATION_KEY,
            protocol_version=SUPERVISED_POLLING_PROTOCOL_VERSION,
        )
    return {
        "ok": True,
        **activation,
        "mailbox": MAILBOX,
        "supervised_continuous_polling": True,
        "state_dir": str(resolved),
        "state_write": True,
        "network_action": False,
        "will_poll": False,
        "will_sign": False,
        "will_post": False,
        "will_execute": False,
        "will_reply": False,
        "will_update_router": False,
    }


def worker_deactivate(*, state_dir: Path, confirm: str) -> dict[str, Any]:
    if confirm != WORKER_DEACTIVATE_CONFIRMATION:
        raise SafetyError("worker deactivation requires exact confirmation")
    assert_isolated(BenchConfig(state_dir=state_dir, subject_did=BENCH_DID))
    resolved = state_dir.expanduser().resolve(strict=False)
    status = migration_status(resolved)
    if not status["database_exists"]:
        raise SafetyError("worker deactivation requires existing Bench state database")
    if status["pending_migrations"]:
        raise SafetyError("worker deactivation requires migrated Bench state")
    with connect_state(resolved) as conn:
        activation = record_mailbox_deactivation(
            conn,
            mailbox=SUPERVISED_POLLING_ACTIVATION_KEY,
            protocol_version=SUPERVISED_POLLING_PROTOCOL_VERSION,
        )
    return {
        "ok": True,
        **activation,
        "mailbox": MAILBOX,
        "supervised_continuous_polling": False,
        "existing_records_preserved": True,
        "running_workers_exit_after_current_poll_or_sleep": True,
        "state_dir": str(resolved),
        "state_write": True,
        "network_action": False,
        "will_poll": False,
        "will_sign": False,
        "will_post": False,
        "will_execute": False,
        "will_reply": False,
        "will_update_router": False,
    }


def worker_status(*, state_dir: Path, now: Callable[[], datetime] = _now) -> dict[str, Any]:
    assert_isolated(BenchConfig(state_dir=state_dir, subject_did=BENCH_DID))
    row = mailbox_worker_snapshot(state_dir, mailbox=MAILBOX)
    polling_activation = _supervised_polling_activation(state_dir)
    if row is None:
        status = "unavailable"
        lease_status = "absent"
        row = {"cursor": None, "pending_human_review": 0}
    elif not row.get("worker_row_present"):
        status = "unavailable"
        lease_status = "absent"
    else:
        try:
            lease_active = (
                row.get("instance_id") is not None
                and datetime.fromisoformat(str(row["lease_expires_at"])) > now()
            )
        except (TypeError, ValueError):
            lease_active = False
        status = str(row.get("worker_status", "stopped"))
        lease_status = (
            "active" if lease_active else "expired" if row.get("instance_id") else "released"
        )
    return {
        "ok": True,
        "worker_status": status,
        "lease_status": lease_status,
        "started_at": row.get("started_at"),
        "last_heartbeat_at": row.get("last_heartbeat_at"),
        "last_poll_started_at": row.get("last_poll_started_at"),
        "last_successful_poll_at": row.get("last_successful_poll_at"),
        "consecutive_failures": int(row.get("consecutive_failures", 0)),
        "current_backoff_seconds": row.get("current_backoff_seconds", 0),
        "last_failure_classification": row.get("last_failure_classification"),
        "worker_instance_id": row.get("instance_id"),
        "cursor": row.get("cursor", 0),
        "pending_human_review": row.get("pending_human_review", 0),
        "supervised_continuous_polling": polling_activation["active"],
        "supervised_continuous_polling_activation": polling_activation["activation_status"],
        "state_write": False,
        "network_action": False,
    }


def worker_health(*, state_dir: Path, now: Callable[[], datetime] = _now) -> dict[str, Any]:
    status = worker_status(state_dir=state_dir, now=now)
    heartbeat = status["last_heartbeat_at"]
    if status["worker_status"] == "unavailable":
        health = "unavailable"
    elif status["lease_status"] != "active":
        health = "stopped" if status["worker_status"] == "stopped" else "stale"
    else:
        try:
            age = (now() - datetime.fromisoformat(str(heartbeat))).total_seconds()
        except (TypeError, ValueError):
            age = float("inf")
        row = mailbox_worker_snapshot(state_dir, mailbox=MAILBOX) or {}
        interval = max(float(row.get("poll_interval_seconds", DEFAULT_POLL_INTERVAL_SECONDS)), 1.0)
        if age > interval * 3:
            health = "stale"
        elif status["consecutive_failures"]:
            health = "degraded"
        else:
            health = "healthy"
    return {**status, "health": health}


def run_worker(
    *,
    state_dir: Path,
    transport: ActivationTransport,
    once: bool = False,
    poll_interval: float = DEFAULT_POLL_INTERVAL_SECONDS,
    max_backoff: float = DEFAULT_MAX_BACKOFF_SECONDS,
    clock: Callable[[], datetime] = _now,
    sleeper: Callable[[float], None] = time.sleep,
    jitter: Callable[[], float] = lambda: 0.0,
    poll: Callable[..., dict[str, Any]] = poll_mailbox,
    should_stop: Callable[[], bool] = lambda: False,
    log: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    validate_worker_timing(poll_interval=poll_interval, max_backoff=max_backoff)
    assert_isolated(BenchConfig(state_dir=state_dir, subject_did=BENCH_DID))
    if not once and not _supervised_polling_active(state_dir):
        raise SafetyError(
            "persistent mailbox worker requires supervised continuous polling activation"
        )
    instance_id = uuid.uuid4().hex
    lease_seconds = max(60.0, poll_interval * 2)
    with connect_state(state_dir) as conn:
        if not acquire_mailbox_worker_lease(
            conn,
            mailbox=MAILBOX,
            instance_id=instance_id,
            now=clock(),
            lease_seconds=lease_seconds,
            poll_interval_seconds=poll_interval,
        ):
            raise SafetyError("mailbox worker lease is held by another active worker")
    last: dict[str, Any] = {}
    try:
        while not should_stop():
            if not once and not _supervised_polling_active(state_dir):
                last = {
                    "ok": True,
                    "history_scan_complete": True,
                    "poll_status": "stopped_supervised_polling_deactivated",
                }
                break
            now = clock()
            with connect_state(state_dir) as conn:
                if not update_mailbox_worker(
                    conn,
                    mailbox=MAILBOX,
                    instance_id=instance_id,
                    now=now,
                    lease_seconds=lease_seconds,
                    poll_started=True,
                ):
                    raise SafetyError("mailbox worker lease was lost")
            try:
                last = poll(
                    state_dir=state_dir,
                    network=True,
                    transport=transport,
                    sleep_on_429=False,
                )
            except Exception:
                last = {"ok": False, "failure_classification": "worker_poll_exception"}
            if last.get("ok") is True and last.get("history_scan_complete") is True:
                delay = poll_interval
                with connect_state(state_dir) as conn:
                    update_mailbox_worker(
                        conn,
                        mailbox=MAILBOX,
                        instance_id=instance_id,
                        now=clock(),
                        lease_seconds=lease_seconds,
                        successful=True,
                    )
                event = "poll_complete"
            else:
                current = mailbox_worker_state(state_dir, mailbox=MAILBOX) or {}
                failures = int(current.get("consecutive_failures", 0)) + 1
                base = min(max_backoff, poll_interval * (2 ** (failures - 1)))
                delay = min(
                    max_backoff, max(poll_interval, base * (1 + max(-0.1, min(0.1, jitter()))))
                )
                with connect_state(state_dir) as conn:
                    update_mailbox_worker(
                        conn,
                        mailbox=MAILBOX,
                        instance_id=instance_id,
                        now=clock(),
                        lease_seconds=lease_seconds,
                        successful=False,
                        backoff_seconds=delay,
                        failure_classification=_safe_failure(last),
                    )
                event = "poll_incomplete"
            if log is not None:
                log(
                    {
                        "event": event,
                        "timestamp": clock().isoformat(),
                        "worker_instance_id": instance_id,
                        "poll_status": "complete" if last.get("ok") is True else "incomplete",
                        "cursor": last.get("cursor_after")
                        if isinstance(last.get("cursor_after"), int)
                        else None,
                        "failure_classification": _safe_failure(last)
                        if last.get("ok") is not True
                        else None,
                        "backoff_seconds": delay,
                    }
                )
            if once:
                break
            sleeper(delay)
    finally:
        with connect_state(state_dir) as conn:
            release_mailbox_worker_lease(conn, mailbox=MAILBOX, instance_id=instance_id)
    return {
        "ok": last.get("ok", False),
        "worker_instance_id": instance_id,
        "last_poll": last,
        "state_write": True,
        "network_action": "bounded_read_only",
    }
