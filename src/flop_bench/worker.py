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
    mailbox_worker_snapshot,
    mailbox_worker_state,
    release_mailbox_worker_lease,
    update_mailbox_worker,
)

DEFAULT_POLL_INTERVAL_SECONDS = 30.0
DEFAULT_MAX_BACKOFF_SECONDS = 300.0
MAX_INTERVAL_SECONDS = 3600.0
_SAFE_FAILURE_RE = re.compile(r"^[a-z0-9_]{1,64}$")


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


def worker_status(*, state_dir: Path, now: Callable[[], datetime] = _now) -> dict[str, Any]:
    assert_isolated(BenchConfig(state_dir=state_dir, subject_did=BENCH_DID))
    row = mailbox_worker_snapshot(state_dir, mailbox=MAILBOX)
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
