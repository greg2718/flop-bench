from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .exceptions import IsolationError

DEFAULT_PRODUCTION_STATE = Path.home() / ".flop_agents" / "bench"
CANONICAL_ROOM = "d-flop-bench"
MAILBOX = "mb-flop-bench"

SCOUT_STATE = Path.home() / ".flop_agents" / "scout"
LEGACY_SCOUT_STATE = Path.home() / ".flop_scout"
SCOUT_ROOM = "d-flop-scout"
SCOUT_MAILBOX = "mb-flop-scout"
SCOUT_DID = "did:key:z6MkfJnczowbivU9SEDcZ77MEpKUfQTVbcD3i1gcwsfo4yL1"


@dataclass(frozen=True)
class BenchConfig:
    state_dir: Path
    canonical_room: str = CANONICAL_ROOM
    mailbox: str = MAILBOX
    subject_did: str | None = None


def _same_path(left: Path, right: Path) -> bool:
    return left.expanduser().resolve(strict=False) == right.expanduser().resolve(strict=False)


def _path_overlaps(left: Path, right: Path) -> bool:
    resolved_left = left.expanduser().resolve(strict=False)
    resolved_right = right.expanduser().resolve(strict=False)
    if resolved_left == resolved_right:
        return True
    return resolved_left.is_relative_to(resolved_right) or resolved_right.is_relative_to(
        resolved_left
    )


def isolation_boundaries(config: BenchConfig) -> list[dict[str, Any]]:
    state = config.state_dir.expanduser().resolve(strict=False)
    checks = [
        {
            "boundary": "bench_state_not_scout_state",
            "value": str(state),
            "deny": str(SCOUT_STATE),
            "ok": not _path_overlaps(state, SCOUT_STATE),
        },
        {
            "boundary": "bench_state_not_legacy_scout_state",
            "value": str(state),
            "deny": str(LEGACY_SCOUT_STATE),
            "ok": not _path_overlaps(state, LEGACY_SCOUT_STATE),
        },
        {
            "boundary": "bench_room_not_scout_room",
            "value": config.canonical_room,
            "deny": SCOUT_ROOM,
            "ok": config.canonical_room != SCOUT_ROOM,
        },
        {
            "boundary": "bench_mailbox_not_scout_mailbox",
            "value": config.mailbox,
            "deny": SCOUT_MAILBOX,
            "ok": config.mailbox != SCOUT_MAILBOX,
        },
        {
            "boundary": "bench_did_not_scout_did",
            "value": config.subject_did or "<none>",
            "deny": SCOUT_DID,
            "ok": config.subject_did != SCOUT_DID,
        },
    ]
    return checks


def assert_isolated(config: BenchConfig) -> None:
    failures = []
    if _path_overlaps(config.state_dir, SCOUT_STATE) or _path_overlaps(
        config.state_dir, LEGACY_SCOUT_STATE
    ):
        failures.append("state directory overlaps Scout state")
    for child in ("identity.pem", "identity.json", "observer.sqlite", "activity.jsonl"):
        if _same_path(config.state_dir / child, SCOUT_STATE / child) or _same_path(
            config.state_dir / child, LEGACY_SCOUT_STATE / child
        ):
            failures.append(f"state child overlaps Scout {child}")
    if config.canonical_room == SCOUT_ROOM:
        failures.append("canonical room overlaps Scout room")
    if config.mailbox == SCOUT_MAILBOX:
        failures.append("mailbox overlaps Scout mailbox")
    if config.subject_did == SCOUT_DID:
        failures.append("subject DID overlaps known Scout DID")
    if failures:
        raise IsolationError("; ".join(failures))


def assert_no_forbidden_config_values(values: Iterable[str]) -> None:
    overlap: list[str] = []
    for raw in values:
        value = str(raw)
        if value in {SCOUT_ROOM, SCOUT_MAILBOX, SCOUT_DID}:
            overlap.append(value)
            continue
        try:
            candidate = Path(value)
        except ValueError:
            continue
        if _path_overlaps(candidate, SCOUT_STATE) or _path_overlaps(candidate, LEGACY_SCOUT_STATE):
            overlap.append(value)
    if overlap:
        raise IsolationError(
            f"configuration contains Scout value(s): {', '.join(sorted(set(overlap)))}"
        )
