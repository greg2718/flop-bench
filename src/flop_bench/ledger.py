from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .canonical import canonical_json_bytes, sha256_bytes
from .exceptions import LedgerError


def ledger_path(state_dir: Path) -> Path:
    return state_dir / "ledger.jsonl"


def previous_hash(state_dir: Path) -> str | None:
    path = ledger_path(state_dir)
    if not path.exists():
        return None
    last = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            last = json.loads(line)
    return None if last is None else str(last["record_hash"])


def compute_record_hash(record: dict[str, Any]) -> str:
    payload = {k: v for k, v in record.items() if k != "record_hash"}
    return sha256_bytes(canonical_json_bytes(payload))


def append_record(state_dir: Path, record: dict[str, Any]) -> dict[str, Any]:
    state_dir.mkdir(parents=True, exist_ok=True)
    record = dict(record)
    record["previous_ledger_hash"] = previous_hash(state_dir)
    record["record_hash"] = compute_record_hash(record)
    path = ledger_path(state_dir)
    line = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
    fd = os.open(path, flags, 0o600)
    try:
        written = os.write(fd, line)
        if written != len(line):
            raise LedgerError("short write while appending ledger record")
        os.fsync(fd)
    except OSError as exc:
        raise LedgerError("failed to append ledger record") from exc
    finally:
        os.close(fd)
    path.chmod(0o600)
    return record


def verify_ledger(state_dir: Path) -> dict[str, Any]:
    path = ledger_path(state_dir)
    if not path.exists():
        return {"ok": True, "records": 0, "last_hash": None}
    prior = None
    count = 0
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise LedgerError(f"invalid JSON on ledger line {line_no}") from exc
        if record.get("previous_ledger_hash") != prior:
            raise LedgerError(f"broken ledger linkage on line {line_no}")
        expected = compute_record_hash(record)
        if record.get("record_hash") != expected:
            raise LedgerError(f"record hash mismatch on line {line_no}")
        prior = expected
        count += 1
    return {"ok": True, "records": count, "last_hash": prior}
