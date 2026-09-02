from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .canonical import atomic_write_text, canonical_json_bytes, sha256_bytes
from .config import BENCH_DID
from .exceptions import SafetyError, ValidationError
from .state import (
    connect_state,
    migration_status,
    record_verification_result_import,
    verification_result_import,
)

LOCAL_OPERATOR_GROUP = "local-flop-agent-family"
ROUTING_LINKAGE_FIELDS = (
    "routing_decision_id",
    "routing_decision_hash",
    "task_hash",
    "verification_mode",
)
VERIFICATION_RESULT_SCHEMA_VERSION = "flop-verification-result/v1"
MAX_VERIFICATION_RESULT_BYTES = 64 * 1024
_REQUIRED_RESULT_FIELDS = frozenset(
    {
        "schema_version",
        "request_id",
        "bench_did",
        "routing_decision_id",
        "routing_decision_hash",
        "task_hash",
        "verification_mode",
        "status",
        "score",
        "findings",
        "checks",
        "reproducibility",
        "same_operator",
        "independent_reputation",
        "operator_group",
        "result_hash",
        "artifact_hashes",
        "completed_at",
        "network_writes",
        "private_key_accesses",
        "tclk_settlement_actions",
    }
)


def canonical_json_hash(value: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def load_json_artifact(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValidationError(f"{path} must contain a JSON object")
    return loaded


def write_json_artifact(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def verify_signing_request(
    request: dict[str, Any], *, completed_at: str | None = None
) -> dict[str, Any]:
    if request.get("schema_version") != "flop-verification-request/v1":
        raise ValidationError("unsupported verification request schema")
    if request.get("task_type") != "technocore.synthetic_signing_payload_order":
        raise ValidationError("unsupported verification task type")
    specimen = request.get("specimen")
    if not isinstance(specimen, dict):
        raise ValidationError("verification request specimen must be an object")
    room = str(specimen.get("room", ""))
    nonce = str(specimen.get("nonce", ""))
    text = str(specimen.get("text", ""))
    expected_payload = f"{room}|{nonce}|{text}"
    supplied_payload = str(specimen.get("supplied_payload", ""))
    expected_supplied = f"{room}|{text}|{nonce}"
    expected_properties = request.get("expected_properties")
    if not isinstance(expected_properties, dict):
        expected_properties = {}
    checks = {
        "canonical_order_expected": expected_properties.get("canonical_order") == "room|nonce|text",
        "broken_payload_detected": supplied_payload == expected_supplied,
        "preimage_differs": supplied_payload != expected_payload,
        "correct_reconstruction_identified": specimen.get("expected_payload") == expected_payload,
    }
    passed = all(checks.values())
    findings = ["nonce/text ordering defect identified"] if passed else []
    operator_group = request.get("operator_group", LOCAL_OPERATOR_GROUP)
    same_operator = request.get("same_operator")
    if not isinstance(same_operator, bool):
        same_operator = operator_group == LOCAL_OPERATOR_GROUP
    independent_reputation = request.get("independent_reputation")
    if not isinstance(independent_reputation, bool):
        independent_reputation = False
    result = {
        "schema_version": VERIFICATION_RESULT_SCHEMA_VERSION,
        "request_id": request.get("request_id"),
        "bench_did": BENCH_DID,
        "status": "PASS" if passed else "FAIL",
        "checks": checks,
        "score": 100 if passed else 0,
        "findings": findings,
        "reproducibility": "DETERMINISTIC",
        "artifact_hashes": {
            "request_sha256": canonical_json_hash(request),
            "expected_payload_sha256": sha256_bytes(expected_payload.encode("utf-8")),
            "supplied_payload_sha256": sha256_bytes(supplied_payload.encode("utf-8")),
        },
        "completed_at": completed_at or datetime.now(UTC).isoformat(),
        "operator_group": operator_group,
        "same_operator": same_operator,
        "independent_reputation": independent_reputation,
        "network_writes": 0,
        "private_key_accesses": 0,
        "tclk_settlement_actions": 0,
    }
    for field in ROUTING_LINKAGE_FIELDS:
        if field in request:
            result[field] = request[field]
    if same_operator is True and independent_reputation is False:
        result["evidence_classification"] = "CONTROLLED_SAME_OPERATOR_VALIDATION"
    result["result_hash"] = canonical_json_hash(result)
    return result


def _require_text(result: dict[str, Any], field: str, *, max_bytes: int = 4096) -> str:
    value = result.get(field)
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > max_bytes:
        raise ValidationError(f"verification result {field} is invalid")
    return value


def validate_verification_result(result: dict[str, Any]) -> None:
    """Validate a Router-linked result without coercing it into legacy evidence."""
    if result.get("schema_version") != VERIFICATION_RESULT_SCHEMA_VERSION:
        raise ValidationError("unsupported verification result schema")
    missing = _REQUIRED_RESULT_FIELDS - result.keys()
    if missing:
        raise ValidationError("verification result missing required fields")
    for field in (
        "request_id",
        "routing_decision_id",
        "verification_mode",
        "reproducibility",
        "operator_group",
        "completed_at",
    ):
        _require_text(result, field)
    if result.get("bench_did") != BENCH_DID:
        raise ValidationError("verification result bench DID does not match this Bench")
    for field in ("routing_decision_hash", "task_hash", "result_hash"):
        value = _require_text(result, field, max_bytes=64)
        if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ValidationError(f"verification result {field} must be a SHA-256 hex digest")
    if result.get("status") not in {"PASS", "PARTIAL", "FAIL"}:
        raise ValidationError("verification result status is invalid")
    score = result.get("score")
    if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
        raise ValidationError("verification result score is invalid")
    if not isinstance(result.get("findings"), list) or not all(
        isinstance(item, str) and len(item.encode("utf-8")) <= 4096 for item in result["findings"]
    ):
        raise ValidationError("verification result findings are invalid")
    if not isinstance(result.get("checks"), dict) or not all(
        isinstance(key, str) and isinstance(value, bool) for key, value in result["checks"].items()
    ):
        raise ValidationError("verification result checks are invalid")
    artifact_hashes = result.get("artifact_hashes")
    if not isinstance(artifact_hashes, dict) or not artifact_hashes:
        raise ValidationError("verification result artifact hashes are invalid")
    if not all(
        isinstance(key, str)
        and isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
        for key, value in artifact_hashes.items()
    ):
        raise ValidationError("verification result artifact hashes are invalid")
    if not isinstance(result.get("same_operator"), bool) or not isinstance(
        result.get("independent_reputation"), bool
    ):
        raise ValidationError("verification result operator provenance is invalid")
    if any(
        result.get(field) != 0
        for field in ("network_writes", "private_key_accesses", "tclk_settlement_actions")
    ):
        raise ValidationError("verification result safety counters must be zero")
    hash_input = {key: value for key, value in result.items() if key != "result_hash"}
    if canonical_json_hash(hash_input) != result["result_hash"]:
        raise ValidationError("verification result hash does not match its contents")


def prepare_verification_delivery(result_path: Path, *, state_dir: Path) -> dict[str, Any]:
    """Import a validated unsigned verification result into the existing delivery state."""
    raw = result_path.read_bytes()
    if len(raw) > MAX_VERIFICATION_RESULT_BYTES:
        raise ValidationError("verification result exceeds local size limit")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("verification result must be valid UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise ValidationError("verification result must contain a JSON object")
    validate_verification_result(parsed)
    existing = (
        verification_result_import(state_dir, request_id=parsed["request_id"])
        if migration_status(state_dir)["database_exists"]
        else None
    )
    if existing is not None:
        if existing["result_hash"] != parsed["result_hash"]:
            raise SafetyError(
                "verification result request_id conflicts with existing imported result"
            )
        return {
            "ok": True,
            "request_id": parsed["request_id"],
            "status": "already-prepared",
            "result_hash": parsed["result_hash"],
            "authenticity_status": "UNSIGNED_LOCAL",
            "private_key_accesses": 0,
            "network_writes": 0,
            "state_write": False,
            "network_action": False,
        }
    with connect_state(state_dir) as conn:
        created = record_verification_result_import(conn, result=parsed)
    return {
        "ok": True,
        "request_id": parsed["request_id"],
        "status": "prepared" if created else "already-prepared",
        "result_hash": parsed["result_hash"],
        "authenticity_status": "UNSIGNED_LOCAL",
        "private_key_accesses": 0,
        "network_writes": 0,
        "state_write": created,
        "network_action": False,
    }


def verify_request_file(
    request_path: Path,
    *,
    output: Path | None = None,
    completed_at: str | None = None,
) -> dict[str, Any]:
    result = verify_signing_request(load_json_artifact(request_path), completed_at=completed_at)
    if output is not None:
        write_json_artifact(output, result)
    return result
