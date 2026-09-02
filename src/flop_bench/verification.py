from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .canonical import atomic_write_text, canonical_json_bytes, sha256_bytes
from .config import BENCH_DID
from .exceptions import ValidationError

LOCAL_OPERATOR_GROUP = "local-flop-agent-family"
ROUTING_LINKAGE_FIELDS = (
    "routing_decision_id",
    "routing_decision_hash",
    "task_hash",
    "verification_mode",
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
        "schema_version": "flop-verification-result/v1",
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
