from __future__ import annotations

import json
import math
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .activation import (
    MAX_RESPONSE_BYTES,
    ActivationRequestError,
    ActivationTransport,
    validate_live_gate,
)
from .canonical import atomic_write_text, canonical_json_bytes, sha256_bytes, sha256_json
from .config import (
    BENCH_DID,
    BENCH_SERVICE_CAPABILITIES,
    DEFAULT_PRODUCTION_STATE,
    MAILBOX,
    BenchConfig,
    assert_isolated,
)
from .exceptions import SafetyError, ValidationError
from .identity import b64u, load_production_identity_key
from .ledger import append_record
from .models import EvidenceBundle, MailboxResultPreview
from .posting import (
    classify_post_status,
    classify_post_transport_failure,
    message_hash,
    post_room_url,
    posted_record_matches,
    scan_room_history_for_hash,
    signed_post_body,
    signed_post_headers,
    signed_post_preimage,
    validate_signed_write_room,
)
from .protocol import parse_timestamp
from .schemas import (
    EVIDENCE_BUNDLE_SCHEMA,
    MAILBOX_RESULT_SCHEMA,
    validate_with_schema,
)
from .state import (
    complete_mailbox_execution,
    connect_state,
    insert_run,
    mailbox_activation_state,
    mailbox_execution_history,
    mailbox_request_for_execution,
    mark_mailbox_execution_running,
    migration_status,
    record_result_delivery_attempt,
    reserve_mailbox_execution,
    result_delivery_attempt,
    result_delivery_history,
    update_result_delivery_attempt,
    verification_result_import,
)
from .state import next_post_nonce as reserve_post_nonce

EXECUTE_PASSIVE_CONFIRMATION = "EXECUTE-PASSIVE-BENCH-REQUEST"
RESULT_SEND_CONFIRMATION = "SEND-FLOP-BENCH-RESULT"
MAILBOX_RESULT_SCHEMA_VERSION = "flop-bench.mailbox-result.v0.1"
SUPPORTED_REMOTE_PROCEDURE = "literal_equality"
MAX_PROCEDURE_BYTES = 2048
MAX_SCALAR_STRING_BYTES = 512
MAX_SCALAR_NUMBER_ABS = 1_000_000_000_000
STRONG_RESULT_DELIVERY_STATUSES = frozenset({"posted", "reconciled_posted", "already-posted"})


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    raise ValidationError("literal_equality values must be bounded JSON scalars")


def _check_scalar(value: Any, *, field: str) -> None:
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_SCALAR_STRING_BYTES:
            raise ValidationError(f"{field} string exceeds literal_equality bound")
        return
    if isinstance(value, int):
        if abs(value) > MAX_SCALAR_NUMBER_ABS:
            raise ValidationError(f"{field} integer exceeds literal_equality bound")
        return
    if isinstance(value, float):
        if not math.isfinite(value) or not (
            -MAX_SCALAR_NUMBER_ABS <= value <= MAX_SCALAR_NUMBER_ABS
        ):
            raise ValidationError(f"{field} number exceeds literal_equality bound")
        return
    raise ValidationError(f"{field} must be a bounded JSON scalar")


def _procedure_from_test_spec(test_spec: dict[str, Any]) -> dict[str, Any]:
    encoded = canonical_json_bytes(test_spec)
    if len(encoded) > MAX_PROCEDURE_BYTES:
        raise ValidationError("test_spec exceeds passive procedure bound")
    if "type" in test_spec:
        procedure = test_spec
    elif set(test_spec) == {"procedure"} and isinstance(test_spec.get("procedure"), list):
        procedures = test_spec["procedure"]
        if len(procedures) != 1:
            raise SafetyError("multiple remote procedures are not supported in Phase E1")
        procedure = procedures[0]
    else:
        raise ValidationError("test_spec must contain one literal_equality procedure")
    if not isinstance(procedure, dict):
        raise ValidationError("remote procedure must be an object")
    if set(procedure) != {"type", "actual", "expected"}:
        raise ValidationError("literal_equality procedure has unsupported fields")
    if procedure["type"] != SUPPORTED_REMOTE_PROCEDURE:
        raise SafetyError("unsupported remote procedure")
    _check_scalar(procedure["actual"], field="actual")
    _check_scalar(procedure["expected"], field="expected")
    if len(canonical_json_bytes(procedure)) > MAX_PROCEDURE_BYTES:
        raise ValidationError("literal_equality procedure exceeds bound")
    return dict(procedure)


def _load_envelope(row: dict[str, Any]) -> dict[str, Any]:
    request_json = row.get("request_json")
    if not isinstance(request_json, str) or not request_json:
        raise SafetyError("canonical_request_payload_unavailable")
    try:
        envelope = json.loads(request_json)
    except json.JSONDecodeError as exc:
        raise ValidationError("stored request envelope is malformed") from exc
    if not isinstance(envelope, dict):
        raise ValidationError("stored request envelope must be an object")
    return envelope


def _request_metadata(row: dict[str, Any], envelope: dict[str, Any] | None) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "message_id": row.get("message_id"),
        "room": row.get("room"),
        "seq": row.get("seq"),
        "sender_did": row.get("sender_did"),
        "nonce": row.get("nonce"),
        "nonce_decimal": row.get("nonce_decimal"),
        "message_hash": row.get("message_hash"),
        "remote_ts": row.get("remote_ts"),
        "authentication_level": row.get("authentication_level"),
        "request_id": row.get("request_id"),
        "requested_capability": row.get("requested_capability"),
        "classification": row.get("classification"),
        "review_status": row.get("review_status"),
        "received_at": row.get("received_at"),
        "expires_at": row.get("expires_at"),
        "evidence_id": row.get("evidence_id"),
        "result_link": row.get("result_link"),
        "has_canonical_request_payload": isinstance(row.get("request_json"), str)
        and bool(row.get("request_json")),
        "has_provenance": bool(row.get("provenance_json")),
    }
    if envelope is not None:
        provenance = envelope.get("provenance")
        metadata["canonical_request"] = {
            "schema_version": envelope.get("schema_version"),
            "request_id": envelope.get("request_id"),
            "sender_did": envelope.get("sender_did"),
            "target_did": envelope.get("target_did"),
            "requested_capability": envelope.get("requested_capability"),
            "created_at": envelope.get("created_at"),
            "expires_at": envelope.get("expires_at"),
            "hypothesis_sha256": sha256_bytes(str(envelope.get("hypothesis", "")).encode("utf-8")),
            "test_spec_sha256": sha256_json(envelope.get("test_spec")),
            "provenance_keys": sorted(provenance) if isinstance(provenance, dict) else [],
            "reply_room_present": isinstance(envelope.get("reply_room"), str),
        }
    return metadata


def _eligibility(
    *,
    state_dir: Path,
    request_id: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    resolved = state_dir.expanduser().resolve(strict=False)
    blockers: list[str] = []
    schema_status = migration_status(resolved)
    database_exists = bool(schema_status["database_exists"])
    pending_migrations = list(schema_status["pending_migrations"])
    migration_required = bool(pending_migrations)
    if migration_required:
        blockers.append("state_schema_migration_required")
    activation = mailbox_activation_state(resolved, mailbox=MAILBOX)
    if not activation["active"]:
        blockers.append("mailbox_intake_inactive")
    row = mailbox_request_for_execution(resolved, request_id=request_id)
    envelope: dict[str, Any] | None = None
    procedure: dict[str, Any] | None = None
    if row is None:
        blockers.append("request_not_found")
    else:
        if row.get("classification") != "valid_request":
            blockers.append("request_classification_not_valid_request")
        if row.get("review_status") != "approved_for_manual_execution":
            blockers.append("request_not_approved_for_manual_execution")
        requested = row.get("requested_capability")
        if requested not in BENCH_SERVICE_CAPABILITIES:
            blockers.append("unsupported_capability")
        expires_at = row.get("expires_at")
        if not isinstance(expires_at, str) or not expires_at:
            blockers.append("expires_at_missing")
        else:
            execution_time = now or _utc_now()
            if parse_timestamp(expires_at, "expires_at") <= execution_time:
                blockers.append("request_expired")
        execution = row.get("execution")
        if isinstance(execution, dict):
            execution_status = execution.get("execution_status")
            if execution_status == "completed":
                pass
            elif execution_status in {"reserved", "running"}:
                blockers.append("execution_reserved_or_running")
            elif execution_status == "failed_internal":
                blockers.append("execution_failed_internal_manual_recovery_required")
        try:
            envelope = _load_envelope(row)
            procedure = _procedure_from_test_spec(envelope["test_spec"])
        except (SafetyError, ValidationError) as exc:
            blockers.append(str(exc))
    return {
        "ok": True,
        "request_id": request_id,
        "eligible": not blockers,
        "blockers": blockers,
        "request": row,
        "request_metadata": None if row is None else _request_metadata(row, envelope),
        "request_envelope": envelope,
        "procedure": procedure,
        "database_exists": database_exists,
        "schema_migrations": schema_status["schema_migrations"],
        "pending_migrations": pending_migrations,
        "migration_required": migration_required,
        "permission_issues": schema_status["permission_issues"],
        "state_write": False,
        "network_action": False,
        "will_load_private_key": False,
        "will_sign": False,
        "will_post": False,
        "will_reply": False,
        "will_update_router": False,
        "will_follow_urls": False,
    }


def execution_preview(*, state_dir: Path, request_id: str) -> dict[str, Any]:
    assert_isolated(BenchConfig(state_dir=state_dir, subject_did=BENCH_DID))
    resolved = state_dir.expanduser().resolve(strict=False)
    try:
        report = _eligibility(state_dir=resolved, request_id=request_id)
    except SafetyError as exc:
        if str(exc) != "state database does not exist":
            raise
        return {
            "ok": True,
            "request_id": request_id,
            "eligible": False,
            "blockers": ["state_database_missing"],
            "state_dir": str(resolved),
            "state_write": False,
            "network_action": False,
            "will_execute": False,
            "will_load_private_key": False,
            "will_sign": False,
            "will_post": False,
            "will_reply": False,
            "will_update_router": False,
        }
    safe_report = {
        key: value for key, value in report.items() if key not in {"request", "request_envelope"}
    }
    return {
        **safe_report,
        "state_dir": str(resolved),
        "will_execute": report["eligible"],
        "execution_mode": "manual_passive_only",
        "supported_remote_procedure": SUPPORTED_REMOTE_PROCEDURE,
    }


def _run_literal_equality(procedure: dict[str, Any]) -> dict[str, Any]:
    actual = procedure["actual"]
    expected = procedure["expected"]
    actual_type = _json_type(actual)
    expected_type = _json_type(expected)
    passed = actual_type == expected_type and canonical_json_bytes(actual) == canonical_json_bytes(
        expected
    )
    return {
        "procedure_type": SUPPORTED_REMOTE_PROCEDURE,
        "actual_type": actual_type,
        "expected_type": expected_type,
        "actual_canonical_sha256": sha256_json(actual),
        "expected_canonical_sha256": sha256_json(expected),
        "pass": passed,
    }


def _evidence_substantive(
    *,
    row: dict[str, Any],
    envelope: dict[str, Any],
    procedure: dict[str, Any],
    observation: dict[str, Any],
) -> dict[str, Any]:
    result = "PASS" if observation["pass"] is True else "FAIL"
    failure_conditions = [] if result == "PASS" else ["literal_equality values differed"]
    sender_did = row.get("sender_did")
    return {
        "claim_id": envelope["request_id"],
        "request_id": envelope["request_id"],
        "hypothesis": envelope["hypothesis"],
        "capabilities": [envelope["requested_capability"]],
        "procedure": [
            {
                "type": SUPPORTED_REMOTE_PROCEDURE,
                "description": (
                    "Compare JSON scalar type and canonical JSON value; strings are inert data."
                ),
                "procedure": procedure,
            }
        ],
        "observations": [observation],
        "result": result,
        "failure_conditions": failure_conditions,
        "provenance": {
            "source": "technocore_mailbox",
            "mailbox": MAILBOX,
            "message_id": row.get("message_id"),
            "message_hash": row.get("message_hash"),
            "message_seq": row.get("seq"),
            "sender_did": sender_did,
            "remote_ts": row.get("remote_ts"),
            "request_provenance": envelope.get("provenance", {}),
            "authentication_level": row.get("authentication_level"),
            "common_control_disclosure": True,
            "independent_evidence": False,
        },
    }


def _write_evidence(
    *,
    state_dir: Path,
    row: dict[str, Any],
    envelope: dict[str, Any],
    procedure: dict[str, Any],
    observation: dict[str, Any],
) -> dict[str, Any]:
    substantive = _evidence_substantive(
        row=row,
        envelope=envelope,
        procedure=procedure,
        observation=observation,
    )
    evidence_id = "ev-mb-" + sha256_json(substantive)[:32]
    created_at = _utc_now().isoformat()
    safety_report = {
        "wallet_support": False,
        "flop_transfers": False,
        "technocore_network_calls": False,
        "outbound_posting": False,
        "automatic_url_fetching": False,
        "local_execution": False,
        "local_execution_authorized_by_cli": False,
        "identity_loaded": False,
        "signing": False,
        "mailbox_reply": False,
        "router_update": False,
        "remote_content_was_untrusted": True,
        "urls_followed": False,
        "code_executed": False,
        "network_action": False,
        "human_approval_recorded": True,
        "execution_confirmation_recorded": True,
        "confirmation_phrase_stored": False,
        "common_control_disclosure": True,
        "independent_evidence": False,
    }
    record = {
        "schema_version": "flop-bench.evidence-bundle.v0.1",
        "evidence_id": evidence_id,
        **substantive,
        "created_at": created_at,
        "assertions": [{"expect": "actual and expected have identical JSON type and value"}],
        "safety_report": safety_report,
        "previous_ledger_hash": None,
        "record_hash": "",
    }
    ledger_record = append_record(state_dir, record)
    evidence = dict(ledger_record)
    evidence_dir = state_dir / "evidence"
    evidence_path = evidence_dir / f"{evidence_id}.json"
    atomic_write_text(evidence_path, json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    artifact_hash = sha256_bytes(canonical_json_bytes(evidence))
    evidence["artifact_hash"] = artifact_hash
    validate_with_schema(evidence, EVIDENCE_BUNDLE_SCHEMA)
    EvidenceBundle.from_mapping(evidence)
    atomic_write_text(evidence_path, json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    with connect_state(state_dir) as conn:
        insert_run(
            conn,
            evidence_id=evidence_id,
            claim_id=evidence["claim_id"],
            result=evidence["result"],
            evidence_path=evidence_path,
            created_at=created_at,
        )
    return {"evidence": evidence, "evidence_path": evidence_path}


def execute_passive(*, state_dir: Path, request_id: str, confirm: str) -> dict[str, Any]:
    if confirm != EXECUTE_PASSIVE_CONFIRMATION:
        raise SafetyError("passive execution requires exact confirmation")
    assert_isolated(BenchConfig(state_dir=state_dir, subject_did=BENCH_DID))
    resolved = state_dir.expanduser().resolve(strict=False)
    initial = _eligibility(state_dir=resolved, request_id=request_id)
    if not initial["eligible"]:
        blockers = ", ".join(initial["blockers"])
        raise SafetyError(f"request is not eligible for execution: {blockers}")
    with connect_state(resolved) as conn:
        reservation = reserve_mailbox_execution(conn, request_id=request_id)
    if not reservation["created"]:
        if reservation["execution_status"] == "completed":
            return {
                "ok": True,
                "request_id": request_id,
                "execution": reservation,
                "idempotent": True,
                "execution_performed": False,
                "state_write": False,
                "network_action": False,
                "will_sign": False,
                "will_post": False,
                "will_reply": False,
                "will_update_router": False,
            }
        raise SafetyError(
            "request execution is reserved/running or requires future manual recovery"
        )
    reserved_check = _eligibility(state_dir=resolved, request_id=request_id)
    blocked_after_reservation = [
        blocker
        for blocker in reserved_check["blockers"]
        if blocker != "execution_reserved_or_running"
    ]
    if blocked_after_reservation:
        raise SafetyError(
            "request became ineligible after reservation: " + ", ".join(blocked_after_reservation)
        )
    row = reserved_check["request"]
    envelope = reserved_check["request_envelope"]
    procedure = reserved_check["procedure"]
    if (
        not isinstance(row, dict)
        or not isinstance(envelope, dict)
        or not isinstance(procedure, dict)
    ):
        raise SafetyError("request execution lost required state after reservation")
    with connect_state(resolved) as conn:
        mark_mailbox_execution_running(conn, request_id=request_id)
    observation = _run_literal_equality(procedure)
    written = _write_evidence(
        state_dir=resolved,
        row=row,
        envelope=envelope,
        procedure=procedure,
        observation=observation,
    )
    evidence = written["evidence"]
    with connect_state(resolved) as conn:
        execution = complete_mailbox_execution(
            conn,
            request_id=request_id,
            evidence_id=evidence["evidence_id"],
            evidence_path=written["evidence_path"],
            evidence_hash=evidence["artifact_hash"],
            result=evidence["result"],
        )
    return {
        "ok": True,
        "request_id": request_id,
        "execution": execution,
        "evidence": {
            "evidence_id": evidence["evidence_id"],
            "evidence_hash": evidence["artifact_hash"],
            "verdict": evidence["result"],
        },
        "idempotent": False,
        "execution_performed": True,
        "state_write": True,
        "network_action": False,
        "will_load_private_key": False,
        "will_sign": False,
        "will_post": False,
        "will_reply": False,
        "will_update_router": False,
    }


def execution_history(*, state_dir: Path, limit: int) -> dict[str, Any]:
    assert_isolated(BenchConfig(state_dir=state_dir, subject_did=BENCH_DID))
    return mailbox_execution_history(state_dir, limit=limit)


def result_preview(*, state_dir: Path, request_id: str) -> dict[str, Any]:
    assert_isolated(BenchConfig(state_dir=state_dir, subject_did=BENCH_DID))
    imported = verification_result_import(state_dir, request_id=request_id)
    if imported is not None:
        return {
            "schema_version": "flop-bench.verification-result-preview.v1",
            "request_id": request_id,
            "bench_did": imported["bench_did"],
            "routing_decision_id": imported["routing_decision_id"],
            "routing_decision_hash": imported["routing_decision_hash"],
            "task_hash": imported["task_hash"],
            "verification_mode": imported["verification_mode"],
            "status": imported["status"],
            "score": imported["score"],
            "findings": imported["findings"],
            "checks": imported["checks"],
            "reproducibility": imported["reproducibility"],
            "same_operator": imported["same_operator"],
            "independent_reputation": imported["independent_reputation"],
            "operator_group": imported["operator_group"],
            "evidence_classification": imported["evidence_classification"],
            "result_hash": imported["result_hash"],
            "artifact_hashes": imported["artifact_hashes"],
            "completed_at": imported["completed_at"],
            "authenticity_status": "UNSIGNED_LOCAL",
            "result_delivery_status": "not_sent",
            "state_write": False,
            "network_action": False,
            "will_load_private_key": False,
            "will_sign": False,
            "will_post": False,
            "will_reply": False,
            "will_update_router": False,
            "urls_followed": False,
        }
    row = mailbox_request_for_execution(state_dir, request_id=request_id)
    if row is None:
        raise SafetyError("request not found")
    execution = row.get("execution")
    if not isinstance(execution, dict) or execution.get("execution_status") != "completed":
        raise SafetyError("result preview requires completed execution")
    envelope = _load_envelope(row)
    preview = {
        "schema_version": MAILBOX_RESULT_SCHEMA_VERSION,
        "request_id": request_id,
        "evidence_id": execution["evidence_id"],
        "verdict": execution["result"],
        "evidence_hash": execution["evidence_hash"],
        "bench_did": BENCH_DID,
        "original_sender_did": row.get("sender_did"),
        "reply_room": envelope.get("reply_room"),
        "common_control_disclosure": True,
        "independent_evidence": False,
        "result_delivery_status": "not_sent",
        "phase": "Phase E1 manual-only result preparation; delivery disabled",
        "network_action": False,
        "state_write": False,
        "will_load_private_key": False,
        "will_sign": False,
        "will_acquire_nonce": False,
        "will_post": False,
        "will_reply": False,
        "will_update_router": False,
        "urls_followed": False,
    }
    validate_with_schema(preview, MAILBOX_RESULT_SCHEMA)
    MailboxResultPreview.from_mapping(preview)
    return preview


def _completed_result_envelope(row: dict[str, Any]) -> dict[str, Any]:
    execution = row.get("execution")
    if not isinstance(execution, dict) or execution.get("execution_status") != "completed":
        raise SafetyError("result delivery requires completed execution")
    target_did = row.get("sender_did")
    if not isinstance(target_did, str) or not target_did:
        raise SafetyError("result delivery target DID is unavailable")
    return {
        "schema_version": MAILBOX_RESULT_SCHEMA_VERSION,
        "request_id": row["request_id"],
        "target_did": target_did,
        "bench_did": BENCH_DID,
        "verdict": execution["result"],
        "evidence_id": execution["evidence_id"],
        "evidence_hash": execution["evidence_hash"],
        "common_control_disclosure": True,
        "independent_evidence": False,
        "urls_followed": False,
        "code_executed": False,
        "network_action": False,
    }


def _imported_verification_result_envelope(imported: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "flop-bench.verification-result-delivery.v1",
        "request_id": imported["request_id"],
        "bench_did": imported["bench_did"],
        "routing_decision_id": imported["routing_decision_id"],
        "routing_decision_hash": imported["routing_decision_hash"],
        "task_hash": imported["task_hash"],
        "verification_mode": imported["verification_mode"],
        "status": imported["status"],
        "score": imported["score"],
        "findings": imported["findings"],
        "reproducibility": imported["reproducibility"],
        "same_operator": imported["same_operator"],
        "independent_reputation": imported["independent_reputation"],
        "operator_group": imported["operator_group"],
        "evidence_classification": imported["evidence_classification"],
        "result_hash": imported["result_hash"],
        "artifact_hashes": imported["artifact_hashes"],
        "completed_at": imported["completed_at"],
        "authenticity_status": "UNSIGNED_LOCAL",
    }


def _canonical_result_text(envelope: dict[str, Any]) -> str:
    return canonical_json_bytes(envelope).decode("utf-8")


def _delivery_destination_blockers(
    *,
    reply_room: Any,
    destination: str | None,
) -> tuple[str | None, list[str]]:
    blockers: list[str] = []
    resolved = reply_room if isinstance(reply_room, str) else None
    if resolved is None:
        blockers.append("missing_result_destination")
    else:
        try:
            validate_signed_write_room(resolved)
        except SafetyError:
            blockers.append("unsupported_result_destination")
        if not resolved.startswith("mb-"):
            blockers.append("unsupported_result_destination")
    if destination is not None:
        try:
            validate_signed_write_room(destination)
        except SafetyError:
            blockers.append("unsupported_cli_destination")
        if not destination.startswith("mb-"):
            blockers.append("unsupported_cli_destination")
        if resolved is not None and destination != resolved:
            blockers.append("destination_mismatch")
    return resolved, list(dict.fromkeys(blockers))


def result_delivery_preview(*, state_dir: Path, request_id: str) -> dict[str, Any]:
    assert_isolated(BenchConfig(state_dir=state_dir, subject_did=BENCH_DID))
    resolved = state_dir.expanduser().resolve(strict=False)
    blockers: list[str] = []
    status = migration_status(resolved)
    imported = (
        None
        if not status["database_exists"]
        else verification_result_import(resolved, request_id=request_id)
    )
    if imported is not None:
        row = None
        reply_room = None
        envelope = _imported_verification_result_envelope(imported)
        blockers.append("missing_result_destination")
        blockers.append("result_delivery_target_did_unavailable")
    elif not status["database_exists"]:
        blockers.append("state_database_missing")
        row = None
        envelope = None
        reply_room = None
    else:
        pending_migrations = list(status["pending_migrations"])
        if pending_migrations:
            blockers.append("state_schema_migration_required")
        row = mailbox_request_for_execution(resolved, request_id=request_id)
        if row is None:
            blockers.append("request_not_found")
            envelope = None
            reply_room = None
        else:
            try:
                request_envelope = _load_envelope(row)
                reply_room = request_envelope.get("reply_room")
            except (SafetyError, ValidationError) as exc:
                blockers.append(str(exc))
                reply_room = None
            try:
                envelope = _completed_result_envelope(row)
            except SafetyError as exc:
                blockers.append(str(exc))
                envelope = None
    destination, destination_blockers = _delivery_destination_blockers(
        reply_room=reply_room, destination=None
    )
    blockers.extend(destination_blockers)
    result_text = _canonical_result_text(envelope) if envelope is not None else None
    return {
        "ok": True,
        "request_id": request_id,
        "can_send": not blockers,
        "blockers": list(dict.fromkeys(blockers)),
        "destination": destination,
        "message_hash": message_hash(result_text) if result_text is not None else None,
        "message_bytes": len(result_text.encode("utf-8")) if result_text is not None else None,
        "result_envelope": envelope,
        "result_text": result_text,
        "state_dir": str(resolved),
        "state_write": False,
        "network_action": False,
        "will_load_private_key": False,
        "will_sign": False,
        "will_acquire_nonce": False,
        "will_post": False,
        "will_reply": False,
        "will_update_router": False,
        "urls_followed": False,
    }


def _start_result_delivery_audit(
    state_dir: Path,
    *,
    request_id: str,
    destination: str,
    target_did: str,
    message_hash_value: str,
    bench_did: str,
) -> int:
    with connect_state(state_dir) as conn:
        return record_result_delivery_attempt(
            conn,
            request_id=request_id,
            destination=destination,
            bench_did=bench_did,
            target_did=target_did,
            message_hash=message_hash_value,
            delivery_status="started",
            response_status=None,
            nonce_used=None,
            seq=None,
            failure_classification=None,
        )


def _update_result_delivery_audit(
    state_dir: Path,
    *,
    delivery_id: int,
    delivery_status: str,
    response_status: int | None,
    nonce_used: int | None,
    seq: int | None,
    failure_classification: str | None,
) -> None:
    with connect_state(state_dir) as conn:
        update_result_delivery_attempt(
            conn,
            delivery_id=delivery_id,
            delivery_status=delivery_status,
            response_status=response_status,
            nonce_used=nonce_used,
            seq=seq,
            failure_classification=failure_classification,
        )


def _next_delivery_nonce(state_dir: Path) -> int:
    with connect_state(state_dir) as conn:
        return reserve_post_nonce(conn)


def _result_delivery_transition(
    current: dict[str, Any],
    *,
    observed_status: str,
    observed_seq: int | None,
    observed_failure_classification: str | None,
) -> dict[str, Any]:
    current_status = str(current["delivery_status"])
    current_seq = current["seq"] if isinstance(current["seq"], int) else None
    current_failure = current["failure_classification"]
    if observed_status == "reconciled_posted":
        return {
            "state_write": (
                current_status != "reconciled_posted"
                or current_seq != observed_seq
                or current_failure is not None
            ),
            "delivery_status": "reconciled_posted",
            "seq": observed_seq if observed_seq is not None else current_seq,
            "failure_classification": None,
        }
    if current_status in STRONG_RESULT_DELIVERY_STATUSES:
        return {
            "state_write": False,
            "delivery_status": current_status,
            "seq": current_seq,
            "failure_classification": current_failure,
        }
    if observed_status in {"reconciliation_incomplete", "matching_message_different_nonce"}:
        return {
            "state_write": False,
            "delivery_status": current_status,
            "seq": current_seq,
            "failure_classification": current_failure,
        }
    if observed_status == "reconciled_absent":
        return {
            "state_write": (
                current_status != "reconciled_absent"
                or current_failure != observed_failure_classification
            ),
            "delivery_status": "reconciled_absent",
            "seq": current_seq,
            "failure_classification": observed_failure_classification,
        }
    return {
        "state_write": False,
        "delivery_status": current_status,
        "seq": current_seq,
        "failure_classification": current_failure,
    }


def send_result_delivery(
    *,
    state_dir: Path,
    request_id: str,
    destination: str,
    live: bool,
    confirm: str,
    passphrase: str,
    transport: ActivationTransport,
    expected_state_dir: Path = DEFAULT_PRODUCTION_STATE,
    expected_bench_did: str = BENCH_DID,
) -> dict[str, Any]:
    preview = result_delivery_preview(state_dir=state_dir, request_id=request_id)
    preview_destination = preview["destination"]
    _, destination_blockers = _delivery_destination_blockers(
        reply_room=preview_destination,
        destination=destination,
    )
    blockers = list(dict.fromkeys([*preview["blockers"], *destination_blockers]))
    if blockers:
        raise SafetyError("result delivery is blocked: " + ", ".join(blockers))
    if destination != preview_destination:
        raise SafetyError("result delivery destination_mismatch")
    resolved_state = validate_live_gate(
        live=live,
        confirm=confirm,
        expected_confirm=RESULT_SEND_CONFIRMATION,
        state_dir=state_dir,
        expected_state_dir=expected_state_dir,
    )
    envelope = preview["result_envelope"]
    text = preview["result_text"]
    if not isinstance(envelope, dict) or not isinstance(text, str):
        raise SafetyError("result delivery preview did not produce sendable bytes")
    digest = message_hash(text)
    key = load_production_identity_key(
        state_dir=resolved_state,
        passphrase=passphrase,
        expected_state_dir=expected_state_dir,
        expected_did=expected_bench_did,
    )
    target_did = str(envelope["target_did"])
    delivery_id = _start_result_delivery_audit(
        resolved_state,
        request_id=request_id,
        destination=destination,
        target_did=target_did,
        message_hash_value=digest,
        bench_did=expected_bench_did,
    )
    try:
        preflight = scan_room_history_for_hash(
            transport,
            room=destination,
            expected_did=expected_bench_did,
            digest=digest,
        )
        if not preflight["history_scan_complete"]:
            raise ActivationRequestError(
                "Technocore result destination history could not be completely searched",
                failure_classification=str(
                    preflight["failure_classification"] or "history_scan_incomplete"
                ),
            )
    except ActivationRequestError as exc:
        _update_result_delivery_audit(
            resolved_state,
            delivery_id=delivery_id,
            delivery_status="failed_preflight",
            response_status=exc.response.status if exc.response else None,
            nonce_used=None,
            seq=None,
            failure_classification=exc.failure_classification,
        )
        raise
    if preflight["exact_match_found"]:
        _update_result_delivery_audit(
            resolved_state,
            delivery_id=delivery_id,
            delivery_status="already-posted",
            response_status=None,
            nonce_used=None,
            seq=int(preflight["seq"]),
            failure_classification=None,
        )
        return {
            "ok": True,
            "request_id": request_id,
            "destination": destination,
            "did": expected_bench_did,
            "delivery_status": "already-posted",
            "message_hash": digest,
            "nonce": None,
            "seq": preflight["seq"],
            "delivery_id": delivery_id,
            "idempotency_preflight": preflight,
            "network_action": True,
            "state_write": True,
        }
    nonce = _next_delivery_nonce(resolved_state)
    try:
        sig = b64u(key.sign(signed_post_preimage(destination, nonce, text)))
    except Exception as exc:
        _update_result_delivery_audit(
            resolved_state,
            delivery_id=delivery_id,
            delivery_status="failed",
            response_status=None,
            nonce_used=nonce,
            seq=None,
            failure_classification="signing_failure",
        )
        raise SafetyError("Technocore result delivery signing failed") from exc
    body = signed_post_body(did=expected_bench_did, sig=sig, nonce=nonce, text=text)
    headers = signed_post_headers()
    url = post_room_url(destination)
    try:
        response = transport.request("POST", url, body=body, headers=headers)
        if response.final_url and response.final_url != url:
            raise ActivationRequestError(
                "Technocore redirect refused",
                failure_classification="redirect_rejected",
                response=response,
            )
        if len(response.body) > MAX_RESPONSE_BYTES:
            raise ActivationRequestError(
                "Technocore response exceeded local safety limit",
                failure_classification="oversized_response",
                response=response,
            )
        if response.status != 200:
            raise ActivationRequestError(
                f"Technocore result delivery failed: HTTP {response.status}",
                failure_classification=classify_post_status(response.status),
                response=response,
            )
        parsed = json.loads(response.body.decode("utf-8"))
    except ActivationRequestError as exc:
        delivery_status, failure_classification = classify_post_transport_failure(
            exc.failure_classification
        )
        if exc.response is not None:
            delivery_status = "confirmed_rejected"
            failure_classification = exc.failure_classification
        _update_result_delivery_audit(
            resolved_state,
            delivery_id=delivery_id,
            delivery_status=delivery_status,
            response_status=exc.response.status if exc.response else None,
            nonce_used=nonce,
            seq=None,
            failure_classification=failure_classification,
        )
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _update_result_delivery_audit(
            resolved_state,
            delivery_id=delivery_id,
            delivery_status="failed",
            response_status=response.status if "response" in locals() else None,
            nonce_used=nonce,
            seq=None,
            failure_classification="malformed_response",
        )
        raise SafetyError("Technocore returned an invalid JSON response") from exc
    except Exception as exc:
        _update_result_delivery_audit(
            resolved_state,
            delivery_id=delivery_id,
            delivery_status="failed",
            response_status=None,
            nonce_used=nonce,
            seq=None,
            failure_classification="unexpected_local_failure",
        )
        raise SafetyError("Technocore result delivery failed unexpectedly") from exc
    if not isinstance(parsed, dict) or not isinstance(parsed.get("posted"), dict):
        _update_result_delivery_audit(
            resolved_state,
            delivery_id=delivery_id,
            delivery_status="failed",
            response_status=response.status,
            nonce_used=nonce,
            seq=None,
            failure_classification="malformed_response",
        )
        raise SafetyError("Technocore did not return a posted record")
    posted = parsed["posted"]
    seq = posted.get("seq")
    if not posted_record_matches(posted, did=expected_bench_did, text=text, nonce=nonce):
        _update_result_delivery_audit(
            resolved_state,
            delivery_id=delivery_id,
            delivery_status="failed",
            response_status=response.status,
            nonce_used=nonce,
            seq=seq if isinstance(seq, int) else None,
            failure_classification="unverifiable_post",
        )
        raise SafetyError("returned posted record did not match signed result delivery")
    _update_result_delivery_audit(
        resolved_state,
        delivery_id=delivery_id,
        delivery_status="posted",
        response_status=response.status,
        nonce_used=nonce,
        seq=seq,
        failure_classification=None,
    )
    return {
        "ok": True,
        "request_id": request_id,
        "destination": destination,
        "did": expected_bench_did,
        "delivery_status": "posted",
        "message_hash": digest,
        "nonce": nonce,
        "seq": seq,
        "delivery_id": delivery_id,
        "network_action": True,
        "state_write": True,
    }


def reconcile_result_delivery(
    *,
    state_dir: Path,
    delivery_id: int,
    transport: ActivationTransport,
    expected_bench_did: str = BENCH_DID,
) -> dict[str, Any]:
    resolved_state = state_dir.expanduser().resolve(strict=False)
    attempt = result_delivery_attempt(resolved_state, delivery_id=delivery_id)
    destination = str(attempt["destination"])
    validate_signed_write_room(destination)
    if not destination.startswith("mb-"):
        raise SafetyError("result delivery reconcile is restricted to mb-* attempts")
    if attempt["bench_did"] != expected_bench_did:
        raise SafetyError("result delivery attempt DID does not match Bench DID")
    attempt_nonce = attempt["nonce_used"]
    if not isinstance(attempt_nonce, int):
        raise SafetyError("result delivery reconcile attempt has no recorded nonce")
    digest = str(attempt["message_hash"])
    scan = scan_room_history_for_hash(
        transport,
        room=destination,
        expected_did=expected_bench_did,
        digest=digest,
        attempt_nonce=attempt_nonce,
    )
    observed_seq: int | None
    if scan["exact_attempt_match"]:
        observed_status = "reconciled_posted"
        observed_classification = None
        observed_seq = int(scan["exact_attempt_seq"])
    elif scan["matching_message_different_nonce"]:
        observed_status = "matching_message_different_nonce"
        observed_classification = None
        observed_seq = attempt["seq"] if isinstance(attempt["seq"], int) else None
    elif scan["history_scan_complete"]:
        observed_status = "reconciled_absent"
        observed_classification = "absent_not_proven_rejected"
        observed_seq = None
    else:
        observed_status = "reconciliation_incomplete"
        observed_classification = str(scan["failure_classification"] or "history_scan_incomplete")
        observed_seq = attempt["seq"] if isinstance(attempt["seq"], int) else None
    transition = _result_delivery_transition(
        attempt,
        observed_status=observed_status,
        observed_seq=observed_seq,
        observed_failure_classification=observed_classification,
    )
    state_write = bool(transition["state_write"])
    if state_write:
        _update_result_delivery_audit(
            resolved_state,
            delivery_id=delivery_id,
            delivery_status=str(transition["delivery_status"]),
            response_status=attempt["response_status"],
            nonce_used=attempt_nonce,
            seq=transition["seq"] if isinstance(transition["seq"], int) else None,
            failure_classification=(
                str(transition["failure_classification"])
                if transition["failure_classification"] is not None
                else None
            ),
        )
    return {
        "ok": scan["history_scan_complete"],
        "delivery_id": delivery_id,
        "request_id": attempt["request_id"],
        "destination": destination,
        "bench_did": expected_bench_did,
        "message_hash": digest,
        "exact_match_found": scan["exact_match_found"],
        "exact_attempt_match": scan["exact_attempt_match"],
        "attempt_nonce": attempt_nonce,
        "matched_nonce": scan["matched_nonce"],
        "matching_message_other_nonce": scan["matching_message_other_nonce"],
        "matching_message_different_nonce": scan["matching_message_different_nonce"],
        "matching_message_unattributable_nonce": scan["matching_message_unattributable_nonce"],
        "seq": observed_seq if scan["exact_attempt_match"] else scan["seq"],
        "history_scan_complete": scan["history_scan_complete"],
        "pages_scanned": scan["pages_scanned"],
        "reconciliation_status": observed_status,
        "audit_status": transition["delivery_status"],
        "audit_transition": "updated" if state_write else "preserved",
        "state_write": state_write,
        "network_action": "bounded_read_only",
    }


def result_history(*, state_dir: Path, limit: int) -> dict[str, Any]:
    assert_isolated(BenchConfig(state_dir=state_dir, subject_did=BENCH_DID))
    return result_delivery_history(state_dir, limit=limit)
