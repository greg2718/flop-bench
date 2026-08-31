from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .canonical import sha256_json
from .config import (
    BENCH_DID,
    CANONICAL_ROOM,
    DEFAULT_PRODUCTION_STATE,
    MAILBOX,
    SCOUT_DID,
    BenchConfig,
    assert_isolated,
)
from .exceptions import SafetyError, ValidationError
from .identity import load_production_identity_key
from .protocol import (
    REQUEST_SCHEMA_VERSION,
    RESPONSE_SCHEMA_VERSION,
    SUPPORTED_CAPABILITIES,
    independent_evidence_for_subject,
    operator_group_for_subject,
    sign_envelope,
    validate_nonce,
    validate_room_and_mailbox,
    validate_timestamp_window,
    verify_signed_envelope,
)
from .state import connect_state, connect_state_with_migrations, migration_status, reserve_request

REQUEST_REQUIRED = {
    "schema_version",
    "request_id",
    "sender_did",
    "target_did",
    "requested_capability",
    "hypothesis",
    "test_spec",
    "created_at",
    "expires_at",
    "nonce",
    "signature",
    "provenance",
}
REQUEST_OPTIONAL = {"operator_group"}


def validate_request_shape(envelope: dict[str, Any]) -> None:
    unexpected = set(envelope) - REQUEST_REQUIRED - REQUEST_OPTIONAL
    missing = REQUEST_REQUIRED - set(envelope)
    if unexpected:
        raise ValidationError(f"unexpected request field(s): {', '.join(sorted(unexpected))}")
    if missing:
        raise ValidationError(f"missing request field(s): {', '.join(sorted(missing))}")
    for field in ("request_id", "sender_did", "target_did", "requested_capability", "hypothesis"):
        if not isinstance(envelope[field], str) or not envelope[field]:
            raise ValidationError(f"{field} must be a nonempty string")
    if not isinstance(envelope["test_spec"], dict):
        raise ValidationError("test_spec must be an object")
    if not isinstance(envelope["provenance"], dict):
        raise ValidationError("provenance must be an object")
    if "operator_group" in envelope and not isinstance(envelope["operator_group"], dict):
        raise ValidationError("operator_group must be an object")


def inspect_request(request_path: Path, *, state_dir: Path) -> dict[str, Any]:
    assert_isolated(BenchConfig(state_dir=state_dir))
    envelope = json.loads(request_path.read_text(encoding="utf-8"))
    validate_request_shape(envelope)
    return {
        "ok": True,
        "request_id": envelope["request_id"],
        "sender_did": envelope["sender_did"],
        "target_did": envelope["target_did"],
        "requested_capability": envelope["requested_capability"],
        "contains_url": "http://" in json.dumps(envelope) or "https://" in json.dumps(envelope),
        "network_action": False,
        "execution_action": False,
    }


def verify_request(
    request_path: Path,
    *,
    state_dir: Path,
    expected_bench_did: str = BENCH_DID,
    now: datetime | None = None,
) -> dict[str, Any]:
    assert_isolated(BenchConfig(state_dir=state_dir, subject_did=expected_bench_did))
    envelope = json.loads(request_path.read_text(encoding="utf-8"))
    validate_request_shape(envelope)
    if envelope["schema_version"] != REQUEST_SCHEMA_VERSION:
        raise ValidationError("unsupported request schema_version")
    if envelope["target_did"] != expected_bench_did:
        raise SafetyError("request target_did is not the Bench DID")
    if envelope["sender_did"] == expected_bench_did:
        raise SafetyError("Bench requests to itself are not independent evidence")
    if envelope["sender_did"] == SCOUT_DID and envelope.get("operator_group") is None:
        raise SafetyError("Scout requests must include common-control operator_group disclosure")
    if envelope["requested_capability"] not in SUPPORTED_CAPABILITIES:
        raise SafetyError("unsupported requested capability")
    nonce = validate_nonce(envelope["nonce"])
    validate_timestamp_window(envelope["created_at"], envelope["expires_at"], now=now)
    verify_signed_envelope("request", envelope, envelope["sender_did"])
    with connect_state(state_dir) as conn:
        reservation = reserve_request(
            conn,
            request_id=envelope["request_id"],
            sender_did=envelope["sender_did"],
            nonce=nonce,
            expires_at=envelope["expires_at"],
        )
    return {
        "ok": True,
        "request_id": envelope["request_id"],
        "sender_did": envelope["sender_did"],
        "target_did": envelope["target_did"],
        "requested_capability": envelope["requested_capability"],
        "policy_approval_required": True,
        "will_execute": False,
        "reservation": reservation,
    }


def response_payload_from_evidence(
    evidence: dict[str, Any],
    *,
    verifier_did: str = BENCH_DID,
) -> dict[str, Any]:
    provenance = evidence.get("provenance", {})
    if not isinstance(provenance, dict):
        raise ValidationError("evidence provenance must be an object")
    subject_did = str(provenance.get("subject_did") or evidence.get("subject_did") or "")
    if not subject_did:
        subject_did = str(provenance.get("sender_did") or "unknown")
    independent = independent_evidence_for_subject(subject_did)
    return {
        "schema_version": RESPONSE_SCHEMA_VERSION,
        "request_id": evidence.get("request_id", evidence.get("claim_id", "")),
        "verifier_did": verifier_did,
        "subject_did": subject_did,
        "capability": (evidence.get("capabilities") or ["unknown"])[0],
        "hypothesis": evidence["hypothesis"],
        "procedure": evidence["procedure"],
        "observations": evidence["observations"],
        "result": evidence["result"],
        "failure_conditions": evidence["failure_conditions"],
        "evidence_id": evidence["evidence_id"],
        "provenance": evidence["provenance"],
        "limitations": [
            "FLOP Bench Phase A is offline-only and does not validate live Technocore state.",
            "Related-agent validation must not be counted as independent peer reputation.",
        ],
        "operator_group": operator_group_for_subject(subject_did),
        "independent_evidence": independent,
        "created_at": datetime.now(UTC).isoformat(),
    }


def prepare_signed_response(
    evidence_path: Path,
    *,
    state_dir: Path,
    passphrase: str,
    expected_bench_did: str = BENCH_DID,
    expected_identity_state_dir: Path | None = None,
) -> dict[str, Any]:
    key = load_production_identity_key(
        state_dir=state_dir,
        passphrase=passphrase,
        expected_state_dir=expected_identity_state_dir or DEFAULT_PRODUCTION_STATE,
        expected_did=expected_bench_did,
    )
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    payload = response_payload_from_evidence(evidence, verifier_did=expected_bench_did)
    return sign_envelope("response", payload, key)


def verify_signed_response(envelope: dict[str, Any]) -> None:
    if envelope.get("schema_version") != RESPONSE_SCHEMA_VERSION:
        raise ValidationError("unsupported response schema_version")
    verify_signed_envelope("response", envelope, str(envelope.get("verifier_did", "")))


def plan_init(*, state_dir: Path) -> dict[str, Any]:
    assert_isolated(BenchConfig(state_dir=state_dir, subject_did=BENCH_DID))
    validate_room_and_mailbox()
    return {
        "ok": True,
        "dry_run": True,
        "state_dir": str(state_dir.expanduser().resolve(strict=False)),
        "bench_did": BENCH_DID,
        "canonical_room": CANONICAL_ROOM,
        "mailbox": MAILBOX,
        "planned_actions": [
            {"action": "create-room", "room": CANONICAL_ROOM, "will_execute": False},
            {
                "action": "create-mailbox",
                "room": MAILBOX,
                "will_execute": False,
                "creation_required": False,
                "protocol": "signed-write-only-room",
                "advertised": False,
            },
        ],
        "network_action": False,
        "state_write": False,
        "migrations_applied": [],
    }


def service_doctor(*, state_dir: Path, read_only: bool = False) -> dict[str, Any]:
    assert_isolated(BenchConfig(state_dir=state_dir, subject_did=BENCH_DID))
    if read_only:
        status = migration_status(state_dir)
        return {
            "ok": True,
            "dry_run": True,
            "read_only": True,
            "state_dir": str(state_dir.expanduser().resolve(strict=False)),
            "schema_migrations": status["schema_migrations"],
            "pending_migrations": status["pending_migrations"],
            "state_dir_exists": status["state_dir_exists"],
            "database_exists": status["database_exists"],
            "permission_issues": status["permission_issues"],
            "state_write": False,
            "migrations_applied": [],
            "live_transport": False,
            "network_action": False,
        }
    conn, migrations_applied = connect_state_with_migrations(state_dir)
    with conn:
        migrations = [row[0] for row in conn.execute("SELECT version FROM schema_migrations")]
    return {
        "ok": True,
        "dry_run": True,
        "read_only": False,
        "state_dir": str(state_dir.expanduser().resolve(strict=False)),
        "schema_migrations": migrations,
        "pending_migrations": [],
        "permission_issues": [],
        "state_write": True,
        "migrations_applied": migrations_applied,
        "live_transport": False,
        "network_action": False,
    }


def dry_run_sign_payload(
    payload_path: Path,
    *,
    state_dir: Path,
    passphrase: str,
    expected_bench_did: str = BENCH_DID,
    expected_identity_state_dir: Path | None = None,
) -> dict[str, Any]:
    key = load_production_identity_key(
        state_dir=state_dir,
        passphrase=passphrase,
        expected_state_dir=expected_identity_state_dir or DEFAULT_PRODUCTION_STATE,
        expected_did=expected_bench_did,
    )
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValidationError("payload must be a JSON object")
    dry_run_payload = {
        **payload,
        "dry_run": True,
        "network_action": False,
        "payload_hash": sha256_json(payload),
    }
    return sign_envelope("dry-run", dry_run_payload, key)
