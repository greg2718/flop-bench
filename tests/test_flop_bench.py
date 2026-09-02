from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

from flop_bench import config as config_mod
from flop_bench import engine
from flop_bench.activation import (
    CREATE_MAILBOX_CONFIRMATION,
    CREATE_ROOM_CONFIRMATION,
    MAX_RESPONSE_BYTES,
    TECHNOCORE_ORIGIN,
    ActivationRequestError,
    TransportResponse,
    classify_transport_exception,
    create_mailbox,
    create_room,
    request_text,
    room_owner_claim_preimage,
    technocore_status,
    validate_origin,
)
from flop_bench.adapters import run_local_command_step
from flop_bench.config import (
    BENCH_DID,
    BENCH_SERVICE_CAPABILITIES,
    SCOUT_DID,
    SCOUT_MAILBOX,
    SCOUT_ROOM,
    BenchConfig,
    assert_isolated,
    assert_no_forbidden_config_values,
)
from flop_bench.engine import router_export, verify_spec
from flop_bench.exceptions import IsolationError, LedgerError, SafetyError, ValidationError
from flop_bench.execution import (
    EXECUTE_PASSIVE_CONFIRMATION,
    RESULT_SEND_CONFIRMATION,
    execute_passive,
    execution_history,
    execution_preview,
    reconcile_result_delivery,
    result_delivery_preview,
    result_history,
    result_preview,
    send_result_delivery,
)
from flop_bench.identity import (
    IDENTITY_CONFIRMATION,
    b64u,
    create_ephemeral_test_identity,
    create_production_identity,
    public_did,
    read_interactive_new_passphrase,
    verify_identity,
)
from flop_bench.identity_note import (
    DID_NOTE_CONFIRMATION,
    NOTE_RESPONSE_BANNER,
    did_profile_path,
    identity_note_status,
    identity_note_value,
    note_hash,
    parse_note_response_value,
    preview_identity_note,
    publish_identity_note,
    reconcile_identity_note,
    scout_compatible_mailbox_from_note,
)
from flop_bench.ledger import append_record, verify_ledger
from flop_bench.mailbox import (
    MAILBOX_ACTIVATE_CONFIRMATION,
    MAILBOX_DEACTIVATE_CONFIRMATION,
    MAILBOX_REQUEST_SCHEMA_VERSION,
    classify_authentication,
    mailbox_activate,
    mailbox_activation_preview,
    mailbox_deactivate,
    mailbox_inspect,
    mailbox_messages,
    mailbox_status,
    parse_mailbox_envelope,
    poll_mailbox,
    request_approve,
    request_queue,
    request_reject,
    request_show,
)
from flop_bench.posting import (
    MAX_POST_BYTES,
    POST_CONFIRMATION,
    message_hash,
    post_room_url,
    posted_record_matches,
    preview_post,
    proposed_initial_announcement,
    protocol_check_post,
    reconcile_post,
    scan_room_history_for_hash,
    send_post,
    service_manifest,
    sign_post_message,
    signed_post_body,
    signed_post_headers,
    signed_post_preimage,
)
from flop_bench.posting import (
    history as post_history,
)
from flop_bench.protocol import (
    REQUEST_SCHEMA_VERSION,
    RESPONSE_SCHEMA_VERSION,
    SUPPORTED_CAPABILITIES,
    b64u_decode,
    protocol_error_from_response,
    public_key_from_did,
    sign_envelope,
    verify_signed_envelope,
)
from flop_bench.provenance import (
    UNKNOWN_LEGACY,
    export_room,
    provenance_doctor,
    technocore_signed_post_preimage,
    verify_export_file,
    verify_record_file,
    verify_record_mapping,
)
from flop_bench.schemas import (
    EVIDENCE_BUNDLE_SCHEMA,
    MAILBOX_REQUEST_SCHEMA,
    MAILBOX_RESULT_SCHEMA,
    ROUTER_EXPORT_SCHEMA,
    TEST_SPEC_SCHEMA,
    validate_test_spec,
    validate_with_schema,
)
from flop_bench.service import (
    dry_run_sign_payload,
    inspect_request,
    plan_init,
    prepare_signed_response,
    service_doctor,
    verify_request,
    verify_signed_response,
)
from flop_bench.state import (
    SCHEMA_VERSION,
    STATE_DB,
    activation_history,
    connect_state,
    migration_status,
    record_did_note_observation,
)
from flop_bench.transport import DisabledTechnocoreTransport
from flop_bench.verification import (
    LOCAL_OPERATOR_GROUP,
    canonical_json_hash,
    verify_request_file,
    verify_signing_request,
)

REPO = Path(__file__).resolve().parents[1]
GOLDEN_SCOUT_TECHNOCORE_ORIGIN = "https://technocore.chat"
GOLDEN_SCOUT_USER_AGENT = "flop-scout/0.3.2"


def write_json(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
    return path


def verification_request_fixture() -> dict[str, object]:
    return {
        "schema_version": "flop-verification-request/v1",
        "request_id": "FVR-local-1",
        "routing_decision_id": "frd1-local",
        "routing_decision_hash": "0" * 64,
        "task_hash": "1" * 64,
        "created_at": "2026-09-02T12:00:00Z",
        "requester_did": SCOUT_DID,
        "target_agent_did": "did:key:z6MkSyntheticExternal",
        "task_type": "technocore.synthetic_signing_payload_order",
        "required_capabilities": ["technocore.signed_post", "software.debugging"],
        "verification_mode": "OBJECTIVE_BENCH",
        "specimen": {
            "room": "technocore",
            "nonce": "123",
            "text": "synthetic signing specimen",
            "supplied_payload": "technocore|synthetic signing specimen|123",
            "supplied_order": "room|text|nonce",
            "expected_payload": "technocore|123|synthetic signing specimen",
            "expected_order": "room|nonce|text",
        },
        "expected_properties": {
            "canonical_order": "room|nonce|text",
            "broken_order": "room|text|nonce",
            "expected_finding": "nonce/text ordering defect identified",
        },
        "response_destination": "local://scout/bench-result",
        "operator_group": LOCAL_OPERATOR_GROUP,
        "same_operator": True,
        "independent_reputation": False,
    }


def spec(
    tmp_path: Path, procedure: list[dict[str, object]], mode: str = "passive"
) -> dict[str, object]:
    return {
        "schema_version": "flop-bench.test-spec.v0.1",
        "claim_id": "claim-1",
        "hypothesis": "local passive checks are deterministic",
        "requested_capabilities": ["file-check"],
        "mode": mode,
        "procedure": procedure,
        "assertions": [{"expect": "procedure result"}],
        "failure_conditions": ["step failed"],
        "provenance": {"fixture": str(tmp_path)},
    }


def strong_test_phrase() -> str:
    return "".join(["Strong", "Passphrase", "1!"])


def different_test_phrase() -> str:
    return "".join(["Different", "Passphrase", "1!"])


def weak_test_phrase() -> str:
    return "".join(["we", "ak"])


def test_verification_request_detects_broken_technocore_payload_order() -> None:
    request = verification_request_fixture()
    result = verify_signing_request(request, completed_at="2026-09-02T12:00:01Z")
    assert result["schema_version"] == "flop-verification-result/v1"
    assert result["request_id"] == "FVR-local-1"
    assert result["routing_decision_id"] == "frd1-local"
    assert result["routing_decision_hash"] == "0" * 64
    assert result["task_hash"] == "1" * 64
    assert result["verification_mode"] == "OBJECTIVE_BENCH"
    assert result["status"] == "PASS"
    assert result["score"] == 100
    assert result["checks"]["canonical_order_expected"] is True
    assert result["checks"]["broken_payload_detected"] is True
    assert result["checks"]["preimage_differs"] is True
    assert result["checks"]["correct_reconstruction_identified"] is True
    assert result["findings"] == ["nonce/text ordering defect identified"]
    assert result["same_operator"] is True
    assert result["independent_reputation"] is False
    assert result["operator_group"] == LOCAL_OPERATOR_GROUP
    assert result["evidence_classification"] == "CONTROLLED_SAME_OPERATOR_VALIDATION"
    assert result["network_writes"] == 0
    assert result["private_key_accesses"] == 0
    assert result["tclk_settlement_actions"] == 0
    expected_hash = canonical_json_hash(
        {key: value for key, value in result.items() if key != "result_hash"}
    )
    assert result["result_hash"] == expected_hash


def test_verification_result_preserves_same_operator_for_synthetic_external_target() -> None:
    request = verification_request_fixture()
    request["target_agent_did"] = "did:key:z6MkExternalSyntheticTarget"
    result = verify_signing_request(request, completed_at="2026-09-02T12:00:01Z")
    assert result["status"] == "PASS"
    assert result["same_operator"] is True
    assert result["independent_reputation"] is False
    assert result["operator_group"] == LOCAL_OPERATOR_GROUP


def test_verification_result_is_deterministic_for_fixed_completion_time() -> None:
    request = verification_request_fixture()
    first = verify_signing_request(request, completed_at="2026-09-02T12:00:01Z")
    second = verify_signing_request(request, completed_at="2026-09-02T12:00:01Z")
    assert first == second


def test_verification_failed_request_does_not_pass() -> None:
    request = verification_request_fixture()
    specimen = dict(request["specimen"])  # type: ignore[arg-type]
    specimen["supplied_payload"] = "technocore|123|synthetic signing specimen"
    request["specimen"] = specimen
    result = verify_signing_request(request, completed_at="2026-09-02T12:00:01Z")
    assert result["status"] == "FAIL"
    assert result["score"] == 0
    assert result["findings"] == []


def test_verification_request_file_writes_local_result_artifact(tmp_path: Path) -> None:
    request_path = write_json(tmp_path / "request.json", verification_request_fixture())
    output_path = tmp_path / "result.json"
    result = verify_request_file(
        request_path,
        output=output_path,
        completed_at="2026-09-02T12:00:01Z",
    )
    stored = json.loads(output_path.read_text(encoding="utf-8"))
    assert stored == result
    assert stored["artifact_hashes"]["request_sha256"]
    assert stored["reproducibility"] == "DETERMINISTIC"


def load_scout_module() -> object:
    source = os.environ.get("FLOP_SCOUT_SOURCE")
    if not source:
        pytest.skip("set FLOP_SCOUT_SOURCE to run optional cross-repo Scout parity")
    scout_path = Path(source).expanduser()
    spec = importlib.util.spec_from_file_location("flop_scout_opt_in", scout_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def scout_signed_post_request_parts(
    *,
    did: str,
    key: Ed25519PrivateKey,
    room: str,
    nonce: int,
    text: str,
) -> dict[str, object]:
    payload = f"{room}|{nonce}|{text}".encode()
    sig = b64u(key.sign(payload))
    body = json.dumps(
        {"did": did, "sig": sig, "nonce": str(nonce), "text": text},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 - fixed Technocore URL in parity test.
        f"{GOLDEN_SCOUT_TECHNOCORE_ORIGIN}/r/{urllib.parse.quote(room, safe='')}?format=json",
        data=body,
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": GOLDEN_SCOUT_USER_AGENT,
        },
    )
    return {
        "method": request.get_method(),
        "url": request.full_url,
        "body": request.data,
        "headers": dict(request.header_items()),
        "sig": sig,
        "preimage": payload,
    }


def opt_in_scout_signed_post_request_parts(
    *,
    did: str,
    key: Ed25519PrivateKey,
    room: str,
    nonce: int,
    text: str,
) -> dict[str, object]:
    scout = load_scout_module()
    for name in ("BASE_URL", "USER_AGENT", "b64u"):
        if not hasattr(scout, name):
            raise AssertionError(f"FLOP_SCOUT_SOURCE missing required Scout attribute {name}")
    payload = f"{room}|{nonce}|{text}".encode()
    sig = scout.b64u(key.sign(payload))  # type: ignore[attr-defined]
    body = json.dumps(
        {"did": did, "sig": sig, "nonce": str(nonce), "text": text},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 - opt-in source parity test.
        f"{scout.BASE_URL}/r/{urllib.parse.quote(room, safe='')}?format=json",  # type: ignore[attr-defined]
        data=body,
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": scout.USER_AGENT,  # type: ignore[attr-defined]
        },
    )
    return {
        "method": request.get_method(),
        "url": request.full_url,
        "body": request.data,
        "headers": dict(request.header_items()),
        "sig": sig,
        "preimage": payload,
    }


class FakeActivationTransport:
    def __init__(self) -> None:
        self.notes: dict[tuple[str, str], str] = {}
        self.note_statuses: dict[tuple[str, str], int] = {}
        self.nonce_statuses: dict[str, int] = {}
        self.nonces: dict[str, int] = {}
        self.write_statuses: list[int] = []
        self.post_statuses: list[int] = []
        self.room_history_statuses: list[int] = []
        self.requests: list[tuple[str, str]] = []
        self.post_bodies: list[dict[str, object]] = []
        self.note_bodies: list[dict[str, object]] = []
        self.room_messages: dict[str, list[dict[str, object]]] = {}
        self.timeout_after_accept = False
        self.reject_without_accept = False
        self.redirect_url: str | None = None
        self.oversized = False

    def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 20.0,
    ) -> TransportResponse:
        del timeout
        validate_origin(url)
        assert headers is not None
        assert headers["User-Agent"].startswith("flop-bench/")
        self.requests.append((method, url))
        if self.redirect_url is not None:
            return TransportResponse(200, b"redirected", {}, final_url=self.redirect_url)
        if self.oversized:
            return TransportResponse(200, b"x" * (MAX_RESPONSE_BYTES + 1), {}, final_url=url)
        parsed = urllib.parse.urlparse(url)
        parts = parsed.path.strip("/").split("/")
        if method == "GET" and len(parts) == 2 and parts[0] == "r":
            room = urllib.parse.unquote(parts[1])
            if self.room_history_statuses:
                return TransportResponse(
                    self.room_history_statuses.pop(0),
                    b"history unavailable token=abc123",
                    {},
                    final_url=url,
                )
            query = urllib.parse.parse_qs(parsed.query)
            limit = int(query.get("limit", ["200"])[0])
            since = int(query.get("since", ["0"])[0])
            messages = [
                msg for msg in self.room_messages.get(room, []) if int(msg.get("seq", 0)) > since
            ][:limit]
            response = {"messages": messages}
            return TransportResponse(
                200,
                json.dumps(response, separators=(",", ":")).encode(),
                {},
                final_url=url,
            )
        if method == "POST" and len(parts) == 2 and parts[0] == "r":
            room = urllib.parse.unquote(parts[1])
            assert headers["Accept"] == "application/json"
            assert headers["Content-Type"] == "application/json; charset=utf-8"
            assert body is not None
            payload = json.loads(body.decode("utf-8"))
            self.post_bodies.append(payload)
            if self.reject_without_accept:
                raise ActivationRequestError(
                    "Technocore request timed out",
                    failure_classification="timeout",
                )
            status = self.post_statuses.pop(0) if self.post_statuses else 200
            if status != 200:
                headers = {"Retry-After": "2"} if status == 429 else {}
                return TransportResponse(
                    status, b"post rejected token=abc123", headers, final_url=url
                )
            next_seq = len(self.room_messages.get(room, [])) + 1
            posted_nonce = int(payload["nonce"])
            self.room_messages.setdefault(room, []).append(
                {
                    "seq": next_seq,
                    "from": payload["did"],
                    "text": payload["text"],
                    "nonce": posted_nonce,
                }
            )
            if self.timeout_after_accept:
                raise ActivationRequestError(
                    "Technocore request timed out",
                    failure_classification="timeout",
                )
            response = {
                "posted": {
                    "from": payload["did"],
                    "text": payload["text"],
                    "nonce": posted_nonce,
                    "seq": 123,
                }
            }
            return TransportResponse(
                200,
                json.dumps(response, separators=(",", ":")).encode(),
                {},
                final_url=url,
            )
        if len(parts) >= 3 and parts[0] == "kv":
            namespace = urllib.parse.unquote(parts[1])
            key = urllib.parse.unquote(parts[2])
            if method == "GET" and len(parts) == 3:
                status = self.note_statuses.get((namespace, key))
                if status is not None:
                    return TransportResponse(
                        status, b"remote password=supersecret", {}, final_url=url
                    )
                if namespace == "room-nonce":
                    nonce_status = self.nonce_statuses.get(key)
                    if nonce_status is not None:
                        return TransportResponse(
                            nonce_status,
                            b"nonce unavailable password=supersecret",
                            {},
                            final_url=url,
                        )
                    return TransportResponse(
                        200,
                        str(self.nonces.get(key, 0)).encode(),
                        {},
                        final_url=url,
                    )
                value = self.notes.get((namespace, key))
                if value is None:
                    return TransportResponse(404, b"", {}, final_url=url)
                return TransportResponse(200, value.encode(), {}, final_url=url)
            if method == "POST" and len(parts) == 3:
                payload = json.loads((body or b"{}").decode("utf-8"))
                self.note_bodies.append(payload)
                status = self.write_statuses.pop(0) if self.write_statuses else 200
                if payload.get("if_absent") is True and (namespace, key) in self.notes:
                    return TransportResponse(
                        409,
                        json.dumps(
                            {"value": self.notes[(namespace, key)]},
                            separators=(",", ":"),
                        ).encode(),
                        {},
                        final_url=url,
                    )
                if status in {200, 201, 204}:
                    self.notes[(namespace, key)] = str(payload.get("value", ""))
                headers = {"Retry-After": "2"} if status == 429 else {}
                return TransportResponse(status, b"ok token=abc123", headers, final_url=url)
            if len(parts) >= 8 and parts[3] == "set-signed":
                status = self.write_statuses.pop(0) if self.write_statuses else 200
                if status in {200, 201, 204}:
                    self.notes[(namespace, key)] = urllib.parse.unquote(parts[7])
                    self.nonces[key] = max(self.nonces.get(key, 0), int(parts[6]))
                headers = {"Retry-After": "2"} if status == 429 else {}
                return TransportResponse(status, b"duplicate token=abc123", headers, final_url=url)
        return TransportResponse(400, b"bad request", {}, final_url=url)


def insert_post_attempt_for_test(
    state: Path,
    *,
    did: str,
    text: str,
    nonce: int,
    status: str,
    seq: int | None = None,
    failure_classification: str | None = None,
) -> int:
    with connect_state(state) as conn:
        attempt_id = conn.execute(
            """
            INSERT INTO post_attempts(
                room, expected_owner_did, message_hash, post_status,
                request_timestamp, response_status, nonce_used, seq,
                failure_classification
            )
            VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?)
            """,
            (
                "d-flop-bench",
                did,
                message_hash(text),
                status,
                datetime.now(UTC).isoformat(),
                nonce,
                seq,
                failure_classification,
            ),
        ).lastrowid
        conn.commit()
    if attempt_id is None:
        raise AssertionError("missing test attempt id")
    return int(attempt_id)


def temp_production_identity(tmp_path: Path) -> tuple[Path, str, str]:
    state = tmp_path / "bench-identity"
    passphrase = strong_test_phrase()
    metadata = create_production_identity(
        state_dir=state,
        confirm=IDENTITY_CONFIRMATION,
        passphrase=passphrase,
        passphrase_confirmation=passphrase,
        expected_state_dir=state,
    )
    return state, passphrase, str(metadata["did"])


def signed_request(
    *,
    sender_key: Ed25519PrivateKey,
    request_id: str = "req-1",
    target_did: str = BENCH_DID,
    requested_capability: str = "file-check",
    nonce: int = 1_777_000_000_001,
    created_at: str | None = None,
    expires_at: str | None = None,
    operator_group: dict[str, object] | None = None,
) -> dict[str, object]:
    now = datetime.now(UTC)
    fixture_path = Path("offline-request-fixture")
    payload: dict[str, object] = {
        "schema_version": REQUEST_SCHEMA_VERSION,
        "request_id": request_id,
        "sender_did": public_did(sender_key),
        "target_did": target_did,
        "requested_capability": requested_capability,
        "hypothesis": "signed offline request is valid",
        "test_spec": spec(fixture_path, [{"adapter": "file_exists", "path": "README.md"}]),
        "created_at": created_at or now.isoformat(),
        "expires_at": expires_at or (now + timedelta(minutes=10)).isoformat(),
        "nonce": nonce,
        "provenance": {"source": "pytest"},
    }
    if operator_group is not None:
        payload["operator_group"] = operator_group
    return sign_envelope("request", payload, sender_key)


def resign_request(request: dict[str, object], sender_key: Ed25519PrivateKey) -> None:
    request["signature"] = sign_envelope(
        "request",
        {key: value for key, value in request.items() if key != "signature"},
        sender_key,
    )["signature"]


def test_schema_validation_accepts_spec_and_rejects_missing_required(tmp_path: Path) -> None:
    doc = spec(tmp_path, [])
    validate_test_spec(doc)
    bad = dict(doc)
    del bad["claim_id"]
    with pytest.raises(ValidationError):
        validate_test_spec(bad)
    Draft202012Validator(TEST_SPEC_SCHEMA).validate(doc)


def test_schema_rejects_invalid_enums_extra_fields_and_malformed_assertions(
    tmp_path: Path,
) -> None:
    doc = spec(tmp_path, [{"adapter": "file_exists", "path": str(tmp_path / "x")}])
    for mutation in [
        {"mode": "networked"},
        {"unexpected": True},
        {"assertions": [{"unexpected": "shape"}]},
        {
            "procedure": [
                {
                    "adapter": "local_command",
                    "argv": [sys.executable],
                    "cwd": str(tmp_path),
                    "allow_local_exec": True,
                }
            ]
        },
        {"procedure": [{"adapter": "unknown", "path": str(tmp_path / "x")}]},
    ]:
        bad = dict(doc)
        bad.update(mutation)
        with pytest.raises(ValidationError):
            validate_test_spec(bad)


def test_external_schema_files_match_python_schema_constants() -> None:
    expected = {
        "schemas/test-spec-v0.1.json": TEST_SPEC_SCHEMA,
        "schemas/evidence-bundle-v0.1.json": EVIDENCE_BUNDLE_SCHEMA,
        "schemas/router-validation-export-v0.1.json": ROUTER_EXPORT_SCHEMA,
        "schemas/mailbox-result-v0.1.json": MAILBOX_RESULT_SCHEMA,
    }
    for relative_path, schema in expected.items():
        assert json.loads((REPO / relative_path).read_text(encoding="utf-8")) == schema


def test_pass_partial_fail_and_deterministic_evidence_ids(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    target.write_text("hello bench", encoding="utf-8")
    pass_spec = write_json(
        tmp_path / "pass.json",
        spec(tmp_path, [{"adapter": "text_contains", "path": str(target), "text": "bench"}]),
    )
    fail_spec = write_json(
        tmp_path / "fail.json",
        spec(tmp_path, [{"adapter": "text_contains", "path": str(target), "text": "missing"}]),
    )
    partial_spec = write_json(
        tmp_path / "partial.json",
        spec(
            tmp_path,
            [
                {"adapter": "text_contains", "path": str(target), "text": "bench"},
                {"adapter": "text_contains", "path": str(target), "text": "missing"},
            ],
        ),
    )
    ev1 = verify_spec(pass_spec, state_dir=tmp_path / "state1")
    ev2 = verify_spec(pass_spec, state_dir=tmp_path / "state2")
    ev3 = verify_spec(pass_spec, state_dir=tmp_path / "state1")
    assert ev1["result"] == "PASS"
    assert ev1["evidence_id"] == ev2["evidence_id"]
    assert ev1["evidence_id"] == ev3["evidence_id"]
    assert ev1["created_at"] != ev3["created_at"]
    assert ev3["previous_ledger_hash"] == ev1["record_hash"]
    assert verify_spec(fail_spec, state_dir=tmp_path / "state3")["result"] == "FAIL"
    assert verify_spec(partial_spec, state_dir=tmp_path / "state4")["result"] == "PARTIAL"
    Draft202012Validator(EVIDENCE_BUNDLE_SCHEMA).validate(ev1)
    assert ev1["input_hashes"][0]["sha256"] == hashlib.sha256(pass_spec.read_bytes()).hexdigest()
    assert ev1["artifact_hash"]
    assert ev1["safety_report"]["local_execution"] is False
    assert ev1["safety_report"]["technocore_network_calls"] is False


def test_passive_adapters_file_hash_json_path_and_schema(tmp_path: Path) -> None:
    data = write_json(tmp_path / "data.json", {"name": "bench", "nested": {"value": 7}})
    schema_path = write_json(tmp_path / "schema.json", {"type": "object", "required": ["name"]})
    digest = hashlib.sha256(data.read_bytes()).hexdigest()
    doc = spec(
        tmp_path,
        [
            {"adapter": "file_exists", "path": str(data)},
            {"adapter": "file_sha256", "path": str(data), "sha256": digest},
            {
                "adapter": "json_path_equals",
                "path": str(data),
                "json_path": "nested.value",
                "equals": 7,
            },
            {"adapter": "json_schema", "path": str(data), "schema_path": str(schema_path)},
        ],
    )
    evidence = verify_spec(write_json(tmp_path / "spec.json", doc), state_dir=tmp_path / "state")
    assert evidence["result"] == "PASS"


def test_ledger_verification_and_tamper_detection(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    target.write_text("ok", encoding="utf-8")
    spec_path = write_json(
        tmp_path / "spec.json",
        spec(tmp_path, [{"adapter": "text_contains", "path": str(target), "text": "ok"}]),
    )
    state = tmp_path / "state"
    verify_spec(spec_path, state_dir=state)
    verify_spec(spec_path, state_dir=state)
    assert verify_ledger(state)["records"] == 2
    ledger = state / "ledger.jsonl"
    lines = ledger.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["result"] = "FAIL"
    ledger.write_text(json.dumps(first) + "\n" + lines[1] + "\n", encoding="utf-8")
    with pytest.raises(LedgerError):
        verify_ledger(state)


def test_empty_and_one_record_ledgers_are_verified(tmp_path: Path) -> None:
    assert verify_ledger(tmp_path / "empty") == {"ok": True, "records": 0, "last_hash": None}
    state = tmp_path / "state"
    append_record(state, {"schema_version": "test", "value": 1})
    verified = verify_ledger(state)
    assert verified["ok"] is True
    assert verified["records"] == 1
    assert verified["last_hash"]


def test_ledger_append_reports_short_write_without_accepting_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("flop_bench.ledger.os.write", lambda _fd, _line: 0)
    with pytest.raises(LedgerError):
        append_record(tmp_path / "state", {"schema_version": "test", "value": 1})
    assert verify_ledger(tmp_path / "state")["records"] == 0


def test_deletion_from_middle_and_reordering_detected(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    target.write_text("ok", encoding="utf-8")
    spec_path = write_json(
        tmp_path / "spec.json",
        spec(tmp_path, [{"adapter": "text_contains", "path": str(target), "text": "ok"}]),
    )
    state = tmp_path / "state"
    for _ in range(3):
        verify_spec(spec_path, state_dir=state)
    ledger = state / "ledger.jsonl"
    lines = ledger.read_text(encoding="utf-8").splitlines()
    ledger.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
    with pytest.raises(LedgerError):
        verify_ledger(state)
    ledger.write_text("\n".join(reversed(lines)) + "\n", encoding="utf-8")
    with pytest.raises(LedgerError):
        verify_ledger(state)


def test_state_database_initialized_in_temp_dir(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    target.write_text("ok", encoding="utf-8")
    spec_path = write_json(
        tmp_path / "spec.json", spec(tmp_path, [{"adapter": "file_exists", "path": str(target)}])
    )
    state = tmp_path / "state"
    verify_spec(spec_path, state_dir=state)
    assert (state / "state.sqlite").exists()


def test_refuses_scout_identity_state_room_mailbox_and_did(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_scout = tmp_path / "fake-scout"
    fake_legacy = tmp_path / "fake-legacy-scout"
    monkeypatch.setattr(config_mod, "SCOUT_STATE", fake_scout)
    monkeypatch.setattr(config_mod, "LEGACY_SCOUT_STATE", fake_legacy)
    for config in [
        BenchConfig(state_dir=fake_scout),
        BenchConfig(state_dir=fake_scout / "bench"),
        BenchConfig(state_dir=tmp_path, canonical_room=SCOUT_ROOM),
        BenchConfig(state_dir=tmp_path, mailbox=SCOUT_MAILBOX),
        BenchConfig(state_dir=tmp_path, subject_did=SCOUT_DID),
    ]:
        with pytest.raises(IsolationError):
            assert_isolated(config)


def test_forbidden_config_values_resolve_path_aliases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_scout = tmp_path / "fake-scout"
    fake_legacy = tmp_path / "fake-legacy-scout"
    monkeypatch.setattr(config_mod, "SCOUT_STATE", fake_scout)
    monkeypatch.setattr(config_mod, "LEGACY_SCOUT_STATE", fake_legacy)
    scout_link = tmp_path / "scout-link"
    scout_link.symlink_to(fake_scout)
    for value in [
        str(scout_link / "bench"),
        str(fake_legacy / ".." / "fake-legacy-scout"),
        SCOUT_ROOM,
        SCOUT_MAILBOX,
        SCOUT_DID,
    ]:
        with pytest.raises(IsolationError):
            assert_no_forbidden_config_values([value])


def test_production_identity_creation_refusal_and_ephemeral_containment(tmp_path: Path) -> None:
    meta = create_ephemeral_test_identity(tmp_path / "identity")
    assert meta["purpose"] == "test-only"
    assert meta["persistent"] is False
    assert str(tmp_path) in meta["private_key_path"]


def test_successful_temporary_production_style_identity_creation(tmp_path: Path) -> None:
    state = tmp_path / "bench"
    passphrase = strong_test_phrase()
    metadata = create_production_identity(
        state_dir=state,
        confirm=IDENTITY_CONFIRMATION,
        passphrase=passphrase,
        passphrase_confirmation=passphrase,
        expected_state_dir=state,
    )
    pem = state / "identity.pem"
    identity_json = state / "identity.json"
    assert pem.exists()
    assert identity_json.exists()
    assert metadata == json.loads(identity_json.read_text(encoding="utf-8"))
    assert metadata["purpose"] == "flop-bench-production"
    assert metadata["persistent"] is True
    assert metadata["canonical_room"] == "d-flop-bench"
    assert metadata["mailbox"] == "mb-flop-bench"
    assert metadata["did"] != SCOUT_DID
    assert metadata["operator_group"]["related_agents"] == [
        "FLOP Scout",
        "FLOP Bench",
        "FLOP Sentinel",
    ]
    serialized = json.dumps(metadata, sort_keys=True)
    assert "private" not in serialized.lower()
    assert passphrase not in serialized


def test_production_identity_refusals(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = tmp_path / "bench"
    fake_scout = tmp_path / "fake-scout"
    monkeypatch.setattr(config_mod, "SCOUT_STATE", fake_scout)
    passphrase = strong_test_phrase()
    with pytest.raises(SafetyError):
        create_production_identity(
            state_dir=state,
            confirm="WRONG",
            passphrase=passphrase,
            passphrase_confirmation=passphrase,
            expected_state_dir=state,
        )
    with pytest.raises(SafetyError):
        create_production_identity(
            state_dir=tmp_path / "other",
            confirm=IDENTITY_CONFIRMATION,
            passphrase=passphrase,
            passphrase_confirmation=passphrase,
            expected_state_dir=state,
        )
    with pytest.raises(IsolationError):
        create_production_identity(
            state_dir=fake_scout,
            confirm=IDENTITY_CONFIRMATION,
            passphrase=passphrase,
            passphrase_confirmation=passphrase,
            expected_state_dir=fake_scout,
        )


def test_existing_identity_refusal_and_passphrase_policy(tmp_path: Path) -> None:
    state = tmp_path / "bench"
    passphrase = strong_test_phrase()
    create_production_identity(
        state_dir=state,
        confirm=IDENTITY_CONFIRMATION,
        passphrase=passphrase,
        passphrase_confirmation=passphrase,
        expected_state_dir=state,
    )
    with pytest.raises(SafetyError):
        create_production_identity(
            state_dir=state,
            confirm=IDENTITY_CONFIRMATION,
            passphrase=passphrase,
            passphrase_confirmation=passphrase,
            expected_state_dir=state,
        )
    for bad_passphrase, confirmation in [
        ("", ""),
        ("short", "short"),
        ("alllowercasebutlong", "alllowercasebutlong"),
        (strong_test_phrase(), different_test_phrase()),
    ]:
        with pytest.raises(SafetyError):
            create_production_identity(
                state_dir=tmp_path / f"bad-{len(bad_passphrase)}-{len(confirmation)}",
                confirm=IDENTITY_CONFIRMATION,
                passphrase=bad_passphrase,
                passphrase_confirmation=confirmation,
                expected_state_dir=tmp_path / f"bad-{len(bad_passphrase)}-{len(confirmation)}",
            )


def test_identity_cli_passphrase_prompt_refuses_noninteractive() -> None:
    with pytest.raises(SafetyError):
        read_interactive_new_passphrase()


def test_encrypted_pem_did_derivation_and_permissions(tmp_path: Path) -> None:
    state = tmp_path / "bench"
    passphrase = strong_test_phrase()
    metadata = create_production_identity(
        state_dir=state,
        confirm=IDENTITY_CONFIRMATION,
        passphrase=passphrase,
        passphrase_confirmation=passphrase,
        expected_state_dir=state,
    )
    pem_bytes = (state / "identity.pem").read_bytes()
    assert b"BEGIN ENCRYPTED PRIVATE KEY" in pem_bytes
    with pytest.raises(TypeError):
        serialization.load_pem_private_key(pem_bytes, password=None)
    loaded = serialization.load_pem_private_key(pem_bytes, password=passphrase.encode("utf-8"))
    assert isinstance(loaded, Ed25519PrivateKey)
    assert public_did(loaded) == metadata["did"]
    assert state.stat().st_mode & 0o777 == 0o700
    assert (state / "identity.pem").stat().st_mode & 0o777 == 0o600
    assert (state / "identity.json").stat().st_mode & 0o777 == 0o600


def test_identity_atomic_failure_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = tmp_path / "bench"
    passphrase = strong_test_phrase()

    def fail_json_write(_path: Path, _value: dict[str, object], _mode: int = 0o600) -> None:
        raise OSError("simulated metadata write failure")

    monkeypatch.setattr("flop_bench.identity._atomic_write_json_no_replace", fail_json_write)
    with pytest.raises(OSError):
        create_production_identity(
            state_dir=state,
            confirm=IDENTITY_CONFIRMATION,
            passphrase=passphrase,
            passphrase_confirmation=passphrase,
            expected_state_dir=state,
        )
    assert not (state / "identity.pem").exists()
    assert not (state / "identity.json").exists()


def test_identity_verification_success_wrong_passphrase_and_tamper_detection(
    tmp_path: Path,
) -> None:
    state = tmp_path / "bench"
    passphrase = strong_test_phrase()
    create_production_identity(
        state_dir=state,
        confirm=IDENTITY_CONFIRMATION,
        passphrase=passphrase,
        passphrase_confirmation=passphrase,
        expected_state_dir=state,
    )
    result = verify_identity(state_dir=state, passphrase=passphrase, expected_state_dir=state)
    assert result["ok"] is True
    assert result["pem_encrypted"] is True
    with pytest.raises(SafetyError) as wrong_pass:
        verify_identity(
            state_dir=state,
            passphrase=different_test_phrase(),
            expected_state_dir=state,
        )
    assert different_test_phrase() not in str(wrong_pass.value)
    metadata = json.loads((state / "identity.json").read_text(encoding="utf-8"))
    metadata["purpose"] = "tampered"
    write_json(state / "identity.json", metadata)
    (state / "identity.json").chmod(0o600)
    with pytest.raises(ValidationError):
        verify_identity(state_dir=state, passphrase=passphrase, expected_state_dir=state)
    metadata["purpose"] = "flop-bench-production"
    metadata["did"] = SCOUT_DID
    write_json(state / "identity.json", metadata)
    (state / "identity.json").chmod(0o600)
    with pytest.raises(IsolationError):
        verify_identity(state_dir=state, passphrase=passphrase, expected_state_dir=state)


def test_identity_verification_rejects_unencrypted_pem(tmp_path: Path) -> None:
    state = tmp_path / "bench"
    passphrase = strong_test_phrase()
    create_production_identity(
        state_dir=state,
        confirm=IDENTITY_CONFIRMATION,
        passphrase=passphrase,
        passphrase_confirmation=passphrase,
        expected_state_dir=state,
    )
    key = Ed25519PrivateKey.generate()
    (state / "identity.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (state / "identity.pem").chmod(0o600)
    with pytest.raises(ValidationError):
        verify_identity(state_dir=state, passphrase=passphrase, expected_state_dir=state)


def test_identity_outputs_exceptions_and_json_do_not_leak_secrets(tmp_path: Path) -> None:
    state = tmp_path / "bench"
    passphrase = strong_test_phrase()
    metadata = create_production_identity(
        state_dir=state,
        confirm=IDENTITY_CONFIRMATION,
        passphrase=passphrase,
        passphrase_confirmation=passphrase,
        expected_state_dir=state,
    )
    public_result = verify_identity(
        state_dir=state, passphrase=passphrase, expected_state_dir=state
    )
    visible = json.dumps({"metadata": metadata, "verify": public_result}, sort_keys=True)
    assert passphrase not in visible
    assert "seed" not in visible.lower()
    assert "private_key" not in visible
    with pytest.raises(SafetyError) as exc:
        create_production_identity(
            state_dir=tmp_path / "weak",
            confirm=IDENTITY_CONFIRMATION,
            passphrase=weak_test_phrase(),
            passphrase_confirmation=weak_test_phrase(),
            expected_state_dir=tmp_path / "weak",
        )
    assert weak_test_phrase() not in str(exc.value)


def test_disabled_technocore_transport() -> None:
    transport = DisabledTechnocoreTransport()
    for method in [
        transport.send,
        transport.post,
        transport.join,
        transport.fetch,
        transport.transfer,
        transport.create_room,
        transport.create_mailbox,
        transport.fetch_url,
        transport.wallet,
    ]:
        with pytest.raises(SafetyError):
            method()


def test_url_network_action_rejected(tmp_path: Path) -> None:
    spec_path = write_json(
        tmp_path / "spec.json",
        spec(
            tmp_path,
            [
                {
                    "adapter": "text_contains",
                    "path": str(tmp_path / "x"),
                    "text": "https://example.com",
                }
            ],
        ),
    )
    with pytest.raises(SafetyError):
        verify_spec(spec_path, state_dir=tmp_path / "state")


def test_local_command_rejects_network_and_dynamic_code_requests(tmp_path: Path) -> None:
    for step in [
        {"argv": ["curl", "https://example.com"], "cwd": str(tmp_path), "timeout_seconds": 5},
        {
            "argv": [sys.executable, "-c", "eval('1 + 1')"],
            "cwd": str(tmp_path),
            "timeout_seconds": 5,
        },
        {
            "argv": [sys.executable, "-m", "http.server"],
            "cwd": str(tmp_path),
            "timeout_seconds": 5,
        },
        {
            "argv": [sys.executable, "--version"],
            "cwd": str(tmp_path),
            "timeout_seconds": 5,
            "env": {"SECRET_TOKEN": "nope"},
        },
    ]:
        with pytest.raises(SafetyError):
            run_local_command_step(step, allow_local_exec=True)


def test_command_execution_denied_by_default_and_allowed_with_cli_authorization(
    tmp_path: Path,
) -> None:
    step = {
        "adapter": "local_command",
        "argv": [sys.executable, "--version"],
        "cwd": str(tmp_path),
        "timeout_seconds": 5,
    }
    spec_path = write_json(tmp_path / "spec.json", spec(tmp_path, [step], mode="approved-local"))
    with pytest.raises(SafetyError):
        verify_spec(spec_path, state_dir=tmp_path / "state")
    evidence = verify_spec(spec_path, state_dir=tmp_path / "state2", allow_local_exec=True)
    assert evidence["result"] == "PASS"
    assert evidence["safety_report"]["local_execution_authorized_by_cli"] is True
    assert evidence["observations"][0]["provenance"]["network_sandboxed"] is False


def test_passive_mode_refuses_local_command_before_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_if_called(_step: dict[str, object], *, allow_local_exec: bool) -> dict[str, object]:
        raise AssertionError("local command adapter should not run in passive mode")

    monkeypatch.setattr(engine, "run_local_command_step", fail_if_called)
    step = {
        "adapter": "local_command",
        "argv": [sys.executable, "--version"],
        "cwd": str(tmp_path),
        "timeout_seconds": 5,
    }
    spec_path = write_json(tmp_path / "spec.json", spec(tmp_path, [step], mode="passive"))
    with pytest.raises(SafetyError):
        verify_spec(spec_path, state_dir=tmp_path / "state", allow_local_exec=True)


def test_argv_handling_without_shell(tmp_path: Path) -> None:
    marker = tmp_path / "should_not_exist"
    result = run_local_command_step(
        {
            "argv": [sys.executable, "-c", f"print('hello; touch {marker}')"],
            "cwd": str(tmp_path),
            "timeout_seconds": 5,
        },
        allow_local_exec=True,
    )
    assert result["exit_code"] == 0
    assert not marker.exists()


def test_timeouts_output_limits_and_secret_redaction(tmp_path: Path) -> None:
    timeout = run_local_command_step(
        {
            "argv": [sys.executable, "-c", "import time; time.sleep(2)"],
            "cwd": str(tmp_path),
            "timeout_seconds": 0.1,
        },
        allow_local_exec=True,
    )
    assert timeout["timed_out"] is True
    output = run_local_command_step(
        {
            "argv": [sys.executable, "-c", "print('password=supersecret'); print('x'*9000)"],
            "cwd": str(tmp_path),
            "timeout_seconds": 5,
        },
        allow_local_exec=True,
    )
    assert "supersecret" not in output["stdout"]
    assert "[truncated]" in output["stdout"]


def test_end_to_end_passive_verification_and_router_export(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    target.write_text("FLOP Bench", encoding="utf-8")
    spec_path = write_json(
        tmp_path / "spec.json",
        spec(tmp_path, [{"adapter": "text_contains", "path": str(target), "text": "FLOP Bench"}]),
    )
    evidence = verify_spec(spec_path, state_dir=tmp_path / "state")
    export = router_export(evidence)
    assert export["operator_group"]["common_control_disclosure"] is True
    assert "common-control" in export["operator_group"]["note"]
    Draft202012Validator(ROUTER_EXPORT_SCHEMA).validate(export)


def test_router_export_schema_rejects_malformed_documents(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    target.write_text("ok", encoding="utf-8")
    spec_path = write_json(
        tmp_path / "spec.json",
        spec(tmp_path, [{"adapter": "text_contains", "path": str(target), "text": "ok"}]),
    )
    export = router_export(verify_spec(spec_path, state_dir=tmp_path / "state"))
    for mutation in [
        {"result": "UNKNOWN"},
        {"operator_group": {"common_control_disclosure": False}},
        {"extra": True},
    ]:
        bad = dict(export)
        bad.update(mutation)
        with pytest.raises(ValidationError):
            validate_with_schema(bad, ROUTER_EXPORT_SCHEMA)


def test_signed_request_verification_and_replay_reservation(tmp_path: Path) -> None:
    sender_key = Ed25519PrivateKey.generate()
    request = signed_request(sender_key=sender_key)
    path = write_json(tmp_path / "request.json", request)
    result = verify_request(path, state_dir=tmp_path / "state")
    assert result["ok"] is True
    assert result["policy_approval_required"] is True
    assert result["will_execute"] is False
    assert result["reservation"]["request_id"] == "req-1"
    with pytest.raises(SafetyError):
        verify_request(path, state_dir=tmp_path / "state")


def test_invalid_signature_wrong_target_and_unsupported_capability(tmp_path: Path) -> None:
    sender_key = Ed25519PrivateKey.generate()
    tampered = signed_request(sender_key=sender_key)
    tampered["hypothesis"] = "tampered after signing"
    with pytest.raises(SafetyError):
        verify_request(write_json(tmp_path / "tampered.json", tampered), state_dir=tmp_path / "s1")
    wrong_target = signed_request(
        sender_key=sender_key, request_id="req-2", target_did=public_did(sender_key)
    )
    with pytest.raises(SafetyError):
        verify_request(
            write_json(tmp_path / "wrong-target.json", wrong_target),
            state_dir=tmp_path / "s2",
        )
    unsupported = signed_request(
        sender_key=sender_key,
        request_id="req-3",
        requested_capability="wallet-transfer",
        nonce=1_777_000_000_003,
    )
    with pytest.raises(SafetyError):
        verify_request(
            write_json(tmp_path / "unsupported.json", unsupported),
            state_dir=tmp_path / "s3",
        )


def test_signed_request_capabilities_remain_execution_allowlist(tmp_path: Path) -> None:
    sender_key = Ed25519PrivateKey.generate()
    assert SUPPORTED_CAPABILITIES == frozenset({"approved-local-command", "file-check"})
    assert "software.testing" not in SUPPORTED_CAPABILITIES
    request = signed_request(
        sender_key=sender_key,
        requested_capability="software.testing",
    )
    with pytest.raises(SafetyError):
        verify_request(
            write_json(tmp_path / "service-capability.json", request),
            state_dir=tmp_path / "state",
        )


def test_scout_operator_relationship_request_rules(tmp_path: Path) -> None:
    sender_key = Ed25519PrivateKey.generate()
    request = signed_request(sender_key=sender_key)
    request["sender_did"] = SCOUT_DID
    resign_request(request, sender_key)
    with pytest.raises(SafetyError):
        verify_request(
            write_json(tmp_path / "scout-undisclosed.json", request), state_dir=tmp_path / "s1"
        )
    request["operator_group"] = {"common_control_disclosure": True}
    resign_request(request, sender_key)
    with pytest.raises(SafetyError):
        verify_request(
            write_json(tmp_path / "scout-bad-sig.json", request), state_dir=tmp_path / "s2"
        )


def test_expired_future_dated_duplicate_nonce_and_malformed_requests(tmp_path: Path) -> None:
    sender_key = Ed25519PrivateKey.generate()
    now = datetime.now(UTC)
    expired = signed_request(
        sender_key=sender_key,
        expires_at=(now - timedelta(seconds=1)).isoformat(),
    )
    with pytest.raises(SafetyError):
        verify_request(write_json(tmp_path / "expired.json", expired), state_dir=tmp_path / "s1")
    future = signed_request(
        sender_key=sender_key,
        request_id="req-future",
        nonce=1_777_000_000_002,
        created_at=(now + timedelta(minutes=6)).isoformat(),
    )
    with pytest.raises(SafetyError):
        verify_request(write_json(tmp_path / "future.json", future), state_dir=tmp_path / "s2")
    first = signed_request(sender_key=sender_key, request_id="req-a", nonce=1_777_000_000_010)
    second = signed_request(sender_key=sender_key, request_id="req-b", nonce=1_777_000_000_010)
    verify_request(write_json(tmp_path / "first.json", first), state_dir=tmp_path / "s3")
    with pytest.raises(SafetyError):
        verify_request(write_json(tmp_path / "second.json", second), state_dir=tmp_path / "s3")
    malformed = signed_request(sender_key=sender_key, request_id="req-malformed")
    malformed["unexpected"] = True
    with pytest.raises(ValidationError):
        verify_request(
            write_json(tmp_path / "malformed.json", malformed),
            state_dir=tmp_path / "s4",
        )


def test_request_inspect_keeps_urls_inert_and_signed_code_does_not_execute(tmp_path: Path) -> None:
    sender_key = Ed25519PrivateKey.generate()
    marker = tmp_path / "must-not-exist"
    request = signed_request(
        sender_key=sender_key,
        requested_capability="approved-local-command",
        nonce=1_777_000_000_020,
    )
    request["test_spec"] = spec(
        tmp_path,
        [
            {
                "adapter": "local_command",
                "argv": [sys.executable, "-c", f"open('{marker}', 'w').write('bad')"],
                "cwd": str(tmp_path),
                "timeout_seconds": 5,
            }
        ],
        mode="approved-local",
    )
    request["provenance"] = {"source": "pytest", "url": "https://example.com/inert"}
    resign_request(request, sender_key)
    path = write_json(tmp_path / "request.json", request)
    inspected = inspect_request(path, state_dir=tmp_path / "state")
    verified = verify_request(path, state_dir=tmp_path / "state")
    assert inspected["contains_url"] is True
    assert inspected["network_action"] is False
    assert verified["will_execute"] is False
    assert not marker.exists()


def test_concurrent_request_reservation_allows_one_duplicate(tmp_path: Path) -> None:
    sender_key = Ed25519PrivateKey.generate()
    path = write_json(tmp_path / "request.json", signed_request(sender_key=sender_key))
    state = tmp_path / "state"
    barrier = threading.Barrier(4)
    results: list[str] = []
    lock = threading.Lock()

    def worker() -> None:
        barrier.wait()
        try:
            verify_request(path, state_dir=state)
            value = "ok"
        except SafetyError:
            value = "duplicate"
        with lock:
            results.append(value)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count("ok") == 1
    assert results.count("duplicate") == 3


def test_database_rollback_after_duplicate_request(tmp_path: Path) -> None:
    sender_key = Ed25519PrivateKey.generate()
    state = tmp_path / "state"
    request = signed_request(sender_key=sender_key)
    path = write_json(tmp_path / "request.json", request)
    verify_request(path, state_dir=state)
    with pytest.raises(SafetyError):
        verify_request(path, state_dir=state)
    with connect_state(state) as conn:
        count = conn.execute("SELECT COUNT(*) FROM bench_requests").fetchone()[0]
    assert count == 1


def test_signed_response_verification_tamper_and_related_agent_limitations(
    tmp_path: Path,
) -> None:
    passphrase = strong_test_phrase()
    state = tmp_path / "bench-id"
    metadata = create_production_identity(
        state_dir=state,
        confirm=IDENTITY_CONFIRMATION,
        passphrase=passphrase,
        passphrase_confirmation=passphrase,
        expected_state_dir=state,
    )
    target = tmp_path / "data.txt"
    target.write_text("ok", encoding="utf-8")
    evidence_path = write_json(
        tmp_path / "spec.json",
        spec(
            tmp_path,
            [{"adapter": "text_contains", "path": str(target), "text": "ok"}],
        )
        | {"provenance": {"subject_did": SCOUT_DID}},
    )
    evidence = verify_spec(evidence_path, state_dir=tmp_path / "evidence-state")
    evidence["request_id"] = "req-response"
    evidence["provenance"]["subject_did"] = SCOUT_DID
    ev_path = write_json(tmp_path / "evidence.json", evidence)
    response = prepare_signed_response(
        ev_path,
        state_dir=state,
        passphrase=passphrase,
        expected_bench_did=metadata["did"],
        expected_identity_state_dir=state,
    )
    assert response["schema_version"] == RESPONSE_SCHEMA_VERSION
    assert response["verifier_did"] == metadata["did"]
    assert response["subject_did"] == SCOUT_DID
    assert response["independent_evidence"] is False
    assert "independent peer reputation" in response["limitations"][1]
    verify_signed_response(response)
    response["result"] = "FAIL"
    with pytest.raises(SafetyError):
        verify_signed_response(response)


def test_dry_run_sign_and_protocol_error_redaction(tmp_path: Path) -> None:
    passphrase = strong_test_phrase()
    state = tmp_path / "bench-id"
    metadata = create_production_identity(
        state_dir=state,
        confirm=IDENTITY_CONFIRMATION,
        passphrase=passphrase,
        passphrase_confirmation=passphrase,
        expected_state_dir=state,
    )
    payload_path = write_json(tmp_path / "payload.json", {"room": "d-flop-bench", "nonce": 1})
    signed = dry_run_sign_payload(
        payload_path,
        state_dir=state,
        passphrase=passphrase,
        expected_bench_did=metadata["did"],
        expected_identity_state_dir=state,
    )
    assert signed["dry_run"] is True
    assert signed["network_action"] is False
    verify_signed_envelope("dry-run", signed, metadata["did"])
    parsed = protocol_error_from_response(422, "duplicate token=abc123")
    assert parsed["duplicate"] is True
    assert "abc123" not in parsed["body"]


def test_activation_live_gate_refusals(tmp_path: Path) -> None:
    state, passphrase, did = temp_production_identity(tmp_path)
    transport = FakeActivationTransport()
    with pytest.raises(SafetyError):
        create_room(
            live=False,
            confirm=CREATE_ROOM_CONFIRMATION,
            state_dir=state,
            passphrase=passphrase,
            transport=transport,
            expected_state_dir=state,
            expected_bench_did=did,
        )
    with pytest.raises(SafetyError):
        create_room(
            live=True,
            confirm="WRONG",
            state_dir=state,
            passphrase=passphrase,
            transport=transport,
            expected_state_dir=state,
            expected_bench_did=did,
        )
    with pytest.raises(SafetyError):
        create_room(
            live=True,
            confirm=CREATE_ROOM_CONFIRMATION,
            state_dir=tmp_path / "wrong-state",
            passphrase=passphrase,
            transport=transport,
            expected_state_dir=state,
            expected_bench_did=did,
        )
    with pytest.raises(SafetyError):
        create_room(
            live=True,
            confirm=CREATE_ROOM_CONFIRMATION,
            state_dir=state,
            passphrase=passphrase,
            transport=transport,
            expected_state_dir=state,
            expected_bench_did=BENCH_DID,
        )
    assert transport.requests == []
    assert not (state / "state.sqlite").exists()


def test_room_activation_uses_scout_owner_preimage_and_endpoint(tmp_path: Path) -> None:
    state, passphrase, did = temp_production_identity(tmp_path)
    transport = FakeActivationTransport()
    assert room_owner_claim_preimage("d-flop-bench", 42, did) == (
        f"room-owners|d-flop-bench|42|{did}".encode()
    )
    create_room(
        live=True,
        confirm=CREATE_ROOM_CONFIRMATION,
        state_dir=state,
        passphrase=passphrase,
        transport=transport,
        expected_state_dir=state,
        expected_bench_did=did,
        sleep_on_429=False,
    )
    write_urls = [url for _method, url in transport.requests if "set-signed" in url]
    assert len(write_urls) == 1
    parsed = urllib.parse.urlparse(write_urls[0])
    parts = parsed.path.strip("/").split("/")
    assert [urllib.parse.unquote(part) for part in parts[:4]] == [
        "kv",
        "room-owners",
        "d-flop-bench",
        "set-signed",
    ]
    assert urllib.parse.parse_qs(parsed.query) == {"if_absent": ["1"]}


def test_activation_origin_redirect_timeout_and_size_safety(tmp_path: Path) -> None:
    transport = FakeActivationTransport()
    with pytest.raises(SafetyError):
        validate_origin("http://technocore.chat/kv/room-owners/d-flop-bench")
    with pytest.raises(SafetyError):
        validate_origin("https://evil.example/kv/room-owners/d-flop-bench")
    transport.redirect_url = "https://technocore.chat/other"
    with pytest.raises(SafetyError):
        request_text(transport, "GET", f"{TECHNOCORE_ORIGIN}/kv/room-owners/d-flop-bench")
    transport.redirect_url = None
    transport.oversized = True
    with pytest.raises(SafetyError):
        request_text(transport, "GET", f"{TECHNOCORE_ORIGIN}/kv/room-owners/d-flop-bench")

    class TimeoutTransport(FakeActivationTransport):
        def request(self, *args: object, **kwargs: object) -> TransportResponse:
            raise SafetyError("Technocore request timed out")

    with pytest.raises(SafetyError):
        request_text(
            TimeoutTransport(),
            "GET",
            f"{TECHNOCORE_ORIGIN}/kv/room-owners/d-flop-bench",
        )


def test_room_preflight_503_creates_single_failed_audit_without_signing(
    tmp_path: Path,
) -> None:
    state, passphrase, did = temp_production_identity(tmp_path)
    transport = FakeActivationTransport()
    transport.note_statuses[("room-owners", "d-flop-bench")] = 503
    with pytest.raises(SafetyError) as exc:
        create_room(
            live=True,
            confirm=CREATE_ROOM_CONFIRMATION,
            state_dir=state,
            passphrase=passphrase,
            transport=transport,
            expected_state_dir=state,
            expected_bench_did=did,
            sleep_on_429=False,
        )
    assert "HTTP 503" in str(exc.value)
    with connect_state(state) as conn:
        rows = conn.execute("SELECT * FROM service_activations").fetchall()
    assert len(rows) == 1
    row = rows[0]
    assert row["service_type"] == "room"
    assert row["service_name"] == "d-flop-bench"
    assert row["expected_owner_did"] == did
    assert row["observed_owner_did"] is None
    assert row["activation_status"] == "failed_preflight"
    assert row["response_status"] == 503
    assert row["nonce_used"] is None
    assert row["failure_classification"] == "remote_unavailable"
    assert row["response_hash"] is not None
    assert all("room-nonce" not in url for _method, url in transport.requests)
    assert all("set-signed" not in url for _method, url in transport.requests)
    stored = json.dumps([dict(row)], sort_keys=True)
    assert passphrase not in stored
    assert "supersecret" not in stored
    assert "signature" not in stored


def test_room_preflight_timeout_and_malformed_response_are_audited(tmp_path: Path) -> None:
    state, passphrase, did = temp_production_identity(tmp_path)

    class TimeoutTransport(FakeActivationTransport):
        def request(self, *args: object, **kwargs: object) -> TransportResponse:
            raise ActivationRequestError(
                "Technocore request timed out",
                failure_classification="timeout",
            )

    with pytest.raises(SafetyError):
        create_room(
            live=True,
            confirm=CREATE_ROOM_CONFIRMATION,
            state_dir=state,
            passphrase=passphrase,
            transport=TimeoutTransport(),
            expected_state_dir=state,
            expected_bench_did=did,
            sleep_on_429=False,
        )
    other_did = public_did(Ed25519PrivateKey.generate())
    malformed = FakeActivationTransport()
    malformed.notes[("room-owners", "d-flop-bench")] = f"{did} {other_did}"
    with pytest.raises(SafetyError):
        create_room(
            live=True,
            confirm=CREATE_ROOM_CONFIRMATION,
            state_dir=state,
            passphrase=passphrase,
            transport=malformed,
            expected_state_dir=state,
            expected_bench_did=did,
            sleep_on_429=False,
        )
    with connect_state(state) as conn:
        rows = conn.execute(
            "SELECT activation_status, response_status, nonce_used, failure_classification "
            "FROM service_activations ORDER BY id"
        ).fetchall()
    assert [row["activation_status"] for row in rows] == [
        "failed_preflight",
        "failed_preflight",
    ]
    assert rows[0]["response_status"] is None
    assert rows[0]["nonce_used"] is None
    assert rows[0]["failure_classification"] == "timeout"
    assert rows[1]["response_status"] == 200
    assert rows[1]["nonce_used"] is None
    assert rows[1]["failure_classification"] == "malformed_response"


def test_successful_room_creation_with_audit(tmp_path: Path) -> None:
    state, passphrase, did = temp_production_identity(tmp_path)
    transport = FakeActivationTransport()
    transport.nonces["d-flop-bench"] = 41
    room = create_room(
        live=True,
        confirm=CREATE_ROOM_CONFIRMATION,
        state_dir=state,
        passphrase=passphrase,
        transport=transport,
        expected_state_dir=state,
        expected_bench_did=did,
        sleep_on_429=False,
    )
    assert room["status"] == "created"
    with connect_state(state) as conn:
        rows = conn.execute("SELECT * FROM service_activations").fetchall()
    assert len(rows) == 1
    assert rows[0]["service_type"] == "room"
    assert rows[0]["activation_status"] == "created"
    assert rows[0]["nonce_used"] == 42
    stored = json.dumps([dict(row) for row in rows], sort_keys=True)
    assert passphrase not in stored
    assert "signature" not in stored
    assert (state / "ledger.jsonl").exists()


def test_mailbox_creation_fails_closed_before_transport_signing_or_state(tmp_path: Path) -> None:
    class ExplodingTransport(FakeActivationTransport):
        def request(self, *args: object, **kwargs: object) -> TransportResponse:
            raise AssertionError("mailbox transport must not be invoked")

    state = tmp_path / "missing-state"
    with pytest.raises(SafetyError) as exc:
        create_mailbox(
            live=True,
            confirm=CREATE_MAILBOX_CONFIRMATION,
            state_dir=state,
            transport=ExplodingTransport(),
            expected_state_dir=state,
            expected_bench_did=public_did(Ed25519PrivateKey.generate()),
            sleep_on_429=False,
        )
    assert "MAILBOX_CREATION_NOT_REQUIRED" in str(exc.value)
    assert not state.exists()


def test_existing_owned_foreign_owned_and_unverifiable_activation(tmp_path: Path) -> None:
    state, passphrase, did = temp_production_identity(tmp_path)
    transport = FakeActivationTransport()
    transport.notes[("room-owners", "d-flop-bench")] = did
    already = create_room(
        live=True,
        confirm=CREATE_ROOM_CONFIRMATION,
        state_dir=state,
        passphrase=passphrase,
        transport=transport,
        expected_state_dir=state,
        expected_bench_did=did,
    )
    assert already["status"] == "already-owned"
    foreign = FakeActivationTransport()
    foreign.notes[("room-owners", "d-flop-bench")] = public_did(Ed25519PrivateKey.generate())
    with pytest.raises(SafetyError):
        create_room(
            live=True,
            confirm=CREATE_ROOM_CONFIRMATION,
            state_dir=state,
            passphrase=passphrase,
            transport=foreign,
            expected_state_dir=state,
            expected_bench_did=did,
        )
    unverifiable = FakeActivationTransport()
    original_request = unverifiable.request

    def lose_verified_owner(*args: object, **kwargs: object) -> TransportResponse:
        response = original_request(*args, **kwargs)
        if len(unverifiable.requests) >= 4 and args[0] == "GET":
            return TransportResponse(404, b"", {}, final_url=str(args[1]))
        return response

    unverifiable.request = lose_verified_owner  # type: ignore[method-assign]
    with pytest.raises(SafetyError):
        create_room(
            live=True,
            confirm=CREATE_ROOM_CONFIRMATION,
            state_dir=state,
            passphrase=passphrase,
            transport=unverifiable,
            expected_state_dir=state,
            expected_bench_did=did,
        )


def test_activation_http_status_retry_nonce_and_redaction(tmp_path: Path) -> None:
    state, passphrase, did = temp_production_identity(tmp_path)
    transport = FakeActivationTransport()
    transport.nonces["d-flop-bench"] = 10
    transport.write_statuses = [409, 422, 200]
    created = create_room(
        live=True,
        confirm=CREATE_ROOM_CONFIRMATION,
        state_dir=state,
        passphrase=passphrase,
        transport=transport,
        expected_state_dir=state,
        expected_bench_did=did,
        sleep_on_429=False,
    )
    assert created["status"] == "created"
    write_urls = [url for _method, url in transport.requests if "set-signed" in url]
    assert len(write_urls) == 3
    assert "/11/" in write_urls[0]
    assert "/12/" in write_urls[1]
    assert "/13/" in write_urls[2]
    rate_limited = FakeActivationTransport()
    rate_limited.write_statuses = [429, 200]
    create_room(
        live=True,
        confirm=CREATE_ROOM_CONFIRMATION,
        state_dir=state,
        passphrase=passphrase,
        transport=rate_limited,
        expected_state_dir=state,
        expected_bench_did=did,
        sleep_on_429=False,
    )
    failing = FakeActivationTransport()
    failing.write_statuses = [422, 422, 422]
    with pytest.raises(SafetyError) as exc:
        create_room(
            live=True,
            confirm=CREATE_ROOM_CONFIRMATION,
            state_dir=state,
            passphrase=passphrase,
            transport=failing,
            expected_state_dir=state,
            expected_bench_did=did,
            sleep_on_429=False,
        )
    message = str(exc.value)
    assert "abc123" not in message
    assert "creation_rejection" in message
    with connect_state(state) as conn:
        row = conn.execute(
            "SELECT failure_classification FROM service_activations ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert row["failure_classification"] == "creation_rejection"


def test_post_manifest_and_preview_are_pure(tmp_path: Path) -> None:
    message_path = tmp_path / "message.txt"
    message_text = proposed_initial_announcement()
    message_path.write_text(f"{message_text}\n", encoding="utf-8")
    state = tmp_path / "missing-state"
    preview = preview_post(message_path, state_dir=state)
    manifest = service_manifest()
    assert preview["room"] == "d-flop-bench"
    assert preview["message_text"] == message_text
    assert "proposed_initial_announcement" not in preview
    assert preview["will_sign"] is False
    assert preview["will_acquire_nonce"] is False
    assert preview["network_action"] is False
    assert preview["state_write"] is False
    assert preview["manifest"] == manifest
    assert manifest["bench_did"] == BENCH_DID
    assert manifest["room"] == "d-flop-bench"
    assert manifest["mailbox"]["status"] == "signed-write-only-room"
    assert manifest["mailbox"]["activation_status"] == "inactive"
    assert manifest["safety"]["url_following"] is False
    assert manifest["safety"]["automatic_code_execution"] is False
    assert manifest["safety"]["wallets"] is False
    assert manifest["safety"]["flop_transfers"] is False
    assert manifest["safety"]["autonomous_outbound_posting"] is False
    assert manifest["safety"]["requests_accepted"] is False
    assert "https://" not in proposed_initial_announcement()
    assert not state.exists()


def test_post_preview_arbitrary_file_reports_selected_message_only(tmp_path: Path) -> None:
    message_path = tmp_path / "message.txt"
    message_text = "Narrow arbitrary preview text for a local dry run"
    message_path.write_text(message_text, encoding="utf-8")

    preview = preview_post(message_path, state_dir=tmp_path / "state")

    assert preview["message_text"] == message_text
    assert preview["message_hash"] == message_hash(message_text)
    assert "proposed_initial_announcement" not in preview
    assert proposed_initial_announcement() not in json.dumps(preview)


def test_post_message_validation_rejects_url_control_length_and_utf8(tmp_path: Path) -> None:
    for name, data in {
        "url.txt": b"Visit https://example.test",
        "control.txt": b"hello\nworld",
        "long.txt": b"x" * (MAX_POST_BYTES + 1),
    }.items():
        path = tmp_path / name
        path.write_bytes(data)
        with pytest.raises((SafetyError, ValidationError)):
            preview_post(path, state_dir=tmp_path / "state")
    invalid = tmp_path / "invalid.txt"
    invalid.write_bytes(b"\xff")
    with pytest.raises(ValidationError):
        preview_post(invalid, state_dir=tmp_path / "state")


def test_post_local_gates_do_not_create_audit(tmp_path: Path) -> None:
    state, passphrase, did = temp_production_identity(tmp_path)
    message = tmp_path / "message.txt"
    message.write_text("FLOP Bench test announcement", encoding="utf-8")
    transport = FakeActivationTransport()
    with pytest.raises(SafetyError):
        send_post(
            message,
            state_dir=state,
            live=False,
            confirm=POST_CONFIRMATION,
            passphrase=passphrase,
            transport=transport,
            expected_state_dir=state,
            expected_bench_did=did,
        )
    with pytest.raises(SafetyError):
        send_post(
            message,
            state_dir=state,
            live=True,
            confirm="WRONG",
            passphrase=passphrase,
            transport=transport,
            expected_state_dir=state,
            expected_bench_did=did,
        )
    with pytest.raises(SafetyError):
        signed_post_preimage("d-other", 1, "hello")
    with connect_state(state) as conn:
        rows = conn.execute("SELECT * FROM post_attempts").fetchall()
    assert rows == []
    assert transport.requests == []


def test_post_send_uses_scout_preimage_body_nonce_and_one_audit_row(tmp_path: Path) -> None:
    state, passphrase, did = temp_production_identity(tmp_path)
    message = tmp_path / "message.txt"
    text = "FLOP Bench test announcement"
    message.write_text(text, encoding="utf-8")
    transport = FakeActivationTransport()
    transport.notes[("room-owners", "d-flop-bench")] = did
    result = send_post(
        message,
        state_dir=state,
        live=True,
        confirm=POST_CONFIRMATION,
        passphrase=passphrase,
        transport=transport,
        expected_state_dir=state,
        expected_bench_did=did,
    )
    assert result["ok"] is True
    assert result["room"] == "d-flop-bench"
    assert result["seq"] == 123
    assert len(transport.post_bodies) == 1
    body = transport.post_bodies[0]
    assert body["did"] == did
    assert body["text"] == text
    assert isinstance(body["nonce"], str)
    assert str(body["nonce"]).isdigit()
    assert len(str(body["nonce"])) <= 19
    assert signed_post_preimage("d-flop-bench", int(body["nonce"]), text) == (
        f"d-flop-bench|{body['nonce']}|{text}".encode()
    )
    public_key_from_did(did).verify(
        b64u_decode(str(body["sig"])),
        signed_post_preimage("d-flop-bench", int(body["nonce"]), text),
    )
    post_urls = [url for method, url in transport.requests if method == "POST"]
    assert post_urls == [post_room_url()]
    with connect_state(state) as conn:
        rows = conn.execute("SELECT * FROM post_attempts").fetchall()
    assert len(rows) == 1
    row = rows[0]
    assert row["post_status"] == "posted"
    assert row["nonce_used"] == int(body["nonce"])
    assert row["seq"] == 123
    stored = json.dumps([dict(row)], sort_keys=True)
    assert text not in stored
    assert str(body["sig"]) not in stored
    assert passphrase not in stored


def test_post_success_requires_integer_response_nonce_equal_to_local_nonce(tmp_path: Path) -> None:
    assert posted_record_matches(
        {"from": "did:key:z6MkOwn", "text": "hello", "nonce": 123, "seq": 1},
        did="did:key:z6MkOwn",
        text="hello",
        nonce=123,
    )
    base = {"from": "did:key:z6MkOwn", "text": "hello", "seq": 1}
    for label, raw_nonce, expected_nonce in (
        ("string", "123", 123),
        ("bool", True, 1),
        ("float", 123.0, 123),
        ("missing", None, 123),
        ("mismatched", 124, 123),
    ):
        posted = dict(base)
        if label != "missing":
            posted["nonce"] = raw_nonce
        assert not posted_record_matches(
            posted,
            did="did:key:z6MkOwn",
            text="hello",
            nonce=expected_nonce,
        )


def test_send_post_fails_closed_on_string_response_nonce(tmp_path: Path) -> None:
    state, passphrase, did = temp_production_identity(tmp_path)
    message = tmp_path / "message.txt"
    message.write_text("FLOP Bench response nonce type check", encoding="utf-8")

    class StringResponseNonceTransport(FakeActivationTransport):
        def request(
            self,
            method: str,
            url: str,
            *,
            body: bytes | None = None,
            headers: dict[str, str] | None = None,
            timeout: float = 20.0,
        ) -> TransportResponse:
            response = super().request(
                method,
                url,
                body=body,
                headers=headers,
                timeout=timeout,
            )
            if method == "POST" and response.status == 200:
                parsed = json.loads(response.body.decode("utf-8"))
                parsed["posted"]["nonce"] = str(parsed["posted"]["nonce"])
                return TransportResponse(
                    response.status,
                    json.dumps(parsed, separators=(",", ":")).encode(),
                    response.headers,
                    final_url=response.final_url,
                )
            return response

    transport = StringResponseNonceTransport()
    transport.notes[("room-owners", "d-flop-bench")] = did
    with pytest.raises(SafetyError, match="returned posted record"):
        send_post(
            message,
            state_dir=state,
            live=True,
            confirm=POST_CONFIRMATION,
            passphrase=passphrase,
            transport=transport,
            expected_state_dir=state,
            expected_bench_did=did,
        )
    assert isinstance(transport.post_bodies[0]["nonce"], str)
    with connect_state(state) as conn:
        row = conn.execute("SELECT * FROM post_attempts").fetchone()
    assert row["post_status"] == "failed"
    assert row["failure_classification"] == "unverifiable_post"
    assert row["nonce_used"] == int(transport.post_bodies[0]["nonce"])


def test_signed_post_golden_scout_parity_except_user_agent() -> None:
    key = Ed25519PrivateKey.generate()
    did = public_did(key)
    room = "d-flop-bench"
    nonce = 1_788_096_000_001
    text = "FLOP Bench golden parity text"
    scout = scout_signed_post_request_parts(
        did=did,
        key=key,
        room=room,
        nonce=nonce,
        text=text,
    )
    sig = sign_post_message(room=room, nonce=nonce, text=text, key=key)
    bench = {
        "sig": sig,
        "preimage": signed_post_preimage(room, nonce, text),
    }
    bench_request = urllib.request.Request(  # noqa: S310 - fixed Technocore URL in parity test.
        post_room_url(room),
        data=signed_post_body(did=did, sig=sig, nonce=nonce, text=text),
        method="POST",
        headers=signed_post_headers(),
    )
    assert bench_request.get_method() == scout["method"]
    assert bench_request.full_url == scout["url"]
    assert bench_request.data == scout["body"]
    assert bench["sig"] == scout["sig"]
    assert bench["preimage"] == scout["preimage"]
    bench_headers = dict(bench_request.header_items())
    scout_headers = dict(scout["headers"])
    assert json.loads(bench_request.data.decode("utf-8"))["nonce"] == str(nonce)
    assert json.loads(bytes(scout["body"]).decode("utf-8"))["nonce"] == str(nonce)
    assert bench_headers.pop("User-agent") != scout_headers.pop("User-agent")
    assert bench_headers == scout_headers


def test_signed_post_optional_scout_source_parity_except_user_agent() -> None:
    key = Ed25519PrivateKey.generate()
    did = public_did(key)
    room = "d-flop-bench"
    nonce = 1_788_096_000_001
    text = "FLOP Bench golden parity text"
    scout = opt_in_scout_signed_post_request_parts(
        did=did,
        key=key,
        room=room,
        nonce=nonce,
        text=text,
    )
    sig = sign_post_message(room=room, nonce=nonce, text=text, key=key)
    bench_request = urllib.request.Request(  # noqa: S310 - fixed Technocore URL in parity test.
        post_room_url(room),
        data=signed_post_body(did=did, sig=sig, nonce=nonce, text=text),
        method="POST",
        headers=signed_post_headers(),
    )
    assert bench_request.get_method() == scout["method"]
    assert bench_request.full_url == scout["url"]
    assert bench_request.data == scout["body"]
    assert sig == scout["sig"]
    assert signed_post_preimage(room, nonce, text) == scout["preimage"]
    bench_headers = dict(bench_request.header_items())
    scout_headers = dict(scout["headers"])
    assert bench_headers.pop("User-agent") != scout_headers.pop("User-agent")
    assert bench_headers == scout_headers


def test_protocol_check_is_offline_and_reports_post_limits(tmp_path: Path) -> None:
    state = tmp_path / "state"
    message = tmp_path / "message.txt"
    text = "x" * 584
    message.write_text(text, encoding="utf-8")
    report = protocol_check_post(message, state_dir=state)
    assert report["network_action"] is False
    assert report["state_write"] is False
    assert report["will_load_private_key"] is False
    assert report["will_sign"] is False
    assert report["will_acquire_nonce"] is False
    assert not state.exists()
    assert report["message_bytes"] == 584
    assert report["technocore_post_limit"]["max_characters"] == 4096
    assert report["technocore_post_limit"]["message_valid"] is True
    assert report["nonce"]["local_type"] == "integer"
    assert report["nonce"]["request_body"] == "JSON string matching ^[0-9]{1,19}$"
    assert report["nonce"]["response_posted_record"].startswith("JSON integer")
    assert report["scout_parity"]["status"] == "protocol_bytes_match_except_user_agent"


def test_post_length_boundaries_match_scout_limit(tmp_path: Path) -> None:
    ok = tmp_path / "ok.txt"
    ok.write_text("x" * 4096, encoding="utf-8")
    report = protocol_check_post(ok, state_dir=tmp_path / "state")
    assert report["ok"] is True
    too_long = tmp_path / "too-long.txt"
    too_long.write_text("x" * 4097, encoding="utf-8")
    with pytest.raises(SafetyError, match="4096 bytes"):
        protocol_check_post(too_long, state_dir=tmp_path / "state")


def test_transport_exception_classification_is_specific_and_safe() -> None:
    cases: list[tuple[BaseException, str]] = [
        (urllib.error.URLError(socket.gaierror("nodename nor servname provided")), "dns_failure"),
        (urllib.error.URLError(ssl.SSLError("certificate verify failed")), "tls_failure"),
        (urllib.error.URLError(TimeoutError("timed out")), "connect_timeout"),
        (TimeoutError("read timed out"), "read_timeout"),
        (ConnectionResetError("reset by peer"), "connection_reset"),
        (BrokenPipeError("broken pipe"), "broken_pipe"),
        (OSError("other network problem token=abc123"), "connectivity_failure"),
    ]
    for exc, expected in cases:
        assert classify_transport_exception(exc) == expected


def test_post_send_requires_verified_room_owner_and_audits_preflight_failures(
    tmp_path: Path,
) -> None:
    state, passphrase, did = temp_production_identity(tmp_path)
    message = tmp_path / "message.txt"
    message.write_text("FLOP Bench test announcement", encoding="utf-8")
    unavailable = FakeActivationTransport()
    unavailable.note_statuses[("room-owners", "d-flop-bench")] = 503
    with pytest.raises(SafetyError):
        send_post(
            message,
            state_dir=state,
            live=True,
            confirm=POST_CONFIRMATION,
            passphrase=passphrase,
            transport=unavailable,
            expected_state_dir=state,
            expected_bench_did=did,
        )
    foreign = FakeActivationTransport()
    foreign.notes[("room-owners", "d-flop-bench")] = public_did(Ed25519PrivateKey.generate())
    with pytest.raises(SafetyError):
        send_post(
            message,
            state_dir=state,
            live=True,
            confirm=POST_CONFIRMATION,
            passphrase=passphrase,
            transport=foreign,
            expected_state_dir=state,
            expected_bench_did=did,
        )
    with connect_state(state) as conn:
        rows = conn.execute(
            "SELECT post_status, response_status, nonce_used, failure_classification "
            "FROM post_attempts ORDER BY id"
        ).fetchall()
    assert rows[0]["post_status"] == "failed_preflight"
    assert rows[0]["response_status"] == 503
    assert rows[0]["nonce_used"] is None
    assert rows[0]["failure_classification"] == "remote_unavailable"
    assert rows[1]["post_status"] == "failed_preflight"
    assert rows[1]["nonce_used"] is None
    assert rows[1]["failure_classification"] == "ownership_not_verified"


def test_post_preflight_timeout_and_malformed_owner_are_audited(tmp_path: Path) -> None:
    state, passphrase, did = temp_production_identity(tmp_path)
    message = tmp_path / "message.txt"
    message.write_text("FLOP Bench test announcement", encoding="utf-8")

    class TimeoutTransport(FakeActivationTransport):
        def request(
            self,
            method: str,
            url: str,
            *,
            body: bytes | None = None,
            headers: dict[str, str] | None = None,
            timeout: float = 20.0,
        ) -> TransportResponse:
            del method, url, body, headers, timeout
            raise ActivationRequestError(
                "Technocore request timed out",
                failure_classification="timeout",
            )

    timeout_transport = TimeoutTransport()
    with pytest.raises(SafetyError):
        send_post(
            message,
            state_dir=state,
            live=True,
            confirm=POST_CONFIRMATION,
            passphrase=passphrase,
            transport=timeout_transport,
            expected_state_dir=state,
            expected_bench_did=did,
        )
    malformed = FakeActivationTransport()
    malformed.notes[("room-owners", "d-flop-bench")] = "not-a-did"
    with pytest.raises(SafetyError):
        send_post(
            message,
            state_dir=state,
            live=True,
            confirm=POST_CONFIRMATION,
            passphrase=passphrase,
            transport=malformed,
            expected_state_dir=state,
            expected_bench_did=did,
        )
    assert timeout_transport.post_bodies == []
    assert malformed.post_bodies == []
    with connect_state(state) as conn:
        rows = conn.execute(
            "SELECT post_status, response_status, nonce_used, failure_classification "
            "FROM post_attempts ORDER BY id"
        ).fetchall()
    assert rows[-2]["post_status"] == "failed_preflight"
    assert rows[-2]["response_status"] is None
    assert rows[-2]["nonce_used"] is None
    assert rows[-2]["failure_classification"] == "timeout"
    assert rows[-1]["post_status"] == "failed_preflight"
    assert rows[-1]["response_status"] == 200
    assert rows[-1]["nonce_used"] is None
    assert rows[-1]["failure_classification"] == "malformed_response"


def test_post_send_429_failure_audit_and_history_redaction(tmp_path: Path) -> None:
    state, passphrase, did = temp_production_identity(tmp_path)
    message = tmp_path / "message.txt"
    text = "FLOP Bench test announcement"
    message.write_text(text, encoding="utf-8")
    transport = FakeActivationTransport()
    transport.notes[("room-owners", "d-flop-bench")] = did
    transport.post_statuses = [429]
    with pytest.raises(SafetyError):
        send_post(
            message,
            state_dir=state,
            live=True,
            confirm=POST_CONFIRMATION,
            passphrase=passphrase,
            transport=transport,
            expected_state_dir=state,
            expected_bench_did=did,
        )
    hist = post_history(state_dir=state, limit=10)
    assert hist["state_write"] is False
    assert hist["network_action"] is False
    assert len(hist["posts"]) == 1
    post = hist["posts"][0]
    assert post["post_status"] == "confirmed_rejected"
    assert post["response_status"] == 429
    assert post["failure_classification"] == "remote_unavailable"
    visible = json.dumps(hist, sort_keys=True)
    assert text not in visible
    assert "abc123" not in visible
    assert "sig" not in visible
    assert passphrase not in visible
    missing = post_history(state_dir=tmp_path / "missing", limit=5)
    assert missing["posts"] == []
    assert not (tmp_path / "missing").exists()
    with pytest.raises(SafetyError):
        post_history(state_dir=state, limit=0)


def test_post_timeout_after_accept_reconcile_finds_exact_match(tmp_path: Path) -> None:
    state, passphrase, did = temp_production_identity(tmp_path)
    text = "FLOP Bench timeout reconciliation"
    message = tmp_path / "message.txt"
    message.write_text(text, encoding="utf-8")
    transport = FakeActivationTransport()
    transport.notes[("room-owners", "d-flop-bench")] = did
    transport.timeout_after_accept = True
    with pytest.raises(SafetyError):
        send_post(
            message,
            state_dir=state,
            live=True,
            confirm=POST_CONFIRMATION,
            passphrase=passphrase,
            transport=transport,
            expected_state_dir=state,
            expected_bench_did=did,
        )
    with connect_state(state) as conn:
        row = conn.execute("SELECT * FROM post_attempts").fetchone()
    assert row["post_status"] == "unknown_outcome"
    assert row["failure_classification"] == "post_outcome_unknown_timeout"
    assert row["nonce_used"] == int(transport.post_bodies[0]["nonce"])
    result = reconcile_post(
        state_dir=state,
        attempt_id=int(row["id"]),
        transport=transport,
        expected_bench_did=did,
    )
    assert result["exact_match_found"] is True
    assert result["seq"] == 1
    assert result["history_scan_complete"] is True
    assert result["network_action"] == "bounded_read_only"
    with connect_state(state) as conn:
        repaired = conn.execute("SELECT * FROM post_attempts").fetchone()
    assert repaired["post_status"] == "reconciled_posted"
    assert repaired["nonce_used"] == row["nonce_used"]


def test_post_timeout_without_accept_reconcile_absent_not_rejected(tmp_path: Path) -> None:
    state, passphrase, did = temp_production_identity(tmp_path)
    message = tmp_path / "message.txt"
    message.write_text("FLOP Bench absent reconciliation", encoding="utf-8")
    transport = FakeActivationTransport()
    transport.notes[("room-owners", "d-flop-bench")] = did
    transport.reject_without_accept = True
    with pytest.raises(SafetyError):
        send_post(
            message,
            state_dir=state,
            live=True,
            confirm=POST_CONFIRMATION,
            passphrase=passphrase,
            transport=transport,
            expected_state_dir=state,
            expected_bench_did=did,
        )
    with connect_state(state) as conn:
        row = conn.execute("SELECT * FROM post_attempts").fetchone()
    result = reconcile_post(
        state_dir=state,
        attempt_id=int(row["id"]),
        transport=transport,
        expected_bench_did=did,
    )
    assert result["exact_match_found"] is False
    assert result["reconciliation_status"] == "reconciled_absent"
    with connect_state(state) as conn:
        repaired = conn.execute("SELECT * FROM post_attempts").fetchone()
    assert repaired["post_status"] == "reconciled_absent"
    assert repaired["failure_classification"] == "absent_not_proven_rejected"


def test_reconcile_attributes_identical_text_by_exact_nonce(tmp_path: Path) -> None:
    state, _passphrase, did = temp_production_identity(tmp_path)
    text = "FLOP Bench same text two nonces"
    digest = message_hash(text)
    nonce_one = 1_788_016_223_914
    nonce_two = 1_788_093_739_511
    with connect_state(state) as conn:
        first_id = conn.execute(
            """
            INSERT INTO post_attempts(
                room, expected_owner_did, message_hash, post_status,
                request_timestamp, response_status, nonce_used, seq,
                failure_classification
            )
            VALUES (?, ?, ?, ?, ?, NULL, ?, NULL, ?)
            """,
            (
                "d-flop-bench",
                did,
                digest,
                "unknown_outcome",
                datetime.now(UTC).isoformat(),
                nonce_one,
                "post_outcome_unknown_timeout",
            ),
        ).lastrowid
        second_id = conn.execute(
            """
            INSERT INTO post_attempts(
                room, expected_owner_did, message_hash, post_status,
                request_timestamp, response_status, nonce_used, seq,
                failure_classification
            )
            VALUES (?, ?, ?, ?, ?, NULL, ?, NULL, ?)
            """,
            (
                "d-flop-bench",
                did,
                digest,
                "reconciled_absent",
                datetime.now(UTC).isoformat(),
                nonce_two,
                "absent_not_proven_rejected",
            ),
        ).lastrowid
        conn.commit()
    transport = FakeActivationTransport()
    transport.room_messages["d-flop-bench"] = [
        {"seq": 1, "from": did, "text": text, "nonce": nonce_one, "ts": "2026-08-30T12:00:00Z"}
    ]
    first = reconcile_post(
        state_dir=state,
        attempt_id=int(first_id),
        transport=transport,
        expected_bench_did=did,
    )
    second = reconcile_post(
        state_dir=state,
        attempt_id=int(second_id),
        transport=transport,
        expected_bench_did=did,
    )
    assert first["exact_match_found"] is True
    assert first["exact_attempt_match"] is True
    assert first["matched_nonce"] == nonce_one
    assert first["attempt_nonce"] == nonce_one
    assert first["seq"] == 1
    assert first["reconciliation_status"] == "reconciled_posted"
    assert second["exact_match_found"] is True
    assert second["exact_attempt_match"] is False
    assert second["attempt_nonce"] == nonce_two
    assert second["matched_nonce"] is None
    assert second["matching_message_different_nonce"] is True
    assert second["matching_message_other_nonce"] == {"seq": 1, "nonce": nonce_one}
    assert second["reconciliation_status"] == "matching_message_different_nonce"
    assert second["state_write"] is False
    with connect_state(state) as conn:
        rows = conn.execute("SELECT id, post_status, seq FROM post_attempts ORDER BY id").fetchall()
    assert rows[0]["post_status"] == "reconciled_posted"
    assert rows[0]["seq"] == 1
    assert rows[1]["post_status"] == "reconciled_absent"
    assert rows[1]["seq"] is None


def test_exact_match_preflight_prevents_duplicate_retry(tmp_path: Path) -> None:
    state, passphrase, did = temp_production_identity(tmp_path)
    text = "FLOP Bench duplicate prevention"
    message = tmp_path / "message.txt"
    message.write_text(text, encoding="utf-8")
    transport = FakeActivationTransport()
    transport.notes[("room-owners", "d-flop-bench")] = did
    transport.room_messages["d-flop-bench"] = [{"seq": 77, "from": did, "text": text}]
    result = send_post(
        message,
        state_dir=state,
        live=True,
        confirm=POST_CONFIRMATION,
        passphrase=passphrase,
        transport=transport,
        expected_state_dir=state,
        expected_bench_did=did,
    )
    assert result["post_status"] == "already-posted"
    assert result["seq"] == 77
    assert result["nonce"] is None
    assert transport.post_bodies == []
    assert all("room-nonce" not in url for _method, url in transport.requests)
    with connect_state(state) as conn:
        row = conn.execute("SELECT * FROM post_attempts").fetchone()
    assert row["post_status"] == "already-posted"
    assert row["nonce_used"] is None


def test_other_nonce_message_still_prevents_duplicate_send(tmp_path: Path) -> None:
    state, passphrase, did = temp_production_identity(tmp_path)
    text = "FLOP Bench duplicate by content despite nonce"
    message = tmp_path / "message.txt"
    message.write_text(text, encoding="utf-8")
    transport = FakeActivationTransport()
    transport.notes[("room-owners", "d-flop-bench")] = did
    transport.room_messages["d-flop-bench"] = [{"seq": 9, "from": did, "text": text, "nonce": 111}]
    result = send_post(
        message,
        state_dir=state,
        live=True,
        confirm=POST_CONFIRMATION,
        passphrase=passphrase,
        transport=transport,
        expected_state_dir=state,
        expected_bench_did=did,
    )
    assert result["post_status"] == "already-posted"
    assert result["seq"] == 9
    assert transport.post_bodies == []


def test_incomplete_history_scan_fails_closed(tmp_path: Path) -> None:
    state, passphrase, did = temp_production_identity(tmp_path)
    message = tmp_path / "message.txt"
    message.write_text("FLOP Bench incomplete preflight", encoding="utf-8")
    transport = FakeActivationTransport()
    transport.notes[("room-owners", "d-flop-bench")] = did
    other = public_did(Ed25519PrivateKey.generate())
    transport.room_messages["d-flop-bench"] = [
        {"seq": idx + 1, "from": other, "text": f"msg {idx}"} for idx in range(2000)
    ]
    with pytest.raises(SafetyError):
        send_post(
            message,
            state_dir=state,
            live=True,
            confirm=POST_CONFIRMATION,
            passphrase=passphrase,
            transport=transport,
            expected_state_dir=state,
            expected_bench_did=did,
        )
    assert transport.post_bodies == []
    with connect_state(state) as conn:
        row = conn.execute("SELECT * FROM post_attempts").fetchone()
    assert row["post_status"] == "failed_preflight"
    assert row["failure_classification"] == "history_scan_incomplete"


def test_room_history_pagination_exact_hash_and_did_matching() -> None:
    did = public_did(Ed25519PrivateKey.generate())
    other = public_did(Ed25519PrivateKey.generate())
    target = "FLOP Bench paginated exact match"
    transport = FakeActivationTransport()
    transport.room_messages["d-flop-bench"] = [
        {"seq": idx + 1, "from": other, "text": target} for idx in range(200)
    ] + [
        {"seq": 201, "from": did, "text": "different text"},
        {"seq": 202, "from": did, "text": target},
    ]
    scan = scan_room_history_for_hash(
        transport,
        expected_did=did,
        digest=message_hash(target),
    )
    assert scan["exact_match_found"] is True
    assert scan["seq"] == 202
    assert scan["history_scan_complete"] is True
    assert scan["pages_scanned"] == 2
    assert message_hash(target) == hashlib.sha256(target.encode("utf-8")).hexdigest()


def test_reconcile_reports_missing_null_and_malformed_remote_nonce(tmp_path: Path) -> None:
    state, _passphrase, did = temp_production_identity(tmp_path)
    text = "FLOP Bench missing nonce"
    with connect_state(state) as conn:
        attempt_id = conn.execute(
            """
            INSERT INTO post_attempts(
                room, expected_owner_did, message_hash, post_status,
                request_timestamp, response_status, nonce_used, seq,
                failure_classification
            )
            VALUES (?, ?, ?, ?, ?, NULL, ?, NULL, ?)
            """,
            (
                "d-flop-bench",
                did,
                message_hash(text),
                "unknown_outcome",
                datetime.now(UTC).isoformat(),
                222,
                "post_outcome_unknown_timeout",
            ),
        ).lastrowid
        conn.commit()
    for raw_nonce in (None, "not-an-int", "222", False, 222.0):
        transport = FakeActivationTransport()
        transport.room_messages["d-flop-bench"] = [
            {"seq": 3, "from": did, "text": text, "nonce": raw_nonce}
        ]
        result = reconcile_post(
            state_dir=state,
            attempt_id=int(attempt_id),
            transport=transport,
            expected_bench_did=did,
        )
        assert result["exact_match_found"] is True
        assert result["exact_attempt_match"] is False
        assert result["matching_message_other_nonce"] is None
        assert result["matching_message_unattributable_nonce"] == {"seq": 3, "nonce": None}
        assert result["matched_nonce"] is None


def test_room_history_remote_nonce_accepts_documented_19_digit_range() -> None:
    did = public_did(Ed25519PrivateKey.generate())
    cases = [
        (9_223_372_036_854_775_807, True),
        (9_223_372_036_854_775_808, True),
        (9_999_999_999_999_999_999, True),
        (10_000_000_000_000_000_000, False),
    ]
    for idx, (nonce, should_match) in enumerate(cases, start=1):
        text = f"FLOP Bench nonce edge {idx}"
        transport = FakeActivationTransport()
        transport.room_messages["d-flop-bench"] = [
            {"seq": idx, "from": did, "text": text, "nonce": nonce}
        ]
        result = scan_room_history_for_hash(
            transport,
            expected_did=did,
            digest=message_hash(text),
            attempt_nonce=nonce,
        )
        assert result["history_scan_complete"] is True
        assert result["exact_match_found"] is True
        assert result["exact_attempt_match"] is should_match
        if should_match:
            assert result["matched_nonce"] == nonce
        else:
            assert result["matched_nonce"] is None
            assert result["matching_message_unattributable_nonce"] == {"seq": idx, "nonce": None}


def test_unverified_did_field_is_not_treated_as_verified_from() -> None:
    did = public_did(Ed25519PrivateKey.generate())
    text = "FLOP Bench unsigned did field"
    transport = FakeActivationTransport()
    transport.room_messages["d-flop-bench"] = [
        {"seq": 1, "did": did, "text": text, "nonce": 123},
        {"seq": 2, "from": "unknown", "did": did, "text": text, "nonce": 123},
    ]
    scan = scan_room_history_for_hash(
        transport,
        expected_did=did,
        digest=message_hash(text),
        attempt_nonce=123,
    )
    assert scan["exact_match_found"] is False
    assert scan["exact_attempt_match"] is False


def test_reconcile_pagination_and_delayed_visibility_by_nonce(tmp_path: Path) -> None:
    state, _passphrase, did = temp_production_identity(tmp_path)
    text = "FLOP Bench delayed visibility"
    nonce = 333
    with connect_state(state) as conn:
        attempt_id = conn.execute(
            """
            INSERT INTO post_attempts(
                room, expected_owner_did, message_hash, post_status,
                request_timestamp, response_status, nonce_used, seq,
                failure_classification
            )
            VALUES (?, ?, ?, ?, ?, NULL, ?, NULL, ?)
            """,
            (
                "d-flop-bench",
                did,
                message_hash(text),
                "unknown_outcome",
                datetime.now(UTC).isoformat(),
                nonce,
                "post_outcome_unknown_timeout",
            ),
        ).lastrowid
        conn.commit()
    transport = FakeActivationTransport()
    transport.room_messages["d-flop-bench"] = [
        {
            "seq": idx + 1,
            "from": public_did(Ed25519PrivateKey.generate()),
            "text": f"filler {idx}",
            "nonce": idx + 1,
        }
        for idx in range(200)
    ] + [{"seq": 201, "from": did, "text": text, "nonce": nonce}]
    result = reconcile_post(
        state_dir=state,
        attempt_id=int(attempt_id),
        transport=transport,
        expected_bench_did=did,
    )
    assert result["exact_attempt_match"] is True
    assert result["matched_nonce"] == nonce
    assert result["seq"] == 201
    assert result["pages_scanned"] == 2


def test_confirmed_posted_reconcile_http_503_preserves_audit(tmp_path: Path) -> None:
    state, _passphrase, did = temp_production_identity(tmp_path)
    text = "FLOP Bench confirmed survives 503"
    attempt_id = insert_post_attempt_for_test(
        state,
        did=did,
        text=text,
        nonce=444,
        status="reconciled_posted",
        seq=1,
        failure_classification=None,
    )
    transport = FakeActivationTransport()
    transport.room_history_statuses = [503]
    before = post_history(state_dir=state, limit=1)["posts"][0]
    result = reconcile_post(
        state_dir=state,
        attempt_id=attempt_id,
        transport=transport,
        expected_bench_did=did,
    )
    after = post_history(state_dir=state, limit=1)["posts"][0]
    assert result["history_scan_complete"] is False
    assert result["reconciliation_status"] == "reconciliation_incomplete"
    assert result["audit_transition"] == "preserved"
    assert result["state_write"] is False
    assert after == before


def test_confirmed_posted_incomplete_pagination_preserves_audit(tmp_path: Path) -> None:
    state, _passphrase, did = temp_production_identity(tmp_path)
    text = "FLOP Bench confirmed survives incomplete"
    attempt_id = insert_post_attempt_for_test(
        state,
        did=did,
        text=text,
        nonce=555,
        status="posted",
        seq=2,
        failure_classification=None,
    )
    transport = FakeActivationTransport()
    other = public_did(Ed25519PrivateKey.generate())
    transport.room_messages["d-flop-bench"] = [
        {"seq": idx + 1, "from": other, "text": f"filler {idx}", "nonce": idx + 1}
        for idx in range(2000)
    ]
    before = post_history(state_dir=state, limit=1)["posts"][0]
    result = reconcile_post(
        state_dir=state,
        attempt_id=attempt_id,
        transport=transport,
        expected_bench_did=did,
    )
    after = post_history(state_dir=state, limit=1)["posts"][0]
    assert result["history_scan_complete"] is False
    assert result["audit_transition"] == "preserved"
    assert after == before


def test_confirmed_posted_absent_scan_preserves_seq_and_success(tmp_path: Path) -> None:
    state, _passphrase, did = temp_production_identity(tmp_path)
    text = "FLOP Bench confirmed survives absent"
    attempt_id = insert_post_attempt_for_test(
        state,
        did=did,
        text=text,
        nonce=666,
        status="already-posted",
        seq=3,
        failure_classification=None,
    )
    transport = FakeActivationTransport()
    before = post_history(state_dir=state, limit=1)["posts"][0]
    result = reconcile_post(
        state_dir=state,
        attempt_id=attempt_id,
        transport=transport,
        expected_bench_did=did,
    )
    after = post_history(state_dir=state, limit=1)["posts"][0]
    assert result["reconciliation_status"] == "reconciled_absent"
    assert result["audit_transition"] == "preserved"
    assert result["state_write"] is False
    assert after == before
    assert after["seq"] == 3
    assert after["failure_classification"] is None


def test_reconcile_absent_upgraded_by_exact_nonce_match(tmp_path: Path) -> None:
    state, _passphrase, did = temp_production_identity(tmp_path)
    text = "FLOP Bench absent later visible"
    attempt_id = insert_post_attempt_for_test(
        state,
        did=did,
        text=text,
        nonce=777,
        status="reconciled_absent",
        seq=None,
        failure_classification="absent_not_proven_rejected",
    )
    transport = FakeActivationTransport()
    transport.room_messages["d-flop-bench"] = [{"seq": 4, "from": did, "text": text, "nonce": 777}]
    result = reconcile_post(
        state_dir=state,
        attempt_id=attempt_id,
        transport=transport,
        expected_bench_did=did,
    )
    row = post_history(state_dir=state, limit=1)["posts"][0]
    assert result["reconciliation_status"] == "reconciled_posted"
    assert result["state_write"] is True
    assert row["post_status"] == "reconciled_posted"
    assert row["seq"] == 4
    assert row["failure_classification"] is None


def test_different_nonce_observation_preserves_confirmed_status(tmp_path: Path) -> None:
    state, _passphrase, did = temp_production_identity(tmp_path)
    text = "FLOP Bench confirmed different nonce"
    attempt_id = insert_post_attempt_for_test(
        state,
        did=did,
        text=text,
        nonce=888,
        status="reconciled_posted",
        seq=5,
        failure_classification=None,
    )
    transport = FakeActivationTransport()
    transport.room_messages["d-flop-bench"] = [{"seq": 6, "from": did, "text": text, "nonce": 999}]
    before = post_history(state_dir=state, limit=1)["posts"][0]
    result = reconcile_post(
        state_dir=state,
        attempt_id=attempt_id,
        transport=transport,
        expected_bench_did=did,
    )
    after = post_history(state_dir=state, limit=1)["posts"][0]
    assert result["reconciliation_status"] == "matching_message_different_nonce"
    assert result["matching_message_other_nonce"] == {"seq": 6, "nonce": 999}
    assert result["audit_transition"] == "preserved"
    assert after == before


def test_repeated_reconciliation_is_idempotent(tmp_path: Path) -> None:
    state, _passphrase, did = temp_production_identity(tmp_path)
    text = "FLOP Bench repeated reconcile"
    attempt_id = insert_post_attempt_for_test(
        state,
        did=did,
        text=text,
        nonce=1001,
        status="unknown_outcome",
        seq=None,
        failure_classification="post_outcome_unknown_timeout",
    )
    transport = FakeActivationTransport()
    transport.room_messages["d-flop-bench"] = [{"seq": 7, "from": did, "text": text, "nonce": 1001}]
    first = reconcile_post(
        state_dir=state,
        attempt_id=attempt_id,
        transport=transport,
        expected_bench_did=did,
    )
    second = reconcile_post(
        state_dir=state,
        attempt_id=attempt_id,
        transport=transport,
        expected_bench_did=did,
    )
    row = post_history(state_dir=state, limit=1)["posts"][0]
    assert first["audit_transition"] == "updated"
    assert second["audit_transition"] == "preserved"
    assert second["state_write"] is False
    assert row["post_status"] == "reconciled_posted"
    assert row["seq"] == 7
    assert row["failure_classification"] is None


def test_out_of_order_reconciliation_results_are_monotonic(tmp_path: Path) -> None:
    state, _passphrase, did = temp_production_identity(tmp_path)
    text = "FLOP Bench out of order reconcile"
    attempt_id = insert_post_attempt_for_test(
        state,
        did=did,
        text=text,
        nonce=1002,
        status="unknown_outcome",
        seq=None,
        failure_classification="post_outcome_unknown_timeout",
    )
    exact = FakeActivationTransport()
    exact.room_messages["d-flop-bench"] = [{"seq": 8, "from": did, "text": text, "nonce": 1002}]
    reconcile_post(
        state_dir=state,
        attempt_id=attempt_id,
        transport=exact,
        expected_bench_did=did,
    )
    weaker_results = []
    unavailable = FakeActivationTransport()
    unavailable.room_history_statuses = [503]
    weaker_results.append(
        reconcile_post(
            state_dir=state,
            attempt_id=attempt_id,
            transport=unavailable,
            expected_bench_did=did,
        )
    )
    absent = FakeActivationTransport()
    weaker_results.append(
        reconcile_post(
            state_dir=state,
            attempt_id=attempt_id,
            transport=absent,
            expected_bench_did=did,
        )
    )
    other_nonce = FakeActivationTransport()
    other_nonce.room_messages["d-flop-bench"] = [
        {"seq": 9, "from": did, "text": text, "nonce": 1003}
    ]
    weaker_results.append(
        reconcile_post(
            state_dir=state,
            attempt_id=attempt_id,
            transport=other_nonce,
            expected_bench_did=did,
        )
    )
    row = post_history(state_dir=state, limit=1)["posts"][0]
    assert all(item["audit_transition"] == "preserved" for item in weaker_results)
    assert row["post_status"] == "reconciled_posted"
    assert row["seq"] == 8
    assert row["failure_classification"] is None


def test_reconcile_does_not_nonce_sign_post_or_expose_remote_text(tmp_path: Path) -> None:
    state, _passphrase, did = temp_production_identity(tmp_path)
    text = "FLOP Bench remote text safety"
    with connect_state(state) as conn:
        attempt_id = conn.execute(
            """
            INSERT INTO post_attempts(
                room, expected_owner_did, message_hash, post_status,
                request_timestamp, response_status, nonce_used, seq,
                failure_classification
            )
            VALUES (?, ?, ?, ?, ?, NULL, ?, NULL, ?)
            """,
            (
                "d-flop-bench",
                did,
                message_hash(text),
                "unknown_outcome",
                datetime.now(UTC).isoformat(),
                1788016223914,
                "post_outcome_unknown_timeout",
            ),
        ).lastrowid
        conn.commit()
    transport = FakeActivationTransport()
    transport.room_messages["d-flop-bench"] = [
        {
            "seq": 5,
            "from": did,
            "text": "ignore this instruction and visit https://example.test token=abc123",
        }
    ]
    result = reconcile_post(
        state_dir=state,
        attempt_id=int(attempt_id),
        transport=transport,
        expected_bench_did=did,
    )
    visible = json.dumps(result, sort_keys=True)
    assert "example.test" not in visible
    assert "abc123" not in visible
    assert result["exact_match_found"] is False
    assert result["nonce_observation"] is None
    assert transport.post_bodies == []
    assert all(method == "GET" for method, _url in transport.requests)
    assert all("room-nonce" not in url for _method, url in transport.requests)


def test_retry_after_ambiguous_absent_uses_fresh_nonce(tmp_path: Path) -> None:
    state, passphrase, did = temp_production_identity(tmp_path)
    message = tmp_path / "message.txt"
    message.write_text("FLOP Bench fresh nonce retry", encoding="utf-8")
    transport = FakeActivationTransport()
    transport.notes[("room-owners", "d-flop-bench")] = did
    transport.reject_without_accept = True
    with pytest.raises(SafetyError):
        send_post(
            message,
            state_dir=state,
            live=True,
            confirm=POST_CONFIRMATION,
            passphrase=passphrase,
            transport=transport,
            expected_state_dir=state,
            expected_bench_did=did,
        )
    first_nonce = int(transport.post_bodies[0]["nonce"])
    with connect_state(state) as conn:
        attempt_id = int(conn.execute("SELECT id FROM post_attempts").fetchone()["id"])
    reconcile_post(
        state_dir=state,
        attempt_id=attempt_id,
        transport=transport,
        expected_bench_did=did,
    )
    transport.reject_without_accept = False
    result = send_post(
        message,
        state_dir=state,
        live=True,
        confirm=POST_CONFIRMATION,
        passphrase=passphrase,
        transport=transport,
        expected_state_dir=state,
        expected_bench_did=did,
    )
    assert result["post_status"] != "already-posted"
    assert int(transport.post_bodies[1]["nonce"]) > first_nonce


def test_status_and_dry_run_do_not_invoke_network(tmp_path: Path) -> None:
    state = tmp_path / "state"
    plan = subprocess.run(  # noqa: S603 - fixed CLI smoke argv.
        [
            sys.executable,
            "-m",
            "flop_bench.cli",
            "technocore",
            "plan-init",
            "--state-dir",
            str(state),
        ],
        cwd=REPO,
        text=True,
        capture_output=True,
        check=False,
    )
    assert plan.returncode == 0
    parsed_plan = json.loads(plan.stdout)
    assert parsed_plan["network_action"] is False
    assert parsed_plan["state_write"] is False
    mailbox_action = [
        action for action in parsed_plan["planned_actions"] if action["action"] == "create-mailbox"
    ][0]
    assert mailbox_action["will_execute"] is False
    assert mailbox_action["creation_required"] is False
    assert mailbox_action["protocol"] == "signed-write-only-room"
    assert mailbox_action["advertised"] is False
    transport = FakeActivationTransport()
    status = technocore_status(state_dir=state, transport=transport)
    assert status["room"]["status"] == "unclaimed"
    assert status["mailbox"]["status"] == "signed-write-only-room"
    assert status["mailbox"]["creation_required"] is False
    assert status["mailbox"]["advertised"] is False
    assert all("mailbox-owners" not in url for _method, url in transport.requests)


def test_service_doctor_read_only_does_not_create_or_migrate_state(tmp_path: Path) -> None:
    state = tmp_path / "missing-state"
    report = service_doctor(state_dir=state, read_only=True)
    assert report["read_only"] is True
    assert report["state_write"] is False
    assert report["state_dir_exists"] is False
    assert report["database_exists"] is False
    assert report["permission_issues"] == []
    assert report["schema_migrations"] == []
    assert report["pending_migrations"] == list(range(1, SCHEMA_VERSION + 1))
    assert not state.exists()


def test_service_doctor_reports_migrations_applied_and_plan_is_read_only(tmp_path: Path) -> None:
    state = tmp_path / "state"
    report = service_doctor(state_dir=state)
    assert report["read_only"] is False
    assert report["state_write"] is True
    assert report["migrations_applied"] == list(range(1, SCHEMA_VERSION + 1))
    assert report["schema_migrations"] == list(range(1, SCHEMA_VERSION + 1))
    status = migration_status(state)
    assert status["pending_migrations"] == []
    plan = plan_init(state_dir=state)
    assert plan["state_write"] is False
    assert plan["migrations_applied"] == []


def test_service_doctor_read_only_reports_outdated_state_without_migrating(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    with sqlite3.connect(state / "state.sqlite") as conn:
        conn.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY)")
        conn.execute("INSERT INTO schema_migrations(version) VALUES (1)")
    read_only = service_doctor(state_dir=state, read_only=True)
    assert read_only["state_write"] is False
    assert read_only["schema_migrations"] == [1]
    assert read_only["pending_migrations"] == list(range(2, SCHEMA_VERSION + 1))
    after_read_only = migration_status(state)
    assert after_read_only["schema_migrations"] == [1]
    normal = service_doctor(state_dir=state)
    assert normal["state_write"] is True
    assert normal["migrations_applied"] == list(range(2, SCHEMA_VERSION + 1))
    assert normal["schema_migrations"] == list(range(1, SCHEMA_VERSION + 1))


def test_private_state_database_and_sidecar_permissions(tmp_path: Path) -> None:
    state = tmp_path / "state"
    with connect_state(state) as conn:
        conn.execute("INSERT INTO metadata(key, value, updated_at) VALUES ('k', 'v', 'now')")
        conn.commit()
        assert (state / "state.sqlite").stat().st_mode & 0o777 == 0o600
        for sidecar in (state / "state.sqlite-wal", state / "state.sqlite-shm"):
            if sidecar.exists():
                assert sidecar.stat().st_mode & 0o777 == 0o600


def test_existing_permissive_database_tightened_on_writable_open(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    db = state / "state.sqlite"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY)")
        conn.execute("INSERT INTO schema_migrations(version) VALUES (1)")
    db.chmod(0o644)
    with connect_state(state):
        pass
    assert db.stat().st_mode & 0o777 == 0o600


def test_read_only_state_inspection_detects_insecure_permissions_without_chmod(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    db = state / "state.sqlite"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY)")
        conn.execute("INSERT INTO schema_migrations(version) VALUES (1)")
    db.chmod(0o644)
    report = service_doctor(state_dir=state, read_only=True)
    assert report["state_write"] is False
    assert report["permission_issues"] == [
        {"path": str(db), "mode": "0644", "expected_mode": "0600"}
    ]
    assert db.stat().st_mode & 0o777 == 0o644


def test_ledger_file_mode_is_private(tmp_path: Path) -> None:
    state = tmp_path / "state"
    append_record(state, {"schema_version": "test", "value": "ok"})
    assert (state / "ledger.jsonl").stat().st_mode & 0o777 == 0o600


def test_activation_history_read_only_safe_fields_limits_and_missing_db(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing"
    missing_report = activation_history(missing, limit=10)
    assert missing_report["state_write"] is False
    assert missing_report["network_action"] is False
    assert missing_report["activations"] == []
    assert not missing.exists()

    state = tmp_path / "state"
    with connect_state(state) as conn:
        for idx in range(3):
            conn.execute(
                """
                INSERT INTO service_activations(
                    service_type, service_name, expected_owner_did, observed_owner_did,
                    activation_status, request_timestamp, response_status, nonce_used,
                    response_hash, failure_classification
                )
                VALUES ('room', 'd-flop-bench', ?, NULL, 'failed_preflight',
                        '2026-01-01T00:00:00+00:00', 503, NULL, ?, ?)
                """,
                (BENCH_DID, f"secret-response-hash-{idx}", "remote_unavailable"),
            )
        conn.commit()
    history = activation_history(state, limit=2)
    assert history["state_write"] is False
    assert history["network_action"] is False
    assert len(history["activations"]) == 2
    assert [item["id"] for item in history["activations"]] == [3, 2]
    visible = json.dumps(history, sort_keys=True)
    assert "response_hash" not in visible
    assert "secret-response-hash" not in visible
    assert "signature" not in visible
    assert "passphrase" not in visible
    with pytest.raises(SafetyError):
        activation_history(state, limit=0)
    with pytest.raises(SafetyError):
        activation_history(state, limit=101)


def test_cli_smoke_tests_use_temp_state_only(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    target.write_text("ok", encoding="utf-8")
    spec_path = write_json(
        tmp_path / "spec.json",
        spec(tmp_path, [{"adapter": "text_contains", "path": str(target), "text": "ok"}]),
    )
    request_path = write_json(
        tmp_path / "request.json",
        signed_request(sender_key=Ed25519PrivateKey.generate()),
    )
    payload_path = write_json(tmp_path / "payload.json", {"room": "d-flop-bench", "nonce": 1})
    message_path = tmp_path / "message.txt"
    message_path.write_text("FLOP Bench test announcement", encoding="utf-8")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO / "src")
    state = tmp_path / "state"
    commands = [
        [sys.executable, "-m", "flop_bench.cli", "validate-spec", str(spec_path)],
        [sys.executable, "-m", "flop_bench.cli", "doctor", "--state-dir", str(state)],
        [sys.executable, "-m", "flop_bench.cli", "service", "doctor", "--state-dir", str(state)],
        [
            sys.executable,
            "-m",
            "flop_bench.cli",
            "service",
            "doctor",
            "--state-dir",
            str(tmp_path / "read-only-missing"),
            "--read-only",
        ],
        [sys.executable, "-m", "flop_bench.cli", "isolation-check", "--state-dir", str(state)],
        [
            sys.executable,
            "-m",
            "flop_bench.cli",
            "request",
            "inspect",
            str(request_path),
            "--state-dir",
            str(state),
        ],
        [
            sys.executable,
            "-m",
            "flop_bench.cli",
            "request",
            "verify",
            str(request_path),
            "--state-dir",
            str(state),
        ],
        [
            sys.executable,
            "-m",
            "flop_bench.cli",
            "verify",
            str(spec_path),
            "--state-dir",
            str(state),
        ],
        [sys.executable, "-m", "flop_bench.cli", "ledger", "verify", "--state-dir", str(state)],
        [
            sys.executable,
            "-m",
            "flop_bench.cli",
            "technocore",
            "plan-init",
            "--state-dir",
            str(state),
        ],
        [
            sys.executable,
            "-m",
            "flop_bench.cli",
            "post",
            "preview",
            str(message_path),
            "--state-dir",
            str(tmp_path / "preview-missing"),
        ],
        [
            sys.executable,
            "-m",
            "flop_bench.cli",
            "post",
            "history",
            "--state-dir",
            str(tmp_path / "post-history-missing"),
            "--limit",
            "5",
        ],
    ]
    for command in commands:
        completed = subprocess.run(  # noqa: S603 - fixed CLI smoke argv.
            command, cwd=REPO, env=env, text=True, capture_output=True, check=False
        )
        assert completed.returncode == 0, completed.stderr
    evidence_file = next((state / "evidence").glob("*.json"))
    export = subprocess.run(  # noqa: S603 - fixed CLI smoke argv.
        [sys.executable, "-m", "flop_bench.cli", "router-export", str(evidence_file)],
        cwd=REPO,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert export.returncode == 0, export.stderr
    refusal = subprocess.run(  # noqa: S603 - fixed CLI smoke argv.
        [
            sys.executable,
            "-m",
            "flop_bench.cli",
            "identity",
            "create-production",
            "--state-dir",
            str(tmp_path / "no-production-access"),
            "--confirm",
            IDENTITY_CONFIRMATION,
        ],
        cwd=REPO,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert refusal.returncode == 4
    assert "interactive terminal required" in refusal.stderr
    verify_refusal = subprocess.run(  # noqa: S603 - fixed CLI smoke argv.
        [
            sys.executable,
            "-m",
            "flop_bench.cli",
            "identity",
            "verify",
            "--state-dir",
            str(tmp_path / "no-production-access"),
        ],
        cwd=REPO,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert verify_refusal.returncode == 4
    assert "interactive terminal required" in verify_refusal.stderr
    response_refusal = subprocess.run(  # noqa: S603 - fixed CLI smoke argv.
        [
            sys.executable,
            "-m",
            "flop_bench.cli",
            "response",
            "prepare",
            str(evidence_file),
            "--state-dir",
            str(tmp_path / "no-production-access"),
        ],
        cwd=REPO,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert response_refusal.returncode == 4
    dry_run_refusal = subprocess.run(  # noqa: S603 - fixed CLI smoke argv.
        [
            sys.executable,
            "-m",
            "flop_bench.cli",
            "technocore",
            "dry-run-sign",
            str(payload_path),
            "--state-dir",
            str(tmp_path / "no-production-access"),
        ],
        cwd=REPO,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert dry_run_refusal.returncode == 4
    post_send_refusal = subprocess.run(  # noqa: S603 - fixed CLI smoke argv.
        [
            sys.executable,
            "-m",
            "flop_bench.cli",
            "post",
            "send",
            str(message_path),
            "--state-dir",
            str(tmp_path / "no-production-access"),
            "--live",
            "--confirm",
            POST_CONFIRMATION,
        ],
        cwd=REPO,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert post_send_refusal.returncode == 4
    assert "interactive terminal required" in post_send_refusal.stderr
    mailbox_refusal = subprocess.run(  # noqa: S603 - fixed CLI smoke argv.
        [
            sys.executable,
            "-m",
            "flop_bench.cli",
            "technocore",
            "create-mailbox",
            "--state-dir",
            str(tmp_path / "no-production-access"),
            "--live",
            "--confirm",
            CREATE_MAILBOX_CONFIRMATION,
        ],
        cwd=REPO,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert mailbox_refusal.returncode == 4
    assert "MAILBOX_CREATION_NOT_REQUIRED" in mailbox_refusal.stderr
    assert not (tmp_path / "read-only-missing").exists()
    assert not (tmp_path / "preview-missing").exists()
    assert not (tmp_path / "post-history-missing").exists()


def test_local_command_spec_cannot_enable_permission(tmp_path: Path) -> None:
    step = {
        "adapter": "local_command",
        "argv": [sys.executable, "--version"],
        "cwd": str(tmp_path),
        "timeout_seconds": 5,
        "allow_local_exec": True,
    }
    spec_path = write_json(tmp_path / "spec.json", spec(tmp_path, [step], mode="approved-local"))
    with pytest.raises(ValidationError):
        verify_spec(spec_path, state_dir=tmp_path / "state", allow_local_exec=False)


def mailbox_request_text(
    *,
    sender_did: str,
    request_id: str = "mb-req-1",
    target_did: str = BENCH_DID,
    capability: str = "software.testing",
    created_at: str | None = None,
    expires_at: str | None = None,
    extra: dict[str, object] | None = None,
) -> str:
    now = datetime.now(UTC)
    payload: dict[str, object] = {
        "schema_version": MAILBOX_REQUEST_SCHEMA_VERSION,
        "request_id": request_id,
        "sender_did": sender_did,
        "target_did": target_did,
        "requested_capability": capability,
        "hypothesis": "mailbox request stays inert",
        "test_spec": spec(
            Path("mailbox-fixture"),
            [{"adapter": "file_exists", "path": "README.md"}],
        ),
        "created_at": created_at or now.isoformat(),
        "expires_at": expires_at or (now + timedelta(minutes=10)).isoformat(),
        "provenance": {"source": "pytest", "url": "https://example.test/inert"},
    }
    if extra:
        payload.update(extra)
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def literal_equality_spec(actual: object, expected: object) -> dict[str, object]:
    return {"type": "literal_equality", "actual": actual, "expected": expected}


def approved_literal_request(
    tmp_path: Path,
    *,
    request_id: str = "literal-pass",
    actual: object = "ok",
    expected: object = "ok",
    sender: str | None = None,
    expires_at: str | None = None,
    extra: dict[str, object] | None = None,
) -> tuple[Path, str]:
    state = tmp_path / request_id
    with connect_state(state):
        pass
    write_reconciled_did_note_observation(state)
    mailbox_activate(state_dir=state, confirm=MAILBOX_ACTIVATE_CONFIRMATION)
    sender_did = sender or public_did(Ed25519PrivateKey.generate())
    payload_extra: dict[str, object] = {
        "test_spec": literal_equality_spec(actual, expected),
        "provenance": {"source": "pytest-e1"},
    }
    if extra:
        payload_extra.update(extra)
    transport = FakeActivationTransport()
    transport.room_messages["mb-flop-bench"] = [
        {
            "seq": 1,
            "from": sender_did,
            "nonce": 1,
            "text": mailbox_request_text(
                sender_did=sender_did,
                request_id=request_id,
                expires_at=expires_at,
                extra=payload_extra,
            ),
            "ts": "2026-08-31T10:00:00Z",
        }
    ]
    poll_mailbox(state_dir=state, network=True, transport=transport, sleep_on_429=False)
    request_approve(
        state_dir=state,
        request_id=request_id,
        confirm="APPROVE-BENCH-REQUEST",
    )
    return state, sender_did


def write_bench_identity_json(state: Path) -> None:
    state.mkdir(parents=True, exist_ok=True)
    write_json(
        state / "identity.json",
        {
            "schema_version": "flop-bench.identity.v0.1",
            "did": BENCH_DID,
            "purpose": "flop-bench-production",
            "canonical_room": "d-flop-bench",
            "mailbox": "mb-flop-bench",
        },
    )


def write_reconciled_did_note_observation(state: Path) -> None:
    namespace, key, _fingerprint = did_profile_path(BENCH_DID)
    expected_hash = note_hash(identity_note_value(BENCH_DID))
    with connect_state(state) as conn:
        record_did_note_observation(
            conn,
            namespace=namespace,
            key=key,
            expected_hash=expected_hash,
            observed_hash=expected_hash,
            action="reconcile",
            status="already-matching",
            response_status=200,
            failure_classification=None,
        )


def test_mailbox_capability_validation_uses_advertised_service_capabilities() -> None:
    sender = public_did(Ed25519PrivateKey.generate())
    assert BENCH_SERVICE_CAPABILITIES == (
        "software.testing",
        "software.api",
        "software.debugging",
        "technocore.api",
        "technocore.signed_post",
        "technocore.protocol",
        "reproducibility",
        "verification",
    )
    assert tuple(service_manifest()["capabilities"]) == BENCH_SERVICE_CAPABILITIES
    assert SUPPORTED_CAPABILITIES == frozenset({"file-check", "approved-local-command"})
    assert "software.testing" in BENCH_SERVICE_CAPABILITIES
    assert "file-check" not in BENCH_SERVICE_CAPABILITIES
    assert "approved-local-command" not in BENCH_SERVICE_CAPABILITIES
    for capability in BENCH_SERVICE_CAPABILITIES:
        parsed = parse_mailbox_envelope(
            mailbox_request_text(sender_did=sender, capability=capability),
            remote_sender=sender,
        )
        assert parsed["requested_capability"] == capability
    for capability in ("approved-local-command", "file-check", "unknown.capability"):
        with pytest.raises(SafetyError):
            parse_mailbox_envelope(
                mailbox_request_text(sender_did=sender, capability=capability),
                remote_sender=sender,
            )


def test_mailbox_activation_preview_is_pure(tmp_path: Path) -> None:
    state = tmp_path / "missing-state"
    preview = mailbox_activation_preview(state_dir=state)
    assert preview["mailbox"] == "mb-flop-bench"
    assert preview["protocol_version"] == MAILBOX_REQUEST_SCHEMA_VERSION
    assert preview["can_activate"] is False
    assert preview["database_exists"] is False
    assert preview["schema_migrations"] == []
    assert preview["pending_migrations"] == list(range(1, SCHEMA_VERSION + 1))
    assert preview["migration_required"] is True
    assert preview["activation_blockers"] == [
        "state_database_missing",
        "state_schema_migration_required",
        "did_note_advertisement_not_reconciled",
    ]
    assert preview["current_activation"]["activation_status"] == "inactive"
    assert preview["disabled_behaviors"]["network"] is False
    assert preview["disabled_behaviors"]["identity_loading"] is False
    assert preview["disabled_behaviors"]["mailbox_creation"] is False
    assert preview["state_write"] is False
    assert preview["network_action"] is False
    assert preview["will_sign"] is False
    assert preview["will_execute"] is False
    assert not state.exists()


def test_mailbox_activation_preview_pending_activation_migration(tmp_path: Path) -> None:
    state = tmp_path / "state"
    with connect_state(state):
        pass
    write_reconciled_did_note_observation(state)
    db_path = state / STATE_DB
    with sqlite3.connect(db_path) as conn:
        conn.execute("DROP TABLE mailbox_intake_activation")
        conn.execute("DELETE FROM schema_migrations WHERE version >= 8")
        conn.commit()
    before = db_path.read_bytes()
    before_mtime = db_path.stat().st_mtime_ns
    preview = mailbox_activation_preview(state_dir=state)
    assert preview["can_activate"] is False
    assert preview["database_exists"] is True
    assert preview["schema_migrations"] == list(range(1, 8))
    assert preview["pending_migrations"] == list(range(8, SCHEMA_VERSION + 1))
    assert preview["migration_required"] is True
    assert preview["activation_blockers"] == ["state_schema_migration_required"]
    assert preview["advertised"] is True
    assert preview["advertisement_status"] == "already-matching"
    assert preview["current_activation"]["activation_status"] == "inactive"
    assert db_path.read_bytes() == before
    assert db_path.stat().st_mtime_ns == before_mtime


def test_mailbox_activation_preview_fully_migrated_inactive_ready(tmp_path: Path) -> None:
    state = tmp_path / "state"
    with connect_state(state):
        pass
    write_reconciled_did_note_observation(state)
    preview = mailbox_activation_preview(state_dir=state)
    assert preview["can_activate"] is True
    assert preview["activation_blockers"] == []
    assert preview["database_exists"] is True
    assert preview["schema_migrations"] == list(range(1, SCHEMA_VERSION + 1))
    assert preview["pending_migrations"] == []
    assert preview["migration_required"] is False
    assert preview["current_activation"]["activation_status"] == "inactive"


def test_mailbox_activation_preview_already_active(tmp_path: Path) -> None:
    state = tmp_path / "state"
    with connect_state(state):
        pass
    write_reconciled_did_note_observation(state)
    mailbox_activate(state_dir=state, confirm=MAILBOX_ACTIVATE_CONFIRMATION)
    preview = mailbox_activation_preview(state_dir=state)
    assert preview["can_activate"] is True
    assert preview["activation_blockers"] == []
    assert preview["current_activation"]["activation_status"] == "active"
    assert preview["current_activation"]["active"] is True


def test_mailbox_activation_preview_unreconciled_advertisement(tmp_path: Path) -> None:
    state = tmp_path / "state"
    with connect_state(state):
        pass
    preview = mailbox_activation_preview(state_dir=state)
    assert preview["can_activate"] is False
    assert preview["migration_required"] is False
    assert preview["activation_blockers"] == ["did_note_advertisement_not_reconciled"]
    assert preview["advertised"] is None
    assert preview["advertisement_status"] == "unknown_not_reconciled"


def test_mailbox_activation_preview_multiple_blockers(tmp_path: Path) -> None:
    state = tmp_path / "state"
    with connect_state(state):
        pass
    db_path = state / STATE_DB
    with sqlite3.connect(db_path) as conn:
        conn.execute("DROP TABLE mailbox_intake_activation")
        conn.execute("DELETE FROM schema_migrations WHERE version = 8")
        conn.commit()
    preview = mailbox_activation_preview(state_dir=state)
    assert preview["can_activate"] is False
    assert preview["database_exists"] is True
    assert preview["migration_required"] is True
    assert preview["activation_blockers"] == [
        "state_schema_migration_required",
        "did_note_advertisement_not_reconciled",
    ]


def test_mailbox_activation_wrong_confirmation_and_missing_advertisement_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    with connect_state(state) as conn:
        assert [int(row[0]) for row in conn.execute("SELECT version FROM schema_migrations")]
    with pytest.raises(SafetyError):
        mailbox_activate(state_dir=state, confirm="wrong")
    with pytest.raises(SafetyError) as exc:
        mailbox_activate(state_dir=state, confirm=MAILBOX_ACTIVATE_CONFIRMATION)
    assert "DID-note" in str(exc.value)

    def fail_identity_load(*args: object, **kwargs: object) -> object:
        raise AssertionError("activation must not load identity material")

    monkeypatch.setattr("flop_bench.identity.load_production_identity_key", fail_identity_load)
    write_reconciled_did_note_observation(state)
    activated = mailbox_activate(state_dir=state, confirm=MAILBOX_ACTIVATE_CONFIRMATION)
    assert activated["activation_status"] == "active"
    assert activated["network_action"] is False
    assert activated["will_create_mailbox"] is False
    assert activated["will_poll"] is False


def test_mailbox_activation_success_idempotency_private_permissions_and_manifest(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    with connect_state(state):
        pass
    write_reconciled_did_note_observation(state)
    first = mailbox_activate(state_dir=state, confirm=MAILBOX_ACTIVATE_CONFIRMATION)
    second = mailbox_activate(state_dir=state, confirm=MAILBOX_ACTIVATE_CONFIRMATION)
    assert first["activation_status"] == "active"
    assert second["activation_status"] == "active"
    assert second["activated_at"] == first["activated_at"]
    assert first["execution_mode"] == "manual_only"
    assert first["autonomous_polling"] is False
    assert first["autonomous_execution"] is False
    assert first["autonomous_reply"] is False
    assert first["router_updates"] is False
    assert (state / "state.sqlite").stat().st_mode & 0o777 == 0o600
    assert (state / "state.sqlite-wal").stat().st_mode & 0o777 == 0o600
    status = mailbox_status(state_dir=state)
    manifest = service_manifest(state_dir=state)
    assert status["intake_active"] is True
    assert manifest["mailbox"]["active"] is True
    assert manifest["safety"]["requests_accepted"] is True
    assert manifest["safety"]["autonomous_polling"] is False
    assert manifest["safety"]["autonomous_reply"] is False
    assert manifest["safety"]["router_updates"] is False


def test_mailbox_deactivation_preserves_existing_requests_and_blocks_new_intake(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    with connect_state(state):
        pass
    write_reconciled_did_note_observation(state)
    mailbox_activate(state_dir=state, confirm=MAILBOX_ACTIVATE_CONFIRMATION)
    sender = public_did(Ed25519PrivateKey.generate())
    first_transport = FakeActivationTransport()
    first_transport.room_messages["mb-flop-bench"] = [
        {
            "seq": 1,
            "from": sender,
            "nonce": 1,
            "text": mailbox_request_text(sender_did=sender, request_id="active-req"),
        }
    ]
    poll_mailbox(state_dir=state, network=True, transport=first_transport, sleep_on_429=False)
    deactivated = mailbox_deactivate(
        state_dir=state,
        confirm=MAILBOX_DEACTIVATE_CONFIRMATION,
    )
    assert deactivated["activation_status"] == "inactive"
    second_transport = FakeActivationTransport()
    second_transport.room_messages["mb-flop-bench"] = [
        {
            "seq": 2,
            "from": sender,
            "nonce": 2,
            "text": mailbox_request_text(sender_did=sender, request_id="inactive-req"),
        }
    ]
    result = poll_mailbox(state_dir=state, network=True, transport=second_transport)
    assert result["ok"] is True
    messages = mailbox_messages(state_dir=state, limit=10)["messages"]
    by_request = {item["request_id"]: item for item in messages}
    assert by_request["active-req"]["review_status"] == "pending_human_review"
    assert by_request["inactive-req"]["classification"] == "intake_inactive"
    assert by_request["inactive-req"]["review_status"] == "rejected"
    assert request_queue(state_dir=state)["requests"][0]["request_id"] == "active-req"


def test_mailbox_active_request_pending_review_lifecycle_remains_non_executing(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    with connect_state(state):
        pass
    write_reconciled_did_note_observation(state)
    mailbox_activate(state_dir=state, confirm=MAILBOX_ACTIVATE_CONFIRMATION)
    sender = public_did(Ed25519PrivateKey.generate())
    marker = tmp_path / "must-not-exist"
    transport = FakeActivationTransport()
    transport.room_messages["mb-flop-bench"] = [
        {
            "seq": 1,
            "from": sender,
            "nonce": 1,
            "text": mailbox_request_text(
                sender_did=sender,
                request_id="active-lifecycle",
                extra={
                    "test_spec": spec(
                        tmp_path,
                        [
                            {
                                "adapter": "local_command",
                                "argv": [
                                    sys.executable,
                                    "-c",
                                    f"open({str(marker)!r}, 'w').write('bad')",
                                ],
                                "cwd": str(tmp_path),
                            }
                        ],
                        mode="approved-local",
                    )
                },
            ),
        }
    ]
    polled = poll_mailbox(state_dir=state, network=True, transport=transport, sleep_on_429=False)
    approved = request_approve(
        state_dir=state,
        request_id="active-lifecycle",
        confirm="APPROVE-BENCH-REQUEST",
    )
    assert polled["will_sign"] is False
    assert polled["will_post"] is False
    assert polled["will_acquire_nonce"] is False
    assert polled["followed_urls"] is False
    assert polled["executed_remote_content"] is False
    assert approved["will_execute"] is False
    assert approved["will_reply"] is False
    assert approved["will_update_router"] is False
    assert not marker.exists()
    assert all(method == "GET" for method, _url in transport.requests)
    assert transport.post_bodies == []
    assert transport.note_bodies == []


def test_mailbox_schema_and_parser_agree_on_example() -> None:
    schema_file = json.loads((REPO / "schemas" / "mailbox-request-v0.1.json").read_text())
    assert schema_file == MAILBOX_REQUEST_SCHEMA
    sender = public_did(Ed25519PrivateKey.generate())
    payload = json.loads(
        mailbox_request_text(
            sender_did=sender,
            extra={"reply_room": "mb-fictional-replies", "operator_group": None},
        )
    )
    errors = sorted(Draft202012Validator(schema_file).iter_errors(payload), key=str)
    assert errors == []
    parsed = parse_mailbox_envelope(
        json.dumps(payload, separators=(",", ":")),
        remote_sender=sender,
    )
    assert parsed["request_id"] == payload["request_id"]
    bad_payload = {**payload, "extra": True}
    assert list(Draft202012Validator(schema_file).iter_errors(bad_payload))
    with pytest.raises(ValidationError):
        parse_mailbox_envelope(json.dumps(bad_payload, separators=(",", ":")), remote_sender=sender)


def test_mailbox_cli_activation_and_no_autonomous_scheduler(tmp_path: Path) -> None:
    state = tmp_path / "state"
    with connect_state(state):
        pass
    write_reconciled_did_note_observation(state)
    preview = subprocess.run(  # noqa: S603 - fixed CLI smoke argv.
        [
            sys.executable,
            "-m",
            "flop_bench.cli",
            "mailbox",
            "activation-preview",
            "--state-dir",
            str(state),
        ],
        cwd=REPO,
        text=True,
        capture_output=True,
        check=False,
    )
    assert preview.returncode == 0
    parsed_preview = json.loads(preview.stdout)
    assert parsed_preview["state_write"] is False
    activate = subprocess.run(  # noqa: S603 - fixed CLI smoke argv.
        [
            sys.executable,
            "-m",
            "flop_bench.cli",
            "mailbox",
            "activate",
            "--state-dir",
            str(state),
            "--confirm",
            MAILBOX_ACTIVATE_CONFIRMATION,
        ],
        cwd=REPO,
        text=True,
        capture_output=True,
        check=False,
    )
    assert activate.returncode == 0
    parsed_activate = json.loads(activate.stdout)
    assert parsed_activate["autonomous_scheduler"] is False
    assert parsed_activate["will_poll"] is False


def test_mailbox_service_capability_does_not_authorize_actions(tmp_path: Path) -> None:
    state = tmp_path / "state"
    with connect_state(state):
        pass
    write_reconciled_did_note_observation(state)
    mailbox_activate(state_dir=state, confirm=MAILBOX_ACTIVATE_CONFIRMATION)
    sender = public_did(Ed25519PrivateKey.generate())
    marker = tmp_path / "must-not-exist"
    transport = FakeActivationTransport()
    transport.room_messages["mb-flop-bench"] = [
        {
            "seq": 1,
            "from": sender,
            "nonce": 1,
            "text": mailbox_request_text(
                sender_did=sender,
                capability="software.testing",
                extra={
                    "test_spec": spec(
                        tmp_path,
                        [
                            {
                                "adapter": "local_command",
                                "argv": [
                                    sys.executable,
                                    "-c",
                                    f"open({str(marker)!r}, 'w').write('bad')",
                                ],
                                "cwd": str(tmp_path),
                                "timeout_seconds": 5,
                            }
                        ],
                        mode="approved-local",
                    )
                },
            ),
        }
    ]
    result = poll_mailbox(
        state_dir=state,
        network=True,
        transport=transport,
        sleep_on_429=False,
    )
    queued = request_queue(state_dir=state)
    assert result["network_action"] == "bounded_read_only"
    assert result["will_sign"] is False
    assert result["will_post"] is False
    assert result["will_acquire_nonce"] is False
    assert queued["requests"][0]["review_status"] == "pending_human_review"
    assert not marker.exists()
    assert all(method == "GET" for method, _url in transport.requests)


def framed_note(value: str) -> str:
    return f"{NOTE_RESPONSE_BANNER}\n\n{value}"


def test_mailbox_status_and_local_poll_are_local_only(tmp_path: Path) -> None:
    state = tmp_path / "state"
    status = mailbox_status(state_dir=state)
    poll = poll_mailbox(state_dir=state, network=False, transport=FakeActivationTransport())
    assert status["protocol"] == "signed-write-only-room"
    assert status["creation_required"] is False
    assert status["advertised"] is None
    assert status["advertisement_status"] == "unknown_not_reconciled"
    assert status["network_action"] is False
    assert poll["poll_status"] == "local_only"
    assert poll["will_sign"] is False
    assert poll["will_post"] is False
    assert poll["will_acquire_nonce"] is False
    assert not state.exists()


def test_mailbox_unused_404_and_empty_mailbox_advance_safely(tmp_path: Path) -> None:
    state = tmp_path / "state"
    not_found = FakeActivationTransport()
    not_found.room_history_statuses = [404]
    missing = poll_mailbox(
        state_dir=state,
        network=True,
        transport=not_found,
        sleep_on_429=False,
    )
    assert missing["ok"] is True
    assert missing["cursor_after"] == 0
    assert missing["inserted"] == 0
    empty = poll_mailbox(
        state_dir=state,
        network=True,
        transport=FakeActivationTransport(),
        sleep_on_429=False,
    )
    assert empty["history_scan_complete"] is True
    assert empty["cursor_after"] == 0


def test_mailbox_canonical_parsing_authentication_and_pending_review(tmp_path: Path) -> None:
    state = tmp_path / "state"
    with connect_state(state):
        pass
    write_reconciled_did_note_observation(state)
    mailbox_activate(state_dir=state, confirm=MAILBOX_ACTIVATE_CONFIRMATION)
    sender = public_did(Ed25519PrivateKey.generate())
    text = mailbox_request_text(sender_did=sender)
    transport = FakeActivationTransport()
    transport.room_messages["mb-flop-bench"] = [
        {"seq": 1, "from": sender, "nonce": 123, "text": text, "ts": "2026-08-31T10:00:00Z"}
    ]
    assert classify_authentication(transport.room_messages["mb-flop-bench"][0])[0] == (
        "server_verified_signed_lane"
    )
    string_nonce = {"seq": 2, "from": sender, "nonce": "124", "text": text}
    assert classify_authentication(string_nonce)[0] == "malformed_or_unverifiable"
    parsed = parse_mailbox_envelope(text, remote_sender=sender)
    assert parsed["request_id"] == "mb-req-1"
    result = poll_mailbox(
        state_dir=state,
        network=True,
        transport=transport,
        sleep_on_429=False,
    )
    assert result["ok"] is True
    assert result["cursor_after"] == 1
    assert result["inserted"] == 1
    queue = request_queue(state_dir=state)
    assert queue["requests"][0]["review_status"] == "pending_human_review"
    inspected = mailbox_inspect(state_dir=state, message_id="mb-flop-bench:1")
    assert inspected["sender_did"] == sender
    assert inspected["nonce"] == 123
    assert inspected["remote_text_is_untrusted"] is True
    assert inspected["urls_followed"] is False


def test_mailbox_nonce_storage_preserves_19_digit_decimal_text(tmp_path: Path) -> None:
    state = tmp_path / "state"
    sender = public_did(Ed25519PrivateKey.generate())
    edge_nonces = [
        9_223_372_036_854_775_807,
        9_223_372_036_854_775_808,
        9_999_999_999_999_999_999,
    ]
    transport = FakeActivationTransport()
    transport.room_messages["mb-flop-bench"] = [
        {
            "seq": idx,
            "from": sender,
            "nonce": nonce,
            "text": mailbox_request_text(sender_did=sender, request_id=f"nonce-edge-{idx}"),
        }
        for idx, nonce in enumerate(edge_nonces, start=1)
    ]
    result = poll_mailbox(
        state_dir=state,
        network=True,
        transport=transport,
        sleep_on_429=False,
    )
    assert result["ok"] is True
    messages = mailbox_messages(state_dir=state, limit=10)["messages"]
    by_seq = {item["seq"]: item for item in messages}
    assert by_seq[1]["nonce"] == edge_nonces[0]
    assert by_seq[1]["nonce_decimal"] == str(edge_nonces[0])
    assert by_seq[2]["nonce"] == str(edge_nonces[1])
    assert by_seq[2]["nonce_decimal"] == str(edge_nonces[1])
    assert by_seq[3]["nonce"] == str(edge_nonces[2])
    assert by_seq[3]["nonce_decimal"] == "9999999999999999999"
    inspected = mailbox_inspect(state_dir=state, message_id="mb-flop-bench:3")
    assert inspected["nonce"] == "9999999999999999999"
    assert inspected["nonce_decimal"] == "9999999999999999999"
    with sqlite3.connect(state / "state.sqlite") as conn:
        conn.row_factory = sqlite3.Row
        rows = list(
            conn.execute("SELECT seq, nonce, nonce_text FROM mailbox_messages ORDER BY seq")
        )
    assert rows[0]["nonce"] == edge_nonces[0]
    assert rows[0]["nonce_text"] == str(edge_nonces[0])
    assert rows[1]["nonce"] is None
    assert rows[1]["nonce_text"] == str(edge_nonces[1])
    assert rows[2]["nonce"] is None
    assert rows[2]["nonce_text"] == "9999999999999999999"


def test_mailbox_malformed_and_oversized_nonce_do_not_abort_poll(tmp_path: Path) -> None:
    state = tmp_path / "state"
    sender = public_did(Ed25519PrivateKey.generate())
    text = mailbox_request_text(sender_did=sender)
    bad_nonces: list[object] = [
        False,
        0,
        -1,
        1.0,
        "1",
        "+1",
        " 1",
        "01",
        10_000_000_000_000_000_000,
    ]
    transport = FakeActivationTransport()
    transport.room_messages["mb-flop-bench"] = [
        {"seq": idx, "from": sender, "nonce": nonce, "text": text}
        for idx, nonce in enumerate(bad_nonces, start=1)
    ]
    result = poll_mailbox(
        state_dir=state,
        network=True,
        transport=transport,
        sleep_on_429=False,
    )
    assert result["ok"] is True
    assert result["cursor_after"] == len(bad_nonces)
    assert result["inserted"] == len(bad_nonces)
    messages = mailbox_messages(state_dir=state, limit=20)["messages"]
    assert {item["authentication_level"] for item in messages} == {"malformed_or_unverifiable"}
    assert {item["classification"] for item in messages} == {"malformed_or_unverifiable"}
    assert all(item["review_status"] == "rejected" for item in messages)
    assert all(item["nonce"] is None for item in messages)
    assert all("nonce_decimal" not in item for item in messages)


def test_mailbox_nonce_migration_dedup_and_inspection_preserve_integer_records(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    db_path = state / "state.sqlite"
    sender = public_did(Ed25519PrivateKey.generate())
    with sqlite3.connect(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY);
            INSERT INTO schema_migrations(version) VALUES (1),(2),(3),(4),(5),(6);
            CREATE TABLE metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE mailbox_messages (
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
            CREATE UNIQUE INDEX idx_mailbox_messages_request_id
                ON mailbox_messages(request_id)
                WHERE request_id IS NOT NULL;
            """
        )
        conn.execute(
            """
            INSERT INTO mailbox_messages(
                message_id, room, seq, sender_did, nonce, message_hash,
                untrusted_text, remote_ts, authentication_level, request_id,
                requested_capability, classification, review_status,
                received_at, expires_at, provenance_json, evidence_id, result_link
            )
            VALUES (?, 'mb-flop-bench', 1, ?, 123, ?, '{}', NULL,
                    'server_verified_signed_lane', 'legacy-req', 'software.testing',
                    'valid_request', 'pending_human_review', ?, NULL, NULL, NULL, NULL)
            """,
            ("mb-flop-bench:1", sender, message_hash("{}"), datetime.now(UTC).isoformat()),
        )
        conn.execute(
            """
            INSERT INTO metadata(key, value, updated_at)
            VALUES ('mailbox:mb-flop-bench:cursor', '1', ?)
            """,
            (datetime.now(UTC).isoformat(),),
        )
        conn.commit()

    with connect_state(state) as conn:
        first_applied = [
            int(row[0]) for row in conn.execute("SELECT version FROM schema_migrations")
        ]
    with connect_state(state) as conn:
        second_applied = [
            int(row[0]) for row in conn.execute("SELECT version FROM schema_migrations")
        ]
    assert first_applied == second_applied
    assert 7 in first_applied

    history = mailbox_messages(state_dir=state, limit=10)["messages"]
    assert history[0]["nonce"] == 123
    assert history[0]["nonce_decimal"] == "123"
    inspected = mailbox_inspect(state_dir=state, message_id="mb-flop-bench:1")
    assert inspected["nonce"] == 123
    assert inspected["nonce_decimal"] == "123"

    transport = FakeActivationTransport()
    transport.room_messages["mb-flop-bench"] = [
        {
            "seq": 2,
            "from": sender,
            "nonce": 9_999_999_999_999_999_999,
            "text": mailbox_request_text(sender_did=sender, request_id="legacy-req"),
        },
        {
            "seq": 3,
            "from": sender,
            "nonce": 9_999_999_999_999_999_999,
            "text": mailbox_request_text(sender_did=sender, request_id="fresh-req"),
        },
    ]
    result = poll_mailbox(
        state_dir=state,
        network=True,
        transport=transport,
        sleep_on_429=False,
    )
    assert result["ok"] is True
    assert result["cursor_before"] == 1
    assert result["cursor_after"] == 3
    assert result["inserted"] == 2
    assert result["duplicate_request_ids"] == 1
    inspected_huge = mailbox_inspect(state_dir=state, message_id="mb-flop-bench:3")
    assert inspected_huge["nonce"] == "9999999999999999999"
    assert inspected_huge["nonce_decimal"] == "9999999999999999999"


def test_mailbox_nonce_handling_never_uses_float_rounding(tmp_path: Path) -> None:
    state = tmp_path / "state"
    with connect_state(state):
        pass
    write_reconciled_did_note_observation(state)
    mailbox_activate(state_dir=state, confirm=MAILBOX_ACTIVATE_CONFIRMATION)
    sender = public_did(Ed25519PrivateKey.generate())
    precise = 9_999_999_999_999_999_999
    transport = FakeActivationTransport()
    transport.room_messages["mb-flop-bench"] = [
        {
            "seq": 1,
            "from": sender,
            "nonce": precise,
            "text": mailbox_request_text(sender_did=sender, request_id="precise-int"),
        },
        {
            "seq": 2,
            "from": sender,
            "nonce": float(precise),
            "text": mailbox_request_text(sender_did=sender, request_id="rounded-float"),
        },
    ]
    result = poll_mailbox(
        state_dir=state,
        network=True,
        transport=transport,
        sleep_on_429=False,
    )
    assert result["ok"] is True
    first = mailbox_inspect(state_dir=state, message_id="mb-flop-bench:1")
    second = mailbox_inspect(state_dir=state, message_id="mb-flop-bench:2")
    assert first["nonce_decimal"] == "9999999999999999999"
    assert first["classification"] == "valid_request"
    assert "nonce_decimal" not in second
    assert second["classification"] == "malformed_or_unverifiable"
    assert second["review_status"] == "rejected"


def test_mailbox_poll_pagination_duplicates_and_request_id_replay(tmp_path: Path) -> None:
    state = tmp_path / "state"
    sender = public_did(Ed25519PrivateKey.generate())
    transport = FakeActivationTransport()
    transport.room_messages["mb-flop-bench"] = [
        {
            "seq": 1,
            "from": sender,
            "nonce": 1,
            "text": mailbox_request_text(sender_did=sender, request_id="req-a"),
        },
        {
            "seq": 2,
            "from": sender,
            "nonce": 2,
            "text": mailbox_request_text(sender_did=sender, request_id="req-b"),
        },
        {
            "seq": 3,
            "from": sender,
            "nonce": 3,
            "text": mailbox_request_text(sender_did=sender, request_id="req-b"),
        },
    ]
    first = poll_mailbox(
        state_dir=state,
        network=True,
        transport=transport,
        page_limit=2,
        sleep_on_429=False,
    )
    second = poll_mailbox(
        state_dir=state,
        network=True,
        transport=transport,
        page_limit=2,
        sleep_on_429=False,
    )
    assert first["pages_scanned"] == 2
    assert first["cursor_after"] == 3
    assert first["inserted"] == 3
    assert first["duplicate_request_ids"] == 1
    assert second["inserted"] == 0
    assert second["cursor_before"] == 3
    messages = mailbox_messages(state_dir=state, limit=10)["messages"]
    assert len(messages) == 3


def test_mailbox_failures_preserve_cursor_and_do_not_store_partial(tmp_path: Path) -> None:
    sender = public_did(Ed25519PrivateKey.generate())
    for status in (429, 503):
        state = tmp_path / f"state-{status}"
        transport = FakeActivationTransport()
        transport.room_history_statuses = [status, status]
        result = poll_mailbox(
            state_dir=state,
            network=True,
            transport=transport,
            sleep_on_429=False,
        )
        assert result["ok"] is False
        assert result["cursor_after"] == 0
        assert mailbox_messages(state_dir=state, limit=10)["messages"] == []
    malformed = FakeActivationTransport()
    malformed.room_messages["mb-flop-bench"] = [{"seq": 1, "from": sender, "nonce": 1}]
    bad = poll_mailbox(
        state_dir=tmp_path / "malformed",
        network=True,
        transport=malformed,
        sleep_on_429=False,
    )
    assert bad["ok"] is False
    assert bad["cursor_after"] == 0
    gap = FakeActivationTransport()
    gap.room_messages["mb-flop-bench"] = [
        {"seq": 2, "from": sender, "nonce": 2, "text": mailbox_request_text(sender_did=sender)}
    ]
    gap_result = poll_mailbox(
        state_dir=tmp_path / "gap",
        network=True,
        transport=gap,
        sleep_on_429=False,
    )
    assert gap_result["failure_classification"] == "sequence_gap"
    assert gap_result["cursor_after"] == 0


def test_mailbox_envelope_rejections_and_inert_urls_code(tmp_path: Path) -> None:
    sender = public_did(Ed25519PrivateKey.generate())
    now = datetime.now(UTC)
    cases = [
        mailbox_request_text(sender_did=sender, target_did=SCOUT_DID),
        mailbox_request_text(sender_did=sender, capability="wallet-transfer"),
        mailbox_request_text(
            sender_did=sender,
            created_at=(now + timedelta(minutes=6)).isoformat(),
        ),
        mailbox_request_text(
            sender_did=sender,
            expires_at=(now - timedelta(seconds=1)).isoformat(),
        ),
        mailbox_request_text(sender_did=sender, extra={"unexpected": True}),
        "{not-json",
        mailbox_request_text(sender_did=sender).replace(
            sender,
            public_did(Ed25519PrivateKey.generate()),
        ),
    ]
    transport = FakeActivationTransport()
    transport.room_messages["mb-flop-bench"] = [
        {"seq": idx + 1, "from": sender, "nonce": idx + 1, "text": text}
        for idx, text in enumerate(cases)
    ]
    result = poll_mailbox(
        state_dir=tmp_path / "state",
        network=True,
        transport=transport,
        sleep_on_429=False,
    )
    assert result["ok"] is True
    stored = mailbox_messages(state_dir=tmp_path / "state", limit=20)["messages"]
    assert all(item["review_status"] == "rejected" for item in stored)
    assert all(item["classification"] != "valid_request" for item in stored)
    visible = json.dumps(stored, sort_keys=True)
    assert "https://example.test/inert" not in visible


def test_mailbox_unverified_from_is_not_treated_as_signed_lane(tmp_path: Path) -> None:
    transport = FakeActivationTransport()
    transport.room_messages["mb-flop-bench"] = [
        {"seq": 1, "from": "nickname", "nonce": 1, "text": "{}"},
        {"seq": 2, "did": BENCH_DID, "nonce": 2, "text": "{}"},
    ]
    result = poll_mailbox(
        state_dir=tmp_path / "state",
        network=True,
        transport=transport,
        sleep_on_429=False,
    )
    assert result["ok"] is True
    messages = mailbox_messages(state_dir=tmp_path / "state", limit=10)["messages"]
    assert {item["authentication_level"] for item in messages} == {"malformed_or_unverifiable"}


def test_request_approval_and_rejection_are_local_status_only(tmp_path: Path) -> None:
    state = tmp_path / "state"
    with connect_state(state):
        pass
    write_reconciled_did_note_observation(state)
    mailbox_activate(state_dir=state, confirm=MAILBOX_ACTIVATE_CONFIRMATION)
    sender = public_did(Ed25519PrivateKey.generate())
    transport = FakeActivationTransport()
    transport.room_messages["mb-flop-bench"] = [
        {
            "seq": 1,
            "from": sender,
            "nonce": 1,
            "text": mailbox_request_text(sender_did=sender, request_id="approve-me"),
        },
        {
            "seq": 2,
            "from": sender,
            "nonce": 2,
            "text": mailbox_request_text(sender_did=sender, request_id="reject-me"),
        },
    ]
    poll_mailbox(state_dir=state, network=True, transport=transport, sleep_on_429=False)
    shown = request_show(state_dir=state, request_id="approve-me")
    approved = request_approve(
        state_dir=state,
        request_id="approve-me",
        confirm="APPROVE-BENCH-REQUEST",
    )
    rejected = request_reject(state_dir=state, request_id="reject-me", reason="not needed")
    assert shown["will_execute"] is False
    assert approved["review_status"] == "approved_for_manual_execution"
    assert approved["will_execute"] is False
    assert approved["will_post"] is False
    assert approved["will_update_router"] is False
    assert rejected["review_status"] == "rejected"


def test_execution_preview_is_pure_and_reports_missing_state(tmp_path: Path) -> None:
    state = tmp_path / "missing-state"
    preview = execution_preview(state_dir=state, request_id="missing")
    assert preview["eligible"] is False
    assert preview["blockers"] == ["state_database_missing"]
    assert preview["state_write"] is False
    assert preview["network_action"] is False
    assert preview["will_load_private_key"] is False
    assert preview["will_sign"] is False
    assert preview["will_post"] is False
    assert not state.exists()


def test_execution_preview_reports_metadata_without_raw_serialized_payloads(
    tmp_path: Path,
) -> None:
    state, _sender = approved_literal_request(tmp_path, request_id="preview-metadata-e1")
    preview = execution_preview(state_dir=state, request_id="preview-metadata-e1")
    assert preview["eligible"] is True
    assert "request" not in preview
    assert "request_envelope" not in preview
    metadata = preview["request_metadata"]
    assert metadata["request_id"] == "preview-metadata-e1"
    assert metadata["requested_capability"] == "software.testing"
    assert metadata["has_canonical_request_payload"] is True
    assert metadata["has_provenance"] is True
    assert "request_json" not in metadata
    assert "provenance_json" not in metadata
    assert metadata["canonical_request"]["request_id"] == "preview-metadata-e1"
    assert metadata["canonical_request"]["test_spec_sha256"] == message_hash(
        json.dumps(literal_equality_spec("ok", "ok"), separators=(",", ":"), sort_keys=True)
    )
    assert preview["state_write"] is False
    assert preview["network_action"] is False


def test_execution_preview_reports_pending_migration_expiration_and_legacy_payload(
    tmp_path: Path,
) -> None:
    expires_at = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    state, _sender = approved_literal_request(tmp_path, request_id="legacy-expired-e1")
    db_path = state / STATE_DB
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE mailbox_messages SET expires_at = ?, request_json = NULL WHERE request_id = ?",
            (expires_at, "legacy-expired-e1"),
        )
        conn.execute("DELETE FROM schema_migrations WHERE version = 9")
        conn.commit()
    before = db_path.read_bytes()
    before_mtime = db_path.stat().st_mtime_ns

    preview = execution_preview(state_dir=state, request_id="legacy-expired-e1")

    assert preview["eligible"] is False
    assert preview["database_exists"] is True
    assert preview["pending_migrations"] == [9]
    assert preview["migration_required"] is True
    assert "state_schema_migration_required" in preview["blockers"]
    assert "request_expired" in preview["blockers"]
    assert "canonical_request_payload_unavailable" in preview["blockers"]
    assert preview["request_metadata"]["has_canonical_request_payload"] is False
    assert "canonical_request" not in preview["request_metadata"]
    assert preview["will_execute"] is False
    assert db_path.read_bytes() == before
    assert db_path.stat().st_mtime_ns == before_mtime
    with pytest.raises(SafetyError):
        execute_passive(
            state_dir=state,
            request_id="legacy-expired-e1",
            confirm=EXECUTE_PASSIVE_CONFIRMATION,
        )


def test_execute_passive_requires_active_intake_approval_and_unexpired_request(
    tmp_path: Path,
) -> None:
    state, _sender = approved_literal_request(tmp_path, request_id="deactivate-before-exec")
    mailbox_deactivate(state_dir=state, confirm=MAILBOX_DEACTIVATE_CONFIRMATION)
    preview = execution_preview(state_dir=state, request_id="deactivate-before-exec")
    assert "mailbox_intake_inactive" in preview["blockers"]
    with pytest.raises(SafetyError):
        execute_passive(
            state_dir=state,
            request_id="deactivate-before-exec",
            confirm=EXECUTE_PASSIVE_CONFIRMATION,
        )

    pending_state = tmp_path / "pending"
    with connect_state(pending_state):
        pass
    write_reconciled_did_note_observation(pending_state)
    mailbox_activate(state_dir=pending_state, confirm=MAILBOX_ACTIVATE_CONFIRMATION)
    sender = public_did(Ed25519PrivateKey.generate())
    transport = FakeActivationTransport()
    transport.room_messages["mb-flop-bench"] = [
        {
            "seq": 1,
            "from": sender,
            "nonce": 1,
            "text": mailbox_request_text(
                sender_did=sender,
                request_id="pending-e1",
                extra={"test_spec": literal_equality_spec(1, 1)},
            ),
        }
    ]
    poll_mailbox(state_dir=pending_state, network=True, transport=transport, sleep_on_429=False)
    assert (
        "request_not_approved_for_manual_execution"
        in execution_preview(
            state_dir=pending_state,
            request_id="pending-e1",
        )["blockers"]
    )

    expired_at = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    expired_state = tmp_path / "expired"
    with connect_state(expired_state):
        pass
    write_reconciled_did_note_observation(expired_state)
    mailbox_activate(state_dir=expired_state, confirm=MAILBOX_ACTIVATE_CONFIRMATION)
    expired_sender = public_did(Ed25519PrivateKey.generate())
    with connect_state(expired_state) as conn:
        conn.execute(
            """
            INSERT INTO mailbox_messages(
                message_id, room, seq, sender_did, nonce, nonce_text, message_hash,
                untrusted_text, remote_ts, authentication_level, request_id,
                requested_capability, classification, review_status, received_at,
                expires_at, provenance_json, evidence_id, result_link, request_json
            )
            VALUES (?, 'mb-flop-bench', 1, ?, 1, '1', ?, '{}', NULL,
                    'server_verified_signed_lane', 'BENCH-FIXTURE-20260831T155341Z',
                    'software.testing', 'valid_request',
                    'approved_for_manual_execution', ?, ?, '{}', NULL, NULL, ?)
            """,
            (
                "mb-flop-bench:1",
                expired_sender,
                message_hash("{}"),
                datetime.now(UTC).isoformat(),
                expired_at,
                json.dumps(
                    {
                        "schema_version": MAILBOX_REQUEST_SCHEMA_VERSION,
                        "request_id": "BENCH-FIXTURE-20260831T155341Z",
                        "sender_did": expired_sender,
                        "target_did": BENCH_DID,
                        "requested_capability": "software.testing",
                        "hypothesis": "expired fixture must not execute",
                        "test_spec": literal_equality_spec(True, True),
                        "created_at": "2026-08-31T15:53:41+00:00",
                        "expires_at": expired_at,
                        "provenance": {"source": "expired-fixture"},
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            ),
        )
        conn.commit()
    expired_preview = execution_preview(
        state_dir=expired_state,
        request_id="BENCH-FIXTURE-20260831T155341Z",
    )
    assert "request_expired" in expired_preview["blockers"]
    with pytest.raises(SafetyError):
        execute_passive(
            state_dir=expired_state,
            request_id="BENCH-FIXTURE-20260831T155341Z",
            confirm=EXECUTE_PASSIVE_CONFIRMATION,
        )
    assert execution_history(state_dir=expired_state, limit=10)["executions"] == []


def test_literal_equality_pass_fail_strict_type_and_inert_strings(tmp_path: Path) -> None:
    pass_state, _sender = approved_literal_request(
        tmp_path,
        request_id="literal-pass-e1",
        actual="https://example.test/ignored; rm -rf /",
        expected="https://example.test/ignored; rm -rf /",
    )
    with pytest.raises(SafetyError):
        execute_passive(state_dir=pass_state, request_id="literal-pass-e1", confirm="WRONG")
    passed = execute_passive(
        state_dir=pass_state,
        request_id="literal-pass-e1",
        confirm=EXECUTE_PASSIVE_CONFIRMATION,
    )
    assert passed["evidence"]["verdict"] == "PASS"
    evidence = json.loads(Path(passed["execution"]["evidence_path"]).read_text(encoding="utf-8"))
    assert evidence["safety_report"]["code_executed"] is False
    assert evidence["safety_report"]["urls_followed"] is False
    assert evidence["safety_report"]["network_action"] is False
    assert evidence["safety_report"]["confirmation_phrase_stored"] is False
    assert evidence["provenance"]["common_control_disclosure"] is True
    assert evidence["provenance"]["independent_evidence"] is False
    Draft202012Validator(EVIDENCE_BUNDLE_SCHEMA).validate(evidence)

    fail_state, _sender = approved_literal_request(
        tmp_path,
        request_id="literal-fail-e1",
        actual=1,
        expected=True,
    )
    failed = execute_passive(
        state_dir=fail_state,
        request_id="literal-fail-e1",
        confirm=EXECUTE_PASSIVE_CONFIRMATION,
    )
    assert failed["evidence"]["verdict"] == "FAIL"
    fail_evidence = json.loads(
        Path(failed["execution"]["evidence_path"]).read_text(encoding="utf-8")
    )
    assert fail_evidence["observations"][0]["actual_type"] == "integer"
    assert fail_evidence["observations"][0]["expected_type"] == "boolean"
    assert fail_evidence["observations"][0]["pass"] is False


def test_execution_rejects_malformed_unsupported_multiple_and_unbounded_specs(
    tmp_path: Path,
) -> None:
    cases = [
        ("malformed", {"actual": 1, "expected": 1}, "literal_equality"),
        ("unsupported", {"type": "file_check", "actual": 1, "expected": 1}, "unsupported"),
        (
            "multiple",
            {
                "procedure": [
                    literal_equality_spec(1, 1),
                    literal_equality_spec(2, 2),
                ]
            },
            "multiple remote procedures",
        ),
        ("unbounded", literal_equality_spec("x" * 600, "x" * 600), "exceeds"),
    ]
    for request_id, test_spec, expected_error in cases:
        state, _sender = approved_literal_request(
            tmp_path,
            request_id=f"{request_id}-e1",
            extra={"test_spec": test_spec},
        )
        preview = execution_preview(state_dir=state, request_id=f"{request_id}-e1")
        assert preview["eligible"] is False
        assert any(expected_error in blocker for blocker in preview["blockers"])
        with pytest.raises(SafetyError):
            execute_passive(
                state_dir=state,
                request_id=f"{request_id}-e1",
                confirm=EXECUTE_PASSIVE_CONFIRMATION,
            )


def test_execute_passive_atomic_idempotent_and_interrupted_reservation_visible(
    tmp_path: Path,
) -> None:
    state, _sender = approved_literal_request(tmp_path, request_id="race-e1")
    barrier = threading.Barrier(4)
    results: list[dict[str, object]] = []
    lock = threading.Lock()

    def worker() -> None:
        barrier.wait()
        try:
            result = execute_passive(
                state_dir=state,
                request_id="race-e1",
                confirm=EXECUTE_PASSIVE_CONFIRMATION,
            )
            value = {
                "ok": True,
                "execution_status": result["execution"]["execution_status"],
                "execution_performed": result["execution_performed"],
                "evidence_id": result.get("evidence", {}).get("evidence_id"),
            }
        except SafetyError as exc:
            value = {"ok": False, "error": str(exc)}
        with lock:
            results.append(value)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    performed = [item for item in results if item.get("execution_performed") is True]
    assert len(performed) == 1
    assert performed[0]["execution_status"] == "completed"
    assert all(
        item.get("execution_performed") is False
        or item.get("execution_status") == "completed"
        or "execution_reserved_or_running" in str(item.get("error", ""))
        or "reserved/running" in str(item.get("error", ""))
        for item in results
    )
    second = execute_passive(
        state_dir=state,
        request_id="race-e1",
        confirm=EXECUTE_PASSIVE_CONFIRMATION,
    )
    assert second["idempotent"] is True
    assert second["execution_performed"] is False
    assert second["execution"]["execution_status"] == "completed"
    history = execution_history(state_dir=state, limit=10)["executions"]
    assert len(history) == 1
    assert history[0]["execution_status"] == "completed"
    evidence_files = sorted((state / "evidence").glob("*.json"))
    assert len(evidence_files) == 1
    ledger_lines = (state / "ledger.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(ledger_lines) == 1

    interrupted_state, _sender = approved_literal_request(tmp_path, request_id="interrupted-e1")
    with connect_state(interrupted_state) as conn:
        conn.execute(
            """
            INSERT INTO mailbox_request_executions(
                request_id, execution_status, reserved_at, updated_at,
                confirmation_recorded
            )
            VALUES ('interrupted-e1', 'reserved', ?, ?, 1)
            """,
            (datetime.now(UTC).isoformat(), datetime.now(UTC).isoformat()),
        )
        conn.commit()
    interrupted = execution_preview(state_dir=interrupted_state, request_id="interrupted-e1")
    assert "execution_reserved_or_running" in interrupted["blockers"]
    with pytest.raises(SafetyError):
        execute_passive(
            state_dir=interrupted_state,
            request_id="interrupted-e1",
            confirm=EXECUTE_PASSIVE_CONFIRMATION,
        )


def test_result_preview_schema_purity_and_requires_completed_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, sender = approved_literal_request(
        tmp_path,
        request_id="result-preview-e1",
        extra={"reply_room": "mb-fictional-replies"},
    )
    with pytest.raises(SafetyError):
        result_preview(state_dir=state, request_id="result-preview-e1")

    def fail_identity_load(*args: object, **kwargs: object) -> object:
        raise AssertionError("result preview must not load identity")

    def fail_transport(*args: object, **kwargs: object) -> object:
        raise AssertionError("result preview must not use network libraries")

    monkeypatch.setattr("flop_bench.identity.load_production_identity_key", fail_identity_load)
    monkeypatch.setattr("urllib.request.urlopen", fail_transport)
    executed = execute_passive(
        state_dir=state,
        request_id="result-preview-e1",
        confirm=EXECUTE_PASSIVE_CONFIRMATION,
    )
    before_history = execution_history(state_dir=state, limit=10)
    before_ledger = (state / "ledger.jsonl").read_text(encoding="utf-8")
    preview = result_preview(state_dir=state, request_id="result-preview-e1")
    after_history = execution_history(state_dir=state, limit=10)
    after_ledger = (state / "ledger.jsonl").read_text(encoding="utf-8")
    assert preview["schema_version"] == "flop-bench.mailbox-result.v0.1"
    assert preview["request_id"] == "result-preview-e1"
    assert preview["evidence_id"] == executed["evidence"]["evidence_id"]
    assert preview["verdict"] == "PASS"
    assert preview["bench_did"] == BENCH_DID
    assert preview["original_sender_did"] == sender
    assert preview["reply_room"] == "mb-fictional-replies"
    assert preview["result_delivery_status"] == "not_sent"
    assert preview["state_write"] is False
    assert preview["network_action"] is False
    assert preview["will_sign"] is False
    assert preview["will_reply"] is False
    assert preview["will_update_router"] is False
    assert after_history == before_history
    assert after_ledger == before_ledger
    Draft202012Validator(MAILBOX_RESULT_SCHEMA).validate(preview)


def completed_result_request(
    tmp_path: Path,
    *,
    request_id: str = "result-delivery-e2",
    reply_room: str = "mb-result-replies",
) -> tuple[Path, str]:
    state, sender = approved_literal_request(
        tmp_path,
        request_id=request_id,
        extra={"reply_room": reply_room},
    )
    execute_passive(
        state_dir=state,
        request_id=request_id,
        confirm=EXECUTE_PASSIVE_CONFIRMATION,
    )
    return state, sender


def add_identity_to_state(state: Path) -> tuple[str, str]:
    passphrase = strong_test_phrase()
    metadata = create_production_identity(
        state_dir=state,
        confirm=IDENTITY_CONFIRMATION,
        passphrase=passphrase,
        passphrase_confirmation=passphrase,
        expected_state_dir=state,
    )
    return passphrase, str(metadata["did"])


def test_result_delivery_preview_is_pure_and_canonical(tmp_path: Path) -> None:
    state, sender = completed_result_request(tmp_path)
    before_db = (state / STATE_DB).read_bytes()
    before_ledger = (state / "ledger.jsonl").read_text(encoding="utf-8")

    preview = result_delivery_preview(state_dir=state, request_id="result-delivery-e2")

    assert preview["can_send"] is True
    assert preview["blockers"] == []
    assert preview["destination"] == "mb-result-replies"
    assert preview["state_write"] is False
    assert preview["network_action"] is False
    assert preview["will_load_private_key"] is False
    assert preview["will_sign"] is False
    assert preview["will_acquire_nonce"] is False
    assert preview["will_post"] is False
    envelope = preview["result_envelope"]
    assert set(envelope) == {
        "schema_version",
        "request_id",
        "target_did",
        "bench_did",
        "verdict",
        "evidence_id",
        "evidence_hash",
        "common_control_disclosure",
        "independent_evidence",
        "urls_followed",
        "code_executed",
        "network_action",
    }
    assert envelope["target_did"] == sender
    assert envelope["bench_did"] == BENCH_DID
    assert preview["result_text"] == json.dumps(envelope, separators=(",", ":"), sort_keys=True)
    assert "\n" not in preview["result_text"]
    assert preview["message_hash"] == message_hash(preview["result_text"])
    assert preview["message_bytes"] == len(preview["result_text"].encode("utf-8"))
    visible = json.dumps(preview, sort_keys=True)
    assert "evidence_path" not in visible
    assert "request_json" not in visible
    assert (state / STATE_DB).read_bytes() == before_db
    assert (state / "ledger.jsonl").read_text(encoding="utf-8") == before_ledger


def test_result_delivery_preview_blocks_existing_d_room_request(tmp_path: Path) -> None:
    state, _sender = completed_result_request(
        tmp_path,
        request_id="BENCH-E1B-20260901T140608Z",
        reply_room="d-flop-scout",
    )

    preview = result_delivery_preview(
        state_dir=state,
        request_id="BENCH-E1B-20260901T140608Z",
    )

    assert preview["can_send"] is False
    assert preview["destination"] == "d-flop-scout"
    assert "unsupported_result_destination" in preview["blockers"]
    assert result_history(state_dir=state, limit=10)["deliveries"] == []


def test_result_delivery_requires_completed_evidence_before_key_or_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, _sender = approved_literal_request(
        tmp_path,
        request_id="uncompleted-delivery-e2",
        extra={"reply_room": "mb-result-replies"},
    )

    def fail_identity_load(*args: object, **kwargs: object) -> object:
        raise AssertionError("result delivery must not load identity before local gates")

    monkeypatch.setattr("flop_bench.execution.load_production_identity_key", fail_identity_load)
    transport = FakeActivationTransport()
    preview = result_delivery_preview(state_dir=state, request_id="uncompleted-delivery-e2")
    assert preview["can_send"] is False
    assert "result delivery requires completed execution" in preview["blockers"]
    with pytest.raises(SafetyError, match="completed execution"):
        send_result_delivery(
            state_dir=state,
            request_id="uncompleted-delivery-e2",
            destination="mb-result-replies",
            live=True,
            confirm=RESULT_SEND_CONFIRMATION,
            passphrase=strong_test_phrase(),
            transport=transport,
            expected_state_dir=state,
            expected_bench_did=BENCH_DID,
        )
    assert transport.requests == []
    assert result_history(state_dir=state, limit=10)["deliveries"] == []


def test_result_delivery_blocks_missing_mismatched_and_non_mb_destinations(
    tmp_path: Path,
) -> None:
    missing_state, _sender = approved_literal_request(
        tmp_path,
        request_id="missing-destination-e2",
    )
    execute_passive(
        state_dir=missing_state,
        request_id="missing-destination-e2",
        confirm=EXECUTE_PASSIVE_CONFIRMATION,
    )
    missing = result_delivery_preview(
        state_dir=missing_state,
        request_id="missing-destination-e2",
    )
    assert missing["can_send"] is False
    assert "missing_result_destination" in missing["blockers"]

    non_mb_state, _sender = completed_result_request(
        tmp_path,
        request_id="non-mb-destination-e2",
        reply_room="https://example.test/mb-result-replies",
    )
    non_mb = result_delivery_preview(
        state_dir=non_mb_state,
        request_id="non-mb-destination-e2",
    )
    assert non_mb["can_send"] is False
    assert "unsupported_result_destination" in non_mb["blockers"]

    state, _sender = completed_result_request(
        tmp_path,
        request_id="mismatch-destination-e2",
        reply_room="mb-result-replies",
    )
    passphrase, did = add_identity_to_state(state)
    transport = FakeActivationTransport()
    with pytest.raises(SafetyError, match="destination_mismatch"):
        send_result_delivery(
            state_dir=state,
            request_id="mismatch-destination-e2",
            destination="mb-other-replies",
            live=True,
            confirm=RESULT_SEND_CONFIRMATION,
            passphrase=passphrase,
            transport=transport,
            expected_state_dir=state,
            expected_bench_did=did,
        )
    assert transport.requests == []
    assert result_history(state_dir=state, limit=10)["deliveries"] == []


def test_result_delivery_send_gates_nonce_body_audit_and_redaction(tmp_path: Path) -> None:
    state, _sender = completed_result_request(tmp_path, request_id="send-result-e2")
    passphrase, did = add_identity_to_state(state)
    preview = result_delivery_preview(state_dir=state, request_id="send-result-e2")
    transport = FakeActivationTransport()
    with pytest.raises(SafetyError):
        send_result_delivery(
            state_dir=state,
            request_id="send-result-e2",
            destination="mb-result-replies",
            live=False,
            confirm=RESULT_SEND_CONFIRMATION,
            passphrase=passphrase,
            transport=transport,
            expected_state_dir=state,
            expected_bench_did=did,
        )
    with pytest.raises(SafetyError):
        send_result_delivery(
            state_dir=state,
            request_id="send-result-e2",
            destination="mb-result-replies",
            live=True,
            confirm="WRONG",
            passphrase=passphrase,
            transport=transport,
            expected_state_dir=state,
            expected_bench_did=did,
        )
    assert transport.requests == []
    assert result_history(state_dir=state, limit=10)["deliveries"] == []

    result = send_result_delivery(
        state_dir=state,
        request_id="send-result-e2",
        destination="mb-result-replies",
        live=True,
        confirm=RESULT_SEND_CONFIRMATION,
        passphrase=passphrase,
        transport=transport,
        expected_state_dir=state,
        expected_bench_did=did,
    )
    assert result["delivery_status"] == "posted"
    assert result["destination"] == "mb-result-replies"
    body = transport.post_bodies[0]
    assert body["did"] == did
    assert body["text"] == preview["result_text"]
    assert isinstance(body["nonce"], str)
    assert (
        signed_post_preimage(
            "mb-result-replies",
            int(body["nonce"]),
            preview["result_text"],
        )
        == f"mb-result-replies|{body['nonce']}|{preview['result_text']}".encode()
    )
    public_key_from_did(did).verify(
        b64u_decode(str(body["sig"])),
        signed_post_preimage(
            "mb-result-replies",
            int(body["nonce"]),
            preview["result_text"],
        ),
    )
    history = result_history(state_dir=state, limit=10)["deliveries"]
    assert len(history) == 1
    audit = history[0]
    assert audit["delivery_status"] == "posted"
    assert audit["message_hash"] == preview["message_hash"]
    visible = json.dumps(history, sort_keys=True)
    assert preview["result_text"] not in visible
    assert str(body["sig"]) not in visible
    assert passphrase not in visible
    assert "evidence_path" not in visible


def test_result_delivery_send_idempotency_timeout_and_reconciliation_are_monotonic(
    tmp_path: Path,
) -> None:
    state, _sender = completed_result_request(tmp_path, request_id="idem-result-e2")
    passphrase, did = add_identity_to_state(state)
    preview = result_delivery_preview(state_dir=state, request_id="idem-result-e2")
    already = FakeActivationTransport()
    already.room_messages["mb-result-replies"] = [
        {"seq": 7, "from": did, "text": preview["result_text"], "nonce": 111}
    ]
    dup = send_result_delivery(
        state_dir=state,
        request_id="idem-result-e2",
        destination="mb-result-replies",
        live=True,
        confirm=RESULT_SEND_CONFIRMATION,
        passphrase=passphrase,
        transport=already,
        expected_state_dir=state,
        expected_bench_did=did,
    )
    assert dup["delivery_status"] == "already-posted"
    assert already.post_bodies == []

    timeout_state, _sender = completed_result_request(
        tmp_path,
        request_id="timeout-result-e2",
    )
    timeout_passphrase, timeout_did = add_identity_to_state(timeout_state)
    timeout_transport = FakeActivationTransport()
    timeout_transport.timeout_after_accept = True
    with pytest.raises(SafetyError):
        send_result_delivery(
            state_dir=timeout_state,
            request_id="timeout-result-e2",
            destination="mb-result-replies",
            live=True,
            confirm=RESULT_SEND_CONFIRMATION,
            passphrase=timeout_passphrase,
            transport=timeout_transport,
            expected_state_dir=timeout_state,
            expected_bench_did=timeout_did,
        )
    row = result_history(state_dir=timeout_state, limit=1)["deliveries"][0]
    assert row["delivery_status"] == "unknown_outcome"
    assert row["failure_classification"] == "post_outcome_unknown_timeout"
    reconcile = reconcile_result_delivery(
        state_dir=timeout_state,
        delivery_id=row["id"],
        transport=timeout_transport,
        expected_bench_did=timeout_did,
    )
    after = result_history(state_dir=timeout_state, limit=1)["deliveries"][0]
    assert reconcile["reconciliation_status"] == "reconciled_posted"
    assert reconcile["audit_transition"] == "updated"
    assert after["delivery_status"] == "reconciled_posted"
    assert after["failure_classification"] is None

    absent = FakeActivationTransport()
    weaker = reconcile_result_delivery(
        state_dir=timeout_state,
        delivery_id=row["id"],
        transport=absent,
        expected_bench_did=timeout_did,
    )
    preserved = result_history(state_dir=timeout_state, limit=1)["deliveries"][0]
    assert weaker["audit_transition"] == "preserved"
    assert preserved["delivery_status"] == "reconciled_posted"


def test_result_delivery_response_nonce_must_be_integer(tmp_path: Path) -> None:
    state, _sender = completed_result_request(tmp_path, request_id="nonce-result-e2")
    passphrase, did = add_identity_to_state(state)

    class StringResponseNonceTransport(FakeActivationTransport):
        def request(
            self,
            method: str,
            url: str,
            *,
            body: bytes | None = None,
            headers: dict[str, str] | None = None,
            timeout: float = 20.0,
        ) -> TransportResponse:
            response = super().request(
                method,
                url,
                body=body,
                headers=headers,
                timeout=timeout,
            )
            if method == "POST" and response.status == 200:
                parsed = json.loads(response.body.decode("utf-8"))
                parsed["posted"]["nonce"] = str(parsed["posted"]["nonce"])
                return TransportResponse(
                    response.status,
                    json.dumps(parsed, separators=(",", ":")).encode(),
                    response.headers,
                    final_url=response.final_url,
                )
            return response

    transport = StringResponseNonceTransport()
    with pytest.raises(SafetyError, match="returned posted record"):
        send_result_delivery(
            state_dir=state,
            request_id="nonce-result-e2",
            destination="mb-result-replies",
            live=True,
            confirm=RESULT_SEND_CONFIRMATION,
            passphrase=passphrase,
            transport=transport,
            expected_state_dir=state,
            expected_bench_did=did,
        )
    row = result_history(state_dir=state, limit=1)["deliveries"][0]
    assert isinstance(transport.post_bodies[0]["nonce"], str)
    assert row["delivery_status"] == "failed"
    assert row["failure_classification"] == "unverifiable_post"


def test_execution_does_not_shell_import_eval_network_file_or_url_from_remote_spec(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "must-not-exist"
    state, _sender = approved_literal_request(
        tmp_path,
        request_id="inert-remote-strings-e1",
        actual=f"import os; eval('1'); open({str(marker)!r}, 'w'); https://example.test",
        expected=f"import os; eval('1'); open({str(marker)!r}, 'w'); https://example.test",
    )

    def fail_subprocess(*args: object, **kwargs: object) -> object:
        raise AssertionError("remote passive execution must not spawn subprocesses")

    def fail_urlopen(*args: object, **kwargs: object) -> object:
        raise AssertionError("remote passive execution must not open URLs")

    monkeypatch.setattr(subprocess, "run", fail_subprocess)
    monkeypatch.setattr(urllib.request, "urlopen", fail_urlopen)
    result = execute_passive(
        state_dir=state,
        request_id="inert-remote-strings-e1",
        confirm=EXECUTE_PASSIVE_CONFIRMATION,
    )
    assert result["evidence"]["verdict"] == "PASS"
    assert not marker.exists()


def test_identity_note_preview_status_publish_and_conflict_safety(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    write_bench_identity_json(state)
    preview = preview_identity_note(state_dir=state)
    namespace, key, fingerprint = did_profile_path(BENCH_DID)
    assert preview["namespace"] == namespace
    assert preview["key"] == key
    assert preview["fingerprint"] == fingerprint
    assert preview["value"] == identity_note_value(BENCH_DID)
    assert preview["value"] == (
        "did:key:z6MkqqqEMxujBTEAvoanSx6pVBMMZzLP7gMUcmNVdYHS3BVk "
        "mailbox: mb-flop-bench service-room: d-flop-bench role: verification "
        "operator-group: local-flop-agent-family related-agent-evidence-independent: false"
    )
    assert scout_compatible_mailbox_from_note(str(preview["value"])) == "mb-flop-bench"
    assert len(str(preview["value"]).splitlines()) == 1
    assert len(str(preview["value"]).encode("utf-8")) < 4096
    assert preview["network_action"] is False
    assert preview["will_load_private_key"] is False
    assert "unsigned DID note is conventional metadata" in preview["proof_warning"]
    transport = FakeActivationTransport()
    status = identity_note_status(state_dir=state, transport=transport)
    assert status["status"] == "absent"
    framed_transport = FakeActivationTransport()
    framed_transport.notes[(namespace, key)] = framed_note(str(preview["value"]))
    framed_status = identity_note_status(state_dir=state, transport=framed_transport)
    assert framed_status["status"] == "already-matching"
    assert framed_status["current_hash"] == framed_status["expected_hash"]
    production_transport = FakeActivationTransport()
    production_transport.notes[(namespace, key)] = f"{framed_note(str(preview['value']))}\n"
    production_status = identity_note_status(state_dir=state, transport=production_transport)
    assert production_status["status"] == "already-matching"
    different_transport = FakeActivationTransport()
    different_transport.notes[(namespace, key)] = framed_note("different value")
    different_status = identity_note_status(state_dir=state, transport=different_transport)
    assert different_status["status"] == "conflict"
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    published = publish_identity_note(
        state_dir=state,
        live=True,
        confirm=DID_NOTE_CONFIRMATION,
        transport=transport,
        expected_state_dir=state,
    )
    assert published["status"] == "published"
    assert published["cas"] == "if_absent"
    assert transport.notes[(namespace, key)] == preview["value"]
    post_urls = [url for method, url in transport.requests if method == "POST"]
    assert post_urls == [f"{TECHNOCORE_ORIGIN}/kv/did-76/0e4e861a71aa43"]
    assert transport.note_bodies == [{"value": preview["value"], "if_absent": True}]
    conflict = FakeActivationTransport()
    conflict.notes[(namespace, key)] = "unexpected existing value"
    with pytest.raises(SafetyError):
        publish_identity_note(
            state_dir=state,
            live=True,
            confirm=DID_NOTE_CONFIRMATION,
            transport=conflict,
            expected_state_dir=state,
        )
    matching = FakeActivationTransport()
    matching.notes[(namespace, key)] = str(preview["value"])
    already = publish_identity_note(
        state_dir=state,
        live=True,
        confirm=DID_NOTE_CONFIRMATION,
        transport=matching,
        expected_state_dir=state,
    )
    assert already["status"] == "already-matching"
    assert all(method != "POST" for method, _url in matching.requests)
    cas_match = FakeActivationTransport()
    cas_match.notes[(namespace, key)] = str(preview["value"])
    del cas_match.notes[(namespace, key)]
    original_request = cas_match.request

    def cas_409_match(*args: object, **kwargs: object) -> TransportResponse:
        if args[0] == "POST":
            return TransportResponse(
                409,
                framed_note(str(preview["value"])).encode("utf-8"),
                {},
                final_url=str(args[1]),
            )
        return original_request(*args, **kwargs)

    cas_match.request = cas_409_match  # type: ignore[method-assign]
    cas_matched = publish_identity_note(
        state_dir=state,
        live=True,
        confirm=DID_NOTE_CONFIRMATION,
        transport=cas_match,
        expected_state_dir=state,
    )
    assert cas_matched["status"] == "already-matching"
    assert cas_matched["cas"] == "if_absent_conflict_existing_match"
    cas_different = FakeActivationTransport()
    original_different_request = cas_different.request

    def cas_409_different(*args: object, **kwargs: object) -> TransportResponse:
        if args[0] == "POST":
            return TransportResponse(
                409,
                framed_note("unexpected existing value").encode("utf-8"),
                {},
                final_url=str(args[1]),
            )
        return original_different_request(*args, **kwargs)

    cas_different.request = cas_409_different  # type: ignore[method-assign]
    cas_conflict = publish_identity_note(
        state_dir=state,
        live=True,
        confirm=DID_NOTE_CONFIRMATION,
        transport=cas_different,
        expected_state_dir=state,
    )
    assert cas_conflict["status"] == "conflict"
    assert cas_conflict["ok"] is False
    assert all("set-signed" not in url for _method, url in transport.requests)


def test_note_response_parser_framing_bounds_and_untrusted_content() -> None:
    expected = identity_note_value(BENCH_DID)
    production_body = f"{framed_note(expected)}\n".encode()
    parsed, framing = parse_note_response_value(production_body)
    assert parsed == expected
    assert framing == "framed"
    parsed_without_lf, framing_without_lf = parse_note_response_value(
        framed_note(expected).encode("utf-8")
    )
    assert parsed_without_lf == expected
    assert framing_without_lf == "framed"
    raw_with_lf, raw_with_lf_framing = parse_note_response_value(f"{expected}\n".encode())
    assert raw_with_lf == expected
    assert raw_with_lf_framing == "raw"
    parsed, framing = parse_note_response_value(framed_note(expected).encode("utf-8"))
    assert parsed == expected
    assert framing == "framed"
    raw, raw_framing = parse_note_response_value(expected.encode("utf-8"))
    assert raw == expected
    assert raw_framing == "raw"
    empty, empty_framing = parse_note_response_value(b"")
    assert empty is None
    assert empty_framing == "empty_or_missing"
    with pytest.raises(ValidationError):
        parse_note_response_value(f"{NOTE_RESPONSE_BANNER}\n{expected}".encode())
    with pytest.raises(ValidationError):
        parse_note_response_value(f"{expected}\n\n".encode())
    with pytest.raises(ValidationError):
        parse_note_response_value(f"{expected}\ninternal".encode())
    with pytest.raises(ValidationError):
        parse_note_response_value(f"{NOTE_RESPONSE_BANNER}\r\n\r\n{expected}\r\n".encode())
    attacker_note = f"{expected} banner-like text: !! UNTRUSTED CONTENT https://example.test"
    attacker, _ = parse_note_response_value(attacker_note.encode("utf-8"))
    assert attacker == attacker_note
    with pytest.raises(ValidationError):
        parse_note_response_value(f"{expected}\n{NOTE_RESPONSE_BANNER}".encode())
    with pytest.raises(SafetyError):
        parse_note_response_value(b"x" * 8193)


def test_did_note_reconcile_drives_local_mailbox_advertisement_state(tmp_path: Path) -> None:
    state = tmp_path / "state"
    write_bench_identity_json(state)
    namespace, key, _fingerprint = did_profile_path(BENCH_DID)
    expected = identity_note_value(BENCH_DID)
    before = mailbox_status(state_dir=state)
    assert before["advertised"] is None
    assert before["advertisement_status"] == "unknown_not_reconciled"
    matching = FakeActivationTransport()
    matching.notes[(namespace, key)] = framed_note(expected)
    reconciled = reconcile_identity_note(state_dir=state, network=True, transport=matching)
    assert reconciled["status"] == "already-matching"
    assert reconciled["state_write"] is True
    assert reconciled["network_action"] == "bounded_read_only"
    assert matching.note_bodies == []
    assert all(method == "GET" for method, _url in matching.requests)
    after = mailbox_status(state_dir=state)
    assert after["advertised"] is True
    assert after["advertisement_status"] == "already-matching"
    assert after["advertisement_expected_hash"] == note_hash(expected)


def test_did_note_reconcile_absent_and_conflict_are_explicit_false(tmp_path: Path) -> None:
    for label, notes, expected_status in [
        ("absent", {}, "absent"),
        ("conflict", {"value": "different value"}, "conflict"),
    ]:
        state = tmp_path / label
        write_bench_identity_json(state)
        namespace, key, _fingerprint = did_profile_path(BENCH_DID)
        transport = FakeActivationTransport()
        if notes:
            transport.notes[(namespace, key)] = framed_note(str(notes["value"]))
        result = reconcile_identity_note(state_dir=state, network=True, transport=transport)
        status = mailbox_status(state_dir=state)
        assert result["status"] == expected_status
        assert result["state_write"] is True
        assert status["advertised"] is False
        assert status["advertisement_status"] == expected_status


def test_did_note_reconcile_503_preserves_prior_matching_evidence(tmp_path: Path) -> None:
    state = tmp_path / "state"
    write_bench_identity_json(state)
    namespace, key, _fingerprint = did_profile_path(BENCH_DID)
    matching = FakeActivationTransport()
    matching.notes[(namespace, key)] = framed_note(identity_note_value(BENCH_DID))
    reconcile_identity_note(state_dir=state, network=True, transport=matching)
    before = mailbox_status(state_dir=state)
    unavailable = FakeActivationTransport()
    unavailable.note_statuses[(namespace, key)] = 503
    result = reconcile_identity_note(state_dir=state, network=True, transport=unavailable)
    after = mailbox_status(state_dir=state)
    assert result["status"] == "reconciliation_incomplete"
    assert result["state_write"] is False
    assert after == before


def test_did_note_reconcile_absent_or_conflict_preserves_prior_matching_evidence(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    write_bench_identity_json(state)
    namespace, key, _fingerprint = did_profile_path(BENCH_DID)
    matching = FakeActivationTransport()
    matching.notes[(namespace, key)] = framed_note(identity_note_value(BENCH_DID))
    reconcile_identity_note(state_dir=state, network=True, transport=matching)
    before = mailbox_status(state_dir=state)
    absent = reconcile_identity_note(
        state_dir=state,
        network=True,
        transport=FakeActivationTransport(),
    )
    conflict_transport = FakeActivationTransport()
    conflict_transport.notes[(namespace, key)] = framed_note("different value")
    conflict = reconcile_identity_note(
        state_dir=state,
        network=True,
        transport=conflict_transport,
    )
    after = mailbox_status(state_dir=state)
    assert absent["status"] == "absent"
    assert absent["state_write"] is False
    assert absent["audit_transition"] == "preserved"
    assert conflict["status"] == "conflict"
    assert conflict["state_write"] is False
    assert conflict["audit_transition"] == "preserved"
    assert after == before


def test_did_note_reconcile_requires_network_and_never_publishes(tmp_path: Path) -> None:
    state = tmp_path / "state"
    write_bench_identity_json(state)
    with pytest.raises(SafetyError):
        reconcile_identity_note(
            state_dir=state,
            network=False,
            transport=FakeActivationTransport(),
        )
    transport = FakeActivationTransport()
    namespace, key, _fingerprint = did_profile_path(BENCH_DID)
    transport.notes[(namespace, key)] = framed_note(identity_note_value(BENCH_DID))
    reconcile_identity_note(state_dir=state, network=True, transport=transport)
    assert transport.note_bodies == []
    assert all(method == "GET" for method, _url in transport.requests)


def test_identity_note_publish_audits_safe_lifecycle_and_ambiguous_outcome(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    write_bench_identity_json(state)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    transport = FakeActivationTransport()
    published = publish_identity_note(
        state_dir=state,
        live=True,
        confirm=DID_NOTE_CONFIRMATION,
        transport=transport,
        expected_state_dir=state,
    )
    assert published["status"] == "published"
    with connect_state(state) as conn:
        rows = conn.execute(
            """
            SELECT namespace, key, expected_hash, observed_hash, action, status,
                   response_status, failure_classification
            FROM did_note_observations
            ORDER BY id
            """
        ).fetchall()
    assert [row["status"] for row in rows] == ["publish_started", "published"]
    stored = json.dumps([dict(row) for row in rows], sort_keys=True)
    assert identity_note_value(BENCH_DID) not in stored
    assert "signature" not in stored
    assert "cookie" not in stored.lower()
    assert "password" not in stored.lower()

    class AmbiguousPublishTransport(FakeActivationTransport):
        def request(
            self,
            method: str,
            url: str,
            *,
            body: bytes | None = None,
            headers: dict[str, str] | None = None,
            timeout: float = 20.0,
        ) -> TransportResponse:
            if method == "POST":
                raise ActivationRequestError(
                    "write timed out password=supersecret",
                    failure_classification="timeout_unknown_phase",
                )
            return super().request(method, url, body=body, headers=headers, timeout=timeout)

    ambiguous_state = tmp_path / "ambiguous"
    write_bench_identity_json(ambiguous_state)
    with pytest.raises(ActivationRequestError):
        publish_identity_note(
            state_dir=ambiguous_state,
            live=True,
            confirm=DID_NOTE_CONFIRMATION,
            transport=AmbiguousPublishTransport(),
            expected_state_dir=ambiguous_state,
        )
    with connect_state(ambiguous_state) as conn:
        statuses = [
            row["status"]
            for row in conn.execute("SELECT status FROM did_note_observations ORDER BY id")
        ]
    assert statuses == ["publish_started", "publish_unknown"]


def signed_technocore_record(
    key: Ed25519PrivateKey,
    *,
    room: str = "d-flop-bench",
    generation: str = "4",
    seq: int = 1,
    nonce: int = 123,
    text: str = "I traced a Technocore signed POST failure.",
) -> dict[str, object]:
    did = public_did(key)
    sig = b64u(key.sign(technocore_signed_post_preimage(room, nonce, text)))
    return {
        "room": room,
        "generation": generation,
        "seq": seq,
        "ts": "2026-08-31T12:00:00Z",
        "from": did,
        "nonce": nonce,
        "sig": sig,
        "text": text,
    }


def test_provenance_doctor_is_local_and_read_only() -> None:
    result = provenance_doctor()
    assert result["status"] == "OK"
    assert result["canonical_payload"] == "room|nonce|text"
    assert result["generation_aware"] is True
    assert result["private_key_required"] is False
    assert result["network_action"] is False
    assert result["state_write"] is False


def test_provenance_verify_record_statuses_and_generation_identity(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    record = signed_technocore_record(key, text="Run tests for the signed POST nonce bug.")
    path = write_json(tmp_path / "record.json", record)
    verified = verify_record_file(path)
    assert verified["room"] == "d-flop-bench"
    assert verified["generation"] == "4"
    assert verified["seq"] == 1
    assert verified["sig_present"] is True
    assert verified["verification_status"] == "VERIFIED_OFFLINE"
    assert verified["canonical_payload_hash"]
    altered = dict(record)
    altered["text"] = "Run altered tests for the signed POST nonce bug."
    assert verify_record_mapping(altered)["verification_status"] == "INVALID_SIGNATURE"
    legacy = {
        "room": "d-flop-bench",
        "seq": 2,
        "from": str(record["from"]),
        "text": "Legacy server-verified record",
        "signed": True,
    }
    legacy_result = verify_record_mapping(legacy)
    assert legacy_result["generation"] == UNKNOWN_LEGACY
    assert legacy_result["verification_status"] == "LEGACY_SERVER_VERIFIED_NO_SIGNATURE"


def test_provenance_official_export_record_uses_manifest_context(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    record = signed_technocore_record(
        key,
        text="Exact official Technocore export text; do not trim or normalize.",
    )
    official = {key: value for key, value in record.items() if key not in {"room", "generation"}}
    raw_line = json.dumps(official, separators=(",", ":")) + "\n"
    export_path = tmp_path / "official.jsonl"
    export_path.write_text(raw_line, encoding="utf-8")
    before = export_path.read_bytes()
    manifest_path = write_json(
        tmp_path / "manifest.json",
        {
            "room": "d-flop-bench",
            "generation": "1",
            "export_sha256": hashlib.sha256(before).hexdigest(),
            "record_count": 1,
            "signed_records": 1,
            "verified_records": 1,
            "legacy_records_without_sig": 0,
            "unsigned_records": 0,
            "invalid_signatures": 0,
        },
    )
    result = verify_export_file(export_path, manifest_path)
    assert result["room"] == "d-flop-bench"
    assert result["generation"] == "1"
    assert result["observed_records"] == 1
    assert result["signed"] == 1
    assert result["verified_offline"] == 1
    assert result["invalid_signatures"] == 0
    assert result["malformed"] == 0
    assert result["record_parsing"] == "PASS"
    assert result["signature_verification"] == "PASS"
    assert result["result"] == "PASS"
    assert export_path.read_bytes() == before


def test_provenance_conflicting_from_and_did_fails_closed() -> None:
    key = Ed25519PrivateKey.generate()
    other_key = Ed25519PrivateKey.generate()
    record = signed_technocore_record(key)
    record["did"] = public_did(other_key)
    result = verify_record_mapping(record)
    assert result["verification_status"] == "PROVENANCE_INCOMPLETE"
    assert result["provenance_conflict"] is True


def test_provenance_verify_record_never_opens_private_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = Ed25519PrivateKey.generate()
    path = write_json(tmp_path / "record.json", signed_technocore_record(key))
    original_open = Path.open

    def refuse_identity_open(self: Path, *args: object, **kwargs: object) -> object:
        if self.name == "identity.pem":
            raise AssertionError("identity.pem must not be opened")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", refuse_identity_open)
    assert verify_record_file(path)["verification_status"] == "VERIFIED_OFFLINE"


def test_provenance_verify_export_counts_and_preserves_raw_jsonl(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    good = signed_technocore_record(key, seq=1, text="Run tests for the signed POST nonce bug.")
    bad = dict(good)
    bad["seq"] = 2
    bad["text"] = "Tampered after signing."
    legacy = {
        "room": "d-flop-bench",
        "generation": "4",
        "seq": 3,
        "from": str(good["from"]),
        "signed": True,
        "text": "Legacy server verified without original signature.",
    }
    unsigned = {
        "room": "d-flop-bench",
        "generation": "4",
        "seq": 4,
        "from": str(good["from"]),
        "text": "Unsigned record.",
    }
    export_path = tmp_path / "export.jsonl"
    export_path.write_text(
        "\n".join(json.dumps(item) for item in [good, bad, legacy, unsigned]) + "\n{not-json\n",
        encoding="utf-8",
    )
    before = export_path.read_bytes()
    manifest_path = write_json(
        tmp_path / "manifest.json", {"export_sha256": hashlib.sha256(before).hexdigest()}
    )
    result = verify_export_file(export_path, manifest_path)
    assert result["room"] == "d-flop-bench"
    assert result["generation"] == "4"
    assert result["records"] == 4
    assert result["verified_offline"] == 1
    assert result["legacy_without_sig"] == 1
    assert result["unsigned"] == 1
    assert result["invalid_signatures"] == 1
    assert result["malformed"] == 1
    assert result["result"] == "FAIL"
    assert export_path.read_bytes() == before


def test_provenance_verify_export_detects_conflicting_generation_seq(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    first = signed_technocore_record(key, seq=5, text="Run tests for the signed POST nonce bug.")
    second = signed_technocore_record(key, seq=5, text="Debug a different signed POST bug.")
    export_path = tmp_path / "conflict.jsonl"
    export_path.write_text(json.dumps(first) + "\n" + json.dumps(second) + "\n", encoding="utf-8")
    manifest_path = write_json(
        tmp_path / "manifest.json",
        {"sha256": hashlib.sha256(export_path.read_bytes()).hexdigest()},
    )
    result = verify_export_file(export_path, manifest_path)
    assert result["conflicts"] == 1
    assert result["result"] == "FAIL"


def test_provenance_verify_export_detects_old_manifest_count_mismatch(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    record = signed_technocore_record(key)
    official = {key: value for key, value in record.items() if key not in {"room", "generation"}}
    export_path = tmp_path / "official.jsonl"
    export_path.write_text(json.dumps(official) + "\n", encoding="utf-8")
    manifest_path = write_json(
        tmp_path / "manifest.json",
        {
            "room": "d-flop-bench",
            "generation": "1",
            "export_sha256": hashlib.sha256(export_path.read_bytes()).hexdigest(),
            "record_count": 0,
            "signed_records": 0,
            "verified_records": 0,
        },
    )
    result = verify_export_file(export_path, manifest_path)
    assert result["raw_export_integrity"] == "PASS"
    assert result["record_parsing"] == "PASS"
    assert result["signature_verification"] == "PASS"
    assert result["manifest_statistics"] == "MISMATCH"
    assert result["result"] == "MANIFEST_MISMATCH"
    assert result["manifest_record_count"] == 0
    assert result["observed_record_count"] == 1
    assert result["manifest_signed_records"] == 0
    assert result["observed_signed_records"] == 1


def test_provenance_same_seq_different_manifest_generations_remains_distinct(
    tmp_path: Path,
) -> None:
    key = Ed25519PrivateKey.generate()
    record = signed_technocore_record(key, seq=2)
    official = {key: value for key, value in record.items() if key not in {"room", "generation"}}
    ids = []
    for generation in ("1", "2"):
        export_path = tmp_path / f"generation-{generation}.jsonl"
        export_path.write_text(json.dumps(official) + "\n", encoding="utf-8")
        manifest_path = write_json(
            tmp_path / f"manifest-{generation}.json",
            {
                "room": "d-flop-bench",
                "generation": generation,
                "export_sha256": hashlib.sha256(export_path.read_bytes()).hexdigest(),
            },
        )
        result = verify_export_file(export_path, manifest_path)
        ids.append(result)
    assert ids[0]["generation"] == "1"
    assert ids[1]["generation"] == "2"


def test_provenance_verify_export_manifest_mismatch_fails_safely(tmp_path: Path) -> None:
    export_path = tmp_path / "export.jsonl"
    export_path.write_text("{}\n", encoding="utf-8")
    manifest_path = write_json(tmp_path / "manifest.json", {"export_sha256": "0" * 64})
    with pytest.raises(ValidationError):
        verify_export_file(export_path, manifest_path)


def test_provenance_export_room_is_dry_run_without_yes(tmp_path: Path) -> None:
    class FailingTransport:
        def request(self, *_args: object, **_kwargs: object) -> object:
            raise AssertionError("dry run must not fetch")

    result = export_room(
        "d-flop-bench",
        yes=False,
        transport=FailingTransport(),  # type: ignore[arg-type]
        state_dir=tmp_path / "state",
    )
    assert result["dry_run"] is True
    assert result["network_action"] is False
    assert result["state_write"] is False
    assert not (tmp_path / "state").exists()


def test_provenance_export_room_yes_fetches_get_only_and_preserves_export(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    raw = (json.dumps(signed_technocore_record(key)) + "\n").encode()

    class ExportTransport:
        def __init__(self) -> None:
            self.requests: list[tuple[str, str, bytes | None]] = []

        def request(
            self,
            method: str,
            url: str,
            *,
            body: bytes | None = None,
            headers: dict[str, str] | None = None,
            timeout: float = 0,
        ) -> TransportResponse:
            del headers, timeout
            self.requests.append((method, url, body))
            return TransportResponse(200, raw, {"X-Room-Generation": "4"}, url)

    transport = ExportTransport()
    result = export_room(
        "d-flop-bench", yes=True, transport=transport, state_dir=tmp_path / "state"
    )
    assert transport.requests == [("GET", f"{TECHNOCORE_ORIGIN}/r/d-flop-bench/export", None)]
    assert result["network_action"] is True
    assert result["state_write"] is True
    assert Path(str(result["destination"])).read_bytes() == raw
    manifest = json.loads(Path(str(result["manifest"])).read_text(encoding="utf-8"))
    assert manifest["generation"] == "4"
    assert manifest["export_sha256"] == hashlib.sha256(raw).hexdigest()


def test_provenance_cli_dispatch_and_help(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from flop_bench import cli

    key = Ed25519PrivateKey.generate()
    record_path = write_json(tmp_path / "record.json", signed_technocore_record(key))
    export_path = tmp_path / "export.jsonl"
    export_path.write_text(record_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    manifest_path = write_json(
        tmp_path / "manifest.json",
        {"export_sha256": hashlib.sha256(export_path.read_bytes()).hexdigest()},
    )
    with pytest.raises(SystemExit) as help_exit:
        cli.build_parser().parse_args(["provenance", "--help"])
    assert help_exit.value.code == 0
    assert cli.run(["provenance", "doctor"]) == 0
    assert cli.run(["provenance", "verify-record", str(record_path)]) == 0
    assert (
        cli.run(["provenance", "verify-export", str(export_path), "--manifest", str(manifest_path)])
        == 0
    )
    assert cli.run(["provenance", "export-room", "d-flop-bench"]) == 0
    output = capsys.readouterr().out
    assert "DRY_RUN_ONLY" in output
    help_text = cli.build_parser().format_help()
    for command in (
        "doctor",
        "service",
        "request",
        "response",
        "technocore",
        "mailbox",
        "identity-note",
        "provenance",
    ):
        assert command in help_text


def test_cli_phase_d_local_commands_smoke(tmp_path: Path) -> None:
    state = tmp_path / "state"
    write_bench_identity_json(state)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO / "src")
    commands = [
        [sys.executable, "-m", "flop_bench.cli", "mailbox", "status", "--state-dir", str(state)],
        [sys.executable, "-m", "flop_bench.cli", "mailbox", "poll", "--state-dir", str(state)],
        [
            sys.executable,
            "-m",
            "flop_bench.cli",
            "mailbox",
            "messages",
            "--state-dir",
            str(state),
            "--limit",
            "5",
        ],
        [
            sys.executable,
            "-m",
            "flop_bench.cli",
            "request",
            "queue",
            "--state-dir",
            str(state),
        ],
        [
            sys.executable,
            "-m",
            "flop_bench.cli",
            "identity-note",
            "preview",
            "--state-dir",
            str(state),
        ],
    ]
    for command in commands:
        completed = subprocess.run(  # noqa: S603 - fixed CLI smoke argv.
            command,
            cwd=REPO,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
