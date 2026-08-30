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
    SCOUT_DID,
    SCOUT_MAILBOX,
    SCOUT_ROOM,
    BenchConfig,
    assert_isolated,
    assert_no_forbidden_config_values,
)
from flop_bench.engine import router_export, verify_spec
from flop_bench.exceptions import IsolationError, LedgerError, SafetyError, ValidationError
from flop_bench.identity import (
    IDENTITY_CONFIRMATION,
    create_ephemeral_test_identity,
    create_production_identity,
    public_did,
    read_interactive_new_passphrase,
    verify_identity,
)
from flop_bench.ledger import append_record, verify_ledger
from flop_bench.posting import (
    MAX_POST_BYTES,
    POST_CONFIRMATION,
    message_hash,
    post_room_url,
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
    b64u_decode,
    protocol_error_from_response,
    public_key_from_did,
    sign_envelope,
    verify_signed_envelope,
)
from flop_bench.schemas import (
    EVIDENCE_BUNDLE_SCHEMA,
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
from flop_bench.state import activation_history, connect_state, migration_status
from flop_bench.transport import DisabledTechnocoreTransport

REPO = Path(__file__).resolve().parents[1]
SCOUT_PATH = Path("/Users/greg/Dev/flop_scout_v02/flop_scout.py")


def write_json(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
    return path


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


def load_scout_module() -> object:
    spec = importlib.util.spec_from_file_location("flop_scout_readonly", SCOUT_PATH)
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
    scout = load_scout_module()
    payload = f"{room}|{nonce}|{text}".encode()
    sig = scout.b64u(key.sign(payload))  # type: ignore[attr-defined]
    body = json.dumps(
        {"did": did, "sig": sig, "nonce": nonce, "text": text},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 - fixed Technocore URL in parity test.
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
        self.requests: list[tuple[str, str]] = []
        self.post_bodies: list[dict[str, object]] = []
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
        if method == "GET" and parts == ["r", "d-flop-bench"]:
            query = urllib.parse.parse_qs(parsed.query)
            limit = int(query.get("limit", ["200"])[0])
            since = int(query.get("since", ["0"])[0])
            messages = [
                msg
                for msg in self.room_messages.get("d-flop-bench", [])
                if int(msg.get("seq", 0)) > since
            ][:limit]
            response = {"messages": messages}
            return TransportResponse(
                200,
                json.dumps(response, separators=(",", ":")).encode(),
                {},
                final_url=url,
            )
        if method == "POST" and parts == ["r", "d-flop-bench"]:
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
            next_seq = len(self.room_messages.get("d-flop-bench", [])) + 1
            self.room_messages.setdefault("d-flop-bench", []).append(
                {
                    "seq": next_seq,
                    "from": payload["did"],
                    "text": payload["text"],
                    "nonce": payload["nonce"],
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
                    "nonce": payload["nonce"],
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
            if len(parts) == 3:
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
            if len(parts) >= 8 and parts[3] == "set-signed":
                status = self.write_statuses.pop(0) if self.write_statuses else 200
                if status in {200, 201, 204}:
                    self.notes[(namespace, key)] = urllib.parse.unquote(parts[7])
                    self.nonces[key] = max(self.nonces.get(key, 0), int(parts[6]))
                headers = {"Retry-After": "2"} if status == 429 else {}
                return TransportResponse(status, b"duplicate token=abc123", headers, final_url=url)
        return TransportResponse(400, b"bad request", {}, final_url=url)


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
    assert "PROTOCOL_UNCONFIRMED" in str(exc.value)
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
    message_path.write_text(f"{proposed_initial_announcement()}\n", encoding="utf-8")
    state = tmp_path / "missing-state"
    preview = preview_post(message_path, state_dir=state)
    manifest = service_manifest()
    assert preview["room"] == "d-flop-bench"
    assert preview["will_sign"] is False
    assert preview["will_acquire_nonce"] is False
    assert preview["network_action"] is False
    assert preview["state_write"] is False
    assert preview["manifest"] == manifest
    assert manifest["bench_did"] == BENCH_DID
    assert manifest["room"] == "d-flop-bench"
    assert manifest["mailbox"]["status"] == "protocol-unconfirmed"
    assert manifest["safety"]["url_following"] is False
    assert manifest["safety"]["automatic_code_execution"] is False
    assert manifest["safety"]["wallets"] is False
    assert manifest["safety"]["flop_transfers"] is False
    assert manifest["safety"]["autonomous_outbound_posting"] is False
    assert manifest["safety"]["requests_accepted"] is False
    assert "https://" not in proposed_initial_announcement()
    assert not state.exists()


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
    assert isinstance(body["nonce"], int)
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
    assert row["nonce_used"] == body["nonce"]
    assert row["seq"] == 123
    stored = json.dumps([dict(row)], sort_keys=True)
    assert text not in stored
    assert str(body["sig"]) not in stored
    assert passphrase not in stored


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
    assert row["nonce_used"] == transport.post_bodies[0]["nonce"]
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
    assert mailbox_action["protocol_status"] == "unconfirmed"
    transport = FakeActivationTransport()
    status = technocore_status(state_dir=state, transport=transport)
    assert status["room"]["status"] == "unclaimed"
    assert status["mailbox"]["status"] == "unknown"
    assert status["mailbox"]["protocol_status"] == "unconfirmed"
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
    assert report["pending_migrations"] == [1, 2, 3, 4]
    assert not state.exists()


def test_service_doctor_reports_migrations_applied_and_plan_is_read_only(tmp_path: Path) -> None:
    state = tmp_path / "state"
    report = service_doctor(state_dir=state)
    assert report["read_only"] is False
    assert report["state_write"] is True
    assert report["migrations_applied"] == [1, 2, 3, 4]
    assert report["schema_migrations"] == [1, 2, 3, 4]
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
    assert read_only["pending_migrations"] == [2, 3, 4]
    after_read_only = migration_status(state)
    assert after_read_only["schema_migrations"] == [1]
    normal = service_doctor(state_dir=state)
    assert normal["state_write"] is True
    assert normal["migrations_applied"] == [2, 3, 4]
    assert normal["schema_migrations"] == [1, 2, 3, 4]


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
    assert "PROTOCOL_UNCONFIRMED" in mailbox_refusal.stderr
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
