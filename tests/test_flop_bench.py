from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

from flop_bench import config as config_mod
from flop_bench import engine
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
from flop_bench.protocol import (
    REQUEST_SCHEMA_VERSION,
    RESPONSE_SCHEMA_VERSION,
    protocol_error_from_response,
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
    prepare_signed_response,
    verify_request,
    verify_signed_response,
)
from flop_bench.state import connect_state
from flop_bench.transport import DisabledTechnocoreTransport

REPO = Path(__file__).resolve().parents[1]


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
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO / "src")
    state = tmp_path / "state"
    commands = [
        [sys.executable, "-m", "flop_bench.cli", "validate-spec", str(spec_path)],
        [sys.executable, "-m", "flop_bench.cli", "doctor", "--state-dir", str(state)],
        [sys.executable, "-m", "flop_bench.cli", "service", "doctor", "--state-dir", str(state)],
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
