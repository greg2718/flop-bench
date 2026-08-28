from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from flop_bench import engine
from flop_bench.adapters import run_local_command_step
from flop_bench.config import (
    LEGACY_SCOUT_STATE,
    SCOUT_DID,
    SCOUT_MAILBOX,
    SCOUT_ROOM,
    SCOUT_STATE,
    BenchConfig,
    assert_isolated,
    assert_no_forbidden_config_values,
)
from flop_bench.engine import router_export, verify_spec
from flop_bench.exceptions import IsolationError, LedgerError, SafetyError, ValidationError
from flop_bench.identity import create_ephemeral_test_identity, refuse_production_identity_creation
from flop_bench.ledger import append_record, verify_ledger
from flop_bench.schemas import (
    EVIDENCE_BUNDLE_SCHEMA,
    ROUTER_EXPORT_SCHEMA,
    TEST_SPEC_SCHEMA,
    validate_test_spec,
    validate_with_schema,
)
from flop_bench.transport import DisabledTechnocoreTransport

REPO = Path(__file__).resolve().parents[1]
PRODUCTION_PATHS = [Path.home() / ".flop_agents" / "bench", Path.home() / ".flop_agents" / "scout"]


@pytest.fixture(autouse=True)
def no_production_state_created() -> None:
    before = {path: path.exists() for path in PRODUCTION_PATHS}
    yield
    for path, existed in before.items():
        if not existed:
            assert not path.exists(), f"test created forbidden production path {path}"


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


def test_refuses_scout_identity_state_room_mailbox_and_did(tmp_path: Path) -> None:
    for config in [
        BenchConfig(state_dir=Path.home() / ".flop_agents" / "scout"),
        BenchConfig(state_dir=Path.home() / ".flop_agents" / "scout" / "bench"),
        BenchConfig(state_dir=tmp_path, canonical_room=SCOUT_ROOM),
        BenchConfig(state_dir=tmp_path, mailbox=SCOUT_MAILBOX),
        BenchConfig(state_dir=tmp_path, subject_did=SCOUT_DID),
    ]:
        with pytest.raises(IsolationError):
            assert_isolated(config)


def test_forbidden_config_values_resolve_path_aliases(tmp_path: Path) -> None:
    scout_link = tmp_path / "scout-link"
    scout_link.symlink_to(SCOUT_STATE)
    for value in [
        str(scout_link / "bench"),
        str(LEGACY_SCOUT_STATE / ".." / ".flop_scout"),
        SCOUT_ROOM,
        SCOUT_MAILBOX,
        SCOUT_DID,
    ]:
        with pytest.raises(IsolationError):
            assert_no_forbidden_config_values([value])


def test_production_identity_creation_refusal_and_ephemeral_containment(tmp_path: Path) -> None:
    with pytest.raises(SafetyError):
        refuse_production_identity_creation()
    meta = create_ephemeral_test_identity(tmp_path / "identity")
    assert meta["purpose"] == "test-only"
    assert meta["persistent"] is False
    assert str(tmp_path) in meta["private_key_path"]
    assert not (Path.home() / ".flop_agents" / "bench" / "identity.pem").exists()
    assert not (Path.home() / ".flop_agents" / "bench" / "identity.json").exists()


def test_disabled_technocore_transport() -> None:
    transport = DisabledTechnocoreTransport()
    for method in [
        transport.send,
        transport.post,
        transport.join,
        transport.fetch,
        transport.transfer,
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


def test_cli_smoke_tests_use_temp_state_only(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    target.write_text("ok", encoding="utf-8")
    spec_path = write_json(
        tmp_path / "spec.json",
        spec(tmp_path, [{"adapter": "text_contains", "path": str(target), "text": "ok"}]),
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO / "src")
    state = tmp_path / "state"
    commands = [
        [sys.executable, "-m", "flop_bench.cli", "validate-spec", str(spec_path)],
        [sys.executable, "-m", "flop_bench.cli", "doctor", "--state-dir", str(state)],
        [sys.executable, "-m", "flop_bench.cli", "isolation-check", "--state-dir", str(state)],
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
        [sys.executable, "-m", "flop_bench.cli", "identity", "create-production"],
        cwd=REPO,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert refusal.returncode != 0
    assert "disabled" in refusal.stderr
    failed_isolation = subprocess.run(  # noqa: S603 - fixed CLI smoke argv.
        [
            sys.executable,
            "-m",
            "flop_bench.cli",
            "isolation-check",
            "--state-dir",
            str(Path.home() / ".flop_agents" / "scout"),
        ],
        cwd=REPO,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert failed_isolation.returncode != 0
    failed_report = json.loads(failed_isolation.stdout)
    assert failed_report["ok"] is False
    assert len(failed_report["checks"]) >= 5


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


def test_no_files_created_under_forbidden_paths_after_delay() -> None:
    time.sleep(0.01)
    for path in PRODUCTION_PATHS:
        assert not path.exists()
