from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .adapters import run_local_command_step, run_passive_step
from .canonical import (
    atomic_write_text,
    canonical_json_bytes,
    sha256_bytes,
    sha256_file,
    sha256_json,
)
from .config import BenchConfig, assert_isolated
from .exceptions import SafetyError
from .ledger import append_record
from .models import EvidenceBundle, RouterValidationExport, TestSpec
from .schemas import EVIDENCE_BUNDLE_SCHEMA, validate_test_spec, validate_with_schema
from .state import connect_state, insert_run


def _result_from_observations(observations: list[dict[str, Any]]) -> str:
    passed = sum(1 for obs in observations if obs.get("pass") is True)
    if passed == len(observations) and observations:
        return "PASS"
    if passed > 0:
        return "PARTIAL"
    return "FAIL"


def _substantive_evidence(
    spec: dict[str, Any], observations: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "claim_id": spec["claim_id"],
        "hypothesis": spec["hypothesis"],
        "capabilities": spec["requested_capabilities"],
        "procedure": spec["procedure"],
        "assertions": spec["assertions"],
        "observations": observations,
        "result": _result_from_observations(observations),
        "failure_conditions": spec["failure_conditions"],
        "provenance": spec["provenance"],
    }


def derive_evidence_id(spec: dict[str, Any], observations: list[dict[str, Any]]) -> str:
    return "ev-" + sha256_json(_substantive_evidence(spec, observations))[:32]


def verify_spec(
    spec_path: Path,
    *,
    state_dir: Path,
    allow_local_exec: bool = False,
    subject_did: str | None = None,
) -> dict[str, Any]:
    config = BenchConfig(state_dir=state_dir, subject_did=subject_did)
    assert_isolated(config)
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    validate_test_spec(spec)
    spec_model = TestSpec.from_mapping(spec)
    observations: list[dict[str, Any]] = []
    local_execution = False
    for step in spec_model.procedure:
        if step.get("adapter") == "local_command":
            if spec_model.mode != "approved-local":
                raise SafetyError("local_command adapter requires spec mode approved-local")
            local_execution = True
            observations.append(run_local_command_step(step, allow_local_exec=allow_local_exec))
        else:
            observations.append(run_passive_step(step))
    evidence_id = derive_evidence_id(spec, observations)
    created_at = datetime.now(UTC).isoformat()
    input_hashes = [{"path": str(spec_path), "sha256": sha256_file(spec_path)}]
    safety_report = {
        "wallet_support": False,
        "flop_transfers": False,
        "technocore_network_calls": False,
        "outbound_posting": False,
        "automatic_url_fetching": False,
        "local_execution": local_execution,
        "local_execution_authorized_by_cli": allow_local_exec,
        "network_sandboxed_for_subprocesses": False,
    }
    record = {
        "schema_version": "flop-bench.evidence-bundle.v0.1",
        "evidence_id": evidence_id,
        **_substantive_evidence(spec, observations),
        "created_at": created_at,
        "input_hashes": input_hashes,
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
            claim_id=spec["claim_id"],
            result=evidence["result"],
            evidence_path=evidence_path,
            created_at=created_at,
        )
    return evidence


def router_export(evidence: dict[str, Any], *, subject_did: str | None = None) -> dict[str, Any]:
    capabilities = evidence.get("capabilities") or ["unknown"]
    export = {
        "schema_version": "flop-bench.router-validation-export.v0.1",
        "subject_did": subject_did,
        "capability": str(capabilities[0]),
        "result": evidence["result"],
        "evidence_id": evidence["evidence_id"],
        "evidence_quality": "portable-offline-json-ledgered",
        "limitations": [
            "FLOP Bench v0.1 is offline-first and does not validate Technocore network state.",
            "Subprocess network isolation is not guaranteed portably when approved "
            "local execution is used.",
        ],
        "provenance": evidence["provenance"],
        "operator_group": {
            "common_control_disclosure": True,
            "operator_group_id": "local-flop-bench-operator",
            "note": "Export supports transparent common-control disclosure for "
            "Agent Router ingestion.",
        },
    }
    RouterValidationExport.from_mapping(export)
    return export
