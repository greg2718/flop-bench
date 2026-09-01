from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from .schemas import (
    EVIDENCE_BUNDLE_SCHEMA,
    MAILBOX_RESULT_SCHEMA,
    ROUTER_EXPORT_SCHEMA,
    TEST_SPEC_SCHEMA,
    validate_with_schema,
)

Result = Literal["PASS", "PARTIAL", "FAIL"]
Mode = Literal["passive", "approved-local"]


@dataclass(frozen=True)
class TestSpec:
    schema_version: str
    claim_id: str
    hypothesis: str
    requested_capabilities: list[str]
    mode: Mode
    procedure: list[dict[str, Any]]
    assertions: list[dict[str, Any]]
    failure_conditions: list[str]
    provenance: dict[str, Any]

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> TestSpec:
        validate_with_schema(value, TEST_SPEC_SCHEMA)
        return cls(
            schema_version=value["schema_version"],
            claim_id=value["claim_id"],
            hypothesis=value["hypothesis"],
            requested_capabilities=list(value["requested_capabilities"]),
            mode=value["mode"],
            procedure=list(value["procedure"]),
            assertions=list(value["assertions"]),
            failure_conditions=list(value["failure_conditions"]),
            provenance=dict(value["provenance"]),
        )


@dataclass(frozen=True)
class EvidenceBundle:
    schema_version: str
    evidence_id: str
    claim_id: str
    hypothesis: str
    capabilities: list[str]
    procedure: list[dict[str, Any]]
    observations: list[dict[str, Any]]
    result: Result
    failure_conditions: list[str]
    provenance: dict[str, Any]
    safety_report: dict[str, Any]
    previous_ledger_hash: str | None
    record_hash: str

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> EvidenceBundle:
        validate_with_schema(value, EVIDENCE_BUNDLE_SCHEMA)
        return cls(
            schema_version=value["schema_version"],
            evidence_id=value["evidence_id"],
            claim_id=value["claim_id"],
            hypothesis=value["hypothesis"],
            capabilities=list(value["capabilities"]),
            procedure=list(value["procedure"]),
            observations=list(value["observations"]),
            result=value["result"],
            failure_conditions=list(value["failure_conditions"]),
            provenance=dict(value["provenance"]),
            safety_report=dict(value["safety_report"]),
            previous_ledger_hash=value["previous_ledger_hash"],
            record_hash=value["record_hash"],
        )


@dataclass(frozen=True)
class RouterValidationExport:
    schema_version: str
    subject_did: str | None
    capability: str
    result: Result
    evidence_id: str
    evidence_quality: str
    limitations: list[str]
    provenance: dict[str, Any]
    operator_group: dict[str, Any]

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> RouterValidationExport:
        validate_with_schema(value, ROUTER_EXPORT_SCHEMA)
        return cls(
            schema_version=value["schema_version"],
            subject_did=value["subject_did"],
            capability=value["capability"],
            result=value["result"],
            evidence_id=value["evidence_id"],
            evidence_quality=value["evidence_quality"],
            limitations=list(value["limitations"]),
            provenance=dict(value["provenance"]),
            operator_group=dict(value["operator_group"]),
        )


@dataclass(frozen=True)
class MailboxResultPreview:
    schema_version: str
    request_id: str
    evidence_id: str
    verdict: Result
    evidence_hash: str
    bench_did: str
    original_sender_did: str | None
    reply_room: str | None
    common_control_disclosure: bool
    independent_evidence: bool
    result_delivery_status: str
    phase: str

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> MailboxResultPreview:
        validate_with_schema(value, MAILBOX_RESULT_SCHEMA)
        return cls(
            schema_version=value["schema_version"],
            request_id=value["request_id"],
            evidence_id=value["evidence_id"],
            verdict=value["verdict"],
            evidence_hash=value["evidence_hash"],
            bench_did=value["bench_did"],
            original_sender_did=value["original_sender_did"],
            reply_room=value.get("reply_room"),
            common_control_disclosure=value["common_control_disclosure"],
            independent_evidence=value["independent_evidence"],
            result_delivery_status=value["result_delivery_status"],
            phase=value["phase"],
        )
