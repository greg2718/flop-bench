from __future__ import annotations

from typing import Any

from jsonschema import Draft202012Validator

from .exceptions import ValidationError

ASSERTION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["expect"],
    "additionalProperties": False,
    "properties": {"expect": {"type": "string", "minLength": 1}},
}

PASSIVE_STEP_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "object",
        "required": ["adapter", "path"],
        "additionalProperties": False,
        "properties": {
            "adapter": {"const": "file_exists"},
            "path": {"type": "string", "minLength": 1},
        },
    },
    {
        "type": "object",
        "required": ["adapter", "path", "sha256"],
        "additionalProperties": False,
        "properties": {
            "adapter": {"const": "file_sha256"},
            "path": {"type": "string", "minLength": 1},
            "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
    },
    {
        "type": "object",
        "required": ["adapter", "path", "text"],
        "additionalProperties": False,
        "properties": {
            "adapter": {"const": "text_contains"},
            "path": {"type": "string", "minLength": 1},
            "text": {"type": "string"},
        },
    },
    {
        "type": "object",
        "required": ["adapter", "path", "json_path", "equals"],
        "additionalProperties": False,
        "properties": {
            "adapter": {"const": "json_path_equals"},
            "path": {"type": "string", "minLength": 1},
            "json_path": {"type": "string", "minLength": 1},
            "equals": True,
        },
    },
    {
        "type": "object",
        "required": ["adapter", "path", "schema_path"],
        "additionalProperties": False,
        "properties": {
            "adapter": {"const": "json_schema"},
            "path": {"type": "string", "minLength": 1},
            "schema_path": {"type": "string", "minLength": 1},
        },
    },
]

LOCAL_COMMAND_STEP_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["adapter", "argv", "cwd"],
    "additionalProperties": False,
    "properties": {
        "adapter": {"const": "local_command"},
        "argv": {
            "type": "array",
            "minItems": 1,
            "items": {"type": "string", "minLength": 1},
        },
        "cwd": {"type": "string", "minLength": 1},
        "timeout_seconds": {"type": "number", "exclusiveMinimum": 0},
        "expect_exit_code": {"type": "integer"},
        "env": {"type": "object", "additionalProperties": {"type": "string"}},
    },
}

PROCEDURE_STEP_SCHEMA: dict[str, Any] = {
    "oneOf": [*PASSIVE_STEP_SCHEMAS, LOCAL_COMMAND_STEP_SCHEMA]
}

TEST_SPEC_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://flop-bench.local/schemas/test-spec-v0.1.json",
    "type": "object",
    "required": [
        "schema_version",
        "claim_id",
        "hypothesis",
        "requested_capabilities",
        "mode",
        "procedure",
        "assertions",
        "failure_conditions",
        "provenance",
    ],
    "additionalProperties": False,
    "properties": {
        "schema_version": {"const": "flop-bench.test-spec.v0.1"},
        "claim_id": {"type": "string", "minLength": 1},
        "hypothesis": {"type": "string", "minLength": 1},
        "requested_capabilities": {"type": "array", "items": {"type": "string"}},
        "mode": {"enum": ["passive", "approved-local"]},
        "procedure": {"type": "array", "items": PROCEDURE_STEP_SCHEMA},
        "assertions": {"type": "array", "items": ASSERTION_SCHEMA},
        "failure_conditions": {"type": "array", "items": {"type": "string"}},
        "provenance": {"type": "object"},
    },
}

EVIDENCE_BUNDLE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://flop-bench.local/schemas/evidence-bundle-v0.1.json",
    "type": "object",
    "required": [
        "schema_version",
        "evidence_id",
        "claim_id",
        "hypothesis",
        "capabilities",
        "procedure",
        "observations",
        "result",
        "failure_conditions",
        "provenance",
        "safety_report",
        "previous_ledger_hash",
        "record_hash",
    ],
    "additionalProperties": False,
    "properties": {
        "schema_version": {"const": "flop-bench.evidence-bundle.v0.1"},
        "evidence_id": {"type": "string"},
        "claim_id": {"type": "string"},
        "hypothesis": {"type": "string"},
        "capabilities": {"type": "array", "items": {"type": "string"}},
        "procedure": {"type": "array", "items": {"type": "object"}},
        "observations": {"type": "array", "items": {"type": "object"}},
        "result": {"enum": ["PASS", "PARTIAL", "FAIL"]},
        "failure_conditions": {"type": "array", "items": {"type": "string"}},
        "provenance": {"type": "object"},
        "safety_report": {"type": "object"},
        "previous_ledger_hash": {"type": ["string", "null"]},
        "record_hash": {"type": "string"},
        "created_at": {"type": "string"},
        "input_hashes": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["path", "sha256"],
                "additionalProperties": False,
                "properties": {
                    "path": {"type": "string"},
                    "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                },
            },
        },
        "artifact_hash": {"type": "string"},
        "assertions": {"type": "array", "items": ASSERTION_SCHEMA},
    },
}

ROUTER_EXPORT_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://flop-bench.local/schemas/router-validation-export-v0.1.json",
    "type": "object",
    "required": [
        "schema_version",
        "subject_did",
        "capability",
        "result",
        "evidence_id",
        "evidence_quality",
        "limitations",
        "provenance",
        "operator_group",
    ],
    "additionalProperties": False,
    "properties": {
        "schema_version": {"const": "flop-bench.router-validation-export.v0.1"},
        "subject_did": {"type": ["string", "null"]},
        "capability": {"type": "string"},
        "result": {"enum": ["PASS", "PARTIAL", "FAIL"]},
        "evidence_id": {"type": "string"},
        "evidence_quality": {"type": "string"},
        "limitations": {"type": "array", "items": {"type": "string"}},
        "provenance": {"type": "object"},
        "operator_group": {
            "type": "object",
            "required": ["common_control_disclosure", "operator_group_id", "note"],
            "additionalProperties": False,
            "properties": {
                "common_control_disclosure": {"const": True},
                "operator_group_id": {"type": "string", "minLength": 1},
                "note": {"type": "string", "minLength": 1},
            },
        },
    },
}


def validate_with_schema(instance: dict[str, Any], schema: dict[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(schema).iter_errors(instance),
        key=lambda err: err.path,
    )
    if errors:
        first = errors[0]
        path = ".".join(str(part) for part in first.path) or "<root>"
        raise ValidationError(f"schema validation failed at {path}: {first.message}")


def validate_test_spec(spec: dict[str, Any]) -> None:
    validate_with_schema(spec, TEST_SPEC_SCHEMA)
