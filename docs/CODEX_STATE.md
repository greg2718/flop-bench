# Codex State

Last updated: 2026-09-01.

- Current main commit: `f806029795af762db508bd5650ec268a83798f81`.
- Current development branch: `chore/codex-efficiency-context`.
- Production Bench DID: `did:key:z6MkqqqEMxujBTEAvoanSx6pVBMMZzLP7gMUcmNVdYHS3BVk`.
- Scout DID: `did:key:z6MkfJnczowbivU9SEDcZ77MEpKUfQTVbcD3i1gcwsfo4yL1`.
- Owned room: `d-flop-bench`.
- Published announcement: sequence `1`, confirmed nonce `1788093739511`.
- Mailbox: `mb-flop-bench`, advertised by DID note but not yet polled.
- DID note: production publish reportedly succeeded and was reportedly verified already-matching; local reconciliation/audit state support is present, but live reconcile has not been run by this implementation.
- Schema migrations: `1..10` in SQLite, current `SCHEMA_VERSION = 10`; migration 8 adds the idempotent local `mailbox_intake_activation` record, migration 9 adds canonical valid-request storage plus `mailbox_request_executions`, and migration 10 adds private result-delivery audit history.
- Completed features: offline verification, identity ceremony, signed request/response preparation, room ownership activation, signed posting, signed-POST request-string/response-integer nonce compatibility for documented 1-19 digit response nonces, exact-content idempotency, nonce-attributed reconciliation, monotonic post audit transitions, protocol-check diagnostics, Phase D mailbox intake/review with local activation gating and explicit read-only activation-preview readiness blockers, lossless remote nonce text storage, DID-note preview/status/publish/reconcile audit plumbing, separate mailbox service-capability validation, Phase E1 manual passive approved-request execution/result-preview plumbing with read-only execution-preview blocker completeness and metadata-only request reporting, and Phase E2 human-approved signed idempotent result delivery to exact canonical `mb-*` reply rooms only.
- Phase E1 execution state machine: `reserved -> running -> completed`, with visible reserved/running interruptions requiring future explicit manual recovery; completed executions are idempotent and not overwritten by weaker retries.
- Phase E1 supported remote procedure: one bounded `literal_equality` JSON-scalar comparison only; `approved-local-command`, `file-check`, filesystem adapters, shell/subprocess/import/eval, URL/network access, and remote adapter selection remain forbidden.
- Evidence/result schemas: evidence bundles now allow top-level `request_id`; offline result preview uses `flop-bench.mailbox-result.v0.1` with `result_delivery_status: not_sent`.
- Production safety posture: offline-first; no autonomous service loop, scheduler, wallet, FLOP transfer, Router submission, URL following, inferred mailbox reply, or autonomous posting. Result delivery exists only through explicit `result send --live --confirm SEND-FLOP-BENCH-RESULT` after pure preview and exact `mb-*` destination match.
- Current production facts: `mb-flop-bench` intake is reportedly active, polling is manual, requests enter `pending_human_review`, approval changes status to `approved_for_manual_execution` only, and existing request `BENCH-FIXTURE-20260831T155341Z` is expired plumbing evidence that must not execute or count as independent reputation.
- Credential status: production identity `SET`; wallet credentials `MISSING`; mailbox polling credentials `MISSING`.
- Latest targeted E2 result-delivery checks: `.venv/bin/pytest -q -k 'result and (delivery or reconcile or history)'` passed with 6 selected tests; `.venv/bin/ruff check src tests` and `.venv/bin/mypy src` passed on 2026-09-01. Latest full gate remains the prior 2026-09-01 run.
- Scheduler/daemon status: none.
- Safe production sequence: merge reviewed code; run `flop-bench service doctor --state-dir ~/.flop_agents/bench --read-only`; explicitly run normal `flop-bench service doctor --state-dir ~/.flop_agents/bench` to apply pending migrations; rerun `flop-bench mailbox activation-preview --state-dir ~/.flop_agents/bench`; activate only when `can_activate` is true.
- Next immediate task: Review Phase E2 result-delivery implementation before any production use; mailbox polling/activation and Router updates remain separately gated.

For durable design context, see [ARCHITECTURE.md](ARCHITECTURE.md), [RISK_CONSTITUTION.md](RISK_CONSTITUTION.md), and [TECHNOCORE_EVIDENCE.md](TECHNOCORE_EVIDENCE.md).
