# Codex State

Last updated: 2026-08-31.

- Current main commit: `f806029795af762db508bd5650ec268a83798f81`.
- Current development branch: `chore/codex-efficiency-context`.
- Production Bench DID: `did:key:z6MkqqqEMxujBTEAvoanSx6pVBMMZzLP7gMUcmNVdYHS3BVk`.
- Scout DID: `did:key:z6MkfJnczowbivU9SEDcZ77MEpKUfQTVbcD3i1gcwsfo4yL1`.
- Owned room: `d-flop-bench`.
- Published announcement: sequence `1`, confirmed nonce `1788093739511`.
- Mailbox: `mb-flop-bench`, advertised by DID note but not yet polled.
- DID note: production publish reportedly succeeded; local Technocore framing parser fix is present, but live status recheck has not been run.
- Schema migrations: `1..5` in SQLite, current `SCHEMA_VERSION = 5`.
- Completed features: offline verification, identity ceremony, signed request/response preparation, room ownership activation, signed posting, exact-content idempotency, nonce-attributed reconciliation, monotonic post audit transitions, protocol-check diagnostics, Phase D mailbox intake/review, and DID-note preview/status/publish plumbing.
- Production safety posture: offline-first; no autonomous service loop, scheduler, wallet, FLOP transfer, Router submission, URL following, request execution, mailbox reply, or autonomous posting. `mailbox poll --network`, `identity-note status`, and `identity-note publish --live` are implemented but require explicit human operation.
- Current blockers: production mailbox has not been polled by this implementation.
- Credential status: production identity `SET`; wallet credentials `MISSING`; mailbox polling credentials `MISSING`.
- Latest full test count: 100 tests collected and passing.
- Scheduler/daemon status: none.
- Next immediate task: Verify DID-note status with the framing-aware parser, then perform the first separately authorized mailbox poll if desired.

For durable design context, see [ARCHITECTURE.md](ARCHITECTURE.md), [RISK_CONSTITUTION.md](RISK_CONSTITUTION.md), and [TECHNOCORE_EVIDENCE.md](TECHNOCORE_EVIDENCE.md).
