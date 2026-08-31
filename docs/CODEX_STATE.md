# Codex State

Last updated: 2026-08-31.

- Current main commit: `f806029795af762db508bd5650ec268a83798f81`.
- Current development branch: `chore/codex-efficiency-context`.
- Production Bench DID: `did:key:z6MkqqqEMxujBTEAvoanSx6pVBMMZzLP7gMUcmNVdYHS3BVk`.
- Scout DID: `did:key:z6MkfJnczowbivU9SEDcZ77MEpKUfQTVbcD3i1gcwsfo4yL1`.
- Owned room: `d-flop-bench`.
- Published announcement: sequence `1`, confirmed nonce `1788093739511`.
- Mailbox: `mb-flop-bench`, not yet advertised or polled.
- Schema migrations: `1..4` in SQLite, current `SCHEMA_VERSION = 4`.
- Completed features: offline verification, identity ceremony, signed request/response preparation, room ownership activation, signed posting, exact-content idempotency, nonce-attributed reconciliation, monotonic post audit transitions, protocol-check diagnostics.
- Production safety posture: offline-first; no autonomous service loop, scheduler, wallet, FLOP transfer, mailbox polling, Router submission, URL following, or autonomous posting.
- Current blockers: Phase D mailbox intake and DID-note advertisement are not implemented.
- Credential status: production identity `SET`; wallet credentials `MISSING`; mailbox polling credentials `MISSING`.
- Latest full test count: 90 tests collected and passing.
- Scheduler/daemon status: none.
- Next immediate task: Phase D mailbox intake and DID-note advertisement.

For durable design context, see [ARCHITECTURE.md](ARCHITECTURE.md), [RISK_CONSTITUTION.md](RISK_CONSTITUTION.md), and [TECHNOCORE_EVIDENCE.md](TECHNOCORE_EVIDENCE.md).
