# Architecture

FLOP Bench is an offline-first verification agent. The canonical overview remains [README.md](../README.md); this page is the compact map for future Codex sessions.

## Components

- CLI routing: [src/flop_bench/cli.py](../src/flop_bench/cli.py).
- Configuration and Scout isolation: [src/flop_bench/config.py](../src/flop_bench/config.py).
- Identity creation, verification, and encrypted key loading: [src/flop_bench/identity.py](../src/flop_bench/identity.py).
- SQLite state, migrations, replay reservations, mailbox activation, manual execution reservations, and audit tables: [src/flop_bench/state.py](../src/flop_bench/state.py).
- Local verification engine and adapters: [src/flop_bench/engine.py](../src/flop_bench/engine.py), [src/flop_bench/adapters.py](../src/flop_bench/adapters.py).
- Manual approved-request execution and result preview: [src/flop_bench/execution.py](../src/flop_bench/execution.py).
- Request/response envelope protocol: [src/flop_bench/protocol.py](../src/flop_bench/protocol.py), [src/flop_bench/service.py](../src/flop_bench/service.py).
- Hash-chained ledger: [src/flop_bench/ledger.py](../src/flop_bench/ledger.py).
- Technocore activation transport and room ownership: [src/flop_bench/activation.py](../src/flop_bench/activation.py).
- Signed posting, idempotency, reconciliation, and diagnostics: [src/flop_bench/posting.py](../src/flop_bench/posting.py).
- Schemas: [src/flop_bench/schemas.py](../src/flop_bench/schemas.py), [schemas/](../schemas).

## Trust Boundaries

Local specs, request envelopes, Technocore room text, command output, and copied agent content are untrusted data. Signatures prove key control only. Local command execution requires explicit CLI authorization and never comes from a spec alone.

## Identity And State

Bench production state is separate from Scout state. Production identity is an encrypted Ed25519 key under the Bench state directory. Tests use temporary state only. State migrations are SQLite-backed and private-state files are tightened during writable opens.

## Evidence And Audit Flow

Verification outputs deterministic evidence IDs and appends hash-chained ledger records. Activation, post, and manual request-execution attempts record safe metadata only: statuses, public DIDs, rooms, nonces, sequences, hashes, and failure classes. Message bodies, signatures, passphrases, private keys, cookies, and tokens are not stored.

## Request Lifecycle

Request verification checks schema, target DID, signature, timestamp window, expiration, capability, request ID replay, nonce replay, and common-operator disclosure. It reserves accepted request IDs/nonces but does not execute work. Mailbox intake has a separate local SQLite activation record: inactive valid mailbox messages are classified as `intake_inactive`, while active valid messages enter `pending_human_review`.

Phase E1 adds explicit manual passive execution only. Approval changes review state but never executes. `request execution-preview` is read-only and reports blockers without creating or migrating state. `request execute-passive` requires active intake, `valid_request`, `approved_for_manual_execution`, unexpired request at execution time, supported service capability, the exact confirmation string, and a supported deterministic passive procedure. Reservation is atomic and monotonic: `reserved` to `running` to `completed`, with interrupted reservations visible until a future manual recovery operation. Completed evidence is idempotent and is not overwritten by weaker failures.

The only supported remote procedure is `literal_equality` over bounded JSON scalars. It compares JSON type and canonical JSON value; strings are never interpreted as URLs, commands, code, paths, or instructions. Remote requests cannot select local adapters such as `approved-local-command` or `file-check`.

`result preview` emits an offline `flop-bench.mailbox-result.v0.1` envelope only after completion. It does not sign, acquire a nonce, write state, post, reply, follow `reply_room`, or update Router. Phase E result delivery remains disabled.

## Network Gates

Default operation is offline. Live Technocore operations are limited to explicit room activation/status, human-approved signed posting, bounded read-only reconciliation, and separately authorized bounded mailbox polling. Phase G1 adds a supervised intake worker with a local expiring SQLite lease and bounded polling/backoff only; it cannot approve, execute, sign, reply, or update Router. Router submission, wallet actions, transfers, and deployment/supervisor configuration remain separate work.
