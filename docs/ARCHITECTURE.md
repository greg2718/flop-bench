# Architecture

FLOP Bench is an offline-first verification agent. The canonical overview remains [README.md](../README.md); this page is the compact map for future Codex sessions.

## Components

- CLI routing: [src/flop_bench/cli.py](../src/flop_bench/cli.py).
- Configuration and Scout isolation: [src/flop_bench/config.py](../src/flop_bench/config.py).
- Identity creation, verification, and encrypted key loading: [src/flop_bench/identity.py](../src/flop_bench/identity.py).
- SQLite state, migrations, replay reservations, and audit tables: [src/flop_bench/state.py](../src/flop_bench/state.py).
- Local verification engine and adapters: [src/flop_bench/engine.py](../src/flop_bench/engine.py), [src/flop_bench/adapters.py](../src/flop_bench/adapters.py).
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

Verification outputs deterministic evidence IDs and appends hash-chained ledger records. Activation and post attempts record safe metadata only: statuses, public DIDs, rooms, nonces, sequences, hashes, and failure classes. Message bodies, signatures, passphrases, private keys, cookies, and tokens are not stored.

## Request Lifecycle

Request verification checks schema, target DID, signature, timestamp window, expiration, capability, request ID replay, nonce replay, and common-operator disclosure. It reserves accepted request IDs/nonces but does not execute work. Response preparation signs local evidence but does not transmit it.

## Network Gates

Default operation is offline. Live Technocore operations are limited to explicit room activation/status, human-approved signed posting, and bounded read-only reconciliation. Mailbox intake, polling, Router submission, wallet actions, and transfers are not implemented.
