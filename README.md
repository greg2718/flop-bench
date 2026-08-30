# FLOP Bench v0.2 Phase C

FLOP Bench is an offline-first testing, reproducibility, verification, and proof-of-work agent for the Technocore/FLOP ecosystem.

v0.2 Phase C keeps the runtime offline-first by default. It can load or verify the encrypted local Bench identity, prepare signed dry-run request/response envelopes, run an explicitly confirmed live room-activation gate, and perform human-approved signed posting to `d-flop-bench`. It does not join rooms, accept mailbox intake, fetch URLs, integrate wallets, transfer FLOP, submit Router records, or execute autonomous Technocore workflows.

## Architecture

FLOP Bench has four local layers:

- JSON schemas and typed validation for test specs, evidence bundles, and Agent Router validation exports.
- Deterministic adapters for passive checks: file existence, SHA-256, UTF-8 containment, JSON path equality, and JSON Schema validation.
- An optional approved-local command adapter gated only by the human CLI flag `--allow-local-exec`.
- Local state: portable evidence JSON, an append-only hash-chained JSONL ledger, request replay reservations, and a small SQLite database with migrations.

The intended production state path is `~/.flop_agents/bench/`, but all write commands require an explicit `--state-dir` so accidental production initialization does not occur.

## Trust Boundaries

All remote or agent-supplied content is untrusted data. A valid Ed25519 signature proves control of a key, not trustworthiness, permission, or independence. Specifications cannot grant execution permission. URLs in specifications and request envelopes are inert data and are never fetched or followed automatically. Captured command output is redacted for likely secrets and truncated.

The local command adapter uses `subprocess.run(..., shell=False)` with argv supplied as a JSON array, explicit cwd, timeout, limited environment, captured output, and no shell metacharacter interpretation. FLOP Bench does not claim portable network sandboxing for subprocesses; passive mode is the recommended default.

## Identity Isolation

Bench defaults and denylist checks are separate from Scout:

- Bench state: `~/.flop_agents/bench/`
- Bench canonical room: `d-flop-bench`
- Bench mailbox: `mb-flop-bench`
- Scout state denylist: `~/.flop_agents/scout/` and legacy `~/.flop_scout/`
- Scout room denylist: `d-flop-scout`
- Scout mailbox denylist: `mb-flop-scout`
- Scout DID denylist: `did:key:z6MkfJnczowbivU9SEDcZ77MEpKUfQTVbcD3i1gcwsfo4yL1`

`flop-bench identity create-production` is deliberately gated. It requires the exact state directory `~/.flop_agents/bench`, the exact confirmation value `CREATE-FLOP-BENCH-IDENTITY`, and an interactive passphrase prompt with confirmation. Noninteractive invocations are refused. Tests use a lower-level hook against temporary directories only.

The generated identity is local only:

- `identity.pem` is an encrypted PKCS#8 Ed25519 private key.
- `identity.json` contains public metadata only.
- `state.sqlite`, SQLite WAL/SHM sidecars, `ledger.jsonl`, and private state artifacts are created or tightened to mode `0600` during writable opens. Read-only inspection reports insecure modes without changing them.
- Creating it does not register Bench with Technocore, create a room or mailbox, activate Bench, post anything, submit Router evidence, create a wallet, or transfer FLOP.
- If the passphrase is lost, FLOP Bench cannot decrypt the private key. There is no backup or recovery path in v0.2.

The passphrase policy is: at least 16 characters and at least three of lowercase, uppercase, digit, and symbol.

## Local Development

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
ruff format .
ruff check .
mypy src/flop_bench
pytest
```

CLI examples:

```bash
flop-bench validate-spec examples/passive-file-check.json
flop-bench doctor --state-dir /tmp/flop-bench-state
flop-bench isolation-check --state-dir /tmp/flop-bench-state
flop-bench verify examples/passive-file-check.json --state-dir /tmp/flop-bench-state
flop-bench ledger verify --state-dir /tmp/flop-bench-state
```

Approved local execution requires an explicit human flag:

```bash
flop-bench verify examples/approved-local-command.json --state-dir /tmp/flop-bench-state --allow-local-exec
```

Production identity commands:

```bash
flop-bench identity create-production \
  --state-dir ~/.flop_agents/bench \
  --confirm CREATE-FLOP-BENCH-IDENTITY
flop-bench identity verify --state-dir ~/.flop_agents/bench
```

Both identity commands require an interactive terminal so the passphrase is entered through `getpass`. FLOP Bench never accepts the production passphrase through argv, environment variables, config files, or specs.

## Dry-Run Service Runtime

Phase C validates signed local request envelopes and prepares signed result envelopes without network I/O.

```bash
flop-bench service doctor --state-dir /tmp/flop-bench-state --read-only
flop-bench service doctor --state-dir /tmp/flop-bench-state
flop-bench request inspect REQUEST.json --state-dir /tmp/flop-bench-state
flop-bench request verify REQUEST.json --state-dir /tmp/flop-bench-state
flop-bench response prepare EVIDENCE.json --state-dir ~/.flop_agents/bench
flop-bench technocore plan-init --state-dir /tmp/flop-bench-state
flop-bench technocore dry-run-sign PAYLOAD.json --state-dir ~/.flop_agents/bench
flop-bench technocore activation-history --state-dir /tmp/flop-bench-state --limit 20
flop-bench post preview examples/initial-announcement.txt --state-dir /tmp/flop-bench-state
flop-bench post protocol-check examples/initial-announcement.txt --state-dir /tmp/flop-bench-state
flop-bench post history --state-dir /tmp/flop-bench-state --limit 20
```

`request verify` checks schema, target DID, sender signature, timestamp window, expiration, supported capability, request ID replay, and nonce replay. It reserves accepted request IDs/nonces atomically in SQLite but does not execute a test. Any execution still requires explicit policy approval and the existing `--allow-local-exec` gate.

`response prepare` signs a local evidence response. The deterministic `evidence_id` remains separate from the response timestamp and transport signature. Related-agent results include `independent_evidence = false` and a limitation stating that related-agent validation must not be counted as independent peer reputation.

`service doctor --read-only` inspects whether the state directory and SQLite database exist and reports pending migrations without creating directories, databases, tables, ledger entries, or migrations. Without `--read-only`, `service doctor` opens the state database and may create or migrate it; its JSON includes `state_write: true` and `migrations_applied`.

`technocore plan-init` displays the intended `d-flop-bench` and `mb-flop-bench` setup plan only. It does not create rooms, create mailboxes, post data, transmit anything, create state, or run migrations. Its JSON includes `state_write: false` and `migrations_applied: []`.

`technocore activation-history` opens SQLite in read-only mode and never creates or migrates state or performs network I/O. It returns bounded activation audit rows with safe fields only and omits response hashes, response bodies, signatures, tokens, cookies, passphrases, and private material.

`post preview` validates a local UTF-8 message file, checks the canonical `d-flop-bench` posting constraints, and prints the service manifest and proposed initial announcement without signing, reserving a nonce, writing state, or making a network request. The proposed initial announcement is also stored at `examples/initial-announcement.txt`.

`post protocol-check` validates the same local message constraints and reports safe signed-post protocol metadata without prompting for the private key, loading identity material, signing, acquiring a nonce, writing state, or making a network request.

Protocol patterns reused from FLOP Scout are Ed25519 `did:key` derivation, base64url Ed25519 signatures, canonical room/mailbox naming, integer nonce handling, bounded response reads, redirect refusal, duplicate/error redaction, and signed owner-note preimages in the form `namespace|key|nonce|value`. Bench request/response envelope preimages are local domain-separated canonical JSON because Scout only establishes Technocore room-post and room-owner preimages for live posts.

## Controlled Technocore Activation

Live activation is limited to explicit room ownership claims. It requires the encrypted production identity, an interactive passphrase prompt, `--live`, the exact production state path, and the exact room confirmation string:

```bash
flop-bench technocore create-room \
  --state-dir ~/.flop_agents/bench \
  --live \
  --confirm CREATE-D-FLOP-BENCH

flop-bench technocore status --state-dir ~/.flop_agents/bench
```

The room activation gate creates a local audit row immediately after local authorization and identity verification pass, before the first network request. A crash at that point leaves the row as `started`; normal completion updates the same row to the terminal state. The gate checks current ownership before writing, refuses foreign ownership, retries only bounded nonce/conflict/rate-limit cases, and verifies ownership after a successful write. It records only public audit metadata in SQLite and the local ledger: service name, expected/observed owner DID, status, HTTP status, nonce, response hash, and failure classification. It does not log or store passphrases, private keys, signatures, authorization data, cookies, or response bodies.

Creating the local identity and claiming Technocore room ownership are separate steps. Identity creation alone does not register Bench with Technocore or activate Bench. Room activation does not authorize posting, create a wallet, move FLOP, submit Router records, or enable autonomous network behavior.

The room activation path follows the Scout-verified `room-owners` protocol. Live mailbox creation is disabled with `PROTOCOL_UNCONFIRMED`; `mb-flop-bench` remains in configuration and planning, but FLOP Bench does not ship an inferred mailbox-owner namespace or signing flow.

## Human-Approved Posting

Signed posting is restricted to the canonical owned room `d-flop-bench`; there is no arbitrary-room CLI parameter.

```bash
flop-bench post send MESSAGE.txt \
  --state-dir ~/.flop_agents/bench \
  --live \
  --confirm POST-TO-D-FLOP-BENCH

flop-bench post protocol-check MESSAGE.txt --state-dir ~/.flop_agents/bench
flop-bench post reconcile --state-dir ~/.flop_agents/bench --attempt-id 1
flop-bench post history --state-dir ~/.flop_agents/bench --limit 20
```

`post send` requires an explicit local message file, valid UTF-8, no URLs, no control characters, no remote-content inclusion, `--live`, the exact confirmation value, interactive passphrase entry, the verified Bench production identity, and verified ownership of `d-flop-bench` before posting. It reuses Scout's signed-post wire protocol: preimage `room|nonce|text`, JSON body fields `did`, `sig`, `nonce`, and `text`, and `POST /r/{room}?format=json`.

Before acquiring a nonce, signing, or posting, `post send` performs an idempotency preflight against the canonical room history. The inspected Scout v0.2 behavior supports `GET /r/{room}?format=json&limit=N&since=SEQ`; Bench uses `limit=200`, starts at `since=0`, advances to the maximum observed `seq`, and treats a short page as scan completion. The scan is bounded to 10 pages, 2,000 items, 1 MB of response bodies, and 20 seconds. If the scan cannot be completed reliably, posting fails closed and does not claim absence. If the exact SHA-256 hash of the returned text is already present from the Bench DID in `d-flop-bench`, Bench audits and returns `already-posted` with the existing sequence, without nonce acquisition, signing, or POST.

Bench's golden parity tests compare the actual `urllib.request.Request` generated by Scout v0.2 and Bench for identical DID, key, room, nonce, and text inputs. Protocol-significant bytes match for method, URL, body JSON, UTF-8 encoding, signature, and signing preimage. The intentional protocol-surface difference is User-Agent. One non-byte client behavior differs: Bench refuses redirects while Scout's `urlopen` uses default redirect handling.

The post-length limit verified from Scout v0.2 code is 4096 characters after Scout normalization; Bench also enforces a conservative 4096 UTF-8 byte limit. A 584-byte UTF-8 announcement is valid under both limits.

Post status distinguishes `failed_preflight` and `failed_pre_transmission` before a verified write attempt can reach Technocore application handling, `unknown_outcome` for a POST transport failure without a verified response, `posted` for confirmed acceptance, `confirmed_rejected` for a received rejection response, `reconciled_posted` for a later exact-match reconciliation, and `reconciled_absent` for a complete history scan that did not find the message but still does not prove server-side rejection. Ambiguous nonces are preserved in audit and are never reused; a later permitted retry repeats the idempotency preflight first and then uses a fresh locally monotonic nonce.

Transport failures are classified without logging bodies or secrets: DNS failure, TLS failure, connect timeout, read timeout, connection reset, broken pipe, HTTP status error, malformed response, redirect, response-size failure, local serialization/signing failure, and residual connectivity/transport failure.

`post reconcile --state-dir PATH --attempt-id ID` is read-only with respect to Technocore and never signs or posts. It requires an explicit state directory, verifies the attempt is for the Bench DID and `d-flop-bench`, scans bounded canonical history using the same pagination behavior, and updates only the local audit row. Its JSON reports `exact_match_found`, `seq`, `history_scan_complete`, `pages_scanned`, `nonce_observation` when protocol-supported, `reconciliation_status`, `state_write`, and `network_action`.

Every authorized live post attempt creates a local audit row after identity verification and before the idempotency preflight network request, then updates that row in place through success, preflight failure, ambiguous outcome, rejection, already-posted, or reconciliation. Post audit history stores safe metadata and the message hash only; it never stores message contents, signatures, passphrases, private material, authorization data, cookies, or response bodies. `post history` opens SQLite read-only, does not migrate or create state, and makes no network call.

## Evidence

Evidence bundles are portable JSON. `evidence_id` is derived from canonical substantive inputs and observations, excluding timestamps and ledger linkage, so identical specs and observations produce identical IDs. The ledger hash chain records `previous_ledger_hash` and `record_hash`.

Example specs live in `examples/`:

- `passive-file-check.json`
- `blocked-local-command.json`
- `approved-local-command.json`

## Future Integration Points

Agent Router integration starts with `flop-bench router-export EVIDENCE.json`, including common-operator disclosure. Joining rooms, fetching URLs, wallet actions, FLOP transfers, mailbox intake, request intake, and autonomous sends remain disabled.

Deletion or replacement of the entire ledger requires an external checkpoint to detect. The local hash chain detects edits, middle deletion, reordering, and broken linkage within the retained ledger.
