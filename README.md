# FLOP Bench v0.1

FLOP Bench is an offline-first testing, reproducibility, verification, and proof-of-work agent for the Technocore/FLOP ecosystem.

v0.1 is deliberately local. It can create an encrypted local Bench identity only after an explicit provisioning gate, but it does not join rooms, create mailboxes, post outbound messages, fetch URLs, integrate wallets, transfer FLOP, submit Router records, or make Technocore network calls.

## Architecture

FLOP Bench has four local layers:

- JSON schemas and typed validation for test specs, evidence bundles, and Agent Router validation exports.
- Deterministic adapters for passive checks: file existence, SHA-256, UTF-8 containment, JSON path equality, and JSON Schema validation.
- An optional approved-local command adapter gated only by the human CLI flag `--allow-local-exec`.
- Local state: portable evidence JSON, an append-only hash-chained JSONL ledger, and a small SQLite database with migrations.

The intended production state path is `~/.flop_agents/bench/`, but v0.1 write commands require an explicit `--state-dir` so accidental production initialization does not occur.

## Trust Boundaries

All remote or agent-supplied content is untrusted data. Specifications cannot grant execution permission. URLs in specifications are rejected rather than fetched or followed. Captured command output is redacted for likely secrets and truncated.

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
- Creating it does not register Bench with Technocore, create a room or mailbox, activate Bench, post anything, submit Router evidence, create a wallet, or transfer FLOP.
- If the passphrase is lost, FLOP Bench cannot decrypt the private key. There is no backup or recovery path in v0.1.

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

## Evidence

Evidence bundles are portable JSON. `evidence_id` is derived from canonical substantive inputs and observations, excluding timestamps and ledger linkage, so identical specs and observations produce identical IDs. The ledger hash chain records `previous_ledger_hash` and `record_hash`.

Example specs live in `examples/`:

- `passive-file-check.json`
- `blocked-local-command.json`
- `approved-local-command.json`

## Future Integration Points

The Technocore transport is present only as a disabled fail-closed interface for `send`, `post`, `join`, `fetch`, and `transfer`. Agent Router integration starts with `flop-bench router-export EVIDENCE.json`, including common-operator disclosure.

Deletion or replacement of the entire ledger requires an external checkpoint to detect. The local hash chain detects edits, middle deletion, reordering, and broken linkage within the retained ledger.
