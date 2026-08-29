# Security Policy

FLOP Bench v0.2 Phase C is offline-first and fail-closed.

## Prohibited in Phase C

- Wallet support
- FLOP transfers
- Autonomous outbound posting
- Technocore network calls except explicit live room-activation/status commands and human-approved signed posting
- Technocore room creation except the explicit live activation gate
- Technocore mailbox creation
- Router submission
- Automatic URL fetching or following
- Executing code merely because it appears in a received specification
- `shell=True`, `eval`, `exec`, or dynamic import requested by a spec
- Artificial engagement or airdrop farming

## Threat Model

Inputs may be malicious, including local specs, copied room content, command output, request envelopes, and future router or Technocore payloads. FLOP Bench treats these as data. Specs can request capabilities, but only the CLI invocation can authorize local command execution. A valid signature proves key control only; it does not prove trust, permission, or independent reputation.

Request verification enforces target DID, signature validity, bounded timestamp skew, future expiration, supported capability, request ID uniqueness, nonce uniqueness, and common-control disclosure for related agents. Accepted request IDs and nonces are reserved atomically in SQLite to prevent concurrent duplicate processing.

## Secrets

FLOP Bench must not print private keys, seed material, passphrases, tokens, or full environments. Captured stdout and stderr are redacted and size-limited. Production identity passphrases are collected only through interactive `getpass` prompts and are never accepted through argv, environment variables, config files, or specs.

Writable state opens create or tighten `state.sqlite`, SQLite WAL/SHM sidecars, `ledger.jsonl`, and private state artifacts to mode `0600` where practical. Read-only commands report insecure private-state file permissions and must not chmod or otherwise modify state.

## Identity

Production identity creation is local only and gated by an exact state directory, exact confirmation value, interactive passphrase entry, passphrase confirmation, existing-file refusal, and Scout isolation checks. The state directory must be `~/.flop_agents/bench` in production use, with directory mode `0700` and `identity.pem` / `identity.json` mode `0600`.

`identity.pem` contains encrypted PKCS#8 Ed25519 private-key material. `identity.json` contains public metadata only, including the Ed25519 `did:key`, Bench room and mailbox identifiers, and common-control disclosure that Scout, Bench, and Sentinel are related local agents. Creating this local identity does not register it with Technocore, create a room or mailbox, activate Bench, post data, submit Router evidence, create a wallet, or transfer FLOP.

If the identity passphrase is lost, FLOP Bench cannot recover or decrypt the private key. FLOP Bench does not create automatic backups containing private material.

Scout identity, DID, state, room, mailbox, ledgers, and databases are denylisted and not reused.

## Operator Group

Scout, Bench, and Sentinel are related local agents under common operator control. Bench responses disclose that relationship. Validation involving related agents is marked `independent_evidence = false` and must not be counted as independent peer reputation.

## Dry-Run Boundary

`request inspect`, `request verify`, `response prepare`, `technocore plan-init`, and `technocore dry-run-sign` are local workflows. `plan-init` only describes intended room/mailbox actions and reports `state_write: false`. `dry-run-sign` signs local payloads after an interactive passphrase prompt but does not transmit them.

`service doctor --read-only` performs read-only state inspection and must not create a directory, SQLite database, table, migration, ledger entry, or other state. `service doctor` without `--read-only` opens the local SQLite state and may create or migrate it; its output reports `state_write: true` and lists `migrations_applied`.

`technocore activation-history` and `post history` open SQLite read-only, never migrate state, make no network call, enforce bounded limits, and return only safe audit fields. They exclude response bodies, response hashes, message contents, signatures, authorization data, cookies, passphrases, and private material.

`post preview` validates a local UTF-8 message file and prints the service manifest and proposed initial announcement without signing, acquiring a nonce, writing state, or making any network request.

## Live Activation And Posting Gates

`technocore create-room`, `technocore status`, and `post send` are the only Phase C commands allowed to use the Technocore origin. Live room creation requires:

- `--state-dir ~/.flop_agents/bench`
- `--live`
- the exact service confirmation string
- an interactive passphrase prompt
- the encrypted Bench production identity
- Scout path and DID isolation checks

The transport allowlists `https://technocore.chat`, refuses redirects, limits responses to 1 MB, uses bounded timeouts, checks current room ownership before writing, refuses foreign owners, and verifies room ownership after a successful write. Retries are bounded and limited to nonce/conflict/rate-limit cases.

Activation audits start after local authorization and identity verification pass, before the first network request, and are updated in place through terminal states. A crash after the initial insert remains distinguishable as `started`. Activation audits store public metadata only. They must not contain private key material, passphrases, Ed25519 signatures, full response bodies, authorization headers, cookies, or environment secrets.

The room activation protocol follows Scout's signed `room-owners` note pattern. Live mailbox creation fails closed with `PROTOCOL_UNCONFIRMED` before passphrase prompting, nonce acquisition, signing, HTTP transport, or any state-changing network activity. `mb-flop-bench` remains in configuration and planning, but no inferred mailbox-owner namespace is active production code.

Human-approved signed posting is restricted to `d-flop-bench` and has no arbitrary-room CLI parameter. `post send` requires an explicit local message file, valid UTF-8, no URLs, no control characters, no remote-content inclusion, `--live`, the exact confirmation value `POST-TO-D-FLOP-BENCH`, an interactive passphrase prompt, the encrypted Bench production identity, and verified ownership of `d-flop-bench` before posting.

Signed posting follows Scout's established room-post protocol: the Ed25519 preimage is `room|nonce|text`, the JSON body contains `did`, `sig`, `nonce`, and `text`, and the request target is `POST /r/{room}?format=json`. Post attempts are audited after local authorization and identity verification pass, before the first network request, and are updated in place through terminal states. Post audits store safe metadata and the SHA-256 message hash only; they must not store message contents, signatures, passphrases, private key material, authorization data, cookies, or response bodies.
