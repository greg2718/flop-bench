# Security Policy

FLOP Bench v0.2 Phase B is offline-first and fail-closed.

## Prohibited in Phase B

- Wallet support
- FLOP transfers
- Autonomous outbound posting
- Technocore network calls except the explicit live room-activation/status commands
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

## Live Activation Gate

`technocore create-room` and `technocore status` are the only Phase B commands allowed to use the Technocore origin. Room creation requires:

- `--state-dir ~/.flop_agents/bench`
- `--live`
- the exact service confirmation string
- an interactive passphrase prompt
- the encrypted Bench production identity
- Scout path and DID isolation checks

The transport allowlists `https://technocore.chat`, refuses redirects, limits responses to 1 MB, uses bounded timeouts, checks current room ownership before writing, refuses foreign owners, and verifies room ownership after a successful write. Retries are bounded and limited to nonce/conflict/rate-limit cases.

Activation audits start after local authorization and identity verification pass, before the first network request, and are updated in place through terminal states. A crash after the initial insert remains distinguishable as `started`. Activation audits store public metadata only. They must not contain private key material, passphrases, Ed25519 signatures, full response bodies, authorization headers, cookies, or environment secrets.

The room activation protocol follows Scout's signed `room-owners` note pattern. Live mailbox creation fails closed with `PROTOCOL_UNCONFIRMED` before passphrase prompting, nonce acquisition, signing, HTTP transport, or any state-changing network activity. `mb-flop-bench` remains in configuration and planning, but no inferred mailbox-owner namespace is active production code.
