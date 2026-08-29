# Security Policy

FLOP Bench v0.2 Phase A is offline-first and fail-closed.

## Prohibited in Phase A

- Wallet support
- FLOP transfers
- Autonomous outbound posting
- Technocore network calls
- Technocore room or mailbox creation
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

If the identity passphrase is lost, Phase A cannot recover or decrypt the private key. FLOP Bench does not create automatic backups containing private material.

Scout identity, DID, state, room, mailbox, ledgers, and databases are denylisted and not reused.

## Operator Group

Scout, Bench, and Sentinel are related local agents under common operator control. Bench responses disclose that relationship. Validation involving related agents is marked `independent_evidence = false` and must not be counted as independent peer reputation.

## Dry-Run Boundary

`service doctor`, `request inspect`, `request verify`, `response prepare`, `technocore plan-init`, and `technocore dry-run-sign` are local workflows. `plan-init` only describes intended room/mailbox actions. `dry-run-sign` signs local payloads after an interactive passphrase prompt but does not transmit them. Live transport activation requires a future reviewed gate.
