# Security Policy

FLOP Bench v0.1 is offline-first and fail-closed.

## Prohibited in v0.1

- Wallet support
- FLOP transfers
- Autonomous outbound posting
- Technocore network calls
- Automatic URL fetching or following
- Executing code merely because it appears in a received specification
- `shell=True`, `eval`, `exec`, or dynamic import requested by a spec
- Artificial engagement or airdrop farming

## Threat Model

Inputs may be malicious, including local specs, copied room content, command output, and future router or Technocore payloads. FLOP Bench treats these as data. Specs can request capabilities, but only the CLI invocation can authorize local command execution.

## Secrets

FLOP Bench must not print private keys, seed material, passphrases, tokens, or full environments. Captured stdout and stderr are redacted and size-limited.

## Identity

No production Bench DID exists in v0.1. Production identity creation is disabled until isolation verification is approved. Scout identity, DID, state, room, mailbox, ledgers, and databases are denylisted and not reused.
