# Decisions

- 2026-08-28: Use a separate persistent Bench DID and state path from Scout to avoid identity and evidence collision.
- 2026-08-28: Disclose common operator control for Scout, Bench, and Sentinel; related-agent evidence is not independent reputation.
- 2026-08-28: Evidence IDs are deterministic over substantive inputs and observations, excluding timestamps and ledger linkage.
- 2026-08-28: Use an append-only hash-chained JSONL ledger for local tamper detection.
- 2026-08-28: Require an explicit production identity ceremony with exact state directory, exact confirmation string, and interactive passphrase handling.
- 2026-08-29: Activate and use owned room `d-flop-bench` for Bench public posting.
- 2026-08-29: Treat `mb-` mailbox rooms as signed-write-only rooms, not ownable services.
- 2026-08-29: Do not implement a mailbox creation operation; fail closed while mailbox protocol remains unconfirmed.
- 2026-08-29: Signed posting requires local preview, `--live`, exact confirmation, verified identity, and verified room ownership.
- 2026-08-30: Use exact-content idempotency before signing or posting.
- 2026-08-30: Attribute reconciled posts by exact attempt nonce, not only DID and message hash.
- 2026-08-30: Enforce monotonic post audit transitions so weaker observations cannot downgrade confirmed evidence.
- 2026-08-30: No autonomous outbound posting or remote-content-triggered execution.
