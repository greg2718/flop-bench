# Decisions

- 2026-08-28: Use a separate persistent Bench DID and state path from Scout to avoid identity and evidence collision.
- 2026-08-28: Disclose common operator control for Scout, Bench, and Sentinel; related-agent evidence is not independent reputation.
- 2026-08-28: Evidence IDs are deterministic over substantive inputs and observations, excluding timestamps and ledger linkage.
- 2026-08-28: Use an append-only hash-chained JSONL ledger for local tamper detection.
- 2026-08-28: Require an explicit production identity ceremony with exact state directory, exact confirmation string, and interactive passphrase handling.
- 2026-08-29: Activate and use owned room `d-flop-bench` for Bench public posting.
- 2026-08-29: Treat `mb-` mailbox rooms as signed-write-only rooms, not ownable services.
- 2026-08-29: Do not implement a mailbox creation operation; `mb-flop-bench` is activated only by local intake state after DID-note reconciliation.
- 2026-08-29: Signed posting requires local preview, `--live`, exact confirmation, verified identity, and verified room ownership.
- 2026-08-30: Use exact-content idempotency before signing or posting.
- 2026-08-30: Attribute reconciled posts by exact attempt nonce, not only DID and message hash.
- 2026-08-30: Enforce monotonic post audit transitions so weaker observations cannot downgrade confirmed evidence.
- 2026-08-30: No autonomous outbound posting or remote-content-triggered execution.
- 2026-09-01: Gate mailbox request acceptance with an idempotent local SQLite activation record; inactive valid requests are classified as `intake_inactive`, and active valid requests enter `pending_human_review` only.
- 2026-09-01: Phase E1 permits only manual approved-request execution of one bounded deterministic `literal_equality` remote procedure; remote requests cannot select local adapters.
- 2026-09-01: Approval never overrides expiration. `execute-passive` rechecks `expires_at` immediately before reservation/execution and records monotonic execution states.
- 2026-09-01: Phase E1 result preparation is offline preview only. `flop-bench.mailbox-result.v0.1` is not signed or delivered, and Router updates remain disabled.
- 2026-09-01: The existing Scout fixture `BENCH-FIXTURE-20260831T155341Z` is expired plumbing evidence only; it must not execute and is not independent reputation.
