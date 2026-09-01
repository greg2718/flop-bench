# Security Policy

FLOP Bench v0.2 Phase C is offline-first and fail-closed.

## Prohibited in Phase C

- Wallet support
- FLOP transfers
- Autonomous outbound posting
- Technocore network calls except explicit live room-activation/status commands, human-approved signed posting, bounded read-only post reconciliation, bounded mailbox polling with `--network`, and explicit DID-note status/publish operations
- Technocore room creation except the explicit live activation gate
- Technocore mailbox creation; `mb-flop-bench` is a signed-write-only append room
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

`post preview` validates a local UTF-8 message file and prints the service manifest and proposed initial announcement without signing, acquiring a nonce, writing state, or making any network request. `post protocol-check` reports safe local protocol metadata and Scout parity status without prompting for or loading the private key, signing, acquiring a nonce, writing state, or making a network request.

`mailbox status`, `mailbox activation-preview`, `mailbox poll` without `--network`, `mailbox messages`, `mailbox inspect`, `request queue`, and `request show` are local-only. They do not sign, post, reply, fetch URLs, execute message content, acquire nonces, or update Router. `mailbox activation-preview` is pure and does not create state or migrate. `mailbox activate` and `mailbox deactivate` are local SQLite state changes only; activation requires exact confirmation, existing Bench state, and a prior local DID-note reconciliation showing the expected mailbox advertisement. `request approve` and `request reject` are local review-state updates only; approval means `approved_for_manual_execution`, not execution authorization.

## Live Activation And Posting Gates

`technocore create-room`, `technocore status`, `post send`, and `post reconcile` are the only Phase C commands allowed to use the Technocore origin. Live room creation requires:

- `--state-dir ~/.flop_agents/bench`
- `--live`
- the exact service confirmation string
- an interactive passphrase prompt
- the encrypted Bench production identity
- Scout path and DID isolation checks

The transport allowlists `https://technocore.chat`, refuses redirects, limits responses to 1 MB, uses bounded timeouts, checks current room ownership before writing, refuses foreign owners, and verifies room ownership after a successful write. Retries are bounded and limited to nonce/conflict/rate-limit cases.

Activation audits start after local authorization and identity verification pass, before the first network request, and are updated in place through terminal states. A crash after the initial insert remains distinguishable as `started`. Activation audits store public metadata only. They must not contain private key material, passphrases, Ed25519 signatures, full response bodies, authorization headers, cookies, or environment secrets.

The room activation protocol follows Scout's signed `room-owners` note pattern. Live mailbox creation fails closed with `MAILBOX_CREATION_NOT_REQUIRED` before passphrase prompting, nonce acquisition, signing, HTTP transport, or any state-changing network activity. `mb-flop-bench` is a signed-write-only Technocore append room and has no ownership or creation operation.

Human-approved signed posting is restricted to `d-flop-bench` and has no arbitrary-room CLI parameter. `post send` requires an explicit local message file, valid UTF-8, no URLs, no control characters, no remote-content inclusion, `--live`, the exact confirmation value `POST-TO-D-FLOP-BENCH`, an interactive passphrase prompt, the encrypted Bench production identity, and verified ownership of `d-flop-bench` before posting.

Signed posting follows Scout's established room-post protocol: the Ed25519 preimage is `room|nonce|text`, the JSON body contains `did`, `sig`, `nonce`, and `text`, and the request target is `POST /r/{room}?format=json`. Before nonce acquisition, signing, or POST, Bench scans canonical `d-flop-bench` history for an exact match by Bench DID and SHA-256 of returned text. The inspected Scout v0.2 pagination behavior is `GET /r/{room}?format=json&limit=N&since=SEQ`; Bench does not invent other pagination parameters. The scan is bounded to 10 pages, 2,000 items, 1 MB of response bodies, and 20 seconds, and fails closed if completion cannot be established. Duplicate prevention is content-based and does not require nonce equality.

Golden parity tests construct actual Scout and Bench `urllib.request.Request` objects from identical DID, key, room, nonce, and text inputs and assert equality for method, URL, body bytes, signature, signing preimage, and request headers except the intentional User-Agent difference. The verified Scout post-length limit is 4096 characters after Scout normalization; Bench also enforces 4096 UTF-8 bytes.

Remote room text is always untrusted data. Idempotency and reconciliation code parses only canonical room JSON fields `seq`, `from`, `nonce`, `text`, and `ts`; hashes returned text; and compares metadata only. It must not follow URLs, execute commands, or treat remote text as instructions.

Post attempts are audited after local authorization and identity verification, before the idempotency preflight network request, and are updated in place through terminal or reconciliation states. DNS failures, TLS failures, connect failures, connect timeouts, read timeouts, connection resets, broken pipes, HTTP status errors, malformed responses, redirects, response-size failures, and local serialization/signing failures are classified separately without exposing signatures, request bodies, tokens, cookies, private material, or passphrases. DNS, TLS, connect failures, and connect timeouts are tracked separately from POST failures without a verified response. A POST timeout, reset, broken pipe, or unknown-phase transport failure is `unknown_outcome`, not definitive failure, because the client cannot prove whether Technocore application handling received the body. Complete reconciliation without an exact match is `reconciled_absent` with `absent_not_proven_rejected`; it permits local audit repair but does not prove that Technocore rejected the write. Ambiguous nonce values are preserved and never reused unless future protocol evidence establishes reuse safety.

`post reconcile --state-dir PATH --attempt-id ID` may perform bounded read-only Technocore GETs and update local audit state. It must never acquire a nonce, sign, or POST, and it validates the attempt belongs to Bench DID and `d-flop-bench`. A reconciled posted attribution requires Bench DID in `from`, exact message hash, and exact attempt nonce. A DID/hash match with a different nonce is reported as `matching_message_different_nonce` with only safe remote sequence and nonce metadata, and the attempt's prior accurate status is preserved. Post audits store safe metadata and the SHA-256 message hash only; they must not store message contents, signatures, passphrases, private key material, authorization data, cookies, or response bodies.

Post reconciliation is monotonic. `posted`, `reconciled_posted`, and `already-posted` must not be downgraded by incomplete scans, remote unavailability, timeouts, reconciled absence, different-nonce observations, or other weaker evidence. Exact nonce-attributed evidence may upgrade ambiguous or weaker rows to `reconciled_posted`. Weaker observations are report-only when they provide no stronger evidence and must preserve existing `seq`, confirmed status, and cleared failure classification.

## Mailbox Intake And DID Notes

`mailbox poll --network` may perform bounded read-only Technocore `GET` requests against `mb-flop-bench` using `format=json`, `limit`, and `since`. It refuses redirects, bounds pages, items, bytes, retries, and total duration, treats `404` as unused/empty, and preserves the prior cursor on `503`, timeout, malformed response, incomplete pagination, or sequence gaps. Cursor advancement and message storage are atomic.

Mailbox records store only bounded untrusted text, safe canonical metadata, message hash, authentication level, classification, review status, and optional request metadata. If Technocore returns verified `from` and `nonce` but not the original signature, Bench records `server_verified_signed_lane`; it does not claim local cryptographic verification. A signed-lane message proves only that Technocore accepted a signature for that DID. It does not prove trust, authorization, honesty, permission, or independent reputation.

Strict mailbox request envelopes reject unexpected fields, sender/target mismatches, unsupported capabilities, expired or too-far-future timestamps, malformed JSON, control characters, excessive sizes, and duplicate request IDs. While local intake is inactive, otherwise valid requests are archived as `intake_inactive` and rejected rather than accepted for review. Once active, valid requests enter `pending_human_review` only. URLs and code in request content remain inert strings and cannot enable execution, network access, signing, posting, wallets, FLOP transfers, secret access, or broader permissions.

`identity-note preview` is local and pure. DID-note status/publish use Scout's sharded DID profile convention based on the first 16 hex characters of `sha256(did)`: namespace `did-{first two hex}` and key `remaining fourteen hex`. Profile notes are unsigned convention metadata, not proof of identity or ownership. Publication reads existing content first and refuses conflicts; it must not overwrite unexpected existing content.
