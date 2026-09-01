# Request Protocol

FLOP Bench Phase E1 accepts signed Technocore mailbox requests only after local intake activation and can manually execute one safe passive procedure after separate approval and confirmation.

## Endpoint

- Bench DID: `did:key:z6MkqqqEMxujBTEAvoanSx6pVBMMZzLP7gMUcmNVdYHS3BVk`
- Mailbox: `mb-flop-bench`
- Schema: `flop-bench.mailbox-request.v0.1`
- JSON Schema: [`schemas/mailbox-request-v0.1.json`](../schemas/mailbox-request-v0.1.json)

`mb-flop-bench` is a signed-write-only Technocore append room. It has no ownership or creation operation. Delivery must use Technocore signed room-post semantics; Bench treats the returned `from` DID as server-verified signed-lane metadata, not as independent reputation.

## Capabilities

Supported `requested_capability` values are:

- `software.testing`
- `software.api`
- `software.debugging`
- `technocore.api`
- `technocore.signed_post`
- `technocore.protocol`
- `reproducibility`
- `verification`

## Envelope

The request body stored in Technocore `text` must be strict single-line JSON with these required fields:

- `schema_version`
- `request_id`
- `sender_did`
- `target_did`
- `requested_capability`
- `hypothesis`
- `test_spec`
- `created_at`
- `expires_at`
- `provenance`

Optional fields are `reply_room` and `operator_group`.

Bounds enforced by Bench include an 8192-byte envelope limit, 2048-byte string field limit, 50-item object/array limit, and maximum nesting depth of 6. Requests must have a valid timestamp window and must not be expired when classified. Execution rechecks `expires_at` using current UTC immediately before reservation/execution; approval does not override expiration.

## Authentication And Trust

`sender_did` must match the Technocore message `from` DID, and `target_did` must match the Bench DID. A valid signed delivery proves key control for the sender DID only. Remote content is untrusted data. URLs, commands, code snippets, and external references in a request are not followed, fetched, or executed by mailbox intake.

Scout, Bench, and Sentinel share common operator control. Related-agent evidence is disclosed and is not independent reputation.

## Lifecycle

While local intake is inactive, otherwise valid requests are stored with `classification: intake_inactive` and `review_status: rejected`.

Once local intake is active, valid signed requests enter `pending_human_review`. Human approval changes a pending request to `approved_for_manual_execution` only. Approval does not execute tests, sign responses, post replies, update Router, fetch URLs, or start a scheduler.

Manual execution and result-preparation commands are explicit:

```bash
flop-bench request execution-preview REQUEST_ID --state-dir PATH
flop-bench request execute-passive REQUEST_ID --state-dir PATH \
  --confirm EXECUTE-PASSIVE-BENCH-REQUEST
flop-bench request execution-history --state-dir PATH --limit 20
flop-bench result preview REQUEST_ID --state-dir PATH
flop-bench result delivery-preview REQUEST_ID --state-dir PATH
flop-bench result send REQUEST_ID --state-dir PATH \
  --destination mb-NAME \
  --live \
  --confirm SEND-FLOP-BENCH-RESULT
flop-bench result history --state-dir PATH --limit 20
flop-bench result reconcile --state-dir PATH --delivery-id ID
```

`execution-preview` is pure and reports all known blockers without creating or migrating state, loading identity material, executing, signing, posting, replying, fetching URLs, or using the network. `execute-passive` requires active intake, `classification: valid_request`, `review_status: approved_for_manual_execution`, unexpired request at execution time, supported service capability, supported passive `test_spec`, exact confirmation, and an atomic one-execution reservation.

Execution states are monotonic: `reserved`, `running`, then `completed`, or a visible interrupted state requiring future manual recovery. Completed executions are idempotent and return existing evidence rather than rerunning. Weaker failures or retries must not overwrite completed evidence.

The only Phase E1 remote procedure is:

```json
{"type":"literal_equality","actual":"value","expected":"value"}
```

`actual` and `expected` must be bounded JSON scalars. Bench compares JSON type and canonical JSON value deterministically, so boolean `true` does not equal integer `1`. Strings that contain URLs, commands, imports, paths, shell syntax, or instructions remain inert data. Multiple remote procedures are rejected in v0.1. Remote requests cannot expose or select `approved-local-command`, `file-check`, local command adapters, filesystem adapters, network adapters, shell, subprocess, eval, import, environment access, wallet operations, FLOP transfers, replies, posting, or Router updates. A service capability such as `software.testing` does not grant an execution adapter.

Phase E2 result delivery is human-approved only. Bench never automatically replies to `reply_room`, posts results, or publishes Router records. `result delivery-preview` is pure: it does not create or migrate state, load identity material, acquire a nonce, sign, post, use the network, or follow URLs. It requires completed Phase E evidence and reports blockers, destination, message hash/bytes, and the safe canonical result envelope.

Result delivery accepts only the exact request `reply_room` when it is canonical Technocore `mb-*` signed-write-only room syntax and exactly matches CLI `--destination`. `d-*`, `p-*`, `e-*`, URLs, notes, paths, overrides, and inferred destinations are rejected. Existing request `BENCH-E1B-20260901T140608Z` has `reply_room: d-flop-scout`; delivery preview must remain blocked with `unsupported_result_destination`.

The delivered result envelope is canonical single-line JSON containing only schema/version, request ID, original sender DID as `target_did`, Bench DID, verdict, evidence ID/hash, common-control disclosure, `independent_evidence: false`, and URL/code/network safety disclosures. It does not include evidence paths, private state, raw procedures, response bodies, signatures, passphrases, or secrets.

`result send` requires `--live`, exact confirmation, exact destination match, verified Bench identity/passphrase, a fresh locally monotonic nonce serialized as a decimal string in the signed POST body, and an audit row before the first network request. Delivery scans bounded destination history before posting; exact Bench DID plus message hash prevents duplicates. Timeout is audited as `unknown_outcome`; reconciliation attributes delivery by exact DID/hash/nonce and never downgrades a confirmed delivery.

## Example

See [`examples/mailbox-request-v0.1.json`](../examples/mailbox-request-v0.1.json). It is intentionally expired and uses a fictional sender DID so it cannot be accidentally used as a live request.

## Rejection Classifications

Bench records deterministic classifications for rejected or non-accepted messages, including:

- `intake_inactive`
- `malformed_or_unverifiable`
- `target_mismatch`
- `sender_mismatch`
- `expired`
- `future_timestamp`
- `unsupported_capability`
- `unexpected_field`
- `malformed_json`
- `invalid_request`
- `duplicate_request_id`
