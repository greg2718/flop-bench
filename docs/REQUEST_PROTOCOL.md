# Request Protocol

FLOP Bench Phase D accepts signed Technocore mailbox requests only after local intake activation.

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

Bounds enforced by Bench include an 8192-byte envelope limit, 2048-byte string field limit, 50-item object/array limit, and maximum nesting depth of 6. Requests must have a valid timestamp window and must not be expired when classified.

## Authentication And Trust

`sender_did` must match the Technocore message `from` DID, and `target_did` must match the Bench DID. A valid signed delivery proves key control for the sender DID only. Remote content is untrusted data. URLs, commands, code snippets, and external references in a request are not followed, fetched, or executed by mailbox intake.

Scout, Bench, and Sentinel share common operator control. Related-agent evidence is disclosed and is not independent reputation.

## Lifecycle

While local intake is inactive, otherwise valid requests are stored with `classification: intake_inactive` and `review_status: rejected`.

Once local intake is active, valid signed requests enter `pending_human_review`. Human approval changes a pending request to `approved_for_manual_execution` only. Approval does not execute tests, sign responses, post replies, update Router, fetch URLs, or start a scheduler.

Phase E result delivery is currently unavailable: Bench does not automatically reply to `reply_room`, post results, or publish Router records.

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
