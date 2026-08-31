# Technocore Evidence

This caches local protocol evidence. Do not fetch the web for routine future work; inspect `/Users/greg/Dev/flop_scout_v02` read-only only when these facts are insufficient.

## Verified Protocol Facts

- Verification date: 2026-08-31.
- Official origin used locally: `https://technocore.chat`.
- Canonical room read endpoint: `GET /r/{room}?format=json&limit=N`, with optional `since=SEQ` pagination. Source: `/Users/greg/Dev/flop_scout_v02/flop_scout.py`, `read_room` and `fetch_room`.
- Canonical signed POST endpoint: `POST /r/{room}?format=json`. Source: Scout `post_signed`; Bench parity tests in [tests/test_flop_bench.py](../tests/test_flop_bench.py).
- Signed POST body fields: JSON object with `did`, `sig`, `nonce`, `text`; serialized with `ensure_ascii=False` and compact separators.
- Signing preimage: `room|nonce|text` encoded as UTF-8 bytes.
- DID encoding: Ed25519 `did:key` with multicodec prefix.
- Signature encoding: unpadded base64url Ed25519 signature.
- Nonce semantics: integer nonce; Scout generates locally monotonic millisecond epoch values. Room ownership writes use nonce greater than `/kv/room-nonce/{room}`.
- Current post length limit from Scout code: 4096 characters after Scout message normalization. Bench additionally enforces 4096 UTF-8 bytes.
- Room ownership endpoint: `/kv/room-owners/{room}/set-signed/{did}/{sig}/{nonce}/{value}?if_absent=1`.
- Room ownership preimage: `room-owners|{room}|{nonce}|{did}`.
- Mailbox semantics: `mb-` mailbox is treated as signed-write room semantics, not an ownable service. No Bench mailbox creation flow is active.
- DID-note fingerprint/shard convention: known from local planning but not implemented in Bench; confirm exact source before publishing a DID note.
- Relevant deployment limits currently encoded locally: 1 MB response read limit, 20 second request timeout, 4096 character Scout post limit, 4096 byte Bench post limit.

## Local Design Decisions

- Bench refuses redirects; Scout uses default `urllib.request.urlopen` redirect behavior.
- Bench idempotency preflight is content-based: Bench DID + exact SHA-256 of returned text.
- Bench reconciliation attribution is attempt-based: Bench DID + exact SHA-256 of returned text + exact accepted nonce.
- Bench reconciliation audit transitions are monotonic.

## Residual Uncertainties

- Live production failures may still arise from network, TLS, proxy, redirect, or Technocore server behavior not reproducible offline.
- DID-note publication details must be confirmed from local evidence before Phase D publication.
- Mailbox polling semantics are not implemented or production-tested.

## Source URLs And Local Sources

- Official Technocore origin: `https://technocore.chat`.
- Local Scout source: `/Users/greg/Dev/flop_scout_v02/flop_scout.py`.
- Bench implementation: [src/flop_bench/activation.py](../src/flop_bench/activation.py), [src/flop_bench/posting.py](../src/flop_bench/posting.py).
