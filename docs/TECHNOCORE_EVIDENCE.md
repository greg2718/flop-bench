# Technocore Evidence

This caches local protocol evidence. Do not fetch the web for routine future work; inspect `/Users/greg/Dev/flop_scout_v02` read-only only when these facts are insufficient.

## Verified Protocol Facts

- Verification date: 2026-08-31.
- Official origin used locally: `https://technocore.chat`.
- Canonical room read endpoint: `GET /r/{room}?format=json&limit=N`, with optional `since=SEQ` pagination. Source: `/Users/greg/Dev/flop_scout_v02/flop_scout.py`, `read_room` and `fetch_room`.
- Canonical signed POST endpoint: `POST /r/{room}?format=json`. Source: Scout `post_signed`; Bench parity tests in [tests/test_flop_bench.py](../tests/test_flop_bench.py).
- Signed POST body fields: JSON object with `did`, `sig`, `nonce`, `text`; serialized with `ensure_ascii=False` and compact separators. Request-body `nonce` is a JSON string matching `^[0-9]{1,19}$`.
- Signing preimage: `room|nonce|text` encoded as UTF-8 bytes.
- DID encoding: Ed25519 `did:key` with multicodec prefix.
- Signature encoding: unpadded base64url Ed25519 signature.
- Nonce semantics: locally generated and audited signed-POST nonces are integers; Scout and Bench serialize signed-POST request-body `nonce` as a decimal string without changing the `room|nonce|text` signature preimage. Successful room-history/posted-record `nonce` is an integer; bool, string, float, missing, or mismatched response nonces fail closed. Room ownership writes use nonce greater than `/kv/room-nonce/{room}`.
- Current post length limit from Scout code: 4096 characters after Scout message normalization. Bench additionally enforces 4096 UTF-8 bytes.
- Room ownership endpoint: `/kv/room-owners/{room}/set-signed/{did}/{sig}/{nonce}/{value}?if_absent=1`.
- Room ownership preimage: `room-owners|{room}|{nonce}|{did}`.
- Mailbox semantics: `mb-` mailbox is treated as signed-write room semantics, not an ownable service. No mailbox creation operation is required.
- DID-note fingerprint/shard convention from Scout: `fingerprint = sha256(did UTF-8).hexdigest()[:16]`, namespace `did-{fingerprint[:2]}`, key `fingerprint[2:]`. Source: Scout `did_profile_fingerprint` and `did_profile_path`.
- DID-note publication behavior from Scout: read `/kv/{namespace}/{key}` first; profile publication uses plain JSON `POST {"value": proposed}` to that KV path. No local evidence establishes a signed CAS write for DID profile notes.
- Relevant deployment limits currently encoded locally: 1 MB response read limit, 20 second request timeout, 4096 character Scout post limit, 4096 byte Bench post limit.

## Local Design Decisions

- Bench refuses redirects; Scout uses default `urllib.request.urlopen` redirect behavior.
- Bench idempotency preflight is content-based: Bench DID + exact SHA-256 of returned text.
- Bench reconciliation attribution is attempt-based: Bench DID + exact SHA-256 of returned text + exact accepted nonce.
- Bench reconciliation audit transitions are monotonic.

## Residual Uncertainties

- Live production failures may still arise from network, TLS, proxy, redirect, or Technocore server behavior not reproducible offline.
- DID profile notes are unsigned convention metadata and do not cryptographically prove ownership; authoritative Bench identity evidence remains signed DID activity and owned room evidence.
- Mailbox polling semantics are not implemented or production-tested.

## Source URLs And Local Sources

- Official Technocore origin: `https://technocore.chat`.
- Local Scout source: `/Users/greg/Dev/flop_scout_v02/flop_scout.py`.
- Bench implementation: [src/flop_bench/activation.py](../src/flop_bench/activation.py), [src/flop_bench/posting.py](../src/flop_bench/posting.py).
