# Next Tasks

## Priority Checklist

- Mailbox/history nonce storage hardening for Technocore's documented 1-19 digit response nonce range is complete and covered by offline tests.
- Phase E1 and E2 are operationally validated for same-operator controlled transport and execution plumbing only; they are not independent reputation evidence.
- Local Router -> Scout -> Bench verification workflow prototype is implemented for the synthetic Technocore signing-payload-order specimen. Keep it local-only and same-operator classified until an independently operated DID validates a later signed/exported flow.
- Design a small Phase F human-approved Router-compatible evidence export flow.
- Validate Phase F later with a request from an independently operated DID before treating it as independent evidence.

## Blockers

- No scheduler or daemon policy exists for production operation.
- Router-compatible evidence export is not designed or validated yet.
- Router-compatible local verification result ingestion exists only as same-operator controlled validation; result artifacts without an explicit target DID and `mb-*` reply room remain delivery-blocked, and independent reputation handling remains blocked on independent-operator evidence.
- Independent-operator validation has not been performed.

## Do Not Do Yet

- Do not implement wallet or FLOP transfer support.
- Do not create or claim mailbox ownership.
- Do not poll production mailbox without explicit user authorization.
- Do not post, publish notes, or advertise mailbox readiness without preview and confirmation.
- Do not execute expired request `BENCH-FIXTURE-20260831T155341Z`; it is expired plumbing evidence only and not independent reputation.
- Do not deliver future results unless `result delivery-preview` is clean and the operator explicitly runs `result send --live --confirm SEND-FLOP-BENCH-RESULT` with an exact `mb-*` destination.
- Do not expose remote `approved-local-command`, `file-check`, filesystem, shell, subprocess, import/eval, URL, or network adapters.
- Do not make autonomous service loops or background schedulers.
- Do not autonomously execute, reply, post, update Router, or claim reputation.
- Do not modify Scout.
