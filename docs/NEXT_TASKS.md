# Next Tasks

## Priority Checklist

- Mailbox/history nonce storage hardening for Technocore's documented 1-19 digit response nonce range is complete and covered by offline tests.
- If local production DID-note reconciliation is present and already matching, run `flop-bench mailbox activation-preview --state-dir ~/.flop_agents/bench`, then separately authorize `flop-bench mailbox activate --state-dir ~/.flop_agents/bench --confirm ACTIVATE-MB-FLOP-BENCH` if desired.
- First controlled mailbox poll using `flop-bench mailbox poll --state-dir ~/.flop_agents/bench --network`.
- Review Phase E2 human-approved result delivery implementation before any production use.
- Exercise `result delivery-preview` only against production state first; any `result send` remains a separate explicit live operation.
- Router integration after mailbox flow is safe and audited.

## Blockers

- DID-note publication reportedly succeeded; local audit reconciliation is required before mailbox activation if not already present.
- Production mailbox activation and polling have not been run by this implementation.
- No scheduler or daemon policy exists for production operation.
- Result delivery is implemented for exact canonical `mb-*` reply rooms only, but has not been used in production by this implementation.

## Do Not Do Yet

- Do not implement wallet or FLOP transfer support.
- Do not create or claim mailbox ownership.
- Do not poll production mailbox without explicit user authorization.
- Do not post, publish notes, or advertise mailbox readiness without preview and confirmation.
- Do not execute expired request `BENCH-FIXTURE-20260831T155341Z`; it is expired plumbing evidence only and not independent reputation.
- Do not deliver Phase E results unless `result delivery-preview` is clean and the operator explicitly runs `result send --live --confirm SEND-FLOP-BENCH-RESULT` with an exact `mb-*` destination.
- Do not expose remote `approved-local-command`, `file-check`, filesystem, shell, subprocess, import/eval, URL, or network adapters.
- Do not make autonomous service loops or background schedulers.
- Do not modify Scout.
