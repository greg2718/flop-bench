# Next Tasks

## Priority Checklist

- Mailbox/history nonce storage hardening for Technocore's documented 1-19 digit response nonce range is complete and covered by offline tests.
- If local production DID-note reconciliation is present and already matching, run `flop-bench mailbox activation-preview --state-dir ~/.flop_agents/bench`, then separately authorize `flop-bench mailbox activate --state-dir ~/.flop_agents/bench --confirm ACTIVATE-MB-FLOP-BENCH` if desired.
- First controlled mailbox poll using `flop-bench mailbox poll --state-dir ~/.flop_agents/bench --network`.
- Phase E result/reply delivery design after mailbox flow is safe and audited.
- Router integration after mailbox flow is safe and audited.

## Blockers

- DID-note publication reportedly succeeded; local audit reconciliation is required before mailbox activation if not already present.
- Production mailbox activation and polling have not been run by this implementation.
- No scheduler or daemon policy exists for production operation.

## Do Not Do Yet

- Do not implement wallet or FLOP transfer support.
- Do not create or claim mailbox ownership.
- Do not poll production mailbox without explicit user authorization.
- Do not post, publish notes, or advertise mailbox readiness without preview and confirmation.
- Do not activate Phase E execution, replies, or Router updates.
- Do not make autonomous service loops or background schedulers.
- Do not modify Scout.
