# Next Tasks

## Priority Checklist

- Review `flop-bench identity-note preview --state-dir ~/.flop_agents/bench`.
- If preview is acceptable, separately authorize `identity-note status` and then guarded `identity-note publish --live`.
- First controlled mailbox poll using `flop-bench mailbox poll --state-dir ~/.flop_agents/bench --network`.
- Fixture request path for mailbox intake without production polling.
- Router integration after mailbox flow is safe and audited.

## Blockers

- DID-note publication has not been performed live.
- Production mailbox has not been polled by this implementation.
- No scheduler or daemon policy exists for production operation.

## Do Not Do Yet

- Do not implement wallet or FLOP transfer support.
- Do not create or claim mailbox ownership.
- Do not poll production mailbox without explicit user authorization.
- Do not post, publish notes, or advertise mailbox readiness without preview and confirmation.
- Do not make autonomous service loops or background schedulers.
- Do not modify Scout.
