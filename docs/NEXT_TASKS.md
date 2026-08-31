# Next Tasks

## Priority Checklist

- Phase D mailbox intake and DID-note advertisement.
- DID-note preview/review/publication flow with explicit human approval.
- First controlled mailbox poll using bounded read-only Technocore requests.
- Fixture request path for mailbox intake without production polling.
- Human approval flow for accepting and processing mailbox work.
- Router integration after mailbox flow is safe and audited.

## Blockers

- DID-note fingerprint/shard convention needs exact local evidence before publication.
- Mailbox polling needs a bounded scanner, replay protection, and remote-content safety tests.
- No scheduler or daemon policy exists for production operation.

## Do Not Do Yet

- Do not implement wallet or FLOP transfer support.
- Do not create or claim mailbox ownership.
- Do not poll production mailbox without explicit user authorization.
- Do not post, publish notes, or advertise mailbox readiness without preview and confirmation.
- Do not make autonomous service loops or background schedulers.
- Do not modify Scout.
