# Access planning

**The rule.** Before asking the maintainer for any token, scope or consent, plan the whole job and list every call it
needs, including the likely fix if step one fails. Ask once for the union, naming each scope and why. Least privilege is
the least that covers the plan, not the least that covers step one.

## What to do

1. Write the plan.
2. List every call it needs, including the follow-up you expect.
3. Look up the exact scope names in the vendor's API spec or through the tool's own search. Do not guess one.
4. Ask once for the union, with each scope and the call that needs it.
5. Do not offer a broader grant as a fallback. If a scope name is unconfirmed, look it up, or ask the maintainer for a
   screenshot of the scope list.
6. Do not search the maintainer's secret stores for an existing credential to reuse. New automation gets its own, narrowly
   scoped credential: an app installation, a rotated user token or an OIDC identity.
7. When the job ends, drop the write scopes yourself, or file an issue with a board card that says they are still open. A
   standing write grant is never left in a "when convenient" note.

Approving a task includes planning its access ([Act, then report](act-then-report.md)).

## Why: 2026-10-25

The lead recommended a read-only OAuth grant to a cloud account and said more access was not needed that day. Eleven
minutes later a DELETE call returned 403, for a fix the lead already knew was coming, and the maintainer had to authorize a
second time. Twice the lead offered "choose full access for this session" as the fallback for a scope name it had not
confirmed. Earlier the same day it tried to list secret names in a secrets manager to reuse an existing token; the
classifier denied that and the lead left it. After the job, the write grant stayed in place.

Every extra consent screen costs the maintainer time. A broad fallback or a reused credential undoes the least privilege he
sets for the account.

## How it is enforced

**Doctrine only, not enforced.** Nothing in `safo` (see [safo hooks](hooks.md)) reads an access request, counts consent
trips or checks that a grant was dropped. The approval token in the guard is a speed bump against accidents, not proof of
consent ([Limits](limits.md)). A call-level speed bump for cloud writes is tracked as a separate issue and is not built.
The end-of-job item below is the check.

## Checklist

- [ ] The plan is written, with every call it needs and the likely fix after a failure.
- [ ] Each scope name was looked up, not guessed.
- [ ] One request, the union, each scope named with its reason.
- [ ] No "full access" fallback offered; no secret store searched for a credential to reuse.
- [ ] End of job: write scopes dropped, or an issue and card say they remain and why.

Related: [Act, then report](act-then-report.md), [Done means verified](done-means-verified.md),
[The orchestrator](orchestrator.md).
