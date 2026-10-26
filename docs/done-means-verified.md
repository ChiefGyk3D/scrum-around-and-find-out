# Done means verified

**The rule.** "Done", "fixed", "live" and "working" are claims the maintainer acts on. Each needs an observation made this
turn, through the path the maintainer will use (the public URL, the real command, the default branch's own run), with the
decisive line quoted. A success status from a write call is not done.

## The rule in four parts

- **Observed through the maintainer's path, this turn.** Not a proxy, not the write call's 200, not an earlier read.
- **Reads carry a time.** Every state read says when it was taken. The maintainer's report of a change is newer than the
  lead's last read: re-read, with the same query or a wider one, before contradicting it.
- **Inferred is labeled inferred.** A summary that mixes verified and inferred items labels each one.
- **CI is watched with one tested watcher** that pins the head commit and requires the gate check (`CI green`) to exist.
  A hand-rolled merge-state loop is not a watcher; it passes on a stale or missing run.

## Destructive steps

A delete, a revocation, a visibility change or a force-cancel adds five things:

1. A fresh read of the target and of everything that references it.
2. An export first, where one is possible.
3. A script that stops at the first error. Never a helper that swallows errors and carries on.
4. A read-back afterward, showing the target is in the state intended.
5. The maintainer's authorization, quoted in the same turn.

## Why: 2026-10-25

- The lead reported a Cloudflare fix as done. The Pages custom domain was still pending and no CNAME record existed; two
  minutes later the maintainer hit error 1016. The API call that attached the domain had succeeded, and it creates no DNS
  record.
- The maintainer said a subdomain was already set up on both a Worker and Pages. The lead re-read with a narrower query,
  missed the Worker's domain, and called its record a leftover. The record was live.
- The lead told the maintainer three times to unmount a share that was not mounted.
- Five times that day a CI watcher reported a run as clean or completed when the run it read was stale.
- A note saying a deploy pipeline was live end to end was written while the lead's own check of the public hostname was
  still pending.

A false "done" costs the maintainer a broken page and a second debugging round, and it spends the trust that lets an agent
work unattended.

## How it is enforced

**Doctrine only, not enforced.** `safo hooks guard` ([safo hooks](hooks.md)) does not read completion claims. Its fifth
rule, `lead-waits`, keeps the lead from standing and watching a run, which is why the observation itself is delegated to a
read-only monitor agent whose report quotes the deciding log lines ([The orchestrator](orchestrator.md)). Whether the
monitor read the right run is the lead's check. Enforcement at the cloud-write call level, and an optional Stop hook, are
tracked as separate issues and are not built.

## Checklist (short enough to paste into a brief)

```
Done needs: an observation this turn through the user's path, the decisive line quoted, every read timestamped.
Inferred items say "inferred". His report of a change beats my older read: re-read before contradicting.
Destructive step: fresh read of target and dependents; export; stop at first error; read-back; his authorization quoted.
```

Related: [Look before instructing](look-before-instructing.md), [Access planning](access-planning.md),
[The review loop](review-loop.md).
