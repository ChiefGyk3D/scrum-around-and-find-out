# The review loop

Agents produce output quickly; the loop is what makes it trustworthy. Every task goes through the same cycle, and this
page uses the SAFO v0.1.0 build as the worked example, because it happened. The first three tasks were recorded in the
most detail, so they come first; the later tasks and the wiki generator follow.

## The cycle

1. **Implement.** A task is built from a complete brief. In this build Haiku implements from the plan's pre-verified code.
2. **Task review.** A Sonnet reviewer that did not write the code checks two things separately: does it match the spec, and
   is the quality sound. Findings are rated blocking or minor.
3. **Fix rounds.** The lead decides which findings are fixed now and which are parked, with the reason and the cost if the
   ruling is wrong. A scoped re-review checks each fix round. **The cap is five fix rounds**, and from round four the fix
   goes to a fresh Sonnet agent rather than the same implementer.
4. **Adversarial pass.** Before merge, security-sensitive code is attacked by Codex, which is told to try to break it, not
   to approve it. This is a second reviewer of a different kind, run even when CI and the Sonnet review are green.
5. **CI green, then the maintainer merges.** See [Handoff](handoff.md).

## What the build showed

The first table is the build ledger for T1 to T3. T2 and T3 reached `main` inside one squashed pull request, so their
per-round commits are not in the history; the counts below are the ledger's.

| Task | What it was | Fix rounds | What the reviews found |
|---|---|---|---|
| T1a | Scaffold and network guard | 2 | The guard missed `connect_ex`, `sendto`, `sendmsg` and name lookups; the committed plan file itself failed the project's formatter check |
| T1c | `scripts/apply-baseline.sh` | 1, plus a scoped re-review | The script changes repository security settings, so it had to fail closed on `gh` errors and on a failed allow-list fetch |
| T2 | GraphQL client | 4, with a Sonnet re-review and four Codex rounds | See below |
| T3 | `board.yaml` validator | 2, with two re-reviews | Duplicate keys accepted, deep nesting raised `RecursionError`, anchors and aliases not refused, 14 validations that survived deletion of the check |

T1b needed no fix rounds.

### Why the adversarial pass exists: T2

T2 is the token-handling client every mode uses. It was transcribed from the plan.

- The **Sonnet review** found a blocking defect in the plan's own code: the HTTP layer followed redirects and carried the
  `Authorization` header to the redirect host (reproduced). Fixed in round 1; the client now refuses all redirects.
- The Sonnet re-review said the fix was clean. The **Codex adversarial review** then found a high-severity bug Sonnet had
  missed: mutations were retried after ambiguous failures (a timeout or a 5xx), so a mutation the server had already
  committed would be replayed and create duplicate objects. Reproduced.
- Fix round 2 made mutations retry only when the server provably did not process them. Codex's next pass found that an
  in-body `RATE_LIMITED` error was still retried when the response carried partial data.
- Fix round 3 stopped retrying in-body errors. Codex's next pass found two more: a malformed or null mutation response
  raised the wrong error type, and `INSUFFICIENT_SCOPES` with partial data dropped that data.
- Fix round 4, by a fresh Sonnet agent, replaced the piecemeal rules with one: after a mutation is sent, anything but a
  clean success is an **unknown outcome**, reported with everything the server said, never replayed. A table-driven test
  covers every branch (34 of 41 rows failed against the previous commit). Codex's fourth pass approved with no material
  findings (our own full gate: 117 passed).

The ledger's own conclusion: the plan's client carried a redirect token leak and three mutation-replay paths, and
byte-exact transcription is not a review. That is why the plan, not just the code, is part of what is reviewed.

### The same pattern elsewhere

On 2026-10-07 two other security-sensitive changes outside SAFO were reviewed by Sonnet and then attacked by Codex. On
each, Codex found a high-severity issue the Sonnet reviews missed: a loopback guard bypassed through a CDATA section, and
credential-bearing login URLs that would reach scan artifacts. Codex's adversarial review of a shared-workflow change found
three more real issues. The rule that came out of it: anything security-relevant gets a Codex adversarial review before
merge, even when CI and the Sonnet review are green. The dated entries are in [Lessons](lessons.md).

## The rest of the build

The later tasks kept the same cycle. The fix rounds below are counted from the commit subjects on `main`
(`git log --oneline origin/main`): a round is a distinct `Tn fix N` label, and one round can span several commits.

| Task | What it was | Fix rounds | Commits behind the count |
|---|---|---|---|
| T5 | `safo bootstrap` | 2 | `T5 fix 1: null mutation payloads are unknown outcomes, honest exit codes, strict pagination`; `T5 fix 2: malformed connection nodes are exit 2, reread diagnostics, honest recovery wording` |
| T6 | `safo reconcile` | 2 | Fix 1, three commits: `one desired value per field, strict reads, canonical repositories, alias defaults`; `pin the role rule, the repeated listing and the not-on-the-board reread`; `document that a default never writes the status, Area or Done field`. Fix 2, two commits: `audit keeps type drift, labels agree page to page, RFC 3339 offsets are validated`; `tests that pin the offset pattern, the fraction, a short label list and a first-page repeat` |
| T7 | `safo sync` and `safo status` | 2 | Fix 1, two commits: `the live content decides, escaping reaches every log line and body, acknowledgement ownership, rate-limit exits, descriptor-checked reads`; `tests that kill the surviving mutations (live read shapes, project ownership shapes, printed block controls)`. Fix 2, two commits: `one output module, a structural test that nothing prints outside it, and a stop-commands block that always resumes`; `a resume marker is never written for an opening marker that did not go out` |

T5, T6 and T7 each ended at two fix rounds, short of the cap of five. The history shows no third fix label for any of them, so none
appears to have reached the fresh-agent hand-off in round four. T4 and T8 to T11 were merged as squashed pull requests (T4 inside the group 2 merge, T8 to T11 as group 4), so
their per-round commits are not in the history and no count is given for them. The only T8 trace in the history is
a commit that ignores the three fixture findings in T8's first commit, so the scanners treat the deliberate test fixtures
as such.

### What the fix rounds had in common

The T7 history names a pattern. Alongside the code fix, the task's first test commit and its fix 1 each carry a commit
titled "tests that kill the surviving mutations": tests added because a reviewer showed that deleting or changing a check
left the suite green. T3 found the same thing in its first review (14 validations that survived deletion of the check),
and T6 opened with `hostile-input tests that cannot pass vacuously`. The finding class is a test that passes whether or not
the code is right, and the fix is a test that fails when the check is removed.

The review also kept finding the same two classes in the code itself, which are the ones the cap exists to catch: an
unknown outcome treated as a known one (T2, then T5's `null mutation payloads are unknown outcomes`), and an error path
that exits with the wrong code or wording (T5's fix rounds name exit codes and recovery wording, T7's names rate-limit
exits).

### A second worked example: the wiki generator

The generator that mirrors `docs/` into the GitHub wiki (`scripts/gen_wiki.py`) was built on a branch and attacked by Codex
in four adversarial rounds. The workflow that publishes its output, which is a small caller of the shared wiki workflow,
drew no findings in the same passes. The generator did:

- **A symlink disclosure.** A symbolic link under `docs/` could disclose a file from outside the tree through a
  public page. Fixed first by refusing links (`gen_wiki: refuse symbolic links anywhere under docs/`), then again when
  the next round showed that checking and then opening was racy, by opening through descriptors that do not follow links
  (`gen_wiki: read docs by descriptor opened without following links` and `gen_wiki: write through directory descriptors
  opened without following links`).
- **A spoofable ownership record.** The generator cleans its output directory only if a record says it wrote it, and the
  record could be spoofed so that the generator would clean a directory it did not write. Fixed in two steps: `clean --out only from a record the
  generator wrote beside the tree`, then `bind the ownership record to the tree`.
- **Time-of-check to time-of-use races.** The two descriptor commits above are the fix for these.
- **Two super-linear regular expressions.** A crafted page could make the link scanner or the heading reader take time that
  grew faster than the input. Fixed by `scan links in linear time` and `scan code spans in one linear pass and read headings
  without backtracking`.

The rest of the branch's commits (CommonMark fences, titled and reference links, escaped labels, case-insensitive page
names, code inside blockquotes) fail loudly or handle the form correctly instead of guessing; they came out of the same
rounds as correctness findings. The branch has 16 commits ahead of `main` (`git log --oneline origin/main..HEAD`).

The lesson is the same as T2's: the code that parses untrusted input and writes to disk was reviewed adversarially and
had four rounds of real findings, while the thin workflow caller around it had none. The adversarial pass belongs where
untrusted bytes meet the filesystem or the network, not on every file.

## Why a cap and a fresh agent

A reviewer finding a new problem each round is a signal. This is our reading of T2, not a measured rule: it took four
rounds because each fix patched the symptoms of one case instead of the classification underneath. Round four, from a fresh
agent with the whole picture, fixed the class. The cap forces the question "is the structure wrong?" before the work keeps
cycling. The later tasks bear it out from the other side: none of T5, T6 or T7 passed two rounds, and none needed the
hand-off.

## The costs

Adversarial review is not free: Codex's 5-hour window is the binding limit, so its jobs are spaced (see [Limits](limits.md)
and [Routing](routing.md)). It is used where the cost of a miss is high: token handling, mutation semantics, credential
flow, security tooling, and code that reads untrusted files. Everything else gets the Sonnet review and CI. Who plays each
part is in [Roles](roles.md).
