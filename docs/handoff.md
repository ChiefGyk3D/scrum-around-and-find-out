# Handoff

Work moves from a card to a merged pull request in six steps. Each step leaves something a person can read.

1. **The card.** An issue exists, is on the board, and has the **Agent** field set. `sync` adds a new issue within a minute;
   `reconcile` catches the rest.
2. **Brief in.** A comment on the card with the task, the files, the acceptance test, and what not to touch. A brief that
   needs the conversation it came from is not complete. Hand Codex a self-contained prompt that reads state from files.
3. **Work.** The agent works on a branch and opens a draft pull request that links the card. Status moves to In progress.
4. **Result out.** A comment on the pull request: what changed, how it was checked (the command and its output), and what
   was left. The numbers in the comment come from running the checks, not from memory.
5. **A fresh reviewer.** A different agent or model reviews the diff and the claims, with no memory of the work. Findings go
   on the pull request; the author fixes them. How many rounds, and when Codex attacks it: [The review loop](review-loop.md).
6. **CI green, then the maintainer merges.** `CI green` is required by branch protection. Only the maintainer merges.

## Is the review still about this head?

A push after a review leaves the old approval looking current. `safo handoff check <owner/repo> <pr>` reads the pull
request's comments and compares the `HEAD:` line of the latest report (the header every [DoIA](personas.md) role report
carries: a `ROLE:` line, then `HEAD: <sha>   BASE: <sha>`) with the pull request's head now.

| Exit | Output starts with | Meaning |
|---|---|---|
| 0 | `FRESH` | the latest review report names the current head and was posted after the head arrived (proven by a force-push event) |
| 1 | `STALE` | it names an older head (both short SHAs are printed), predates the head, or predates a base change. Exit 1 means only this: a crash is exit 2 |
| 2 | `UNKNOWN` | no report, an unusable SHA, an internal error, or an answer from GitHub that could not be read in full |

The one-line result names the role that wrote the report and its `VERDICT:` line when it has a recognized one, for
example `FRESH adversarial-reviewer report VERDICT FINDINGS names the current head 1a2b3c4 (draft)`. It says the report
names the head. It never says the work was approved: `FINDINGS` at the current head is still FRESH. A suffix shows a
pull request that is a draft, closed or merged.

What it reads, and how strictly:

- Only comments whose author association is OWNER, MEMBER or COLLABORATOR. A comment from anyone else is ignored, so a
  fork contributor cannot make a pull request look reviewed. Minimized comments are ignored.
- Only a reviewing role counts: `reviewer` and `adversarial-reviewer` by default, or the comma list given to
  `--roles` (any of `implementer`, `reviewer`, `adversarial-reviewer`, `transcriber`, `lead`). A report by another role
  is skipped when looking for the latest review, so a later implementer comment does not replace the review. A report
  whose role cannot be read is not skipped: if it is the newest, the answer is unknown.
- The newest report counts, read as of its current (edited) body. A comment is dated by the later of its creation and
  its last edit, so an old comment edited after a newer one now reads as the newest. Two reports with the same date
  that differ in role, head or verdict, or one comment holding two different heads, are unknown.
- **The report is read from the HTML GitHub rendered (`bodyHTML`), never from the raw Markdown**, and only from the text
  of a top-level `<p>` (lines separated by `<br>` or a newline). The check does not parse Markdown, so it cannot
  disagree with GitHub about what is code. What a person sees as a fenced or indented code block, a `<pre>` block, a
  quotation, a list item (`li`, decided: no), a table, a collapsed `<details>` block, a heading, a script, a style, a
  template, an HTML comment, an element with `hidden`, or anything inside an element it does not recognize is not a
  report. Inside a paragraph, text under a plain inline element (`a`, `strong`, `em`, `b`, `i`, `del`, `s`) is read; text
  under any other element (`code`, `span`, an unknown tag) is dropped. A header needs its `ROLE:` and `HEAD:` lines in the
  same paragraph, one after the other.
- A comment whose HTML is over 200,000 characters, nested over 50 elements deep, or not well formed (a mismatched or
  unclosed tag) cannot be read. If it mentions `ROLE` and its author is trusted, the whole answer is unknown; a comment
  that does not mention `ROLE`, or comes from anyone else, is ignored. The HTML is never copied into the output.
- **The pull request is read twice and must not have changed.** The first round reads, in this order, the pull request
  (head, base branch name and base oid, state and draft flag), the comments, the commits (only when the report names a
  short SHA) and the timeline, and decides. A final round then reads the timeline, the comments and, **last**, the pull
  request again, and any difference from the first round (a new head or base, any new or different timeline event, an
  edited, added or minimized comment, a changed state) makes the answer unknown ("the pull request changed while it
  was being read"). The head read is the last request on purpose: a normal push leaves no timeline event and no
  comment, so only the head read can show it. Request order on a fresh answer: pull request, comments, timeline, then
  timeline, comments, pull request. A push after that very last read cannot be seen; that window is the one that
  remains. The cost is three more read requests (two when the timeline is not needed), and a busy base branch, whose
  oid moves with every push, can make the answer unknown for a moment: run it again.
- **A report is fresh only if it was posted AFTER the moment its commit became the head, and GitHub proves that
  moment.** The only event GitHub records with the time a head arrived is a force-push (`HeadRefForcePushedEvent`
  from the pull request timeline, the last 50 events); the head's time is the latest one whose result is the head. A
  normal push leaves no event with a time (checked 2026-10-27 by read-only schema introspection and a live query:
  `PullRequestCommit` has no timestamp, `PullRequestRevisionMarker` is "the last commit the viewer has seen" and is
  per viewer, and the `pushedDate` field of a commit answers null). A commit's own `committedDate` and `authoredDate` are chosen by
  its author, so they prove nothing and are **never used**. With no force-push to the head the answer is
  **unknown** ("cannot tell when this commit became the head"), so a pull request that only ever received normal
  pushes reads unknown, not fresh. The report's time is the later of its creation and its last edit, so editing an old
  report after a push counts as a new report. A report posted before the head arrived is STALE ("posted before it became
  the head"). This closes the replay: a report naming `aaaa` written while the head was `bbbb`, then a force-push to
  `aaaa`, reads STALE, as does a force-push back to an earlier reviewed commit. A timeline too long to read in full, or
  any event it cannot read, is unknown.
- **The force-push that ended at the head must be the newest force-push of all.** If a later force-push went to
  another commit, the head can only have come back by a normal push (a fast-forward from that commit), and that return
  has no event with a time, so the earlier force-push proves nothing: the answer is unknown ("it returned after a later
  force-push"). A force-push to the head and one to another commit with the same timestamp cannot be put in order
  either: unknown. A force-push back to the head after the other commit makes the head's event the newest again, and
  the report time is then compared as usual.
- **Equal timestamps are unknown.** GitHub timestamps have one-second resolution, so a report and the push (or a base
  change) with the same timestamp cannot be put in order: the answer is unknown ("the report and the push have the
  same timestamp; their order cannot be told"), not fresh and not stale.
- **A base branch change after the report is STALE** (`BaseRefChangedEvent`). This is how the `BASE:` line of the
  header is covered: it is parsed but not compared with anything, and the timeline is the evidence instead.
- A full 40-hex head is compared as is. A shorter one (7 to 39 hex characters) is looked up among the pull request's own
  commits and counts only when exactly one commit starts with it; no match, several matches or a commit list too long to read in full is
  unknown. Fewer than 7 characters, or anything that is not hex (a left-over `<short sha>`), is unknown.
- Anything null, absent, mistyped or truncated in GitHub's answer is unknown, never an empty list: a comment without
  its rendered HTML or author association, a head that is not a full SHA, more than 1,000 comments (the cap on what it
  reads).
- Nothing from a comment reaches the output except the validated SHAs, a role from the fixed list and a verdict from
  the fixed list (`SHIP`, `SHIP WITH CHANGES`, `DO NOT SHIP`, `FINDINGS`, `APPROVE`, `NOT ATTACKED`; anything else is
  left out), and everything printed is escaped. An internal error prints only its class name.
- The client refuses any answer from GitHub over 32 MiB at the one place a body is read, for a query and for a
  mutation alike (an oversized mutation answer is an unknown outcome, never a success), and it does not ask for or
  decode a compressed answer. A response is framed by exactly one of: a single `Content-Length` of ASCII digits, or a
  single `Transfer-Encoding: chunked` (that exact value) with no `Content-Length`. Anything else is malformed framing:
  a sign, spaces, underscores, other scripts' digits, a list, an empty or repeated length; both headers together
  (even when they agree); any other transfer coding (gzip, deflate, compress, identity, a list, another spelling, a
  repeated header). The answer is refused, and a sent mutation is an unknown outcome, because an ambiguously framed or
  cut-short body would otherwise read as complete. JSON nested too deeply, text that is not UTF-8, or `errors` that is
  not a list of objects is an error of the client too, so it ends as unknown like any other.
- **The exit code is the answer.** The verdict is computed first and printed after. If printing fails (a closed
  stream, a broken pipe), the exit code is unchanged. If the verdict cannot be computed for any reason, including an
  exception that is not an `Exception` such as `SystemExit` from a dependency, the exit code is 2 and the line names
  only the class of the error. Only Ctrl-C passes through.

Known limits:

- Review bodies (`gh pr review`) and review-thread comments are not read. A report posted only there reads as no
  report. This is tracked in [#160](https://github.com/ChiefGyk3D/scrum-around-and-find-out/issues/160).
- A normally pushed head cannot be dated (see above), so the check is only useful for a head that arrived by
  force-push, or when you accept unknown. Candidate evidence for a later change (an idea, not built): a real pull
  request review, whose `submittedAt` is set by the server and is tied to a commit, combined with later force-push and
  base-change events; a push webhook or audit-log event that someone keeps outside GitHub; check-suite creation time
  for the head commit. None is used.
- A trusted commenter can still post a forged report after a push: the check cannot tell who wrote it (see below).
- A list item is never read as a report. A report posted as a Markdown list is therefore unknown.
- It sends read queries only (the repository's GraphQL client; GraphQL travels over POST, but no mutation is ever sent).

It proves staleness, not authorship: every agent comments through the maintainer's account, so a forged header from
that account would read as fresh. See [Limits](limits.md). It shows and does not block: no hook calls it, nothing is
invalidated automatically, and the maintainer still decides.

Planned, not built: the merge step runs this check and passes the reviewed head to `safo wait-ci --sha`, so a push after
the review makes the watcher stop. That waits for `safo wait-ci` (GYST pull request 224, not merged yet).

## Before you say "CI is not running"

A pull request with a merge conflict gets no pull-request runs at all, because there is no merge ref to build. "No checks
reported" means look at `mergeable` first. Closing and reopening does nothing. Resolve the conflict.

## Stacked pull requests

Retarget the stacked pull request to the default branch before merging once its base has merged, and check the symbol you
depend on is on the default branch. A merge into a deleted base strands the commit.

## Waiting on a person

Set Status to Blocked. The `agents-status` command lists everything Blocked at the top, because that is the list the
maintainer opens first.
