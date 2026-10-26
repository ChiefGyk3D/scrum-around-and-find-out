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
| 0 | `FRESH` | the latest review report names the current head |
| 1 | `STALE` | it names an older head; both short SHAs are printed. Exit 1 means only this: a crash is exit 2 |
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
- A report header inside a fenced code block (```` ``` ```` or `~~~`) or an HTML comment (`<!-- ... -->`) is a quotation
  and does not count, and neither does a blockquote. An unclosed fence or comment hides the rest of the comment.
- The head is read before the comments and again after them. If it moved, the answer is unknown ("head moved while
  reading"), not a comparison against a stale read.
- A full 40-hex head is compared as is. A shorter one (7 to 39 hex characters) is looked up among the pull request's own
  commits and counts only when exactly one commit starts with it; no match, several matches or a commit list too long to read in full is
  unknown. Fewer than 7 characters, or anything that is not hex (a left-over `<short sha>`), is unknown.
- Anything null, absent, mistyped or truncated in GitHub's answer is unknown, never an empty list: a comment without a
  text body or author association, a head that is not a full SHA, more than 1,000 comments (the cap on what it reads).
- Nothing from a comment reaches the output except the validated SHAs, a role from the fixed list and a verdict from
  the fixed list (`SHIP`, `SHIP WITH CHANGES`, `DO NOT SHIP`, `FINDINGS`, `APPROVE`, `NOT ATTACKED`; anything else is
  left out), and everything printed is escaped. An internal error prints only its class name.
- An answer from GitHub over 32 MiB, JSON nested too deeply to parse, or `errors` that is not a list of objects is an
  error of the client, so it ends as unknown like any other.

Known limits:

- It compares heads, not bases. `BASE:` is parsed but not compared, so a pull request retargeted to another base with
  the same head stays FRESH.
- Review bodies (`gh pr review`) and review-thread comments are not read. A report posted only there reads as no
  report. This is tracked in [#160](https://github.com/ChiefGyk3D/scrum-around-and-find-out/issues/160).
- A report indented as a Markdown code block (four spaces) is not told apart from a header; only fences and HTML
  comments are.
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
