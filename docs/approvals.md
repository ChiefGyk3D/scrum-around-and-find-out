# Approval issues

Part of the process-method work (spec `docs/superpowers/specs/2026-10-26-process-profiles.md`, section 3.2).
`src/safo/approvals.py` decides whether a gate, change or freeze issue counts as an approval. It reads, it never
writes, and it answers `approved`, `open` (with the reason line) or `UNKNOWN`. A read it cannot finish in full is
`UNKNOWN`, never a pass.

## Naming the entry (M13)

A change approval must say which change it approves. The issue **body** must hold exactly one line of this form,
and nothing else on that line:

    Entry: owner/repo#N

- `owner/repo#N` is the `add` or `remove` reference of the `changes` entry, in ASCII. The owner and repository are
  compared after an ASCII-only case fold; the number is compared as an integer.
- The title is never used. A prose mention, a link target or an image URL is not an entry.
- The grammar is intentionally narrow, so that what the approver saw is what is read:
  - Lines inside fenced code are not read. A fence follows CommonMark: it opens with three or more backticks or
    tildes after at most three spaces (a backtick fence's info string may not hold a backtick), and it closes only on
    a line of the same character, at least as long, after at most three spaces, followed by nothing but spaces or
    tabs. A line such as ```` ```oops ```` does not close it. An unterminated fence hides everything after it.
  - **Any raw HTML outside fenced code refuses the whole body** (`UNKNOWN`, "has raw HTML in its body"). That is any
    `<` that begins a tag, comment, declaration, processing instruction or autolink, even inside an inline code
    span. A bare `<` in prose (`a < b`, `<3`) is fine. This is deliberate: `<details>` and similar elements hide
    Markdown the approver does not see, and the reader does not try to model them.
  - A line right after a quote (`>`) or list line, with no blank line between, is a continuation of that block and
    is not an entry line.
  - A second `Entry:` line (even an equal one), or any trailing text or space, means the approval is not for this
    change.

## Edits after the approval

The approval is refused when the issue was edited, renamed or reopened at or after the close. The comparison is
`>=` because GitHub timestamps have one-second resolution: an edit in the same second as the close cannot be
ordered, so it does not pass. Re-approving means reopening and closing the issue again, which moves the close time.
Timestamps that cannot be true (the issue created after its close, or an edit, rename or reopen before it was
created) make the answer `UNKNOWN`.

## Who counts

The close must be manual (no `closer`), completed, not a duplicate, and not performed through a GitHub App. The App
check is the REST cross-check, passed to `verdict()` as a `CrossCheck`: only `VERIFIED_MANUAL`, built by
`cross_check_from_events()` from a complete matching REST read, can approve. `UNCHECKED`, or anything that is not a
`CrossCheck`, is `UNKNOWN`; the type has no truthiness, so no falsey value stands for "checked".

The closer must be a `User` whose `databaseId` is in the board file's approver list. A login is never the identity;
it only words the line.

The issue must have been opened by an account whose author association is `OWNER`, `MEMBER` or `COLLABORATOR`.
That is a filter, not a grant of trust: `COLLABORATOR` can include outside collaborators with only read or triage
access. The actor table (the approver list, by id) decides who approves.
