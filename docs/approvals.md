# Approval issues

Part of the process-method work (spec `docs/superpowers/specs/2026-10-26-process-profiles.md`, section 3.2).
`src/safo/approvals.py` decides whether a gate, change or freeze issue counts as an approval. It reads, it never
writes, and it answers `approved`, `open` (with the reason line) or `UNKNOWN`. A read it cannot finish in full is
`UNKNOWN`, never a pass.

## Naming the entry (M13)

A change approval must say which change it approves. The issue **body** must hold exactly one line of this form,
and nothing else on that line:

    Entry: owner/repo#N

- `owner/repo#N` is the `add` or `remove` reference of the `changes` entry. The owner and repository are compared
  after an ASCII-only case fold; the number is compared as an integer.
- Only a line that starts `Entry:` at column 0 counts. Text inside an HTML comment, a fenced code block
  (backticks or tildes), a raw HTML block, a quoted reply (`>`) or an indented block is ignored, and a mention in
  prose, a link target or an image URL is not an entry.
- A second `Entry:` line, with the same or another reference, or any trailing text (`owner/repo#12x`, a trailing
  space), means the approval is refused with the `does not mention ... on its own Entry: line` line.
- The title is never used. This replaces the whole-token search of the spec's line 8: that search ran on raw
  markdown, so a hidden comment could satisfy it.

## Edits after the approval

The approval is refused when the issue was edited, renamed or reopened at or after the close. The comparison is
`>=` because GitHub timestamps have one-second resolution: an edit in the same second as the close cannot be
ordered, so it does not pass. Re-approving means reopening and closing the issue again, which moves the close time.

## Who counts

The close must be manual (no `closer`), completed, not a duplicate, not performed through a GitHub App (the REST
cross-check, given to `verdict()` as `via_app`), made by a `User` whose `databaseId` is in `process.approvers`,
on an issue opened by an owner, member or collaborator. A login is never the identity; it only words the line.
