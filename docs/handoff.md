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
   on the pull request; the author fixes them.
6. **CI green, then the maintainer merges.** `CI green` is required by branch protection. Only the maintainer merges.

## Before you say "CI is not running"

A pull request with a merge conflict gets no pull-request runs at all, because there is no merge ref to build. "No checks
reported" means look at `mergeable` first. Closing and reopening does nothing. Resolve the conflict.

## Stacked pull requests

Retarget the stacked pull request to the default branch before merging once its base has merged, and check the symbol you
depend on is on the default branch. A merge into a deleted base strands the commit.

## Waiting on a person

Set Status to Blocked. The `agents-status` command lists everything Blocked at the top, because that is the list the
maintainer opens first.
