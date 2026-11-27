# safo-remerge

`safo-remerge` brings `origin/main` into a feature branch and settles the one kind of conflict that needs no judgment:
two branches that each added a line to the same changelog, home page or README list. Anything else it hands back to an
agent. It never pushes. It is a separate entry point, not a `safo` subcommand.

## Run it

```sh
safo-remerge --worktree /path/to/worktree --test-argv '["python", "-m", "pytest", "-q", "tests/test_x.py"]'
```

`--test-argv` is a JSON list of strings, run directly with no shell, in the worktree. It is required: a merge is never
committed without a test run. `--test-timeout SECONDS` (default 900, at most 3600) kills a test run that hangs.

Run it from outside the worktree: a process other than `safo-remerge` itself that has the worktree as its working
directory (an editor, a shell, an agent) makes it refuse.

## What it does

1. Refuses unless the path is the top of a git worktree on a feature branch (not `main`, not detached), with no merge in
   progress, a clean tree (untracked files count) and no other live process using it as a working directory.
2. `git fetch origin`, then `git merge --no-ff --no-commit origin/main`. Already up to date is exit 0.
3. For each conflicted path, only these are settled by code:
   - `CHANGELOG.md`, inside its `## Unreleased` section only.
   - `docs/home.md` and `README.md`.
   - `pyproject.toml`, inside its console-scripts table only: both sides may add lines of the exact shape
     `key = "MODULE:FUNCTION"` (the value must be a module of this package, lower case with digits and underscores,
     a colon and a lower-case function name; no trailing comment). The lines
     are kept, ours first then `main`'s, because the table is unsorted. A key that would appear twice (including the
     same key with two different values, or a key already in the table), an edited or removed line, an addition outside
     the table or any other pyproject conflict (dependencies, tool settings, version) goes to an agent. An added line
     with leading space, odd spacing around the `=`, quotes or a comment is refused. Keys already in the table are
     compared after stripping leading space; a table that holds a quoted key, a dotted key or a value continued over
     several lines is refused as a whole, because the rule cannot reason about it.

   Both sides must have only added lines, and every added block must start with a list item (`-`, `*`, `+` or `1.`) or a table row
   (`|`); indented continuation lines are accepted only after such a row inside the same block. The added lines are kept, this branch's first, then the lines from `main`.
   A line that would appear twice, a blank or prose line, a changed or removed line, a symlink, a delete on one side or
   a conflict marker sends the whole merge to an agent. The rule reads the whole file, so a branch that also reworded an
   old line of one of these files goes to an agent as well.
4. Any other conflicted path, or any path that fails those rules: `git merge --abort`, the tree is checked back to the
   starting commit and clean, and the exit is 11 with one `needs-agent: PATH` line per conflicted path.
5. After a clean result, runs the test command. Exit 0 commits the merge with a fixed message; any other exit, or a
   timeout, aborts the merge and restores the tree (exit 12). The test exit code is printed as `tests: exit N`. The command's output is captured and
   its last 40 lines are shown through the safe output helper (`test> ` prefix), never passed through raw. A git step that
   times out aborts and restores the merge too (exit 13).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Merged and committed, or already up to date |
| 2 | Usage: missing or malformed `--test-argv`, bad timeout, bad path |
| 10 | Refused: dirty tree, live process, `main` or detached, merge in progress |
| 11 | Needs an agent: the paths are printed; the merge was aborted and the tree restored |
| 12 | Tests failed or timed out; the merge was aborted |
| 13 | A git step failed; the merge was aborted |
| 14 | The tree could not be restored; look at it by hand |

## Replacing the changelog rule

The changelog rule is one function, `resolve_changelog`, listed in `RESOLVERS`. When changelog fragments land (#581) a
fragments-aware function replaces that one entry; the merge, the abort and the test run stay as they are.

Tests: `tests/test_remerge.py`, on real temporary git repositories.
