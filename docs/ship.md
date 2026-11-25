# safo-ship: the merge watcher

`safo-ship` waits for CI on an exact commit and then merges that commit. It is a tool, not a guard: it only reads and
merges pull requests through `gh`, and it changes no hook, setting or guard file. It is the tested replacement for a
hand-written watcher (issue #85). Hand-written watchers have called a pull request green when the rollup was empty, when
it was half filled, or when only one of two required checks had reported.

## What it does, per pull request

1. **Pins the head commit** (the first one it reads, or `--expect-head`). If the head moves at any point it stops and
   prints the new head. The merge itself passes `--match-head-commit <pinned sha>`.
2. **Waits, bounded**, until the rollup is complete and the required checks are present and succeeded. Required means the
   check named `CI green` plus every context the base branch's protection lists. An empty rollup, a missing required
   check, or any run still queued or in progress is pending, never done. The wait ends at `--timeout` seconds or
   `--max-polls` polls, whichever comes first.
3. **Re-runs** a cancelled job once per run, and a job whose only failed step is the egress canary (`EX-0001`, an
   approved risk exception) at most twice per run. Any other failure is real and is never re-run. The gate failing
   beside a job that is being re-run is not counted as a second failure.
4. **Requires 0 unresolved review threads.** Otherwise it stops (exit 3) and prints each one: the file and line, the
   comment's link, the author, and the first 600 characters of the comment (control and format characters stripped,
   newlines folded to spaces, `[truncated]` after a cut). It never resolves a thread and never merges past one. This is
   a different exit code from a CI failure.
   With `--wait-for-review SECONDS` (0 to 900, default 0), it first waits for a review by the automated reviewer
   (`copilot-pull-request-reviewer`) on the pinned head, polling every `--interval` seconds through REST
   (`gh api repos/OWNER/REPO/pulls/N/reviews`). The wait ends at the first such review, at SECONDS, at `--timeout` or at
   `--max-polls`, whichever comes first; if none arrived it prints a `NOTICE` and goes on to the thread check either way.
   A head that moves during the wait stops with exit 4, as everywhere else.
5. **Merges**, retries once on "Base branch was modified", then reads the state back and reports `MERGED` only if GitHub
   says so.

`--open-pr --title T --issue N` first pushes the branch (never forced, never `main`), opens the pull request with the body
`Closes #N` (or reuses the open one for the branch), and pins the pushed commit.

## Use

```
safo-ship 123 124 --repo owner/name            # watch and merge, in the order given
safo-ship --open-pr --title "Add x" --issue 85 # push, open, wait, merge
```

One line per pull request, for example `MERGED owner/name#123 head=0123456789ab`; unresolved threads follow as indented
lines.

## Exit codes (several pull requests: the highest wins)

| Code | Meaning |
| --- | --- |
| 0 | merged (or already merged) |
| 1 | CI failed: a real failure, or a re-run budget used up |
| 2 | usage error |
| 3 | unresolved review threads |
| 4 | head moved; the new head is printed |
| 5 | timed out while still pending |
| 6 | merge refused, or the read-back did not say `MERGED` |
| 7 | error: gh or git missing or failing, push or open failed, protection unreadable |

Protection is read from the base branch; a 404 means "none listed" and `CI green` is still required, any other failure to
read it, or an answer of an unexpected shape, is exit 7. A required context with a ` / ` in it must match exactly; only a
bare name such as `CI green` also matches the tail of a `workflow / job` spelling. The wait never sleeps after its last
poll. A merge gh refuses is re-checked: if the head moved meanwhile the result is `HEAD-MOVED` (exit 4) with the new sha. Branch rulesets are not read.

## safo-wait-ci

`safo-wait-ci <owner/repo> <pr|sha>` is the same engine without the merge: read-only, it waits for CI on a pull request
number, or on a 40-hex commit that is the head of exactly one open pull request (the sha is pinned), and prints one line
(`GREEN owner/name#N head=...`, or the result word of the table above). Same exit codes (0, 1, 4, 5, 7).

The issue asked for a `safo wait-ci` subcommand. Adding a `safo` subcommand needs a one-line edit of the guard's
`TOP_LEVEL_COMMANDS` tuple, which is guard code, so it is left to a follow-up that needs the owner's explicit OK. The
separate `safo-wait-ci` entry point delivers the behavior meanwhile.

The monitor-agent template in [Orchestrator](orchestrator.md) stays read-only; a lead that needs a merge watcher runs this
tool in the background instead of writing one.
