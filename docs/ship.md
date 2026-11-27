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
| 7 | error: gh or git missing or failing, push or open failed, protection unreadable, or a malformed answer |
| 8 | conflict with the base branch (`--queue` only; an agent must resolve it) |
| 9 | PROTECTED: branch protection does not require conversation resolution (plain and `--queue`), or (`--queue`) refused the merge |
| 10 | NEEDS-HUMAN: the pull request changes a workflow file, so it is never merged automatically (plain and `--queue`) |

Protection is read from the base branch with `gh api -i`; only an HTTP 404 status line means "none listed" (text in stderr
is never used to decide that) and `CI green` is still required, any other failure to
read it, or an answer of an unexpected shape, is exit 7. A required context with a ` / ` in it must match exactly; only a
bare name such as `CI green` also matches the tail of a `workflow / job` spelling. The wait never sleeps after its last
poll. A merge gh refuses is re-checked: if the head moved meanwhile the result is `HEAD-MOVED` (exit 4) with the new sha. Branch rulesets are not read.

## Where a required check must come from

A required check counts only as a successful check run of the right GitHub App on the pinned commit, read from the
check-runs API with every page. A commit status of the same name never counts, and neither does a check run of another
app. The app is the `app_id` that branch protection lists for the context; `CI green` is always checked, by default
against GitHub Actions (app 15368, `--gate-app-id` to change it; that flag weakens nothing below, but a wrong id only
makes the gate wait or time out).

The app id does not say which workflow ran: every workflow in the repository posts as the same app, and a check run's
name is chosen by its author. So for `CI green` the check run is also tied to its workflow run (the run id in its
details URL, then `GET actions/runs/<id>`), and it counts only when that run

- has `path` equal to the gate workflow file: `--gate-workflow PATH`, else the one `.github/workflows/ci.yml` (or
  `ci.yaml`) listed on the base branch; if neither is derivable the tool stops with exit 7 and asks for the flag;
- has `head_sha` equal to the pinned commit, belongs to this repository, and is bound to this pull request: a
  `pull_request` run that lists this PR number with this base branch, or a `push` run on this PR's head branch (a run
  from a fork lists no PR and never counts);
- and it counts as green only with status `completed` and conclusion `success`: a failed run of the gate on the pin is a
  failure, never dropped.

A same-name job from some other workflow, or a run for another PR with the same sha, is ignored, not fatal. The gate path
is read from the base branch, never from the pull request.

Because a pull request can edit the gate, or what it executes, any pull request that changes anything under `.github/`
(workflows, local actions, CODEOWNERS), the gate file, a `--protect-path PATH` (repeatable; a file or directory, matched
on whole path parts), or whose changed-file list is 300 or longer (the compare API cannot show more), or whose gate file
differs between the base and the pinned head, stops with `NEEDS-HUMAN` (exit 10) and the first such file. A human merges
it. Before that check and again right before the merge call the pull request is re-read: a base branch that is no longer
the one the checks were read for is `MERGE-REFUSED`, a moved head is `HEAD-MOVED`.

The gate file is also read at the pinned head with a YAML parser (no anchors or aliases; at most 256 KiB, 50 references per
file, 20 files, 3 levels of local workflows) and every `uses:` of `jobs.*` and `jobs.*.steps[*]` must be one of: a remote
reference pinned by a 40-hex commit sha, a docker image pinned by a `sha256` digest, or a local workflow or action
(`./path`) whose content is identical on the base and the pinned head (local workflows are followed). A local path may
hold only `[A-Za-z0-9._/-]`, no empty, `.` or `..` part, at most 200 characters; anything else is `NEEDS-HUMAN` ("local
workflow reference has unsupported characters"). Contents are asked for with each path part percent-quoted and the ref as
a `-f ref=` field (never in the URL), and an answer about a different path than the one asked for is exit 7. Anything else, a file
that does not parse or has an odd shape, or a word `uses` outside comments that the parse did not account for (a block
scalar, a flow mapping, a duplicate key), is `NEEDS-HUMAN` ("too many references or nesting too deep to verify" when a cap
is hit); a comment that says "uses" is ignored, a name or string that says it stops the tool and a human reads the file.

The `run:` steps are read too, with a strict allowlist grammar (the shipscan module), not a best-effort reading of shell:
deriving the executed files from arbitrary shell is an open-ended class, so anything outside the grammar is a human stop.
A `run:` text is accepted only when every line is one of these, and the offending line is named in the result:

- blank, or a comment line (first character `#`);
- `cd DIR` on its own, DIR a repository-relative literal path (it moves the lines after it, within that text only);
- an interpreter (bash, sh, python, python3, node, ruby, perl, pwsh), then options from a short per-interpreter list of
  flags that take no value (for example `-e`, `-u`, `-B`, `--no-warnings`), then exactly one repository-relative script
  path, then plain literal arguments;
- a repository-relative executable path that contains a slash, then plain literal arguments;
- an exact command name listed with `--gate-command NAME` (repeatable, for example `make` or `pytest`), then plain
  literal arguments. No file is derived from such a command: list it only together with `--protect-path` for its inputs.

A line may use only letters, digits, `.`, `_`, `/`, `=`, `:`, `@`, `,`, `+`, `-` and spaces. So there are no quotes,
variables, `${{ }}` expressions, pipes, lists (`;`, `&&`, `||`), background jobs, redirections, subshells, command
substitution, backticks, heredocs, continuations, tabs, globs or `~`. A path has no empty, `.` (except a leading `./`) or
`..` part and does not start with `/`. Refused outright: any wrapper (`sudo`, `env`, `timeout`, `nice`, `xvfb-run`,
`strace`, `uv run`, `npx`...), `VAR=value` prefixes, an interpreter option that takes a value, `-c`, `-m`, `-e`,
`source`, `eval`, and every command that is not listed. Each script found is compared between the base and the pinned head
(by content sha); a difference is `NEEDS-HUMAN` naming the file. A file missing at both refs is a generated one and is left
alone. The same grammar applies to the steps of local composite actions (which must name `shell: bash` or `sh`).

Each step also runs from the repository root in bash or sh: a `working-directory`, and a shell other than bash or sh, in
the step, the `run` defaults of the job or of the workflow (the job's own value wins, key by key), is
`NEEDS-HUMAN`; an unset shell counts as bash only on a literal `ubuntu-` or `macos-` runner label (on Windows it would be
pwsh, on any other label it is unknown). An unreadable workflow or action file is exit 7 (only a clear HTTP 404 status line
counts as missing); a local action directory that does not exist is exit 7, and one without an `action.yml` or
`action.yaml` is `NEEDS-HUMAN`.

What this does not see, stated plainly: the text of the scripts themselves (what a script sources or runs is not read; list
those paths with `--protect-path`), Makefile targets and the files a listed command uses, configuration, test
inventories, installed dependencies, and what a Python or Node program imports. The price of closing the gap by
construction is more human stops, which is the right trade for an unattended merge gate. The real controls remain
rulesets with required workflows and CODEOWNERS on the files the gate relies on; this tool narrows the gap and does not
replace them. The workflow run's `path` match is a name match, not a signature. A protected context with no `app_id` is
accepted from any source: pin it. Other pinned contexts are checked by app and name only, not by workflow.

The base is pinned too. Its tip is read before any check and compared again right before the merge; when it moved, or
the merge call answers "Base branch was modified", nothing is merged on the old checks: the whole chain (required
checks, gate path, workflow and file comparisons, run binding, threads, protection) runs again against the new base, once,
on the same head, and a second movement is `MERGE-REFUSED`. The gate's check runs are read once more right before the
merge, and branch protection is read again for every pull request, never remembered from the one before. One merge call
is made per pass.

## Queue mode

```
safo-ship --queue 123 124 125 --repo owner/name --pin 123=<40-hex head>
```

The pull requests are taken one at a time in the order given, each pinned to one head, and the queue stops at the first
that does not merge: that line is its result word, each later one prints `SKIPPED` and is never read. PR numbers are
positive. Differences from the plain mode:

- `--pin N=SHA` pins PR N to a commit you pushed. If the API still shows an older head, it is re-read for up to 6 polls
  (and never past the deadline) before `HEAD-MOVED`. A head that changes after it was seen is `HEAD-MOVED` at once.
- A branch that is `BEHIND` gets one `update-branch` call (with `expected_head_sha` set to the pin). The new head is
  pinned only when it is the merge commit GitHub made: exactly the two parents (the pinned head, then the base tip read
  just before the call), a signature GitHub verified, and the `web-flow` committer. Anything else is `HEAD-MOVED`. CI is
  then waited for again on the new head. A second `BEHIND` stops with `MERGE-REFUSED`.
- Stop words: `CONFLICT` (8), `THREADS` (3, with the count and each thread), `CI-FAILED` (1, naming the failing checks),
  `PROTECTED` (9), `MERGE-REFUSED` (6), `HEAD-MOVED` (4), `TIMEOUT` (5), `ERROR` (7). A merge gh refuses is classified
  from the pull request's merge state (`mergeable`, `mergeStateStatus`), and that state always wins: a clean state with
  a merge error is a plain `MERGE-REFUSED`, whatever the text says. The error text is read only when the state is
  missing or `UNKNOWN`.
- `--timeout` is one deadline per PR, shared by the head wait, update-branch, CI, the review wait and the thread read; no
  sleep goes past it, each `gh` call gets at most the time left (min of the per-PR time, the total time and 60 s), no call
  is started once it has passed (`TIMEOUT`, exit 5), and no merge retry starts after it. A merge call that was already
  sent is followed by its read-back, which may use up to 30 seconds past the deadline (`RECOVERY_SECONDS`) because it only
  settles what the call did; no second merge call starts after the deadline. `--total-timeout`
  (default 7200, at most 28800) bounds the whole run: the PR it cuts off prints `TIMEOUT` and the rest `SKIPPED`.

### The thread check needs branch protection

Review threads are not part of the head commit, so `--match-head-commit` does not cover them. The tool reads the threads
as its last thread read before the merge call, but a thread opened between that read and the merge cannot be stopped by
the tool; only GitHub can make it atomic, with branch protection's "Require conversation resolution before merging" (and
a merge identity that cannot bypass it). So, in plain and queue mode alike, the tool reads
`branches/<base>/protection` and refuses to merge (`PROTECTED`, exit 9, "conversation resolution is not required by
branch protection; thread check would be best-effort") unless `required_conversation_resolution.enabled` is exactly
true; an unreadable or oddly shaped answer is a refusal too. `--best-effort-threads` opts out: the merge goes ahead
after the thread check with a `NOTICE`, and the race above is a known, accepted risk of that flag. On this repository's
`main` the setting was off when read on 2026-11-27, so without the flag `safo-ship` stops there until it is turned on.

## safo-wait-ci

`safo-wait-ci <owner/repo> <pr|sha>` is the same engine without the merge: read-only, it waits for CI on a pull request
number, or on a 40-hex commit that is the head of exactly one open pull request (the sha is pinned), and prints one line
(`GREEN owner/name#N head=...`, or the result word of the table above). Same exit codes (0, 1, 4, 5, 7).

The issue asked for a `safo wait-ci` subcommand. Adding a `safo` subcommand needs a one-line edit of the guard's
`TOP_LEVEL_COMMANDS` tuple, which is guard code, so it is left to a follow-up that needs the owner's explicit OK. The
separate `safo-wait-ci` entry point delivers the behavior meanwhile.

The monitor-agent template in [Orchestrator](orchestrator.md) stays read-only; a lead that needs a merge watcher runs this
tool in the background instead of writing one.
