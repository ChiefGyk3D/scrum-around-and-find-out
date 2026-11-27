# `safo-idle-check`: the never-idle Stop hook (#578)

## Why

The never-idle rule ("do not end a turn with fewer than 6 workers while independent ready work exists") was doctrine
only. On 2026-11-27 the lead ended a turn with free capacity while PRs #564, #559, #552 and #574 were ready. Nothing
counted workers at turn end. This check counts them in code and blocks the end of the turn with the ready list.

## Shape (a separate check; no frozen code is touched)

- New module `idlecheck` in the safo package, new console script `safo-idle-check`. It is its own
  Stop-hook entry point, like `safo-guard`. It does not use argparse, does not import the mode registry, and adds
  nothing to `TOP_LEVEL_COMMANDS`. The frozen guard code, `safo hooks stop` and `settings.json` are not edited.
- The only shared-file change is one line in the scripts table of the project file (the console script).

## What it decides

Block when `running < floor` AND `ready` is not empty. Otherwise allow (silent). Output on a block is
`{"decision": "block", "reason": "<count, floor, the ready items>"}` on stdout, exit 0 (Claude Code then makes the
lead continue). `stop_hook_active: true` always allows, so one block cannot loop; the next stop of the same turn ends it.

### Running count (from the host, never a model)

1. Subagents: `<transcript dir>/<session>/subagents/agent-*.jsonl` files whose mtime is within `window_seconds`
   (default 300) and whose last line is not a finished assistant message (`stop_reason: end_turn`).
2. Detached jobs: the process table (`/proc`): the top-most process of each chain whose command line is `codex exec`
   or `daybreak-run`. A `timeout`, `bash -c` or `node` wrapper of the same job counts once.

### Ready work

1. Open PRs (`gh pr list`, 10 s per repo, 30 s total) in the configured repos, that are failing a check or CONFLICTING,
   and that no running agent names. "Unreviewed" (`reviewDecision` REVIEW_REQUIRED or empty, non-draft only) is an
   opt-in (`include_unreviewed`, default off): it listed 120 items on 2026-11-27, which is noise. An agent
   names a PR when `#N`, `pull/N`, `PR N` or the head branch appears in the first 4 KB of its transcript (subagents)
   or in its command line (processes).
   Only PRs from a trusted author count (#601): the repo owner (the part of `owner/repo` before the slash), a login in
   `trusted_authors`, and a PR from the same repository (`isCrossRepository` false). A fork PR is skipped unless
   `allow_forks` is on; the fork flag must be a real true or false either way. Bots count only when listed by their
   exact login, which keeps the prefix gh gives apps (`app/dependabot`); an app is never the owner. Case is ignored. `gh pr list` has no `authorAssociation` field, so association is not used. Fails closed: a missing or
   unreadable author or fork flag is not trusted, and an old cache entry without an author is not trusted. A skipped
   PR is counted in the log field `skipped_untrusted` (failing or conflicting PRs only) and is never listed in the
   reason, so an outsider cannot steer dispatch with a PR.
2. Unstarted QUEUE.md items: a `READY:` line (items split on `;`), and rows of the dependency table
   (`| item | depends on | state |`) whose state is ready (or blank, todo, queued) and whose dependency cell is `none`
   or blank, or whose state says `ready`. Rows that are running, blocked, held, done or merged never count.

## What the block reason may contain (untrusted text)

The reason is fed to the model as text next to its instructions, so it carries no third-party string. A PR is shown as
`owner/repo#number (failing, conflicting)` with fixed reason codes only: no title, branch name or author. A QUEUE.md item
is shown only as where it is (`queue file QUEUE.md line 12`, plus `item k` for the kth item of a `READY:` line), never its
text, because queue lines are free text. Every piece still goes through the output module's line function. DEGRADED notices are fixed
text (a repo name from the owner's own config at most). Tests: a title, branch and queue line holding instruction-like
text and an escape byte must not appear in the output.

## Fail open, loudly

Each source fails on its own. A source that cannot be read (no `gh`, a timeout, an unreadable queue or registry) adds a
`DEGRADED: <source>` line to a `systemMessage` and a `degraded` row in the log; the others still decide. If the running
count itself cannot be read the hook allows (it cannot tell) and says so. An unexpected exception allows with the same
notice. It never stays silent on a failure, and never blocks on a guess.

## Configuration

`~/.config/safo/idle-check.json` (optional) and environment variables (win over the file):

| key | env | default |
|---|---|---|
| `floor` | `SAFO_IDLE_FLOOR` | 6 |
| `queue_paths` | `SAFO_IDLE_QUEUE` (path list, `:`) | `~/.local/share/agent-box-dev/QUEUE.md` |
| `repos` | `SAFO_IDLE_REPOS` (comma list) | `hooks.tracking_repos` of `~/.config/safo/agents.yaml`, else none (degraded notice) |
| `window_seconds` | `SAFO_IDLE_WINDOW` | 300 |
| `exempt` (`owner/repo#N` list) | | none |
| `include_unreviewed` | `SAFO_IDLE_UNREVIEWED=1` | off |
| `trusted_authors` (login list) | `SAFO_IDLE_TRUSTED` (comma list) | none; the repo owner is always trusted |
| `allow_forks` | `SAFO_IDLE_FORKS=1` | off |
| `cache_seconds` | `SAFO_IDLE_CACHE` (0 turns it off) | 60 |
| `mode` | `SAFO_IDLE_MODE` | `block` (`warn` prints the same text as a `systemMessage` and never blocks) |

## PR scan cache

The scan of every tracked repo took about 28 s, and it runs at each Stop. The PR list of a complete scan is kept for
`cache_seconds` in `idle-check-prs.json` beside the log, keyed on the exact repo list. A scan with any failure is never
cached, and a missing or damaged cache is a miss, so the check still fails open and loud. Agent coverage and the
running count are always read live; only the gh answers are cached.

## Measure

Every run appends one JSON row to `~/.local/share/safo-dev/idle-check.log` (override `SAFO_IDLE_LOG`):
`ts, decision (allow|block|degraded|active), running, ready, skipped_untrusted, floor, session`. `safo-idle-check --stats` prints blocks
per day, allows and degraded runs. Target: blocks per day trend to 0 while ready-and-not-running stays 0 at turn end.

## Install (the owner applies it)

Add a second command to the `Stop` hook list in `settings.json`; see the report for the exact diff. Not installed by
this change.

## Limits

The registry read assumes the Claude Code transcript layout (`subagents/` beside the session transcript). A format
change shows as a degraded notice, not a wrong block. Queue parsing is for the table and `READY:` forms above; prose
lines are ignored. PR matching by text is a heuristic: an agent that never names its PR leaves it listed as ready.
