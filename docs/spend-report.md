# Spend report

`safo spend` is the yardstick for every token-savings change: one weekly report of weighted Claude spend, with a stored
baseline so a later week prints the change per line. It is read-only and prints counts and sums only: no prompt text,
no titles, no paths and no labels from a file.

```sh
safo spend --week 2026-W48                       # one ISO week (default: this week); `all` for every week found
safo spend --week 2026-W48 --merges merges.txt   # add the per merged PR line
safo spend --baseline ~/spend-baseline.json      # first run writes it; later runs print the change
safo spend --json week.json                      # the same numbers in a new file (mode 0600)
```

## Inputs

Every input is a flag with a default, and is checked like the other local modes: a path under `GITHUB_WORKSPACE` is
refused under Actions, a symlink or a file that is not regular is refused (the open does not follow a link and does not
wait on a FIFO), and a missing default is reported as not found while a missing path you gave is an error.

| Flag | Default | Holds |
|---|---|---|
| `--claude` | `~/.claude/projects` | Claude transcripts: the lead is a main session file, an agent is `subagents/agent-*.jsonl` with its `.meta.json` |
| `--codex` | `~/.codex/sessions` | Codex sessions, counted apart and never added to the Claude numbers |
| `--llm-local` | `~/.local/share/llm-local/calls.jsonl` | the `llm-local` calls and outcome rows |
| `--hook-log` | `~/.local/state/safo/hooks/log.jsonl` | one row per dispatch: local step, marked n/a, and the n/a reason class when the log carries one |
| `--share-log` | `~/.local/state/safo/local-share.jsonl` | the `safo-draft` calls |
| `--merges` | none | a plain text list of merge dates, one `YYYY-MM-DD` per line (`#` comments and blank lines are skipped) |

## Weights

Weighted tokens are input tokens x1, output x5, cache read x0.1 and cache write (creation) x1.25. They are the constants
`WEIGHT_INPUT`, `WEIGHT_OUTPUT`, `WEIGHT_CACHE_READ` and `WEIGHT_CACHE_WRITE` in `src/safo/modes/spend.py`. The ratios
are inferred from published price ratios and are the same for every model, so the numbers rank patterns inside one
meter; they are not dollars. Codex has no cache write: its uncached input counts x1 and its cached input x0.1.

A transcript writes one row per content block, so rows are de-duplicated by message id and the row with the largest
output count wins. A message belongs to the ISO week (UTC) of its own timestamp.

## What the report holds

1. Weighted spend by pool: the lead, and agents by type (`implementer`, `general-purpose`, `reviewer` including
   `adversarial-reviewer`, and `other`, which also takes an agent whose `.meta.json` is missing or unreadable).
2. The cache-read share of lead and of agents, as a share of weighted spend and as a share of all tokens, and the output
   share of weighted spend.
3. Weighted tokens per lead turn, and the share of lead turns past turn 200 and past turn 400 (by count and by weighted
   spend). Turns are numbered from the start of the session file, not from the start of the week.
4. Weighted tokens per merged PR: the week's Claude weighted spend divided by the merge dates in the week from `--merges`,
   or "not given".
5. Local use: real `llm-local` calls (a task starting with `eval-` is counted apart), calls with project none, failed or
   busy calls, outcome rows by outcome, the share of dispatches with a local step and with an n/a reason class, and the
   `safo-draft` calls.
6. The first-turn context of agents: the median in tokens, and the median share taken by the instruction files and the
   skill listing where the transcript shows them (sizes in characters, divided by 3.5 characters per token, an estimate).
7. Codex sessions of the week, counted apart.

The hook log written by `safo hooks` has no n/a reason class today; the dispatch guard log does. Point `--hook-log` at
the dispatch guard log to see the class split.

## Baseline

`--baseline PATH`: when the file does not exist, the run writes the report's numbers there (created exclusively, mode
0600) and says so. When it exists, it is read with the bounded JSON loader and never rewritten; the report ends with one
line per number: the value now, the baseline value, the change and the percent. A number the baseline lacks is marked.
`--json PATH` writes a new file the same way and refuses an existing one before it reads anything. To start a new
baseline, delete the old file yourself.

## Bounds

The run stops with a message, and prints no report, when it meets a bound: 50,000 transcript files, folders nested more
than 8 levels, 512 MiB in one file, 64 MiB in one log, 1,000,000 log lines, or 900 seconds. A line over 8 MiB, a line
that is not valid JSON (including a repeated key), a usage count that is not a bounded non-negative integer, and a
symlink or special file inside a folder are skipped and counted at the foot of the report. Files last written before the
week began are not opened. A full `--week all` over several gigabytes of transcripts takes minutes.

## What it does not show

No dollars, no per-model price, no quality measure, and no brief text: whether a brief named a local step comes from the
hook log, never from reading the brief.

## Lead-session curve (`safo lead-curve`)

A read-only companion report (#556, phase 1: measuring only, no hook and no prompt) that shows how lead-session cost
grows with turn position. `safo lead-curve [--week W|all] [--claude DIR]` reads the lead transcripts the way `safo spend`
does (same bounds, same weights, symlinks and special files refused and counted) and writes nothing. Per session it
prints the turn count, the context tokens (input + cache read + cache write) at the first and last turn and summed over
the turns, and the weighted spend by turn bucket (1-100, 101-200, 201-300, 301+); sessions are numbered, never named,
and the 25 longest are shown. The summary gives the share of lead turns and of weighted spend past turn 200 and 400,
and three labeled lines side by side. First, the first turn past 20 at which a 10-turn mean of the per-turn mean spend
passes 1.5 times the median spend of turns 1-20 (`not reached` when it never does). Second, the cumulative view: the
turn after which 50 and 80 percent of a session's weighted spend has been reached, as a median across sessions. Third,
the old definition (1.5 times the median of turns 1-100), kept for comparison: it is weak on real data, because spend
per turn rises with context, so the first-100-turn median is already high and the line trips at turn 101 or never. A handoff is a session whose first user message contains
"handoff", "hand-off" or "handover" (a yes or no, never printed), paired with the latest earlier session of the same
project folder. Its cost has two numbers: the successor's first three turns, MEASURED, and the cost of writing the
note, an ESTIMATE (the largest single reply in the predecessor's last five turns, output tokens x5). Counts only:
no text, title, path, project name or hostname is printed.
## Posting the weekly summary to a private issue

`safo spend-post` runs the same report and posts a short summary as one comment on an issue of a PRIVATE repo. It takes
every input flag `safo spend` takes (`--week`, `--claude`, `--codex`, `--llm-local`, `--hook-log`, `--share-log`,
`--merges`, `--baseline`) and adds `--repo OWNER/REPO`, `--issue N` and `--dry-run`.

```sh
safo spend-post --repo OWNER/PRIVATE-REPO --issue 123 --baseline ~/spend-baseline.json --merges ~/merges.txt
safo spend-post --repo OWNER/PRIVATE-REPO --issue 123 --dry-run    # print the body, post nothing
```

- Before anything else it asks `gh api repos/OWNER/REPO --jq .private`. Only the answer `true` goes on; `false`, an
  empty or odd answer, or a failed lookup refuses the run with exit 2 and posts nothing. A public repo is never a target.
- The body is counts, weighted totals by pool and the change since the stored baseline, from fixed labels and numbers.
  Measured numbers (token and file counts) are separated from the weighted ones, whose price ratios are inferred, and
  the first-turn instruction share is labeled an estimate. It holds no path, user name, host name, title or transcript
  text; as a last check the run refuses when the body contains the home directory, the user name or the host name.
- The comment is posted once and never retried. A failed post exits 2; the next run starts clean.
- With `--baseline`, a missing file is written after a successful post (never on `--dry-run`); an existing one is
  only read, as for `safo spend`.
- Nothing here schedules itself and no setting or secret is added. `gh` must already be signed in for the account.

### Running it weekly

A systemd user timer: save the service unit and the timer unit below under the name `safo-spend-post` in
`~/.config/systemd/user/` (the suffix of each is its kind), then enable the timer unit with
`systemctl --user enable --now` and its full unit name.

```ini
# the service unit
[Service]
Type=oneshot
ExecStart=%h/.local/bin/safo spend-post --repo OWNER/PRIVATE-REPO --issue 123 --baseline %h/spend-baseline.json
```

With `--week` left off the run reports the current ISO week (UTC), so the timer fires late on Sunday:

```ini
# the timer unit
[Timer]
OnCalendar=Sun 23:30 UTC
Persistent=true
```

The timer unit also needs the usual `[Install]` section that makes it wanted by the timers target. The cron equivalent:

```cron
30 23 * * 0  $HOME/.local/bin/safo spend-post --repo OWNER/PRIVATE-REPO --issue 123 --baseline $HOME/spend-baseline.json
```
