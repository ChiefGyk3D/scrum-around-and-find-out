# Activity

What the AI helpers on this machine are doing right now: one short line for a status line, a table, JSON, a live watch
view, and quiet event monitors. Everything is read only. It starts nothing, stops nothing and sends nothing. Tracked in
issue 402.

```sh
safo-activity                  # one line for a status line; empty when nothing is going on (cached 10 s)
safo-activity --table          # the detail table, never cached
safo-activity --json           # the same facts as JSON
safo-activity --watch          # the table, redrawn every 2 seconds until Ctrl-C
safo-activity --events codex   # one line per change of codex, ollama, ledger or copilot
safo-activity --version
```

## Providers

| Provider | What it reads | Default |
|---|---|---|
| `codex` | Running jobs of the Codex plugin: `~/.claude/plugins/data/codex-openai-codex/state/*/jobs/*.json`. A job counts as running when its process is alive; a job completed in the last hour counts as done | on |
| `quota` | The plan windows (5 hour, weekly) of Codex, from the newest of the three latest `~/.codex/sessions/*/*/*/*.jsonl` files, and of Claude, from a small cache file (below). Local files only, no network | on |
| `ledger` | The local spend ledger kept by the SAFO wrapper (the `ledger:` key of the wrapper's config file in `~/.config/safo/`, else its default place under `~/.local/share/safo/`): entries today, the newest one's age, and calls in flight | on |
| `ollama` | The models a local Ollama server has loaded: one `GET /api/ps` under a single 1 second total deadline for all endpoints, never a generate call | opt in |
| `copilot` | Copilot code review on your open pull requests, through `gh` (REST only) | opt in |

A provider that is absent or fails leaves its segment out; nothing raises. On a machine with no configuration only
`codex`, `quota` and `ledger` are read, all from local files. No host is called by default.

## Choosing providers

`SAFO_ACTIVITY_PROVIDERS` (a comma list) wins; otherwise `providers:` in `~/.config/safo/activity.yaml`
(`$XDG_CONFIG_HOME/safo/activity.yaml`). Create the file yourself; SAFO writes none.

```yaml
# ~/.config/safo/activity.yaml
providers: [codex, quota, ledger, ollama, copilot]
copilot:
  owner: N0TST          # whose open pull requests to read; default: the login gh has
```

`SAFO_ACTIVITY_COPILOT_OWNER` overrides the `owner` key. `gemini` is accepted as another name for `ledger`. An unknown
name is ignored and noted in the table. A broken or symlinked config file is ignored.

### Ollama endpoints

Only from `$LLM_LOCAL_URL`, or the endpoints of an `ollama` agent in the agents file (`$SAFO_AGENTS`, else
`~/.config/safo/agents.yaml`, merged with `agents.local.yaml`). Nothing is hard-coded, and with no endpoint there is no
network call at all. The address checks of the local-model client apply (no link-local or metadata address, no
credentials in the URL, no redirect, no proxy). Busy or idle comes from `ss`, when it is on the path.

### Copilot

Opt in. In the refresh, for the owner's open pull requests (one search request, at most 15 of them) it makes four REST reads per
pull request through the `gh` login the machine already has: the pull request, its workflow runs of event `dynamic`, its
reviews and its inline comments. It reports two things:

- a review is **running**: a run named `Running Copilot Code Review` is queued or in progress on the current head;
- a review is **unread**: the `copilot-pull-request-reviewer` account has a review with a non-empty body on the current
  head, or an inline comment on it. Counts only; no review or comment text is ever read into the output or the cache.

The line segment is `cp N run OWNER/REPO#NUMBER` (the first one) or, when none runs, `cp N unread OWNER/REPO#NUMBER`;
it shows only when something runs or is unread.

**Only the background refresh asks GitHub.** Every view (the line, `--table`, `--json`, `--watch`, `--events`) reads the
cached answer and never fetches. When the cache is missing or older than 60 seconds a view starts one detached refresh
process and shows what the cache has (nothing, until the first refresh lands; a cache older than 10 minutes is not
shown). The refresh takes an exclusive lock (a lock older than 2 minutes is taken to be left by a dead process), so
racing starts do not duplicate it, and it runs at most once per 60 seconds across all processes. It is also bounded by:

- at most 15 counted REST calls per refresh, the search included (so about 900 an hour at the very most, with one
  refresh a minute), each call 5 seconds, the whole refresh 20 seconds counted from its first call. A pull request is
  read only when the budget can cover it; pull requests are taken oldest-checked first, never-checked ones before all,
  so the same ones are not skipped every round. What an earlier round learned about a pull request is kept, and the table
  says how many were not refreshed in the last round (`12 not refreshed this round`);
- conditional requests: the per-pull-request reads send `If-None-Match` with the stored ETag, and a `304` means
  unchanged: the stored counts stand, it is not a failure, and it is not charged to the budget (GitHub does not count it
  against the quota). A new head drops the tags of the reviews and comments. Only counts and tags are stored, never
  text. This relies on `gh api -i` printing the status line and headers; it is the one place the arguments go beyond
  `api` and a path (`-i`, and `-H` with `If-None-Match` only);
- up to 10 pages of 100 reviews and of inline comments per pull request; when the 10th page is still full the table
  says the counts are cut at 1000;
- a check of the REST rate limit before it starts (the status call is not counted against the quota): with fewer than
  500 calls left it waits for the reset, at most an hour; a `403` or `429` from GitHub ends the round and waits 5 minutes;
- a backoff after a failed refresh: 60 seconds, then doubling, capped at 15 minutes, recorded in a state file so a
  failing fetch is not retried every two seconds. A refresh counts as failed when the search or `gh` fails, or when more
  than half of the pull request reads it tried failed. A failure never replaces the last good answer, and the table says
  `the last refresh failed (N in a row)` instead of showing zeros.

Files, all in `$XDG_RUNTIME_DIR` (else `~/.cache`), mode 600, written atomically: `safo-activity-copilot.json` (the
answer), `.state` (backoff, written only by the refresh), `.spawn` (written only by views), `.store` (per-pull-request
counts and ETags) and `.lock`. A cache of someone else's, writable by others, or a symlink is not read, and
every value read back is checked again (a reference must look like `owner/repo#number`) and cleaned before it is
printed. The same holds for the line cache. The refresh never uses GraphQL, never reads a board, and the only arguments
it gives `gh` are `api`, a path, and for the conditional reads `-i` and `-H If-None-Match: ...`, so it cannot write.

### Ledger

Read with a lenient tail reader (the last 256 KiB, the last 1000 lines; a call started before that can look absent), not the chain-verifying reader, because a
status line must not fail on a broken chain. Unparsable lines are skipped, a symlink or a FIFO is not opened, no lock is
taken and nothing is written. It shows counts, the action name (`job`) and ages, never a prompt or any other content.
**In flight** means a `call_start` row from today with no `call_end` row of the same call id; a call that crashed looks
the same. When the ledger has no start or end rows at all, the table says they cannot be told apart.

### Quota

- **Codex.** Of the newest three session files only the last 256 KiB is read, and the last event with `rate_limits` is
  used. Only numbers and the plan label (one short alphanumeric word, else dropped) are taken. A window is labeled by
  its length: 300 minutes is `5h`, 10080 is `wk`, anything else is minutes divided by sixty plus `h`. A window with null
  fields is omitted. The reset time (`resets_in_seconds` or an absolute `resets_at`) is shown in the table when the
  event has one. The age is that of the event; over 30 minutes it is marked stale.
- **Claude.** From `~/.cache/safo/claude-usage.json` (override: `SAFO_ACTIVITY_CLAUDE_USAGE`, an absolute path). A
  symlink, a file owned by someone else and a group or world writable file are refused. Missing, malformed or refused
  means nothing is shown. SAFO fills this file from nothing yet; a status line script can write it with
  the `write_claude_usage` function of the `activity` module (atomic, mode 600, only the schema's fields, refuses a document with no valid
  window). It is wired to no setting.

```json
{
  "captured_at": "2026-11-09T14:05:00Z",
  "windows": [
    {"label": "5h", "used_percent": 41.2, "resets_at": "2026-11-09T16:00:00Z"},
    {"label": "wk", "used_percent": 12}
  ]
}
```

`captured_at` and `resets_at` are ISO 8601 stamps or seconds since the epoch; `used_percent` is 0 to 100; `label` is up
to 12 printable characters; at most 8 windows. The line shows `cx 1% wk, age 4m` and `cl 41% 5h 12% wk, age 2m`
(`stale` is appended after 30 minutes).

### Pace and the advisory line

For each window that has a reset time, the table and `--json` show how fast the window is being used.

- **Window length** comes from the label: `5h` is 300 minutes, `wk` is 10080, `Nh` is N times sixty. Any other label has no pace.
- **Elapsed fraction** = 1 - (time left / window length), clamped to between 0.02 and 1 so an early reading does not
  blow the ratio up.
- **Pace ratio** = used percent / (elapsed fraction x 100), shown to one decimal (`1.5x pace`).
- **Band**: `under_pace` below 0.9, `on_pace` from 0.9 to 1.0, `caution` above 1.0 up to 1.3, `over_pace` above 1.3.

Claude windows come from the cache file, Codex windows from the rollout reader. `--json` carries `elapsed_percent`,
`pace_ratio` and `band` per window (null without a reset time), and a `recommendation` key under `quota`.

One combined line, for a dispatch-time prompt, appears in the table and in `--json` only when both the Claude and the
Codex weekly windows are fresh (30 minutes or younger) and have a reset time; with missing or stale data there is no
line and nothing else changes:

```
Budget: Claude wk 42% (1.5x pace), Codex wk 1% (0.1x pace) - prefer Codex for specified implementer tasks
```

The ending is: `prefer Codex for specified implementer tasks` when the Claude weekly band is `caution` or `over_pace` and the
Codex weekly band is `under_pace` or `on_pace`; `hold new Claude agents` when the Claude 5 hour window is above 80
percent (both can apply, joined by a semicolon); otherwise `normal`. **It is advice only.** Nothing reads it back: it
changes no routing, no setting and no file, and it says nothing about how security review is routed. The status line
never shows it.

## Event monitors

`--events PROVIDER` polls every 2 seconds and prints one short line only when that provider's state changes: a Codex job
started or finished, a model loaded, unloaded, busy or idle, the endpoint unreachable and reachable again, a ledger call
started or ended, a Copilot review running, finished or unread. At most 6 lines per minute; the rest are counted and
one `N events dropped` line follows each minute. It ends after 29 minutes (so the monitor can be re-armed) and on
SIGINT or SIGTERM, always with exit 0. The first line says the state when it started.

## Safety

Every string that came from a file or the network is cut to printable ASCII with a plain character class (control
characters, tabs, newlines and anything above ASCII become a space) and to a short length before it is printed. The cache
files are written atomically with mode 600, never through a symlink. The only thing written is a cache file under
`$XDG_RUNTIME_DIR` (or `~/.cache`) and, when a script calls the helper, `~/.cache/safo/claude-usage.json`.

## The Claude Code pane

`mods/ai-activity/` is a Claude Code mod: a pane beside the chat that shows `safo-activity --table`, refreshed every 2
seconds, with the Codex, Quota, Ollama, Ledger and Copilot headers in color. The `/ai` command shows or hides it. It
looks up `safo-activity` on the path with `sh -c 'command -v ... && exec ... || exit 0'`, the same pattern the SAFO hooks
use; when the tool is not installed the pane draws nothing, it is not opened at session start, and `/ai` says
`safo-activity is not installed`. Headers use the `bold` text property, which every Claude Code version with mods
accepts; newer versions list it as deprecated in favor of `weight`. To install, copy or link the folder as a Claude Code
mod (see the mod authoring documentation of your Claude Code version). Nothing here changes any settings file.

## Startup cost

Measured with the status line command in a scrubbed home: about 43 ms with the cache and without it, of which about 9 ms
is Python itself; the rest is importing the standard library and the SAFO helpers. `--table` is about 60 ms with the
network providers off.
