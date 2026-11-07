# The shared GitHub API budget (`ghw`, `safo-ratebudget`)

Every session and agent on one account spends one GitHub budget. On 2026-11-07 a full board listing cost about 600
GraphQL points, about 200 listings were made in one day, GraphQL showed two independent counters, and REST (the `core`
bucket) kept working. `ghw` and the ledger make that spending visible and stop it before the wall (#356, #355, #204).

## `ghw`: gh with the budget applied

`ghw <gh arguments>` runs `gh` after a budget check and records the call. Set `SAFO_CALLER` to name who is calling
(an agent name, a session); it is cleaned to `[A-Za-z0-9._-]`, 40 characters, or `unknown`.

| Rule | What happens |
| --- | --- |
| Worst counter wins | A bucket's state is the WORST of every counter seen for it: the `x-ratelimit-*` headers of answers and the free `rate_limit` endpoint. The endpoint alone is not the truth. |
| 70% used | A WARNING line on stderr; the call goes. |
| 90% used | The call is refused with exit 75 and `retry after Ns`, until that counter's reset time. |
| Retry-After | A 403 or 429 with `Retry-After` blocks the bucket for that long (capped at one hour; `nan`, `inf`, negative and junk are ignored). A secondary-limit answer with no header blocks it 60 seconds. |
| Writes | At least one second apart across all processes: each writer reserves a slot under a file lock. A writer queued past 60 seconds is refused, not parked. |
| Rollover | A counter past its reset time no longer counts. |
| No replay | A call that went out is never repeated here. A timeout is reported (exit 124) and recorded as status 0. |
| Advice only | If the ledger cannot be used, `ghw` says so once and runs the call. |

`gh api` calls get `--include` added so the headers can be read; they are removed again before the body is printed.
Calls that use `--jq`, `--template`, `--paginate`, `--silent` or `--include` themselves, and every other `gh` command
(`gh issue`, `gh pr`, `gh project` count as GraphQL), are recorded without headers. `gh api rate_limit` is free and
neither counted nor blocked.

## Where it lives

`~/.local/state/safo/ratebudget` (or under `$XDG_STATE_HOME`), mode 0700: `ledger.jsonl` (one line per call, rotated at
4 MiB to `ledger.jsonl.1`), `state.json` (counters, blocks, last write slot per bucket), `statusline.txt` (one line,
rewritten on every call, for a session statusline), and `lock`.

## `safo-ratebudget`

    safo-ratebudget [--by-caller] [--refresh] [--json]

Prints the status line, for example `ratebudget: core 20% (4000 left), graphql 83% (850 left) WARN`, and with
`--by-caller` the calls and writes per caller. `--refresh` reads the `rate_limit` endpoint into the ledger first.
Exit 0 when every bucket is under 70%, 1 at WARN or THROTTLE.

## Card edits (`safo-card`, #358)

    safo-card owner/repo#N Field=Value [Field=Value ...] [--item-id N | --resolve] [--option Field:Name=ID] [--dry-run]

One REST `PATCH users/<owner>/projectsV2/<n>/items/<item id>` with `{"fields":[{"id":<numeric field id>,"value":...}]}`
(verified on the user-owned board 2026-11-07), sent through the same budget rules as `ghw`. The ids come from a
persisted map, `boardmap.json` beside the ledger (mode 0600, bounded, duplicate keys and symlinks refused), seeded with
project 3's field ids and the Effort option ids. The board is never listed:

| Situation | Calls |
| --- | --- |
| Card is in the map | 1 (the PATCH) |
| Card not in the map, `--item-id N` | 1; the id is remembered |
| Card not in the map, `--resolve` | 3 the first time (issue read, item finder `items?q=<title>`, PATCH), 1 after; cached only on exactly one match of number and repository |
| Card not in the map, neither flag | 0; exit 2 says how to map it |

A single-select value is an option name from the map or an 8-hex-digit option id; teach the map a name with
`--option Status:Done=<id>`. `Field=` clears the field. An unknown outcome (timeout after the send) is reported and
never repeated. Unverified: the live shape of the REST items listing and the Epic field's kind (`text` in the map).

## Not done here

`safo-ratebudget` and `safo-card` are their own console scripts, not `safo` subcommands: a subcommand must also be added
to `TOP_LEVEL_COMMANDS` in `modes/hooks.py`, which is a guard file (#357) and needs the maintainer's word. This does not change the dispatch guard's issue lookup (a guard file; #357) or the session hooks. Wire `ghw` in
place of `gh` in briefs and scripts by hand; briefs should say: read issues over REST, no board-wide lists, never poll.
