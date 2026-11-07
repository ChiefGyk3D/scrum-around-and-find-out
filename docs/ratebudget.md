# The shared GitHub API budget (`ghw`, `safo-ratebudget`)

Every session and agent on one account spends one GitHub budget. On 2026-11-07 a full board listing cost about 600
GraphQL points, about 200 listings were made in one day, GraphQL showed two independent counters, and REST (the `core`
bucket) kept working. `ghw` and the ledger make that spending visible and stop it before the wall (#356, #355, #204).

## `ghw`: gh with the budget applied

`ghw <gh arguments>` runs `gh` after a budget check and records the call. Set `SAFO_CALLER` to name who is calling
(an agent name, a session); it is cleaned to `[A-Za-z0-9._-]`, 40 characters, or `unknown`.

| Rule | What happens |
| --- | --- |
| Account scope | Counters, blocks and the write queue belong to a GitHub host and an ACCOUNT, because GitHub limits the account: several tokens of one account share one limit and one queue here too. The account is found once per credential with `gh api user` (one REST read) and remembered for an hour in `identity.json`, keyed by a SHA-256 fingerprint of host and token; the scope itself is a hash of host and login. Neither the token nor the login is written. The host comes from `--hostname` or `GH_HOST`; the token from `GH_TOKEN`/`GITHUB_TOKEN` (the enterprise pair for another host) or `gh auth token`. |
| Unknown account | If no credential is found or `gh api user` fails, the scope is `unknown-<credential hash>`: never merged with another credential's, throttled earlier (warn at 50%, refuse at 70%), and said once per five minutes on stderr and in `safo-ratebudget`. Isolation between accounts, and sharing between two credentials of one account, are not available there. |
| Worst counter wins | Within one account and bucket the state is the WORST live counter: the `x-ratelimit-*` headers of answers and the `rate_limit` endpoint. This is deliberately more cautious than GitHub's guidance, which treats the response headers as authoritative when they disagree with `GET /rate_limit`; it follows the #356 rule that the minimum across counters is the truth. |
| 70% used | A WARNING line on stderr; the call goes. |
| 90% used | The call is refused with exit 75 and `retry after Ns`, until that counter's reset time. |
| Retry-After | A 403 or 429 with `Retry-After` blocks the bucket for that long (capped at one hour; `nan`, `inf`, negative and junk are ignored). A 429 with no usable header, or a 403 that says "secondary rate limit", blocks it 60 seconds. A GraphQL answer can carry a secondary limit with HTTP 200: for the GraphQL bucket only, a message in the top-level `errors` list that says "secondary rate limit" blocks it too (the answer's `Retry-After`, else 60 seconds); the same words in `data` or in a REST body do not. |
| Writes | At least one second apart across all processes and all buckets of one account: each writer reserves a slot in one queue under a file lock. A writer queued past 60 seconds is refused, not parked. A writer that slept for its slot re-checks the budget and any block just before it launches `gh`. |
| Option grammar | An option spelled outside gh's documented forms (`-XPATCH`, `-X=PATCH`, an unknown flag) is treated as a write. |
| Rollover | A counter past its reset time no longer counts. A counter reset more than two hours from now, a block more than one hour, or a write slot more than one minute (the queue limit) is treated as corrupt and ignored, in state or in an answer. |
| Headers | Only the final header block is read. A repeated rate-limit header, an obs-fold line or a malformed header name rejects every rate-limit and Retry-After value of that answer. |
| No replay | A call that went out is never repeated here. A timeout or output that is not valid UTF-8 is an unknown outcome (exit 124, recorded as status 0). |
| Advice only | If the ledger directory cannot be used, `ghw` says so once and runs the call. If only the audit row cannot be written, the counters and blocks were already saved; `ghw` says so once. |

`gh api` calls get `--include` added so the headers can be read; they are removed again before the body is printed.
Calls that use `--jq`, `--template`, `--paginate`, `--silent` or `--include` themselves, and every other `gh` command
(`gh issue`, `gh pr`, `gh project` count as GraphQL), are recorded without headers. `gh api rate_limit` does not count
against the primary limit, but GitHub does not promise the same for the secondary limit; `ghw` neither counts nor blocks
it, so a block from another call does not stop it. Do not poll it.

## Where it lives

`~/.local/state/safo/ratebudget` (or under `$XDG_STATE_HOME`): `ledger.jsonl` (one line per call, rotated at
4 MiB to `ledger.jsonl.1`), `state.json` (counters, blocks and the write slot, each under its account scope), `identity.json` (credential fingerprint to account scope, one hour),
`statusline.txt` (one line for the account used last, rewritten on every call, for a session statusline), and `lock`.
The directory is opened without following a symlink, must belong to you, and is set to mode 0700 if it was looser; the
files in it are opened relative to it, must be regular files of yours with one link, and are set to 0600. A file that
is a symlink is never followed. The same holds for reading and writing `boardmap.json` (`safo-card`): a symlinked
directory, a hard-linked or foreign file is a configuration error, not a map.

## `safo-ratebudget`

    safo-ratebudget [--by-caller] [--refresh] [--json]

Prints the status line, for example `ratebudget: core 20% (4000 left), graphql 83% (850 left) WARN`, and with
`--by-caller` the calls and writes per caller. `--refresh` reads the `rate_limit` endpoint into the ledger first (for the account `gh` is logged in as).
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
