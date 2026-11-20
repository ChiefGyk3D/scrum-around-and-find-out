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
| Writes | Two steps. A reservation (under the shared state lock, briefly) gives a place in the queue (a writer queued past 60 seconds is refused, not parked) and sets how long to sleep. The launch gate then decides when the child starts. Each account has its own gate lock, a file named from a hash of its scope, so one account's slow spawn never holds up another account; the shared state lock is only ever held for short reads and writes, never across a spawn. Under the gate lock the writer waits until at least one second after the last ACTUAL launch (recorded, not reserved, so a process descheduled between reserving and launching cannot go out right behind a later ticket), starts the child (the spawn only), records the real launch time and releases. Elapsed time is read from the monotonic clock when the last launch was in this boot (the kernel boot id is stored with it), so a wall-clock step cannot shorten or lengthen it; across a reboot, or without a boot id, the wall clock is used, and a recorded launch that lies in the future (the clock stepped back, or the record is corrupt) is clamped to now and costs one spacing, once; it is never discarded. A same-boot monotonic record that lies in the future (a corrupt state file) is repaired the same way: rewritten from the current clocks under the state lock, one spacing, then the launch goes ahead. A writer waits at most 30 seconds for the gate lock of its own account, then refuses (exit 75). The gate makes at most 20 checks, each followed by a sleep of at most one spacing: that bounds iterations, not elapsed time, because a changing wall clock can change the sleeps; the gate lock wait is the only other wait. The lock is not held while the child runs, so a stuck `gh` never freezes the others. A spawn that fails still counts as a launch. After sleeping for its slot a writer also re-checks the budget and any block just before the gate. |
| Option grammar | An option spelled outside gh's documented forms (`-XPATCH`, `-X=PATCH`, an unknown flag) is treated as a write. |
| Rollover | A counter past its reset time no longer counts. A counter reset more than two hours from now, a block more than one hour, a write slot more than one minute (the queue limit) is treated as corrupt and ignored, in state or in an answer. A recorded launch in the future is the exception: it fails closed (see Writes). |
| Headers | The first header block that is not a 1xx or a proxy's CONNECT answer (at most two such blocks may come first) ends the headers; everything after it is body, even if it starts with `HTTP/`. With `gh api --include` that block is the response's own. A repeated rate-limit header, an obs-fold line or a malformed header name rejects every rate-limit and Retry-After value of that answer. A header section longer than 65,536 characters, or one with no terminating blank line, rejects the whole output: nothing of it (status line, headers or body) is printed, `ghw` says the output was withheld, records the call with status 0 and no counters, and returns the child's own exit code. |
| No replay | A call that went out is never repeated here. A timeout, output that is not valid UTF-8, or a signal is an unknown outcome (recorded as status 0, and the wrapper's own report says `outcome unknown`). `gh` runs in its own process group, detached from your terminal, so SIGINT, SIGTERM and SIGHUP are caught by `ghw` itself from before the launch gate until the call is over: all three handlers are installed together (the signals are blocked while that is done), the handlers that were there before are restored on every path, and the signal is never lost between steps. A signal before anything is started sends nothing (exit 128+N, "nothing was sent"). A signal at any point once a child may exist (in the spawn, while the launch is recorded, between the gate and the wait, or while waiting) is noted, then forwarded to the child's group, which gets 5 seconds before the group is killed and reaped; `ghw` records status 0, says the outcome is unknown and exits 130, 143 or 129 (128 plus the signal). A signal that arrives after the call finished is honoured last: the result is reported, then the exit code is 128+N. `safo-card` treats exits 124, 129, 130 and 143 whose stderr also has a line shaped like the wrapper's report ("ghw: ... outcome unknown") as an unknown outcome (never "GitHub refused"); any other code, even 130 from `gh` itself without such a line, is an ordinary failure. That line is advisory text, not proof of origin: the child's stderr is relayed into the same stream, so a forged line can only make the caller more cautious. Not handled: SIGKILL, and a signal arriving in the few instructions while the handlers are being put back at the very end. |
| Advice only | If the ledger directory cannot be used, or the budget setup meets unusable cache data (a malformed identity record is dropped, and any `TypeError`, `ValueError` or `OverflowError` from cache upkeep counts as the ledger being unavailable), `ghw` says so once and runs the call. If only the audit row cannot be written, the counters and blocks were already saved; `ghw` says so once. |

`gh api` calls get `--include` added so the headers can be read; they are removed again before the body is printed.
Calls that use `--jq`, `--template`, `--paginate`, `--silent` or `--include` themselves, and every other `gh` command
(`gh issue`, `gh pr`, `gh project` count as GraphQL), are recorded without headers. `gh api rate_limit` does not count
against the primary limit, but GitHub does not promise the same for the secondary limit; `ghw` neither counts nor blocks
it, so a block from another call does not stop it. Do not poll it.

## Where it lives

`~/.local/state/safo/ratebudget` (or under `$XDG_STATE_HOME`): `ledger.jsonl` (one line per call, rotated at
4 MiB to `ledger.jsonl.1`), `state.json` (counters, blocks, the write slot and the last launch with its monotonic time and boot id, each under its account scope), `gate-<hash>.lock` (one per account), `identity.json` (credential fingerprint to account scope, one hour),
`statusline.txt` (one line for the account used last, rewritten on every call, for a session statusline), and `lock`.
The directory is opened without following a symlink, must belong to you, and is set to mode 0700 if it was looser; the
files in it are opened relative to it, must be regular files of yours with one link, and are set to 0600. A file that
is a symlink is never followed. The same holds for reading and writing `boardmap.json` (`safo-card`): a symlinked
directory, a hard-linked or foreign file is a configuration error, not a map. Updates to the map are merged: under the
lock `boardmap.lock` the file is re-read and only what this run learned (new items, new options) is laid over it, so
two concurrent edits both persist.

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

`safo ratebudget` and `safo card` are subcommands that run the same code as the `safo-ratebudget` and `safo-card`
scripts (both are in `TOP_LEVEL_COMMANDS` in `modes/hooks.py`, which the dispatch guard reads). This does not change the
dispatch guard's issue lookup (a guard file; #357, #370) or the session hooks. Wire `ghw` in place of `gh` in briefs and
scripts by hand; briefs should say: read issues over REST, no board-wide lists, never poll.
