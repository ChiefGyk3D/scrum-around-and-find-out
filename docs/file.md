# The idea gate and the cross-project line (`safo-file`)

Agents file issues and create work in repositories unrelated to the project at hand, and a new idea can quietly become
a repo, an epic or a card (#443). `safo-file` is the wrapper that asks the question first. It is a tool, not a guard:
the dispatch guard is untouched, and `safo-file` never creates a repository, an epic or a card.

## Advisory by design

The gate is advisory for same-repo filing. Nothing forces an agent to run `check` first, and `issue` in the working
repo works without it. That is the owner's decision: the gate is for new ideas and for filing across repositories.
Routing a direct `gh issue create` to this wrapper is a follow-up in the dispatch guard's territory, not here.

| Enforced by `safo-file` | Not enforced |
| --- | --- |
| `issue` in another repo needs a non-empty `cross-project: <reason>` line | That `check` was run before filing |
| That line is ignored inside a fenced code block (a closing fence has the same character, at least the opener's length, and nothing after it; an unclosed fence runs to the end) | That the reason is true: the line is a reminder, not an adversary-proof control |
| Another owner than the working repo's needs `--allow-other-owner` | A direct `gh issue create` or `gh repo create` by an agent |
| The ledger is opened through directory descriptors (no link followed at any component) before the issue is created | |
| `check` needs exactly one answer; `new-project` needs `--owner-ok` | |
| Repo names follow GitHub's rules (owner: letters, digits and single hyphens, at most 39 characters; no `.` or `..`); comparisons ignore case | |
| `gh` and the memory command run from a trusted path with an allowlisted environment, bounded output and a time limit | |

## Commands

`safo-file check IDEA --working-repo o/r [--answer A] [--owner-ok] [--timebox 30m] [--parking o/r#N]`

Matches the idea against `hooks.tracking_repos`, `gh repo list` for the working repo's owner, and the memory search.
`tracking_repos` comes from the one file `~/.config/safo/agents.yaml`: `SAFO_AGENTS`, `SAFO_AGENTS_LOCAL` and
`agents.local.yaml` are not read, and nothing under `~/.config/safo` is ever written. It prints the top five hits of
each source by shared words (counted in code) and exits 3 until you give exactly one `--answer`:

- `extends:<repo>`: the repo must be in `tracking_repos`, the working repo or `gh repo list`.
- `new-project`: refused (exit 1) without `--owner-ok`. With it, nothing is created; the owner-approved process creates
  the repo, epic and card.
- `tangent`: prints one parking-lot body with a time box (default 30m). With `--parking o/r#N` the body is posted as a
  comment on that one issue. No repo, epic or card.

Everything shown passes through `safo.output`: control characters and `::` workflow-command prefixes are escaped. The
raw text is sent only to GitHub.

`safo-file issue --repo o/r --working-repo o/r --title T --body B [--allow-other-owner] [--ledger PATH]`

Files one issue with `gh issue create --body-file -`: the body goes over stdin, never argv. The ledger (default
`~/.local/state/safo/file-ledger.jsonl`) gets a `pending` record before the issue is created and a `committed` record
with the URL after. If the second write fails, the URL is printed on stderr as "created but not recorded" and the exit
is 2. A pending record with no commit means gh failed or the process stopped in between: look for the issue. The
ledger directory must be owned by you and not writable by group or others, no component of its path may be a symlink,
and an existing ledger must be owned by you and not group or other writable; a new one is created 0600.

`safo-file report [--working-repo o/r] [--ledger PATH]`

Prints `cross-project issues: N of M`, counted in code from the committed records. A corrupt line is skipped with a
count on stderr, and so is the number of pending records that never committed. A ledger that is a symlink, not a
regular file, not owned by you, group or other writable, or larger than 8 MB exits 2. Only filings made through
`safo-file issue` are counted.

## The memory search

Set `SAFO_MEMORY_SEARCH` to a command. It is run as `<command> -- <idea>`, so it must accept `--` before its positional
argument. The command must be an absolute path (or a bare name found on the sanitized PATH), outside the current
directory, and neither it nor any directory above it may be owned by another user (root is fine) or writable by group
or others. Each line of its output is one hit. At most 64 KB is read, for at most 10 seconds; then its process group is
killed. A blank value, a missing or untrusted command, a timeout or a non-zero exit is an error (exit 2). Unset means
no memory hits.

## The child environment

`gh` and the memory command get only: PATH (absolute entries only), HOME, USER, LOGNAME, LANG, `LC_*`, TERM, TZ,
`XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME`, `XDG_CACHE_HOME`, `XDG_RUNTIME_DIR`,
`DBUS_SESSION_BUS_ADDRESS` (a keyring-stored gh login), `GH_CONFIG_DIR` and `GH_HOST`. Nothing else, so `GH_TOKEN`
and `GITHUB_TOKEN` are not passed: `gh` must be logged in with its own stored credentials. `gh` runs from the same
kind of trusted path, in its own process group, with 1 MB of stdout and 64 KB of stderr at most and a 60 second limit.

## Exit codes

0 done, 1 refused by a rule, 2 an error or bad command line, 3 an answer is still needed.
