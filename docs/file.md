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
| That line is ignored inside a fenced code block (``` or ~~~, an unclosed fence runs to the end) | That the reason is true: the line is a reminder, not an adversary-proof control |
| Another owner than the working repo's needs `--allow-other-owner` | A direct `gh issue create` or `gh repo create` by an agent |
| The ledger is opened (regular file, no symlink) before the issue is created | |
| `check` needs exactly one answer; `new-project` needs `--owner-ok` | |
| Repo names `owner/name` with no `.` or `..` part | |

## Commands

`safo-file check IDEA --working-repo o/r [--answer A] [--owner-ok] [--timebox 30m] [--parking o/r#N]`

Matches the idea against `hooks.tracking_repos` (agents.yaml, read through the normal loader), `gh repo list` for the
working repo's owner, and the memory search. It prints the top five hits of each source by shared words (counted in
code) and exits 3 until you give exactly one `--answer`:

- `extends:<repo>`: the repo must be in `tracking_repos`, the working repo or `gh repo list`.
- `new-project`: refused (exit 1) without `--owner-ok`. With it, nothing is created; the owner-approved process creates
  the repo, epic and card.
- `tangent`: prints one parking-lot body with a time box (default 30m). With `--parking o/r#N` the body is posted as a
  comment on that one issue. No repo, epic or card.

Everything shown passes through `safo.output`: control characters and `::` workflow-command prefixes are escaped. The
raw text is sent only to GitHub.

`safo-file issue --repo o/r --working-repo o/r --title T --body B [--allow-other-owner] [--ledger PATH]`

Files one issue with `gh issue create --body-file -`: the body goes over stdin, never argv. `gh` gets no ambient token
variable, no stdin otherwise, and a 60 second limit. The ledger (default `~/.local/state/safo/file-ledger.jsonl`) is
checked and opened first, so a failure there files nothing; each filing appends one JSON line.

`safo-file report [--working-repo o/r] [--ledger PATH]`

Prints `cross-project issues: N of M`, counted in code from the ledger. A corrupt line is skipped with a count on
stderr. A ledger that is a symlink, not a regular file, not owned by you or larger than 8 MB exits 2. Only filings made
through `safo-file issue` are counted.

## The memory search

Set `SAFO_MEMORY_SEARCH` to a command. It is run as `<command> -- <idea>`, so it must accept `--` before its positional
argument. Each line of its output is one hit. At most 64 KB is read, for at most 10 seconds; then its process group is
killed. A blank value, a missing or non-executable command, a timeout or a non-zero exit is an error (exit 2). Unset
means no memory hits.

## Exit codes

0 done, 1 refused by a rule, 2 an error or bad command line, 3 an answer is still needed.
