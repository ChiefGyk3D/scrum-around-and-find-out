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

Everything shown is escaped before it is printed: control characters and `::` workflow-command prefixes are made harmless. The
raw text is sent only to GitHub.

`safo-file issue --repo o/r --working-repo o/r --title T --body B [--allow-other-owner] [--ledger PATH]`

Files one issue with `gh issue create --body-file -`: the body goes over stdin, never argv. The ledger (default
`~/.local/state/safo/file-ledger.jsonl`) gets a `pending` record before the issue is created and a `committed` record
with the URL after. If the second write fails, the URL is printed on stderr as "created but not recorded" and the exit
is 2. A pending record with no commit means gh failed or the process stopped in between: look for the issue. Each record is written under an exclusive lock on the ledger, so two `safo-file` processes cannot interleave lines. The
ledger directory must be owned by you and not writable by group or others, no component of its path may be a symlink,
and an existing ledger must be owned by you and not group or other writable; a new one is created 0600.

`safo-file report [--working-repo o/r] [--ledger PATH]`

Prints `cross-project issues: N of M`, counted in code from the committed records. A corrupt line is skipped with a
count on stderr, and so is the number of pending records that never committed. A ledger that is a symlink, not a
regular file, not owned by you, group or other writable, or larger than 8 MB exits 2. Only filings made through
`safo-file issue` are counted.

## The routing table (#455)

The owner decided that the private repositories are the default home for general work, so `safo-file` can say where a
piece of work belongs and keeps private-workflow work out of public repos. The decision is made by code, from keyword and
path-hint lists, never by a model.

| Class | Default destination | Private |
| --- | --- | --- |
| `product` | the working repo, when it is in `tracking_repos` | no |
| `homelab` (homelab, infra, runner, ops) | `ChiefGyk3D/homelab-ops` | yes |
| `ai-tooling` (AI tooling and config) | `ChiefGyk3D/AI-Shit` | yes |
| `research` (research and evaluation) | `ChiefGyk3D/research-notes` | yes |
| `tangent` (unclassified and tangents) | `ChiefGyk3D/workbench` | yes |

`safo-file route DESCRIPTION --working-repo o/r [--class NAME] [--ledger PATH]`

Prints `destination:`, `class:` and `reason:` (the matched keywords and path hints, or `explicit class NAME`). Exit 0 when
the class is decided. Exit 3 when nothing matched, or when the work is `product` but the working repo is not tracked: the
destination is then only the default (`ChiefGyk3D/workbench`), printed as `(default only)`; pass `--class` to decide.
The decision is appended to the ledger as a `routed` record (class, destination, how it was decided, the matched terms;
never the description). `report` ignores `routed` records, and a route that cannot be recorded exits 2 with no output.

Matching: a keyword counts when it appears as a whole word or phrase, ignoring case (`ops` does not match `hopscotch`).
A path hint counts when it equals a whole segment of a path-like word (`notes/jan.md` matches `notes`; the plain word
`notes` does not). A class scores one point per distinct keyword or hint matched. The highest score wins. A tie goes to
a private class over a public one, then to the class earlier in the table (product, homelab, ai-tooling, research,
tangent, then classes the file adds, in file order).

The table lives in `~/.config/safo-file/routes.toml`, which is not under `~/.config/safo`; no environment variable moves
it. Without the file the defaults above apply. The file must be a regular file you own, not writable by group or others,
with no symbolic link in its path and closed directories above it, at most 64 KB, valid UTF-8 and TOML; anything else is
exit 2 with the reason (never the path). A key you give replaces that key's default; a class the file names that is not
built in is added and needs a `repo`.

```toml
[classes.homelab]
repo = "ChiefGyk3D/homelab-ops"
keywords = ["homelab", "proxmox", "side project"]   # whole words or phrases: a-z, 0-9, space . _ + -
paths = ["infra", "ops/runner"]                      # path segments

[classes.radio]                                       # a new class: repo is required, private defaults to true
repo = "ChiefGyk3D/radio-notes"
keywords = ["sdr", "meshtastic"]
```

`product` takes no `repo` and is never private. At most 32 classes and 200 terms per list.

**Public repos.** `safo-file issue ... [--class NAME] [--allow-public]` finds the work's class from `--class`, else from
what the title and body match (no match means no class, and the issue is filed as before). A private class in a public
repo is refused (exit 1) unless the command has `--allow-public` AND the body has a `public-ok: <reason>` line outside a
code fence. Whether the repo is public comes from `gh api repos/o/r --jq .private`; the answer is cached next to the
ledger (`repo-visibility.jsonl`, same trust rules, believed for 5 minutes). If the lookup fails or answers something
unexpected the issue is refused with exit 2 (fail closed). Every decided issue writes a `routed` record first, with
`outcome` `private-repo`, `override` or `refused`. The cross-project and idea-gate rules still apply on top.

**Parking lot.** `safo-file check ... --answer tangent --parking-number N` posts the parking-lot body to issue N in the
table's `tangent` repo (workbench by default). Without `--parking` or `--parking-number` it prints the default
parking-lot repo and posts nothing. `--parking o/r#N` still works alone; both together is exit 2. `safo-file` never
creates an issue for this.

## The memory search

Set `SAFO_MEMORY_SEARCH` to a command. It is run as `<command> -- <idea>`, so it must accept `--` before its positional
argument. The command must be an absolute path (or a bare name found on the sanitized PATH), outside the current
directory, and neither it nor any directory above it may be owned by another user (root is fine) or writable by group
or others. Each line of its output is one hit. At most 64 KB is read, for at most 10 seconds; then its process group is
killed. A blank value, a missing or untrusted command, a timeout or a non-zero exit is an error (exit 2). Unset means
no memory hits.

## The child environment

Each child gets its own allowlist. The memory command gets only PATH, HOME, USER, LOGNAME, LANG, `LC_*`, TERM and TZ:
no `GH_*`, no `XDG_*`, no session bus. `gh` gets those plus `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME`,
`XDG_CACHE_HOME`, `XDG_RUNTIME_DIR`, `DBUS_SESSION_BUS_ADDRESS` (a keyring-stored login) and `GH_CONFIG_DIR`, but not
`GH_HOST`. Nothing else, so `GH_TOKEN` and `GITHUB_TOKEN` are not passed: `gh` must be logged in with its own stored
credentials.

- HOME must be an absolute directory owned by you, not group or other writable, with trusted parents. If it is not,
  `gh` is not run (exit 2) and the memory command simply gets no HOME.
- `GH_CONFIG_DIR` and the `XDG_*` directories must pass the same test and have no symbolic link in their path; a value
  that fails is dropped, and `gh` falls back to its defaults under HOME.
- PATH keeps only absolute directories that are owned by you or root, not writable by group or others, with every
  directory above them passing too. A symlinked entry is judged both as named and by its resolved target and the
  target's parents. A root-owned sticky directory such as /tmp is accepted, a file never is. If nothing is left PATH is
  `/usr/bin:/bin`. `gh` and a bare-name memory command are looked up on this same trusted PATH, so an untrusted earlier
  directory cannot mask a trusted later one; if the only copy is in an untrusted directory the error (exit 2) names the
  directory and the reason.
- `gh` runs from a trusted absolute path, in its own process group, with 1 MB of stdout and 64 KB of stderr at most and
  a 60 second limit. After a normal exit nothing is signalled; on a timeout or a cap the whole group is killed before
  the leader is reaped.

The ledger lock is tried without blocking for 5 seconds at most; a ledger that stays locked is an error (exit 2), and
after an issue was created the URL is still printed.

## Known limits

- An executable replaced between the trust check and the launch is not caught. It needs write access to directories the
  policy already requires to be closed to others.

## Exit codes

0 done, 1 refused by a rule, 2 an error or bad command line, 3 an answer is still needed (`route`: the class could not be decided).
