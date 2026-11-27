# Runner-first briefs

Full test suites and mutation sweeps on a public repo go to the runner through `ra-remote`. Targeted checks stay local.
Measured on 2026-11-24 to 2026-11-26: 414 mutation runs and 663 broad suite runs ran on the main machine, although the
runner benchmark is 2.1x to 2.7x faster (pytest 163 s to 73.6 s).

## Snippet for an implementer brief

Copy this into the brief and fill the placeholders.

```text
Runner-first checks (issue: OWNER/REPO#N):
- Local, targeted only: pytest on the touched files or with -k, ruff, mypy on the touched modules.
- Full suites, vitest over the whole tree, `npm test`, `make check` and every mutation sweep (mutmut, cosmic-ray,
  stryker) run through ra-remote, never locally. Never use pytest -n: pytest-xdist is not in the repo deps.
- Environment (set by the owner, never stored in a repo): RA_RUNNER_HOST=<ssh alias>, RA_RUNNER_KEY=<path to the
  runner-only key>, RA_RUNNER_USER=<runner account>.
- Command: ra-remote [--timeout SECS] [--cpus N] [--memory Ng] [--visual] [--py V] [--no-deps] [--fetch RELPATH]...
  [--fetch-to DIR] [--plan] WORKTREE -- COMMAND...
  Try `ra-remote --plan WORKTREE -- COMMAND...` first: it prints what would be sent and connects nowhere.
- The worktree must be under ~/.local/share/reach-around-dev (or another folder ra-remote allows) and be a PUBLIC
  checkout. Private repos, the instance repo, the brand repo and lead notes never go to the runner; run those locally.
- A runner-only failure is a lead to confirm in CI, not a verdict. CI stays the judge.
- Check a draft with: safo-runner-check --strict --brief brief.md
```

## The checker

```text
safo-runner-check [--strict] [--repo DIR] (--command LINE | --brief FILE|-)
python -m safo.runner_check ...        # same entry point
```

It reads one command line or a brief and flags a local full suite or sweep. For a flagged command on a public repo it
prints the `ra-remote --plan` form and the real form. It never runs ra-remote and never contacts the runner (its only
network use is the publication proof below). It fails closed: anything it cannot prove public stays local.

### What is classified as a full suite or sweep

A name counts only in the command position of a segment, after env assignments and the wrappers `time`, `nohup`,
`command`, `exec`, `builtin`, `nice`, `ionice`, `timeout`, `env`, `stdbuf`, `setsid`, `chrt`, `taskset`, `unbuffer`,
`flock`, `xvfb-run`, `uv run`, `poetry run`, `pipenv run`, `pdm run`, `hatch run`, `npx`, `bunx`, `pnpm exec`,
`npm exec`, `yarn run`, `xargs`, `python -m`, and `bash|sh|zsh|dash|ksh -c STRING` (the string is checked too). For each
wrapper the checker consumes the wrapper's own options and an optional `--` end-of-options marker, then continues on
what follows, so `command -- pytest`, `nohup -- pytest`, `timeout 60 -- pytest` and `taskset -c 0 -- pytest` are
suites. Segments split on `&&`, `||`, `;`, `|`, `&`, newline, parentheses, backticks and `$(...)`.

Fail-closed rule: when, after the wrappers, the head is not a command the checker knows, any later word equal (case
sensitive) to `pytest`, `vitest`, `jest`, `tox`, `nox`, `unittest`, `mutmut`, `cosmic-ray` or `stryker`, or `test` after
`make|npm|pnpm|yarn|cargo|go|mvn|gradle`, makes the line a local full suite (a false positive is accepted; a missed suite
under `--strict` is not). Known non-runner heads stay unflagged: `pip`, `pip3`, `uv pip`, `which`, `echo`, `printf`,
`grep`, `rg`, `cat`, `less`, `ls`, `ssh`, `scp`, `git`, `apt`, `apt-get`, `brew`, `man`, `type`, `command -v`. So
`pip install pytest`, `which pytest`, `man pytest`, `echo pytest`, `grep pytest f` and `ssh host pytest` are not suites.

- pytest: with no file, no `::` id and no `-k`/`--lf`/`--ff`. Directories count as full. Values of `--deselect`,
  `--ignore`, `--ignore-glob`, `--junitxml`, `-p`, `--rootdir`, `--confcutdir`, `--cov`, `-c`, `-o` (and similar) are not
  targets. `--version`, `--help`, `--collect-only` and similar do not run tests.
- mutation sweeps: `mutmut`, `cosmic-ray`, `stryker`.
- JavaScript: `vitest [run]` with no file; `npm|pnpm|yarn test`, `t`, `run test`, `run test:*`.
- `jest` (like `vitest`); `tox`, `nox`; `make test`, `make check`.
- `python -m unittest` with no module (or `discover`); `go test` with no package or `./...` and no `-run`;
  `cargo test` with no filter and no `--test`; `mvn test` without `-Dtest`; `gradle`/`gradlew test` without `--tests`.
- A command already wrapped in `ra-remote` is accepted.

### What it prints

For a plain line (one command, optionally with `NAME=value` prefixes) the printed command is faithful: env assignments are
re-expressed as `env NAME=value ...` and every word is shell-quoted (`shlex`). If the line has a `cd`, a redirect, a
pipe, a subshell, a command substitution, an expansion, a backslash or more than one command, it prints advice only:
`run this through ra-remote: ra-remote --plan WORKTREE -- <the suite command alone>`. It never prints a rewritten line
that changes meaning.

### Repo class (decision rules, in order)

1. Transport overrides: if any of these is set the repo is "cannot tell: git transport is overridden (setting NAME)" and
   stays local. Environment: `GIT_SSH`, `GIT_SSH_COMMAND`, `GIT_PROXY_COMMAND`, any `GIT_CONFIG_*`. Effective git
   configuration (`git config --show-origin --get-regexp`, includes followed): the keys `sshcommand` and `gitproxy` of the
   `core` section, the keys `vcs`, `proxy` and `pushurl` of any `remote` section, `insteadof` and `pushinsteadof` of any
   `url` section, `path` of an `include` section, any key of a `protocol` section, the key `proxy` of the `http`
   section (plain or per URL; the URL part is never shown), and any
   `includeIf` (named `includeIf gitdir` or `includeIf`). the `credential` section is deliberately not an override: it only changes
   how a login is supplied, never where a remote points. Only the setting key is named, never a value. The checker also runs git with the
   environment it was given, so the real global git configuration of the caller is what is read.
2. Read every remote (`git remote -v`, fetch and push). Each must parse as a `github.com` https, ssh or scp-like
   `owner/name` URL; the host is parsed, so a URL whose host is another site with `github.com` in its path is rejected. Userinfo is never printed.
   Non-ASCII owner or repository names are rejected. No remote, or any remote that does not parse: "cannot tell: keep
   local".
3. Denylist, always wins: built-in name patterns `*-instance`, `reach-around-instance`, `*brand*`, `*dotfiles*`,
   `*ai-shit*`, `*lead*`, `*notes*`, `*private*`, `*secret*`, `*homelab-identity*`, plus one name or glob per line in
   `~/.config/safo/runner-never` (matched against `name` and `owner/name`). Names are normalized first (NFKC, lowercase,
   trailing slashes, dots and spaces stripped, `.git` suffixes removed until stable) and matched in both the normalized
   and the raw form, so a denied name with a repeated `.git` suffix, an upper-case `.GIT` suffix or a trailing dot is still denied. A match on any remote:
   "looks private".
4. Allowlist mode: if `SAFO_PUBLIC_REPOS` (comma list of `owner/name`) is set, even to an empty string, or the file
   `public-repos` exists, even when empty, the repo is public only when every remote is listed. An empty allowlist means
   no repo is public. Otherwise "looks private".
5. No allowlist: owner-level trust. `SAFO_PUBLIC_OWNERS` (comma list; set means used, even if empty) or the file
   `public-owners`; every remote owner must be listed. The output then says "public: owner listed, no denylist match".
6. Anything else: "cannot tell: keep local".

The config files (`runner-never`, `public-repos`, `public-owners`) sit in `$XDG_CONFIG_HOME/safo` (else
`~/.config/safo`), are created by the owner and only read here. Every component of the path is checked with `lstat` from
the root: a symlink anywhere in the ancestry (including `XDG_CONFIG_HOME` itself or its parents), a `..` component, an
ancestor below the home folder that is not yours or is group or world writable, or a folder or file that is not yours
or is group or world writable, makes the repo "cannot tell: keep local". The file is opened with `O_NOFOLLOW`, and its
inode, device, mode, size, mtime and ctime on the open descriptor must equal the earlier `lstat` (a file swapped in between is refused, even when the filesystem reuses the inode number).

### Content gate (before any command is printed)

Classifying the remote proves nothing about the files `ra-remote` would copy (tracked files, untracked files that are
not ignored, symlinks, nested repositories; gitignored files and unsafe index entries are skipped, and ra-remote itself
refuses nested `.git` entries). So for a public repo the checker also inspects the worktree and refuses
("keep local: the worktree holds files the runner would copy that are not in the public repository (N untracked files;
M nested git directories; K symlinks leaving the tree). Commit them, add them to .gitignore, or clone a clean copy under
~/.local/share/reach-around-dev first") when any of these holds:

- `git ls-files --others --exclude-standard` is not empty (a count, never names);
- any tracked entry differs from the public commit, because `ra-remote` copies the current worktree bytes, not the
  commit: "keep local: N tracked files differ from the public commit (modified, staged, intent-to-add,
  assume-unchanged, skip-worktree, a changed mode or link, a missing or extra path, or a submodule); commit or discard
  them first". The authority is the content verification below, not git's status. The older status checks stay as an
  additional layer that can only refuse more: `git status --porcelain=v1 --untracked-files=no -z` not empty, any
  `git ls-files -v` tag other than `H`, `git diff --cached --quiet` failing, or tracked entries with no `HEAD`. A git
  failure is a refusal too. Counts only, never names;
- a nested `.git` directory or file exists anywhere below the root (iterative `scandir` walk, symlinks not followed,
  bounded to 200000 entries: when the bound is hit, or a directory cannot be read, the tree is refused);
- a tracked or untracked-not-ignored symlink resolves outside the worktree;
- a tracked or untracked-not-ignored path has a component that looks like a secret even when it is tracked: `.env`,
  `.env.*`, `*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, `*.p12`, `*.pfx`, `*.kdbx`, `.netrc`, `credentials*`,
  `*secret*` (reported as "secret-looking file names present", a count only).

#### Published HEAD (the commit must be public bytes)

The runner copies the worktree, and the content verification compares it with the local `HEAD` tree. That only proves
the bytes are the commit's bytes; a local commit that was never pushed may hold private material. So the gate also
proves that `HEAD` is part of the public repository's history, and refuses otherwise ("keep local: cannot tell: could
not verify that HEAD is published (<class>)"). The class is one fixed word, never a URL, output or error text:
`network`, `timeout`, `unparseable`, `no-local-tip`, `not-ancestor`, `remote-identity`, `too-many-tips` or `git`.

Decision (round 6, replacing "the checker never contacts the network"): local metadata cannot prove publication. A
Daybreak review found two reproductions, so the check now asks the public remote itself:

1. Remote-tracking refs carry no provenance. A repository cloned from a private source keeps private commits under
   `refs/remotes/origin/*`; after the normal operation `git remote set-url origin <public github url>` the old gate
   treated those private commits as published.
2. Replace refs forge ancestry. `git replace` swaps the public tip for a synthetic commit that descends from a private
   `HEAD`, so `git merge-base --is-ancestor` said yes. Grafts and the commit-graph file are the same class of local
   history rewriting.

The proof, in order:

- The URL is rebuilt from the validated components only: `https://github.com/<owner>/<name>.git`, lowercase ASCII,
  from the owner and name that the repo class parsed. Every remote must name the same pair, else "remote-identity".
  Credentials, ports, paths and queries in the stored URL never reach the proof.
- One anonymous, read-only `git ls-remote --heads --tags` of that URL. The process gets a minimal environment (`PATH`, an
  empty private `HOME`, no prompts, no askpass, no global or system git config, no proxy variables) and runs outside the
  repository, with the `protocol` section set to allow only https, no credential helper, no proxy and no
  redirects. It starts in its own session; on a timeout, the byte cap or any error the whole process group (git and its
  transport helpers) gets SIGTERM, one second of grace, then SIGKILL, and is reaped. Limits: 20 seconds, 1 MiB of output
  (counted while reading), 20000 refs; lines must be `<40 or 64 hex> <ref>`; only
  `refs/heads/*` and `refs/tags/*` (peeled lines included) count. Any failure (offline, timeout, non-zero exit, a 404 for
  a private or renamed repository, a parse error, a cap) refuses, and so does any ordinary exception or malformed
  value from the listing step (fixed class `git` or `unparseable`, never a traceback); only KeyboardInterrupt,
  MemoryError and RecursionError propagate.
- `HEAD` is published only when at least one listed tip exists in the local repository (object ids are content
  addressed, so a local commit equal to a public tip is that public commit) and `git merge-base --is-ancestor HEAD <tip>`
  returns 0. A clone of a private source has none of the public tips. At most 200 existing tips are tried.
- Every git call of the gate disables local history rewriting: `--no-replace-objects`, replace refs off, `GIT_NO_REPLACE_OBJECTS=1`, the commit graph off, an empty alternate-refs
  command, and `GIT_GRAFT_FILE` pointing at an empty file.
- No cache: a fresh proof every run. The proof runs only when a command would be suggested, so a targeted command never
  touches the network.

This makes the checker contact github.com once per suggestion. It needs network access. Offline, the answer is "keep
local" (never a false pass): the work simply runs locally until the network is back. The proof is anonymous, so it
cannot see a private repository; that is intended, since a private repository is never published.

#### Content verification (the authority)

Git's status, `ls-files -v` and the cached diff all trust the index stat cache and apply clean/smudge filters, so a
repository-local `core` settings for the stat check (minimal check, ignoring ctime, ignoring stat) or a clean filter
setting with a `filter=NAME` attribute can make them report "clean" while the bytes the runner copies differ from
`HEAD`. So the gate passes only when this verification passes; a clean status never passes it on its own:

1. The committed tree is the source of truth: `git ls-tree -r -z --full-tree HEAD` (mode, object id and path of every
   entry), through `_git_for_selection` (isolated environment). No commit means every tracked path counts as not
   committed.
2. The copied set (`ls-files -c -o --exclude-standard -z`, tracked part) must equal the committed path set. An entry in
   the index but not in `HEAD`, or the reverse, counts as a difference. Untracked paths keep their own refusal.
3. Every committed entry is compared by content, never by stat: the worktree is opened with `O_NOFOLLOW` one directory
   component at a time (a directory swapped for a symlink is a difference), the raw bytes are hashed as a git blob
   (`blob <size>\0` plus the bytes, SHA-1 or SHA-256 to match the object id length) with no filter applied, and the
   result must equal the committed object id. A symlink is compared by the raw `readlink` target against the committed
   blob; a regular file must be a regular file; the executable bit must match the committed mode (100755 needs it,
   100644 allows none). A gitlink (mode 160000, a submodule) or any other mode is a difference. The hash is computed in
   Python in one pass over the tree, so there is no process per file and no path quoting problem (names with spaces,
   newlines and a leading dash are plain bytes).
4. Bounds, failing closed (never skipped): a file over 100 MB, more than 1 GB in total, or more than 200000 entries
   refuses with "cannot verify the copied bytes (size or entry bound)".
5. Content filters: `git check-attr -z --stdin filter` over every copied path (one batched call, isolated
   environment) reporting anything other than `unspecified`, or any `.gitattributes` in the copied set, the file
   `info/attributes`, or the attributes file named in the `core` section that mentions `filter`, refuses with "cannot tell:
   content filters are configured (filter)". This holds even for an unchanged file, because the runner copies raw bytes
   while the committed object may be the cleaned form. Only the key `filter` is named, never a filter name or value.

A mismatch means "the bytes the runner would copy are not the committed public bytes": commit or discard the change
(or clone a clean copy), then run the check again. Counts only, never names. The verification does not read the index
stat cache and is not affected by the stat-check settings of the `core` section, `status` settings,
the submodule-ignore setting, assume-unchanged or skip-worktree bits, or index extensions.

#### Same file selection as ra-remote

Every git call that lists or inspects files (`ls-files`, `status`, `diff --cached`, `rev-parse HEAD`) goes through one
helper, `_git_for_selection`, which mirrors `git_list` in `~/.local/bin/ra-remote`:

```
GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
  git ... -c <fsmonitor off> -c <untracked cache off> \
          -c <excludes file /dev/null> -c <hooks path /dev/null> ...
```

`ra-remote` also unsets every other `GIT_*` variable first, so the helper drops them (`GIT_DIR`, `GIT_INDEX_FILE` and
the like). Result: an excludes-file setting, a global or XDG ignore file or a system config can no longer hide a file from
the checker that `ra-remote` would copy; `.git/info/exclude` and `.gitignore` still apply to both. The checker runs `git -C
WORKTREE` where `ra-remote` passes `--git-dir` and `--work-tree`; the worktree is already resolved once in `main`.

The transport query (repo class, rule 1) deliberately does not use the helper: it reads the effective configuration,
because it asks where a remote really points, not which files are copied.

A refusal is "keep local", not a violation: `--strict` exits 0 for it. `--strict` exits 1 only when a public, clean repo
in an allowed folder runs a full suite or sweep locally. The decision is recorded as `keep-local-content`; names of files
are never printed or stored.

### Dev-folder rule

The ra-remote command is printed only when the resolved worktree (symlinks and `..` resolved, a real path check, never a
substring test, resolved in exactly one place) is strictly below `~/.local/share/reach-around-dev`, `~/.local/share/safo-dev/agents` or
`~/.local/share/chatty-kathy-dev` (the fixed list in `ra-remote`). Otherwise: "keep local: the worktree is outside the
runner's allowed folders (move or clone it under ~/.local/share/reach-around-dev first)".

`--strict` exits 1 only when a public repo, in an allowed folder, runs a full suite or sweep locally.

Each check appends one line to `~/.local/state/safo/runner-check.jsonl` (`$XDG_STATE_HOME` honored): time, class,
decision and repo class. The command text is never stored. The `safo` state directory is kept at mode 0700 and the file
at 0600 (enforced on existing ones too, symlinks not followed).

### Bounds fail closed

Reading a command is bounded: shell nesting (`bash -c` inside `bash -c`, or inside `ra-remote`) deeper than 4, and more
than 10 stacked wrappers (`nohup`, `env`, `timeout` and so on). Reaching a bound is ambiguous, so the line counts as a
full suite and `--strict` flags it with the note "nesting too deep to read: treat as a local full suite". The walk bound
of the content gate refuses the tree. No other bound exists in the classifier.

### Out of scope

- Shell functions, aliases, differently named Make targets and package scripts that run a suite are not recognized: the
  classification is static and literal, on the command position only.
- A secret already committed to a genuinely public repository is out of scope (it is already public). The content gate
  refuses what is not public: untracked files, modified tracked files, nested repositories, outside symlinks and
  secret-looking names.
