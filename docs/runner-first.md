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
prints the `ra-remote --plan` form and the real form. It never runs ra-remote and never contacts the runner. It fails
closed: anything it cannot prove public stays local.

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
re-expressed as `env NAME=value ...` and every word goes through `shlex.quote`. If the line has a `cd`, a redirect, a
pipe, a subshell, a command substitution, an expansion, a backslash or more than one command, it prints advice only:
`run this through ra-remote: ra-remote --plan WORKTREE -- <the suite command alone>`. It never prints a rewritten line
that changes meaning.

### Repo class (decision rules, in order)

1. Transport overrides: if any of these is set the repo is "cannot tell: git transport is overridden (setting NAME)" and
   stays local. Environment: `GIT_SSH`, `GIT_SSH_COMMAND`, `GIT_PROXY_COMMAND`, any `GIT_CONFIG_*`. Effective git
   configuration (`git config --show-origin --get-regexp`, includes followed): `core.sshcommand`, `core.gitproxy`,
   `remote.*.vcs`, `remote.*.proxy`, `remote.*.pushurl`, `url.*.insteadof`, `url.*.pushinsteadof`, and an `includeIf`
   with a `gitdir` condition. Only the setting key is named, never a value. The checker also runs git with the
   environment it was given, so the real global git configuration of the caller is what is read.
2. Read every remote (`git remote -v`, fetch and push). Each must parse as a `github.com` https, ssh or scp-like
   `owner/name` URL; the host is parsed, so `https://evil.com/github.com/owner/x` is rejected. Userinfo is never printed.
   Non-ASCII owner or repository names are rejected. No remote, or any remote that does not parse: "cannot tell: keep
   local".
3. Denylist, always wins: built-in name patterns `*-instance`, `reach-around-instance`, `*brand*`, `*dotfiles*`,
   `*ai-shit*`, `*lead*`, `*notes*`, `*private*`, `*secret*`, `*homelab-identity*`, plus one name or glob per line in
   `~/.config/safo/runner-never` (matched against `name` and `owner/name`). Names are normalized first (NFKC, lowercase,
   trailing slashes, dots and spaces stripped, `.git` suffixes removed until stable) and matched in both the normalized
   and the raw form, so `x-instance.git.git`, `x-instance.GIT` and `x-instance.` are denied. A match on any remote:
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
inode, device and mode on the open descriptor must equal the earlier `lstat` (a file swapped in between is refused).

### Content gate (before any command is printed)

Classifying the remote proves nothing about the files `ra-remote` would copy (tracked files, untracked files that are
not ignored, symlinks, nested repositories; gitignored files and unsafe index entries are skipped, and ra-remote itself
refuses nested `.git` entries). So for a public repo the checker also inspects the worktree and refuses
("keep local: the worktree holds files the runner would copy that are not in the public repository (N untracked files;
M nested git directories; K symlinks leaving the tree). Commit them, add them to .gitignore, or clone a clean copy under
~/.local/share/reach-around-dev first") when any of these holds:

- `git ls-files --others --exclude-standard` is not empty (a count, never names);
- a nested `.git` directory or file exists anywhere below the root (iterative `scandir` walk, symlinks not followed,
  bounded to 200000 entries: when the bound is hit, or a directory cannot be read, the tree is refused);
- a tracked or untracked-not-ignored symlink resolves outside the worktree;
- a tracked or untracked-not-ignored path has a component that looks like a secret even when it is tracked: `.env`,
  `.env.*`, `*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, `*.p12`, `*.pfx`, `*.kdbx`, `.netrc`, `credentials*`,
  `*secret*` (reported as "secret-looking file names present", a count only).

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
