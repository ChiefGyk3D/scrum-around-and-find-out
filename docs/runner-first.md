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
- Command: ra-remote [--timeout S] [--cpus N] [--memory Ng] [--py V] [--no-deps] [--fetch REL] WORKTREE -- COMMAND...
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
`command`, `exec`, `nice`, `timeout`, `env`, `uv run`, `poetry run`, `pipenv run`, `pdm run`, `hatch run`, `npx`, `bunx`,
`pnpm exec`, `npm exec`, `xargs`, `python -m`, and `bash|sh|zsh|dash|ksh -c STRING` (the string is checked too). Segments
split on `&&`, `||`, `;`, `|`, `&`, newline, parentheses, backticks and `$(...)`. So `pip install pytest`, `which pytest`,
`echo pytest`, `grep pytest f` and `ssh host pytest` are not suites.

- pytest: with no file, no `::` id and no `-k`/`--lf`/`--ff`. Directories count as full. Values of `--deselect`,
  `--ignore`, `--ignore-glob`, `--junitxml`, `-p`, `--rootdir`, `--confcutdir`, `--cov`, `-c`, `-o` (and similar) are not
  targets. `--version`, `--help`, `--collect-only` and similar do not run tests.
- mutation sweeps: `mutmut`, `cosmic-ray`, `stryker`.
- JavaScript: `vitest [run]` with no file; `npm|pnpm|yarn test`, `t`, `run test`, `run test:*`.
- `tox`, `nox`; `make test`, `make check`.
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

1. Read every remote (`git remote -v`, fetch and push). Each must parse as a `github.com` https, ssh or scp-like
   `owner/name` URL; the host is parsed, so `https://evil.com/github.com/owner/x` is rejected. Userinfo is never printed.
   No remote, or any remote that does not parse: "cannot tell: keep local".
2. Denylist, always wins: built-in name patterns `*-instance`, `reach-around-instance`, `*brand*`, `*dotfiles*`,
   `*ai-shit*`, `*lead*`, `*notes*`, `*private*`, `*secret*`, `*homelab-identity*`, plus one name or glob per line in
   `~/.config/safo/runner-never` (matched against `name` and `owner/name`). A match on any remote: "looks private".
3. Allowlist mode: if `SAFO_PUBLIC_REPOS` (comma list of `owner/name`) or the file `public-repos` is set, the repo is
   public only when every remote is listed. Otherwise "looks private".
4. No allowlist: owner-level trust. `SAFO_PUBLIC_OWNERS` (comma list) or the file `public-owners`; every remote owner must
   be listed. The output then says "public: owner listed, no denylist match".
5. Anything else: "cannot tell: keep local".

The config files (`runner-never`, `public-repos`, `public-owners`) sit in `$XDG_CONFIG_HOME/safo` (else
`~/.config/safo`), are created by the owner and only read here. A file, or its folder, that is a symlink, is not yours,
or is group or world writable makes the repo "cannot tell: keep local".

### Dev-folder rule

The ra-remote command is printed only when the resolved worktree (symlinks and `..` resolved, a real path check, never a
substring test) is strictly below `~/.local/share/reach-around-dev`, `~/.local/share/safo-dev/agents` or
`~/.local/share/chatty-kathy-dev` (the fixed list in `ra-remote`). Otherwise: "keep local: the worktree is outside the
runner's allowed folders (move or clone it under ~/.local/share/reach-around-dev first)".

`--strict` exits 1 only when a public repo, in an allowed folder, runs a full suite or sweep locally.

Each check appends one line to `~/.local/state/safo/runner-check.jsonl` (`$XDG_STATE_HOME` honored): time, class,
decision and repo class. The command text is never stored. The `safo` state directory is kept at mode 0700 and the file
at 0600 (enforced on existing ones too, symlinks not followed).
