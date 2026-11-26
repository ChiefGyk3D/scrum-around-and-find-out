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
```

It reads one command line or a brief and flags a local full suite or sweep: pytest with no file, `::` id or `-k`,
`mutmut`, `cosmic-ray`, `stryker`, `vitest run` with no file, `npm test`, `make check`. A command already wrapped in
`ra-remote` is accepted. For a flagged command it prints the `ra-remote --plan` form and the real form. It never runs
ra-remote and never contacts the runner.

A repo counts as public only when its `origin` owner is on the owner list: `SAFO_PUBLIC_OWNERS` (comma separated), else
the file `public-owners` in the safo config dir (one owner per line, `#` comments). An owner not on the list "looks
private"; with no list or no remote it says "cannot tell: keep local". Neither case is ever sent to the runner.
`--strict` exits 1 only when a public repo runs a full suite or sweep locally.

Each check appends one line to `~/.local/state/safo/runner-check.jsonl` (`$XDG_STATE_HOME` honored): time, class,
decision and repo class. The command text is never stored.
