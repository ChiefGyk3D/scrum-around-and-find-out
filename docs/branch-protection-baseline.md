# The branch-protection baseline and how to roll it out

The standard (owner decision, 2026-11-28, issue #541) for a repository's default branch:

| Situation | Gate |
| --- | --- |
| The repository has a `CI green` check | The default branch requires `CI green`, **up to date before merging (strict) on**, **conversation resolution on**, no force push, no deletion |
| The repository has no `CI green` check (a hobby repository) | The BASIC gate: no force push, no deletion, nothing else required |
| A public repository | Secret scanning and push protection on |

`safo protection --all` ([protection audit](protection-audit.md)) reports drift from the standard. `scripts/apply-baseline.sh`
writes it. Neither runs from an agent: the maintainer runs the script from a machine whose active `gh` account owns the
repository.

## `scripts/apply-baseline.sh` modes

```bash
scripts/apply-baseline.sh --repo OWNER/NAME                                 # full baseline for one repo: plan only
scripts/apply-baseline.sh --repo OWNER/NAME --mode standard [--apply]
scripts/apply-baseline.sh --repo OWNER/NAME --mode basic [--apply]
scripts/apply-baseline.sh --repo OWNER/NAME --mode secret-scanning [--apply]
```

| Mode | What it writes |
| --- | --- |
| `full` (default) | This repository's whole baseline (the protection rule with strict and conversation resolution on, the Actions settings, the tag ruleset, reporting and auto-merge) |
| `standard` | Takes the rule as GitHub has it and sets strict and conversation resolution on, force push and deletion off. Every required check keeps its exact name and app; administrator enforcement, the review count and linear history stay as they were |
| `basic` | No rule yet: a rule that requires nothing and blocks force push and deletion. A rule exists already: it is kept and only force push and deletion are set off |
| `secret-scanning` | Secret scanning and push protection on a public repository (a private repository is refused) |

Properties that hold in every non-`full` mode, and for the protection write in `full`:

- **Dry run is the default.** Without `--apply` it reads the live repository (GET only), prints the body it would send,
  and writes nothing. (`full` without `--apply` makes no call at all.)
- **The check name is read, never guessed.** `standard` reads the live rule's required checks and stops if none is
  `CI green` or `<job> / CI green`; use `basic` for that repository.
- **A backup first.** `--apply` writes the old rule to `<backup-dir>/<owner>__<repo>-<UTC stamp>.rule.json` and a PUT-ready
  `.restore.json`, mode 0600, in a 0700 directory (`--backup-dir`, else `SAFO_BACKUP_DIR`, else
  `$XDG_STATE_HOME/safo/protection-backups`).
- **A read-back after each write.** The rule (or the repository's security settings) is read again and compared with what
  was written, and the force-push bypass list is read over GraphQL. The first difference stops the run with exit 4.
- **Rollback lines.** A `ROLLBACK:` line is printed before the write and again on a mismatch: a PUT of the `.restore.json`
  backup, or `DELETE` of the rule when there was none, or a PATCH restoring the old security settings.
- **A repository is refused (exit 3)** when it is archived, is a fork, is not owned by a user account, has no default
  branch, or differs from what the plan expects: `--expect-branch`, `--expect-visibility public|private`,
  `--expect-protection none|rule`.
- A rule this script cannot carry (push restrictions, review dismissal or bypass lists) stops the run before any write.

Exit codes: 0 done, 1 error, 3 refused, 4 read-back mismatch.

## Generating the owner's rollout plan

`scripts/gen-protection-plan.py` turns an audit snapshot (the `repo|vis|branch|prot|ctx|strict|conv|...` table) into one
bash script. It writes a file (mode 0700) and runs nothing against GitHub.

```bash
python3 scripts/gen-protection-plan.py --audit audit.txt --out plan.sh --apply-script scripts/apply-baseline.sh \
  --skip NAME=REASON --secret NAME [--secret NAME ...]
bash plan.sh            # dry run: lists every change, writes nothing
bash plan.sh apply      # writes, one repository at a time
```

Per repository: no rule becomes `basic` (expecting none); a rule with `CI green` but strict or conversation resolution
off becomes `standard`; a rule without `CI green` becomes `basic`; each `--secret` name also gets `secret-scanning`.
Empty repositories and `--skip` names are listed as `SKIP` with the reason and never touched. In `apply`, a refused
repository is skipped and the run goes on (final exit 1); the first failed write or read-back mismatch stops the whole
run. Each repository's `ROLLBACK:` line is in the output and its backup is in the backup directory.

## Notes

- Strict mode makes a pull request rebase or merge `main` before it can merge, so a stack of open pull requests needs one
  update each. That cost is accepted by the standard.
- A repository protected by a ruleset instead of a classic rule is not handled here: a second, classic rule would stack
  on the ruleset. Plans skip such repositories with the reason.
