# Branch-protection drift audit (`safo protection --all`)

`safo protection --repo OWNER/NAME` reads one repository's default branch against ten conditions
([adoption](adoption.md)). `safo protection --all` runs the standard over every repository in the board file, so drift
shows up in one pass. It sends GET requests only (REST, through the same read-only client), reads one repository after
another, and changes nothing. It needs read access to branch protection and rulesets; no token is printed.

```bash
safo --board board.yaml protection --all [--require-app-id 15368]     # exit 0, 1 or 2
```

`--all` and `--repo` are mutually exclusive: give exactly one, or the command exits 2 with a usage error.

## The standard

For each repository (less `rules.gate_exempt_repos`, which are listed and not read), from the classic rule or the active
branch rulesets of the default branch:

| Item | Result when it does not hold |
| --- | --- |
| a rule or ruleset applies | `MISSING protection` |
| the `CI green` check is required (pinned to `--require-app-id` when given) | `MISSING ci-green` |
| a pull request is required | `MISSING pull-request` |
| force pushes are off | `DRIFT force-push` |
| deleting the branch is off | `DRIFT deletion` |
| every security job the repository's workflows declare is required | `MISSING security-check NAME` |

A security job is a job, in a workflow that runs on `pull_request` or `pull_request_target`, whose name or id matches
security, codeql, semgrep, gitleaks, trivy, zizmor, dependency review or sast. A job that never runs on a pull request
cannot be required, so it is not demanded. A required context matches a job by its name, or as `job / inner` or
`outer / job` (the name a reusable workflow's job gets in a caller).

Reported on the line, never a failure: `admins: enforced` or `can bypass`, and `conversation resolution: required` or
`off`.

## Output and exit codes

One line per repository (`OK owner/name [...]`, `owner/name: ITEM; ITEM [...]`, `EXEMPT ...`, or `UNKNOWN owner/name:
reason`) and a last line `protection: N repositories read, D with drift[, U unknown]`. Exit 0 when nothing drifted,
1 when any repository has a MISSING or DRIFT item, 2 when any repository could not be read in full (that outranks 1,
as in `safo audit`). An unreadable repository never counts as a pass, and the others are still read.

## Limits

The protection is read once per repository, not twice as `--repo` does, so a change made during the read can be missed.
This is a drift audit, not the proof of one instant. Reading protection needs administration read access: a token
without it sees a repository as unprotected or unreadable, and the line says what GitHub answered.
