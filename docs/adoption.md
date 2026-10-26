# Adoption

Four steps: create an App, write a `board.yaml`, run `bootstrap`, add the caller. Nothing is hosted; the Action runs in your
workflow with your App's key.

## 1. Create a GitHub App (organization boards)

1. Open your organization's Settings, Developer settings, GitHub Apps, New GitHub App. Name it, set the homepage to your
   repository, and **uncheck Webhook, Active**: the App receives no events.
2. Permissions. **Organization**: Projects, read and write. **Repository**: Issues, read; Pull requests, read. Metadata,
   read, is added for you. Nothing else.
3. "Where can this GitHub App be installed?": **Only on this account**.
4. Note the **Client ID** (an identifier, not a secret). Generate a **private key** (a `.pem`).
5. Install the App on the organization and choose **Only select repositories**: the ones in your `board.yaml`.
6. Store the key in your secret store (a repository secret, or an OIDC-fetched store) and delete the downloaded file.

A repository the App is not installed on answers NOT_FOUND to the App's token. `audit` reports it as **UNKNOWN** and
`reconcile` names it and exits 1, so a missing installation is loud, not silent.

## 2. Write `board.yaml`

Start from [examples/renegade-penguin.yaml](../examples/renegade-penguin.yaml) and the [reference](board-yaml.md). Leave
`project.number` out to have `bootstrap` create the project.

## 3. Bootstrap, then audit

```sh
gh auth refresh -s project            # once: the project scope
safo --board board.yaml bootstrap     # creates what is missing; prints the UI-only checklist
safo --board board.yaml audit         # 0 clean, 1 drift, 2 cannot tell
safo --board board.yaml reconcile     # add every open issue and PR, mark closed ones Done
```

`bootstrap` never edits an existing field's options. If it refuses something it prints the step to do in the project's
settings, and exits 1.

## 4. The caller workflow

Call the Action directly from the repository that holds `board.yaml`:

```yaml
name: Project board
on:
  issues:
    types: [opened, reopened, closed, edited]
  schedule:
    - cron: '17 5 * * 1'
  workflow_dispatch:

permissions:
  contents: read

jobs:
  board:
    runs-on: ubuntu-latest
    steps:
      # First step: a composite action cannot be the first step of a job, so it cannot harden the runner itself.
      - uses: step-security/harden-runner@<sha> # vX.Y.Z
        with:
          egress-policy: block
          allowed-endpoints: api.github.com:443 github.com:443 pypi.org:443 files.pythonhosted.org:443
      - uses: actions/checkout@<sha> # vX.Y.Z
        with:
          persist-credentials: false
      - uses: ChiefGyk3D/scrum-around-and-find-out@<sha> # vX.Y.Z
        with:
          mode: ${{ github.event_name == 'issues' && 'sync' || 'reconcile' }}
          board-file: board.yaml
          client-id: ${{ vars.BOARD_APP_CLIENT_ID }}
          private-key: ${{ secrets.BOARD_APP_PRIVATE_KEY }}
```

Pin by commit with the version in a comment; Dependabot moves both. Pull requests reach the board through the weekly
`reconcile`. To react to pull-request events as well, use `pull_request_target` and read the trust boundary below first:
the board-less inputs (`project-url` and the status inputs, no `board-file`) exist for that job, which needs no checkout.

## 5. Optional: the agent plugins

To hand work to Codex or a local Ollama model from inside Claude Code, add the two plugins. The steps, including pointing
the Ollama plugin at your server, are on [Claude Code plugins](plugins.md). Nothing in the Action needs them.

## 6. Keep agent worktrees out of the index

Claude Code puts agent worktrees under `.claude/worktrees/`. Each one is a nested repository, so a `git add -A` in the
parent stages it as a gitlink (mode 160000, an embedded repository) and the next push carries a pointer to a path nobody
else has. Two controls, both offline:

1. Ignore the path in every repository that agents work in: add `.claude/worktrees/` to `.gitignore`. Nothing that
   writes a `.gitignore` for you does this yet (`scripts/apply-baseline.sh` sets repository settings, not files), so
   adopt it by hand.
2. Fail a change that adds a gitlink anywhere under `.claude/`. `scripts/check-claude-gitlinks.sh`
   reads the index of the checkout it runs in and exits 1, naming each path, when it finds one. A submodule outside
   `.claude/` is not flagged; a gitlink at `.claude` itself is. With `--require-ignore` it also exits 1 when
   `.claude/worktrees/` is not ignored. It exits 2 ("cannot tell") outside a git checkout, when the index cannot be read,
   and on any extra argument, so none of those is ever a pass. Copy the script into a repository, and add a step after
   checkout:

```yaml
      - uses: actions/checkout@<sha> # vX.Y.Z
        with:
          persist-credentials: false
      - run: bash scripts/check-claude-gitlinks.sh --require-ignore
```

In this repository it is part of `make check`. CI enforcement here is indirect: `tests/test_claude_gitlinks.py` runs the
script against the CI checkout, and no workflow step calls it directly. A shared GYST workflow input is only proposed
(GYST issue 217), and the adoption inventory has not been checked against this control. The tests build throwaway
repositories with a staged gitlink.

Not covered: a hook that blocks `git add -A` before it runs. It would need only `tool_input.command` from a PreToolUse
Bash hook, but delivery has not been verified, so this is a CI check and a `.gitignore` line, not a hook.

## The trust boundary

Never run untrusted code (a PR checkout, a build, a script) in the same job before the SAFO Action. With
`pull_request_target`, run SAFO in its own job with no checkout of PR code. The job/runner boundary is the trust boundary:
a same-user process from an earlier step can mutate the Action's venv or read credential-step environments.

The Action does what a composite action can: it builds a fresh venv in a new private directory, runs Python isolated,
checks the venv before and after the install, masks every credential, and passes inputs only through environment
variables. It cannot defend against a step that already runs as the same user in the same job, because that step can
change the venv after it is created or read the environment of the steps that hold the key. Keep the job that holds the
App key free of anything you do not trust. The Action accepts only the modes that talk to the board (`validate`,
`bootstrap`, `audit`, `sync`, `reconcile`, `status`; its preflight also lets `agents-status` through, which has nothing
to read on a runner). The local modes (`usage`, `route`, `outcome`, `local`, `hooks`, `profiles`) are not allowed in the Action. See
[Limits](limits.md) for the rest of what is accepted.

If your repositories already call the shared workflows in
[git-your-ship-together](https://github.com/ChiefGyk3D/git-your-ship-together), its `project-sync.yml` is a thin wrapper
around this Action with the same inputs it always had; bump the pin.

## Check the default branch's protection

A code owner file is only a file until branch protection makes GitHub enforce it. `safo protection` reads the default
branch's protection back and says which required condition does not hold. It sends GET requests only, needs read access,
and changes nothing; you apply the protection yourself.

```bash
safo protection --repo OWNER/NAME [--agent-login AGENT]      # exit 0, 1 or 2
```

It exits 0 only when all ten conditions hold for the default branch, from the classic branch protection rule or from
active branch rulesets (a ruleset in `evaluate` or `disabled` mode, or for tags, does not count):

| Condition | Meaning |
| --- | --- |
| `code-owner-review` | code-owner review is required |
| `ci-green` | the `CI green` check is required: the exact name, or one plain-text prefix and ` / ` (`<caller job> / CI green`); the matched context is printed |
| `up-to-date` | the branch must be up to date before merging, or a merge queue is on |
| `admins-included` | administrators are included (`enforce_admins`; no ruleset bypass) |
| `no-bypass` | no bypass allowance or bypass actor; `--agent-login` is named if that account holds one |
| `no-force-push`, `no-deletion` | force pushes and branch deletion are off |
| `codeowners-board-yaml`, `codeowners-codeowners-file` | the CODEOWNERS file (read at the default branch's head commit) names an owner for `board.yaml` and for `.github/CODEOWNERS` |
| `codeowners-workflows` | every file that is under `.github/workflows/` now, and any file a pull request could add there under any name or depth, has an owner (see below) |

Exit 1 prints a `FAIL <condition>` line for each one that does not hold; an unprotected branch (404 "Branch not
protected", no rulesets) fails them all. Exit 2 means it could not tell: a 403 or a rate limit, a response that is not
JSON, or any field it reads that is absent, null or the wrong type. It is never read as "nothing is set", and it is never
exit 0. The token goes to `https://api.github.com` only (`--api-url` is for a loopback test server).

Name-only matching lets another source satisfy the check. A required check that is not pinned to an app (GitHub's
`app_id` or `integration_id` is null, absent or -1: "any app") can be reported by any app or token that can write commit
statuses, unless branch protection pins it. The default stays name-only, because the shared baseline sets required
checks by name, but the read-back never reports that silently: it prints `NOTE ci-green: required check is not pinned to
an app (any source can satisfy it)` (or says the check is pinned to an app other than the expected GitHub Actions app
15368) and the exit code is unchanged. To make the pin a condition, pass `--require-app-id 15368`: then every matching
check must be pinned to exactly that app, or `ci-green` fails with exit 1. An `app_id` or `integration_id` that is not
null, -1 or a positive integer is exit 2.

### How CODEOWNERS is judged

The file is read at the default branch's head commit (the commit is read once, and CODEOWNERS, the CODEOWNERS errors
and the workflow tree are all read at it). Last matching rule wins. An owner counts only if it passes two layers: GitHub's
naming rules (`@login` of at most 39 characters with no leading, trailing or doubled hyphen, `@org/team`, or an email), and
GitHub's own answer from `GET /repos/{owner}/{repo}/codeowners/errors?ref=<commit>` (the endpoint exists and returned
`{"errors":[]}` on a live read; the shape of a non-empty list, `line` and `path` per entry, is INFERRED from the REST
docs and not yet observed). A line that fails either layer is treated as having no owner. If the errors endpoint cannot
be read, that is exit 2.

`codeowners-workflows` is judged three ways, and all must pass:

1. **Real files.** The workflow directory is listed from the git tree at that commit (root, `.github`, then
   `workflows` recursively, so nested files count; a truncated listing is exit 2). Every file must have an owner.
2. **Structure (the proof).** The last directory-wide rule (`/.github/workflows/`, `.../**`, a parent such as
   `/.github/`, `/.github/**`, or `*`) must name an owner, and no later rule that could touch the directory may name none.
   Then every path under it, whatever it is called, ends at an owner. A rule for `*` passes this, and it also covers the
   rest of the repository. File-specific owners (`/.github/workflows/ci.yml @o`) and partial globs (`*.yml`) do not pass: a
   new `release.yml` would have no owner.
3. **Sampling (a second layer, not a proof).** About twenty paths with random names and random directory names (`.yml`,
   `.yaml` or none, one to three levels), generated at run time, are asked of the rules. A rule file cannot have
   anticipated them. It is a sample, so a pattern engineered to own most names can pass one run; the structure check above
   is what stops it.

An empty or absent `.github/workflows/` is **not** vacuously covered: checks 2 and 3 still apply, so it passes only
when a directory-wide rule is in place.

### Exit codes and output

0 all conditions hold; 1 at least one does not; 2 cannot tell; 130 interrupted (nothing was decided). The decision is
computed before anything is printed. If the report cannot be written (a closed pipe), a 1 or a 2 stays as it was, and a 0
becomes 2: a pass nobody could read is not reported as one. The repository document is read at the start and again at the
end (`id`, `full_name` and `default_branch` must be identical, and `full_name` must be the repository asked for); a
change in between is exit 2. A list with a `rel="next"` link is exit 2 whether or not it is short. Each response is read
once, with no redirect, a read timeout and a 1 MiB cap; a body shorter than its Content-Length, or two different
Content-Length headers, is exit 2.

This is a local mode, not part of the Action. Shared logic with the GraphQL default-branch gate read (#129) is for a
later change; the two read different APIs and share no code today.

## A public repository on a personal account, a board in an organization

Set `app-owner` to the organization and the token is minted from the organization's App installation, so a public
repository on a personal account can sync to the organization's board. The token is never installation-wide, so it
needs a repository scope, and the calling repository cannot be one (it belongs to the personal account). Name the
organization's repositories in `repositories` (names only, no owner), or list them in `board.yaml`. The token then
carries only the one organization-projects permission, limited to those repositories, and the repository must be public
because the organization's App can read a personal account's issues and pull requests only then. Without a scope the
run stops and says so.

## The personal-token exception (user-owned boards)

A GitHub App has no user-account Projects permission, so an App cannot write a board owned by a user. For that one case the
Action accepts a fine-grained personal access token as `token`, with Projects read and write and Issues and Pull requests
read. It is refused for an organization board unless you also set `allow-token-for-org: true`, and `safo` refuses an App
token for a user board before it makes a request.

Better still, keep a user-owned board current from your own machine: `safo reconcile` with `gh auth token`, on a schedule
you run (cron or a systemd timer). No token is stored anywhere.

## First run, end to end

1. `safo bootstrap`, then do the UI checklist it prints.
2. `safo audit` until it prints `clean`.
3. `safo --dry-run reconcile`: every change is printed as `dry run: would ...`, none is sent.
4. `safo reconcile`. Run it again: it reports `nothing to do`.
5. Open a test issue. It appears as Backlog within a minute. Close it: Done, with today's date.
