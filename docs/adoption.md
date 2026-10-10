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
to read on a runner). The local modes (`usage`, `route`, `outcome`, `local`, `hooks`) are not allowed in the Action. See
[Limits](limits.md) for the rest of what is accepted.

If your repositories already call the shared workflows in
[git-your-ship-together](https://github.com/ChiefGyk3D/git-your-ship-together), its `project-sync.yml` is a thin wrapper
around this Action with the same inputs it always had; bump the pin.

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
