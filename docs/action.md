# The Action: what it trusts from its caller

The Action runs in a workflow that someone else writes and triggers. This page states exactly what it checks before it
fetches, mints or uses a credential, and what it reads from the repository. Read it with [Adopting](adoption.md) (the
caller workflow) and [Limits](limits.md) (the trust boundary of a composite action).

## What is guaranteed

**A credential is used only on an event the Action positively classifies as trusted.** The check is an allow-list and
runs in the preflight step, before the secret-store fetch, the App token mint and any use of a literal `private-key` or
`token` input. An event that is not on the list gets no credential path at all and the run fails with a message that
names the event and the ref. Matching is exact: the event name and the ref are compared as given, with no case folding,
trimming or normalization. A value that is missing or not exactly `true` or `false` where one is required is a refusal.

| Event | Trusted when |
| --- | --- |
| `push` | the ref is the default branch or a tag, and the run did not come from a fork |
| `schedule` | the ref is the default branch (the repository's default branch must be present in the event) |
| `workflow_dispatch` | the ref is a branch or tag of this repository (GitHub offers manual runs only to users with write access) |
| `issues`, `workflow_run` | the ref is the default branch and the run did not come from a fork |
| `pull_request` | the pull request is from this repository |
| `pull_request_target` | the ref is the default branch and the pull request is from this repository; a pull request from a fork only when `allow-fork-pull-request-target` is `"true"` |

A repository that is itself a fork receives no credential on any event unless `allow-fork-repository` is `"true"`.

Every other event is refused for a run that needs a credential. That includes events that can carry pull request
content, reusable-workflow callers and manual events from a fork. The `validate` mode uses no credential and runs on any
event.

**No credential value reaches a process before the verdict.** The preflight is the first step after the install and
receives only whether a key and a token were given, never their values. The step that masks the credentials, the
secret-manager fetch, the token mint and the run step wait for its verdict, and `validate` runs with no token.

**The board file and the status-body file come from a revision the caller binds.** With a credential in play the
preflight reads both files from the git object database at the trusted revision, never from the working tree, and hands
the later steps a private copy. The trusted revision is the `trusted-ref` input (a full commit id, or a full `refs/heads/`
or `refs/tags/` name the checkout holds) and, when it is empty, the commit this run is on (`github.sha`). So:

- A file edited, added or removed in the working tree after the commit is not what the Action reads.
- A path that is absolute, contains `..`, `.` or empty parts, a backslash or a control character, or names a directory
  is refused.
- A path that is a symbolic link in the trusted revision, or that passes through one, is refused. Only a regular file
  is read, up to a size limit.
- The repository must be checked out for a run that reads a file (`actions/checkout` with `persist-credentials: false`).
- The checked-out commit must be the trusted revision, so a credential never sits next to a different revision's files.
  For `pull_request_target`, `workflow_run` and `issues` runs `trusted-ref` can only name the commit the run is on.
  `trusted-ref` is never the head commit of the pull request under test, except for a `pull_request` from this repository.

The board's `repositories` list decides which repositories the installation token is limited to, so the scope of the
token is the scope the trusted revision declares.

**The run reports what it decided.** The preflight prints one notice with the event, the ref and the short trusted
revision.

## What is not guaranteed

- The Action cannot inspect other steps. A step that runs pull request code in the same job before the Action, or that
  reads the credential steps' environment, is outside what a composite action can stop. Keep the job that holds the
  credential free of such steps ([Limits](limits.md)).
- The caller chooses `trusted-ref`. The Action holds it to the rules above and no further: a ref the caller points at a
  revision it does not trust is trusted.
- The Action trusts the values the runner supplies for the event and the ref.
- `workflow_dispatch` trust rests on GitHub's rule that only users with write access can start one.
- With `allow-fork-pull-request-target` set, a fork's pull request can make the job run with a credential; the job must
  have no checkout of pull request code and run nothing from the pull request.
- A personal access token keeps the permissions it was created with. [Dry run](#dry-run) lowers an App token only.

## Dry run

`dry-run: "true"` prints every change instead of making it. On the App credential path the minted token is also
read-only (Projects read). A personal access token passed as `token` keeps the permissions it was created with, so use a
read-only token for a dry run on that path.

## Caller examples

Scheduled and event-driven board sync from the repository that holds `board.yaml`:

```yaml
on:
  issues:
    types: [opened, reopened, closed, edited]
  schedule:
    - cron: '17 5 * * 1'
  workflow_dispatch:

jobs:
  board:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@<sha> # vX.Y.Z
        with:
          persist-credentials: false
      - uses: ChiefGyk3D/scrum-around-and-find-out@<sha> # vX.Y.Z
        with:
          mode: ${{ github.event_name == 'issues' && 'sync' || 'reconcile' }}
          board-file: board.yaml
          trusted-ref: ${{ github.sha }}
          client-id: ${{ vars.BOARD_APP_CLIENT_ID }}
          private-key: ${{ secrets.BOARD_APP_PRIVATE_KEY }}
```

Pull request events with no checkout and no board file (the board-less inputs):

```yaml
on:
  pull_request_target:
    types: [opened, reopened, ready_for_review, closed]

jobs:
  card:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: ChiefGyk3D/scrum-around-and-find-out@<sha> # vX.Y.Z
        with:
          mode: sync
          project-url: https://github.com/orgs/<login>/projects/<n>
          client-id: ${{ vars.BOARD_APP_CLIENT_ID }}
          private-key: ${{ secrets.BOARD_APP_PRIVATE_KEY }}
```

A pull request from a fork reaches the board only after you set `allow-fork-pull-request-target: "true"` on that job.
