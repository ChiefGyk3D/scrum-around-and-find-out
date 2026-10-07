# Scrum Around and Find Out — design

**Status:** draft for the maintainer's review, 2026-10-07.
**Repository:** `ChiefGyk3D/scrum-around-and-find-out` (public).
**Delivered by:** `ChiefGyk3D/git-your-ship-together` (GYST), whose
`project-sync.yml` becomes a thin wrapper around this project's Action.

## Why

One maintainer working evenings and weekends, a dozen repositories, and a team of
AI agents (a Claude lead with Claude subagents, OpenAI Codex, GitHub Copilot's
coding agent). Agents multiply output; without a lead, review gates and one
place to see the work, they multiply unverified churn instead. The GitHub
Project is that one place, so it has to be complete, current and cheap to keep
that way.

Today that is held together by private scripts in the maintainer's dotfiles
(`board_reconcile.py`, `fields_dump.py`, `board_migrate.py`, `agents-status`),
a GYST workflow that only handles issue events, and lessons that live in one
assistant's memory. This project makes all of it public, reusable, tested and
written down: a board defined as code, an Action that applies and keeps it, and
a playbook for running the agent team, with the lessons that shaped it.

## Rulings already taken (2026-10-07)

1. **Name:** Scrum Around and Find Out; slug `scrum-around-and-find-out`.
2. **Audience:** public and reusable by anyone; the maintainer's
   Renegade-Penguin suite board is the worked example.
3. **Form:** a GitHub **Action** plus a **bring-your-own GitHub App**. No hosted
   service. User-owned boards (which no GitHub App can write) may use a
   fine-grained PAT; documented for adopters, never used in the maintainer's
   repositories.
4. **Split with GYST:** this repository owns the project-management logic;
   GYST is the delivery layer and deploys it through a thin reusable workflow.
   Generic CI plumbing still goes straight into GYST (the wiki is published
   with GYST's existing `wiki.yml` / `wiki-publish.yml`).
5. **Board as code, safe apply:** create what is missing; never edit an
   existing single-select field's options through the API.

## Scope

**In (v0.1.0):** `board.yaml` schema; the Action with five modes; the `safo`
CLI; `agents-status`; the docs and wiki (why, roles, routing, handoff, limits,
board conventions, lessons, adoption); the Renegade-Penguin example; tests;
GYST wrapper; the wiki through GYST's existing wiki workflows; migration of the suite board.

**Out:** a hosted webhook App; any non-GitHub tracker; automatic agent
dispatch (the playbook says how a lead hands work out; this project does not
run agents); moving the maintainer's private memory into the repo.

## `board.yaml`

```yaml
version: 1
project:
  owner: Renegade-Penguin        # org or user login
  owner_type: organization       # organization | user
  number: 1
  title: Hammunition suite
repositories:                    # every repo whose issues and PRs belong here
  - owner: Renegade-Penguin
    name: Hammunition
    default_area: Engine
  - owner: ChiefGyk3D
    name: git-your-ship-together
    default_area: CI and GYST
fields:
  - name: Status
    type: single_select
    options:
      - {name: Backlog, color: GRAY, description: "Not scheduled"}
      - {name: Next, color: BLUE, description: "Scheduled for the current or next sprint"}
      - {name: In progress, color: YELLOW, description: ""}
      - {name: Blocked, color: RED, description: "Needs the maintainer"}
      - {name: Done, color: GREEN, description: ""}
  - name: Agent
    type: single_select
    options:
      - {name: Claude, color: ORANGE, description: "Claude lead or a Claude subagent"}
      - {name: Codex, color: GREEN, description: "OpenAI Codex"}
      - {name: Copilot, color: BLUE, description: "GitHub Copilot coding agent"}
      - {name: You, color: PURPLE, description: "The maintainer"}
  - name: Sprint
    type: iteration
    start: 2026-10-06
    duration_days: 14
    count: 12
  - {name: Start date, type: date}
  - {name: Target date, type: date}
  - {name: Done on, type: date}
views:
  - {name: Board, layout: board, filter: "-status:Done"}
  - {name: Roadmap, layout: roadmap, filter: "-status:Done"}
  - {name: Agents at work, layout: table, filter: 'status:"In progress",Next'}
rules:
  status:
    opened: Backlog
    reopened: Backlog
    closed: Done
    merged: Done
  done_date_field: Done on
ui_only:                          # cannot be set by any API; printed as a checklist
  - "Roadmap: Date fields = Start date / Target date; Zoom = Quarter"
  - "By repository: Group by = Repository"
  - "Workflows: Item closed -> Done; Pull request merged -> Done"
```

The schema lives in `src/safo/schema.py` (stdlib dataclasses plus a
hand-written validator that names the offending key). Python's standard
library has no YAML parser, so **PyYAML is the one runtime dependency**,
installed by the Action with `pip install --require-hashes` from a pinned
`requirements.txt` and loaded with `yaml.safe_load` only.

## The Action and the CLI

One package, `safo`, Python 3.11+, standard library plus hash-pinned PyYAML. GraphQL over
`urllib.request`; retries with backoff on secondary rate limits; pagination
always through `$endCursor`.

Credentials, in the Action: inputs `app-id` and `private-key` go to the pinned
`actions/create-github-app-token` step (Python's standard library cannot sign
the RS256 JWT), whose token the Python steps use; or input `token` for a
user-owned board's fine-grained PAT (documented, refused when `owner_type` is
`organization` unless `allow-token-for-org: true`). The CLI uses the caller's
`gh auth token`.

Modes (Action input `mode`, CLI subcommand):

| Mode | Trigger | Does | Exit |
|---|---|---|---|
| `bootstrap` | manual | creates missing fields, options of **new** fields, iterations, views (layout, then filter via `updateProjectV2View`); refuses to change an existing field's options and prints the UI step that does it safely | 0 applied, 1 refused items, 2 cannot tell |
| `audit` | schedule, manual | compares the live board with `board.yaml` and every listed repository's open issues and PRs; reports drift | 0 clean, 1 drift, 2 cannot tell (a question the token could not ask) |
| `sync` | `issues` events | adds the item, sets Status by `rules.status`, Area by repository, Done on when closed | 0 / non-zero on API failure |
| `reconcile` | schedule, manual | adds every missing open issue and PR across `repositories`, flips closed/merged items to Done with the date, fills missing Area; idempotent | 0, 1 when anything could not be fixed |
| `status` | manual | posts a project status update from a body file | 0 |

Learned rules the code enforces (each has a test):

- Never send `updateProjectV2Field` with `singleSelectOptions` for a field that
  already exists (it replaces options with new ids and wipes every item's value).
- `createProjectV2View` takes no filter; set it with
  `updateProjectV2View(viewId, filter)` afterwards.
- After `addProjectV2ItemById`, set fields by item **node id**; a fresh item can
  be missing from listings for a while.
- Verify adds with the project's `items.totalCount`, not with a listing.
- A personal-account repository cannot be linked to an organization project;
  `repositories` still covers it through `reconcile`.
- Pull-request events cannot reach an OIDC secret store whose identity does not
  cover the `pull_request` subject; PRs reach the board through `reconcile`.

`agents-status` (in `tools/`): one read-only view of the board's In progress
and Next items by Agent, Codex sessions and plan limits read from
`~/.codex/sessions` (`token_count.rate_limits`), and Copilot agent tasks
(`gh agent-task list`). Claude subagents cannot be listed from a shell; the
page says so.

## GYST delivery

- `project-sync.yml` in GYST becomes: Doppler OIDC fetch of the App key (as
  today) → `uses: ChiefGyk3D/scrum-around-and-find-out@<sha> # vX.Y.Z` with
  `mode: sync` on issue events and `mode: reconcile` on its weekly schedule.
  Inputs keep their names, so callers only bump their GYST pin.
- The wiki is published with GYST's existing `wiki.yml` / `wiki-publish.yml`
  (measured on GYST main 2026-10-07); no new workflow.

## Documentation (source in `docs/`, mirrored to the wiki)

`why.md`, `roles.md` (Claude lead; Sonnet default for implementation and
review; Haiku for mechanical one-file edits; Opus only with the maintainer's
OK and the reason stated; Codex for research, plans and implementation from
complete plans; Copilot for small fully specified issues and deferred minors;
the maintainer for decisions, bench and merges), `routing.md` (task shape →
agent → why → cost signal), `handoff.md` (card with Agent set; brief-in and
result-out comments; a fresh reviewer from another agent or model; CI green;
the maintainer merges), `limits.md` (how to read each tool's real usage and
when to switch agent or plan, from measured numbers), `board.md` (fields,
sprints, Done log, status updates, "the board is always current"),
`agents-status.md`, `lessons.md` (dated: what happened → evidence → the rule
now; seeded with the 2026-10-05..07 lessons above plus "Codex's plugin records
only background jobs" and the first measured Codex Plus usage), `adoption.md`
(create an App, write a `board.yaml`, call the Action directly or through
GYST, the PAT exception for user boards).

**Privacy:** examples come from the public suite board only. A test fails on
hostnames, machine identifiers, the maintainer's regions, an employer name or
a callsign pattern anywhere under `docs/`, `examples/` or `README.md`.

## Tests

- A fake GraphQL server (loopback, records every mutation) drives every mode:
  bootstrap creates only what is missing and never sends an option-replacing
  update to an existing field; audit's 0/1/2; reconcile run twice changes
  nothing the second time; pagination through `$endCursor` across three pages;
  view filter set after creation; secondary-rate-limit retry.
- Schema validation of `board.yaml` and `examples/renegade-penguin.yaml`.
- A socket guard: nothing but loopback (the GYST/hill pattern).
- The privacy test.
- One live, read-only `audit` against the real board, run on demand
  (`workflow_dispatch`), never on pull requests.

CI calls GYST (python-ci, security; release on tags), pinned by commit with the
`# vX.Y.Z` comment, gate named `CI green`.

## Migration of the suite board

1. `safo audit` against org project 1 reports zero drift from
   `examples/renegade-penguin.yaml` (the example is fixed until it does).
2. GYST release with the wrapper; the six suite callers bump their pin.
3. Two weekly reconciles checked by hand; then the dotfiles board tools retire.
4. tray and gps-tether still need their Doppler identities (Hammunition #367)
   for event-driven sync; `reconcile` covers them meanwhile.

This repository has its own board (a user-owned project, so its `sync` uses
the documented PAT exception **or** stays on `reconcile` through the
maintainer's own `gh` login; decided at plan time), created by its own
`bootstrap` as the first real use.

## Release

`v0.1.0` when `bootstrap`, `audit` and `reconcile` are proven against the real
suite board; signed tags; GYST release workflow.

## Open questions for the maintainer

1. SAFO's own board is user-owned: sync it with a fine-grained PAT (the
   exception this project documents) or keep it on scheduled `reconcile` run
   from your own login only?
2. Licence: GPL-3.0-or-later like your other tools, or MIT/Apache-2.0 so
   companies adopt the Action more readily?
