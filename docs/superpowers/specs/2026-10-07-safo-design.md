# Scrum Around and Find Out — design

**Status:** approved by the maintainer, 2026-10-07 (SAFO #1).
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
6. **This repository's own board** is user-owned: it stays on scheduled
   `reconcile` run from the maintainer's own `gh` login. No PAT in CI (SAFO #1).
7. **Licence: MIT**, matching GYST, its delivery sibling (SAFO #1).
8. **Agent routing and optimization is in v0.1.0:** routing rules as data (`agents.yaml`), measured headroom
   (`safo usage`), recommendations (`safo route`), and an outcomes log, built from the maintainer's own measured
   workload (2026-10-07).
9. **A local LLM served by Ollama is the cheapest agent** and is part of the same routing: endpoints come from
   configuration (never from the repository), a probe is read-only, and a request that would evict a model another
   service keeps resident is never sent (2026-10-07).

## Scope

**In (v0.1.0):** `board.yaml` schema; the Action with five modes; the `safo`
CLI; `agents-status`; agent routing and optimization (`agents.yaml`, `safo usage`, `safo route`,
`safo outcome`, `safo local run`, the outcomes log); the docs and wiki (why, roles, routing, usage, handoff, limits,
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
  - owner: ChiefGyk3D
    name: penguin-overlord
    default_area: Penguin Overlord
fields:
  - name: Area
    type: single_select
    options:                     # as the live board has them; audit fixes this list until it reports zero drift
      - {name: Engine, color: GRAY, description: "Hammunition's engine and catalog"}
      - {name: CI and GYST, color: GRAY, description: "Shared workflows and the baseline"}
      - {name: Penguin Overlord, color: GRAY, description: "The Discord bot"}
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

## Agent routing and optimization

Agents differ in what they are good at, what they cost and how much room is left today. Choosing between them from
feeling wastes the cheap ones and exhausts the scarce ones, so the choice becomes data (rules and limits), measurement
(what is left) and a record (what happened). Everything below is read-only and local, and none of it dispatches
anything: the lead reads the answer and sets the card.

**a) `agents.yaml`.** One file, validated like `board.yaml` (every error names the key), with:

- *Agents.* The Claude lead, Claude subagents by model (Sonnet, Haiku, Opus), Codex, Copilot, a local LLM (Ollama) and
  the maintainer. Each has its limits (Codex: a 5-hour and a weekly window; Copilot: a monthly premium-request
  allowance; Claude: the plan), its measured strengths and its constraints. The shipped values are one maintainer's
  measured workload: Codex's sandbox cannot commit inside a git worktree or open sockets, so the lead runs the full
  suite and commits; Copilot pull requests need a review gate; Codex's adversarial review is a strong second reviewer;
  Opus only with the maintainer's OK.
- *Task shapes, each with a preferred agent, a fallback chain and a required reviewer.* Research: Codex, then Sonnet.
  Plan writing: Codex or Sonnet. Integration code: Sonnet, then Codex. Well-specified code from a complete plan: Codex,
  then Sonnet. A small mechanical pull request: Copilot, then Haiku, reviewed by Sonnet. Security-sensitive design: the
  Claude lead, and Opus only with approval. Adversarial review: Codex. Plus the local shapes below.
- *Thresholds.* An agent whose measured headroom is over a line is skipped, with the agent to use instead.

`docs/routing.md` is **generated** from `agents.yaml` by `scripts/gen_routing.py`, and a test fails if the two differ.

**b) `safo usage`.** Reads local meters only: Codex's `~/.codex/sessions/**/*.jsonl` `token_count` rows
(`rate_limits.primary` the 5-hour window, `secondary` the weekly one, `plan_type`, `resets_at`, plus per-session token
totals); Claude Code's `~/.claude/projects/**/*.jsonl` message usage per model, subagent transcripts included;
Copilot sessions per month from `gh agent-task list`, and exact premium-request use only if the token can read the
billing endpoint (optional, `--billing`; `safo` never asks for a broader scope on the maintainer's behalf and reports
`unknown` otherwise). Exit 0; `--json`.

**c) `safo route <shape>`.** Applies the rules to the live headroom and prints the recommended agent, the reason and a
reviewer who is not the author (for example: Codex above 80% of its 5-hour window goes to Sonnet; Copilot above 70% of
its month goes to Haiku). Unknown headroom never blocks. It prints the value for the card's Agent field and never
dispatches anything.

**d) The outcomes log.** One JSON line per finished task: date, card URL, agent, shape, review rounds, findings by
severity, tokens or requests when known. `safo outcome add ...` appends one after validating it; `safo usage --report`
summarises the month; the lessons cite it. `examples/outcomes-2026-10.jsonl` is seeded from the maintainer's measured
day (Codex at 14% of its weekly and 56% of its 5-hour window after about 27M input tokens across research, a
3,400-line plan, a review and one implementation task; Copilot's 40 October sessions, 4 of 4 pull requests needing
fixes, one a functional bug its own test hid; the Codex-authored plan's preflight scan finding 21 conflicts and 19
defects; Codex's adversarial review of GYST #114 finding 3 real issues; Task 1 by Codex passing review after one fix
round), written generically.

**e) Privacy.** Usage reading is local and read-only. It sends nothing about the maintainer's sessions anywhere; its only
network requests are `gh`'s own calls made with the maintainer's login (`gh agent-task list`, and the optional billing
read) and read-only probes of the maintainer's own endpoints. The docs say so, and a test fails if the meter code
mentions the real home directory or opens a socket of its own.

**f) The local LLM.** An `ollama` agent has one or more endpoints from configuration: base URL, roles (`general`,
`embedding`), the only models `safo` may ask for, a `num_ctx` cap, a `think` default and `protected_models` that must
never be evicted. The public example uses a placeholder host (`http://ollama.lan:11434` and `:11435`); the real
endpoints live in a local, git-ignored file (`~/.config/safo/agents.local.yaml`) merged over the example. No real
address, hostname or remote-access name is ever written into the repository, and the privacy test fails on private
and carrier-grade addresses.

Measured facts encoded in the example. Instance A (a 16 GB GPU) keeps a 12B thinking model and a safety model resident at
`num_ctx` 8192 for other services; requesting any other model there *evicts* a resident one, so its rule allows only the
already-resident general model at `num_ctx` 8192 or less, and it is marked shared with production. Instance B (an 8 GB
GPU) is free for small models (3 to 7B) and embeddings. The resident 12B model generated about 50 tokens a second, and
a one-sentence answer cost about 436 evaluated tokens because it thinks by default, so cheap tasks send `think: false`.

Availability comes and goes (the LAN at home, a zero-trust remote-access client when away). `safo usage` probes each
endpoint read-only (`GET /api/tags`, `GET /api/ps`, 3-second timeout; never `/api/generate`, never loading a model) and
reports reachable, loaded models, or unreachable. `safo route` uses the local agent only when it is reachable, falls
back otherwise, and never routes to a protected-model endpoint anything that would load a different model.

Local shapes (cost zero, always reviewed by a Claude model before anything lands; never a security decision, never
code that ships without review): CI-log and test-output summaries, issue triage and labelling, first drafts of
changelog fragments and commit messages, documentation proofreading, and embedding-based duplicate-issue search on the
free endpoint. `safo local run --shape <shape> --prompt-file F` sends one prompt to the endpoint routing picks (Ollama's
native API, the `think` flag honoured, a timeout), prints the answer and appends an outcomes line.

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
- A socket guard: nothing but loopback (the GYST/hill pattern). Routing tests build synthetic Codex and Claude session
  files under a temporary `$HOME` (never the real one), use a fake Ollama server on loopback, and cover an endpoint that
  flips to unreachable mid-task and a request that would evict a protected model.
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
5. Penguin Overlord (amendment below) is added to `repositories` and gets its
   Area; its GYST caller goes green once its own settings exist.

This repository has its own board (a user-owned project), created by its own
`bootstrap` as the first real use and kept current by scheduled `reconcile`
from the maintainer's own `gh` login (ruling 6).

## Release

`v0.1.0` when `bootstrap`, `audit` and `reconcile` are proven against the real
suite board; signed tags; GYST release workflow.

## Amendment 2026-10-07: Penguin Overlord joins the board (proposed)

The maintainer said the same day that Penguin Overlord had not been added to
GYST or to SAFO. GYST it has called since 2026-09-21 (five callers, in the
baseline); a board it has never been on. The ruling this amendment asks for:
**the Discord bot's issues and pull requests belong on the suite board**, the
one place the "Why" section wants, rather than on a board of their own.

What follows from the rulings already taken:

- `ChiefGyk3D/penguin-overlord` is a personal-account repository, as GYST is.
  It cannot be linked to the organization project (learned rule 5), so it
  reaches the board the way GYST does: `reconcile` across `repositories`, and
  an event-driven GYST `project-sync.yml` caller of its own until this
  project's Action replaces it. That caller is written (penguin-overlord, the
  pull request of 2026-10-07, with the plan
  `docs/superpowers/plans/2026-10-07-board-and-gyst-onboarding.md`).
- The `Area` option `Penguin Overlord` is a UI step. `bootstrap` creates
  options for **new** fields only (ruling 5), and the sync script refuses an
  option it cannot find before changing anything.
- The `Area` field was absent from the `board.yaml` example although
  `default_area`, `sync` and `reconcile` all refer to it; the example now
  carries it. Its options are written as the example names them and are
  corrected, like the rest of the example, until `audit` reports zero drift
  (migration step 1).
- The App must be installed on the `ChiefGyk3D` account with access to the
  repository, and the `gha-projects` identity needs that repository's
  subjects. Both are settings, not code; the plan lists them in order.
- The first reconcile adds every open issue, and on 2026-10-07 thirty-one of
  that repository's thirty-six were CodeQL findings filed by the security
  scan. A triage pass before the first reconcile is in the same plan. The
  general rule it suggests for `lessons.md`: a scanner that files issues
  fills a board; close or fix its findings before a repository joins one.

## Open questions for the maintainer

One: the amendment above, that Penguin Overlord joins the suite board
rather than getting a board of its own. The two original questions were
answered in SAFO #1 (rulings 6 and 7).
