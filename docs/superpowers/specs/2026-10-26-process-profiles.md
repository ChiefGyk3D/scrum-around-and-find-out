# Process methods: Agile and Waterfall on one board-as-code core, and a tracker seam for Jira: design

**Status:** draft, revision 3, for the maintainer's review, 2026-10-26. Revision 2 applied the independent adversarial
review of revision 1 (5 blocking and 14 important or minor findings); revision 3 applies the re-review of revision 2 and
records four decisions the maintainer made on 2026-10-26 (M7, M8, M12, M13: section 9). Nothing in it is built.
**Scope:** SAFO #108 (the issue title says "process profiles" and stays). The maintainer's ruling, 2026-10-26: "allow
flexibility for both Agile and Waterfall work, and eventually look at working with Jira too." The shape-only Jira key
acceptance, documented in `docs/no-hidden-work.md:29` and tracked on #108, is folded into sections 7 and 8.
**Term.** This document says *method* (the `agile` and `waterfall` methods), not *profile*, because SAFO already has
agent profiles (VERIFIED `docs/profiles.md`, `src/safo/profile.py`, `src/safo/modes/profiles.py`, `safo profiles
verify|brief`). The file name of this spec keeps the issue's word. The rename is decision M6, and it is cheap to reverse
because nothing is built.
**No code in this document.** It names files, keys, rules, messages and tests. Section 11 is the build plan; nothing in it
is started by this document, and every build issue links back to #108.

Every claim about today's code is marked **VERIFIED** (the file was read, with its line numbers on `origin/main` at
a5863e6, 2026-10-26; `src/` is unchanged since 6796e9f, so the earlier citations hold except where this revision corrects
them) or **INFERRED** (reasoned, not read or not run). A claim about GitHub's API is VERIFIED only when it came from a
read-only schema introspection or REST read made for this revision (2026-10-26 13:10 EDT), and says so; a statement from
the review that I could not re-run is marked INFERRED and listed in section 6.2.

## Why

SAFO's rule is a constant: no hidden work. Everything else is a choice that happens to be agile-shaped today: the status
names, the sprint field, the "Next" column, the end-of-sprint status update. A waterfall program (phases, gates, a frozen
scope baseline with change control) can already describe most of its board in `board.yaml`, but it cannot say "nobody
starts Build work while the Design gate is open", and nothing reads such a rule. This design adds that, keeps every
valid existing board's behavior and output unchanged (2.4 states the one exception honestly), and fixes the seam a Jira
tracker would later plug into.

## Rulings carried over

- `board.yaml` is the single source of a board's shape (v0.1.0 design, `2026-10-07-safo-design.md`). A method is a key
  in it, not a second file.
- Exit codes stay 0 clean, 1 drift, 2 cannot tell, and "cannot tell" outranks drift (VERIFIED `modes/audit.py:26-33`,
  `errors.py:8-10`).
- Code groups and counts; a model never does (VERIFIED `statusgroups.py:1-7`). Nothing here gives a model a new job.
- A check that is not configured says so and never reads as a pass (VERIFIED `coverage.py:60-73`).
- The threat model comes before the build (#71). Section 8 is that model for this design.

## 1. The problem, measured against the code

### 1.1 What is already method-neutral

| Part | Evidence | Why it is neutral |
|---|---|---|
| Status decisions | VERIFIED `rules.py:18-56` | Every status is a name read from `rules.status`; no status name is written in the code |
| The reconcile plan | VERIFIED `plan.py:84-135` | Adds, flips, fills by the same names; "Done" means `rules.status.closed`/`merged` |
| Status and field names | VERIFIED `schema.py:121-130`, `schema.py:416-460` | `status_field`, `area_field`, `done_date_field` and every status are configurable |
| Statuses and options | VERIFIED `schema.py:351-392` | Any single-select field, any options; iteration, date, text, number fields |
| Tracking fields | VERIFIED `schema.py:97-106`, `coverage.py:53-57` | Kind, Epic and Effort are names; any type; empty turns a check off |
| The no-hidden-work audit | VERIFIED `modes/audit.py:99-112`, `coverage.py:152-207` | Linked issue, card presence, field presence: none of it knows about sprints |
| The dispatch guard | VERIFIED `hooks.py:381-388`, `tracking.py:183-213` | Reads a brief's `issue:` line and an issue's open state only |
| Routing | INFERRED from `docs/routing.md` and the absence of any board read in `routing.py` | Picks an agent by task shape; never reads the board |
| `agents-status` | VERIFIED `modes/agents_status.py:43-59` | Groups by `agents.working` and `agents.waiting`, both from `board.yaml` |

### 1.2 What is agile-shaped

| Part | Evidence | The shape |
|---|---|---|
| Default statuses | VERIFIED `schema.py:87-94` | `opened` and `reopened` default to `Backlog`, `closed`/`merged` to `Done` |
| Default working set | VERIFIED `schema.py:133-137` | `agents.working` defaults to `In progress`, `Next`; `waiting` to `Blocked` |
| Default tracking fields | VERIFIED `schema.py:103-105` | `Kind`, `Epic`, `Effort` (Epic and Effort are Scrum words; the checks are not) |
| Status-update groups | VERIFIED `statusgroups.py:60-70` (grouping: "In progress" is the first of `agents.working`, every other working status is "Next"), `statusgroups.py:134-141` (the headings) | The names of the groups |
| Headline prompt | VERIFIED `headline.py:35` | The local-model prompt says "Next" |
| Maintainer agent value | VERIFIED `modes/status.py:329` | `--human-agent` defaults to `You` |
| Board-less Action mode | VERIFIED `compat.py:58-69` (inside `board_from_env`, `compat.py:47-80`) | Defaults `Backlog`, `In progress`, `Done` |
| This project's example | VERIFIED `examples/safo.yaml:30`, `:55`, `:75` | "Next: scheduled for the current or next sprint", a 14-day `Sprint` iteration, `working: [In progress, Next]` |
| The docs | VERIFIED `docs/board.md:13` ("the sprint is the unit of Next"), `docs/board.md:30-33`, `docs/no-hidden-work.md:5` ("That is the point of Agile") | The words, not the mechanism |

### 1.3 What is missing for waterfall

- No phase concept and no gate: nothing reads an ordering of phases or an approval (VERIFIED: no such key in the
  top-level key set at `schema.py:299-304`, and unknown keys are refused at `schema.py:253-257`).
- No scope baseline and no change record.
- No dependency read. GitHub's live schema has native issue dependencies: `Issue.blockedBy` and `Issue.blocking`
  (`IssueConnection`, with `first`/`after`/`orderBy`), the mutations `addBlockedBy`/`removeBlockedBy`, and the timeline
  events `BLOCKED_BY_ADDED_EVENT`, `BLOCKED_BY_REMOVED_EVENT`, `BLOCKING_ADDED_EVENT`, `BLOCKING_REMOVED_EVENT` (VERIFIED
  by schema introspection, 2026-10-26 13:10 EDT). The project field types are `ASSIGNEES, LINKED_PULL_REQUESTS,
  REVIEWERS, LABELS, MILESTONE, REPOSITORY, TITLE, TEXT, SINGLE_SELECT, MULTI_SELECT, NUMBER, DATE, ITERATION, TRACKS,
  TRACKED_BY, ISSUE_TYPE, PARENT_ISSUE, SUB_ISSUES_PROGRESS, CREATED, UPDATED, CLOSED` (VERIFIED, introspection of
  2026-10-26 12:37 EDT): there is no blocked-by **project field**, so a dependency is read from issues, not the board.
  That `blockedBy` can point across repositories and owners, and that creating one needs at least triage on the
  repository being edited, is VERIFIED by the independent re-review (read-only, 2026-10-26; not repeated by me, section
  6.2). The schema is consistent with it (a blocked-by event carries a `blockingIssue`, which has a `repository`).
- A Roadmap view's date fields, zoom and grouping cannot be set by any API (VERIFIED `docs/lessons.md:46-50`); SAFO
  lists them under `ui_only` (VERIFIED `modes/audit.py:149-152`).
- The live field reader keeps types it does not map as GitHub's raw data type (VERIFIED `live.py:63-69`, `live.py:206-207`),
  and `board.yaml` can declare only `single_select, iteration, date, text, number` (VERIFIED `schema.py:26`). A built-in
  Milestone column is therefore a UI choice, not something `board.yaml` can declare.

### 1.4 The Jira seam today

- A reference is `owner/repo#N` or a Jira-style `KEY-N` (VERIFIED `tracking.py:25-26`, `tracking.py:50-59`).
- The resolver returns `open` for any non-GitHub reference without a lookup (VERIFIED `tracking.py:141-143`), so a
  Jira-style key is accepted by shape alone. This is documented (`docs/no-hidden-work.md:29`) and is fixed first, by
  unit U1. The operator's repository list applies to GitHub references only (VERIFIED `tracking.py:201-203`).
- The Jira field mapping is documented and tracker-neutral (VERIFIED `docs/no-hidden-work.md:93-111`). Nothing calls Jira.

## 2. The process method

### 2.1 What a method is

A **process method** is a named set of rules that code applies on top of the fields `board.yaml` already declares. It
does not create fields, rename statuses or inject defaults. The status set stays in `fields`, the event mapping in
`rules.status`, the working set in `agents`, exactly as today. A method decides four things:

| A method sets | `agile` | `waterfall` |
|---|---|---|
| Planning unit | iteration (any iteration field, optional, never required: today's behavior) | phase (`process.phase_field`, required) |
| Extra audit rules | none | phase presence, gate order, scope baseline, baseline phase pinning, archived-card check |
| Optional neutral rules | dependency check (off by default) | dependency check (off by default) |
| Status-update shape | today's four groups | today's four groups plus a "Phases and gates" section |

**Why not a method that also sets the status set and transitions.** Two reasons. Board-as-code means the file says
everything; a status set hidden behind a method name is a second source a reviewer cannot see in the diff. And
transitions cannot be enforced: the project exposes a card's current field values, and the only field-change history
GitHub offers for a project card is for the **Status** field (VERIFIED, introspection 2026-10-26 13:10 EDT: the issue
and pull request timelines have `PROJECT_V2_ITEM_STATUS_CHANGED_EVENT` with `actor`, `createdAt`, `previousStatus`,
`status`, `project`, `wasAutomated`, plus `ADDED_TO_PROJECT_V2_EVENT` and `REMOVED_FROM_PROJECT_V2_EVENT`; there is no
event for a change of any other project field, so no Phase-change event exists). SAFO reads none of that history today
(VERIFIED: no history query in `items.py` or `live.py`). `ISSUE_FIELD_CHANGED_EVENT` also exists, but it belongs to
organization issue fields, a different feature from project fields (INFERRED; not explored). A transition table SAFO
cannot check for Phase is doctrine dressed as code. What audit can check is a **state invariant** (a card in this phase
and this status while that gate is open), and that is what the waterfall rules are. The example files (section 10)
carry each method's status set.

A "none" planning unit (Kanban flow) needs no method: it is `agile` with no iteration field, which works today.

### 2.2 Declaring it in `board.yaml`

A new optional top-level key, `process`. `version` stays `1`: the key is additive. An older `safo` reading a file that
has it refuses it as an unknown key (VERIFIED `schema.py:253-257`), which fails closed: an old binary can never audit a
waterfall board and call it clean while ignoring its gates.

Agile, stated explicitly (identical in effect to leaving `process` out, including the output: 2.4):

```yaml
process:
  method: agile
```

Waterfall, complete:

```yaml
rules:
  add_closed_days: 30           # required to be >= 1 on a waterfall board (2.5): the gate rule reads recent closes

process:
  method: waterfall             # agile (default) | waterfall
  active_statuses: [In progress, In review]   # required on a waterfall board; no default (3.2)
  dependencies: none            # none (default) | blocked_by; not `off`, which YAML reads as false
  phase_field: Phase            # a single_select in fields; its option order is the phase order (3.2, 3.5)
  approvers:                    # required, at least one: people whose manual close of a gate or change issue counts
    - {login: maintainer-login, id: 1234567}   # id is the user's immutable databaseId; the login alone is never enough
  gates:                        # the exit gate of a phase: work in a later phase waits for it
    - {phase: Requirements, issue: acme/gates#1}
    - {phase: Design, issue: acme/gates#2}
    - {phase: Build, issue: acme/gates#3}
    - {phase: Verify, issue: acme/gates#4}   # Release is the last phase: a gate there would gate nothing (refused)
  baseline:
    frozen: 2026-11-02          # the day scope was frozen
    approved_in: acme/gates#5 # a freeze issue of its own (not a gate), closed on or before `frozen`
    intake: [Backlog]           # statuses that are not "in scope" yet; default [rules.status.opened]
    items:
      - {ref: acme/app#12, phase: Design}
      - {ref: acme/app#13, phase: Build}
    changes:
      - {add: acme/app#55, phase: Build, approved_in: acme/gates#21}
      - {remove: acme/app#13, approved_in: acme/gates#22}
```

Per repository, for mixed mode (section 5):

```yaml
repositories:
  - {owner: acme, name: gates, default_area: Gates}   # the dedicated gates repository (M7)
  - {owner: acme, name: app, default_area: App}
  - {owner: acme, name: mobile, default_area: Mobile, method: agile}   # an agile team inside the program
```

### 2.3 Keys and defaults

| Key | Default | Kind | Meaning |
|---|---|---|---|
| `process` | absent = `{method: agile}` | mapping | |
| `process.method` | `agile` | neutral | `agile` or `waterfall`: the default for every repository |
| `process.active_statuses` | none (required when waterfall) | waterfall | Statuses that mean "being worked"; the gate and dependency rules read them. No default, because the agile default (the first of `agents.working`, VERIFIED `statusgroups.py:70`) leaves "In review" or "Next" invisible to the gate rule |
| `process.dependencies` | `none` | neutral | `blocked_by` turns on the dependency rule (3.2) |
| `process.phase_field` | none | waterfall | Required when any repository is waterfall |
| `process.approvers` | none (required when waterfall) | waterfall | `{login, id}` entries; at least one. An empty list is refused: an unconfigured approver check would mean "any person", which is a weakening, not a default |
| `process.gates` | `[]` | waterfall | Empty: the gate check is not configured, and audit says so |
| `process.baseline` | absent | waterfall | Absent: the scope check is not configured, and audit says so |
| `repositories[i].method` | `process.method` | | `agile` or `waterfall` for that repository's cards |

"Waterfall keys" are accepted only when `process.method` or some `repositories[i].method` is `waterfall`.

### 2.4 Compatibility of existing boards, stated exactly

What is unchanged for every **valid** board without a waterfall repository, with or without an explicit
`process: {method: agile}`:

- the parsed `Board` carries a default `Process()`; every code path that reads it does nothing for an all-agile board;
- no new query: the waterfall reads (the phase field on cards, archived cards, `closingIssuesReferences` with ids,
  `stateReason`, gate and approval issues, `blockedBy`) are all gated on a waterfall repository or `dependencies:
  blocked_by`. In particular the shared pull request query `Q_PULL_LINKS` (VERIFIED `coverage.py:25-35`, used for every
  board) is **not edited**: G3 uses a separate query that only a waterfall board runs;
- no new output line: the `PROCESS` header line (U5c) prints only for a non-agile method, so an explicit `process:
  {method: agile}` prints exactly what an absent block prints;
- the board-less Action mode (VERIFIED `compat.py:47-80`) builds a `Board` with the default and takes no method input in
  the first cut.

What changes, honestly: adding `process` to the top-level allowed set and `method` to the repository allowed set changes
the **text** of the existing `unknown key (allowed: ...)` error (VERIFIED `schema.py:249-257`: the allowed keys are
listed in the message) for an **invalid** board that has a typo at the top level or in a repository. A valid board is
unaffected. The release notes say so, and the tests that assert the old text (none found in `tests/` by grep for
`allowed:` on 2026-10-26; INFERRED complete) are updated in U2.

The test that proves "unchanged" is a golden one, and **the golden files do not exist**: VERIFIED `tests/golden` holds
only `harness`. So the plan has a step **before U2** that captures, on `main` and before any change, the outputs of
`audit`, `reconcile --dry-run`, `status --post --print` and `agents-status` against the fake GitHub (`tests/fakegh`) for
`examples/safo.yaml` and `examples/renegade-penguin.yaml`, and commits them (unit U0). U2 and every later unit then
asserts byte equality against U0's files, and also against the same inputs with `process: {method: agile}` added.

### 2.5 Validation

Every error is a `ConfigError` (exit 2, VERIFIED `errors.py:19-20`) whose message starts with `<file>: <key path>:`, like
every existing one (VERIFIED `schema.py:245-246`). The messages, exactly:

| Input | Message |
|---|---|
| `method: kanban` | `board.yaml: process.method: 'kanban' is not one of agile, waterfall` |
| `repositories[2].method: hybrid` | `board.yaml: repositories[2].method: 'hybrid' is not one of agile, waterfall` |
| waterfall with no `phase_field` | `board.yaml: process.phase_field: required when a repository is waterfall` |
| `phase_field` names no field | `board.yaml: process.phase_field: names field 'Phase', which is not in fields` |
| `phase_field` is a text field | `board.yaml: process.phase_field: field 'Phase' is text, not single_select` |
| waterfall key on an all-agile board | `board.yaml: process.gates: only used when the method or a repository is waterfall` |
| waterfall with no `active_statuses` | `board.yaml: process.active_statuses: required when a repository is waterfall` |
| a status not in the status field | `board.yaml: process.active_statuses[0]: 'Doing' is not an option of 'Status'` |
| a done status as active | `board.yaml: process.active_statuses[1]: 'Done' is a done status (rules.status.closed or merged)` |
| `rules.add_closed_days` below 1 on a waterfall board | `board.yaml: rules.add_closed_days: must be at least 1 when a repository is waterfall (the gate rule reads recently closed cards)` |
| `dependencies: off` | `board.yaml: process.dependencies: False is not one of none, blocked_by` (`off` loads as a boolean, as `docs/board-yaml.md:9-10` warns) |
| no approvers | `board.yaml: process.approvers: required (at least one) when the method or a repository is waterfall` |
| an approver that is not `{login, id}` | `board.yaml: process.approvers[0]: expected {login, id}` |
| bad login | `board.yaml: process.approvers[0].login: 'two words' is not a GitHub login` |
| bad id | `board.yaml: process.approvers[0].id: expected a positive integer (the user's databaseId)` |
| unknown phase | `board.yaml: process.gates[1].phase: 'Buld' is not an option of 'Phase' (options: Requirements, Design, Build, Verify, Release)` |
| two gates for a phase | `board.yaml: process.gates[2].phase: phase 'Design' has a gate already (gates[1])` |
| a gate on the last phase | `board.yaml: process.gates[3].phase: 'Release' is the last phase, so its gate would gate nothing` |
| bad reference | `board.yaml: process.gates[0].issue: expected owner/repo#N` |
| any reference outside the board's repositories | `board.yaml: <path>: acme/elsewhere is not in repositories` (applies to **every** reference in `process`: gate `issue`, `baseline.approved_in`, `baseline.items[i].ref`, `baseline.changes[i].add`, `.remove` and `.approved_in`) |
| a reference listed twice | `board.yaml: process.baseline.items[4].ref: acme/app#12 is listed twice` |
| an approval issue cited twice | `board.yaml: process.baseline.changes[1].approved_in: acme/gates#21 is cited already (process.baseline.changes[0].approved_in)` |
| an approval issue that is a gate | `board.yaml: process.baseline.changes[0].approved_in: acme/gates#2 is a gate issue (process.gates[1].issue)` |
| a freeze issue that is a gate | `board.yaml: process.baseline.approved_in: acme/gates#1 is a gate issue (process.gates[0].issue)` |
| a change with both or neither | `board.yaml: process.baseline.changes[0]: expected exactly one of add, remove` |
| an add with no phase | `board.yaml: process.baseline.changes[0].phase: required with add` |
| intake names a done status | `board.yaml: process.baseline.intake[0]: 'Done' is a done status` |
| a cap exceeded | `board.yaml: process.baseline.items: at most 5000 entries` |

References use the guard's own pattern (VERIFIED `tracking.py:25`) with `fullmatch`. **Why every reference is checked
against `repositories`:** the audit reads these references with an installation token, and its log may be public. A
hostile `board.yaml` that could name any `owner/repo#N` would turn the audit into an existence oracle for private
issues (a line "cannot be read" versus "is closed" tells the two apart). Checking at load time, offline, before any
request, closes that for every reference at once; the check for gates alone was not enough. Caps, so a hostile file
cannot turn one audit into thousands of API calls: 16 phases (options of the phase field), 32 gates, 32 approvers, 16
active statuses, 5,000 baseline items, 500 changes. The existing loader limits (1 MiB, depth 64, no aliases, anchors,
merge keys or duplicate keys; VERIFIED `schema.py:156-235`) cover the block unchanged.

## 3. The two methods

### 3.1 Agile (today, unchanged)

Exactly the current behavior. Planning unit: an iteration field if the board declares one (`Sprint` in
`examples/safo.yaml`), which `bootstrap` creates and `audit` compares (VERIFIED `modes/audit.py:71-78`); nothing requires
a card to hold one. The optional dependency rule (3.2) is the only addition an agile board can opt into.

### 3.2 Waterfall

**Planning unit: the phase.** `process.phase_field` names a single-select field; its options, in `board.yaml` order, are
the phases in order. The order comes from the file, not the live project: the live order can differ and audit already
reports that as a note (VERIFIED `modes/audit.py:61-62`). Consequences, stated because the review found them: the schema
never edits existing options (VERIFIED `modes/audit.py:56`, `modes/bootstrap.py:4-5`), so no SAFO procedure moves live
options; and a card whose live Phase is not in the file's options cannot be ordered (see "Unknown phase" below and
3.5).

**Gates: an issue, listed in `board.yaml`.** The three candidates:

| | Gate issue (chosen) | Field on cards | Milestone |
|---|---|---|---|
| Visible as work | Yes: it is a card, covered by no hidden work | No | Partly (not a card) |
| Who approved | Readable: the newest `ClosedEvent`, with `actor`, `closer`, `stateReason` and `duplicateOf` (VERIFIED, introspection 2026-10-26 13:10 EDT: `ClosedEvent` has `actor, closable, closer, createdAt, duplicateOf, id, intent, resourcePath, stateReason, url`; `Closer` is `Commit`, `ProjectV2` or `PullRequest`; `Actor` is `Bot`, `EnterpriseUserAccount`, `Mannequin`, `Organization` or `User`; `IssueStateReason` is `REOPENED, NOT_PLANNED, COMPLETED, DUPLICATE`; `Issue.timelineItems` takes `itemTypes` with `CLOSED_EVENT` and `last`; `User` has `databaseId` and `id`; `Issue` has `lastEditedAt` and `createdAt`) | Not readable: a field value has no author SAFO can read (no Phase-change event exists, 2.1) | Not readable: `Milestone` has `creator` but no closer (VERIFIED: its field list) |
| Spans repositories | Yes: one issue gates the program | Yes | No: a milestone belongs to one repository, so a program needs one per repository kept in step |
| Created by API | Yes | Yes | VERIFIED no GraphQL mutation has "Milestone" in its name (introspection of the mutation list, 2026-10-26 13:10 EDT); REST only (INFERRED) |
| Discussion and evidence | The issue thread | None | The description |
| Re-gating | Reopen it | Edit the field | Reopen it |

The gate issue wins because it is the only one that records **who** approved, in a form audit can read, and because it
obeys the rule this project exists for: the gate is itself visible work. A milestone stays useful as a **date carrier**
for the schedule (3.4), never as the gate. Gates are listed in `board.yaml`, not discovered by a label: a label anyone
with triage rights can add or remove would let a fake gate in or a real gate out, while the list changes only through a
reviewed change to the file (section 8, R2).

**Where gates live and who may close them (decided by the maintainer, M7, 2026-10-26).** Gate, freeze and change issues
live in a **dedicated repository** (`acme/gates` in the examples), which is listed in `repositories` so every reference to
it passes the load check. Agents run on a fine-grained token that has no `issues:write` on that repository; **only the
maintainer closes** gate, freeze and change issues, and the maintainer files them. A manual experiment on a scratch
repository (unit U-exp) confirms what that token can and cannot do before any real board relies on it; that experiment
and the protection read-back (unit U-prereq) are hard prerequisites for adopting waterfall.

**The approval test.** One test, used for a gate, a change issue and the freeze issue. An issue `I` is **approved**
only when every line holds; it is **open** (for the gate rule, "not passed") when it is readable and a line fails; it is
**UNKNOWN** when it cannot be read or a required piece is missing.

1. `I` is an issue (not a pull request), it is CLOSED, and its canonical repository is the one named.
2. The newest close event exists. It is read as `timelineItems(itemTypes: CLOSED_EVENT, last: 1)` (the default page is
   the **oldest** first, which would read a stale close after a reopen), selecting `createdAt`, `stateReason`,
   `closer { __typename }`, `duplicateOf { id }` and `actor { __typename login ... on User { databaseId } }`. A CLOSED
   issue with no such event is UNKNOWN.
3. `stateReason` is `COMPLETED` and `duplicateOf` is null.
4. **`closer` is null: a manual close.** A close caused by merging a pull request whose body says `Closes
   owner/repo#N`, by a commit, or by a project workflow has `closer` set (`PullRequest`, `Commit`, `ProjectV2`), and its
   `actor` is whoever merged or moved the card, who may be an approver without having approved anything. Such a close
   never counts. VERIFIED on public issues, read-only, 2026-10-26: `cli/cli#14708`, closed by hand as not planned, has
   `closer` null; `cli/cli#14749` and `cli/cli#14718`, closed by merged pull requests, have `closer` `PullRequest`, with
   the merger as `actor` (a `User`) and `COMPLETED` (section 6.2). That a project workflow close has `closer`
   `ProjectV2` stays INFERRED (the union has the member; no such close was found to read). The U3 fixtures pin all
   three.
4b. **No App in the REST event (the cross-check).** GraphQL shows a GitHub App acting for a user as that `User` (no app
   field on `ClosedEvent`), but the REST issue events carry `performed_via_github_app` (VERIFIED: the key is present on
   every event of `cli/cli#14749`, 2026-10-26; whether it is non-null for a user-to-server close is the reviewer's
   finding, INFERRED). So for each approving close audit also reads the REST `closed` event of that issue and treats
   `performed_via_github_app != null` as not manual: the close does not count, with the line `DRIFT   GATE ... was closed
   through a GitHub App; it counts as open`. This is M2 option 1b; it costs one REST read per approval issue and runs
   inside the same read-only token. The REST read is bound to the repository and issue number it was read from and
   must be complete (the last page reached, every page parsed); evidence for another issue, or an incomplete read, is
   UNKNOWN. Provenance is the caller's duty at the REST-transport boundary (a later unit), not a property of the reader's
   types: an in-process caller can always build the evidence object, so the reader makes no claim to resist one.
5. The actor's type is `User` **and** its `databaseId` equals the `id` of an entry in `process.approvers`. The login is
   shown but is not the identity: a login can be renamed or, once released, taken by another person. A matching id with
   a different login counts and prints `NOTE   GATE ... closed by @new-login, who is approver @old-login (renamed)`; a
   matching login with a different id is **not** an approver.
6. `I.lastEditedAt` is null or **strictly before** the close event's `createdAt` (an edit in the same second as the
   close cannot be ordered, so it does not pass; a rename or reopen at or after the close is refused the same way). A
   gate edited after its approval no longer says what was approved, so it counts as open with the line below; re-approving means reopening and closing it again.
7. For a change issue only: `I.createdAt` is on or after the start (UTC) of `baseline.frozen`, and `I` is not a gate. For
   the freeze issue: the close is on or before the end of the `frozen` day (UTC).
8. **The approval is bound to its entry, on one structured line (M13).** For a change issue the **body** must hold
   exactly one line `Entry: owner/repo#N` (the entry's `add` or `remove` reference, such as `acme/app#55`), nothing else
   on the line, in ASCII. The repository is compared after the ASCII-only fold; the number as an integer. The title is
   never used. The body grammar is intentionally narrow, because the human approver sees plain text and the reader must see
   exactly that; it does not model Markdown, it fails closed. The entry line starts at column 0 and stands alone as a
   paragraph (the start of the body or a blank line before it, the end of the body or a blank line after it; a blank
   line is only spaces and tabs). Any of the following anywhere in the body makes the answer UNKNOWN, with a fixed
   line that names the class and never the content:
   - characters other than printable ASCII, tab, and `\n` or `\r\n` line ends (no no-break space, bidi mark,
     zero-width character, NEL, line or paragraph separator, vertical tab, form feed, other control character or lone
     carriage return);
   - raw HTML: any `<` that begins a tag, comment, declaration, processing instruction or autolink, even in code;
   - Markdown structure: a fence (three backticks or tildes anywhere in a line), a thematic break, a heading, a list
     or quote marker, a table (`|`), indented code (four spaces or a tab), a trailing backslash, or any square bracket
     (links, images and reference definitions all need one).
   - any character outside an allow-list: ASCII letters, digits, space, tab and the marks `. , : ; ! ? ' " ( ) # / @ + - =`
     (so no `* _ ` ~ & $ { } ^ %`, which can make a line render as an entry line it does not read as; for example
     `**Entry:**` or `&#69;ntry:`). Only the entry line itself may hold `_` (a repository name may);
   - no other line may contain `Entry` followed by optional whitespace and `:`, in any case. Two entry lines (even
     equal) or any other text on the entry line mean the approval is not for this change.
   Without a matching line, one approval of "something" could be cited for any entry. No issue text becomes scope or
   reaches output (the line names the entry only). Failing it:
   `DRIFT   SCOPE the change adding acme/app#55 cites acme/gates#21, which does not mention acme/app#55 on its own Entry: line; the approval is not for this change`
   Line 6 also refuses a rename or reopen at or after the close, and an edit in the same second as the close (`>=`:
   timestamps have one-second resolution). Timestamps that cannot be true (the issue created after its close, or an
   edit, rename or reopen before it was created) are UNKNOWN. (Decision M13; history in the note under the decisions
   table.)

Every actor case has a verdict and a test (U3):

| Actor of the newest close | Verdict | Line |
|---|---|---|
| `User` in `approvers` (id matches) | approved | none |
| `User` with a matching login but another id | open | `DRIFT   GATE ... was closed by @name, whose id is not the approver's id for that login; it counts as open` |
| `User` not in `approvers` | open | `DRIFT   GATE ... was closed by octocat, who is not in process.approvers; it counts as open` |
| `Bot` | open | `DRIFT   GATE ... was closed by a bot (name[bot]); an approval is a person's; it counts as open` |
| `Mannequin` (an imported placeholder identity) | open | `DRIFT   GATE ... was closed by an imported placeholder account; it counts as open` |
| `Organization` | open | `DRIFT   GATE ... was closed by an organization account; it counts as open` |
| `EnterpriseUserAccount` | open in the first cut (its id is not compared with a `User`'s; INFERRED) | `DRIFT   GATE ... was closed by an enterprise-managed account, which process.approvers cannot name yet; it counts as open` |
| null (a deleted account) | open | `DRIFT   GATE ... was closed by an account that no longer exists; it counts as open` |

A gate is **passed** when its issue is approved. It is **open** otherwise: open, reopened, closed as not planned or
duplicate, closed with a `closer`, closed by anyone but an approver, or edited after approval.

**The gate rule, exactly.** Phases `P1 .. Pn` in order; `G(k)` the gate of `Pk`, if one is listed. A card's **phase** is
defined in G3 below (its own Phase, or the latest of that and its linked issues'). For each card `c` on the board
(archived cards included, see "Archived cards" below) whose phase is `Pj`, and for every `k < j` with `G(k)` listed and not passed:

- **G1 (active ahead of a gate).** If `c`'s status is in `active_statuses` and `c` is not closed:
  `DRIFT   GATE acme/app#41 is In progress in phase Build while the Design gate acme/gates#2 is open`
- **G2 (finished ahead of a gate).** If `c` is an issue closed as completed, or a merged pull request, and its close
  day is on or after `today - rules.add_closed_days` (the window audit already reads, VERIFIED `coverage.py:157-161`),
  and either `G(k)` is not passed or `c` closed before `G(k)`'s **newest** approving close:
  `DRIFT   GATE acme/app#38 was done on 2026-11-02 in phase Build before the Design gate acme/gates#2 passed on 2026-11-05`
  (when the gate is still open: `... in phase Build while the Design gate acme/gates#2 is open`)

Definitions the review required:

- **`add_closed_days` of 0.** Today the default is 0, which means reconcile adds no closed or merged item and the
  pull request check looks at open pull requests only (VERIFIED `schema.py:127`, `coverage.py:155-158`). A window of 0
  would make G2 unable to see any finished work. So a waterfall board must set `rules.add_closed_days` to at least 1
  (validation, 2.5), the waterfall example sets 30, and the G2 window is exactly that setting. Work finished before the
  window is history and is not a finding.
- **Reopened and re-closed gate.** G2 uses the **newest** approving close. Reason: reopening a gate is how the
  maintainer says "not yet"; work that finished while the gate was reopened is exactly what G2 exists to show. The
  first-close alternative would hide it. The cost is a false positive for work that legitimately finished during the
  first passed period; it falls out of the window in at most `add_closed_days` days, and the line names both dates so a
  person can judge. The U5a test: a gate closed on day 1, a card finished on day 2, the gate reopened and closed on day
  3 is a G2 finding for that card.
- **Closed as not planned.** An issue closed as not planned or as a duplicate delivered nothing, so G2 does not apply
  to it (S2 covers a baselined item closed that way). A closed pull request that was not merged is not collected
  either (VERIFIED `coverage.py:135`). Reading an issue's `stateReason` for G2 is a waterfall-only addition to the
  card read (U4).
- **Draft cards.** A draft issue has no repository (VERIFIED `coverage.py:204-206`, `items.py:213`: `content` is
  None for a draft). It is checked by G1 when it holds a Phase and an active status (the Phase is the declaration), and
  its line names the card id: `DRIFT   GATE card PVTI_x is In progress in phase Build while the Design gate acme/gates#2
  is open`. G2 does not apply (a draft has no close). On a board whose **default** method (`process.method`) is
  waterfall, a draft in a status that is neither `baseline.intake` nor a done status and with no Phase is
  `MISSING Phase on card PVTI_x` (a draft belongs to no repository, so only the board's default can say which rule
  applies; on an agile default drafts are not presence-checked, as today).
- **Statuses the rule does not see.** G1 reads `active_statuses` only. Because the list is required and explicit, a
  status outside `active_statuses`, `baseline.intake` and the done statuses (for example "In review" left out by mistake)
  prints `NOTE    GATE status 'In review' is neither active, intake nor done; its cards are not gate-checked`.

The rule is the same for every repository, agile or waterfall: a card that carries a Phase has declared itself part of
the program (section 5). One finding per card names the earliest open gate only, so a card ahead of three open gates is
one line, not three.

**Gate integrity lines.**

| Situation | Line | Exit |
|---|---|---|
| Closed by an actor the approval test refuses | the actor table above | 1 |
| Closed as not planned or duplicate | `DRIFT   GATE acme/gates#2 (Design gate) was closed as not planned; it counts as open` | 1 |
| Closed with a `closer` | `DRIFT   GATE acme/gates#2 (Design gate) was closed through a pull request (acme/app#60), not by hand; it counts as open` (`through a commit` and `by a project workflow` for the other two) | 1 |
| Edited after approval | `DRIFT   GATE acme/gates#2 (Design gate) was edited on 2026-11-09 after it was approved on 2026-11-02; it counts as open` | 1 |
| A pull request, not an issue | `DRIFT   GATE acme/gates#2 (Design gate) is a pull request; a gate is an issue` | 1 |
| Not found, or not readable with the token | `UNKNOWN GATE acme/gates#2 (Design gate) cannot be read with this token, so no card's gate order can be told` | 2 |
| Transferred (canonical repository differs) | `UNKNOWN GATE acme/gates#2 (Design gate) now answers as acme/other#9; update process.gates` | 2 |
| A card's live Phase is not one of the file's options | `UNKNOWN PHASE acme/app#41 has Phase 'Beta', which board.yaml does not list; its gate order cannot be told` (only for a card G1 or G2 actually reads: an active card, or one closed inside the `add_closed_days` window; an old closed card holding a renamed option is history and is silent, or one rename would exit 2 forever) | 2 |
| The gate issue's own Phase differs from its gate's phase | `NOTE    GATE acme/gates#2 is the Design gate but its Phase is Build` | 0 |
| `gates` empty on a waterfall board | `NOTE    Gate check not configured: process.gates is empty` | 0 |
| The phase field's live type differs | `UNKNOWN GATE the Phase field is text on the project, not single_select; gate order cannot be told` | 2 |

An unreadable gate is UNKNOWN, never a pass: an audit that cannot read a gate cannot say any later-phase card is fine.
Logins and titles from GitHub reach the log only through `ctx.say`, which escapes every line (VERIFIED
`context.py:29-31`).

**Phase presence.** In a waterfall repository, an open issue whose status is not in `baseline.intake` (or not
`rules.status.opened` when there is no baseline) and has no Phase is `MISSING Phase on acme/app#41`, the existing format
(VERIFIED `coverage.py:203`). Issues referenced as gates or as `approved_in` are excluded from phase presence and from
the scope rule; they are process records, not scope. A pull request is not asked to type a Phase: it takes one as G3
says. A pull request in a waterfall repository whose phase cannot be derived at all is its own finding (G3).

**G3 (the phase of a pull request).** A pull request card's phase is the **latest** (by option order) of: its own Phase
if it has one, and the Phases of the board cards of the issues it links. The review found that preferring the card's own
Phase let an agent set an early Phase on the pull request and hide a Build issue behind it, so the rule is "latest
wins", never "own wins".

- **Which issues a pull request links.** `closingIssuesReferences` reports only closing keywords and sidebar links (the
  connection takes `userLinkedOnly` and `excludeUserLinked`; VERIFIED the connection exists, `coverage.py:31`, and the
  introspection of 2026-10-26 13:10 EDT; that it omits `Refs #n` is the review's finding and consistent with its name,
  INFERRED). The no-hidden-work audit accepts `Refs` too, by parsing the body (VERIFIED `coverage.py:46-51`,
  `coverage.py:120-127`: the `LINK` pattern and `links_issue`). G3 reads **both**: `closingIssuesReferences(first: 10)`
  with ids, plus the references the same `LINK` pattern finds in the body, resolved to board cards by repository and
  number (a reference to a repository not on the board is ignored; it can name nothing audit reads). The union is
  capped at 10 issues; more is `UNKNOWN GATE acme/app#77 links more than 10 issues; its phase cannot be told`.
- **A linked issue with no Phase** (cleared, or never set) contributes nothing. **An issue parked in an intake status**
  (for example Backlog) still contributes its Phase if it holds one: the pull request's phase is about what the work
  is, not the issue's status. A card that is in no active status is simply not G1-checked.
- **No derivable phase.** A pull request in a waterfall repository, open or inside the G2 window, whose own Phase is
  empty and whose linked issues give none is `DRIFT   MISSING Phase on acme/app#77: no linked issue carries one`. A
  `Refs`-only pull request that links an issue with a Phase is fine: it inherits it.
- **Own Phase earlier than inherited.** `NOTE    PHASE acme/app#77 carries Design but links acme/app#41 in Build; the later phase is
  used`. The check uses the later phase either way.
- **Residual: the author chooses the links.** "Latest wins" only ever raises a pull request's phase. A pull request that
  does Build work but links only an early-phase issue, and carries an early own Phase, is derived as early, and no rule
  here sees it. What limits it: the no-hidden-work audit still requires a linked issue, S1-S4 pin baselined issues, and
  review of the pull request. An optional, not-built NOTE could flag a pull request in an active status whose linked
  issues are all in a phase earlier than the latest phase with a passed gate; it is listed as optional under U7, with
  no rule text promised.

**The frozen-scope baseline and change control.** The baseline is `process.baseline` in `board.yaml`: a date, the
freeze issue, the items with the phase each was baselined in, and a list of changes. A change is one entry plus one
approval issue, and the order matters (the review found a pre-closed issue could be reused): (1) open an issue ("Change:
add acme/app#55 to Build", which must name the entry, line 8 of the approval test); (2) open a pull request that adds
the `changes` entry citing it; (3) an approver closes the issue as completed, by hand; (4) the required check is run
again and passes; (5) merge. Nothing reads change lines out of issue bodies, so no free text from an issue becomes
scope. The pull request's review is the second record.

**Closing an issue does not re-run a pull request's checks** (INFERRED from how GitHub triggers workflows: a check
belongs to a pull request event, and an issue event is a different trigger). Step 4 therefore needs a named mechanism.
Options, cheapest first: (a) the approver re-runs the failed check from the pull request page after closing (manual;
the documented first-cut path); (b) the approver or the author pushes a commit (any commit re-triggers the checks); (c)
the GYST workflow also listens to `issues: closed` and re-runs the check for the open pull requests whose diff cites
that issue (automatic, more moving parts, run from the default branch, and the check result must land on the pull
request's head commit; INFERRED feasible, not tested). The first cut documents (a) and (b); (c) is U8c's optional
extra.

**The ordering check and its clock (`--verify`), decided in M12.** "The approval was closed after the change was
proposed" is checked against the **pull request's creation time**, read from the API, and not against a commit date:
commit dates are set by the author and change under rebase and squash, while a pull request's creation time is set by
GitHub. The rule: the approval's closing time is later than the creation time of the pull request that adds the entry.
The check is `safo process diff --verify` (U8b), which needs a read token. **It is mandatory on same-repository pull
requests**: the GYST workflow (U8c) runs it whenever a token exists. A pull request from a fork gets no token, so it
gets the offline check only, and its result is labeled **advisory**; it cannot be merged on that check alone because the
protection of M8 still requires a code-owner review.

Audit reads (scope set = `items` + `add`s − `remove`s, each change counted only when its `approved_in` is approved by
the approval test; every `approved_in` is cited **once** across the baseline, and is never a gate: both are load-time
errors, 2.5):

| Rule | Line |
|---|---|
| **S1** an **open** issue of a waterfall repository, in a status that is neither `intake` nor a done status, and outside the scope set | `DRIFT   SCOPE acme/app#55 is In progress but not in the baseline of 2026-11-02; record an approved change (process.baseline.changes)` |
| **S2** a scope-set issue closed as not planned with no approved `remove` | `DRIFT   SCOPE acme/app#13 is in the baseline and was closed as not planned; record the removal as an approved change` |
| **S3** a change whose approval is not approved (including: created before `frozen`, closed with a `closer`, closed by a non-approver) | `DRIFT   SCOPE the change adding acme/app#55 cites acme/gates#21, which is open; the change is not approved` (the reason names the failed line of the approval test) |
| **S4** baseline phase pinning: a scope-set issue whose board Phase differs from its baselined phase | `DRIFT   PHASE acme/app#12 is in Build on the board but Design in the baseline; move it back or record a change` |
| **S5** `baseline.approved_in` itself not approved | `DRIFT   SCOPE the baseline cites acme/gates#5, which is not approved; the baseline is not frozen` |
| an item or change names a pull request | `DRIFT   SCOPE acme/app#60 is a pull request; the baseline lists issues` |
| an item or change cannot be read | `UNKNOWN SCOPE acme/app#12 cannot be read with this token` |

S1 is bounded in time on purpose: it applies only to **open** issues in a non-intake, non-done status, so a card that
closed years ago cannot trip it forever, and the rule text now matches the sample line ("is In progress"). Residual,
stated: work that went from intake to done between two audits without ever sitting in another status is not seen by S1.

S4 is what stops the cheapest dodge of the gate rule: an agent moving its card's Phase back to an earlier, already
passed phase. A change entry may carry a new `phase` for an item already in scope, which is how a re-phase is approved.

**Archived cards.** `ProjectV2.items` takes `archivedStates` and **defaults to `[NOT_ARCHIVED]`** (VERIFIED,
introspection 2026-10-26 13:10 EDT), and SAFO's board walk does not pass it (VERIFIED `items.py:63`: `items(first: 100,
after: $endCursor)`), so an archived card is invisible to every rule today. For a waterfall board, archiving an
In-progress Build card would hide it from G1, G2, presence and S1-S4. So a waterfall board reads
`archivedStates: [ARCHIVED, NOT_ARCHIVED]` (the argument's type is the enum `ProjectV2ItemArchivedState`, values
`ARCHIVED` and `NOT_ARCHIVED`, VERIFIED 2026-10-26; U4; `ProjectV2Item.isArchived` exists, VERIFIED), marks each card
`archived`, and:

- an archived card that holds a Phase and whose issue is open or not in a done status is a finding:
  `DRIFT   ARCHIVED acme/app#41 is archived while open in phase Build; unarchive it or close the issue`;
- G1, G2, S1-S4 read archived cards like any other (so the dodge gains nothing), and **phase presence applies to
  archived cards too**: an archived open issue in a non-intake status with no Phase is `MISSING Phase`, so archiving
  cannot hide a card by itself;
- the existing checks (a missing Kind or Epic, Done-on, the reconcile plan) keep ignoring archived cards, so a waterfall
  board does not suddenly grow findings about old archived work;
- whether `items_total` counts archived items, and so whether the "read N of M" check still agrees, is INFERRED; the
  U4 test pins whichever it is. Agile boards keep the default and read no archived card.

**Dependencies: native `blocked_by` links, not a convention.** A text convention (`depends-on: acme/app#30` in a body)
is free text audit would have to parse and anyone can edit silently; the native links are typed, readable and shown in
GitHub's UI (VERIFIED existence; see 1.3). With `process.dependencies: blocked_by`, for each card in `active_statuses`
whose content is an issue, audit reads `blockedBy(first: 20) { totalCount nodes { number state repository {
nameWithOwner } } }`:

- **D1** `DRIFT   DEPENDS acme/app#41 is In progress but is blocked by acme/app#30, which is open`
- more than 20: `UNKNOWN DEPENDS acme/app#41 has more than 20 blockers; they were not all read`
- a blocker the token cannot read: `UNKNOWN DEPENDS acme/app#41 is blocked by an issue this token cannot read`

What audit **can** enforce: an active card with an open blocker it can read. What it **cannot**: that the links are
complete or correct (**anyone with triage rights can add or remove a blocked-by link**, so an agent or collaborator can
delete the link that would have flagged a card; the timeline events `BLOCKED_BY_REMOVED_EVENT` record who, but SAFO does
not read them in the first cut), lead and lag times, dependencies on a pull request (`blockedBy` returns issues only,
VERIFIED the connection type is `IssueConnection`), dependencies held in another tracker, or anything in a repository
the token cannot read. The docs say so in those words.

**The status update.** Code-built like today. A waterfall board adds one section after "Next":

```
**Phases and gates**
- Requirements: gate acme/gates#1 passed 2026-11-02 (0 active, 14 done)
- Design: gate acme/gates#2 open (3 active, 5 done)
- Build: no gate (2 active, 0 done) - 1 card ahead of an open gate
```

Every number is counted in `statusgroups.py`; titles never appear in this section; the headline prompt and the fixed
prose clauses (VERIFIED `statusgroups.py:97-103`) are unchanged.

### 3.3 Exit codes

Unchanged: every new finding is DRIFT (1) or UNKNOWN (2) or NOTE (0), and UNKNOWN outranks DRIFT (VERIFIED
`modes/audit.py:26-33`). `reconcile` and `sync` never **act** on a gate, scope or dependency finding: they stay
mechanical (VERIFIED the plan has no such kind, `plan.py:57-81`). Reconcile prints the same findings as `HUMAN` lines
so its exit code stays 1 while one is open, as it does for a missing Epic today (VERIFIED `docs/no-hidden-work.md:15`,
`modes/reconcile.py:395-396`). That wiring is its own unit (U5b) because reconcile is the write-capable mode: reading
gates there means running the approval reader beside a token that can write. The read must use read-only queries
through the read path only, never touch the applier, and be Codex-reviewed (section 11).

### 3.4 Schedule views: documented and manual

A waterfall schedule lives in fields SAFO already supports: `Start date` and `Target date` date fields on cards, and
optionally a milestone per phase whose `dueOn` carries the phase date (VERIFIED `Milestone.dueOn` in the schema). The
Roadmap view's date fields, zoom, grouping by Phase and milestone markers are set by hand: the waterfall example lists
them under `ui_only`, so `bootstrap` prints the checklist and `audit` repeats it. SAFO computes no schedule, no critical
path and no slip. The one schedule read considered, an open gate past its milestone's due date as a NOTE, is unit U13,
optional and last.

### 3.5 Changing the phase list

Order is a property of the file, and no SAFO mode edits live options, so changing the phase list is a human procedure
with a check at each step. It is documented in `docs/process-methods.md` (U11) and enforced where it can be:

| Change | What happens | Rule |
|---|---|---|
| Append a phase at the end | Add the option in the project (Settings, the field, Add option; SAFO reports a missing option, VERIFIED `modes/audit.py:52-57`), then append it to the field's `options` in `board.yaml` | Allowed by the diff (U8a allowlist) |
| Insert or reorder | Moves which phases sit behind which gate, so it can move a card ahead of an open gate. A pure reorder **is** a weakening | Exits 1 in the diff; needs code-owner review and a fresh `safo audit` |
| Remove a phase | Live cards may still hold the value | Their gate order cannot be told: `UNKNOWN PHASE` (above) until they are moved |
| Rename | Same as remove plus append | Same |
| A gate on the last phase | Would gate nothing | Refused at load (2.5) |

## 4. Neutral and per-rule summary

| Rule | Method | Reads | Code or doctrine |
|---|---|---|---|
| Phase presence | waterfall repos | phase field | code (audit) |
| G1, G2 gate order | any card with a Phase | phase, status, gate close events | code (audit) |
| G3 pull request phase | pull requests | own Phase, closing references, body references | code (audit) |
| Archived-card check | waterfall boards | archived cards | code (audit) |
| S1-S5 scope and pinning | waterfall repos | baseline, approval close events | code (audit) |
| D1 dependencies | opt-in, any method | `blockedBy` | code (audit) |
| "Do not start work behind an open gate" | waterfall | nothing | doctrine; audit finds the breach after the fact |
| "Agents never close a gate or change issue" | waterfall | nothing | doctrine; R1 |
| Roadmap set-up | any | nothing | `ui_only` checklist |

## 5. Mixed mode

**Decision: per repository, with the board's method as the default.** Compared:

| | Board | Repository (chosen) | Area |
|---|---|---|---|
| Fits "agile teams inside a waterfall program" | No: one board would need two | Yes: a team's repository is agile, the program's are waterfall | Yes |
| What decides a card's method | Nothing per card | The card's repository, a fact GitHub returns and audit already canonicalizes (VERIFIED `items.py:317-323`) | A project field anyone with project write can change, filled from a title substring by `area_rules` (VERIFIED `rules.py:59-65`) |
| Dodge by an agent | n/a | Needs a `board.yaml` change, reviewed | Edit the Area of one's own card |
| Drafts | n/a | A draft has no repository: not presence-checked, but G1 reads its Phase (3.2) | A draft has whatever Area was typed |

Area loses because it is agent-writable state: keying a gate rule on it lets the card being checked choose its own rules.
The board level alone cannot express the case the maintainer named.

**What an agile repository inside a waterfall program gets.** Its cards are not asked for a Phase and are outside the
scope baseline. When one of its cards does carry a Phase (the team is delivering into Build), G1 to G3 apply to it like
any other: a phase value is a declaration, and the gate holds whoever makes it. A team cannot be pulled into the gate rule
by accident, and cannot leave it by flipping a field once its work is baselined (S4 covers baselined items only; an
agile repository's cards are never baselined, so for them clearing the Phase is a visible choice, counted in the status
update's Phases section as "no phase").

## 6. Routing, hooks and the API facts this design rests on

### 6.1 Routing and hooks need no method awareness

Answering the issue's question, with reasons:

- **Routing** picks an agent for a task shape. A phase changes what work is allowed to start, not who is best at it.
- **The dispatch guard** checks that a brief names an open issue, inside a 10-second hook budget with a 2-second margin
  (VERIFIED `docs/no-hidden-work.md:37-39`). Checking the gate there would add a project read (field values, the gate
  issues' close events) to every dispatch, a new failure mode that fails closed in block mode, and a board file the hook
  does not read today. Audit catches the breach on the next scheduled run, and the gate rule is about the board, which
  is audit's job.
- **Later, if wanted:** a guard rule that denies a brief whose issue is in a phase behind an open gate. It would need
  the board file in the hook's trusted configuration and a cached, time-bounded read. Not in this design.

The one guard change here is about trackers, not methods: section 7.3.

### 6.2 API facts, with what was and was not re-verified

| Fact | Status |
|---|---|
| `ClosedEvent` fields `actor, closable, closer, createdAt, duplicateOf, id, intent, resourcePath, stateReason, url`; `Closer` = `Commit \| ProjectV2 \| PullRequest` | VERIFIED, introspection 2026-10-26 13:10 EDT |
| `Actor` implementers `Bot, EnterpriseUserAccount, Mannequin, Organization, User`; `User.databaseId` and `User.id` exist; `Actor` itself has only `avatarUrl, login, resourcePath, url` | VERIFIED, same |
| `Issue.lastEditedAt`, `createdAt`, `stateReason`, `blockedBy`, `blocking`, `timelineItems(itemTypes, first, last, after, before, since, skip)` | VERIFIED, same |
| `ProjectV2.items(archivedStates: [ProjectV2ItemArchivedState!] = [NOT_ARCHIVED])`, the enum having `ARCHIVED` and `NOT_ARCHIVED`; `ProjectV2Item.isArchived` | VERIFIED, same, re-read in round 3 |
| `ISSUE_FIELD_CHANGED_EVENT` is in the issue and pull request timeline enums (organization issue fields, a different feature from project fields); `closingIssuesReferences` takes `userLinkedOnly` and `excludeUserLinked` | VERIFIED, same |
| Project card history exists for the **Status** field only: `PROJECT_V2_ITEM_STATUS_CHANGED_EVENT` (`actor, createdAt, previousStatus, status, project, wasAutomated`), `ADDED_TO_PROJECT_V2_EVENT`, `REMOVED_FROM_PROJECT_V2_EVENT`, on both issue and pull request timelines; no event exists for a Phase (or any other field) change | VERIFIED, same |
| No GraphQL mutation names Milestone | VERIFIED, same (mutation list) |
| `addBlockedBy`, `removeBlockedBy` and four blocked-by timeline events exist | VERIFIED, same |
| Cross-repository and cross-owner `blockedBy` exists; creating a dependency needs at least triage on the repository being edited | VERIFIED by the independent re-review (read-only, 2026-10-26); I did not repeat it (no docs fetch tool here, and a mutation test would write) |
| `ClosedEvent.closer` is null for a manual close and `PullRequest` for a close by a merged pull request, whose `actor` is the merger | VERIFIED, read-only, 2026-10-26, re-run by me: `cli/cli#14708` (NOT_PLANNED by hand, `closer` null, actor a `User`); `cli/cli#14749` and `cli/cli#14718` (closed by merged pull requests: `closer` `PullRequest`, actor a `User`, `COMPLETED`) |
| A project workflow close has `closer` `ProjectV2` | INFERRED (the union member exists; no such close was read); pinned by U3 fixtures |
| `Refs #n` is not in `closingIssuesReferences` | VERIFIED by the independent re-review: 4 of 4 public merged pull requests whose body had only `Refs #N` returned `totalCount` 0. I did not repeat the four; one merged pull request I sampled also returned 0 but proves nothing about `Refs`. G3 reads both sources regardless |
| A GitHub App acting for a user appears as that `User` in the GraphQL `ClosedEvent` (it has no app field); REST issue events carry `performed_via_github_app` | PARTLY settled: the missing app field is VERIFIED by introspection; the REST key is present (VERIFIED on the events of `cli/cli#14749`, value null there); that it is non-null for a user-to-server close is the re-review's finding, not re-run. Used by M2 option 1b |
| `Issue.lastEditedAt` semantics (does a title edit, a checkbox toggle, or a comment move it) | INFERRED; the U3 fixtures cannot settle it, a live experiment on a scratch issue can |
| `items_total` counts archived items or not | INFERRED; pinned by the U4 test |
| SAFO `main` has no branch protection and no rulesets | VERIFIED: REST `branches/main/protection` returned 404 "Branch not protected", `rulesets` returned `[]`, `rules/branches/main` returned `[]`, 2026-10-26 13:10 EDT |
| A fine-grained token without `issues:write` cannot close an issue | INFERRED; the manual scratch-repository experiment (unit U-exp, 11) settles it before any adoption, by decision M7 |
| Jira project keys may contain an underscore; Jira keys' exact shape | INFERRED, from memory of Atlassian behavior; verify against Atlassian docs before the Jira build |

## 7. The tracker interface, and Jira later

### 7.1 The minimal operations

```
resolve(ref)            -> open | closed | missing | pull_request | error     (exists today: Resolver)
read_status(ref)        -> the item's status name, or None                     (GitHub: board item Status)
write_status(ref, name) -> applied | unchanged | unknown_outcome               (GitHub: the existing applier)
list_items(scope)       -> the open and recently closed items of one scope     (GitHub: collect_work per repository)
```

`Ref` keeps its `tracker` tag (VERIFIED `tracking.py:39-45`). A `Tracker` protocol holds the four operations and a
`pattern` for its references. GitHub is the first implementation, by wrapping what exists: `gh_resolver`
(VERIFIED `tracking.py:129-180`), the board item read (`items.py`), the applier (`apply.py`, VERIFIED imported and used at
`modes/sync.py:26`, `modes/sync.py:253`) and `collect_work` (VERIFIED `items.py:451`). The modes call the protocol; nothing in `audit`, `reconcile`
or `sync` learns the word Jira. **Not built in the first cut** (stage 5 of section 11): the refactor has no user until a
second tracker exists, and the guard change below does not need it.

### 7.2 Jira, when it comes

INFERRED, every line, and to be verified against Atlassian's own documentation pages before any build: Jira Cloud reads
an issue by key over REST with a field filter, authenticates either a user API token (which carries the user's whole
permission set) or OAuth 2.0 with scopes, and reports a status and a resolution. The design constraints do not depend on
those details:

- The guard needs read only. Sync needs status write on one project. They get separate credentials, the write one only
  in CI through the Doppler OIDC pattern the Action already uses (VERIFIED `.github/workflows/live-audit.yml:6-8`).
- One configured base URL, `https` only, pinned by the same kind of destination check `netguard.py` applies to the local
  model (INFERRED it can be reused; only its function list was read: `netguard.py:36-95`), no redirect followed with the
  credential.
- Only keys and status names leave GitHub for Jira. Only keys and status names come back into GitHub-visible places: a
  Jira title is never written into a public project, a status update or a log line.
- The guard's lookup runs inside the same `remaining()` budget as `gh` (VERIFIED `tracking.py:133-147`).

### 7.3 The shape-only key, now (unit U1)

A Jira-style key is accepted by shape alone today (1.4). The fix, analogous to `hooks.tracking_repos` (VERIFIED
`agentsfile.py:142`, `tracking.py:201-203`), in `agents.yaml`:

```yaml
hooks:
  jira_projects: [OPS, PLAT]   # Jira project keys a brief may cite; empty (the default): no Jira key is accepted
```

One rule name for "this project is not accepted", the same one GitHub uses for a repository outside `tracking_repos`
(VERIFIED `tracking.py:201-203`): `issue-unusable`. `issue-unverified` stays what it is today, a lookup that failed
(VERIFIED `hooks.py:66-68`), and is used for a Jira key only once a resolver exists.

| Brief line | `jira_projects` | Result |
|---|---|---|
| `issue: OPS-12` | `[]` (default) | `issue-unusable`: "OPS is not an accepted Jira project; accepted: none (set hooks.jira_projects to accept keys of a project by shape)" (no lookup) |
| `issue: OPS-12` | `[OPS]` | accepted by shape; the docs state the residual: a number in a listed project is not checked |
| `issue: FAKE-1` | `[OPS]` | `issue-unusable`: "FAKE is not an accepted Jira project; accepted: OPS" (no lookup) |

**What this closes, and in which mode.** It closes the finding **in `block` mode only**. The guard's default mode is
`warn` (VERIFIED `guardlog.py:27-28`, `DEFAULT_MODE = "warn"`), and a missing, unsafe or corrupt mode file falls back to
`warn` (VERIFIED `guardlog.py:182-194`, `mode_health`), so in those cases an unaccepted key is reported and the
dispatch still happens. U1 tests the degraded case: a corrupt mode file yields `warn`, the verdict names the rule, and the
decision is `warn` not `deny`. The docs say it in those words.

`jira_projects` entries fullmatch the project part of `JIRA_KEY` (VERIFIED `tracking.py:26`), at most 64. That pattern,
`[A-Z][A-Z0-9]{1,9}`, has no underscore, so a key such as `MY_PROJ-1` is neither parseable nor listable (it falls into
the "not owner/repo#N or KEY-N" answer, VERIFIED `tracking.py:183-196`). Decision: U1 keeps the pattern and documents
the limit; widening it belongs with the Jira resolver (stage 5), after the real key rules are verified against
Atlassian's documentation. When a Jira resolver exists, a listed project's key is looked up instead of accepted by
shape, and the unlisted case stays `issue-unusable`. Nobody uses Jira keys today (no instance, VERIFIED
`docs/no-hidden-work.md:95`), so the stricter default breaks nothing in use. That is a maintainer decision (M1).

## 8. Threat model

Method: `pack-threat-model`. Covered: this design's new inputs and decisions, and the Jira seam. Not covered: a review of
the existing guard, Action or loader beyond what this design touches; any probing of a live system (none was done; the
only live calls were read-only schema introspection and three read-only REST reads of branch protection).

### 8.1 Assets

| Asset | Class |
|---|---|
| A1 Integrity of the process record: gate state, approvals, the baseline, the audit's verdict and exit code | integrity |
| A2 The maintainer's GitHub credential with `project` scope, which agents may use through his `gh` login | secret |
| A3 A future Jira credential (read for the guard, write for sync) | secret |
| A4 Confidential Jira content (titles, descriptions) of a future private instance | confidential |
| A5 The guard's allow or deny decision, and its log | integrity |
| A6 CI minutes and API rate budget | availability |
| A7 Confidentiality of private issues' existence (what an audit log reveals about them) | confidential |

### 8.2 Actors

The maintainer (trusted); an agent (Claude, Codex, Copilot) acting with the maintainer's token or its own App identity;
a collaborator with project write; **a triage-level collaborator** (can edit issues, reopen them, add or remove
blocked-by links and labels); a contributor with a fork pull request; **a GitHub account takeover or a login rename or
recycle** (the approver's account is taken over, or a released login is registered by someone else); a compromised
dependency in the Action's job; a model reading attacker-written issue text; a future Jira user or administrator.

### 8.3 Trust boundaries

- B1 A pull request's `board.yaml` to the audit that reads it: the rules are in the change being checked.
- B2 Project field values (Phase, Status, archived state) to audit: writable by anyone with project write, which
  includes every agent.
- B3 An issue's close event to "approved": the actor is whoever's token closed it, and the cause (`closer`) may be
  something else.
- B4 An agent's shell to the guard's state and configuration (existing, VERIFIED `docs/no-hidden-work.md:56-59`).
- B5 SAFO to Jira over the network; B6 Jira content to GitHub-visible surfaces (both future).
- B7 YAML text to the loader (existing, extended by the `process` block).
- B8 Repository settings to the controls that live in the repository: CODEOWNERS and a workflow are files, and a file
  is enforcement only when branch protection or a ruleset makes it so.

### 8.4 Risk register (ranked: impact first, then how little the actor needs)

| Id | Abuse case | Impact | Prerequisite | Rank |
|---|---|---|---|---|
| R1 | An agent holding the maintainer's token closes a gate or change issue; the close event says the maintainer approved | High: every gate and change is forgeable | None beyond normal agent operation while agents run on the maintainer's own login (the dedicated gates repository with a restricted agent token, decided in M7, removes it for the gates repository) | 1 |
| R12 | A pull request containing `Closes owner/repo#N` for a gate or change issue is merged; GitHub closes the issue and the close event's actor is the merger, a `User` with `COMPLETED` | High: any merge approves a gate; approvers approve without knowing | Write access to open a pull request that gets merged; or a commit on the default branch | 2 |
| R2 | A pull request edits `board.yaml`, the caller workflow that runs the diff, or CODEOWNERS: drops a gate, switches the method, widens who approves, empties `approvers`, swaps a gate's `issue` to an already-closed issue, widens `baseline.intake`, drops a repository, changes `add_closed_days`, `rules.status` or `agents.working` (which moves the default active set), swaps the phase field, or reorders Phase options (which moves a gate relative to phases). A PR-time audit reads the edited file and passes. **Today nothing enforces review**: SAFO `main` has no protection and no rulesets (VERIFIED, 6.2), so CODEOWNERS is advisory and a direct push skips every check | High | Repository write | 3 |
| R3 | An agent moves its card's Phase back, clears it, or parks the issue in Backlog while a pull request does the work | Medium: gate rule dodged | Project write (every agent has it) | 4 |
| R13 | An agent sets an early Phase on a pull request that implements a Build issue, so the pull request looks like it is in a passed phase | Medium | Project write | 5 |
| R14 | An agent archives its In-progress Build card; archived items are not returned by default, so G1, G2, presence and S1-S4 never see it | Medium | Project write | 6 |
| R15 | An approval issue is reused: one closed issue cited for several changes, a gate issue cited as a change approval, or an old closed issue swapped in for a gate or change (S3, S5) | High | Repository write to `board.yaml` (and protection absent, R2) | 7 |
| R16 | A login is renamed or recycled, or an approver's account is taken over, so a close by "the approver's login" is by someone else | High | A released login registered by another person, or a credential theft | 8 |
| R17 | A triage-level collaborator reopens a gate (availability: work is blocked), edits a gate after approval (changing what was approved), or removes a blocked-by link (D1 goes quiet) | Low to medium | Triage permission | 9 |
| R4 | A brief cites a Jira-style key that no resolver can check; the guard accepts it by shape (documented, closed first by U1) | Medium: hidden work | None | 10 |
| R18 | A hostile `board.yaml` names `owner/repo#N` outside the board's repositories; the audit reads it with the installation token and its public log shows whether it exists or is readable (an existence oracle) | Low to medium | Repository write | 11 |
| R5 | Future: Jira titles or descriptions copied into a public project, status update or CI log | High for a private instance | A Jira integration that renders text | 12 |
| R6 | Future: an over-scoped Jira token (a user API token with full rights) leaks via a log, a redirect to another host, or an agent's environment | High | Access to the job or agent environment | 13 |
| R7 | An unreadable, deleted or transferred gate or approval issue makes the gate rule silently pass | Medium | Issue delete or transfer rights | 14 |
| R19 | The phase list is changed (an option inserted, reordered, removed) so a card sits on the wrong side of a gate, or a card holds a Phase the file does not list and is silently skipped; a gate on the last phase gates nothing | Medium | Repository write, or project write for the live value | 15 |
| R8 | A hostile `process` block (thousands of refs) exhausts the rate budget or the run time | Low to medium | Repository write | 16 |
| R9 | A gate check is skipped (phase field type drift, method mis-set) and audit says clean | Medium | A field edit in the project UI | 17 |
| R10 | A login or title with control characters forges a log line or workflow command | Low | Any GitHub account | 18 |
| R11 | Method definitions loaded from files outside `board.yaml` become an injection or path-traversal surface | n/a by design | n/a | closed |

### 8.5 Mitigations and verification

Every row names the verification that proves the mitigation bites (delete the mitigation, the named test goes red).

| Id | Mitigation | Verification |
|---|---|---|
| R1 | An approval by a `Bot` never counts. `approvers` lists people by immutable id. **M7 (decided): gate and change issues live in a dedicated repository; agents run on a fine-grained token without `issues:write` there and only the maintainer closes them.** The REST cross-check (approval test line 4b) refuses a close performed through a GitHub App. Doctrine, stated in the docs and the agent briefs: agents never close gate or change issues. Audit prints each gate's approver login and close time in the `PROCESS` header line so a person sees who approved | Test: a gate closed `COMPLETED` by a `Bot` actor is open, with the bot line; a close whose REST event has `performed_via_github_app` set is open; the header names the approver. **U-exp** (manual, scratch repository) shows the restricted token cannot close, reopen, edit or create an issue in the gates repository; it is a hard prerequisite before any real board |
| R12 | The approval test requires `closer == null`, `stateReason == COMPLETED` and `duplicateOf == null`; it reads the newest close with `timelineItems(itemTypes: CLOSED_EVENT, last: 1)` | Fixture: a merged pull request closes the gate, the actor is an approver `User` with `COMPLETED`, the gate stays open with the `closer` line. Fixtures for `Commit` and `ProjectV2` closers. Fixture: a gate reopened and closed again reads the newest close, not the oldest |
| R2 | (a) **Prerequisite, decided in M8 (hard):** U8 does not ship until a branch protection rule or ruleset on the default branch is in place and a read-only script reads it back: code-owner review required; the `CI green` check required; the branch required to be up to date (or a merge queue); administrators included; no bypass allowance or bypass actor for the agent account, and none for administrators the agents may use; force pushes off; CODEOWNERS entries for `board.yaml`, `.github/CODEOWNERS` and `.github/workflows/`. `.github/CODEOWNERS:1` (`* @ChiefGyk3D`) is VERIFIED as a file only, **not** as enforcement; the up-to-date requirement also stops two pull requests from citing one approval issue and both merging. (b) A **deny-by-default** offline mode, `safo process diff BASE HEAD` (U8a), applied only to a board with a waterfall repository: on the keys it governs it passes only an explicit allowlist and exits 1 on anything else, including every case in the R2 row; a change under `.github/workflows/`, `.github/CODEOWNERS` or `board.yaml` is reported as `protected path changed` and needs code-owner review but does not exit 1 by itself (otherwise every Dependabot bump would fail). (c) The diff runs from a reusable workflow pinned by commit (U8c), and its caller is under the protected paths, because a pull request can edit the caller that runs the diff. (d) Scheduled audits read the default branch's file; a PR-time audit must read the base branch's file, never the PR's | Prerequisite check (U-prereq): a read-only script that exits non-zero for each missing condition above; today it would exit 1 against SAFO `main` (VERIFIED 404). One diff test per weakening in the R2 row (each goes red with that comparison removed); a test that an unlisted change kind exits 1 (the deny-by-default bite); a test that a workflow-only change exits 0 with the NOTE; tests that each allowlisted change passes; a test that the offline diff reads nothing from the network (the fake GitHub sees no request) |
| R3 | S4 pins baselined items to their phase; phase presence makes a cleared Phase a finding in waterfall repositories; G3 gives a pull request its linked issues' phase, so parking the issue in Backlog does not hide an active pull request; the status update counts cards with no phase | Tests for each: re-phased baselined item, cleared Phase, PR in Build linked to a Backlog issue behind an open gate |
| R13 | G3 takes the **latest** of the card's own Phase and the linked issues' Phases, from `closingIssuesReferences` and from `Refs` in the body | U7 tests: an own early Phase on a pull request linked to a Build issue behind an open gate still yields DRIFT; a `Refs`-only pull request inherits; a `Refs`-only pull request with no phase anywhere is `MISSING Phase`; a linked issue with a cleared Phase contributes nothing; an issue parked in Backlog with a Build Phase still contributes Build |
| R14 | A waterfall board reads `archivedStates: [ARCHIVED, NOT_ARCHIVED]`; an archived card with a Phase and an open or non-done issue is a finding; G1-S4 read archived cards | U4/U5a tests: an archived In-progress Build card behind an open gate yields both the gate line and the archived line; an agile board's query still has no `archivedStates` (golden) |
| R15 | Load-time errors: every `approved_in` cited once, never a gate, a gate's `issue` cited once (2.5); the approval test requires a change issue created on or after `frozen`, a freeze issue closed on or before it, and (line 8, M13) a body that holds the entry's reference on its own `Entry:` line; `safo process diff --verify` (read-only token; mandatory on same-repository pull requests, M12) checks that a new `approved_in` was closed after the **pull request's creation time**, which the author cannot set and a rebase or squash does not change; a fork pull request has no token, runs the offline diff only and is labeled advisory; swapping a gate's `issue` is not on the diff allowlist; the up-to-date branch rule (R2) stops two pull requests both citing one approval issue | Tests: the two load errors; a change issue created before `frozen` is S3; an approval that does not mention its entry is S3; a pre-closed issue cited in a new entry fails `--verify`; the clock is the PR creation time (a rebase does not move it); a gate-`issue` swap exits 1 |
| R16 | Approvers carry the immutable `databaseId`; a matching login with another id is not an approver; a matching id with a new login counts and prints a NOTE | Tests: same login different id, same id different login, and null actor |
| R17 | A gate edited after its approval counts as open with a line. A reopened gate shows as open in the status update and the audit (recoverable, availability only). The blocked-by weakness is stated in "what audit cannot enforce" and in the docs | Tests: `lastEditedAt` later than the close; the docs test that the sentence is present |
| R4 | `hooks.jira_projects`, default empty: every Jira key is `issue-unusable` and block mode denies | Tests: `issue: FAKE-1` with the default is `issue-unusable` and denied in block mode, and **allowed with a warning in warn mode and with a corrupt mode file**; a listed project is accepted; an unlisted project is `issue-unusable` with no lookup (the fake resolver records zero calls) |
| R18 | Every reference in `process` must name a repository in `repositories`, checked at load, offline, before any request (2.5) | A load test per reference kind (gate `issue`, `baseline.approved_in`, `items[i].ref`, `changes[i].add`, `.remove`, `.approved_in`) asserting the error and that the fake GitHub saw no request |
| R5 | Jira text is never rendered; only keys and status names cross; a test fixture with a sentinel title proves it never appears in any output | Sentinel-title test over every mode's output (stage 5, before any Jira build) |
| R6 | Separate read and write credentials; the write one only in CI via Doppler OIDC; https only; destination pinned; no redirect carries the credential; the token never reaches a log | Redirect-to-other-host test drops the header; log scan test with a sentinel token (stage 5) |
| R7 | Unreadable, missing, transferred or pull-request gates and approvals are UNKNOWN or DRIFT, never a pass; UNKNOWN outranks DRIFT | One test per case, each asserting exit 2 or 1 and never 0 |
| R19 | A live Phase the file does not list is `UNKNOWN PHASE` for a card G1 or G2 reads (an old closed card outside the window is silent); a gate on the last phase is refused at load; insert, reorder and remove exit 1 in the diff; append is allowed; the change procedure is documented (3.5) | Tests: unknown live phase on an active card exits 2 and on an old closed card does not; last-phase gate load error; the diff exits 1 for an insert and a reorder and passes an append |
| R8 | Caps (2.5); gate and approval reads batched (aliased issue reads, at most 50 per query, distinct references deduplicated); `blockedBy(first: 20)` with a count | Cap+1 tests for each list; a query-count test for a board at the caps |
| R9 | A live phase field of the wrong type is UNKNOWN for the gate rule (extending `mismatched_fields`, VERIFIED `items.py:369-386`); every waterfall check not configured is a NOTE | Type-drift test asserting exit 2; not-configured note tests |
| R10 | Every line goes through `ctx.say` (VERIFIED `context.py:29-31`) | A login with `::` and control characters is escaped (extends the existing output tests) |
| R11 | Methods are built in and named; `board.yaml` cannot point at another file | The schema refuses any path-valued key under `process` (a test that `process.method: ./mine.yaml` is refused by the choice check) |

### 8.6 Residual risk, and the separations chosen for R1

**R1 is not accepted as written.** When agents act through the maintainer's own login, the close event cannot tell the
maintainer from an agent (INFERRED: both are the same `User`). The options, in order of cost, and what the maintainer
decided on 2026-10-26 (M7, "Dedicated gates repo, restricted agent token"):

1. **`closer == null`, `COMPLETED`, no `duplicateOf` (in the design already).** Removes the merge-and-keyword, commit and
   project-workflow routes (R12). It does **not** separate an agent's `gh issue close` from the maintainer's click:
   both are a manual close by the same user.
   **1b. The REST cross-check (approval test line 4b).** Also read the REST `closed` event and treat
   `performed_via_github_app != null` as not manual. It closes the case of a GitHub App acting for a user, which GraphQL
   shows as that `User` (PARTLY settled, 6.2). It does not separate a person from a personal token.
2. **DECIDED: gate and change issues live in a dedicated repository, and agents run on a fine-grained token without
   `issues:write` there; only the maintainer closes gates.** This is the cheapest real separation when agents otherwise
   run on the maintainer's `gh` login: the maintainer's own login keeps the right to close; the agents' token cannot.
   Whether a fine-grained token without that permission cannot close, reopen, edit or create an issue there is INFERRED;
   **a manual experiment on a scratch repository (unit U-exp) settles it first and is a hard prerequisite for adopting
   waterfall.** Consequences: the dedicated repository is listed in `repositories` (so every reference to it passes the
   load check); the maintainer files the gate and change issues (agents cannot); agents may still read them.
3. **A second signal by the approver, such as a signed tag or a signed commit** naming the gate. Higher cost (a key, a
   verification path); it separates a person from any token. Not in the first cut.
4. **Agents on an App or bot identity that is not an approver.** The strongest and the largest change to how agents run.
   Not needed while option 2 holds.
5. **The reopen signal, honestly worded.** Any gate or change issue closed in a session where an agent was running can be
   found by reading the issue's timeline against the guard log. That comparison is a **manual timestamp match**: the
   guard log records the rule names per dispatch and never the brief or the issue, so no tool joins the two. The
   timeline is a record to read after the fact, not a control.

What stays residual after options 1, 1b and 2: the maintainer's own account, and a token with write access to the gates
repository. Audit proves a close by an approver identity, not that a person decided.

Other residuals:

- **R3 partly.** Work that has neither a card in an active status nor a pull request is invisible to every rule here;
  that is the no-hidden-work rule's residual, unchanged.
- **R13: the author chooses the links** (3.2, G3). "Latest wins" only raises a phase.
- **R4, while a project is listed, and in warn mode:** a number in a listed Jira project is not checked until a resolver
  exists, and warn mode reports without blocking.
- **R2 until the prerequisite lands.** Without enforced protection read back by the check, every diff check is advisory.
  A fork pull request gets the offline diff only, labeled advisory (M12).
- **The audit finds breaches after the fact** (M14): the gate rule reads the board on a schedule; nothing blocks a card
  from moving, and nothing is read at dispatch (6.1).
- **R16:** an account takeover of an approver is not stopped by id pinning; it needs the account's own protections.
  Enterprise-managed approvers cannot be named in the first cut (M15).
- **Approval is not judgment.** Audit proves an approver closed the gate, not that the gate's criteria were met.
- **The guard's own residual** (an agent with shell access can edit the guard's state) is unchanged (VERIFIED
  `docs/no-hidden-work.md:56-59`).

## 9. The issue's open questions, answered

| Question | Answer | Why |
|---|---|---|
| Method granularity (board, repo, Area) | Repository, with the board's method as the default | Section 5: the repository is a fact GitHub returns; Area is writable by the card's own worker |
| Where gates live (card, field, milestone) | An issue per gate, in a dedicated repository, listed in `board.yaml`; a milestone optionally carries the date | 3.2: only the issue records who approved, readable by audit; listing beats label discovery; the dedicated repository is the separation of M7 |
| Baseline changes without heavy process | One approval issue plus one `changes` entry per change, in `board.yaml`, with the order in 3.2 | 3.2: no new file, no body parsing for scope, the PR review is the second record, audit checks the approval |
| Do routing and hooks need method awareness | No | Section 6.1 |

### Decisions for the maintainer

M7, M8, M12 and M13 are **DECIDED** by the maintainer on 2026-10-26, answering a multiple-choice question; his option
label is quoted. Every other row is a **recommendation awaiting the maintainer unless he objects**. Each row says whose
call it is.

| Id | Decision | Status and recommendation |
|---|---|---|
| M1 | Jira keys by default: `issue-unusable` (denied in **block** mode only; reported and allowed in warn mode and with a corrupt mode file) unless their project is in `hooks.jira_projects` | Recommended: yes, ship first (U1). It closes the shape-only acceptance in block mode; nobody uses Jira keys today. The underscore limit of `JIRA_KEY` is documented and left to the Jira build. Maintainer's call |
| M2 | Approval integrity: `closer == null` with `COMPLETED` and no `duplicateOf` (option 1), the REST `performed_via_github_app` cross-check (option 1b), and the separation of M7 (option 2) | Recommended: adopt 1 and 1b in U3 and 2 through M7 (decided). Options 3 and 4 wait for a reason. The reopen signal is a manual timestamp match and not a control. Maintainer's call on 1b (one REST read per approval issue) |
| M3 | `safo process diff` on pull requests as a reusable workflow (or an input of `python-ci`) in git-your-ship-together, which this repository then calls | Recommended: yes, in GYST (unit U8c, an issue in that repository), after M8. Every adopter needs the same step, which is the consolidation rule |
| M4 | G2 (finished ahead of a gate) as DRIFT or as a NOTE, with the window `rules.add_closed_days` (at least 1 on a waterfall board) and the newest approving close for a reopened gate | Recommended: DRIFT, conditional on that definition: a merged pull request ahead of an open gate is the breach the rule exists for. Maintainer's call |
| M5 | This project's own board | Recommended: stays agile; the waterfall board ships as an example file only |
| M6 | Names: *method* (`process.method`, `repositories[i].method`, `docs/process-methods.md`, "Choose a process method") instead of *profile*, which SAFO already uses for agent profiles (`docs/profiles.md`, `safo profiles verify\|brief`); the `process` key, the values `agile` and `waterfall`, and `safo process diff` stay; the issue title stays | Recommended: adopt *method*. Alternatives: `approach`, `discipline`. Maintainer's call |
| M7 | **DECIDED 2026-10-26, "Dedicated gates repo, restricted agent token".** Gate and change issues live in a separate repository where agents run on a fine-grained token without `issues:write`; only the maintainer closes gates. A manual scratch-repository experiment verifies the token behavior first | Decided. It becomes unit U-exp and a **hard prerequisite for waterfall adoption**. The board lists the gates repository; the maintainer files gate and change issues |
| M8 | **DECIDED 2026-10-26, "Yes, hard prerequisite".** U8 does not ship until branch protection with required checks, code-owner review on `board.yaml`, CODEOWNERS and the workflows, no bypass for the agent account, and an up-to-date branch are in place and read back by the read-only script | Decided. Unit U-prereq is the script; U8a, U8b and U8c are ordered after it. SAFO `main` has none of this today (VERIFIED, 6.2). Applying the setting is the maintainer's |
| M9 | Archived cards on a waterfall board: read them (`archivedStates: [ARCHIVED, NOT_ARCHIVED]`), apply the gate rules and phase presence to them, and treat an archived open card with a Phase as a finding | Recommended: yes, for waterfall boards only; agile boards keep today's query |
| M10 | `rules.add_closed_days` must be at least 1 on a waterfall board; the waterfall example sets 30 | Recommended: yes. With 0, G2 cannot see finished work and the pull request check sees open pull requests only |
| M11 | The diff is deny-by-default on the keys it governs (an explicit allowlist passes; anything else on a governed key exits 1), applies only to a board with a waterfall repository, and reports a protected-path change without failing on it | Recommended: yes. It will sometimes block a harmless edit of a governed key; that edit then needs code-owner review, which is the intended friction |
| M12 | **DECIDED 2026-10-26, "--verify mandatory on same-repo PRs, PR creation time as the clock".** The GYST workflow runs `--verify` whenever a token exists; fork pull requests get the offline check only and are labeled advisory | Decided. The clock is the pull request's creation time, read from the API, not a commit date |
| M13 | **DECIDED 2026-10-26, "Yes, required".** An approval issue's title or body must contain the entry's add or remove reference, checked by exact string comparison with no free-text scope parsing | Decided. One adjustment for the maintainer to confirm: the issue text is not available offline, so the check runs in audit and in `--verify`; the load-time part only requires that an `approved_in` is cited for each entry |
| M14 | Audit cadence: gate, scope and phase rules find a breach after the fact, on the next audit; nothing blocks a card from moving | Recommended: run the audit on a schedule of at least daily, and on demand after a gate is closed or reopened; say in the docs that it is detection, not prevention. Dispatch-time gating stays out of scope (6.1). Maintainer's call on the cadence |
| M15 | Enterprise Managed User approvers: an `EnterpriseUserAccount` actor cannot be named in `process.approvers` in the first cut, so such a close counts as open with an explicit line | Recommended: accept for now; revisit when an enterprise-managed organization adopts the method. Maintainer's call |

*Note on M13 (non-normative history).* The maintainer decided on 2026-10-26 that an approval must name its entry. The
first wording searched the issue title or body for the reference as a whole token. The security reviews of unit U3
found that this reads raw markdown (a hidden comment, a link target or an image URL satisfied it) and that a title
rename after the close is not an edit. The normative rule is now line 8 of the approval test: one `Entry:` line in the
body, a fail-closed plain-ASCII-prose body grammar (no raw HTML, no Markdown structure, no brackets), the title never used. The decision itself (the approval must name its entry,
by exact comparison, with no free-text scope parsing) is unchanged.

## 10. Non-goals, compatibility and migration

**Non-goals.** A Jira implementation (only its seam and threat model are here). A Gantt or schedule computation, a
critical path, earned value, resource planning. Transition tables. Gate enforcement at dispatch time. Methods defined in
files outside `board.yaml`. Automatic baselining (`safo` never writes `board.yaml`). Reading change requests from issue
bodies for scope. Any write by `reconcile` or `sync` driven by a gate, scope or dependency finding.

**Compatibility.** A valid board without a waterfall repository behaves and prints exactly as today (2.4, with golden
tests captured on `main` first); the one change is the text of the `unknown key (allowed: ...)` error for an invalid
board. `version` stays 1. An older `safo` refuses a file with `process` (fails closed); the release notes say so. The
Action's inputs do not change in the first cut. `agents.yaml` gains one optional key, `hooks.jira_projects`; its stricter
default changes the guard's answer only for Jira-style keys.

**Migration.** None for existing boards. A team adopting waterfall: (1) completes the experiment U-exp and applies the
protection read back by U-prereq (both hard prerequisites); (2) copies `examples/process-waterfall.yaml`, runs `safo
validate`, then `safo bootstrap` (which creates the Phase field like any other); (3) files, in the dedicated gates
repository, one issue per gate **and a freeze issue of its own (not a gate)** for the baseline; (4) lists the gates and
the freeze issue; (5) adds the baseline once the Requirements gate is approved and the freeze issue is closed by an
approver on or before `frozen`. Each later scope change is a change issue in the gates repository naming its entry, a
pull request, a manual close, a re-run check, and a merge (3.2). The docs page "Choose a process method" walks it,
including the phase-list procedure (3.5).

## 11. Build plan

Units are issue-sized, each one pull request, test first, for a Sonnet implementer. "Codex" means an adversarial Codex
pass on the cyber tier before merge, required wherever approval logic, untrusted parsing, the guard, a token path or a
security control is touched. Every unit's issue links #108; the maintainer merges. U8c lives in another repository
(git-your-ship-together) and has its own issue there, linked to #108.

| Unit | Title | Scope and files | Tests | Code vs doctrine | Review |
|---|---|---|---|---|---|
| U0 | Capture golden outputs on `main` | `tests/golden/process-agile/` (new): the outputs of `audit`, `reconcile --dry-run`, `status --post --print`, `agents-status` against `tests/fakegh` for `examples/safo.yaml` and `examples/renegade-penguin.yaml`; no source change. **The clock is frozen**: audit takes `ctx.today` (VERIFIED `modes/audit.py:106`), and the golden harness sets a fixed date, so the files do not change with the day | The files exist and a test compares fresh output to them; a deliberate one-character change to output goes red; the same run on another date gives the same bytes | Code (tests only) | Sonnet |
| U1 | Guard: accept Jira keys only from `hooks.jira_projects` | `agentsfile.py` (`Hooks.jira_projects`, parse, cap 64), `tracking.py` (`check` takes the list; `gh_resolver` stops answering `open` for Jira), `hooks.py` (pass it), `docs/no-hidden-work.md`, `docs/hooks.md`, `examples/agents.local.example.yaml` comment | The three table rows of 7.3, all with the one rule name `issue-unusable`; default denies in block mode; **warn mode and a corrupt or missing mode file allow with a warning**; no lookup for an unlisted project; parse errors with key paths; `MY_PROJ-1` stays unparseable | Code | Sonnet + Codex |
| U2a | Schema: method, phase field, gates, approvers | `schema.py` (`Process`, `Gate`, `Approver`; `_parse_process` for `method`, `active_statuses`, `dependencies`, `phase_field`, `approvers`, `gates`; per-repository `method`; cross-checks: phase field, last-phase gate, `add_closed_days` >= 1, reference-in-repositories for gates; caps), `docs/board-yaml.md` | The messages of 2.5 for these keys; caps at N and N+1; hostile YAML in the subtree; a load error per gate reference with no request made; U0 golden equality for both examples with and without `process: {method: agile}`; the changed `unknown key` text | Code | Sonnet + Codex (untrusted input) |
| U2b | Schema: the baseline and its changes | `schema.py` (`Baseline`, `Change`; reference-in-repositories for `approved_in`, `items`, `add`, `remove`; each `approved_in` cited once and never a gate; the freeze issue not a gate; caps 5,000 and 500) | The remaining messages of 2.5; a load error per reference kind with no request; duplicate and gate-as-approval errors; cap+1 | Code | Sonnet + Codex (untrusted input) |
| U3 | Approval reader | new `src/safo/approvals.py`: batched aliased reads of issues by reference (state, `createdAt`, `lastEditedAt`, title and body for the entry-binding check only, canonical repository, `timelineItems(itemTypes: CLOSED_EVENT, last: 1)` with `stateReason`, `closer { __typename }`, `duplicateOf { id }`, actor typename, login, `databaseId`, time) plus the REST `closed` event read for `performed_via_github_app`; a pure `verdict()` implementing the eight-line approval test (and 4b); fake GitHub fixtures; first live read-only check of `closer` | Passed, open, reopened and re-closed (newest close), not planned, duplicate, **merged pull request closes the gate and it stays open**, `Commit` and `ProjectV2` closers, closed through an App (REST), every actor row, edited after approval, change issue created before `frozen`, **an approval that does not mention its entry**, missing, transferred, pull request, batching at 50, malformed nodes | Code | Sonnet + Codex (identity) |
| U4 | Read the phase field, `stateReason` and archived cards (waterfall only) | `items.py` (`ItemState.phase`, `archived`, `_read_variables`, `mismatched_fields`, `archivedStates` only on a waterfall board; `stateReason` for closed issues), `live.py` unchanged | Read, blank, wrong live type is not asked for and is reported; an archived card is returned and flagged on a waterfall board and absent on an agile one (query text golden); the `items_total` agreement pinned (INFERRED until then) | Code | Sonnet |
| U5a | Audit core: phase presence, G1, G2, integrity lines | new `src/safo/gates.py` (pure: cards, gates, verdicts to lines), `modes/audit.py` wiring, `coverage.not_configured` notes, `UNKNOWN PHASE` (only for cards G1 or G2 read) | Every line of the gate tables; earliest gate only; window edges for G2 and `add_closed_days` 1; reopened gate uses the newest close; not-planned closure is not G2; unknown outranks drift; an old closed card with a renamed Phase option is silent; U0 golden no-change for agile boards | Code (audit); "do not start" stays doctrine | Sonnet + Codex |
| U5a2 | Audit extras: drafts, archived cards, unused statuses | `gates.py`, `modes/audit.py`: G1 and `MISSING Phase` for draft cards on a waterfall default; the archived-card finding and presence for archived cards; the NOTE for statuses nobody checks | A draft in an active status behind an open gate; a draft with no Phase on a waterfall default and none on an agile default; an archived In-progress Build card gives the gate and the archived line; an archived open issue with no Phase is `MISSING Phase`; `In review` left out of `active_statuses` gives the NOTE | Code | Sonnet |
| U5b | Reconcile prints gate findings as `HUMAN` lines | `modes/reconcile.py` (`needs_a_human` reads gates through the read path only), `docs/no-hidden-work.md` | The `HUMAN` line appears and the exit code stays 1; no write is issued for a gate finding; the gate read in reconcile cannot reach the applier | Code | Sonnet + Codex (a read path inside a write-capable mode) |
| U5c | The `PROCESS` header line | `modes/audit.py`: printed only for a non-agile method, naming each gate's approver and close time | Absent for an absent block and for `process: {method: agile}` (byte equal to U0); present and correct for waterfall | Code | Sonnet |
| U6 | Audit: baseline, scope and phase pinning (S1-S5) | new `src/safo/baseline.py`, audit wiring | Every row of the scope table; approval reuse and one-to-one from U3 and U2b; S1 bounded to open non-intake non-done issues; process records excluded; intake default | Code | Sonnet + Codex |
| U7 | Audit: the phase of a pull request (G3), waterfall only | `coverage.py` (a new query for waterfall boards only: `closingIssuesReferences(first: 10)` with ids and count; the body references via the existing `LINK` pattern; `Q_PULL_LINKS` untouched), `gates.py`; optional, unspecified NOTE for a pull request whose linked issues are all earlier than its status implies | Latest of own and inherited; **own early Phase on a pull request linked to a Build issue behind an open gate still yields DRIFT**; a `Refs`-only pull request inherits; a `Refs`-only pull request with no phase is `MISSING Phase`; cleared Phase on the issue; issue parked in Backlog; more than 10 is UNKNOWN | Code (a security control) | Sonnet + Codex |
| U-exp | **Manual** scratch-repository experiment (a human performs the writes) | A scratch repository and a fine-grained token without `issues:write`. Record, in a docs page, whether that token can create, comment on, edit, close or reopen an issue there; whether the maintainer's own token can; and what `ClosedEvent` and the REST event show for each. No `src` change, no automation | The recorded results, with dates; the spec's INFERRED claims in 6.2 are updated to VERIFIED or struck | Doctrine and evidence | The maintainer runs it; Sonnet writes the page. A **hard prerequisite for waterfall adoption** (M7) |
| U-prereq | Protection read-back (read-only) | A read-only check, no `src` change beyond the script and its docs: it reads REST branch protection or rules for the default branch and exits non-zero unless **all** hold: code-owner review required; the `CI green` check required and the branch required to be up to date (or a merge queue); administrators included (`enforce_admins`); no bypass allowance or bypass actor for the agent account (given as `--agent-login`) and none for administrators the agents may use; force pushes and deletions off; CODEOWNERS covers `board.yaml`, `.github/CODEOWNERS` and `.github/workflows/`. **Why up to date**: without it two pull requests citing one approval issue can both go green and both merge, leaving a duplicate `approved_in` on `main`, which is a load error and makes every audit exit 2 (a self-inflicted outage). It never writes (no mutation, no issue created, no token scope beyond read) | Red against a repository without protection (SAFO `main` today, VERIFIED 404); one fixture per failing condition (no code-owner review, no up-to-date requirement, `enforce_admins` off, a bypass actor, a missing CODEOWNERS path); green against a fully protected fixture; a test that the script issues only GET requests. REST field names are INFERRED until the fixtures are checked against a live protected scratch repository | Code and doctrine | Sonnet + Codex (a security control). The setting itself is the maintainer's to apply (M8) |
| U8a | `safo process diff BASE HEAD` (offline) | new `src/safo/modes/process.py`, `docs/board-yaml.md`. **Scope**: runs only when BASE or HEAD has a waterfall repository; an all-agile pair is untouched (exit 0, one line saying so). **Protected paths** (`.github/workflows/`, `.github/CODEOWNERS`, `board.yaml`): a change prints `NOTE    protected path changed: <path>; code-owner review required` and does **not** exit 1 by itself, so a Dependabot action bump and an ordinary board edit pass; the code-owner review is what holds them. **Governed keys** (`process.*`, `repositories` membership and `method`, `rules.add_closed_days`, `rules.status`, `agents.working`, the phase field's options): deny-by-default, so only these pass: append a `changes` entry with a fresh `approved_in`; add a gate for a phase that has none, with a fresh issue; remove an approver while one remains; narrow `baseline.intake`; widen `active_statuses`; set `dependencies` from `none` to `blocked_by`; append a phase option; raise `add_closed_days`; turn a repository to waterfall; a parsed-equal edit. Everything else on a governed key exits 1 as `DENY <path>: not on the allowlist`, including every case in the R2 row and a gate-`issue` swap. **First creation** is intentional friction, defined: the first appearance of `process` with a waterfall repository, and the first appearance of `baseline` (with its `items`), pass with `NOTE    waterfall introduced (or baseline created); review it as a whole`; they are stricter than before, and the audit (S5) still needs the freeze issue approved. Once a baseline exists, `frozen`, `items` and `approved_in` are fixed except through `changes`, and removing `process` or `baseline` exits 1 | One test per R2 weakening and one for an unlisted change kind; one per allowlisted change passing; a Dependabot-style workflow-only change exits 0 with the NOTE; an all-agile pair exits 0; first creation of `process` and `baseline` passes with the NOTE; removal exits 1; no network; invalid input exits 2 | Code (a security control) | Sonnet + Codex |
| U8b | `--verify` (token path) | `modes/process.py`: an opt-in flag that needs a read token. It checks, for each new `approved_in`, the approval test through U3 (so it **depends on U3**), that the issue was closed after the **pull request's creation time** (read from the API; the clock source is the PR, not a commit date, M12), and the entry-binding of line 8. A fork pull request has no token and cannot run it | Closed before the PR was created fails; closed after passes; a rebase or squash does not change the clock; the check is not run without a token and says so; no token value in any output | Code (a token path) | Sonnet + Codex |
| U8c | The GYST workflow (in git-your-ship-together; its own issue there) | A reusable workflow, or an input of `python-ci`, that runs U8a on every pull request touching the board files, **runs U8b whenever a token exists** (same-repository pull requests; mandatory, M12), and for a fork pull request runs the offline check only and labels the result advisory; optional `issues: closed` re-run (3.2, option c); this repository's caller is pinned by commit | A same-repository run executes `--verify`; a fork run does not and is labeled; the caller is under the protected paths | Code (workflow) | Sonnet + Codex |
| U9 | Audit: the dependency rule D1 | new `src/safo/dependencies.py`, audit wiring | Open blocker, closed blocker, over 20, unreadable blocker, rule off reads nothing | Code | Sonnet |
| U10 | Status update: the Phases and gates section (waterfall only) | `statusgroups.py` (`Row.phase`, a pure section builder), `modes/status.py` (the query adds the phase field **only on a waterfall board**) | Golden body for a waterfall fixture; agile body and query unchanged; no titles in the section; counts | Code | Sonnet |
| U11 | Docs and examples | new `docs/process-methods.md` ("Choose a process method", the phase-list procedure, the order of a change, the freeze issue, the gates repository, what audit cannot enforce), links in `README.md` and `docs/home.md` (required by `tests/test_readme_links.py`), `docs/why.md` and `docs/board.md` wording ("the fields are a choice; the rule is the constant"), `examples/process-waterfall.yaml` with `ui_only` for the Roadmap and `add_closed_days: 30` | `test_examples.py` loads the new example; link tests | Doctrine (the docs) | Sonnet, or Haiku for the link edits |
| U12 | Tracker protocol with GitHub as its implementation | `src/safo/trackers/` (protocol, GitHub wrapper), modes call through it; no behavior change | U0 golden outputs unchanged; protocol conformance tests | Code | Sonnet; **stage 5, not the first cut** |
| U13 | NOTE: an open gate past its milestone's due date | `gates.py`, the gate read adds `milestone { dueOn }` | Overdue, not overdue, no milestone | Code | Sonnet; optional |

**Order.** Stage 0: U0 (before any change to `src/`). Stage 1: U1 (independent; ship first) and U2a, then U2b. Stage 2: U3
(needs nothing but the fake GitHub) and U4 (needs U2a). Stage 3: U5a (needs U2a, U3, U4), then U5a2, U5b and U5c. Stage
4: U6 (needs U2b, U3, U5a) and U7 (needs U5a); **U-exp and U-prereq** (any time, both before U8 and before any real
waterfall board); U8a (needs U2a, U2b, U6 and U-prereq, per M8), then U8b (needs U3, U8a), then U8c (needs U8a and U8b;
a different repository); U9 (needs U2a); U10 (needs U4 and U5a); U11 (last, documents what merged). U13 after U5a,
optional. Stage 5, not committed to a date: U12, then a Jira resolver, which needs its own threat-model update (8, R5 and
R6 made concrete against Atlassian's documentation), the maintainer's decision on credentials, and a Codex pass.

**Review gates.** Every unit: Sonnet review against its tests and `make check` exit 0. Codex adversarial pass before
merge: U1, U2a, U2b, U3, U5a, U5b, U6, U7, U-prereq, U8a, U8b, U8c. A whole-branch review after stage 4, before the docs
unit, that reads the gate, scope, G3 and diff code together, because the bypasses in R2, R3 and R13 cross units.
