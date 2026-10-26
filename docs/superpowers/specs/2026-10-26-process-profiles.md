# Process profiles: Agile and Waterfall on one board-as-code core, and a tracker seam for Jira: design

**Status:** draft, revision 1, for the maintainer's review, 2026-10-26.
**Scope:** SAFO #108. The maintainer's ruling, 2026-10-26: "allow flexibility for both Agile and Waterfall work, and
eventually look at working with Jira too." The issue comment of the same day (a MEDIUM finding from the push security
review) on the shape-only Jira key is folded into sections 7 and 8.
**No code in this document.** It names files, keys, rules, messages and tests. Section 11 is the build plan; nothing in it
is started by this document, and every build issue links back to #108.

Every claim about today's code is marked **VERIFIED** (the file was read for this spec, with its line numbers on
`origin/main` at 6796e9f) or **INFERRED** (reasoned, not read or not run). Claims about GitHub's API carry their source.

## Why

SAFO's rule is a constant: no hidden work. Everything else is a choice that happens to be agile-shaped today: the status
names, the sprint field, the "Next" column, the end-of-sprint status update. A waterfall program (phases, gates, a frozen
scope baseline with change control) can already describe most of its board in `board.yaml`, but it cannot say "nobody
starts Build work while the Design gate is open", and nothing reads such a rule. This design adds that, keeps every
existing board byte-for-byte unchanged, and fixes the seam a Jira tracker would later plug into.

## Rulings carried over

- `board.yaml` is the single source of a board's shape (v0.1.0 design, `2026-10-07-safo-design.md`). A profile is a key
  in it, not a second file.
- Exit codes stay 0 clean, 1 drift, 2 cannot tell, and "cannot tell" outranks drift (VERIFIED `audit.py:28-33`,
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
| Status and field names | VERIFIED `schema.py:120-129`, `schema.py:416-460` | `status_field`, `area_field`, `done_date_field` and every status are configurable |
| Statuses and options | VERIFIED `schema.py:351-392` | Any single-select field, any options; iteration, date, text, number fields |
| Tracking fields | VERIFIED `schema.py:96-106`, `coverage.py:53-57` | Kind, Epic and Effort are names; any type; empty turns a check off |
| The no-hidden-work audit | VERIFIED `audit.py:99-112`, `coverage.py:152-207` | Linked issue, card presence, field presence: none of it knows about sprints |
| The dispatch guard | VERIFIED `hooks.py:381-387`, `tracking.py:183-213` | Reads a brief's `issue:` line and an issue's open state only |
| Routing | INFERRED from `docs/routing.md` and the absence of any board read in `routing.py` | Picks an agent by task shape; never reads the board |
| `agents-status` | VERIFIED `agents_status.py:43-59` | Groups by `agents.working` and `agents.waiting`, both from `board.yaml` |

### 1.2 What is agile-shaped

| Part | Evidence | The shape |
|---|---|---|
| Default statuses | VERIFIED `schema.py:86-93` | `opened` and `reopened` default to `Backlog`, `closed`/`merged` to `Done` |
| Default working set | VERIFIED `schema.py:132-136` | `agents.working` defaults to `In progress`, `Next`; `waiting` to `Blocked` |
| Default tracking fields | VERIFIED `schema.py:103-105` | `Kind`, `Epic`, `Effort` (Epic and Effort are Scrum words; the checks are not) |
| Status-update groups | VERIFIED `statusgroups.py:60-70`, `statusgroups.py:139-141` | "In progress" is the first of `agents.working`, every other working status is "Next" |
| Headline prompt | VERIFIED `headline.py:35` | The local-model prompt says "Next" |
| Maintainer agent value | VERIFIED `status.py:329` | `--human-agent` defaults to `You` |
| Board-less Action mode | VERIFIED `compat.py:58-69` | Defaults `Backlog`, `In progress`, `Done` |
| This project's example | VERIFIED `examples/safo.yaml:30`, `:55`, `:75` | "Next: scheduled for the current or next sprint", a 14-day `Sprint` iteration, `working: [In progress, Next]` |
| The docs | VERIFIED `docs/board.md:13` ("the sprint is the unit of Next"), `docs/board.md:30-33`, `docs/no-hidden-work.md:5` ("That is the point of Agile") | The words, not the mechanism |

### 1.3 What is missing for waterfall

- No phase concept and no gate: nothing reads an ordering of phases or an approval (VERIFIED: no such key in
  `schema.py:299-304`, the full list of top-level keys, and unknown keys are refused at `schema.py:253-257`).
- No scope baseline and no change record.
- No dependency read. GitHub's live schema has native issue dependencies: `Issue.blockedBy` and `Issue.blocking`
  (`IssueConnection`, with `first`/`after`), and the mutations `addBlockedBy`/`removeBlockedBy` (VERIFIED by schema
  introspection, 2026-10-26 12:37 EDT). The project field types are `ASSIGNEES, LINKED_PULL_REQUESTS, REVIEWERS, LABELS,
  MILESTONE, REPOSITORY, TITLE, TEXT, SINGLE_SELECT, MULTI_SELECT, NUMBER, DATE, ITERATION, TRACKS, TRACKED_BY,
  ISSUE_TYPE, PARENT_ISSUE, SUB_ISSUES_PROGRESS, CREATED, UPDATED, CLOSED` (VERIFIED, same introspection): there is no
  blocked-by **project field**, so the issue's statement holds for the board and not for issues. Whether `blockedBy`
  can point across repositories or owners, and the token permission it needs, is INFERRED (unverified).
- A Roadmap view's date fields, zoom and grouping cannot be set by any API (VERIFIED `docs/lessons.md:25-29`); SAFO
  lists them under `ui_only` (VERIFIED `audit.py:149-152`).
- The live field reader keeps types it does not map as GitHub's raw data type (VERIFIED `live.py:63-69`, `live.py:206-207`),
  and `board.yaml` can declare only `single_select, iteration, date, text, number` (VERIFIED `schema.py:26`). A built-in
  Milestone column is therefore a UI choice, not something `board.yaml` can declare.

### 1.4 The Jira seam today

- A reference is `owner/repo#N` or a Jira-style `KEY-N` (VERIFIED `tracking.py:24-26`, `tracking.py:50-59`).
- The resolver returns `open` for any non-GitHub reference without a lookup (VERIFIED `tracking.py:141-143`), so a made-up
  key passes the guard. The operator's repository list applies to GitHub references only (VERIFIED `tracking.py:201-203`).
  This is the MEDIUM finding of 2026-10-26.
- The Jira field mapping is documented and tracker-neutral (VERIFIED `docs/no-hidden-work.md:93-111`). Nothing calls Jira.

## 2. The process profile

### 2.1 What a profile is

A **process profile** is a named set of rules that code applies on top of the fields `board.yaml` already declares. It
does not create fields, rename statuses or inject defaults. The status set stays in `fields`, the event mapping in
`rules.status`, the working set in `agents`, exactly as today. A profile decides four things:

| A profile sets | `agile` | `waterfall` |
|---|---|---|
| Planning unit | iteration (any iteration field, optional, never required: today's behavior) | phase (`process.phase_field`, required) |
| Extra audit rules | none | phase presence, gate order, scope baseline, baseline phase pinning |
| Optional neutral rules | dependency check (off by default) | dependency check (off by default) |
| Status-update shape | today's four groups | today's four groups plus a "Phases and gates" section |

**Why not a profile that also sets the status set and transitions.** Two reasons. Board-as-code means the file says
everything; a status set hidden behind a profile name is a second source a reviewer cannot see in the diff. And
transitions cannot be enforced: GitHub Projects exposes a card's current field values, and no field-change history is
read by SAFO today (VERIFIED: no history query in `items.py` or `live.py`); whether the API offers one at all is INFERRED
(not found, not searched exhaustively). A transition table SAFO cannot check is doctrine dressed as code. What audit can
check is a **state invariant** (a card in this phase and this status while that gate is open), and that is what the
waterfall rules are. The example files (section 10) carry each method's status set.

A "none" planning unit (Kanban flow) needs no profile: it is `agile` with no iteration field, which works today.

### 2.2 Declaring it in `board.yaml`

A new optional top-level key, `process`. `version` stays `1`: the key is additive. An older `safo` reading a file that
has it refuses it as an unknown key (VERIFIED `schema.py:253-257`), which fails closed: an old binary can never audit a
waterfall board and call it clean while ignoring its gates.

Agile, stated explicitly (identical in effect to leaving `process` out):

```yaml
process:
  profile: agile
```

Waterfall, complete:

```yaml
process:
  profile: waterfall            # agile (default) | waterfall
  active_statuses: [In progress, In review]   # default: the first entry of agents.working
  dependencies: none            # none (default) | blocked_by; not `off`, which YAML reads as false
  phase_field: Phase            # a single_select in fields; its option order is the phase order
  approvers: [maintainer-login] # GitHub logins whose closing of a gate or change issue counts as approval
  gates:                        # the exit gate of a phase: work in a later phase waits for it
    - {phase: Requirements, issue: acme/program#1}
    - {phase: Design, issue: acme/program#2}
    - {phase: Build, issue: acme/program#3}
    - {phase: Verify, issue: acme/program#4}
  baseline:
    frozen: 2026-11-02          # the day scope was frozen
    approved_in: acme/program#1 # the issue whose approved closing froze it (here, the Requirements gate)
    intake: [Backlog]           # statuses that are not "in scope" yet; default [rules.status.opened]
    items:
      - {ref: acme/app#12, phase: Design}
      - {ref: acme/app#13, phase: Build}
    changes:
      - {add: acme/app#55, phase: Build, approved_in: acme/program#21}
      - {remove: acme/app#13, approved_in: acme/program#22}
```

Per repository, for mixed mode (section 5):

```yaml
repositories:
  - {owner: acme, name: program, default_area: Program}
  - {owner: acme, name: app, default_area: App}
  - {owner: acme, name: mobile, default_area: Mobile, process: agile}   # an agile team inside the program
```

### 2.3 Keys and defaults

| Key | Default | Kind | Meaning |
|---|---|---|---|
| `process` | absent = `{profile: agile}` | mapping | |
| `process.profile` | `agile` | neutral | `agile` or `waterfall`: the default for every repository |
| `process.active_statuses` | first of `agents.working` | neutral | Statuses that mean "being worked"; the gate and dependency rules read them. The default matches the "In progress" group of the status update (VERIFIED `statusgroups.py:70`) |
| `process.dependencies` | `none` | neutral | `blocked_by` turns on the dependency rule (3.2) |
| `process.phase_field` | none | waterfall | Required when any repository is waterfall |
| `process.approvers` | `[]` | waterfall | Empty: the approver check is not configured, and audit says so (3.2) |
| `process.gates` | `[]` | waterfall | Empty: the gate check is not configured, and audit says so |
| `process.baseline` | absent | waterfall | Absent: the scope check is not configured, and audit says so |
| `repositories[i].process` | `process.profile` | | `agile` or `waterfall` for that repository's cards |

"Waterfall keys" are accepted only when `process.profile` or some `repositories[i].process` is `waterfall`.

### 2.4 Byte-for-byte compatibility

A file without `process` loads to a `Board` whose new `process` attribute is the default `Process()` value, and every
code path that reads it does nothing for an all-agile board: no new query, no new output line, no new note. The test is a
golden one: `audit`, `reconcile --dry-run`, `status --post --print` and `agents-status` against the fake GitHub for
`examples/safo.yaml` and `examples/renegade-penguin.yaml` produce identical output before and after, and so does the same
file with `process: {profile: agile}` added. The board-less Action mode (VERIFIED `compat.py:47-82`) builds a `Board`
with the default and gets no profile input in the first cut.

### 2.5 Validation

Every error is a `ConfigError` (exit 2, VERIFIED `errors.py:13-20`) whose message starts with `<file>: <key path>:`, like
every existing one (VERIFIED `schema.py:245-246`). The messages, exactly:

| Input | Message |
|---|---|
| `profile: kanban` | `board.yaml: process.profile: 'kanban' is not one of agile, waterfall` |
| `repositories[2].process: hybrid` | `board.yaml: repositories[2].process: 'hybrid' is not one of agile, waterfall` |
| waterfall with no `phase_field` | `board.yaml: process.phase_field: required when a repository is waterfall` |
| `phase_field` names no field | `board.yaml: process.phase_field: names field 'Phase', which is not in fields` |
| `phase_field` is a text field | `board.yaml: process.phase_field: field 'Phase' is text, not single_select` |
| waterfall key on an all-agile board | `board.yaml: process.gates: only used when the profile or a repository is waterfall` |
| a status not in the status field | `board.yaml: process.active_statuses[0]: 'Doing' is not an option of 'Status'` |
| a done status as active | `board.yaml: process.active_statuses[1]: 'Done' is a done status (rules.status.closed or merged)` |
| `dependencies: off` | `board.yaml: process.dependencies: False is not one of none, blocked_by` (`off` loads as a boolean, as `docs/board-yaml.md:9-10` warns) |
| bad login | `board.yaml: process.approvers[0]: 'two words' is not a GitHub login` |
| unknown phase | `board.yaml: process.gates[1].phase: 'Buld' is not an option of 'Phase' (options: Requirements, Design, Build, Verify, Release)` |
| two gates for a phase | `board.yaml: process.gates[2].phase: phase 'Design' has a gate already (gates[1])` |
| bad reference | `board.yaml: process.gates[0].issue: expected owner/repo#N` |
| gate repository not on the board | `board.yaml: process.gates[0].issue: acme/elsewhere is not in repositories` |
| a reference listed twice | `board.yaml: process.baseline.items[4].ref: acme/app#12 is listed twice` |
| a change with both or neither | `board.yaml: process.baseline.changes[0]: expected exactly one of add, remove` |
| an add with no phase | `board.yaml: process.baseline.changes[0].phase: required with add` |
| intake names a done status | `board.yaml: process.baseline.intake[0]: 'Done' is a done status` |
| a cap exceeded | `board.yaml: process.baseline.items: at most 5000 entries` |

References use the guard's own pattern (VERIFIED `tracking.py:25`) with `fullmatch`. Caps, so a hostile file cannot turn
one audit into thousands of API calls: 16 phases (options of the phase field), 32 gates, 32 approvers, 16 active
statuses, 5,000 baseline items, 500 changes. The existing loader limits (1 MiB, depth 64, no aliases, anchors, merge keys
or duplicate keys; VERIFIED `schema.py:156-235`) cover the block unchanged.

## 3. The two profiles

### 3.1 Agile (today, unchanged)

Exactly the current behavior. Planning unit: an iteration field if the board declares one (`Sprint` in
`examples/safo.yaml`), which `bootstrap` creates and `audit` compares (VERIFIED `audit.py:70-78`); nothing requires a card
to hold one. The optional dependency rule (3.2) is the only addition an agile board can opt into.

### 3.2 Waterfall

**Planning unit: the phase.** `process.phase_field` names a single-select field; its options, in `board.yaml` order, are
the phases in order. The order comes from the file, not the live project: the live order can differ and audit already
reports that as a note (VERIFIED `audit.py:61-62`).

**Gates: an issue, listed in `board.yaml`.** The three candidates:

| | Gate issue (chosen) | Field on cards | Milestone |
|---|---|---|---|
| Visible as work | Yes: it is a card, covered by no hidden work | No | Partly (not a card) |
| Who approved | Readable: the last `ClosedEvent`'s `actor` (`__typename`, `login`) and `stateReason` (VERIFIED schema introspection: `ClosedEvent` has `actor`, `stateReason`, `createdAt`; `Actor` is `Bot`, `EnterpriseUserAccount`, `Mannequin`, `Organization` or `User`; `IssueStateReason` is `REOPENED, NOT_PLANNED, COMPLETED, DUPLICATE`; `Issue.timelineItems` takes `itemTypes` with `CLOSED_EVENT`) | Not readable: a field value has no author SAFO can read | Not readable: `Milestone` has `creator` but no closer (VERIFIED: its field list) |
| Spans repositories | Yes: one issue gates the program | Yes | No: a milestone belongs to one repository, so a program needs one per repository kept in step |
| Created by API | Yes | Yes | INFERRED no GraphQL mutation (none matched "Milestone" in the mutation list); REST only |
| Discussion and evidence | The issue thread | None | The description |
| Re-gating | Reopen it | Edit the field | Reopen it |

The gate issue wins because it is the only one that records **who** approved, in a form audit can read, and because it
obeys the rule this project exists for: the gate is itself visible work. A milestone stays useful as a **date carrier**
for the schedule (3.4), never as the gate. Gates are listed in `board.yaml`, not discovered by a label: a label anyone
with triage rights can add or remove would let a fake gate in or a real gate out, while the list changes only through a
reviewed change to the file (section 8, R2).

A gate is **passed** when its issue is closed, the last `ClosedEvent` has `stateReason: COMPLETED`, and its actor is a
`User` whose login is in `process.approvers` (any login when the list is empty, with a note). It is **open** otherwise:
open, reopened, closed as not planned or duplicate, or closed by someone not in the list, or by a `Bot`.

**The gate rule, exactly.** Phases `P1 .. Pn` in order; `G(k)` the gate of `Pk`, if one is listed. For each card `c` on
the board whose content is in a listed repository, whose Phase is `Pj`, and for every `k < j` with `G(k)` listed and
not passed:

- **G1 (active ahead of a gate).** If `c`'s status is in `active_statuses`:
  `DRIFT   GATE acme/app#41 is In progress in phase Build while the Design gate acme/program#2 is open`
- **G2 (finished ahead of a gate).** If `c` is closed or merged, and its close date is on or after
  `today - rules.add_closed_days` (the window audit already reads, VERIFIED `coverage.py:157-161`), and either `G(k)` is
  not passed or `c` closed before `G(k)`'s approving close:
  `DRIFT   GATE acme/app#38 was done on 2026-11-02 in phase Build before the Design gate acme/program#2 passed`

The rule is the same for every repository, agile or waterfall: a card that carries a Phase has declared itself part of
the program (section 5). One finding per card names the earliest open gate only, so a card ahead of three open gates is
one line, not three.

**Gate integrity lines.**

| Situation | Line | Exit |
|---|---|---|
| Closed by a login not in `approvers` | `DRIFT   GATE acme/program#2 (Design gate) was closed by octocat, who is not in process.approvers; it counts as open` | 1 |
| Closed by a `Bot` | `DRIFT   GATE acme/program#2 (Design gate) was closed by a bot (name[bot]); an approval is a person's; it counts as open` | 1 |
| Closed as not planned or duplicate | `DRIFT   GATE acme/program#2 (Design gate) was closed as not planned; it counts as open` | 1 |
| A pull request, not an issue | `DRIFT   GATE acme/program#2 (Design gate) is a pull request; a gate is an issue` | 1 |
| Not found, or not readable with the token | `UNKNOWN GATE acme/program#2 (Design gate) cannot be read with this token, so no card's gate order can be told` | 2 |
| Transferred (canonical repository differs) | `UNKNOWN GATE acme/program#2 (Design gate) now answers as acme/other#9; update process.gates` | 2 |
| The gate issue's own Phase differs from its gate's phase | `NOTE    GATE acme/program#2 is the Design gate but its Phase is Build` | 0 |
| `approvers` empty | `NOTE    Gate approver check not configured: process.approvers is empty, so any person's close counts` | 0 |
| `gates` empty on a waterfall board | `NOTE    Gate check not configured: process.gates is empty` | 0 |
| The phase field's live type differs | `UNKNOWN GATE the Phase field is text on the project, not single_select; gate order cannot be told` | 2 |

An unreadable gate is UNKNOWN, never a pass: an audit that cannot read a gate cannot say any later-phase card is fine.
Logins and titles from GitHub reach the log only through `ctx.say`, which escapes every line (VERIFIED
`context.py:29-31`).

**Phase presence.** In a waterfall repository, an open issue whose status is not in `baseline.intake` (or not
`rules.status.opened` when there is no baseline) and has no Phase is `MISSING Phase on acme/app#41`, the existing format
(VERIFIED `coverage.py:203`). Pull requests are not asked to carry a Phase: a pull request takes the latest phase of the
issues it links (G3 below), so nobody types a Phase twice. Issues referenced as gates or as `approved_in` are excluded
from phase presence and from the scope rule; they are process records, not scope.

**G3 (pull requests).** A pull request card with no Phase of its own takes the latest phase among the board cards of the
issues it closes (`closingIssuesReferences`, read with node ids, first 10; VERIFIED the connection exists and is read
today for a count at `coverage.py:31`). More than 10 linked issues: `UNKNOWN GATE acme/app#77 links more than 10 issues;
its phase cannot be told`. With that phase it is checked by G1 and G2 like any card.

**The frozen-scope baseline and change control.** The baseline is `process.baseline` in `board.yaml`: a date, the
approval that froze it, the items with the phase each was baselined in, and a list of changes. A change is one entry
plus one approval issue. That is the whole process: open an issue ("Change: add acme/app#55 to Build"), an approver
closes it as completed, and a pull request adds the `changes` entry citing it. The pull request's review is the second
record. Nothing reads change lines out of issue bodies, so no free text from an issue becomes scope.

Audit reads (scope set = `items` + `add`s − `remove`s, each change counted only when its `approved_in` is passed, same
test as a gate):

| Rule | Line |
|---|---|
| **S1** an issue of a waterfall repository, not in `intake`, not closed as not planned, is outside the scope set | `DRIFT   SCOPE acme/app#55 is In progress but not in the baseline of 2026-11-02; record an approved change (process.baseline.changes)` |
| **S2** a scope-set issue closed as not planned with no approved `remove` | `DRIFT   SCOPE acme/app#13 is in the baseline and was closed as not planned; record the removal as an approved change` |
| **S3** a change whose approval is not passed | `DRIFT   SCOPE the change adding acme/app#55 cites acme/program#21, which is open; the change is not approved` |
| **S4** baseline phase pinning: a scope-set issue whose board Phase differs from its baselined phase | `DRIFT   PHASE acme/app#12 is in Build on the board but Design in the baseline; move it back or record a change` |
| **S5** `baseline.approved_in` itself not passed | `DRIFT   SCOPE the baseline cites acme/program#1, which is not approved; the baseline is not frozen` |
| an item or change names a pull request | `DRIFT   SCOPE acme/app#60 is a pull request; the baseline lists issues` |
| an item or change cannot be read | `UNKNOWN SCOPE acme/app#12 cannot be read with this token` |

S4 is what stops the cheapest dodge of the gate rule: an agent moving its card's Phase back to an earlier, already
passed phase. A change entry may carry a new `phase` for an item already in scope, which is how a re-phase is approved.

**Dependencies: native `blocked_by` links, not a convention.** A text convention (`depends-on: acme/app#30` in a body)
is free text audit would have to parse and anyone can edit silently; the native links are typed, readable and shown in
GitHub's UI (VERIFIED existence; see 1.3). With `process.dependencies: blocked_by`, for each card in `active_statuses`
whose content is an issue, audit reads `blockedBy(first: 20) { totalCount nodes { number state repository {
nameWithOwner } } }`:

- **D1** `DRIFT   DEPENDS acme/app#41 is In progress but is blocked by acme/app#30, which is open`
- more than 20: `UNKNOWN DEPENDS acme/app#41 has more than 20 blockers; they were not all read`
- a blocker the token cannot read: `UNKNOWN DEPENDS acme/app#41 is blocked by an issue this token cannot read`

What audit **can** enforce: an active card with an open blocker it can read. What it **cannot**: that the links are
complete or correct, lead and lag times, dependencies on a pull request (`blockedBy` returns issues only, VERIFIED the
connection type is `IssueConnection`), dependencies held in another tracker, or anything in a repository the token
cannot read. The docs say so in those words.

**The status update.** Code-built like today. A waterfall board adds one section after "Next":

```
**Phases and gates**
- Requirements: gate acme/program#1 passed 2026-11-02 (0 active, 14 done)
- Design: gate acme/program#2 open (3 active, 5 done)
- Build: no gate (2 active, 0 done) - 1 card ahead of an open gate
```

Every number is counted in `statusgroups.py`; titles never appear in this section; the headline prompt and the fixed
prose clauses (VERIFIED `statusgroups.py:97-103`) are unchanged.

### 3.3 Exit codes

Unchanged: every new finding is DRIFT (1) or UNKNOWN (2) or NOTE (0), and UNKNOWN outranks DRIFT (VERIFIED
`audit.py:28-33`). `reconcile` and `sync` never act on a gate, scope or dependency finding: they stay mechanical (VERIFIED
the plan has no such kind, `plan.py:56-81`). Reconcile prints the same findings as `HUMAN` lines so its exit code stays 1
while one is open, as it does for a missing Epic today (VERIFIED `docs/no-hidden-work.md:15`).

### 3.4 Schedule views: documented and manual

A waterfall schedule lives in fields SAFO already supports: `Start date` and `Target date` date fields on cards, and
optionally a milestone per phase whose `dueOn` carries the phase date (VERIFIED `Milestone.dueOn` in the schema). The
Roadmap view's date fields, zoom, grouping by Phase and milestone markers are set by hand: the waterfall example lists
them under `ui_only`, so `bootstrap` prints the checklist and `audit` repeats it. SAFO computes no schedule, no critical
path and no slip. The one schedule read considered, an open gate past its milestone's due date as a NOTE, is unit U13,
optional and last.

## 4. Neutral and per-rule summary

| Rule | Profile | Reads | Code or doctrine |
|---|---|---|---|
| Phase presence | waterfall repos | phase field | code (audit) |
| G1, G2 gate order | any card with a Phase | phase, status, gate close events | code (audit) |
| G3 pull request phase | pull requests | closing references | code (audit) |
| S1-S5 scope and pinning | waterfall repos | baseline, approval close events | code (audit) |
| D1 dependencies | opt-in, any profile | `blockedBy` | code (audit) |
| "Do not start work behind an open gate" | waterfall | nothing | doctrine; audit finds the breach after the fact |
| "Agents never close a gate or change issue" | waterfall | nothing | doctrine; R1 |
| Roadmap set-up | any | nothing | `ui_only` checklist |

## 5. Mixed mode

**Decision: per repository, with the board's profile as the default.** Compared:

| | Board | Repository (chosen) | Area |
|---|---|---|---|
| Fits "agile teams inside a waterfall program" | No: one board would need two | Yes: a team's repository is agile, the program's are waterfall | Yes |
| What decides a card's profile | Nothing per card | The card's repository, a fact GitHub returns and audit already canonicalizes (VERIFIED `items.py:317-323`) | A project field anyone with project write can change, filled from a title substring by `area_rules` (VERIFIED `rules.py:59-65`) |
| Dodge by an agent | n/a | Needs a `board.yaml` change, reviewed | Edit the Area of one's own card |
| Drafts | n/a | A draft has no repository: not checked, as today (VERIFIED `coverage.py:204-206`) | A draft has whatever Area was typed |

Area loses because it is agent-writable state: keying a gate rule on it lets the card being checked choose its own rules.
The board level alone cannot express the case the maintainer named.

**What an agile repository inside a waterfall program gets.** Its cards are not asked for a Phase and are outside the
scope baseline. When one of its cards does carry a Phase (the team is delivering into Build), G1 to G3 apply to it like
any other: a phase value is a declaration, and the gate holds whoever makes it. A team cannot be pulled into the gate rule
by accident, and cannot leave it by flipping a field once its work is baselined (S4 covers baselined items only; an
agile repository's cards are never baselined, so for them clearing the Phase is a visible choice, counted in the status
update's Phases section as "no phase").

## 6. Routing and hooks need no profile awareness

Answering the issue's question, with reasons:

- **Routing** picks an agent for a task shape. A phase changes what work is allowed to start, not who is best at it.
- **The dispatch guard** checks that a brief names an open issue, inside a 10-second hook budget with a 2-second margin
  (VERIFIED `docs/no-hidden-work.md:37-39`). Checking the gate there would add a project read (field values, the gate
  issues' close events) to every dispatch, a new failure mode that fails closed in block mode, and a board file the hook
  does not read today. Audit catches the breach on the next scheduled run, and the gate rule is about the board, which
  is audit's job.
- **Later, if wanted:** a guard rule that denies a brief whose issue is in a phase behind an open gate. It would need
  the board file in the hook's trusted configuration and a cached, time-bounded read. Not in this design.

The one guard change here is about trackers, not profiles: section 7.3.

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
`sync.py:26`, `sync.py:253`) and `collect_work` (VERIFIED `items.py:451`). The modes call the protocol; nothing in `audit`, `reconcile`
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
  model (INFERRED it can be reused; it was not read for this spec), no redirect followed with the credential.
- Only keys and status names leave GitHub for Jira. Only keys and status names come back into GitHub-visible places: a
  Jira title is never written into a public project, a status update or a log line.
- The guard's lookup runs inside the same `remaining()` budget as `gh` (VERIFIED `tracking.py:133-147`).

### 7.3 The shape-only key, now (unit U1)

Today a made-up `KEY-1` passes (1.4). The fix, analogous to `hooks.tracking_repos` (VERIFIED `agentsfile.py:140-142`,
`tracking.py:201-203`), in `agents.yaml`:

```yaml
hooks:
  jira_projects: [OPS, PLAT]   # Jira project keys a brief may cite; empty (the default): no Jira key is accepted
```

| Brief line | `jira_projects` | Result |
|---|---|---|
| `issue: OPS-12` | `[]` (default) | `issue-unverified`: "no Jira resolver is configured, so OPS-12 cannot be checked; list its project in hooks.jira_projects to accept keys of that project by shape" (block denies, warn reports) |
| `issue: OPS-12` | `[OPS]` | accepted by shape; the docs state the residual: a made-up number in a listed project passes |
| `issue: FAKE-1` | `[OPS]` | `issue-unusable`: "FAKE is not an accepted Jira project; accepted: OPS" (no lookup) |

`jira_projects` entries fullmatch the project part of `JIRA_KEY` (VERIFIED `tracking.py:26`), at most 64. When a Jira
resolver exists, a listed project's key is looked up instead of accepted by shape, and the unlisted case stays
`issue-unusable`. Nobody uses Jira keys today (no instance, VERIFIED `docs/no-hidden-work.md:95`), so the stricter default
breaks nothing in use. That is a maintainer decision (M1).

## 8. Threat model

Method: `pack-threat-model`. Covered: this design's new inputs and decisions, and the Jira seam. Not covered: a review of
the existing guard, Action or loader beyond what this design touches; any probing of a live system (none was done; the
only live calls were read-only schema introspection).

### 8.1 Assets

| Asset | Class |
|---|---|
| A1 Integrity of the process record: gate state, approvals, the baseline, the audit's verdict and exit code | integrity |
| A2 The maintainer's GitHub credential with `project` scope, which agents use through his `gh` login | secret |
| A3 A future Jira credential (read for the guard, write for sync) | secret |
| A4 Confidential Jira content (titles, descriptions) of a future private instance | confidential |
| A5 The guard's allow or deny decision, and its log | integrity |
| A6 CI minutes and API rate budget | availability |

### 8.2 Actors

The maintainer (trusted); an agent (Claude, Codex, Copilot) acting with the maintainer's token or its own App identity;
a collaborator with project write or triage rights; a contributor with a fork pull request; a compromised dependency in
the Action's job; a model reading attacker-written issue text; a future Jira user or administrator.

### 8.3 Trust boundaries

- B1 A pull request's `board.yaml` to the audit that reads it: the rules are in the change being checked.
- B2 Project field values (Phase, Status) to audit: writable by anyone with project write, which includes every agent.
- B3 An issue's close event to "approved": the actor is whoever's token closed it.
- B4 An agent's shell to the guard's state and configuration (existing, VERIFIED `docs/no-hidden-work.md:56-59`).
- B5 SAFO to Jira over the network; B6 Jira content to GitHub-visible surfaces (both future).
- B7 YAML text to the loader (existing, extended by the `process` block).

### 8.4 Risk register (ranked: impact first, then how little the actor needs)

| Id | Abuse case | Impact | Prerequisite | Rank |
|---|---|---|---|---|
| R1 | An agent holding the maintainer's token closes a gate or change issue; the close event says the maintainer approved | High: every gate and change is forgeable | None beyond normal agent operation in a single-account setup | 1 |
| R2 | A pull request edits `board.yaml`: drops a gate, switches the profile to agile, adds an approver, adds a baseline item without a change; a PR-time audit reads the edited file and passes | High | Repository write, and a merge (or a CI that trusts the PR's file) | 2 |
| R3 | An agent moves its card's Phase back, clears it, or parks the issue in Backlog while a pull request does the work | Medium: gate rule dodged | Project write (every agent has it) | 3 |
| R4 | A brief cites a made-up `KEY-1`; the guard accepts it by shape (the 2026-10-26 finding) | Medium: hidden work | None | 4 |
| R5 | Future: Jira titles or descriptions copied into a public project, status update or CI log | High for a private instance | A Jira integration that renders text | 5 |
| R6 | Future: an over-scoped Jira token (a user API token with full rights) leaks via a log, a redirect to another host, or an agent's environment | High | Access to the job or agent environment | 6 |
| R7 | An unreadable, deleted or transferred gate or approval issue makes the gate rule silently pass | Medium | Issue delete or transfer rights | 7 |
| R8 | A hostile `process` block (thousands of refs) exhausts the rate budget or the run time | Low to medium | Repository write | 8 |
| R9 | A gate check is skipped (phase field type drift, profile mis-set) and audit says clean | Medium | A field edit in the project UI | 9 |
| R10 | A login or title with control characters forges a log line or workflow command | Low | Any GitHub account | 10 |
| R11 | Profile definitions loaded from files outside `board.yaml` become an injection or path-traversal surface | n/a by design | n/a | closed |

### 8.5 Mitigations and verification

| Id | Mitigation | Verification |
|---|---|---|
| R1 | An approval by a `Bot` actor never counts (agents on an App identity cannot approve). `approvers` lists people. Doctrine, stated in the docs and the agent briefs: agents never close gate or change issues. Audit prints each gate's approver login in the `PROCESS` header line so a person sees who approved. The residual for a single account is a maintainer decision (M2) | Test: a gate closed `COMPLETED` by a `Bot` actor is open, with the bot line; delete the check and the test goes red. Test: the header names the approver |
| R2 | (a) `CODEOWNERS` covers the board files (today `* @ChiefGyk3D` covers everything, VERIFIED `.github/CODEOWNERS:1`; the docs name the board files explicitly for multi-contributor repositories). (b) A new offline mode, `safo process diff BASE HEAD`, exits 1 on any weakening: profile waterfall to agile, a repository turned agile, a gate removed or moved to a later phase, an approver added, a baseline item added or re-phased without a new `changes` entry, `active_statuses` narrowed, `dependencies` set back to `none`. It runs on pull requests touching board files, needs no token and no network. (c) Scheduled audits read the default branch's file; the docs say a PR-time audit must read the base branch's file, never the PR's | One test per weakening kind (each goes red with that comparison removed); a test that a pure reordering or an added gate is not a weakening; a test that diff reads nothing from the network (the fake GitHub sees no request) |
| R3 | S4 pins baselined items to their phase; phase presence makes a cleared Phase a finding in waterfall repositories; G3 gives a pull request its linked issues' phase, so parking the issue in Backlog does not hide an active pull request; the status update counts cards with no phase | Tests for each: re-phased baselined item, cleared Phase, PR in Build linked to a Backlog issue behind an open gate |
| R4 | `hooks.jira_projects`, default empty: every Jira key is `issue-unverified` and block mode denies | Tests: `issue: FAKE-1` with the default is `issue-unverified` and denied in block mode; listed project accepted; unlisted project `issue-unusable` with no lookup (the fake resolver records zero calls) |
| R5 | Jira text is never rendered; only keys and status names cross; a test fixture with a sentinel title proves it never appears in any output | Sentinel-title test over every mode's output (stage 5, before any Jira build) |
| R6 | Separate read and write credentials; the write one only in CI via Doppler OIDC; https only; destination pinned; no redirect carries the credential; the token never reaches a log | Redirect-to-other-host test drops the header; log scan test with a sentinel token (stage 5) |
| R7 | Unreadable, missing, transferred or pull-request gates and approvals are UNKNOWN or DRIFT, never a pass; UNKNOWN outranks DRIFT | One test per case, each asserting exit 2 or 1 and never 0 |
| R8 | Caps (2.5); gate and approval reads batched (aliased issue reads, at most 50 per query, distinct references deduplicated); `blockedBy(first: 20)` with a count | Cap+1 tests for each list; a query-count test for a board at the caps |
| R9 | A live phase field of the wrong type is UNKNOWN for the gate rule (extending `mismatched_fields`, VERIFIED `items.py:369-386`); every waterfall check not configured is a NOTE | Type-drift test asserting exit 2; not-configured note tests |
| R10 | Every line goes through `ctx.say` (VERIFIED `context.py:29-31`) | A login with `::` and control characters is escaped (extends the existing output tests) |
| R11 | Profiles are built in and named; `board.yaml` cannot point at another file | The schema refuses any path-valued key under `process` (a test that `process.profile: ./mine.yaml` is refused by the choice check) |

### 8.6 Residual risk

- **R1 stays open in a single-account setup.** When agents act through the maintainer's own login, the close event
  cannot tell the maintainer from an agent. The controls make it visible (the header line, the issue's own timeline), not
  impossible. What closes it: agents on an App or bot identity that is not an approver. Reopen signal: any gate or change
  issue closed in a session where an agent was running, found by reading the timeline against the guard log.
- **R3 partly.** Work that has neither a card in an active status nor a pull request is invisible to every rule here;
  that is the no-hidden-work rule's residual, unchanged.
- **R4, while a project is listed:** a made-up number in a listed Jira project passes until a resolver exists.
- **Approval is not judgment.** Audit proves an approver closed the gate, not that the gate's criteria were met.
- **The guard's own residual** (an agent with shell access can edit the guard's state) is unchanged (VERIFIED
  `docs/no-hidden-work.md:56-59`).

## 9. The issue's open questions, answered

| Question | Answer | Why |
|---|---|---|
| Profile granularity (board, repo, Area) | Repository, with the board's profile as the default | Section 5: the repository is a fact GitHub returns; Area is writable by the card's own worker |
| Where gates live (card, field, milestone) | An issue per gate, listed in `board.yaml`; a milestone optionally carries the date | 3.2: only the issue records who approved, readable by audit; listing beats label discovery |
| Baseline changes without heavy process | One approval issue plus one `changes` entry per change, in `board.yaml` | 3.2: no new file, no body parsing, the PR review is the second record, audit checks the approval |
| Do routing and hooks need profile awareness | No | Section 6 |

### Decisions for the maintainer

| Id | Decision | Recommendation |
|---|---|---|
| M1 | Jira keys by default: `issue-unverified` (denied in block mode) unless their project is in `hooks.jira_projects` | Yes, and ship it first (U1): it closes the 2026-10-26 finding, and nobody uses Jira keys today |
| M2 | Approvals in a single-account setup: accept the R1 residual (agents act as you), or move agents to a separate identity before waterfall is used for real | Accept for now, with the bot refusal and the header line; revisit when a second person or an App identity for agents exists |
| M3 | `safo process diff` on pull requests: a reusable workflow (or an input of `python-ci`) in git-your-ship-together, which this repository then calls | Yes, in GYST: every adopter needs the same step, which is the consolidation rule |
| M4 | G2 (finished ahead of a gate) as DRIFT or as a NOTE | DRIFT: a merged pull request ahead of an open gate is the breach the rule exists for |
| M5 | This project's own board | Stays agile; the waterfall board ships only as an example file |
| M6 | Names: the `process` key, the profiles `agile` and `waterfall` | As written; a third profile is added only with a rule that differs |

## 10. Non-goals, compatibility and migration

**Non-goals.** A Jira implementation (only its seam and threat model are here). A Gantt or schedule computation, a
critical path, earned value, resource planning. Transition tables. Gate enforcement at dispatch time. Profiles defined in
files outside `board.yaml`. Automatic baselining (`safo` never writes `board.yaml`). Reading change requests from issue
bodies. Any write by `reconcile` or `sync` driven by a gate, scope or dependency finding.

**Compatibility.** A board without `process` behaves and prints exactly as today (2.4, with golden tests). `version`
stays 1. An older `safo` refuses a file with `process` (fails closed); the release notes say so. The Action's inputs do not
change in the first cut. `agents.yaml` gains one optional key, `hooks.jira_projects`; its stricter default changes the
guard's answer only for Jira-style keys.

**Migration.** None for existing boards. A team adopting waterfall copies `examples/process-waterfall.yaml`, runs
`safo validate`, then `safo bootstrap` (which creates the Phase field like any other), files the gate issues, lists
them, and adds the baseline once the Requirements gate is approved. The docs page "Choose a process profile" walks it.

## 11. Build plan

Units are issue-sized, each one pull request, test first, for a Sonnet implementer. "Codex" means an adversarial Codex
pass on the cyber tier before merge, required wherever approval logic, untrusted parsing, the guard, or a security
control is touched. Every unit's issue links #108; the maintainer merges.

| Unit | Title | Scope and files | Tests | Code vs doctrine | Review |
|---|---|---|---|---|---|
| U1 | Guard: accept Jira keys only from `hooks.jira_projects` | `agentsfile.py` (`Hooks.jira_projects`, parse, cap 64), `tracking.py` (`check` takes the list; `gh_resolver` stops answering `open` for Jira), `hooks.py` (pass it), `docs/no-hidden-work.md`, `docs/hooks.md`, `examples/agents.local.example.yaml` comment | The three table rows of 7.3; default denies in block mode; no lookup for an unlisted project; parse errors with key paths | Code | Sonnet + Codex |
| U2 | Schema: the `process` block | `schema.py` (`Process`, `Gate`, `Baseline`, `Change` dataclasses; `_parse_process`; per-repository `process`; cross-checks; caps), `docs/board-yaml.md` | Every message of 2.5; caps at N and N+1; hostile YAML in the subtree; golden equality of the parsed `Board` for both examples with and without `process: {profile: agile}` | Code | Sonnet + Codex (untrusted input) |
| U3 | Approval reader | new `src/safo/approvals.py`: batched aliased reads of issues by reference (state, `stateReason`, canonical repository, the last `CLOSED_EVENT`'s actor typename and login and time); a pure `verdict()`; fake GitHub fixtures | Passed, open, reopened, not planned, duplicate, non-approver, bot, empty approver list, missing, transferred, pull request, batching at 50, malformed nodes | Code | Sonnet + Codex (identity) |
| U4 | Read the phase field on cards | `items.py` (`ItemState.phase`, `_read_variables`, `mismatched_fields`), `live.py` unchanged | Read, blank, wrong live type is not asked for and is reported | Code | Sonnet |
| U5 | Audit: phase presence and the gate rule G1, G2 | new `src/safo/gates.py` (pure: cards, gates, verdicts to lines), `modes/audit.py` wiring, `coverage.not_configured` notes, the `PROCESS` header line (printed only when `process` is present), reconcile `HUMAN` lines | Every line of the gate tables; earliest gate only; window edges for G2; unknown outranks drift; golden no-change for agile boards | Code (audit); "do not start" stays doctrine | Sonnet + Codex |
| U6 | Audit: baseline, scope and phase pinning (S1-S5) | new `src/safo/baseline.py`, audit wiring | Every row of the scope table; approval reuse from U3; process records excluded; intake default | Code | Sonnet + Codex |
| U7 | Audit: pull request phase from linked issues (G3) | `coverage.py` (closing references with ids, first 10, count), `gates.py` | Inherited phase, conflicting phases take the latest, more than 10 is UNKNOWN, PR with its own Phase keeps it | Code | Sonnet |
| U8 | `safo process diff BASE HEAD` | new `src/safo/modes/process.py`, `docs/board-yaml.md`; then a GYST workflow or input (M3) in git-your-ship-together and this repository's caller | One test per weakening kind; non-weakening changes pass; no network; invalid input exits 2 | Code (a security control) | Sonnet + Codex |
| U9 | Audit: the dependency rule D1 | new `src/safo/dependencies.py`, audit wiring | Open blocker, closed blocker, over 20, unreadable blocker, rule off reads nothing | Code | Sonnet |
| U10 | Status update: the Phases and gates section | `statusgroups.py` (`Row.phase`, a pure section builder), `modes/status.py` (query adds the phase field) | Golden body for a waterfall fixture; agile body unchanged; no titles in the section; counts | Code | Sonnet |
| U11 | Docs and examples | new `docs/process-profiles.md` ("Choose a process profile"), links in `README.md` and `docs/home.md` (required by `tests/test_readme_links.py`), `docs/why.md` and `docs/board.md` wording ("the fields are a choice; the rule is the constant"), `examples/process-waterfall.yaml` with `ui_only` for the Roadmap | `test_examples.py` loads the new example; link tests | Doctrine (the docs) | Sonnet, or Haiku for the link edits |
| U12 | Tracker protocol with GitHub as its implementation | `src/safo/trackers/` (protocol, GitHub wrapper), modes call through it; no behavior change | Golden outputs unchanged; protocol conformance tests | Code | Sonnet; **stage 5, not the first cut** |
| U13 | NOTE: an open gate past its milestone's due date | `gates.py`, the gate read adds `milestone { dueOn }` | Overdue, not overdue, no milestone | Code | Sonnet; optional |

**Order.** Stage 1: U1 (independent; ship first) and U2. Stage 2: U3 (needs nothing but the fake GitHub) and U4 (needs
U2). Stage 3: U5 (needs U2, U3, U4). Stage 4: U6 and U7 (need U5), U8 (needs U2; best after U6 so the baseline weakening
cases exist), U9 (needs U2), U10 (needs U4 and U5), U11 (last, documents what merged). U13 after U5, optional. Stage 5,
not committed to a date: U12, then a Jira resolver, which needs its own threat-model update (8, R5 and R6 made concrete
against Atlassian's documentation), the maintainer's decision on credentials, and a Codex pass.

**Review gates.** Every unit: Sonnet review against its tests and `make check` exit 0. Codex adversarial pass before
merge: U1, U2, U3, U5, U6, U8. A whole-branch review after stage 4, before the docs unit, that reads the gate, scope and
diff code together, because the bypasses in R2 and R3 cross units.
