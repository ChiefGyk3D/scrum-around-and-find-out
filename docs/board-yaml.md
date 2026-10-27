# board.yaml reference

`board.yaml` describes one GitHub Project (v2) and the repositories whose issues and pull requests belong on it.
`safo` validates it before it makes any request, and every error names the offending key, for example
`board.yaml: fields[0].options[2].color: 'TEAL' is not one of GRAY, BLUE, GREEN, YELLOW, ORANGE, RED, PINK, PURPLE`.
The file is loaded with a custom YAML loader that refuses hostile inputs. A complete worked file is
[examples/renegade-penguin.yaml](../examples/renegade-penguin.yaml).

Quote any option name YAML might read as something else. `No`, `yes`, `on`, `off` become booleans and `1.0`
becomes a number; `safo` refuses them with the key path rather than guessing.

## Top level

The top-level mapping is required and must contain:

| Key | Type | Required | Meaning |
|---|---|---|---|
| `version` | integer | yes | Must be `1` (exactly; not a boolean) |
| `project` | mapping | yes | The project description |
| `repositories` | list | yes | Repositories whose items belong on the board (may be empty) |
| `fields` | list | no | Custom fields; built-in fields are not listed |
| `views` | list | no | Views of the board |
| `rules` | mapping | no | Automation and field cross-references |
| `agents` | mapping | no | Agent status tracking |
| `ui_only` | list | no | Manual settings not readable via the API |
| `process` | mapping | no | The [process method](#process); absent means `{method: agile}` |

Unknown keys are refused with the key path.

## project

| Key | Required | Meaning |
|---|---|---|
| `owner` | yes | The organization or user login that owns the project |
| `owner_type` | yes | `organization` or `user`. A GitHub App can write only an organization's projects |
| `number` | no | The project number in its URL. Leave it out and `safo bootstrap` creates the project and prints the number to write here |
| `title` | yes | The project's title (used when bootstrap creates it) |

## repositories

A list; every repository whose open issues and pull requests belong on the board.

| Key | Meaning |
|---|---|
| `owner`, `name` | The repository. It may belong to a different account than the project |
| `default_area` | The `Area` option given to an item from this repository when nothing more specific matches |
| `area_rules` | Optional list of `{match, area}`; the first rule whose `match` (case-insensitive) occurs in the title or a label wins. Used by `reconcile` only: an event never reads a title |
| `method` | Optional, `agile` or `waterfall`: this repository's process method. Default: `process.method`. A `null` is refused |

## fields

A list of fields the project must have. Built-in fields (Title, Assignees, Labels, Repository and the rest) are not listed.

| Key | Meaning |
|---|---|
| `name`, `type` | `single_select`, `iteration`, `date`, `text` or `number` |
| `options` | For `single_select`: a list of `{name, color, description}`; color is one of GRAY, BLUE, GREEN, YELLOW, ORANGE, RED, PINK, PURPLE |
| `start`, `duration_days`, `count` | For `iteration` only: the first start date (YYYY-MM-DD), the length of each iteration (integer >= 1), and how many to create (integer >= 1). Required together for an iteration field |
| `title_prefix` | For `iteration` only: iterations are titled `<prefix> 1`, `<prefix> 2` (default: the field name) |

A `single_select` field requires at least one option. Duplicate option names within a field are refused.
`bootstrap` creates a field that is missing, with all its options or iterations. It never edits a field that exists:
see [Lessons](lessons.md) for why.

## views

A list of `{name, layout, filter}`; layout is `board`, `table` or `roadmap`. A view is created with its layout, then its
filter is set in a second call. An existing view with another layout is refused; with another filter it is left alone and
`audit` reports it.

## rules

| Key | Default | Meaning |
|---|---|---|
| `status_field` | `Status` | The single-select field holding an item's status |
| `area_field` | `Area` | The single-select field `default_area` and `area_rules` fill |
| `status.opened` | `Backlog` | An issue that opens |
| `status.opened_pr` | `opened` | A pull request that opens or is marked ready for review |
| `status.draft_pr` | `opened` | A draft pull request |
| `status.reopened` | `Backlog` | An issue reopened out of Done |
| `status.closed`, `status.merged` | `Done` | A closed issue or pull request, a merged pull request |
| `done_date_field` | empty (off) | The date field set to the close date; cleared when an issue is reopened |
| `new_item_defaults` | none | `{field: option}` pairs filled only when blank on any managed card, so a later run repairs partial initialization; nonblank manual values are preserved. A default never writes the status, Area or Done-date field: those follow their own rules |
| `add_closed_days` | `0` | `reconcile` also adds items closed or merged within this many days, as Done |
| `tracking` | see below | The [no-hidden-work](no-hidden-work.md) checks: `kind_field` (`Kind`), `epic_field` (`Epic`), `effort_field` (`Effort`), and `exempt_repos` (`owner/name` list whose pull requests need no linked issue). A field name that is empty, or not in `fields`, turns that check off and the audit says "not configured" |
| `threat_model` | off | The [threat model before build](threat-model.md) check: `label` (empty turns it off and the audit says "not configured"; `ai-surface` is the usual name) and `exempt_repos` (`owner/name` list whose issues need no threat-model line) |
| `gate_check` | `CI green` | The [branch gate](no-hidden-work.md#the-branch-gate): the status check the default branch of each listed repository must require, matched by its own name or after a workflow prefix (`ci / CI green`). Empty turns the rule off; the audit then says "not configured" and its summary line says the gate was not checked |
| `gate_forbid_force_push` | `true` | Also report a default branch that allows force pushes, or whose force-push block can be bypassed |
| `gate_exempt_repos` | none | `owner/name` list, each entry listed in `repositories`, that is not evaluated for the gate; the audit prints a `NOTE` for each |
| `gate_require_admin_enforced` | `false` | `true` also reports a classic protection rule that does not apply to administrators (`enforce_admins` off). Off by default because the shipped baseline (`scripts/apply-baseline.sh`) sets `enforce_admins` to false; a repository that is gated only for non-administrators then gets a `NOTE` |
| `gate_admin_exempt_repos` | none | With `gate_require_admin_enforced` on: `owner/name` list, each entry listed in `repositories`, where administrators may bypass, accepted |
| `gate_check_app_id` | `15368` | The app (GitHub App id, an integer from 1 to 2147483647, GraphQL's `Int`) the gate check must be pinned to; `15368` is GitHub Actions. A required check with no source restriction, or tied to another app, can be satisfied by an app other than your CI and is reported by the [branch gate](no-hidden-work.md#the-branch-gate). Set it to your CI app's id if it is not GitHub Actions. A pin proves the app, not the workflow (every workflow can post as the Actions app), so a pinned check passes with a `NOTE` every time |

Every status name must be an option of the status field; `safo` checks that against `fields` when it loads the file and
against the live project before it changes anything.

## agents

Used by `agents-status`. All keys are optional.

| Key | Default | Meaning |
|---|---|---|
| `field` | `Agent` | A single-select field that names the agent. Must exist in `fields` |
| `working` | `In progress`, `Next` | Status options that mean the agent is working on an item |
| `waiting` | `Blocked` | Status options that mean the agent is blocked |

All values in `working` and `waiting` must be options of the status field.

## process

Optional. Absent, `process: {}` and `process: {method: agile}` mean the same thing, and an all-agile board behaves and
prints exactly as it did before this key existed. This release only reads and checks the block; no audit rule uses it yet.
Every error names the key path and is raised at load time, before any request. A value that is `null`, the wrong type or
not on a list is refused, never replaced by a default. Text echoed in an error is ASCII, cut to 40 characters.

| Key | Default | Meaning |
|---|---|---|
| `method` | `agile` | `agile` or `waterfall`: the default for every repository |
| `dependencies` | `none` | `none` or `blocked_by`. Do not write `off`: YAML reads it as `false`, which is refused |
| `phase_field` | none | Waterfall only, required. A `single_select` in `fields` (not the status or area field); its option order is the phase order; at most 16 options |
| `active_statuses` | none | Waterfall only, required, at most 16. Options of the status field that mean "being worked", none of them `rules.status.closed` or `merged` |
| `approvers` | none | Waterfall only, required, 1 to 32 entries of `{login, id}`: a valid GitHub login and the user's positive `databaseId`. Neither may repeat |
| `gates` | `[]` | Waterfall only, at most 32 entries of `{phase, issue}`: a phase option, one gate per phase, none on the last phase, and `issue` as `owner/repo#N` in one of `repositories` (checked offline) |

"Waterfall" means `process.method` or some `repositories[i].method` is `waterfall`. Waterfall-only keys on any other board
are refused with `only used when the method or a repository is waterfall`, and a waterfall board needs
`rules.add_closed_days` of at least 1. On a waterfall board the option names of the phase field and of the status field are restricted: letters and digits, single spaces between words, and the punctuation `- _ . , : ( ) / + & #`, already NFKC-normalized, at most 100 characters. Combining marks, variation selectors, joiners, emoji, tabs, non-ASCII spaces and a leading, trailing or doubled space are refused by option number, never echoed. This stops control and bidi injection and names that differ only in invisible marks; it does not stop look-alike letters from other scripts. The phase field may have at most 16 options and the status field at most 64, checked before any option is read. A board with no waterfall `process` block has no such limits. Unknown keys inside `process` are refused (`baseline` arrives with a later release).

```yaml
rules:
  add_closed_days: 30
process:
  method: waterfall
  phase_field: Phase
  active_statuses: [In progress]
  approvers:
    - {login: maintainer-login, id: 1234567}
  gates:
    - {phase: Requirements, issue: acme/gates#1}
```

## ui_only

A list of sentences for the settings no API can read or set (a Roadmap's date fields and zoom, a view's grouping, the
project's built-in workflows). `bootstrap` prints them as a checklist and `audit` prints them as a reminder.

## Limits

Every list the loader reads has a limit, checked on the length of the raw list before any entry is read, so a hostile
file costs one comparison. The error names the key and the limit, for example `fields: at most 100 entries`. The
shipped boards use at most 25 repositories, 12 fields, 5 views, 15 options in a field and 27 area rules in a
repository, well under every limit.

| List | Limit |
|---|---|
| `repositories` | 200 |
| `fields` | 100 |
| options of one field | 64 (a waterfall board's phase field: 16) |
| `views` | 50 |
| `area_rules` of one repository | 100 |
| `ui_only`, `rules.new_item_defaults` | 100 |
| `exempt_repos` (tracking, threat model), `gate_exempt_repos`, `gate_admin_exempt_repos` | 200 |
| `agents.working`, `agents.waiting` | 64 |
| `process.active_statuses` | 16 |
| `process.approvers`, `process.gates` | 32 |

Duplicate names are found with a set, so the check is linear. A value echoed in an error is cut to 200 characters of its
`repr` followed by `...` (a realistic value prints exactly as before). Values from the `process` block are cut harder: a
shown value is at most 120 characters in total, quotes and ellipsis included, and a list of option names is at most 400
characters in total, ellipsis included.

## Refused YAML

The YAML loader refuses the following as hostile or ambiguous:

- **Duplicate keys**: a key appears twice in any mapping (e.g., `project: {owner: a, owner: b}`)
- **Anchors** (e.g., `project: &p {...}`): mark locations in the file; `safo` forbids them to avoid hidden references
- **Aliases** (e.g., `- *p`): refer to anchored nodes; silently shared nodes hide what a value really is
- **Merge keys** (`<<`): combine mappings; they obscure the actual keys
- **File size** > 1 MiB: prevents reading huge files
- **Nesting depth** > 64 levels (measured during composition): prevents exponential parse times and RecursionError crashes

All these YAML features are checked in the loader itself; parsing fails with an error that names the file, line, and kind.

After an unknown outcome, `status` cannot verify whether the update landed; check the existing project updates before posting again.

`sync` treats the event payload as a pointer: it reads the issue or pull request live (state, draft flag, number, repository) and writes from that. An action that contradicts the live state, or a node that is not in the repository the payload names, is a NOTE (exit 1) and writes nothing. `status` checks that the acknowledged update belongs to the project (`statusUpdate.project.id`); an acknowledgement that does not say so is an unknown outcome. An exhausted rate limit before any write exits 1; after a write was sent it is an unknown outcome (exit 2). Text from GitHub is escaped on every log line, and `status --post --print` shows the update inside `::stop-commands::`.

An error that lists a field's options (for example a status that is not one of them) lists every option exactly as before. It is identical to the earlier text for every board whose option names are printable; a name with a control, bidi or separator character is escaped (hardening).
