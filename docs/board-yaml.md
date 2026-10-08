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

## ui_only

A list of sentences for the settings no API can read or set (a Roadmap's date fields and zoom, a view's grouping, the
project's built-in workflows). `bootstrap` prints them as a checklist and `audit` prints them as a reminder.

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
