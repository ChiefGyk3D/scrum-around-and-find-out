# board.yaml reference

`board.yaml` describes one GitHub Project (v2) and the repositories whose issues and pull requests belong on it.
`safo` validates it before it makes any request, and every error names the offending key, for example
`board.yaml: fields[0].options[2].color: 'TEAL' is not one of GRAY, BLUE, GREEN, YELLOW, ORANGE, RED, PINK, PURPLE`.
The file is read with `yaml.safe_load` only. A complete worked file is
[examples/renegade-penguin.yaml](../examples/renegade-penguin.yaml).

Quote any option name YAML might read as something else. `No`, `yes`, `on`, `off` become booleans and `1.0`
becomes a number; `safo` refuses them with the key path rather than guessing.

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
| `start`, `duration_days`, `count` | For `iteration`: the first start date, the length of each iteration, and how many to create |
| `title_prefix` | For `iteration`: iterations are titled `<prefix> 1`, `<prefix> 2` (default: the field name) |

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
| `new_item_defaults` | none | `{field: option}` pairs set on every item `safo` adds, and only on those |
| `add_closed_days` | `0` | `reconcile` also adds items closed or merged within this many days, as Done |

Every status name must be an option of the status field; `safo` checks that against `fields` when it loads the file and
against the live project before it changes anything.

## agents

Used by `agents-status`: `field` (default `Agent`), `working` (default `In progress`, `Next`) and `waiting` (default `Blocked`).

## ui_only

A list of sentences for the settings no API can read or set (a Roadmap's date fields and zoom, a view's grouping, the
project's built-in workflows). `bootstrap` prints them as a checklist and `audit` prints them as a reminder.
