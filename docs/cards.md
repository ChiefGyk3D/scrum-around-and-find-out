# safo-cards

`safo-cards` sets Kind, Epic and Effort (and Area and Priority defaults) on project cards from a table, so a card is
complete when its issue is created and the drift that `safo audit` reports cannot come back. It is a separate entry
point (not a `safo` subcommand), and it never lists the board.

```sh
safo-cards plan  table.json [--board board.yaml]
safo-cards apply table.json [--board board.yaml] [--max-writes N]
```

`plan` prints what would change and writes nothing (it still reads: the field list and each card). `apply` writes.
`--board` defaults to `~/.config/safo/board.yaml`.

## The table

Strict JSON (duplicate keys, nesting and size are refused; a symlinked file is refused):

```json
{"cards": [
  {"repo": "owner/name", "issue": 7, "kind": "Task", "epic": "Epic 518", "effort": "M"},
  {"repo": "owner/name", "issue": 8, "kind": "Bug", "epic": "Epic 518", "effort": "S", "area": "Docs", "priority": "P1 soon"}
]}
```

Required: `repo`, `issue`, `kind`, `epic`, `effort`. Optional: `area`, `priority`. Any other key refuses the table.
Every value is checked against the option names in board.yaml (Kind, Effort, Area, Priority), the repository against
its `repositories` list, and `epic` must be 1 to 200 printable characters. One bad card refuses the whole table before
any call is made, and the message names the card number and the part, not the value.

Defaults: Area is the repository's `default_area`, Priority is `rules.new_item_defaults.Priority`. A default is set
only when the card's field is empty. A value written in the table always wins.

## What it sends

REST only, through the shared budget (`ghw`, see [ratebudget](ratebudget.md)). No GraphQL, no board listing.

1. One read of the project's field list, for the numeric field ids and option ids (`board.yaml` holds names, not ids).
2. Per card: the item id from the persisted map (`boardmap.json`), else one issue read and one lookup by title. A card
   that is not on the board is added with one `POST users/<owner>/projectsV2/<n>/items` (`plan` says `WOULD ADD`).
3. One read of the card with a comma-separated `fields=` list, then one `PATCH` carrying only the fields that differ.
4. A second read of the same shape. Every written value must match, or the run stops with an error.

The first failure stops the run (exit non-zero). A lost reply is an unknown outcome and is never replayed. A second
run finds nothing to change. `--max-writes N` stops cleanly after N writes or adds (exit 0); re-run to continue.
Output lists card references, field names and table values; no response body and no token is printed.

The add body (`type`, `owner`, `repo`, `number`) is one of the two shapes in GitHub's published REST description of
`POST /users/{username}/projectsV2/{project_number}/items` (fetched 2026-11-27; the other is `type` and `id`). Not
verified against the live board: the shape of the single-item read and of the add reply are read defensively; a shape
that differs fails closed rather than guessing.
