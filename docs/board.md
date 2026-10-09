# The board

The board is always current. That is a property the tools maintain, not a habit anyone has to keep.

## Fields

| Field | Why it exists |
|---|---|
| Status | Backlog, Next, In progress, Blocked, Done. Blocked means it needs a person |
| Agent | Who owns the card: Claude, Codex, Copilot or the maintainer |
| Area | Which part of the system the card is about; filled from the repository and from `area_rules` |
| Kind, Priority, Effort, Epic | Optional triage fields; `safo` creates them from `board.yaml` and never overwrites a value |
| Sprint | An iteration field; the sprint is the unit of "Next" |
| Start date, Target date | Feed the Roadmap view |
| Done on | Set to the close date when a card reaches Done, so a "done log" is a filter, not a document |

## What the tools do

| Event | Result |
|---|---|
| Issue opened | Added if absent, Status per `rules.status.opened`, Area per the repository, `new_item_defaults` set |
| Pull request opened or ready for review | Added if absent, `opened_pr`; a draft gets `draft_pr` |
| Issue reopened out of Done | `reopened`, and the Done-on date cleared |
| Closed or merged | `closed` or `merged`, and Done on set to the close date |
| Weekly reconcile | Adds anything missing, finishes anything closed, fills blank Area and Status |

Reconcile never reopens a card and never changes the status of an open card that has one. If an open card sits in Done,
`audit` reports it and a person decides.

## Sprints and status updates

Sprints are 14-day iterations created by `bootstrap`. Post a status update at the end of each one with
`safo status --body-file update.md --state ON_TRACK`; the update lives on the project, beside the cards it describes.

`safo status --post` writes the update for you. It groups the cards into done since a date (`--since`, a week ago by
default), in progress, waiting on the maintainer (Blocked, or a working card whose Agent is the maintainer's value,
`--human-agent`) and next, and it counts them. The groups and the counts come from the board's fields, never from a
model. Code always renders the count sentence. A reachable local model may append one exact approved prose clause;
invalid, multiline or unavailable prose adds nothing. Look at
the update first with `safo status --post --print`: nothing is sent.

## What no API can set

A Roadmap's date fields and zoom, a view's grouping, and the project's built-in workflows (item closed, pull request
merged) are UI-only. List them under `ui_only` in `board.yaml`: `bootstrap` prints the checklist and `audit` repeats it.

## Keeping the file and the board in agreement

`safo audit` compares them: a field, option, iteration or view the file names and the project lacks is **drift**; a colour
or description that differs is a **note**, because `safo` cannot change an existing option and would only be nagging.
