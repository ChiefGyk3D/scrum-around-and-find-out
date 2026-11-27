# Kind for a board's open cards, and a write cap for reconcile

Phase 1 of cleaning up a large board (#479). Two small tools, both safe to re-run.

## `safo reconcile --max-writes N` and `--no-adds`

- `--max-writes N` stops the run after N mutations (an add counts one, each field write counts one). It prints
  `stopped at the write cap (N), re-run to continue` and exits 0: a planned stop, not drift. Reconcile is idempotent, so
  the next run picks up where this one ended. The cap also applies to `--dry-run`, so a dry run shows what one capped
  batch would do.
- `--no-adds` repairs the cards already on the board (the Done status, the Done date, blank Area and defaults) and adds
  no missing work. A `NOT ADDED n cards` line says how many were left off.

- `--closed-only` is phase 1 of a big cleanup: it writes only the Status and the Done date, and only on closed cards
  already on the board. Open cards are left alone (counted), nothing is added, and the blank Area and Priority of closed
  cards are not touched. Use it with `--max-writes` for batches.

Reconcile never writes Kind, Epic or Effort. It prints them as `HUMAN` lines.

## `safo kind`

Writes Kind on open cards, from rules and a map a human approved. It never writes Epic or Effort.

1. `safo kind --snapshot-dir DIR --project users/<login>/projectsV2/<n> --read-board` reads the whole board once by REST
   pages (never GraphQL), two seconds between pages, into DIR. The directory is private (0700), its files 0600, and it
   holds titles: keep it out of every repository. A new read keeps the earlier `items.json` as `items-<stamp>.json`.
2. `safo kind --snapshot-dir DIR --propose proposal.json --residue residue.json` reads the snapshot and prints counts.
   For each open card with an empty Kind the rules run in this order, and the first hit wins:
   labels (`epic`, `release`, `bug`, `enhancement` or `feature`, `documentation`, `chore`, `dependencies` or `ci`), then
   the title prefix (`feat:`, `fix:`, `docs:`, `chore:`, `release:`, `Epic:`, `lesson:`, `decision:` and a few
   synonyms), then Dependabot and `Bump` pull requests. A rule whose Kind the board does not have gives no hit. Only the
   board's own Kind option names are used, read from the board.
   `proposal.json` is a plain `{"owner/repo#N": "Kind"}` file for a human to read and edit. `residue.json` lists the cards
   no rule names, with titles; residue is never written. Both are new files (an existing file is never overwritten).
3. `safo [--dry-run] kind --snapshot-dir DIR --project ... --map approved.json [--max-writes N]` writes an approved map.
   Any value that is not one of the board's Kind option names refuses the whole map before anything is sent. A card is
   written only when it is open and its Kind is empty (a closed card or a card that already has a Kind is skipped and
   counted). Each write is one REST PATCH that carries the Kind field and nothing else, through the shared budget
   (`ghw`; see [ratebudget.md](ratebudget.md)). If GitHub refuses a write, the Kind option ids are read again once; when
   they changed the write is retried once, otherwise the run stops. A lost reply is an unknown outcome and stops the
   run: the write may have landed, so it is not replayed. Every write is appended to `kind-writes.jsonl` in DIR with the
   old and new value (the old value is always empty, so a rollback clears the field).

Re-run `--read-board` before a re-run of `--map`: the snapshot does not know about earlier writes, and a card that
already has a Kind is skipped only once the snapshot shows it.
