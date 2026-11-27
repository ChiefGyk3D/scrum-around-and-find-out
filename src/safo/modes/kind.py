# SPDX-License-Identifier: Apache-2.0
"""`safo kind`: rule-driven Kind for a board's open cards, from a private snapshot and an approved map (#479).

See `safo.kindwrite` for the three steps and their guarantees, and docs/board-kind.md for the run order.
"""

from __future__ import annotations

import argparse
import io
import json
import re
from pathlib import Path

from safo import boardmap, kindwrite
from safo.context import LocalContext
from safo.errors import EXIT_OK, ApiError, ConfigError
from safo.modes import LocalMode, register_local
from safo.modes.reconcile import positive

_PROJECT = re.compile(r"(users|orgs)/[A-Za-z0-9][A-Za-z0-9-]{0,38}/projectsV2/[0-9]{1,9}")


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--snapshot-dir", required=True, type=Path, help="the private snapshot directory (created 0700)")
    p.add_argument("--project", help="users/<login>/projectsV2/<number>, for --read-board and --map")
    p.add_argument(
        "--read-board", action="store_true", help="read the whole board by REST pages into the snapshot first"
    )
    p.add_argument(
        "--propose", type=Path, metavar="FILE", help="write the rule hits as a map for review (new file, 0600)"
    )
    p.add_argument(
        "--residue", type=Path, metavar="FILE", help="write the cards no rule names, with titles (new file, 0600)"
    )
    p.add_argument("--map", type=Path, metavar="FILE", help="write this approved map of owner/repo#N to Kind")
    p.add_argument(
        "--max-writes", type=positive, default=None, metavar="N", help="stop cleanly after N writes (exit 0)"
    )


def _project(args: argparse.Namespace) -> str:
    project = args.project or ""
    if not _PROJECT.fullmatch(project):
        raise ConfigError("--project users/<login>/projectsV2/<number> is required for this step")
    return str(project)


def run(ctx: LocalContext, args: argparse.Namespace) -> int:
    directory: Path = args.snapshot_dir
    if args.read_board:
        gh = ctx.which("gh")
        if not gh:
            raise ConfigError("gh was not found on PATH; it makes the board read")
        count = kindwrite.read_board(
            _project(args), directory, run=ctx.run, gh=gh, now=ctx.now.isoformat(timespec="seconds")
        )
        ctx.say(f"read the board by REST: {count} items saved in the private snapshot")
    cards = kindwrite.load_cards(directory)
    field_id, options = kindwrite.kind_options(kindwrite.load_fields(directory))
    allowed = frozenset(options)
    open_cards = [c for c in cards if c.state == "open"]
    proposal = kindwrite.propose(cards, allowed)
    ctx.say(f"board Kind options: {', '.join(sorted(allowed))}")
    blank = len(proposal.hits) + len(proposal.residue)
    ctx.say(f"snapshot: {len(cards)} cards, {len(open_cards)} open, {blank} open with no Kind")
    for rule, n in proposal.by_rule().items():
        ctx.say(f"  rule {rule}: {n}")
    for kind, n in proposal.by_kind().items():
        ctx.say(f"  would be {kind}: {n}")
    ctx.say(f"rule hits {len(proposal.hits)}, residue (no rule, never written) {len(proposal.residue)}")
    if args.propose:
        kindwrite.write_new_file(args.propose, _dump({k: v[0] for k, v in sorted(proposal.hits.items())}))
        ctx.say("proposal written for review (not applied)")
    if args.residue:
        titles = {c.key: c.title for c in cards}
        kindwrite.write_new_file(args.residue, _dump({k: titles[k] for k in sorted(proposal.residue)}))
        ctx.say("residue written for review (not applied)")
    if not args.map:
        return EXIT_OK
    board = boardmap.BoardMap(
        _project(args), {kindwrite.KIND: boardmap.Field(field_id, "single_select", dict(options))}, {}
    )
    mapping = kindwrite.load_map(args.map, allowed)
    transport = boardmap.gh_transport(ctx.env, run=ctx.run, gh=ctx.which("gh"))
    if ctx.dry_run:
        kindwrite.apply_map(
            cards,
            mapping,
            board,
            transport,
            say=ctx.say,
            dry_run=True,
            max_writes=args.max_writes,
            journal=io.StringIO(),
        )
        return EXIT_OK
    with kindwrite.open_journal(directory) as journal:
        try:
            result = kindwrite.apply_map(
                cards,
                mapping,
                board,
                transport,
                say=ctx.say,
                dry_run=False,
                max_writes=args.max_writes,
                journal=journal,
            )
        except ApiError as problem:
            ctx.say("stopped: re-read the board before any re-run (see the journal for what landed)")
            raise problem
    ctx.say(
        f"kind: {result.written} written, {result.skipped_set} already set, "
        f"{result.skipped_closed} closed, {result.skipped_unknown} unknown"
    )
    return EXIT_OK


def _dump(data: dict[str, str]) -> str:
    return json.dumps(data, indent=1, sort_keys=True) + "\n"


register_local(
    LocalMode("kind", "write Kind on open board cards from rules and an approved map (phase 1)", add_arguments, run)
)
