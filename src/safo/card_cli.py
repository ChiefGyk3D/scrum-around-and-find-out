# SPDX-License-Identifier: Apache-2.0
"""safo-card: edit one project card with a single REST PATCH, from a persisted map of ids (#358). Never lists the board.

    safo-card owner/repo#N Field=Value [Field=Value ...] [--item-id N | --resolve] [--option Field:Name=ID]

The map lives beside the rate-budget ledger (`boardmap.json`). A card not in it needs `--item-id` (from a read you made)
or `--resolve` (two REST reads, once). `Field=` with no value clears the field. `--dry-run` prints the request and sends
nothing; the map is still updated, since it is a local file. The call goes through the shared budget (`ghw` rules).
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import sys
from collections.abc import Mapping, Sequence
from typing import TextIO

from safo import boardmap
from safo.context import LocalContext
from safo.errors import EXIT_OK, ConfigError, SafoError
from safo.modes.reconcile import safe


def _edits(words: list[str]) -> dict[str, str | None]:
    edits: dict[str, str | None] = {}
    for word in words:
        name, sep, value = word.partition("=")
        if not sep or not name:
            raise ConfigError("an edit is Field=Value (Field= clears it)")
        if name in edits:
            raise ConfigError(f"field {name} is given twice")
        edits[name] = value or None
    return edits


def _learn(board: boardmap.BoardMap, spec: str) -> None:
    head, sep, option_id = spec.partition("=")
    name, sep2, label = head.partition(":")
    if not sep or not sep2 or not label or name not in board.fields:
        raise ConfigError("--option is Field:Name=ID for a field the map knows")
    if not boardmap.OPTION_ID.fullmatch(option_id):
        raise ConfigError("--option: an option id is 8 lowercase hex digits")
    board.fields[name].options[label] = option_id


def run(ctx: LocalContext, args: argparse.Namespace) -> int:
    key = args.issue
    boardmap.parse_key(key)
    path = boardmap.map_path(ctx.env)
    board = boardmap.load(path)
    before = boardmap.to_json(board)
    for spec in args.option:
        _learn(board, spec)
    if args.item_id:
        board.items[key] = boardmap.check_id(args.item_id, "--item-id")
    dry = ctx.dry_run or args.card_dry_run
    transport = boardmap.gh_transport(ctx.env, run=ctx.run, gh=ctx.which("gh"))
    try:
        edits = _edits(args.edits)
        if args.resolve:
            boardmap.resolve_item(board, transport, key)
        request = boardmap.build_request(board, key, edits)
    finally:
        boardmap.merge_save(path, before, board)
    if dry:
        ctx.say(f"{request.method} {request.path}")
        ctx.say(request.body)
        return EXIT_OK
    boardmap.edit_card(board, transport, key, edits)
    ctx.say(f"{key}: {', '.join(edits)} set (1 REST call)")
    return EXIT_OK


def add_arguments(p: argparse.ArgumentParser) -> None:
    """The arguments, shared by `safo-card` and `safo card`."""
    p.add_argument("issue", help="owner/repo#N")
    p.add_argument("edits", nargs="*", help="Field=Value (Field= clears)")
    p.add_argument("--item-id", type=int, default=0, help="the card's project item id; remembered in the map")
    p.add_argument("--resolve", action="store_true", help="find the item id with two REST reads, once")
    p.add_argument("--option", action="append", default=[], help="learn an option: Field:Name=ID (8 hex digits)")
    p.add_argument("--dry-run", dest="card_dry_run", action="store_true", help="print the request, send nothing")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="safo-card", description="edit one project card with one REST PATCH")
    add_arguments(p)
    return p


def main(
    argv: Sequence[str], *, env: Mapping[str, str], out: TextIO, err: TextIO, now: dt.datetime | None = None
) -> int:
    args = parser().parse_args(argv)
    ctx = LocalContext(out, env, now or dt.datetime.now(dt.UTC))
    try:
        return run(ctx, args)
    except SafoError as problem:
        err.write(f"safo-card: {safe(str(problem))}\n")
        return problem.exit_code


def entry() -> None:
    raise SystemExit(main(sys.argv[1:], env=os.environ, out=sys.stdout, err=sys.stderr))
