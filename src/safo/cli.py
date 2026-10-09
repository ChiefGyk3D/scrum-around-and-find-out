# SPDX-License-Identifier: MIT
"""The `safo` command line, and the entry point `python -m safo` shares with the Action."""

from __future__ import annotations

import argparse
import datetime as dt
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from typing import TextIO

from safo import __version__, compat, credentials, output
from safo.context import Context
from safo.errors import SafoError
from safo.graphql import GRAPHQL_URL, Client
from safo.modes import load_all, validate
from safo.modes.reconcile import safe
from safo.schema import Board, load_board

ClientFactory = Callable[[Board, Mapping[str, str], bool], Client]


def default_client(board: Board, env: Mapping[str, str], dry_run: bool) -> Client:
    creds = credentials.from_env(env) or credentials.from_gh(env, env.get("SAFO_GH_USER", "").strip())
    if creds is None:
        raise credentials.NoTokenError(
            "no token: set SAFO_TOKEN (the Action does this from its token or App inputs), "
            "or log in with `gh auth login`"
        )
    credentials.check_for_board(creds, board.project.owner_type, env)
    return Client(creds.token, env.get("GITHUB_GRAPHQL_URL", GRAPHQL_URL), dry_run=dry_run)


def resolve_board(path: str | None, env: Mapping[str, str]) -> Board:
    """--board, then $SAFO_BOARD, then the board-less inputs ($SAFO_PROJECT_URL), then ./board.yaml."""
    chosen = path or env.get("SAFO_BOARD", "")
    if chosen:
        return load_board(chosen)
    if env.get("SAFO_PROJECT_URL"):
        return compat.board_from_env(env)
    return load_board("board.yaml")


def build_parser() -> tuple[argparse.ArgumentParser, dict[str, argparse.ArgumentParser]]:
    parser = argparse.ArgumentParser(
        prog="safo", description="Scrum Around and Find Out: a GitHub Project defined as code."
    )
    parser.add_argument("--version", action="version", version=f"safo {__version__}")
    parser.add_argument("--board", default=None, help="the board file (default: $SAFO_BOARD, else ./board.yaml)")
    parser.add_argument("--gh-user", default="", help="use this logged-in gh account's token instead of the active one")
    parser.add_argument("--dry-run", action="store_true", help="read, and print every mutation instead of sending it")
    sub = parser.add_subparsers(dest="mode", required=True)
    subs: dict[str, argparse.ArgumentParser] = {}
    for name, mode in load_all().items():
        subs[name] = sub.add_parser(name, help=mode.help)
        mode.add_arguments(subs[name])
    return parser, subs


def report(err: SafoError, env: Mapping[str, str], stream: TextIO) -> None:
    text = safe(str(err))  # the text may carry what GitHub or a payload sent: no newline can start a new command
    if env.get("GITHUB_ACTIONS") == "true":
        output.annotation(stream, text)
    else:
        output.write(stream, f"error: {text}")


def main(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    client_factory: ClientFactory = default_client,
    out: TextIO | None = None,
    err: TextIO | None = None,
    today: dt.date | None = None,
) -> int:
    env = os.environ if env is None else env
    out = out or sys.stdout
    err = err or sys.stderr
    parser, _ = build_parser()
    args = parser.parse_args(argv)
    mode = load_all()[args.mode]
    if args.gh_user:
        env = {**env, "SAFO_GH_USER": args.gh_user}
    try:
        board = resolve_board(args.board, env)
        if args.mode == "validate":
            output.write(out, validate.MESSAGE)
            return 0
        try:
            client = client_factory(board, env, args.dry_run)
        except credentials.NoTokenError:
            if not args.dry_run:
                raise
            output.write(out, "UNKNOWN no token: nothing read; use validate for offline configuration checks")
            return 2
        return mode.run(Context(board, client, out, today or dt.datetime.now(dt.UTC).date(), env), args)
    except SafoError as error:
        report(error, env, err)
        return error.exit_code


def run() -> None:
    raise SystemExit(main())
