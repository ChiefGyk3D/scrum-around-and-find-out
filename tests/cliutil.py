# SPDX-License-Identifier: MIT
"""Run the board-based command line in-process."""

from __future__ import annotations

import io

from safo.cli import default_client, main
from safo.graphql import Client
from world import DATA

BOARD = str(DATA / "board.yaml")


def run_cli(*argv: str, env: dict[str, str] | None = None, client: Client | None = None) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    factory = (lambda b, e, d: client) if client else default_client
    code = main(list(argv), env=env or {}, client_factory=factory, out=out, err=err)
    return code, out.getvalue(), err.getvalue()
