# SPDX-License-Identifier: MIT
"""A connection node that is not an object, or lacks a key its reader needs, is exit 2 and never "clean"."""

from __future__ import annotations

import dataclasses
import io
from pathlib import Path
from typing import Any

import pytest

from fakegh import FakeGitHub
from fakegh.core import HANDLERS
from safo.cli import main
from safo.errors import MalformedDataError
from safo.graphql import Client
from safo.modes.bootstrap import run as bootstrap_run
from world import build_world, load_test_board, make_context

READS = [
    ("ProjectFieldsOrg", ("organization", "projectV2", "fields")),
    ("ProjectViewsOrg", ("organization", "projectV2", "views")),
    ("ProjectItems", ("node", "items")),
    ("RepoOpenIssues", ("repository", "issues")),
    ("RepoOpenPulls", ("repository", "pullRequests")),
]
BAD_NODES: list[Any] = [{}, 1, False, 0, [], ""]


def append_bad_node(fake: FakeGitHub, op: str, path: tuple[str, ...], bad: Any) -> None:
    real = HANDLERS[op]

    def handler(f: FakeGitHub, v: dict[str, Any]) -> dict[str, Any]:
        data = real(f, v)
        node: Any = data
        for key in path:
            node = node[key]
        node["nodes"].append(bad)
        return data

    fake.handlers[op] = handler


@pytest.mark.parametrize("bad", BAD_NODES, ids=repr)
@pytest.mark.parametrize(("op", "path"), READS, ids=[r[0] for r in READS])
def test_audit_exits_2_and_never_says_clean_for_a_malformed_node(
    fake: FakeGitHub, client: Client, op: str, path: tuple[str, ...], bad: Any
) -> None:
    build_world(fake)
    append_bad_node(fake, op, path, bad)
    out, err = io.StringIO(), io.StringIO()
    board_file = str(Path(__file__).parent / "data" / "board.yaml")
    code = main(["--board", board_file, "audit"], env={}, client_factory=lambda b, e, d: client, out=out, err=err)
    assert code == 2, (out.getvalue(), err.getvalue())
    assert "clean" not in out.getvalue().splitlines() and "clean" not in err.getvalue()


@pytest.mark.parametrize("bad", [{}, 1], ids=repr)
def test_discovery_raises_malformed_data_for_a_malformed_node(fake: FakeGitHub, client: Client, bad: Any) -> None:
    board = load_test_board()
    board = dataclasses.replace(board, project=dataclasses.replace(board.project, number=None))
    fake.add_owner("organization", "acme")
    append_bad_node(fake, "DiscoverProjectsOrg", ("organization", "projectsV2"), bad)
    ctx, _ = make_context(fake, board, client)
    with pytest.raises(MalformedDataError):
        bootstrap_run(ctx, __import__("argparse").Namespace())
    assert fake.mutations == []
