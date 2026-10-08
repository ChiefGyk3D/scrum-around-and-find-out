# SPDX-License-Identifier: MIT
"""Build, on the fake, the live project a board.yaml describes, so a test starts from zero drift."""

from __future__ import annotations

import datetime as dt
import io
from pathlib import Path

from fakegh import FakeGitHub
from fakegh.core import FProject
from safo.context import Context
from safo.graphql import Client
from safo.live import LAYOUT_ENUMS
from safo.schema import Board, load_board

DATA = Path(__file__).parent / "data"
DATA_TYPES = {
    "single_select": "SINGLE_SELECT",
    "iteration": "ITERATION",
    "date": "DATE",
    "text": "TEXT",
    "number": "NUMBER",
}


def load_test_board() -> Board:
    return load_board(DATA / "board.yaml")


def build_project(fake: FakeGitHub, board: Board) -> FProject:
    project = fake.add_project(
        board.project.owner_type, board.project.owner, board.project.number or 1, board.project.title
    )
    for f in board.fields:
        made = fake.add_field(
            project, f.name, DATA_TYPES[f.type], [(o.name, o.color, o.description) for o in f.options] or None
        )
        if f.type == "iteration" and f.start:
            made.duration = f.duration_days
            for i in range(f.count):
                start = f.start + dt.timedelta(days=f.duration_days * i)
                made.iterations.append(
                    {
                        "id": fake.new_id("ITER"),
                        "title": f"Sprint {i + 1}",
                        "startDate": start.isoformat(),
                        "duration": f.duration_days,
                    }
                )
    for v in board.views:
        fake.add_view(project, v.name, LAYOUT_ENUMS[v.layout], v.filter)
    return project


def build_world(fake: FakeGitHub, board: Board | None = None) -> tuple[Board, FProject]:
    """The project plus the repositories board.yaml lists, all installed and empty."""
    board = board or load_test_board()
    project = build_project(fake, board)
    for repo in board.repositories:
        fake.add_repo(repo.full_name)
    return board, project


TODAY = dt.date(2026, 10, 7)


def make_context(
    fake: FakeGitHub, board: Board, client: Client, *, today: dt.date = TODAY
) -> tuple[Context, io.StringIO]:
    out = io.StringIO()
    return Context(board, client, out, today, {}), out
