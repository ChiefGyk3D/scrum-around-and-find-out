# SPDX-License-Identifier: Apache-2.0
"""Each shipped board's `Agents at work` view lists every working and waiting status of its agents config (#175)."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest

from safo.schema import Board, load_board

ROOT = Path(__file__).parent.parent
VIEW = "Agents at work"
# collect loosely: any yaml under boards/ or examples/ that names the view (examples/ also holds non-board files)
FILES = sorted(
    p for p in [*(ROOT / "boards").glob("*.yaml"), *(ROOT / "examples").glob("*.yaml")] if VIEW in p.read_text()
)


def listed_statuses(board: Board) -> set[str]:
    """The names in the view's `status:` term: quoted names may hold spaces, bare ones end at a comma."""
    views = [v for v in board.views if v.name == VIEW]
    assert len(views) == 1, f"{VIEW!r} must be defined exactly once"
    match = re.fullmatch(r"status:(.+)", views[0].filter.strip())
    assert match, f"the view filter must be one status: term, got {views[0].filter!r}"
    return {a or b for a, b in re.findall(r'"([^"]+)"|([^,"]+)', match.group(1))}


def missing(board: Board) -> set[str]:
    return {*board.agents.working, *board.agents.waiting} - listed_statuses(board)


def test_the_guard_collects_the_boards_and_the_examples() -> None:
    names = {p.name for p in FILES}
    assert {"siem-stack.board.yaml", "all-projects.board.yaml", "siem-and-cah.board.yaml"} <= names
    assert {"safo.yaml", "renegade-penguin.yaml"} <= names


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_the_agents_view_lists_every_working_and_waiting_status(path: Path) -> None:
    board = load_board(path)
    assert board.agents.waiting, "the board must define a waiting status or this guard proves nothing"
    assert missing(board) == set()


def test_dropping_blocked_from_a_boards_view_is_caught(tmp_path: Path) -> None:
    copy = tmp_path / "board.yaml"
    shutil.copy(ROOT / "boards" / "siem-stack.board.yaml", copy)
    text = copy.read_text()
    assert ",Blocked'" in text
    copy.write_text(text.replace(",Blocked'", "'", 1))
    assert missing(load_board(copy)) == {"Blocked"}
