# SPDX-License-Identifier: Apache-2.0
"""Golden outputs of today's board modes, so a later process-profile change proves the agile path is byte-identical.

Four modes (audit, reconcile --dry-run, status --post --print, agents-status) run through the real command line
against tests/fakegh for the two shipped example boards. Each run's exit code, standard output and standard error
are stored under tests/golden/process-agile/ (spec 2026-10-26-process-profiles.md, sections 2.4 and 11, unit U0).

The clock and the random stop-commands token are frozen: `today` is passed to `safo.cli.main`, `status` gets an
explicit `--since`, and the Codex and Copilot sections of agents-status are switched off because they read the wall
clock and the machine's agents. A test runs everything again with a different date and requires identical bytes.

Fail-closed: a missing golden file fails the test. A test run never writes a golden file. To regenerate them after
an intended change in output, run this module as a script, then review `git diff tests/golden/process-agile/`:

    .venv/bin/python tests/test_golden_process_agile.py --regenerate

Only examples/ boards and invented card titles are used: nothing here comes from a live board.
"""

from __future__ import annotations

import datetime as dt
import io
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest
import yaml

from fakegh import FakeGitHub
from fakegh.core import FContent, FProject
from safo.cli import main
from safo.graphql import Client
from safo.schema import Board, load_board
from world import build_world

ROOT = Path(__file__).parent.parent
GOLDEN = Path(__file__).parent / "golden" / "process-agile"
BOARDS = ("safo", "renegade-penguin")
# argv after the board option, per mode name (the name is the golden file's second part)
MODES: dict[str, tuple[str, ...]] = {
    "audit": ("audit",),
    "reconcile-dry-run": ("--dry-run", "reconcile"),
    "status-post-print": ("status", "--post", "--print", "--no-local", "--since", "2026-10-01"),
    "agents-status": ("agents-status", "--no-codex", "--no-copilot"),
}
FROZEN = dt.date(2026, 10, 26)
OTHER_DAY = dt.date(2027, 3, 14)
CASES = [(b, m) for b in BOARDS for m in MODES]


def golden_name(board: str, mode: str) -> str:
    return f"{board}.{mode}.txt"


def board_copy(board: str, folder: Path) -> Path:
    """A local copy of the example with project.number set, as bootstrap leaves it: the example is never edited."""
    data = yaml.safe_load((ROOT / "examples" / f"{board}.yaml").read_text(encoding="utf-8"))
    data["project"]["number"] = data["project"].get("number") or 1
    copy = folder / f"{board}.yaml"
    copy.write_text(yaml.safe_dump(data), encoding="utf-8")
    return copy


def populate(fake: FakeGitHub, board: Board, project: FProject) -> None:
    """A few cards per repository in every state the four modes tell apart; the same on every run."""
    fields = {f.name for f in board.fields}
    statuses = {o.name for f in board.fields if f.name == board.rules.status_field for o in f.options}
    assert {"Backlog", "Next", "In progress", "Blocked", "Done"} <= statuses

    def put(content: FContent | None, **values: str) -> None:
        fake.add_item(project, content, **{k: v for k, v in values.items() if k in fields})

    for r, repo in enumerate(board.repositories):
        name, base = repo.full_name, r * 10
        put(fake.add_content(name, "Issue", base + 1, "Open work on the board"), Status="In progress", Agent="Claude")
        fake.add_content(name, "Issue", base + 2, "Open work not yet on the board")
        closed = fake.add_content(
            name, "Issue", base + 3, "Closed but still open on the board", state="CLOSED",
            closed_at="2026-10-20T08:00:00Z",
        )  # fmt: skip
        put(closed, Status="Backlog")
        merged = fake.add_content(
            name, "PullRequest", base + 4, "Merged and done", state="MERGED", closed_at="2026-10-22T09:00:00Z"
        )
        put(merged, Status="Done")
        put(fake.add_content(name, "Issue", base + 5, "Waiting on the maintainer"), Status="Blocked", Agent="You")
        put(fake.add_content(name, "Issue", base + 6, "Queued for next"), Status="Next")
        fake.add_content(name, "PullRequest", base + 7, "Open pull request not on the board")
    put(None, Status="Backlog")


def render(board_name: str, mode: str, today: dt.date, client: Client, fake: FakeGitHub, home: Path) -> str:
    """One mode against one example board, as the stored text."""
    path = board_copy(board_name, home)
    board = load_board(path)
    _, project = build_world(fake, board)
    populate(fake, board, project)
    out, err = io.StringIO(), io.StringIO()
    argv = ["--board", str(path), *MODES[mode]]
    # output.block draws a random token for every stop-commands block; freeze it like the clock
    with mock.patch("safo.output.secrets.token_hex", return_value="0" * 32):
        code = main(argv, env={"HOME": str(home)}, client_factory=lambda b, e, d: client, out=out, err=err, today=today)
    return f"exit={code}\n--- stdout ---\n{out.getvalue()}--- stderr ---\n{err.getvalue()}"


def fresh(board_name: str, mode: str, today: dt.date, home: Path) -> str:
    with FakeGitHub().serve() as fake:
        return render(board_name, mode, today, Client(fake.token, fake.url, sleep=lambda s: None), fake, home)


def compare(path: Path, actual: str) -> None:
    """Fail closed: a missing golden file is a failure, never a file the test run creates."""
    hint = f"python tests/{Path(__file__).name} --regenerate"
    assert path.is_file(), f"{path.name} is missing; regenerate deliberately: {hint}"
    assert actual == path.read_text(encoding="utf-8"), f"{path.name} differs from today's output"


@pytest.mark.parametrize(("board", "mode"), CASES, ids=[golden_name(b, m) for b, m in CASES])
def test_output_matches_the_golden_file(board: str, mode: str, tmp_path: Path) -> None:
    compare(GOLDEN / golden_name(board, mode), fresh(board, mode, FROZEN, tmp_path))


@pytest.mark.parametrize(("board", "mode"), CASES, ids=[golden_name(b, m) for b, m in CASES])
def test_a_different_fake_date_gives_identical_bytes(board: str, mode: str, tmp_path: Path) -> None:
    assert fresh(board, mode, OTHER_DAY, tmp_path) == fresh(board, mode, FROZEN, tmp_path)


def test_the_golden_directory_holds_exactly_the_eight_files() -> None:
    assert len(CASES) == 8
    assert sorted(p.name for p in GOLDEN.iterdir()) == sorted(golden_name(b, m) for b, m in CASES)


def test_the_runs_are_not_trivial() -> None:
    """A golden file of an error message would pass forever: each must be a real run with cards in it."""
    for board, mode in CASES:
        text = (GOLDEN / golden_name(board, mode)).read_text(encoding="utf-8")
        assert text.endswith("--- stderr ---\n"), f"{board} {mode}: wrote to stderr"
        assert "#" in text or mode == "audit", f"{board} {mode}: no card in the output"


def test_a_missing_golden_file_fails_and_is_not_created(tmp_path: Path) -> None:
    target = tmp_path / "absent.txt"
    with pytest.raises(AssertionError, match="is missing"):
        compare(target, "anything")
    assert not target.exists()


def test_a_one_character_change_fails_the_comparison(tmp_path: Path) -> None:
    target = tmp_path / "copy.txt"
    target.write_text("exit=0\nclean\n", encoding="utf-8")
    compare(target, "exit=0\nclean\n")
    with pytest.raises(AssertionError, match="differs"):
        compare(target, "exit=0\nclea\n")


def regenerate() -> None:
    GOLDEN.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as home:
        for board, mode in CASES:
            (GOLDEN / golden_name(board, mode)).write_text(fresh(board, mode, FROZEN, Path(home)), encoding="utf-8")


if __name__ == "__main__":
    if sys.argv[1:] != ["--regenerate"]:
        raise SystemExit(f"usage: python tests/{Path(__file__).name} --regenerate")
    regenerate()
    print(f"wrote {len(CASES)} files to {GOLDEN}")
