# SPDX-License-Identifier: MIT
"""The command line: argument handling and error reporting."""

from __future__ import annotations

import pytest

from cliutil import BOARD, run_cli
from fakegh import FakeGitHub
from safo.cli import main
from safo.graphql import Client
from safo.modes import load_all
from world import DATA, build_world


def test_every_registered_mode_is_in_the_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["--help"])
    text = capsys.readouterr().out
    assert load_all()
    for mode in load_all():
        assert mode in text


def test_a_bad_board_is_exit_2_with_the_key_named() -> None:
    code, _, err = run_cli("--board", str(DATA / "missing.yaml"), "audit")
    assert code == 2 and err.startswith("error: ") and "cannot read the board file" in err


def test_under_github_actions_the_error_is_an_annotation() -> None:
    code, _, err = run_cli("--board", str(DATA / "missing.yaml"), "audit", env={"GITHUB_ACTIONS": "true"})
    assert code == 2 and err.startswith("::error title=safo::")


def test_no_token_is_exit_2_and_says_what_to_set() -> None:
    code, _, err = run_cli("--board", BOARD, "audit")
    assert code == 2 and "set SAFO_TOKEN" in err


def test_a_refused_token_is_exit_2_and_never_prints_the_token(fake: FakeGitHub, sleeps: list[float]) -> None:
    build_world(fake)
    bad = Client("wrong-token-sentinel", fake.url, sleep=sleeps.append)
    code, out, err = run_cli("--board", BOARD, "audit", client=bad)
    assert code == 2 and err.startswith("error: ")
    assert "wrong-token-sentinel" not in out + err and "Traceback" not in err


def test_a_failed_items_listing_is_exit_2_not_clean(fake: FakeGitHub, client: Client) -> None:
    from fakegh.core import Fault

    build_world(fake)
    fake.faults.append(Fault(status=500, op="ProjectItems", times=50))
    code, out, err = run_cli("--board", BOARD, "audit", client=client)
    assert code == 2 and err.startswith("error: ")
    assert "Traceback" not in err and "clean" not in out
