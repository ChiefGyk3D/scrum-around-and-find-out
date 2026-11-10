# SPDX-License-Identifier: Apache-2.0
"""`safo ratebudget` and `safo card` are subcommands that wrap the standalone entry points (#357 follow-up)."""

from __future__ import annotations

from pathlib import Path

import pytest

from localcli import cli, tool
from safo import card_cli, ratebudget_cli
from safo.modes import load_all
from safo.modes.hooks import TOP_LEVEL_COMMANDS

CARD = ("example/repo#5", "Epic=Guard", "--item-id", "123", "--dry-run")


def test_both_names_are_registered_and_in_the_guards_static_list() -> None:
    assert {"ratebudget", "card"} <= set(load_all())
    assert {"ratebudget", "card"} <= set(TOP_LEVEL_COMMANDS)


def test_safo_ratebudget_prints_what_safo_ratebudget_prints(tmp_path: Path) -> None:
    # two homes: the unknown-account note is said once per home, so the second call in one home would be shorter
    via = cli("ratebudget", home=tmp_path / "a")
    assert via == tool(ratebudget_cli.main, home=tmp_path / "b") and via[1].startswith("ratebudget:")


def test_safo_ratebudget_takes_the_same_options(tmp_path: Path) -> None:
    code, out, _ = cli("ratebudget", "--by-caller", "--json", home=tmp_path)
    assert code == 0 and out.startswith("{")


def test_safo_card_dry_run_prints_the_request_and_sends_nothing(tmp_path: Path) -> None:
    via = cli("card", *CARD, home=tmp_path / "a")
    alone = tool(card_cli.main, *CARD, home=tmp_path / "b")
    assert via[0] == alone[0] == 0, (via, alone)
    assert "PATCH" in via[1] and via[1] == alone[1]


def test_safo_card_without_an_issue_is_a_usage_error(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as stop:
        cli("card", home=tmp_path)
    assert stop.value.code == 2
