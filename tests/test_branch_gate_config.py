# SPDX-License-Identifier: Apache-2.0
"""Validation of the branch gate's rules keys in board.yaml."""

from __future__ import annotations

from pathlib import Path

import pytest

from safo.errors import ConfigError
from safo.schema import Board, load_board
from world import DATA

SRC = (DATA / "board.yaml").read_text(encoding="utf-8")


def load(tmp_path: Path, lines: str) -> Board:
    path = tmp_path / "b.yaml"
    path.write_text(SRC.replace("\nrules:\n", "\nrules:\n" + lines, 1), encoding="utf-8")
    return load_board(path)


def message(tmp_path: Path, lines: str) -> str:
    with pytest.raises(ConfigError) as info:
        load(tmp_path, lines)
    return str(info.value)


def test_gate_check_with_surrounding_whitespace_says_so(tmp_path: Path) -> None:
    for value in ("' CI green'", "'CI green '", '"CI green\\n"'):
        text = message(tmp_path, f"  gate_check: {value}\n")
        assert "rules.gate_check" in text and "whitespace" in text, text


def test_gate_check_that_is_not_text_does_not_claim_the_empty_string_is_invalid(tmp_path: Path) -> None:
    for value in ("5", "true", "[x]", "{a: b}"):
        text = message(tmp_path, f"  gate_check: {value}\n")
        assert "rules.gate_check" in text and "text" in text, text
        assert "non-empty" not in text, text


def test_gate_check_empty_is_valid_and_means_off(tmp_path: Path) -> None:
    assert load(tmp_path, "  gate_check: ''\n").rules.gate_check == ""


def test_gate_check_long_or_control_characters_are_still_rejected(tmp_path: Path) -> None:
    assert "rules.gate_check" in message(tmp_path, "  gate_check: " + "x" * 101 + "\n")
    assert "rules.gate_check" in message(tmp_path, '  gate_check: "a\\u0001b"\n')


@pytest.mark.parametrize("key", ["gate_exempt_repos", "gate_admin_exempt_repos"])
def test_an_exempt_entry_must_name_a_listed_repository(tmp_path: Path, key: str) -> None:
    text = message(tmp_path, f"  {key}: [acme/typo]\n")
    assert f"rules.{key}[0]" in text and "acme/typo" in text and "repositories" in text, text


@pytest.mark.parametrize("key", ["gate_exempt_repos", "gate_admin_exempt_repos"])
def test_a_listed_repository_is_accepted_whatever_its_case(tmp_path: Path, key: str) -> None:
    board = load(tmp_path, f"  {key}: [acme/widgets, ACME/Manuals]\n")
    assert len(getattr(board.rules, key)) == 2


@pytest.mark.parametrize("key", ["gate_exempt_repos", "gate_admin_exempt_repos"])
def test_a_duplicate_entry_is_an_error(tmp_path: Path, key: str) -> None:
    for entries in ("[acme/widgets, acme/widgets]", "[acme/widgets, ACME/WIDGETS]"):
        text = message(tmp_path, f"  {key}: {entries}\n")
        assert f"rules.{key}[1]" in text and "twice" in text, text
