# SPDX-License-Identifier: Apache-2.0
"""safo-file routing, Daybreak review round 3 (issue #455): the whole public-ok line must be plain ASCII.

The characters are built with chr() so this file holds no invisible or lookalike character itself."""

from __future__ import annotations

from pathlib import Path

import pytest

from safo import idea_gate
from test_idea_gate import Fakes
from test_idea_gate_routes_round2 import Looks, file_in

GOOD = "generic security tracking, no private detail"

LINES = [
    pytest.param("public-" + chr(0x43E) + "k: " + GOOD, id="cyrillic-in-the-keyword"),
    pytest.param("publ" + chr(0x3AF) + "c-ok: " + GOOD, id="greek-in-the-keyword"),
    pytest.param("public-ok: generic security tr" + chr(0x430) + "cking, no private detail", id="cyrillic-in-reason"),
    pytest.param("public-ok: generic s" + chr(0x3B5) + "curity tracking, no private detail", id="greek-in-reason"),
    pytest.param(
        "public-ok: generic security" + chr(0x200B) + " tracking, no private detail", id="zero-width-in-reason"
    ),
    pytest.param("public-ok: generic s" + chr(0xE9) + "curity tracking, no private detail", id="accent-in-reason"),
    pytest.param("public-ok: " + GOOD + " " + chr(0x1F680), id="emoji-in-reason"),
]


@pytest.mark.parametrize("line", LINES)
def test_a_public_ok_line_with_a_non_ascii_character_does_not_override(tmp_path: Path, line: str) -> None:
    f = Fakes(tmp_path)
    code, _, err = file_in(f, Looks(True), "--allow-public", "--class", "homelab", body=line)
    assert code == 1 and f.created == []
    assert "plain ASCII" in err
    assert all(ord(c) < 128 for c in err)  # the characters are never echoed


def test_a_plain_ascii_reason_is_still_accepted(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    assert file_in(f, Looks(True), "--allow-public", "--class", "homelab", body="public-ok: " + GOOD)[0] == 0


def test_a_valid_ascii_line_counts_even_beside_a_bad_one(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    body = "public-ok: generic s" + chr(0xE9) + "curity tracking\npublic-ok: " + GOOD
    assert file_in(f, Looks(True), "--allow-public", "--class", "homelab", body=body)[0] == 0


def test_an_unclassifiable_text_is_not_rescued_by_a_non_ascii_reason(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    body = "public-ok: generic s" + chr(0x3B5) + "curity tracking, no detail"
    code, _, err = file_in(f, Looks(True), "--allow-public", title="pr" + chr(0x43E) + "xmox", body=body)
    assert code == 1 and "plain ASCII" in err and f.created == []


def test_the_reason_check_itself_reports_the_ascii_rule() -> None:
    ok, problem = idea_gate.public_ok_reason("public-ok: generic s" + chr(0xE9) + "curity tracking")
    assert not ok and "plain ASCII" in problem
    assert idea_gate.public_ok_reason("public-ok: " + GOOD) == (True, "")
    assert idea_gate.public_ok_reason("no line here") == (False, "")
