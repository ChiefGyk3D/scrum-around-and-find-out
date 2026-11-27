# SPDX-License-Identifier: Apache-2.0
"""safo-file routing, Daybreak review round 2, Unicode finding (issue #455): text a public target cannot classify.

The characters are built with chr() so this file holds no invisible or lookalike character itself."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from safo import idea_gate_routes as routes
from test_idea_gate import Fakes
from test_idea_gate_routes import ledger_records
from test_idea_gate_routes_round2 import Looks, file_in

REASON = "public-ok: generic security tracking, no private detail"

HAZARDS = [
    pytest.param("rebuild the pr" + chr(0x43E) + "xmox host", "letters or numerals", id="cyrillic-lookalike"),
    pytest.param("rebuild the pr" + chr(0x3BF) + "xmox host", "letters or numerals", id="greek-lookalike"),
    pytest.param("rebuild the " + chr(0x540) + "ost", "letters or numerals", id="armenian"),
    pytest.param("update " + chr(0x4E2D) + chr(0x6587) + " notes", "letters or numerals", id="cjk"),
    pytest.param("rebuild the k" + chr(0x668) + "s cluster", "letters or numerals", id="non-ascii-numeral"),
    pytest.param("rebuild the " + chr(0x1D18) + "roxmox host", "letters or numerals", id="small-capital-latin"),
    pytest.param("rebuild the " + chr(0xF8) + "ps host", "letters or numerals", id="latin-letter-with-no-ascii-base"),
    pytest.param("rebuild the prox" + chr(0x34F) + "mox host", "combining marks", id="invisible-combining-mark"),
    pytest.param("rebuild the prox" + chr(0xFE0F) + "mox host", "combining marks", id="variation-selector"),
    pytest.param(
        "rebuild the prox" + chr(0xE0101) + "mox host", "combining marks", id="ideographic-variation-selector"
    ),
    pytest.param("rebuild the prox" + chr(0x202E) + "mox host", "format", id="bidi-override"),
    pytest.param("rebuild the prox" + chr(0x2066) + "mox host", "format", id="bidi-isolate"),
    pytest.param("rebuild the prox" + chr(0xE0041) + "mox host", "format", id="tag-character"),
    pytest.param("rebuild the prox" + chr(0x200D) + "mox host", "format", id="zero-width-joiner"),
    pytest.param("rebuild the prox" + chr(0x1B) + "mox host", "control", id="control-character"),
    pytest.param("rebuild the prox" + chr(0xE000) + "mox host", "private-use", id="private-use"),
]


@pytest.mark.parametrize(("title", "named"), HAZARDS)
def test_a_text_that_hides_behind_unicode_is_refused_for_a_public_target(
    tmp_path: Path, title: str, named: str
) -> None:
    f = Fakes(tmp_path)
    code, _, err = file_in(f, Looks(True), title=title)  # the working repo, so only the text can refuse it
    assert code == 1 and f.created == []
    assert "cannot be classified" in err and named in err
    assert all(ord(c) < 128 for c in err)  # the characters themselves are never echoed
    assert ledger_records(f)[-1]["outcome"] == "refused"


@pytest.mark.parametrize(("title", "named"), HAZARDS)
def test_the_override_still_works_for_such_a_text(tmp_path: Path, title: str, named: str) -> None:
    f = Fakes(tmp_path)
    assert file_in(f, Looks(True), "--allow-public", title=title, body=REASON)[0] == 0
    assert file_in(f, Looks(True), title=title, body=REASON)[0] == 1  # the reason alone is not enough
    assert len(f.created) == 1


@pytest.mark.parametrize(("title", "named"), HAZARDS)
def test_a_private_target_is_not_affected(tmp_path: Path, title: str, named: str) -> None:
    f = Fakes(tmp_path)
    assert file_in(f, Looks(False), title=title)[0] == 0 and len(f.created) == 1


def test_explicit_product_does_not_get_around_it(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    assert file_in(f, Looks(True), "--class", "product", title="pr" + chr(0x43E) + "xmox")[0] == 1


def test_ordinary_accented_latin_text_and_emoji_are_filed(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    accented = (
        "caf" + chr(0xE9) + " r" + chr(0xE9) + "sum" + chr(0xE9) + " na" + chr(0xEF) + "ve " + chr(0xF1) + chr(0xFC)
    )
    assert file_in(f, Looks(True), title=accented, body="curly " + chr(0x201C) + "quotes" + chr(0x201D))[0] == 0
    assert file_in(f, Looks(True), title="ship it " + chr(0x1F680))[0] == 0
    assert file_in(f, Looks(True), title="e" + chr(0x301) + " decomposed")[0] == 0  # NFKC composes it
    assert len(f.created) == 3


def test_an_accent_does_not_hide_a_private_word(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    code, _, err = file_in(f, Looks(True), title="rebuild the pr" + chr(0xF3) + "xmox host")
    assert code == 1 and "private-workflow" in err


@pytest.mark.parametrize(("title", "named"), HAZARDS)
def test_the_check_names_the_class_of_character(title: str, named: str) -> None:
    assert named in routes.unclassifiable(title)


def test_plain_text_has_nothing_to_report() -> None:
    assert routes.unclassifiable("plain ascii\tand\nlines, with punctuation: (ok)") == ""


def test_the_check_is_linear_on_a_full_size_text() -> None:
    many = ("a" + chr(0x34F) + chr(0x43E) + chr(0x202E)) * (routes.TEXT_LIMIT // 4)
    start = time.monotonic()
    assert routes.unclassifiable(many) != ""
    assert routes.unclassifiable(chr(0x43E) * routes.TEXT_LIMIT) != ""
    assert routes.unclassifiable((chr(0xE9) + " ") * (routes.TEXT_LIMIT // 2)) == ""
    assert time.monotonic() - start < 10


def test_a_full_size_accented_text_is_matched_in_bounded_time() -> None:
    text = (chr(0xE9) + "x ") * (routes.TEXT_LIMIT // 3)
    start = time.monotonic()
    assert routes.matching(routes.default_table(), text) == []
    assert time.monotonic() - start < 10
