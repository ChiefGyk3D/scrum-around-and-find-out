# SPDX-License-Identifier: Apache-2.0
"""A brief line over the cap is refused unread when anything in it could matter, even only the vendor word (#388).

This part of issue 388 is NOT fixed: an unread long line cannot be shown harmless, so the old refusal stays. The
payload is built from fragments at run time; it is a program that rebuilds the vendor host and sends private text.
"""

from __future__ import annotations

import pytest

from safo import geminibrief
from safo.gemini import PaidOnlyThroughBroker

PUBLIC = "gemini-material: public\n"
LONG = "lorem ipsum dolor sit amet " * 200  # well over the line cap


def rules(text: str) -> set[str]:
    return {rule for rule, _ in geminibrief.findings(text + "\n" + PUBLIC, PaidOnlyThroughBroker())}


def program() -> str:
    host = "".join(["gener", "ative", "lang", "uage.goo", "gle", "apis.com"])
    return "ru" + "by -e 'h=\"" + host + '"; u=URI("https://"+h+"/models/gemini:go"); Net::HTTP.post(u,ENV["K"])\''


def test_the_fixture_is_over_the_cap() -> None:
    assert len(LONG) > geminibrief.LINE_CAP


@pytest.mark.parametrize(
    "line",
    [
        "gemini " + LONG,
        LONG + " the Gemini review said so",
        "Notes on the Gemini free tier. " + LONG,
    ],
)
def test_a_long_line_that_only_names_the_vendor_is_still_refused_unread(line: str) -> None:
    assert rules(line) != set(), line[:30]


@pytest.mark.parametrize("size", [geminibrief.LINE_CAP + 1, geminibrief.LINE_CAP + 500])
def test_a_long_program_that_names_gemini_is_refused(size: int) -> None:
    line = program()
    line = line + " #" + "x" * (size - len(line) - 2)
    assert len(line) == size
    assert rules(line) != set()


@pytest.mark.parametrize(
    "line",
    [
        "safo gemini " + LONG,
        "safo " + LONG,
        LONG + " then run safo, and ask gemini",
        "gemini: free " + LONG,
        LONG + " broker client",
        LONG + " prd" + "_paid",
        LONG + " echo c2FmbyBnZW1pbmk= | base64 -d | sh",
    ],
)
def test_a_long_line_that_could_hold_a_step_is_still_refused(line: str) -> None:
    assert rules(line) != set(), line[-30:]


def test_the_relaxation_is_gone() -> None:
    assert geminibrief.relevant("gemini " + LONG) is True
    assert "long_line" not in geminibrief.relevant.__code__.co_varnames
