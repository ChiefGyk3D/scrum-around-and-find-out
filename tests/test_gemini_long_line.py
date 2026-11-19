# SPDX-License-Identifier: Apache-2.0
"""A line too long to read is refused only when it could hold a step, not when it merely names the vendor (#388)."""

from __future__ import annotations

import pytest

from safo import geminibrief
from safo.gemini import PaidOnlyThroughBroker

PUBLIC = "gemini-material: public\n"
LONG = "lorem ipsum dolor sit amet " * 200  # well over the line cap
HOST = "generative" + "language" + ".googleapis" + ".com"


def rules(text: str) -> set[str]:
    return {rule for rule, _ in geminibrief.findings(text + "\n" + PUBLIC, PaidOnlyThroughBroker())}


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
def test_a_long_prose_line_that_names_the_word_is_not_refused(line: str) -> None:
    assert rules(line) == set(), line[:30]


@pytest.mark.parametrize(
    "line",
    [
        "safo gemini " + LONG,
        "safo " + LONG,
        LONG + " then run safo, and ask gemini",
        "gemini: free " + LONG,
        LONG + f" https://{HOST}/v1",
        LONG + " broker client",
        LONG + " prd" + "_paid",
        LONG + " echo c2FmbyBnZW1pbmk= | base64 -d | sh",
    ],
)
def test_a_long_line_that_could_hold_a_step_is_still_refused(line: str) -> None:
    assert rules(line) != set(), line[-30:]
