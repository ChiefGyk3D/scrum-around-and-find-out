# SPDX-License-Identifier: Apache-2.0
"""The guard keeps denying paid use outside the broker flow (#287). The broker entries (`paid`, `paid-dryrun`) are paid
action words: a command that uses one, written out, built at run time or spread over a variable, is denied or treated
as unreadable exactly like the same shape with `ask` or `approve` on main. Nothing is allowed through."""

from __future__ import annotations

import pytest

from safo import geminibrief
from safo.gemini import PaidOnlyThroughBroker

PUBLIC = "gemini-material: public\n"


def rules(text: str) -> set[str]:
    return {rule for rule, _ in geminibrief.findings(text + PUBLIC, PaidOnlyThroughBroker())}


# (shape of the old denial on main with `approve`, the same shape with each paid action word)
SHAPES = [
    "safo gemini {w} --model m --job j --prompt-file p --max-usd 1\n",
    "A={w}; safo gemini $A --model m --job j --max-usd 1\n",
    'eval "safo gemini {w} --model m --job j --max-usd 1"\n',
    "bash -c 'safo gemini {w} --model m --job j --max-usd 1'\n",
    "echo {w} --model m --job j | xargs safo gemini\n",
    "for a in {w}; do safo gemini $a --model m; done\n",
    "safo gemini $X {w}\n",
    "safo gemini $X --job j --max-usd 1\n",
]


@pytest.mark.parametrize("word", ["paid", "paid-dryrun"])
@pytest.mark.parametrize("shape", SHAPES)
def test_every_shape_denied_for_approve_is_denied_for_the_paid_words(shape: str, word: str) -> None:
    on_main = rules(shape.format(w="approve"))
    assert "gemini-paid" in on_main, "the reference shape is denied (it was on main)"
    assert "gemini-paid" in rules(shape.format(w=word)), shape.format(w=word)


@pytest.mark.parametrize("word", ["paid", "paid-dryrun"])
def test_the_negative_case_prose_about_the_paid_tier_is_not_a_step(word: str) -> None:
    assert rules(f"The {word} tier is used through the broker when the maintainer allows it.\n") == set()
    assert rules("Run `safo gemini quota --model gemini-3.6-flash` to see the line.\n") == set()
