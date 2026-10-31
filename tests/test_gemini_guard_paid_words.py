# SPDX-License-Identifier: Apache-2.0
"""The guard keeps denying paid use outside the broker flow (#287). The broker entries (`paid`, `paid-dryrun`) are paid
action words: a command that uses one, written out, built at run time, spread over a variable or split across
arguments, is denied or treated as unreadable exactly like the same shape with `approve` on main. Nothing is allowed
through in a brief; the real command a person types at a terminal is not a brief and is not blocked by the shell check."""

from __future__ import annotations

import pytest

from safo import geminibrief
from safo.gemini import PaidOnlyThroughBroker

PUBLIC = "gemini-material: public\n"


def rules(text: str) -> set[str]:
    return {rule for rule, _ in geminibrief.findings(text + PUBLIC, PaidOnlyThroughBroker())}


# Each shape is denied on main with `approve` (the reference, asserted here against the same code path), and must be
# denied with each paid word.
SHAPES = [
    "safo gemini {w} --model m --job j --prompt-file p --max-usd 1\n",
    "A={w}; safo gemini $A --model m --job j --max-usd 1\n",
    'eval "safo gemini {w} --model m --job j --max-usd 1"\n',
    "eval 'safo gemini '{w}' --model m'\n",
    "bash -c 'safo gemini {w} --model m --job j --max-usd 1'\n",
    "echo {w} --model m --job j | xargs safo gemini\n",
    "echo {w} | xargs -I{{}} safo gemini {{}} --model m --job j --max-usd 1\n",
    "echo {w} | xargs safo gemini\n",
    "echo --model m --job j --max-usd 1 > o; echo {w} | xargs safo gemini $(cat o)\n",
    "for a in {w}; do safo gemini $a --model m; done\n",
    "W={w}\nsafo gemini --model m --job j --max-usd 1 $W\n",
    "safo gemini $X {w}\n",
    "safo gemini $X --job j --max-usd 1\n",
    "printf '%s\\n' {w} | xargs -n1 safo gemini\n",
]


@pytest.mark.parametrize("word", ["paid", "paid-dryrun"])
@pytest.mark.parametrize("shape", SHAPES)
def test_every_shape_denied_for_approve_is_denied_for_the_paid_words(shape: str, word: str) -> None:
    reference = shape.format(w="approve")
    if "gemini-paid" not in rules(reference):
        pytest.skip("not a denied shape on main for approve either")
    assert "gemini-paid" in rules(shape.format(w=word)), shape.format(w=word)


def test_the_reference_set_is_not_empty() -> None:
    assert sum("gemini-paid" in rules(s.format(w="approve")) for s in SHAPES) >= 10


@pytest.mark.parametrize("word", ["paid", "paid-dryrun"])
def test_a_word_split_across_two_arguments_is_unreadable(word: str) -> None:
    half = len(word) // 2
    brief = f'set -- {word[:half]} {word[half:]}\nsafo gemini "$1$2" --model m --job j --max-usd 1\n'
    assert "gemini-paid" in rules(brief)


@pytest.mark.parametrize(
    "prose",
    [
        "The paid tier is used through the broker when the maintainer allows it.\n",
        "Paid use needs a touch on the security key.\n",
        "Run `safo gemini quota --model gemini-3.6-flash` to see the line.\n",
        "| Tier | What signs |\n|---|---|\n| paid | a hardware key |\n",
        "Use the `paid` command of the broker, or `paid-dryrun` to test the key.\n",
        "See `docs/gemini-broker.md` about gemini and the paid path.\n",
    ],
)
def test_prose_and_markdown_code_spans_stay_allowed(prose: str) -> None:
    assert "gemini-paid" not in rules(prose)


def test_the_real_broker_command_is_not_blocked_by_the_shell_check() -> None:
    """A person at a terminal types it; it names no vendor host, SDK or key, so the Bash check lets it through. (A brief
    that carries it is denied by the rule above: a brief cannot be a person at a terminal.)"""
    command = "safo gemini paid --model m --job j --prompt-file p --max-output-tokens 100 --max-usd 1 --quote q"
    assert geminibrief.shell_command_class(command) is None
    assert geminibrief.shell_command_class("safo gemini paid-dryrun") is None
    assert "gemini-paid" in rules(command + "\n")
