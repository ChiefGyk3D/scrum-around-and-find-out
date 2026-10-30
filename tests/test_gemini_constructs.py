# SPDX-License-Identifier: Apache-2.0
"""A command built across lines (variables, arrays, functions, eval, xargs) is read as the command it is, or blocked
as unreadable when it cannot be resolved; the same constructs in a brief with no Gemini words are left alone (#200)."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from safo.geminibrief import GEMINI_MATERIAL, GEMINI_PAID, findings

OK = "id-0123456789ab"
PUBLIC = "gemini-material: public\n"


def accepts(record: str) -> str | None:
    return None if record == OK else "no such approval record"


def rules(prompt: str, check: Callable[[str], str | None] | None = accepts) -> list[str]:
    return [rule for rule, _ in findings(prompt, check, ())]


def why(prompt: str) -> str:
    return " ".join(text for _, text in findings(prompt, accepts, ()))


BLOCKED = {
    "two plain assignments, then an expansion": "A=safo\nB=gemini\n$A $B ask --paid --model m\n",
    "assignments with quotes": 'A="safo"\nB=\'gemini\'\n"$A" "${B}" ask --paid --model m\n',
    "an array": 'CMD=(safo gemini ask --paid)\n"${CMD[@]}"\n',
    "an array built in pieces": 'C=(safo)\nC+=(gemini ask)\n"${C[@]}" --paid\n',
    "a function": 'f() {\n  "$1" "$2" ask --paid\n}\nf safo gemini\n',
    "a function keyword": "function run {\n  $1 $2 ask --paid\n}\nrun safo gemini\n",
    "a continuation": "A=safo B=gemini \\\n$A $B ask --paid --model m\n",
    "an environment prefix": "A=safo B=gemini env $A $B ask --paid --model m\n",
    "an assignment from a substitution": "A=$(echo safo)\nB=gemini\n$A $B ask --paid\n",
    "a backtick assignment": "A=`echo safo`\nB=gemini\n$A $B ask --paid\n",
    "an undefined variable": "$A $B ask --paid\nwords: safo gemini\n",
    "eval of a built string": 'X="safo gemini"\neval "$X ask --paid"\n',
    "xargs": "printf 'safo gemini ask --paid' |\nxargs -n1 echo\nxargs ask --paid\n",
    "a shell -c": "S='safo gemini'\nbash -c \"$S ask --paid\"\n",
    "export": "export A=safo\nexport B=gemini\n$A $B ask --paid --model m\n",
}


@pytest.mark.parametrize("name", sorted(BLOCKED))
def test_a_paid_command_built_across_lines_is_blocked(name: str) -> None:
    assert GEMINI_PAID in rules(BLOCKED[name] + PUBLIC), name


def test_a_block_names_the_construct_and_repeats_no_text() -> None:
    text = why('CMD=(safo gemini ask --paid)\n"${CMD[@]}"\n' + PUBLIC)
    assert "array" in text and "CMD" not in text
    assert "function" in why(BLOCKED["a function"] + PUBLIC)
    assert "expansion" in why(BLOCKED["an assignment from a substitution"] + PUBLIC)


def test_a_plain_two_line_assignment_is_read_as_the_command_it_is() -> None:
    ok = "A=safo\nB=gemini\n$A $B ask --paid --model m --cap 1.5 --approval " + OK + " --material public\n"
    assert rules(ok + PUBLIC) == []
    no_record = "A=safo\nB=gemini\n$A $B ask --paid --model m --cap 1.5 --approval missing-record-1 --material public\n"
    assert GEMINI_PAID in rules(no_record + PUBLIC)
    over_cap = "A=safo\nB=gemini\n$A $B ask --paid --model m --cap 3 --approval " + OK + " --material public\n"
    assert GEMINI_PAID in rules(over_cap + PUBLIC)


def test_an_assignment_resolves_for_later_lines_only() -> None:
    late = "$A $B ask --paid --model m\nA=safo\nB=gemini\n"
    assert GEMINI_PAID in rules(late + PUBLIC)


ALLOWED = {
    "the constructs without any Gemini word": "A=ls\nB=-l\n$A $B ask --paid\nf() { echo hi; }\nxargs -n1 echo\n",
    "an array without Gemini words": 'C=(git status)\n"${C[@]}" --paid\n',
    "a Gemini quota command through variables": "A=safo\nB=gemini\n$A $B quota --model m\n",
    "prose naming Gemini with an unrelated assignment": "X=1\nThe notes mention gemini and safo only in prose.\n",
    "one literal free command and a plain assignment": (
        "X=1\nsafo gemini ask --model m --prompt-file p.txt --material public\n" + PUBLIC
    ),
    "a markdown code span at the start of a line": (
        "Notes on safo.\nNotes on gemini.\nTo ask is fine.\n`--quoted-at` and `docs/x.md` are options.\n"
    ),
}


@pytest.mark.parametrize("name", sorted(ALLOWED))
def test_the_same_constructs_are_left_alone_where_nothing_is_built_for_gemini(name: str) -> None:
    assert rules(ALLOWED[name]) == [], name


def test_a_free_command_read_through_variables_still_needs_the_material_line() -> None:
    brief = "A=safo\nB=gemini\n$A $B ask --model m --prompt-file p.txt\n"
    assert rules(brief) == [GEMINI_MATERIAL]
    assert rules(brief + PUBLIC) == []


VALID_PAID = "safo gemini ask --paid --model m --cap 1.5 --approval " + OK + " --material public\n"
HIDING = [
    "X=foo\\ bar",
    "eval true",
    "xargs -n1 echo",
    "tar -c x",
    "f() { true; }",
    "function g { true; }",
    "X=$(date)",
    "Y=(1 2)",
    "Z+=(3)",
]


@pytest.mark.parametrize("line", HIDING)
def test_each_hiding_construct_alone_makes_a_brief_with_a_paid_step_unreadable(line: str) -> None:
    """The command itself is one plain line, so only the other line's construct can be what blocks it."""
    assert rules(VALID_PAID + PUBLIC) == []
    assert GEMINI_PAID in rules(line + "\n" + VALID_PAID + PUBLIC), line


@pytest.mark.parametrize("line", HIDING)
def test_the_same_construct_beside_a_brief_without_a_paid_step_is_left_alone(line: str) -> None:
    assert rules(line + "\nNotes on safo and gemini, nothing to run.\n") == []


@pytest.mark.parametrize("words", ["Notes on safo only.", "Notes on gemini only."])
def test_the_rule_needs_both_words_not_one(words: str) -> None:
    assert rules(f"{words}\neval true\nTo ask --paid is not a command.\n") == []
