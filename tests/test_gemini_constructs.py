# SPDX-License-Identifier: Apache-2.0
"""A command built across lines (variables, arrays, functions, eval, xargs) is read as the command it is, or blocked
as unreadable when it cannot be resolved; the same constructs in a brief with no Gemini words are left alone (#200)."""

from __future__ import annotations

import time
from collections.abc import Callable

import pytest

from safo.geminibrief import GEMINI_MATERIAL, GEMINI_PAID, LINE_CAP, _expansion_at_command, findings

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
    "sh -c true",
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


# -- round six: caps, lexer failures, comments, concealed words, and ordinary briefs ---------------------------------

FREE = "safo gemini ask --model gemini-3.6-flash --prompt-file p.txt --material public\n"

ORDINARY = {
    "python -c": 'python -c "print(1)"',
    "bash -c": 'bash -c "pytest -q"',
    "find with xargs": "find . -print0 | xargs -0 wc -l",
    "a helper function": "helper() { echo hi; }",
    "a function declaration": "function build { make; }",
    "an unrelated array": "FILES=(a b c)",
    "a revision from a substitution": "REV=$(git rev-parse HEAD)",
    "an unrelated eval": 'eval "ls -l"',
    "tar -c": "tar -c archive src",
    "a chained build": "make -j4 && ./run.sh",
}


@pytest.mark.parametrize("name", sorted(ORDINARY))
def test_ordinary_additions_beside_a_free_gemini_command_are_allowed(name: str) -> None:
    assert rules(ORDINARY[name] + "\n" + FREE + PUBLIC) == [], name
    assert rules(FREE + PUBLIC + ORDINARY[name] + "\n") == [], name


def test_the_ten_ordinary_briefs_are_all_in_the_fixture() -> None:
    assert len(ORDINARY) == 10


CONCEALED = {
    "ansi-c words": "$'\\x73afo' $'gemini' ask --paid --model m\n",
    "ansi-c assignments with octal": "A=$'\\163afo'\nB=$'\\147emini'\n$A $B ask --paid --model m\n",
    "ansi-c for every word": "A=$'\\x73\\x61\\x66\\x6f'\nB=$'\\x67emini'\n$A $B $'\\x61sk' --paid\n",
    "printf -v": "printf -v A '\\x73afo'\nprintf -v B 'gemini'\n$A $B ask --paid --model m\n",
    "an unresolved substitution": "A=$(printf '\\x73afo')\n$A gemini ask --paid\n",
    "every word unresolved": "A=$(printf '\\x73afo')\nB=$(printf '\\x67emini')\n$A $B $(printf '\\x61sk') --paid\n",
    "printf -v with a conversion": "printf -v A '%s' safo\n$A gemini ask --paid\n",
}


@pytest.mark.parametrize("name", sorted(CONCEALED))
def test_words_built_by_escapes_do_not_hide_a_paid_command(name: str) -> None:
    assert GEMINI_PAID in rules(CONCEALED[name] + PUBLIC), name


def test_plain_escapes_are_read_as_the_command_they_produce() -> None:
    ok = "A=$'\\x73afo'\nB=gemini\n$A $B ask --paid --model m --cap 1.5 --approval " + OK + " --material public\n"
    assert rules(ok + PUBLIC) == []
    assert GEMINI_PAID in rules(ok.replace(OK, "missing-record-1") + PUBLIC)


def test_escapes_and_substitutions_in_a_brief_that_builds_no_gemini_command_are_left_alone() -> None:
    assert rules("A=$'\\x41'\n$A foo\n") == []
    assert rules("printf -v A '\\x41'\n$A foo\nthen ask --paid is only prose\n") == []
    assert rules("echo $'\\x41'\n") == []


def test_an_expanded_line_past_the_line_limit_is_unreadable_not_dropped() -> None:
    brief = "A=" + "x" * 3000 + "\necho $A$A safo gemini ask --model m\n" + PUBLIC
    assert GEMINI_PAID in rules(brief)


def test_amplified_expansions_are_bounded_in_time_and_size() -> None:
    big = "A=" + "x" * (LINE_CAP - 100) + "\n"
    nested = big + "$A" * 1500 + "\n" + "\n".join("$A$A$A" for _ in range(3000)) + "\nsafo gemini quota --model m\n"
    started = time.monotonic()
    found = rules(nested + PUBLIC)
    assert time.monotonic() - started < 3.0
    assert GEMINI_PAID in found


def test_a_line_the_lexer_cannot_read_is_unreadable_and_comments_are_not_code() -> None:
    assert _expansion_at_command('echo "$A') is True
    assert _expansion_at_command("echo 'x") is False
    assert _expansion_at_command("ls # $A and `date`") is False
    assert _expansion_at_command("# $A is described here") is False
    assert _expansion_at_command("$A ask") is True


def test_resolve_checks_the_clock_per_line_and_per_substitution() -> None:
    from safo.geminibrief import _resolve

    ticks: list[int] = []
    _resolve(["A=x", "$A $A", "$A"], lambda: ticks.append(1))
    assert len(ticks) == 3 + 3, "one check per line and one per substitution"


def test_a_rule_that_runs_past_the_deadline_blocks_the_brief() -> None:
    brief = "A=x\n" * 50 + "safo gemini ask --paid --model m\n" + PUBLIC
    assert GEMINI_PAID in [r for r, _ in findings(brief, accepts, (), deadline=time.monotonic() - 1)]


def test_a_tar_c_beside_a_paid_command_is_not_a_hiding_construct_but_a_shell_c_is() -> None:
    assert rules("tar -c archive src\n" + VALID_PAID + PUBLIC) == []
    assert GEMINI_PAID in rules("bash -c true\n" + VALID_PAID + PUBLIC)
    assert GEMINI_PAID in rules("python3 -c 'print(1)'\n" + VALID_PAID + PUBLIC)


def test_a_backtick_command_word_is_a_substitution_and_a_markdown_span_is_not() -> None:
    assert GEMINI_PAID in rules("`echo safo` gemini ask --paid --model m\n" + PUBLIC)
    assert rules("Run `quota` or `approve <job>` as described.\nsafo and gemini are named here.\n") == []


def test_escape_words_make_a_brief_relevant_only_with_a_gemini_option_or_action() -> None:
    from safo.geminibrief import relevant

    assert not relevant("echo $'\\x41'\n")
    assert relevant("echo $'\\x41' --paid\n")


def test_an_unresolved_value_as_an_argument_of_a_line_with_a_gemini_option_is_unreadable() -> None:
    notes = "Notes on safo.\nNotes on gemini.\nTo ask is fine.\n"
    assert GEMINI_PAID in rules(notes + "deploy $TARGET --paid\n" + PUBLIC)
    assert rules(notes + "deploy staging --paid\n") == []
