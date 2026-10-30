# SPDX-License-Identifier: Apache-2.0
"""A command built across lines (variables, arrays, functions, eval, xargs) is read as the command it is, or blocked
as unreadable when it cannot be resolved; the same constructs in a brief with no Gemini words are left alone (#200)."""

from __future__ import annotations

import subprocess
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from safo.geminibrief import GEMINI_PAID, _expansion_at_command, findings

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


def test_a_command_built_from_variables_is_blocked_by_design_whatever_it_says() -> None:
    """No shell semantics are modeled: a variable assigned in the brief that reaches a command position is unreadable,
    even when the command it builds would have been fine."""
    for tail in (
        "--paid --model m --cap 1.5 --approval " + OK + " --material public",
        "--paid --model m --cap 1.5 --approval missing-record-1 --material public",
        "--model m --prompt-file p.txt --material public",
    ):
        brief = "A=safo\nB=gemini\n$A $B ask " + tail + "\n" + PUBLIC
        assert GEMINI_PAID in rules(brief), tail
    assert GEMINI_PAID in rules("A=safo\nB=gemini\n$A $B quota --model m\n")


def test_an_assignment_counts_wherever_it_sits() -> None:
    late = "$A $B ask --paid --model m\nA=safo\nB=gemini\n"
    assert GEMINI_PAID in rules(late + PUBLIC)
    same_line = "A=safo B=gemini; $A $B ask --paid --model m\n"
    assert GEMINI_PAID in rules(same_line + PUBLIC)


ALLOWED = {
    "the constructs without any Gemini word": "A=ls\nB=-l\n$A $B ask --paid\nf() { echo hi; }\nxargs -n1 echo\n",
    "an array without Gemini words": 'C=(git status)\n"${C[@]}" --paid\n',
    "variables that never reach a command position": "A=1\nB=2\necho $A $B\nsafo gemini quota --model m\n",
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


VALID_PAID = "safo gemini ask --paid --model m --cap 1.5 --approval " + OK + " --material public\n"
HIDING = [
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


def test_escapes_that_build_a_gemini_command_are_blocked_not_resolved() -> None:
    ok = "A=$'\\x73afo'\nB=gemini\n$A $B ask --paid --model m --cap 1.5 --approval " + OK + " --material public\n"
    assert GEMINI_PAID in rules(ok + PUBLIC)


def test_escapes_that_never_reach_a_command_or_a_gemini_line_are_left_alone() -> None:
    assert rules("echo $'\\x41'\n") == []
    assert rules("A=$'\\x41'\necho $A\n") == []
    assert GEMINI_PAID in rules("A=$'\\x41'\n$A foo\n"), "a concealed-surface brief with a variable as the command"


ALL_CONCEALED = {
    "ansi-c words and option": "$'\\x73afo' $'\\x67emini' $'\\x61sk' $'\\x2d\\x2dpaid'\n",
    "ansi-c variables": "A=$'\\x73afo'\nB=$'\\x67emini'\nC=$'\\x61sk'\nD=$'\\x2d\\x2dpaid'\n$A $B $C $D\n",
    "printf -v for everything": (
        "printf -v A '\\x73afo'\nprintf -v B '\\x67emini'\nprintf -v C '\\x61sk'\n$A $B $C --paid\n"
    ),
    "octal for everything": "A=$'\\163\\141\\146\\157'\nB=$'\\147emini'\n$A $B $'\\141sk' $'\\55\\55paid'\n",
    "substitutions for everything": (
        "$(printf '\\x73afo') $(printf '\\x67emini') $(printf '\\x61sk') $(printf '\\x2d\\x2dpaid')\n"
    ),
}


@pytest.mark.parametrize("name", sorted(ALL_CONCEALED))
def test_a_brief_whose_words_and_options_are_all_concealed_is_still_read(name: str) -> None:
    from safo.geminibrief import relevant

    assert relevant(ALL_CONCEALED[name]), name
    assert GEMINI_PAID in rules(ALL_CONCEALED[name] + PUBLIC), name


def test_a_brief_with_escapes_is_relevant_with_no_visible_gemini_token() -> None:
    from safo.geminibrief import relevant

    assert relevant("echo $'\\x41'\n")
    assert not relevant("rename a variable and review the diff\n")


def test_amplification_has_nothing_to_amplify_and_a_big_brief_is_bounded_in_time() -> None:
    big = "\n".join(f"A{i}=x" for i in range(3000)) + "\n" + "\n".join("$A1$A2$A3" for _ in range(3000))
    started = time.monotonic()
    found = rules(big + "\nsafo gemini quota --model m\n" + PUBLIC)
    assert time.monotonic() - started < 3.0
    assert GEMINI_PAID in found, "a variable at a command position in a brief that names safo"


def test_a_line_the_lexer_cannot_read_is_unreadable_and_comments_are_not_code() -> None:
    assert _expansion_at_command('echo "$A') is True
    assert _expansion_at_command("echo 'x") is False
    assert _expansion_at_command("ls # $A and `date`") is False
    assert _expansion_at_command("# $A is described here") is False
    assert _expansion_at_command("$A ask") is True


def test_the_flow_scan_checks_the_clock_once_per_line() -> None:
    from safo.geminibrief import _flows

    ticks: list[int] = []
    _flows(["A=x", "$A $A", "$A"], lambda: ticks.append(1))
    assert len(ticks) == 3


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


def test_an_unresolved_value_as_an_argument_of_a_line_with_a_gemini_option_is_unreadable() -> None:
    notes = "Notes on safo.\nNotes on gemini.\nTo ask is fine.\n"
    assert GEMINI_PAID in rules(notes + "deploy $TARGET --paid\n" + PUBLIC)
    assert rules(notes + "deploy staging --paid\n") == []


# -- bash is the reference: a stub safo prints its arguments, and the guard must block whatever reaches it ----------

STUB = '#!/bin/sh\nprintf "ARGV:"; for a; do printf " <%s>" "$a"; done; echo\n'


def stub_runs(script: str, tmp: Path) -> bool:
    """Whether bash, given this script, ends up running the stub as `safo gemini ask ...`."""
    bindir = tmp / "bin"
    bindir.mkdir(exist_ok=True)
    stub = bindir / "safo"
    stub.write_text(STUB)
    stub.chmod(0o755)
    done = subprocess.run(  # noqa: S603 - the system bash on a script made by this test, a stub on PATH, no network
        ["/bin/bash", "-c", script],
        capture_output=True,
        text=True,
        timeout=10,
        cwd=tmp,
        env={"PATH": f"{bindir}:/usr/bin:/bin", "HOME": str(tmp)},
        check=False,
    )
    return "ARGV: <gemini> <ask>" in done.stdout


SHADOWED = {
    "an assignment inside a comment": "A=safo # A=echo\nB=gemini\n$A $B ask --paid --model m\n",
    "a comment line with assignments": "A=safo\n# A=echo B=x\nB=gemini\n$A $B ask --paid --model m\n",
    "a prefix that shadows an earlier value": "A=safo\nB=gemini\nA=echo $A $B ask --paid --model m\n",
    "several prefixes": "A=safo\nB=gemini\nA=x B=y $A $B ask --paid --model m\n",
    "a prefix on an env command": "A=safo\nB=gemini\nA=echo env $A $B ask --paid --model m\n",
    "a later reassignment": "A=safo\nB=gemini\n$A $B ask --paid --model m\nA=echo\n",
}


@pytest.mark.parametrize("name", sorted(SHADOWED))
def test_what_bash_runs_as_safo_is_what_the_guard_blocks(name: str, tmp_path: Path) -> None:
    assert stub_runs(SHADOWED[name], tmp_path), "the case is real: bash really runs safo gemini ask"
    assert GEMINI_PAID in rules(SHADOWED[name] + PUBLIC), name


def test_a_prefix_that_makes_bash_run_something_else_is_still_blocked_conservatively(tmp_path: Path) -> None:
    script = "A=echo\nB=gemini\nA=safo $A $B ask --paid --model m\n"
    assert not stub_runs(script, tmp_path)
    assert GEMINI_PAID in rules(script + PUBLIC)


# -- round seven: every way a name is assigned, and where a flow counts ---------------------------------------------

NAMED = {
    "a for variable": "for f in safo; do $f gemini ask --paid; done\n",
    "a read variable": "read X <<< safo\n$X gemini ask --paid\n",
    "an export": "export CMD=safo\n$CMD gemini ask --paid\n",
    "declare": "declare -r CMD=safo\n$CMD gemini ask --paid\n",
    "a braced reference": "CMD=safo\n${CMD} gemini ask --paid\n",
    "a quoted reference": 'CMD=safo\n"$CMD" gemini ask --paid\n',
    "a reference inside a substitution": "CMD=safo\n$(echo $CMD) gemini ask --paid\n",
}


@pytest.mark.parametrize("name", sorted(NAMED))
def test_every_kind_of_assigned_name_that_becomes_the_command_blocks(name: str) -> None:
    assert GEMINI_PAID in rules(NAMED[name] + PUBLIC), name


def test_a_comment_is_not_code_even_when_it_holds_a_variable_and_a_gemini_option() -> None:
    brief = "A=1\necho ok # $A ask --paid\n" + FREE + PUBLIC
    assert rules(brief) == []
    assert rules("A=1\necho ok # B=2 and $A run\n" + FREE + PUBLIC) == []
    assert GEMINI_PAID in rules("A=1\necho ok '# not a comment' $A --paid\n" + FREE + PUBLIC)


def test_more_names_than_can_be_followed_is_unreadable() -> None:
    brief = "Notes on safo.\n" + "\n".join(f"V{i}=1" for i in range(2100)) + "\n"
    started = time.monotonic()
    assert GEMINI_PAID in rules(brief + PUBLIC)
    assert time.monotonic() - started < 3.0


def test_a_weak_flow_needs_safo_gemini_and_an_action_all_named() -> None:
    assert rules("Notes on safo.\n$X ask --paid\n") == []
    assert GEMINI_PAID in rules("Notes on safo.\nNotes on gemini.\n$X ask --paid\n" + PUBLIC)


def test_a_variable_or_an_escape_on_a_gemini_line_blocks_where_the_surface_is_named() -> None:
    assert GEMINI_PAID in rules("X=1\nNotes on safo.\ndeploy $X --paid\n")
    assert GEMINI_PAID in rules("Notes on safo.\necho $'\\x41' ask\n")
    assert GEMINI_PAID in rules("Notes on safo.\nrun printf '\\x41' ask\n")
    assert rules("X=1\nNotes on safo.\ndeploy $X now\n") == []


def test_a_markdown_span_that_starts_with_a_command_word_is_prose() -> None:
    prose = (
        "Notes: `printf -v` is described.\nNotes on safo.\nNotes on gemini.\nTo ask is fine, and --paid is an option.\n"
    )
    assert rules(prose) == []


# -- round seven, part two: the action and the flag hidden behind expansions -----------------------------------------

HIDDEN_ACTION = {
    "braced names": "X=ask\nY=--paid\nsafo gemini ${X} ${Y}\n",
    "quoted names": 'A=safo\nB=gemini\nC=ask\nD=--paid\n"$A" "$B" "$C" "$D"\n',
    "unassigned expansions": "safo gemini $ACTION $FLAG --model m\n",
    "a substitution": "safo gemini $(printf ask) $(printf %s --paid)\n",
    "no literal word at all but the brief names gemini": "Notes on gemini.\nA=safo\n$A $B $C\n",
}


@pytest.mark.parametrize("name", sorted(HIDDEN_ACTION))
def test_an_action_and_a_flag_that_are_both_hidden_behind_expansions_are_unreadable(name: str) -> None:
    assert GEMINI_PAID in rules(HIDDEN_ACTION[name] + PUBLIC), name


def test_a_line_that_names_the_surface_and_uses_any_variable_is_a_hard_flow() -> None:
    assert GEMINI_PAID in rules("Notes on safo.\nX=1\necho $X gemini\n" + PUBLIC)
    assert rules("X=1\necho $X\nsafo gemini ask --model m --prompt-file p.txt --material public\n" + PUBLIC) == []


def test_a_loop_or_read_variable_that_is_the_command_blocks_without_a_visible_gemini_option() -> None:
    assert GEMINI_PAID in rules("Notes on safo.\nfor f in $'\\x61sk'; do $f --paid; done\n" + PUBLIC)
    assert GEMINI_PAID in rules("Notes on safo.\nread -r C <<< $'\\x61sk'\n$C --paid\n" + PUBLIC)


def test_an_ansi_c_word_with_a_plain_escape_on_a_gemini_line_blocks() -> None:
    assert GEMINI_PAID in rules("Notes on safo.\necho $'a\\nb' ask\n")
    assert rules("Notes on safo.\necho $'a\\nb'\n") == []


def test_a_loop_or_read_variable_run_as_a_command_is_a_flow_in_a_brief_that_names_the_surface() -> None:
    assert GEMINI_PAID in rules("Notes on safo.\nY=$'\\x41'\nfor f in a b; do $f; done\n")
    assert GEMINI_PAID in rules("Notes on safo.\nY=$'\\x41'\nread -r C\n$C now\n")
    assert rules("Notes on safo.\nfor f in a b; do echo done; done\n") == []
