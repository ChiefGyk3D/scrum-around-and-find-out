# SPDX-License-Identifier: Apache-2.0
"""A command built across lines (variables, arrays, functions, eval, xargs) is read as the command it is, or blocked
as unreadable when it cannot be resolved; the same constructs in a brief with no Gemini words are left alone (#200)."""

from __future__ import annotations

import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import safo.geminibrief as _geminibrief
from safo.geminibrief import GEMINI_PAID, _expansion_at_command, findings

_GEMINIBRIEF = _geminibrief.__file__
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
    "the constructs without any Gemini word": "A=ls\nB=-l\n$A $B\nf() { echo hi; }\nxargs -n1 echo\n",
    "an array without Gemini words": 'C=(git status)\n"${C[@]}" --verbose\n',
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
    "approve in prose": "Please approve the change before merging.",
    "a docker capability with a variable": "IMAGE=x\ndocker run --cap-add=NET_ADMIN $IMAGE",
    "approve in prose beside a variable": "The reviewer should approve $PR_NUMBER only after the tests pass.",
}


@pytest.mark.parametrize("name", sorted(ORDINARY))
def test_ordinary_additions_beside_a_free_gemini_command_are_allowed(name: str) -> None:
    assert rules(ORDINARY[name] + "\n" + FREE + PUBLIC) == [], name
    assert rules(FREE + PUBLIC + ORDINARY[name] + "\n") == [], name


def test_the_ordinary_briefs_are_all_in_the_fixture() -> None:
    assert len(ORDINARY) == 13


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


def stub_runs(script: str, tmp: Path, extra_env: dict[str, str] | None = None) -> bool:
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
        env={"PATH": f"{bindir}:/usr/bin:/bin", "HOME": str(tmp), **(extra_env or {})},
        check=False,
    )
    return "ARGV: <gemini> <" in done.stdout


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


def test_a_plain_comment_is_not_code_but_one_that_could_hide_a_command_is_read_whole() -> None:
    assert rules("A=1\necho ok # just words and B=2\n" + FREE + PUBLIC) == []
    assert rules("A=1\necho ok # B=2 then run\n" + FREE + PUBLIC) == []
    # a comment holding an expansion, a separator or a backtick is kept whole: it is read as code (a false block)
    assert GEMINI_PAID in rules("A=1\necho ok # $A ask --paid\n" + FREE + PUBLIC)
    assert GEMINI_PAID in rules("A=1\necho ok '# not a comment' $A --paid\n" + FREE + PUBLIC)


def test_more_names_than_can_be_followed_is_unreadable() -> None:
    brief = "Notes on safo.\n" + "\n".join(f"V{i}=1" for i in range(2100)) + "\n"
    started = time.monotonic()
    assert GEMINI_PAID in rules(brief + PUBLIC)
    assert time.monotonic() - started < 3.0


def test_a_weak_flow_needs_safo_gemini_and_an_action_all_named() -> None:
    assert rules("Notes on safo.\n$X ask now\n") == []
    assert GEMINI_PAID in rules("Notes on safo.\nNotes on gemini.\n$X ask now\n" + PUBLIC)


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


# -- round eight: words built by substitutions, interpreters, tr, awk, sed, a sourced file or the environment ---------

BUILT = {
    "printf": 'A=$(printf "%s%s" sa fo)\nB=$(printf "%s%s" gem ini)\n$A $B ask --paid --model m\n',
    "an interpreter one-liner": (
        'A=$(python3 -c \'print("s"+"a"+"f"+"o")\')\nB=$(python3 -c \'print("gem"+"ini")\')\n'
        "$A $B ask --paid --model m\n"
    ),
    "tr": "A=$(echo SAFO | tr A-Z a-z)\nB=$(echo GEMINI | tr A-Z a-z)\n$A $B ask --paid --model m\n",
    "awk": 'A=$(awk \'BEGIN{printf "sa" "fo"}\')\nB=$(awk \'BEGIN{printf "gem" "ini"}\')\n$A $B ask --paid --model m\n',
    "sed": "A=$(echo sxfo | sed s/x/a/)\nB=$(echo gemXni | sed s/X/i/)\n$A $B ask --paid --model m\n",
    "a sourced file": "printf 'A=safo\\nB=gemini\\n' > vars.sh\n. ./vars.sh\n$A $B ask --paid --model m\n",
    "values from the environment": "$BIN $SUB ask --paid --model m\n",
    "a command string": 'bash -c "$BIN $SUB ask --paid --model m"\n',
    "approve": 'A=$(printf "%s%s" sa fo)\nB=$(printf "%s%s" gem ini)\n$A $B approve --max-usd 1\n',
}
BUILT_ENV = {"BIN": "safo", "SUB": "gemini"}


@pytest.mark.parametrize("name", sorted(BUILT))
def test_a_command_built_without_naming_the_surface_is_blocked_where_bash_runs_it(name: str, tmp_path: Path) -> None:
    from safo.geminibrief import relevant

    script = BUILT[name]
    assert stub_runs(script, tmp_path, BUILT_ENV), "the case is real: bash really runs safo gemini"
    assert relevant(script), name
    assert GEMINI_PAID in rules(script + PUBLIC), name


def test_a_gemini_option_beside_a_command_made_of_an_expansion_is_enough_without_any_named_surface() -> None:
    assert GEMINI_PAID in rules("$X $Y ask --paid\n")
    assert GEMINI_PAID in rules("$X --approval id\n")
    assert GEMINI_PAID in rules("$X --cap 1\n")
    assert GEMINI_PAID in rules("$X approve now\n")
    assert rules("docker run --cap-add=NET_ADMIN $IMAGE\n") == []
    assert rules("approve $X\n") == []
    assert rules("$X ask\n") == [], "ask alone is not a Gemini-risk token"
    assert rules("$X approver now\n") == [] and rules("$X disapprove now\n") == [], "approve is a word of its own"


# -- round eight: here-documents are scanned like any other line ------------------------------------------------------

HEREDOCS = {
    "bash": "bash <<'EOF'\nA=safo\nB=gemini\n$A $B ask --paid --model m\nEOF\n",
    "sh -s": "sh -s <<'EOF'\nA=safo\nB=gemini\n$A $B ask --paid --model m\nEOF\n",
    "source": "source /dev/stdin <<'EOF'\nA=safo\nB=gemini\n$A $B ask --paid --model m\nEOF\n",
}


@pytest.mark.parametrize("name", sorted(HEREDOCS))
def test_a_heredoc_that_a_shell_runs_is_blocked_not_skipped(name: str, tmp_path: Path) -> None:
    assert stub_runs(HEREDOCS[name], tmp_path), "the case is real: bash really runs it"
    assert GEMINI_PAID in rules(HEREDOCS[name] + PUBLIC), name


# -- round eight: the comment cutter follows bash --------------------------------------------------------------------

NBSP = "\u00a0"
COMMENTED = {
    "an ANSI-C word that holds an escaped quote": "A=safo\nB=gemini\necho $'a\\' # b' ; $A $B ask --paid --model m\n",
    "a non-ASCII space before the hash": "A=safo\nB=gemini\necho x" + NBSP + "#y ; $A $B ask --paid --model m\n",
    "a hash after an ordinary space inside quotes": "A=safo\nB=gemini\necho 'x #y' ; $A $B ask --paid --model m\n",
    "a hash in a word": "A=safo\nB=gemini\necho x#y ; $A $B ask --paid --model m\n",
}


@pytest.mark.parametrize("name", sorted(COMMENTED))
def test_what_the_comment_cutter_hides_is_never_what_bash_runs(name: str, tmp_path: Path) -> None:
    assert stub_runs(COMMENTED[name], tmp_path), "the case is real: bash really runs safo gemini"
    assert GEMINI_PAID in rules(COMMENTED[name] + PUBLIC), name


def test_a_hash_after_a_redirection_and_a_real_comment_are_cut_the_way_bash_cuts() -> None:
    from safo.geminibrief import _strip_comment

    assert _strip_comment("echo hi # a plain comment") == "echo hi "
    assert _strip_comment("echo hi #plain") == "echo hi "
    assert _strip_comment("echo x#y") == "echo x#y"
    assert _strip_comment("echo 'a # b'") == "echo 'a # b'"
    assert _strip_comment("cat < #c") == "cat < "
    assert _strip_comment("# only a comment") == ""
    # fail closed: text that bash may still run is kept whole
    assert _strip_comment("echo a<#b ; $A") == "echo a<#b ; $A"
    assert _strip_comment("ls # $A") == "ls # $A"
    assert _strip_comment("ls # `date`") == "ls # `date`"
    assert _strip_comment("ls # a; b") == "ls # a; b"
    assert _strip_comment("echo $'x' # y") == "echo $'x' # y"
    assert _strip_comment("echo x" + NBSP + "# y") == "echo x" + NBSP + "# y"
    # each cutting rule on its own, with a benign comment so that the fail-closed rules do not apply
    assert _strip_comment('echo "a\\" # b"') == 'echo "a\\" # b"', "a backslash escapes a quote in double quotes"
    assert _strip_comment("echo a<#b") == "echo a<", "a hash after < starts a comment"
    assert _strip_comment("echo a>#b") == "echo a>", "a hash after > starts a comment"
    assert _strip_comment("echo x" + NBSP + "y # z") == "echo x" + NBSP + "y # z", (
        "a non-ASCII space is a word character"
    )
    assert _strip_comment("echo (a)#b") == "echo (a)"
    assert _strip_comment("echo a #b") == "echo a "


# -- round nine: wrapper options, brace-built option names ----------------------------------------------------------

WRAPPED = {
    "env -u": "env -u FOO $BIN $SUB ask --paid --model m\n",
    "time -p": "time -p $BIN $SUB ask --paid --model m\n",
    "nohup": "nohup $BIN $SUB ask --paid --model m\n",
    "env with several options": "env -u A -u B $BIN $SUB ask --paid --model m\n",
    "a quoted wrapper": '"env" -u FOO $BIN $SUB ask --paid --model m\n',
    "a backslashed wrapper": "\\env -u FOO $BIN $SUB ask --paid --model m\n",
    "a wrapper by path": "/usr/bin/env -u FOO $BIN $SUB ask --paid --model m\n",
    "an assignment before the wrapper": "X=1 env -u FOO $BIN $SUB ask --paid --model m\n",
    "an assignment before nohup": "X=1 Y=2 nohup $BIN $SUB ask --paid --model m\n",
    "nice": "nice -n 5 $BIN $SUB ask --paid --model m\n",
}
WRAPPED_GUARD_ONLY = {
    "command -p": "command -p $BIN $SUB ask --paid --model m\n",
    "nohup --": "nohup -- $BIN $SUB ask --paid --model m\n",
    "eval --": "eval -- $BIN $SUB ask --paid --model m\n",
    "xargs -n1": "echo x | xargs -n1 $BIN $SUB ask --paid --model m\n",
    "timeout 5": "timeout 5 $BIN $SUB ask --paid --model m\n",
}


@pytest.mark.parametrize("name", sorted(WRAPPED))
def test_a_wrapper_with_options_before_an_expansion_command_is_still_seen(name: str, tmp_path: Path) -> None:
    from safo.geminibrief import relevant

    assert stub_runs(WRAPPED[name], tmp_path, BUILT_ENV), "the case is real"
    assert relevant(WRAPPED[name]) and GEMINI_PAID in rules(WRAPPED[name] + PUBLIC), name


@pytest.mark.parametrize("name", sorted(WRAPPED_GUARD_ONLY))
def test_other_wrappers_with_options_are_seen_too(name: str) -> None:
    from safo.geminibrief import relevant

    assert relevant(WRAPPED_GUARD_ONLY[name]) and GEMINI_PAID in rules(WRAPPED_GUARD_ONLY[name] + PUBLIC), name


BRACED = {
    "an option name built by braces": "$BIN $SUB ask --{p,un}aid --model m\n",
    "approve built by braces": "$BIN $SUB appro{v,w}e --max-usd 1\n",
    "a cap built by braces": "$BIN $SUB ask --{cap,ca}p 1\n",
    "a sequence expression": "$BIN $SUB ask --{p..p}aid --model m\n",
    "nested braces": "$BIN $SUB ask --{{p,q},un}aid --model m\n",
    "braces after an option fragment": "$BIN $SUB ask --pa{id,xx} --model m\n",
    "a quoted part and an unquoted list": "$BIN $SUB ask --'p'{aid,xx} --model m\n",
    "a double-quoted prefix": '$BIN $SUB ask "--"{p,un}aid --model m\n',
    "quotes inside a built word": '$BIN $SUB ask --"pa"{id,xx} --model m\n',
}


@pytest.mark.parametrize("name", sorted(BRACED))
def test_a_risk_token_built_by_brace_expansion_is_seen(name: str, tmp_path: Path) -> None:
    from safo.geminibrief import relevant

    assert stub_runs(BRACED[name], tmp_path, BUILT_ENV), "the case is real: bash runs the stub with the built word"
    assert relevant(BRACED[name]) and GEMINI_PAID in rules(BRACED[name] + PUBLIC), name


def test_braces_are_judged_without_building_any_word_and_the_false_blocks_are_the_documented_ones() -> None:
    assert rules("echo {a,b}\ndocker run --cap-add=NET_ADMIN $IMAGE\n") == []
    assert rules("echo ${HOME} ${X:-a,b}\n") == []
    assert rules('$BIN $SUB ask now "--{p,un}aid"\n') == [], "a quoted word is not brace-expanded by the shell"
    # documented false blocks: a brace list beside an expansion past the first word, or as the command
    assert GEMINI_PAID in rules("$BIN $SUB ask --{a,b}ccount\n")
    assert GEMINI_PAID in rules("docker run --cap-{add,drop}=NET_ADMIN $IMAGE\n")


# -- round ten: nothing is enumerated, so nothing can be exhausted or silently cut ------------------------------------


def _steps(work: Callable[[int], object], size: int, files: tuple[str, ...]) -> int:
    """How many Python lines the work runs in the given source files: a count, not a clock, so a slow or busy
    machine and the interpreter version cannot change it. Work done inside C (a regex) is not counted."""
    count = 0

    def local(frame: Any, event: str, arg: object) -> Any:
        nonlocal count
        if event == "line":
            count += 1
        return local

    def tracer(frame: Any, event: str, arg: object) -> Any:
        return local if frame.f_code.co_filename in files else None

    previous = sys.gettrace()
    sys.settrace(tracer)
    try:
        work(size)
    finally:
        sys.settrace(previous)
    return count


def _grows_linearly(
    work: Callable[[int], object], files: tuple[str, ...] = (_GEMINIBRIEF,), small: int = 20, big: int = 160
) -> bool:
    """Count the lines run for an input 8x larger and for a small one: linear work counts about 8x, quadratic about
    64x. The bound of 12x sits between them, and the count is exact, so it never flakes. The sizes keep every line
    under LINE_CAP: a longer line is clipped, which would hide growth."""
    low, high = _steps(work, small, files), _steps(work, big, files)
    assert low > 0, "nothing was counted: the guard is not looking at the code it protects"
    return high < 12 * low


def _brace_lines(size: int) -> None:
    many = "$BIN $SUB ask --{" + ",".join("a" * 10 for _ in range(size)) + "}paid --model m\n"
    assert GEMINI_PAID in rules(many + PUBLIC)
    depth = size // 4
    nested = "$BIN $SUB ask --" + "{a," * depth + "b" + "}" * depth + "\n"
    assert GEMINI_PAID in rules(nested + PUBLIC)
    words = "$BIN " + " ".join("{a,b}" * 3 for _ in range(size)) + " --paid\n"
    assert GEMINI_PAID in rules(words + PUBLIC)


def test_a_line_with_a_huge_brace_list_is_judged_in_linear_time() -> None:
    assert _grows_linearly(_brace_lines)


def test_the_linear_time_guard_bites_on_quadratic_work(monkeypatch: pytest.MonkeyPatch) -> None:
    import safo.geminibrief as gb

    real = gb._brace_list

    def quadratic_brace_list(word: str) -> bool:
        for end in range(len(word)):  # rescans the prefix at every character: quadratic
            real(word[: end + 1])
        return real(word)

    assert _grows_linearly(_brace_lines), "the real code is judged linear"
    monkeypatch.setattr(gb, "_brace_list", quadratic_brace_list)
    assert not _grows_linearly(_brace_lines, (_GEMINIBRIEF, __file__)), "a quadratic scan is caught"



def test_a_line_past_the_length_bound_that_could_hold_a_risk_token_is_unreadable_not_cut() -> None:
    long = "$BIN " + "x " * 5000 + "--paid\n"
    assert GEMINI_PAID in rules(long + PUBLIC)
    assert rules("echo " + "x " * 5000 + "\n") == []


def test_a_parameter_expansion_is_not_a_brace_list_and_a_long_brace_word_is_never_cut() -> None:
    from safo.geminibrief import _brace_word_risk

    assert rules("$BIN ${X:-a,b} now\n") == []
    assert _brace_word_risk("--" + "x" * 5000 + "{") is True, "past the length bound it is a marker, never silently cut"
    assert _brace_word_risk("--x{") is False
    assert _brace_word_risk("echo {a,b}") is False


# -- round eleven: mixed quoting, braces behind a wrapper, and ${...} inside a list ---------------------------------

BRACED_WRAPPED = {
    "env -u": "env -u FOO $BIN $SUB ask --{p,un}aid --model m\n",
    "time -p": "time -p $BIN $SUB ask --{p,un}aid --model m\n",
    "nohup": "nohup $BIN $SUB ask --{p,un}aid --model m\n",
    "nice": "nice -n 5 $BIN $SUB ask --{p,un}aid --model m\n",
    "a quoted wrapper": '"env" -u FOO $BIN $SUB ask --{p,un}aid --model m\n',
    "a backslashed wrapper": "\\env -u FOO $BIN $SUB ask --{p,un}aid --model m\n",
    "a wrapper by path": "/usr/bin/env -u FOO $BIN $SUB ask --{p,un}aid --model m\n",
    "an assignment before the wrapper": "X=1 env -u FOO $BIN $SUB ask --{p,un}aid --model m\n",
}
BRACED_WRAPPED_GUARD_ONLY = {
    "command -p": "command -p $BIN $SUB ask --{p,un}aid --model m\n",
    "timeout": "timeout 5 $BIN $SUB ask --{p,un}aid --model m\n",
    "xargs -n1": "echo x | xargs -n1 $BIN $SUB ask --{p,un}aid --model m\n",
    "eval --": "eval -- $BIN $SUB ask --{p,un}aid --model m\n",
}


@pytest.mark.parametrize("name", sorted(BRACED_WRAPPED))
def test_a_brace_built_risk_token_behind_a_wrapper_is_blocked(name: str, tmp_path: Path) -> None:
    from safo.geminibrief import relevant

    assert stub_runs(BRACED_WRAPPED[name], tmp_path, BUILT_ENV), "the case is real"
    assert relevant(BRACED_WRAPPED[name]) and GEMINI_PAID in rules(BRACED_WRAPPED[name] + PUBLIC), name


@pytest.mark.parametrize("name", sorted(BRACED_WRAPPED_GUARD_ONLY))
def test_a_brace_built_risk_token_behind_other_wrappers_is_blocked(name: str) -> None:
    from safo.geminibrief import relevant

    text = BRACED_WRAPPED_GUARD_ONLY[name]
    assert relevant(text) and GEMINI_PAID in rules(text + PUBLIC), name


def test_the_brace_scanner_keeps_parameter_expansions_apart_from_lists() -> None:
    from safo.geminibrief import _brace_list

    assert _brace_list("${X:-a,b}") is False
    assert _brace_list("${X:-a,b}{p,q}") is True, "a real list after a parameter expansion"
    assert _brace_list("{p,q}${X:-a,b}") is True
    assert _brace_list("{a,${X}}") is True, "a list wrapping a parameter expansion"
    assert _brace_list("{a${X:-b,c}}") is False, "a comma inside ${...} does not make the outer braces a list"
    assert _brace_list("${X}{a}") is False and _brace_list("{a}") is False
    assert _brace_list("{a..b}") is True and _brace_list("${X:-a..b}") is False
