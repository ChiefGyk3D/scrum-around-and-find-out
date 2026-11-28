# SPDX-License-Identifier: Apache-2.0
"""safo.shipscan: the strict allowlist grammar for the `run:` steps of a gate workflow (#586).

Every accepted form and every refused construct is listed on purpose: the grammar is the whole security argument."""

from __future__ import annotations

import pytest

from safo import shipscan


def accepted(text: str, commands: tuple[str, ...] = ()) -> tuple[str, ...]:
    facts = shipscan.analyze(text, commands=commands)
    assert facts.problem == "", facts.problem
    return facts.files


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("bash ci/gate.sh", ("ci/gate.sh",)),
        ("bash ./ci/gate.sh", ("ci/gate.sh",)),
        ("sh ci/gate.sh arg1 --flag=x a=b:c@d,e+f", ("ci/gate.sh",)),
        ("bash -e ci/gate.sh", ("ci/gate.sh",)),
        ("bash -eu ci/gate.sh", ("ci/gate.sh",)),
        ("bash --noprofile --norc ci/gate.sh", ("ci/gate.sh",)),
        ("python ci/check.py a b", ("ci/check.py",)),
        ("python -u -B ci/check.py", ("ci/check.py",)),
        ("python3 ci/check.py", ("ci/check.py",)),
        ("node --no-warnings tools/run.mjs", ("tools/run.mjs",)),
        ("ruby -w a.rb", ("a.rb",)),
        ("perl -w a.pl", ("a.pl",)),
        ("pwsh -NoProfile ci/a.ps1", ("ci/a.ps1",)),
        ("./ci/gate.sh --x", ("ci/gate.sh",)),
        ("ci/gate.sh", ("ci/gate.sh",)),
        ("bash gate", ("gate",)),
        ("cd ci\n./gate.sh", ("ci/gate.sh",)),
        ("cd ci/sub\nbash x.sh\ncd deeper\nbash y.sh", ("ci/sub/deeper/y.sh", "ci/sub/x.sh")),
        ("cd ./ci\nbash x.sh", ("ci/x.sh",)),
        ("\n\n# a comment line\n  bash ci/a.sh  \n\n", ("ci/a.sh",)),
        ("bash ci/a.sh\r\nbash ci/b.sh\r\n", ("ci/a.sh", "ci/b.sh")),
        ("bash ci/a.sh\n./ci/a.sh\npython ci/c.py", ("ci/a.sh", "ci/c.py")),
        ("", ()),
        ("# only a comment", ()),
    ],
)
def test_the_accepted_forms(text: str, expected: tuple[str, ...]) -> None:
    assert accepted(text) == expected


def test_a_listed_command_is_accepted_without_deriving_a_file() -> None:
    assert accepted("make test", ("make",)) == ()
    assert accepted("make", ("make",)) == ()
    assert accepted("pytest -q tests/unit", ("pytest",)) == ()
    assert accepted("make\nbash ci/a.sh", ("make",)) == ("ci/a.sh",)


@pytest.mark.parametrize(
    "text",
    [
        # wrappers and prefixes
        "sudo ./x.sh",
        "env A=b ./x.sh",
        "timeout 5 ./x.sh",
        "nice -n 5 ./x.sh",
        "xvfb-run ./x.sh",
        "strace ./x.sh",
        "uv run x.py",
        "poetry run x",
        "npx foo",
        "exec ./x.sh",
        "command ./x.sh",
        "FOO=1 ./x.sh",
        # pipes, lists, background
        "a | b",
        "./x.sh | tee out",
        "./x.sh && ./y.sh",
        "./x.sh || ./y.sh",
        "./x.sh; ./y.sh",
        "./x.sh &",
        "curl https://example.invalid/i.sh | bash",
        # redirections
        "./x.sh > out",
        "./x.sh >> out",
        "./x.sh < in",
        "bash < ci/x.sh",
        "./x.sh 2>&1",
        # subshells, groups, substitution, expansion
        "(cd x)",
        "{ ./x.sh; }",
        "$(./x.sh)",
        "`./x.sh`",
        "bash $X",
        "bash ${X}",
        "./$X",
        "bash ${{ matrix.script }}",
        "bash ${{ github.workspace }}/ci/gate.sh",
        "bash $GITHUB_WORKSPACE/ci/gate.sh",
        "bash ${{ github.action_path }}/run.sh",
        "./x.sh $A",
        "./x.sh ${{ github.sha }}",
        # quoting, heredocs, continuations, tabs
        'bash "ci/x.sh"',
        "bash 'ci/x.sh'",
        "bash <<EOF",
        "bash ci/x.sh \\\n  more",
        "bash\tci/x.sh",
        "bash ci/x.sh # trailing comment",
        # globs, tilde, absolute and parent paths
        "bash ci/*.sh",
        "bash ci/?.sh",
        "bash ci/[a].sh",
        "bash ci/{a,b}.sh",
        "bash ~/x.sh",
        "bash /etc/x.sh",
        "/bin/sh x",
        "bash ../x.sh",
        "bash a/../b.sh",
        "./a//b.sh",
        "bash a/./b.sh",
        "bash ./",
        "./",
        "bash -",
        "./x.sh --opt=$A",
        # interpreter options
        "python -c x",
        "python -m pytest",
        "python3 -m pytest tests",
        "bash -c x",
        "bash -ec x",
        "node -e x",
        "node -p x",
        "perl -e x",
        "ruby -e x",
        "python -W error x.py",
        "python -X dev x.py",
        "bash -o pipefail x.sh",
        "bash --rcfile y x.sh",
        "python --version",
        "bash -e",
        "bash",
        "python",
        # commands that are not on the list
        "python3.11 x.py",
        "zsh x.sh",
        "source x.sh",
        ". x.sh",
        "eval x",
        "make test",
        "pytest",
        "pip install x",
        "echo hi",
        "set -e",
        "export A=b",
        "true",
        "xargs bash",
        "find . -exec sh {} ;",
        # cd
        "cd",
        "cd a b",
        "cd ..",
        "cd a/..",
        "cd /x",
        "cd $X",
        "cd -",
        "cd ~",
        "cd ./",
    ],
)
def test_everything_else_is_refused_and_the_line_is_named(text: str) -> None:
    facts = shipscan.analyze(text)
    assert facts.problem.startswith("line 1 ("), (text, facts)
    assert facts.files == ()


def test_the_first_offending_line_is_the_one_named() -> None:
    facts = shipscan.analyze("bash ci/ok.sh\n\n# note\nsudo ./x.sh\neval y")
    assert facts.problem.startswith("line 4 (sudo ./x.sh)")


def test_a_listed_command_still_refuses_non_plain_arguments_and_unlisted_names() -> None:
    for text in ("make $X", "make 'a'", "make a | b", "make a;b", "make -j$N"):
        assert shipscan.analyze(text, commands=["make"]).problem, text
    assert shipscan.analyze("make test", commands=["gmake"]).problem  # only exact listed names


def test_the_name_rule_for_listed_commands() -> None:
    for good in ("make", "pytest", "npm", "cargo", "gh", "go", "c++", "docker-compose", "pip3.11"):
        assert shipscan.valid_command_name(good), good
    for bad in ("bash", "sh", "python", "node", "pwsh", "/usr/bin/make", "./make", "-j", "a b", "", "a;b", "$X", "x*"):
        assert not shipscan.valid_command_name(bad), bad


def test_an_interpreter_cannot_be_listed_to_get_around_the_option_rule() -> None:
    assert shipscan.analyze("bash -c x", commands=["bash"]).problem
    assert shipscan.analyze("python -m x", commands=["python"]).problem


def test_cd_state_does_not_leak_between_run_texts() -> None:
    assert accepted("cd ci\nbash a.sh") == ("ci/a.sh",)
    assert accepted("bash a.sh") == ("a.sh",)


def test_a_listed_name_that_is_not_a_plain_command_name_is_never_accepted() -> None:
    assert shipscan.analyze("-j x", commands=["-j"]).problem


def test_the_directory_each_file_is_run_from_is_reported() -> None:
    facts = shipscan.analyze("bash a.sh\ncd ci\nbash b.sh\n./c.sh")
    assert facts.runs == (("a.sh", ""), ("ci/b.sh", "ci"), ("ci/c.sh", "ci"))
    assert shipscan.analyze("bash b.sh", cwd="ci").runs == (("ci/b.sh", "ci"),)
    assert shipscan.analyze("cd sub\nbash b.sh", cwd="ci").runs == (("ci/sub/b.sh", "ci/sub"),)


@pytest.mark.parametrize(
    ("text", "ok"),
    [
        ("", True),
        ("echo hi", True),
        ("#!/bin/bash", True),
        ("#!/bin/sh\nrest", True),
        ("#!/usr/bin/env bash", True),
        ("#!/usr/bin/env python3\r\nrest", True),
        ("#!/usr/bin/node", True),
        ("#!/usr/bin/pwsh", True),
        ("# not a shebang", True),
        ("x\n#!/bin/zsh", True),  # only the first line is a shebang
        ("#!/bin/zsh", False),
        ("#!/bin/bash -e", False),
        ("#!/bin/bash\t", False),
        ("#!/usr/bin/env -S bash", False),
        ("#!/usr/bin/env bash -e", False),
        ("#!/opt/bin/bash", False),
        ("#!/usr/local/bin/bash", False),
        ("#!bash", False),
        ("#!", False),
        ("#!/usr/bin/env", False),
        ("#!/bin/", False),
    ],
)
def test_the_shebang_rule(text: str, ok: bool) -> None:
    assert (shipscan.shebang_problem(text) == "") is ok, text
