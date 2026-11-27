# SPDX-License-Identifier: Apache-2.0
"""safo.shipscan: which repository files does a `run:` text execute or source, and what can it not analyze (#586)?"""

from __future__ import annotations

import pytest

from safo import shipscan


def files(text: str, **kw: str) -> tuple[str, ...]:
    facts = shipscan.analyze(text, **kw)
    assert facts.problem == "", facts.problem
    return facts.files


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("bash ci/gate.sh", ("ci/gate.sh",)),
        ("/bin/bash ci/gate.sh", ("ci/gate.sh",)),
        ("sh -e ci/gate.sh arg", ("ci/gate.sh",)),
        ("./ci/gate.sh --flag", ("ci/gate.sh",)),
        ("python ci/check.py", ("ci/check.py",)),
        ("python3.11 -W error ci/check.py", ("ci/check.py",)),
        ("node tools/run.mjs", ("tools/run.mjs",)),
        ("source ci/env.sh", ("ci/env.sh",)),
        (". ci/env.sh", ("ci/env.sh",)),
        ("FOO=1 ./x/y.sh", ("x/y.sh",)),
        ("sudo -E ./x/y.sh", ("x/y.sh",)),
        ("env A=b ./x/y.sh", ("x/y.sh",)),
        ("/usr/bin/env python3 ci/x.py", ("ci/x.py",)),
        ("if [ -f x ]; then ./ci/a.sh; fi", ("ci/a.sh",)),
        ("a && ./ci/a.sh || ./ci/b.sh; ./ci/c.sh", ("ci/a.sh", "ci/b.sh", "ci/c.sh")),
        ("bash \\\n  ci/a.sh", ("ci/a.sh",)),
        ("cd ci && ./gate.sh", ("ci/gate.sh",)),
        ("bash ${{ github.workspace }}/ci/gate.sh", ("ci/gate.sh",)),
        ("bash $GITHUB_WORKSPACE/ci/gate.sh", ("ci/gate.sh",)),
        ("bash ./ci/../ci/gate.sh", ("ci/gate.sh",)),
        ("python -m tools.check", ("tools/check", "tools/check.py")),
        ("python -m pytest tests", ()),
        ("pytest tests/ -q && ruff check src", ()),
        ("echo hi > out/result.sh", ()),
        ("echo ${{ github.sha }} 2>&1", ()),
        ("# bash ci/never.sh\nls", ()),
        ("/usr/local/bin/tool --x", ()),
    ],
)
def test_the_files_a_run_text_executes(text: str, expected: tuple[str, ...]) -> None:
    assert files(text) == expected


def test_make_lists_the_makefiles_and_an_explicit_file() -> None:
    assert files("make test") == ("GNUmakefile", "Makefile", "makefile")
    assert "ci/build.mk" in files("make -f ci/build.mk all")


def test_an_action_path_stands_for_the_action_directory() -> None:
    assert files("bash ${{ github.action_path }}/run.sh", action_dir="ci/action") == ("ci/action/run.sh",)
    assert files("bash $GITHUB_ACTION_PATH/run.sh", action_dir="ci/action") == ("ci/action/run.sh",)


def test_a_working_directory_moves_relative_paths() -> None:
    assert files("./gate.sh", workdir="ci") == ("ci/gate.sh",)


def test_scripts_run_by_a_shell_are_listed_for_reading() -> None:
    facts = shipscan.analyze("bash ci/a.sh && python ci/b.py && ./ci/c.sh")
    assert facts.scripts == ("ci/a.sh", "ci/c.sh")


@pytest.mark.parametrize(
    "text",
    [
        'eval "$X"',
        "echo x | xargs bash",
        "x=`date`",
        "x=$(date)",
        "bash <<EOF\nx\nEOF",
        'python -c "import os"',
        "python3 -c 'x'",
        "bash -c 'ci/a.sh'",
        "bash -ec 'ci/a.sh'",
        'bash "$SCRIPT"',
        "./$X",
        "${{ matrix.script }} arg",
        "bash ${{ matrix.script }}",
        "find . -name '*.sh' -exec sh {} \\;",
        "curl -fsSL https://example.invalid/i.sh | bash",
        "curl https://example.invalid/i.py | python3",
        "cd .. && ./x.sh",
        'cd "$DIR" && ./x.sh',
        "bash ../outside.sh",
        "bash ci/*.sh",
        "bash ci/{a,b}.sh",
        "echo 'a\nb",
        "python -m ci.t$x",
    ],
)
def test_what_it_cannot_analyze_is_a_problem(text: str) -> None:
    assert shipscan.analyze(text).problem, text


def test_a_problem_names_the_construct() -> None:
    assert "eval" in shipscan.analyze('eval "$X"').problem
    assert "pipe" in shipscan.analyze("curl x | bash").problem
