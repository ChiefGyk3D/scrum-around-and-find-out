# SPDX-License-Identifier: Apache-2.0
"""The CODEOWNERS matcher against git itself: the same pattern as a .gitignore, `git check-ignore --no-index`.

CODEOWNERS patterns follow gitignore, so for every pattern we support, a path is covered exactly when git says the
path is ignored. Patterns we cannot evaluate with confidence must fail closed instead (tested here as well).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from safo.codeowners import CodeownersError, covered, parse_rules, uncovered

PATHS = [
    "agents.yaml",
    "sub/agents.yaml",
    "docs/lessons.md",
    "docs/a/lessons.md",
    "sub/docs/lessons.md",
    "examples/harness/probe.md",
    "examples/harness/probe.yaml",
    "examples/harness/sub/probe.md",
    "sub/examples/harness/x.md",
    "src/safo/agentsfile.py",
    "src/safo/profile_render.py",
    "src/safo/ax",
    "src/agentsfile.py",
    "abc.md",
    "a/c.md",
    "a#b",
    "a b",
    "a*b",
    "x/y/z",
    "x/z",
    "z",
    ".claude/agents/probe.md",
    ".claude/agents/probe.yaml",
    "agents/probe.md",
]

PATTERNS = [
    "*",
    "/agents.yaml",
    "agents.yaml",
    "/examples/harness/",
    "examples/harness/",
    "harness/",
    "/examples/harness",
    "/examples/harness/*.md",
    "/examples/harness/*",
    "/examples/harness/**",
    "*.md",
    "docs/*.md",
    "/docs/**",
    "/**/lessons.md",
    "**/lessons.md",
    "docs/**/lessons.md",
    "/src/safo/",
    "/src/safo/agentsfile.py",
    "s**agentsfile.py",
    "/src/safo/**x",
    "/src/safo/a**",
    "/a?c.md",
    "a/**/z",
    "x/**/z",
    "x/**",
    "**",
    "***",
    "x/**z",
    "/**/",
    "/x/*/z",
    "/x/*",
    "lessons.md",
    "docs/lessons.md",
    "/.claude/agents/",
    "/agents/",
    "a\\#b",
    "a\\ b",
    "a\\*b",
    "*b",
    "a*",
    "/a/",
    "a/c.md",
]


def git_ignored(tmp_path: Path, pattern: str) -> set[str]:
    repo = tmp_path / "r"
    shutil.rmtree(repo, ignore_errors=True)
    repo.mkdir()
    # fixed argv, no shell, a path pytest made: git is the oracle here (S603/S607: a test calling the installed git)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)  # noqa: S603, S607
    (repo / ".gitignore").write_text(pattern + "\n")
    done = subprocess.run(  # noqa: S603 - fixed argv, no shell; the patterns go through a file and stdin
        ["git", "-C", str(repo), "check-ignore", "--no-index", "--stdin", "-z"],  # noqa: S607 - the installed git
        input="\0".join(PATHS) + "\0",
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode in (0, 1), done.stderr
    return {p for p in done.stdout.split("\0") if p}


def test_the_table_is_large_enough_to_mean_something() -> None:
    assert len(PATTERNS) * len(PATHS) >= 800


@pytest.mark.parametrize("pattern", PATTERNS)
def test_the_matcher_agrees_with_git_check_ignore(pattern: str, tmp_path: Path) -> None:
    if shutil.which("git") is None:
        pytest.skip("git is not installed: the differential test against `git check-ignore` cannot run")
    rules = parse_rules(f"{pattern} @owner\n")
    want = git_ignored(tmp_path, pattern)
    got = {p for p in PATHS if covered(rules, p)}
    assert got == want, f"{pattern!r}: only we cover {sorted(got - want)}; only git covers {sorted(want - got)}"


def test_the_reported_repros() -> None:
    with pytest.raises(CodeownersError, match="cannot evaluate CODEOWNERS rule at line 2"):
        parse_rules("* @o\n/a*g*e*n*t*s*.*y*a*ml\n")
    assert not covered(parse_rules("s**agentsfile.py @owner\n"), "src/safo/agentsfile.py")
    assert not covered(parse_rules("* @o\n/examples/harness/*.md\n"), "examples/harness/probe.md")
    assert uncovered(parse_rules("* @o\n/examples/harness/*.md\n"), ["examples/harness/"]) == ["examples/harness/"]
    assert uncovered(parse_rules("* @o\n/examples/harness/*.yaml\n"), ["examples/harness/"]) == ["examples/harness/"]
    assert uncovered(parse_rules("* @o\n"), ["examples/harness/"]) == []


@pytest.mark.parametrize(
    ("line", "why"),
    [
        ("[Section] @o", "bracket"),
        ("^[Section] @o", "bracket"),
        ("/a[bc].md @o", "bracket"),
        ("!/a.md @o", "negation"),
        ("/a\\q.md @o", "escape"),
        ("x**/z @o", "ambiguous"),
        ("/a**/z @o", "ambiguous"),
        ("x/y**/z @o", "ambiguous"),
        ("/a\\", "escape"),
        ("/" + "x" * 300 + " @o", "long"),
        ("/a*b*c*d*e*f*g*h*i @o", "wildcards"),
    ],
)
def test_a_rule_that_cannot_be_evaluated_fails_closed_naming_its_line(line: str, why: str) -> None:
    with pytest.raises(CodeownersError, match=r"cannot evaluate CODEOWNERS rule at line 3"):
        parse_rules(f"* @o\n# c\n{line}\n")


def test_rules_past_the_cap_fail_closed() -> None:
    from safo.codeowners import MAX_RULES

    with pytest.raises(CodeownersError, match="cannot evaluate"):
        parse_rules("# note\n" * MAX_RULES + "* @owner\n")


def test_escapes_are_honoured() -> None:
    assert covered(parse_rules("a\\ b @o\n"), "a b")
    assert covered(parse_rules("a\\#b @o\n"), "a#b")
    assert covered(parse_rules("a\\*b @o\n"), "a*b") and not covered(parse_rules("a\\*b @o\n"), "axb")
