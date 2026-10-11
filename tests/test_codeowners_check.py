# SPDX-License-Identifier: MIT
"""Spec test 22: `safo profiles verify` fails when CODEOWNERS misses a path the profiles are rendered from."""

from __future__ import annotations

from pathlib import Path

import pytest

from evdata import repo
from localcli import cli
from profiledata import doc, profile, put
from safo.codeowners import REQUIRED, CodeownersError, covered, find_codeowners, parse_rules, required_paths

ALL = [
    "/agents.yaml",
    "/examples/harness/",
    "/.claude/agents/",
    "/agents/",
    "/docs/lessons.md",
    "/src/safo/agentsfile.py",
    "/src/safo/profile_render.py",
]


def owners(lines: list[str]) -> str:
    return "".join(f"{x} @owner\n" for x in lines)


def verify(tmp_path: Path, home: Path, text: str | None, d: dict | None = None) -> tuple[int, str]:
    path = repo(tmp_path, d, codeowners=text)
    code, out, _ = cli("profiles", "verify", "--agents", str(path), home=home)
    return code, out


def test_full_coverage_passes(tmp_path: Path, _private_home: Path) -> None:
    code, out = verify(tmp_path, _private_home, owners(ALL))
    assert code == 0 and "CODEOWNERS covers" in out


def test_a_star_rule_covers_everything(tmp_path: Path, _private_home: Path) -> None:
    code, _ = verify(tmp_path, _private_home, "* @owner\n")
    assert code == 0


@pytest.mark.parametrize("missing", ALL)
def test_each_listed_path_must_be_covered(tmp_path: Path, _private_home: Path, missing: str) -> None:
    code, out = verify(tmp_path, _private_home, owners([x for x in ALL if x != missing]))
    assert code == 1
    assert f"not covered by CODEOWNERS: {missing.lstrip('/')}" in out


def test_the_template_directory_of_a_profile_must_be_covered(tmp_path: Path, _private_home: Path) -> None:
    d = doc()
    profile(d, "codex")["brief"] = {"template": "briefs/codex/brief.md"}
    put(tmp_path, "briefs/codex/brief.md", "Work from this.\n\n{{task}}\n")
    code, out = verify(tmp_path, _private_home, owners(ALL), d)
    assert code == 1 and "not covered by CODEOWNERS: briefs/codex/" in out
    code, out = verify(tmp_path, _private_home, owners([*ALL, "/briefs/"]), d)
    assert code == 0, out


def test_a_configured_lessons_path_is_the_one_checked(tmp_path: Path, _private_home: Path) -> None:
    d = doc()
    d["evidence_sources"] = {"lessons": "notes/learned.md"}
    put(tmp_path, "notes/learned.md", "")
    path_text = owners([x for x in ALL if x != "/docs/lessons.md"])
    # the lessons file is not at docs/lessons.md here, so every pointer dangles; the CODEOWNERS gap is still reported
    code, out = verify(tmp_path, _private_home, path_text, d)
    assert "not covered by CODEOWNERS: notes/learned.md" in out and code == 1


def test_no_codeowners_file_at_all_fails(tmp_path: Path, _private_home: Path) -> None:
    code, out = verify(tmp_path, _private_home, None)
    assert code == 1 and "no CODEOWNERS file" in out


def test_an_owner_less_later_rule_removes_ownership(tmp_path: Path, _private_home: Path) -> None:
    code, out = verify(tmp_path, _private_home, "* @owner\n/examples/harness/\n")
    assert code == 1 and "examples/harness/" in out


def test_a_rule_with_no_valid_owner_covers_nothing(tmp_path: Path, _private_home: Path) -> None:
    code, _ = verify(tmp_path, _private_home, "* not-an-owner\n")
    assert code == 1


def test_a_comment_is_not_a_rule() -> None:
    assert not covered(parse_rules("# * @owner\n"), "agents.yaml")


def test_the_last_matching_rule_wins() -> None:
    rules = parse_rules("* @a\n/docs/ @b\n/docs/lessons.md\n")
    assert covered(rules, "agents.yaml") and covered(rules, "docs/other.md")
    assert not covered(rules, "docs/lessons.md")


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("*", "a/b/c.py", True),
        ("/agents.yaml", "agents.yaml", True),
        ("/agents.yaml", "sub/agents.yaml", False),
        ("agents.yaml", "sub/agents.yaml", True),
        ("/examples/harness/", "examples/harness/x/y.md", True),
        ("/examples/harness/", "examples/harness", False),
        ("examples/harness/", "examples/harness/x", True),
        ("harness/", "examples/harness/x", True),
        ("*.md", "docs/lessons.md", True),
        ("*.md", "docs/lessons.txt", False),
        ("docs/*.md", "docs/lessons.md", True),
        ("docs/*.md", "docs/a/lessons.md", False),
        ("/docs/**", "docs/a/b.md", True),
        ("/**/lessons.md", "docs/lessons.md", True),
        ("/src/safo/agentsfile.py", "src/safo/agentsfile.py", True),
        ("/src/safo/", "src/safo/profile_render.py", True),
        ("/a?c.md", "abc.md", True),
        ("/a?c.md", "a/c.md", False),
        ("/src", "src/safo/x.py", True),
    ],
)
def test_the_pattern_forms(pattern: str, path: str, expected: bool) -> None:
    assert covered(parse_rules(f"{pattern} @owner\n"), path) is expected


@pytest.mark.parametrize("owner", ["@user", "@org/team", "someone@example.com"])
def test_owner_forms(owner: str) -> None:
    assert covered(parse_rules(f"* {owner}\n"), "x")


def test_the_three_github_locations_in_precedence_order(tmp_path: Path) -> None:
    for place, mark in ((".github/CODEOWNERS", "gh"), ("CODEOWNERS", "root"), ("docs/CODEOWNERS", "docs")):
        put(tmp_path, place, f"* @{mark}\n")
    assert find_codeowners(tmp_path).startswith("* @gh")
    (tmp_path / ".github" / "CODEOWNERS").unlink()
    assert find_codeowners(tmp_path).startswith("* @root")
    (tmp_path / "CODEOWNERS").unlink()
    assert find_codeowners(tmp_path).startswith("* @docs")


def test_a_symbolic_link_or_a_huge_codeowners_is_refused(tmp_path: Path) -> None:
    put(tmp_path, "elsewhere", "* @owner\n")
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "CODEOWNERS").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(CodeownersError):
        find_codeowners(tmp_path)
    (tmp_path / ".github" / "CODEOWNERS").unlink()
    put(tmp_path, ".github/CODEOWNERS", "# " + "x" * (3 * 1024 * 1024) + "\n")
    with pytest.raises(CodeownersError):
        find_codeowners(tmp_path)


def test_the_required_list_is_the_one_the_spec_names() -> None:
    assert REQUIRED == ("agents.yaml", "examples/harness/", ".claude/agents/", "agents/", "src/safo/agentsfile.py", "src/safo/profile_render.py")
    assert "docs/lessons.md" in required_paths("docs/lessons.md", ())
    assert "briefs/" in required_paths("docs/lessons.md", ("briefs/a.md",))
    assert "x/y/" in required_paths("docs/lessons.md", ("x/y/z.md",))


def test_this_repositorys_own_codeowners_covers_the_profile_paths() -> None:
    root = Path(__file__).parent.parent
    rules = parse_rules(find_codeowners(root))
    assert all(covered(rules, p) for p in required_paths("docs/lessons.md", ()))
