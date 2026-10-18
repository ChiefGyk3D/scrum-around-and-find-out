# SPDX-License-Identifier: Apache-2.0
"""Where GitHub's CODEOWNERS differs from gitignore, and what GitHub does with the file itself.

The gitignore differential test (test_codeowners_differential.py) cannot see these; they are written from GitHub's
documented behaviour.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from profiledata import put
from safo.codeowners import MAX_BYTES, CodeownersError, covered, find_codeowners, parse_rules


def test_an_escaped_leading_hash_is_refused_because_github_does_not_support_it() -> None:
    with pytest.raises(CodeownersError, match=r"cannot evaluate CODEOWNERS rule at line 2: an escaped leading # is"):
        parse_rules("* @o\n\\#notes.md @o\n")
    assert covered(parse_rules("a\\#b @o\n"), "a#b")  # an escaped hash elsewhere in the pattern is fine


def test_a_file_of_the_size_limit_or_more_is_refused(tmp_path: Path) -> None:
    def write(size: int) -> None:
        put(tmp_path, ".github/CODEOWNERS", "# " + "x" * (size - 3) + "\n")

    write(MAX_BYTES - 1)
    assert len(find_codeowners(tmp_path).encode()) == MAX_BYTES - 1
    for size in (MAX_BYTES, MAX_BYTES + 1):
        write(size)
        with pytest.raises(CodeownersError, match="3 MiB or more"):
            find_codeowners(tmp_path)


def test_a_line_without_an_owner_clears_ownership_and_the_last_match_wins() -> None:
    rules = parse_rules("* @a\n/docs/ @b\n/docs/lessons.md\n")
    assert covered(rules, "x.py") and covered(rules, "docs/other.md")
    assert not covered(rules, "docs/lessons.md")
    assert covered(parse_rules("/docs/lessons.md\n* @a\n"), "docs/lessons.md")


def test_the_first_codeowners_found_is_the_one_read(tmp_path: Path) -> None:
    for place, mark in ((".github/CODEOWNERS", "gh"), ("CODEOWNERS", "root"), ("docs/CODEOWNERS", "docs")):
        put(tmp_path, place, f"* @{mark}\n")
    assert find_codeowners(tmp_path).startswith("* @gh")
    (tmp_path / ".github" / "CODEOWNERS").unlink()
    assert find_codeowners(tmp_path).startswith("* @root")
    (tmp_path / "CODEOWNERS").unlink()
    assert find_codeowners(tmp_path).startswith("* @docs")
