# SPDX-License-Identifier: Apache-2.0
"""report-not-found (#353): a report that says not found, blocked or 403 must show how it looked.

Checks report SHAPE (listed queries or a named fallback), never whether the claim is true.
"""

from __future__ import annotations

import pytest

from safo.reportshape import check

TWO = "no statement found\nquery: tuxedo computers intel me\nsearch: tuxedo press release intel me disable"


def test_a_report_with_two_listed_queries_passes() -> None:
    assert check(TWO) == []


def test_a_403_report_with_no_queries_warns() -> None:
    found = check("Standards portal: 403, not read\nUsed Wikipedia instead.")
    assert found and "403" in found[0] and "two" in found[0]


@pytest.mark.parametrize(
    "phrase",
    [
        "not found",
        "could not find it",
        "unverified",
        "blocked",
        "got a 403",
        "could not read the page",
        "not read",
        "no statement found",
    ],
)
def test_every_trigger_phrase_warns_alone(phrase: str) -> None:
    assert check(f"The vendor claim is {phrase}.")


def test_one_query_is_not_enough() -> None:
    assert check("not found\nquery: only one")


def test_the_same_query_twice_counts_once() -> None:
    assert check("not found\nquery: same thing\nQuery: SAME  thing")


def test_a_named_fallback_source_is_enough() -> None:
    assert check("403 on the portal.\nfallback: web.archive.org copy of the page, read in full") == []
    assert check("blocked\nsecond source: the vendor's press release on its news page") == []


def test_an_empty_fallback_does_not_count() -> None:
    assert check("blocked\nfallback:") != []


def test_a_report_with_no_trigger_phrase_is_not_checked() -> None:
    assert check("ROLE: implementer\nGATE: make check exit=0\nNOT VERIFIED: none") == []
    assert check("The roadblocked path is fine and the notation is read aloud.") == []


def test_list_markers_before_a_query_line_are_accepted() -> None:
    assert check("not found\n- query: a b c\n* search: d e f") == []


# -- wired into `safo handoff shape` ----------------------------------------------------------------------

from pathlib import Path  # noqa: E402  (kept next to the tests that use it)

from fakegh import FakeGitHub  # noqa: E402
from fakegh.core import FPull  # noqa: E402
from handoff_render import render  # noqa: E402
from hooksdata import agents_file  # noqa: E402
from localcli import cli  # noqa: E402

REPO = "n0tst/demo"
HOME = Path("/nonexistent-home")


def shape(fake: FakeGitHub, body: str, *extra: str, assoc: str = "OWNER") -> tuple[int, str, str]:
    node = {
        "authorAssociation": assoc,
        "createdAt": "2026-10-20T10:00:00Z",
        "bodyHTML": render(body),
        "isMinimized": False,
        "lastEditedAt": None,
    }
    fake.pulls[(REPO, 7)] = FPull(head="a" * 40, comments=[node])
    env = {"SAFO_TOKEN": fake.token, "GITHUB_GRAPHQL_URL": fake.url}
    return cli("handoff", "shape", *extra, REPO, "7", home=HOME, extra_env=env)


HEADER = "ROLE: implementer   MODEL: n0tst-model\nHEAD: " + "a" * 7 + "   BASE: 1234567\n"


def test_shape_warns_on_a_403_report_with_no_queries(fake: FakeGitHub) -> None:
    code, out, _ = shape(fake, HEADER + "Standards portal: 403, not read\n")
    assert code == 0 and out.startswith("WARN report-not-found")


def test_shape_passes_a_report_with_two_queries(fake: FakeGitHub) -> None:
    code, out, _ = shape(fake, HEADER + "no statement found\nquery: one thing\nquery: other thing\n")
    assert code == 0 and out.startswith("OK report-not-found")


def test_shape_ignores_a_comment_from_a_stranger(fake: FakeGitHub) -> None:
    code, out, _ = shape(fake, HEADER + "not found\n", assoc="NONE")
    assert code == 2 and out.startswith("UNKNOWN")


def test_shape_can_be_switched_off_in_agents_yaml(fake: FakeGitHub, tmp_path: Path) -> None:
    path = agents_file(tmp_path / "agents.yaml", research={"report_not_found": False})
    code, out, _ = shape(fake, HEADER + "blocked\n", "--agents", str(path))
    assert code == 0 and out.startswith("OFF report-not-found")
