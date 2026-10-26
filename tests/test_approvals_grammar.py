# SPDX-License-Identifier: Apache-2.0
"""The approval body grammar (one `Entry:` line, no raw HTML, CommonMark fences), the cross-check type and impossible
timestamps. Split from test_approvals.py to keep both files readable."""

from __future__ import annotations

from typing import Any

import pytest

from fakegh import FakeGitHub
from fakegh.approval_ops import issue_node
from fakegh.core import JSON
from safo.approvals import CrossCheck
from safo.graphql import Client
from test_approvals import GATE, M13, E, gate, judge, newest

FENCE_CASES: dict[str, tuple[str, bool]] = {
    "closing fence with trailing text does not close": (f"```\nnot visible\n```oops\n{E}", False),
    "tilde closing with trailing text does not close": (f"~~~\nnot visible\n~~~oops\n{E}", False),
    "shorter closing run does not close": (f"````\nx\n```\n{E}", False),
    "shorter tilde run does not close": (f"~~~~~\nx\n~~~~\n{E}", False),
    "other character does not close": (f"```\nx\n~~~\n{E}", False),
    "four-space closing does not close": (f"```\nx\n    ```\n{E}", False),
    "indented three opens a fence": (f"   ```\n{E}\n   ```", False),
    "tilde info string with a backtick still opens": (f"~~~ a`b\n{E}\n~~~", False),
    "longer fence closed by the same run": (f"````\nx\n````\n{E}", True),
    "longer closing run closes": (f"```\nx\n````\n{E}", True),
    "trailing spaces and tabs close": (f"```\nx\n``` \t \n{E}", True),
    "info string": (f"```python title\nx\n```\n{E}", True),
    "backtick in a backtick info string is no fence": (f"``` a`b\n{E}", True),
    "four-space indent is no fence": (f"    ```\n{E}", True),
    "four-space fenced pair is no fence": (f"    ```\nx\n    ```\n{E}", True),
    "quote continuation line is not its own entry": (f"> quoted\n{E}", False),
    "list continuation line is not its own entry": (f"- item\n{E}", False),
}


@pytest.mark.parametrize("name", list(FENCE_CASES))
def test_the_fence_grammar_is_commonmarks(fake: FakeGitHub, client: Client, name: str) -> None:
    body, counts = FENCE_CASES[name]
    v = judge(fake, client, issue_node(title="t", body=body))
    assert v.approved is counts, name
    assert counts or v.lines == (M13,)


HTML_REFUSED: dict[str, str] = {
    "nested details": f"<details>\n<summary>approval data</summary>\n\n{E}\n</details>",
    "details with attributes and case": f"<DETAILS open class='x'>\n\n<Summary>a</Summary>\n\n{E}\n</DETAILS>",
    "unclosed details": f"<details>\n{E}",
    "malformed tag": f"<div\n{E}",
    "unterminated attribute": f'<div class="x\n\n{E}',
    "type 1 script": f"<script>\nx\n</script>\n\n{E}",
    "type 1 pre": f"<pre>\nx\n</pre>\n\n{E}",
    "type 1 style": f"<style>\nx\n</style>\n\n{E}",
    "type 1 textarea": f"<textarea>\nx\n</textarea>\n\n{E}",
    "type 2 comment": f"<!-- c -->\n{E}",
    "type 3 processing instruction": f"<?php x ?>\n{E}",
    "type 4 declaration": f"<!DOCTYPE html>\n{E}",
    "type 5 cdata": f"<![CDATA[x]]>\n{E}",
    "type 6 div": f"<div>\n{E}",
    "type 6 table": f"<table>\n\n{E}",
    "type 7 open tag": f"<a href=x>\n{E}",
    "type 7 closing tag": f"</span>\n{E}",
    "inline span": f"text <span>x</span>\n{E}",
    "comment after the entry": f"{E}\n<!-- later -->",
    "html after the entry": f"{E}\n<b>x</b>",
    "not a tag to a human, a tag to CommonMark": f"<not a tag>\n{E}",
    "single letter tag": f"<a>\n{E}",
    "autolink is refused too": f"<https://example.test>\n{E}",
    "inside an inline code span": f"`<b>`\n{E}",
}


@pytest.mark.parametrize("name", list(HTML_REFUSED))
def test_a_body_with_raw_html_is_refused_entirely(fake: FakeGitHub, client: Client, name: str) -> None:
    v = judge(fake, client, issue_node(title="t", body=HTML_REFUSED[name]))
    assert v.state == "unknown" and not v.approved, name
    assert v.lines == (
        "UNKNOWN SCOPE acme/gates#21 has raw HTML in its body; an approval body must be plain text, "
        "so its entry cannot be told",
    )


@pytest.mark.parametrize(
    "body",
    [
        f"a < b\n{E}",
        f"I <3 this\n{E}",
        f"1<2 and x <- y\n{E}",
        f"```\n<div>\n<!-- c -->\n```\n{E}",
        f"~~~html\n<script>x</script>\n~~~\n{E}",
        f"{E}\n```\n<b>\n```",
    ],
)
def test_an_angle_bracket_that_is_not_a_tag_and_html_inside_a_fence_are_literal(
    fake: FakeGitHub, client: Client, body: str
) -> None:
    assert judge(fake, client, issue_node(title="t", body=body)).approved


@pytest.mark.parametrize("flag", [0, 1, "", "VERIFIED_MANUAL", [], {}, None, True, False])
def test_only_the_exact_manual_cross_check_approves(fake: FakeGitHub, client: Client, flag: Any) -> None:
    v = judge(fake, client, issue_node(), gate(), cross_check=flag)
    assert not v.approved and v.state in ("open", "unknown")


IMPOSSIBLE: dict[str, JSON] = {
    "created after the close": {"createdAt": "2026-11-06T00:00:00Z"},
    "edited before it existed": {"lastEditedAt": "2026-11-01T00:00:00Z"},
    "renamed before it existed": {"changes": newest("RenamedTitleEvent", "2026-11-01T00:00:00Z")},
    "reopened before it existed": {"changes": newest("ReopenedEvent", "2026-11-01T00:00:00Z")},
}


@pytest.mark.parametrize("name", list(IMPOSSIBLE))
def test_an_impossible_timestamp_relationship_is_unknown(fake: FakeGitHub, client: Client, name: str) -> None:
    v = judge(fake, client, issue_node(**IMPOSSIBLE[name]), gate())
    assert v.state == "unknown" and not v.approved, name
    assert v.lines == (f"UNKNOWN {GATE} has timestamps that cannot be true; its approval cannot be told",)


def test_created_in_the_same_second_as_the_close_is_possible(fake: FakeGitHub, client: Client) -> None:
    assert judge(fake, client, issue_node(createdAt="2026-11-05T12:00:00Z"), gate()).approved


def test_a_cross_check_has_no_truthiness() -> None:
    for member in CrossCheck:
        with pytest.raises(TypeError):
            bool(member)
