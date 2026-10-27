# SPDX-License-Identifier: Apache-2.0
"""The approval body grammar (plain paragraphs, one standalone `Entry:` line, no raw HTML, no Markdown structure), the
cross-check type and impossible timestamps. Split from test_approvals.py to keep both files readable."""

from __future__ import annotations

import datetime as dt
from typing import Any

import pytest

from fakegh import FakeGitHub
from fakegh.approval_ops import issue_node
from fakegh.core import JSON
from safo import approvals
from safo.approvals import Check
from safo.graphql import Client
from test_approvals import GATE, E, check, gate, judge, newest

HTML_LINE = (
    "UNKNOWN SCOPE acme/gates#21 has raw HTML in its body; an approval body must be plain text, "
    "so its entry cannot be told"
)


def structure_line(kind: str) -> str:
    return (
        f"UNKNOWN SCOPE acme/gates#21 has Markdown structure in its body ({kind}); "
        "an approval body must be plain paragraphs, so its entry cannot be told"
    )


# construct text -> the class the refusal names. Each is placed before, around and after the Entry line.
STRUCTURES: dict[str, tuple[str, str]] = {
    "fence 3": ("```", "fence"),
    "fence 4": ("````", "fence"),
    "fence tilde": ("~~~", "fence"),
    "fence tilde 5": ("~~~~~", "fence"),
    "fence info string": ("```python title", "fence"),
    "fence backtick in info": ("``` a`b", "fence"),
    "fence tilde info": ("~~~ a`b", "fence"),
    "fence indent 3": ("   ```", "fence"),
    "fence indent 4": ("    ```", "fence"),
    "fence trailing text": ("```oops", "fence"),
    "inline triple backticks": ("x ```y``` z", "fence"),
    "unterminated fence with content": ("```\nhidden", "fence"),
    "bullet dash": ("- item", "list or quote"),
    "bullet star": ("* item", "list or quote"),
    "bullet plus": ("+ item", "list or quote"),
    "ordered dot": ("1. item", "list or quote"),
    "ordered paren": ("2) item", "list or quote"),
    "empty bullet": ("*", "list or quote"),
    "list with lazy continuation": ("- item\n  more", "list or quote"),
    "quote": ("> quoted", "list or quote"),
    "quote no space": (">quoted", "list or quote"),
    "quote indented": ("   > quoted", "list or quote"),
    "table with rule": ("| a | b |\n|---|---|", "table"),
    "table without edges": ("a | b", "table"),
    "link reference": ("[x]: http://example.test", "brackets"),
    "link reference multi-line title": ('[x]: http://example.test "multi\nline"', "brackets"),
    "footnote definition": ("[^n]: note", "brackets"),
    "link reference, one space": (" [x]: http://example.test", "brackets"),
    "link reference, three spaces": ('   [x]: http://example.test "title"', "brackets"),
    "link reference, title on the next line": ('[x]:\n  http://example.test\n  "a title"', "brackets"),
    "open bracket alone": ("[", "brackets"),
    "close bracket alone": ("]", "brackets"),
    "inline link": ("see [a](https://example.test/x)", "brackets"),
    "image": ("![b](https://example.test/y)", "brackets"),
    "bracket inside prose": ("a [b c", "brackets"),
    "indented code": ("    code", "indented code"),
    "tab indented code": ("\tcode", "indented code"),
    "atx heading": ("# Heading", "heading"),
    "atx heading 6": ("###### Heading", "heading"),
    "atx empty heading": ("#", "heading"),
    "setext equals": ("Title\n=====", "heading"),
    "setext dashes": ("Title\n--", "heading"),
    "thematic dashes": ("---", "thematic break"),
    "thematic stars": ("***", "thematic break"),
    "thematic spaced": ("* * *", "thematic break"),
    "thematic underscores": ("___", "thematic break"),
    "backslash at end of line": ("line ends\\", "line continuation"),
}


def placements(construct: str) -> dict[str, str]:
    return {
        "before": f"{construct}\n\n{E}",
        "after": f"{E}\n\n{construct}",
        "around": f"intro\n\n{construct}\n\n{E}\n\n{construct}",
        "touching": f"{construct}\n{E}",
        "inside a paragraph": f"intro\n{construct}\n{E}\nouter",
    }


CASES = [(n, w) for n in STRUCTURES for w in placements("x")]


@pytest.mark.parametrize(("name", "where"), CASES, ids=[f"{n}/{w}" for n, w in CASES])
def test_any_markdown_structure_anywhere_makes_the_body_unknown(
    fake: FakeGitHub, client: Client, name: str, where: str
) -> None:
    construct, kind = STRUCTURES[name]
    v = judge(fake, client, issue_node(title="t", body=placements(construct)[where]))
    assert v.state == "unknown" and not v.approved, (name, where)
    assert v.lines == (structure_line(kind),), (name, where)


def test_the_refusal_names_the_class_and_never_the_content(fake: FakeGitHub, client: Client) -> None:
    v = judge(fake, client, issue_node(title="t", body=f"- SECRET-PAYLOAD\n\n{E}"))
    assert "SECRET-PAYLOAD" not in v.lines[0] and "list or quote" in v.lines[0]


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
    "inside a fence": f"```\n<div>\n```\n{E}",
}


@pytest.mark.parametrize("name", list(HTML_REFUSED))
def test_a_body_with_raw_html_is_refused_entirely(fake: FakeGitHub, client: Client, name: str) -> None:
    v = judge(fake, client, issue_node(title="t", body=HTML_REFUSED[name]))
    assert v.state == "unknown" and not v.approved, name
    assert v.lines == (HTML_LINE,)


ACCEPTED = {
    "only the entry": E,
    "only the entry and a newline": f"{E}\n",
    "crlf": f"Intro.\r\n\r\n{E}\r\n\r\nOutro.",
    "prose, blank, entry, blank, prose": f"Intro paragraph.\nSecond line.\n\n{E}\n\nOutro paragraph.\n",
    "whitespace-only blank lines": f"Intro.\n  \n{E}\n \t \nOutro.",
    "entry mentioned inline elsewhere": f"I approve {E.removeprefix('Entry: ')}.\n\n{E}",
    "inner tab in prose": f"a\tb\n\n{E}",
}


MARKUP_REFUSED: dict[str, str] = {
    "strong": "**Entry:** attacker/repo#9",
    "character reference": "&#69;ntry: attacker/repo#9",
    "code span": "`Entry: attacker/repo#9`",
    "strikethrough": "~~Entry:~~ attacker/repo#9",
    "math": "$Entry:$ attacker/repo#9",
    "backslash": "\\Entry: attacker/repo#9",
    "split by a character reference": "Entr&#121;: attacker/repo#9",
    "emphasis star": "*Entry:* attacker/repo#9",
    "emphasis underscore": "_Entry:_ attacker/repo#9",
    "a bare angle bracket": "a < b",
    "less-than digit": "I <3 this",
    "arrows": "1<2 and x <- y",
}


@pytest.mark.parametrize("name", list(MARKUP_REFUSED))
@pytest.mark.parametrize("where", ["before", "after"])
def test_a_rendered_second_entry_cannot_hide_behind_markup(
    fake: FakeGitHub, client: Client, name: str, where: str
) -> None:
    bad = MARKUP_REFUSED[name]
    body = f"{bad}\n\n{E}" if where == "before" else f"{E}\n\n{bad}"
    v = judge(fake, client, issue_node(title="t", body=body))
    assert v.state == "unknown" and not v.approved, name
    assert v.lines == (UNUSUAL_LINE,), name


@pytest.mark.parametrize("ch", list("*_`~&$^%{}"))
def test_every_markup_character_outside_the_allow_list_refuses_the_body(
    fake: FakeGitHub, client: Client, ch: str
) -> None:
    v = judge(fake, client, issue_node(title="t", body=f"intro {ch} text\n\n{E}"))
    assert v.state == "unknown" and v.lines == (UNUSUAL_LINE,), ch


ENTRY_LOOKALIKES: dict[str, str] = {
    "upper case": "ENTRY: x/y#1",
    "lower case": "entry: x/y#1",
    "space before the colon": "Entry : x/y#1",
    "inside a sentence": "Please note Entry: x/y#1 here",
    "tab after the colon": "Entry:\tx/y#1",
    "mixed case in a sentence": "an eNtRy: field",
    "tab before the colon": "Entry\t: x/y#1",
}


@pytest.mark.parametrize("name", list(ENTRY_LOOKALIKES))
def test_no_other_line_may_look_like_an_entry_line(fake: FakeGitHub, client: Client, name: str) -> None:
    for body in (f"{ENTRY_LOOKALIKES[name]}\n\n{E}", f"{E}\n\n{ENTRY_LOOKALIKES[name]}"):
        v = judge(fake, client, issue_node(title="t", body=body))
        assert v.state == "open" and not v.approved, (name, body)
    alone = judge(fake, client, issue_node(title="t", body=ENTRY_LOOKALIKES[name]))
    assert alone.state == "open" and not alone.approved, name


def test_ordinary_prose_with_the_allowed_punctuation_is_approved(fake: FakeGitHub, client: Client) -> None:
    prose = "Hello, world. Is this ok? Yes! See (issue #12; a/b @c +1 = 2 - 1: 'x' \"y\")."
    assert judge(fake, client, issue_node(title="t", body=f"{prose}\n\n{E}\n\n{prose}")).approved
    underscore_repo = "Entry: acme/my_repo.git#55"
    chk = check_for("acme/my_repo.git#55")
    assert judge(fake, client, issue_node(title="t", body=f"{prose}\n\n{underscore_repo}"), chk).approved


def check_for(entry: str) -> Check:
    return check(entry=entry)


def test_two_entry_lines_are_not_for_this_change_even_when_apart(fake: FakeGitHub, client: Client) -> None:
    for body in (f"{E}\n\n{E}", f"{E}\n\nEntry: acme/app#56", f"Entry: acme/app#56\n\n{E}"):
        v = judge(fake, client, issue_node(title="t", body=body))
        assert v.state == "open" and not v.approved, body


UNUSUAL = {
    "no-break space": chr(0xA0),
    "line separator": chr(0x2028),
    "paragraph separator": chr(0x2029),
    "next line": "\u0085",
    "vertical tab": "\x0b",
    "form feed": "\x0c",
    "zero-width space": "​",
    "ideographic space": "　",
    "bidi override": "‮",
    "nul": "\x00",
    "escape": "\x1b",
    "accented letter": "é",
}
UNUSUAL_LINE = (
    "UNKNOWN SCOPE acme/gates#21 has unusual or markup characters in its body; an approval body must be plain text "
    "using letters, digits and basic punctuation, so its entry cannot be told"
)


@pytest.mark.parametrize("name", list(UNUSUAL))
@pytest.mark.parametrize("where", ["blank line before", "blank line after", "inside the entry", "trailing", "leading"])
def test_a_character_outside_printable_ascii_makes_the_body_unknown(
    fake: FakeGitHub, client: Client, name: str, where: str
) -> None:
    ch = UNUSUAL[name]
    body = {
        "blank line before": f"intro\n{ch}\n{E}",
        "blank line after": f"{E}\n{ch}\noutro",
        "inside the entry": f"intro\n\nEntry:{ch}acme/app#55",
        "trailing": f"intro\n\n{E}{ch}",
        "leading": f"{ch}intro\n\n{E}",
    }[where]
    v = judge(fake, client, issue_node(title="t", body=body))
    assert v.state == "unknown" and not v.approved and v.lines == (UNUSUAL_LINE,), (name, where)


def test_a_lone_carriage_return_is_refused_and_crlf_is_not(fake: FakeGitHub, client: Client) -> None:
    lone = judge(fake, client, issue_node(title="t", body=f"intro\r{E}"))
    assert lone.state == "unknown" and lone.lines == (UNUSUAL_LINE,)
    assert judge(fake, client, issue_node(title="t", body=f"intro\r\n\r\n{E}\r\n")).approved


def test_a_tab_is_never_indentation(fake: FakeGitHub, client: Client) -> None:
    for body in (f"intro\n\n\t{E}", f"\tintro\n\n{E}", f"intro\n\n \t{E}"):
        v = judge(fake, client, issue_node(title="t", body=body))
        assert v.state == "unknown" and not v.approved, body


def test_a_tab_only_line_is_blank_like_commonmark(fake: FakeGitHub, client: Client) -> None:
    assert judge(fake, client, issue_node(title="t", body=f"intro\n\t \t\n{E}\n \t\nouter")).approved


@pytest.mark.parametrize("name", list(ACCEPTED))
def test_plain_paragraphs_with_a_standalone_entry_line_are_approved(
    fake: FakeGitHub, client: Client, name: str
) -> None:
    assert judge(fake, client, issue_node(title="t", body=ACCEPTED[name])).approved, name


@pytest.mark.parametrize("flag", [0, 1, "", "VERIFIED_MANUAL", [], {}, None, True, False, object()])
def test_only_a_real_events_read_can_approve(fake: FakeGitHub, client: Client, flag: Any) -> None:
    v = judge(fake, client, issue_node(), gate(), events=flag)
    assert not v.approved and v.state == "unknown"


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


@pytest.mark.parametrize(
    "ch", [chr(0xA0), chr(0x2028), chr(0x2029), chr(0x85), "\x0b", "\x0c", chr(0x200B), chr(0x3000)]
)
def test_a_line_of_unicode_whitespace_is_not_a_blank_line_even_past_the_ascii_gate(
    ch: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Defense in depth: with the ASCII gate lifted, the blank-line test is still CommonMark's, spaces and tabs only."""
    monkeypatch.setattr(approvals, "_lines", lambda body: body.split("\n"))
    monkeypatch.setattr(approvals, "body_problem", lambda body: None)
    assert approvals._entry_state(f"intro\n{ch}\n{E}", "acme/app#55") == "missing"
    assert approvals._entry_state(f"{E}\n{ch}\nouter", "acme/app#55") == "missing"
    assert approvals._entry_state(f"intro\n \t\n{E}\n\t \nouter", "acme/app#55") == "named"


class _Duck:
    """Looks like a complete, matching, manual EventsRead but is not one."""

    repo = "acme/gates"
    number = 21
    complete = True
    closes = (approvals.RestClose(dt.datetime(2026, 11, 5, 12, 0, tzinfo=dt.UTC), False),)


def test_a_look_alike_of_an_events_read_never_approves(fake: FakeGitHub, client: Client) -> None:
    v = judge(fake, client, issue_node(), gate(), events=_Duck())
    assert v.state == "unknown" and not v.approved


def test_an_events_read_marked_incomplete_never_approves_even_with_closes(fake: FakeGitHub, client: Client) -> None:
    close = approvals.RestClose(dt.datetime(2026, 11, 5, 12, 0, tzinfo=dt.UTC), False)
    events = approvals.EventsRead("acme/gates", 21, False, (close,))
    v = judge(fake, client, issue_node(), gate(), events=events)
    assert v.state == "unknown" and not v.approved
