# SPDX-License-Identifier: Apache-2.0
"""`safo handoff check` reads a report only from the HTML GitHub rendered, and only from a top-level paragraph.

Real renderings are in tests/data/handoff_html (SOURCES.md says where each came from). Everything else here is
hand-written and UNVERIFIED against GitHub's renderer; the shapes are copied from the real ones.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from fakegh import FakeGitHub
from safo.modes import handoff
from test_handoff_check import EARLY, A, B, comment, report, run

DATA = Path(__file__).parent / "data" / "handoff_html"


def para(*lines: str) -> str:
    return '<p dir="auto">' + "<br>\n".join(lines) + "</p>"


HEADER = ("ROLE: reviewer   MODEL: n0tst-model", f"HEAD: {A}   BASE: 1234567")
REPORT_P = para(*HEADER)


# -- the reader, on real renderings -----------------------------------------------------------------------------


def lines_of(name: str) -> list[str]:
    return handoff.report_lines((DATA / name).read_text(encoding="utf-8"))


def test_the_real_list_comment_yields_only_its_top_level_paragraphs() -> None:
    lines = lines_of("issue_comment_with_list.html")
    text = "\n".join(lines)
    assert "You are seeing this message because" in text and "For more information about" in text
    assert "The 'Security' tab" not in text and "What Enabling Code Scanning Means" not in text  # li and h3


def test_the_real_details_and_blockquote_yield_nothing_from_inside_them() -> None:
    text = "\n".join(lines_of("pr_body_with_details_and_blockquote.html"))
    assert "Bumps the actions group" in text
    for hidden in ("Release notes", "Sourced from", "v2.22.0", "What's Changed", "Linux ARM64"):
        assert hidden not in text


def test_the_real_fenced_code_yields_no_code() -> None:
    text = "\n".join(lines_of("pr_body_with_fenced_code.html"))
    assert "First of the seven" in text
    assert "scripts/apply-baseline.sh" not in text and "git pull" not in text


def test_the_real_dropped_html_comment_is_not_in_the_output() -> None:
    text = "\n".join(lines_of("pr_body_with_dropped_html_comment.html"))
    assert "raw HTML omitted" not in text and "Bumps the python-dependencies group" in text


def test_the_real_hard_break_splits_a_paragraph_into_lines() -> None:
    lines = [line for line in lines_of("paragraph_with_hard_break_fragment.html") if line]
    assert len(lines) == 2 and lines[0].endswith("a deep") and lines[1].startswith("checkout path pushes")


# -- the reader, on hand-written HTML (UNVERIFIED) ----------------------------------------------------------------


def test_a_plain_paragraph_with_hard_breaks_gives_its_lines() -> None:
    assert handoff.report_lines(REPORT_P) == [*HEADER, ""]
    assert handoff.report_lines(para("a") + "\n" + para("b")) == ["a", "", "b", ""]
    assert handoff.report_lines("<p>ROLE: reviewer\nHEAD: x</p>") == ["ROLE: reviewer", "HEAD: x", ""]  # a bare newline


def test_character_references_are_decoded() -> None:
    assert handoff.report_lines("<p>HEAD: &lt;short sha&gt; &amp; more</p>") == ["HEAD: <short sha> & more", ""]


def test_plain_inline_elements_inside_a_paragraph_are_read() -> None:
    html = '<p dir="auto"><strong>ROLE:</strong> <a href="/x">reviewer</a> <em>MODEL</em></p>'
    assert handoff.report_lines(html) == ["ROLE: reviewer MODEL", ""]


@pytest.mark.parametrize("wrapper", ["code", "span", "tt", "kbd", "custom-x", "sup"])
def test_text_inside_any_other_inline_element_is_dropped(wrapper: str) -> None:
    html = f"<p>ROLE: <{wrapper}>reviewer</{wrapper}></p>"
    assert handoff.report_lines(html) == ["ROLE:", ""]


@pytest.mark.parametrize(
    "wrapper",
    ["pre", "blockquote", "details", "summary", "li", "ul", "ol", "table", "div", "section", "h2", "script", "style",
     "template", "custom-x", "td", "figure", "dd", "noscript"],
)  # fmt: skip
def test_a_paragraph_inside_any_other_element_is_not_read(wrapper: str) -> None:
    assert handoff.report_lines(f"<{wrapper}>{REPORT_P}</{wrapper}>") == []
    assert handoff.report_lines(f"<{wrapper}>ROLE: reviewer<br>\nHEAD: {A}</{wrapper}>") == []


def test_text_directly_in_a_container_or_at_the_top_level_is_not_read() -> None:
    assert handoff.report_lines(f"ROLE: reviewer\nHEAD: {A}") == []
    assert handoff.report_lines(f"<pre><code>ROLE: reviewer\nHEAD: {A}\n</code></pre>") == []
    assert handoff.report_lines('<div class="highlight"><pre><span>ROLE: reviewer</span></pre></div>') == []


def test_a_hidden_element_is_not_read() -> None:
    assert handoff.report_lines("<p hidden>ROLE: reviewer</p>") == []
    assert handoff.report_lines("<p>ROLE: <span hidden>reviewer</span> x</p>") == ["ROLE:  x", ""]
    assert handoff.report_lines("<p>ROLE: <a hidden>reviewer</a> x</p>") == ["ROLE:  x", ""]


def test_an_html_comment_is_ignored_and_hides_its_markup() -> None:
    assert handoff.report_lines(f"<!-- {REPORT_P} -->") == []
    assert handoff.report_lines("<p>a<!-- ROLE: reviewer -->b</p>") == ["ab", ""]


def test_a_paragraph_after_a_closed_container_is_read() -> None:
    assert handoff.report_lines(f"<pre><code>x</code></pre>\n{REPORT_P}") == [*HEADER, ""]


@pytest.mark.parametrize(
    "html", ["<p>ROLE: x", "<p>x</div>", "<div><p>x</p>", "<p><b>x</p></b>", "</p>", "<p>x</p></p>"]
)
def test_html_that_is_not_well_formed_is_unreadable(html: str) -> None:
    with pytest.raises(handoff.UnreadableHtml):
        handoff.report_lines(html)


def test_html_over_the_size_cap_is_unreadable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(handoff, "MAX_HTML", 100)
    assert handoff.report_lines("<p>" + "a" * 93 + "</p>") == ["a" * 93, ""]  # exactly 100 characters
    with pytest.raises(handoff.UnreadableHtml, match="too large"):
        handoff.report_lines("<p>" + "a" * 94 + "</p>")


def test_html_nested_too_deeply_is_unreadable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(handoff, "MAX_DEPTH", 5)
    assert handoff.report_lines("<div>" * 5 + "</div>" * 5) == []
    with pytest.raises(handoff.UnreadableHtml, match="deeply"):
        handoff.report_lines("<div>" * 6 + "</div>" * 6)


def test_the_shipped_html_limits() -> None:
    assert (handoff.MAX_HTML, handoff.MAX_DEPTH) == (200_000, 50)


# -- the check, end to end ---------------------------------------------------------------------------------------------


def test_a_report_in_a_plain_paragraph_counts(fake: FakeGitHub) -> None:
    assert run(fake, [comment("", html=REPORT_P)])[0] == 0


def test_the_report_is_read_from_the_html_not_from_the_raw_body(fake: FakeGitHub) -> None:
    assert run(fake, [comment(report(A), html="<p>nothing to see</p>")])[0] == 2
    assert run(fake, [comment("nothing to see", html=REPORT_P)])[0] == 0


@pytest.mark.parametrize(
    "body",
    [
        "    ROLE: reviewer   MODEL: m\n    HEAD: " + A + "   BASE: 1234567\n",  # indented code
        "\tROLE: reviewer   MODEL: m\n\tHEAD: " + A + "   BASE: 1234567\n",
        "<pre>\nROLE: reviewer   MODEL: m\nHEAD: " + A + "   BASE: 1234567\n</pre>\n",  # a pre HTML block
        "````\n```\n" + report(A) + "```\n````\n",  # an inner fence shorter than the opener
        "````\n" + report(A) + "```\n",  # closed by too short a fence: still code, never closed
        "~~~\n" + report(A) + "~~~\n",
        "```\n" + report(A) + "```\n",
        "> " + "\n> ".join(report(A).splitlines()) + "\n",
        "- ROLE: reviewer   MODEL: m\n- HEAD: " + A + "   BASE: 1234567\n",
        "1. ROLE: reviewer   MODEL: m\n2. HEAD: " + A + "   BASE: 1234567\n",
    ],
)
def test_a_report_a_reader_sees_as_code_a_quotation_or_a_list_is_not_a_report(fake: FakeGitHub, body: str) -> None:
    code, out, _ = run(fake, [comment(body)])
    assert code == 2 and "no review report" in out


@pytest.mark.parametrize(
    "html",
    [
        f"<details><summary>s</summary>{REPORT_P}</details>",
        f"<blockquote>\n{REPORT_P}\n</blockquote>",
        f'<ul dir="auto"><li>ROLE: reviewer<br>\nHEAD: {A}</li></ul>',
        '<div class="snippet-clipboard-content notranslate"><div class="highlight">'
        f"<pre>ROLE: reviewer\nHEAD: {A}</pre></div></div>",
        f"<table><tr><td>{REPORT_P}</td></tr></table>",
        f"<script>{REPORT_P}</script>",
        f"<style>{REPORT_P}</style>",
        f"<template>{REPORT_P}</template>",
        f"<p hidden>ROLE: reviewer<br>\nHEAD: {A}</p>",
        f"<custom-x>{REPORT_P}</custom-x>",
        f"<!-- {REPORT_P} -->",
    ],
)
def test_a_report_inside_an_unreadable_wrapper_is_not_a_report(fake: FakeGitHub, html: str) -> None:
    code, out, _ = run(fake, [comment("", html=html)])
    assert code == 2 and "no review report" in out


def test_quoting_an_old_report_does_not_replace_the_newest(fake: FakeGitHub) -> None:
    quote = comment("> " + "\n> ".join(report(B).splitlines()), "2026-10-21T10:00:00Z")
    assert run(fake, [comment(report(A), EARLY), quote], head=A)[0] == 0


def test_a_report_after_a_code_block_in_the_same_comment_counts(fake: FakeGitHub) -> None:
    assert run(fake, [comment("```\ncode\n```\n\n" + report(A))])[0] == 0


def test_a_header_split_over_two_paragraphs_is_not_a_header(fake: FakeGitHub) -> None:
    html = para(HEADER[0]) + "\n" + para(HEADER[1])
    assert run(fake, [comment("", html=html)])[0] == 2


def test_an_unreadable_trusted_comment_that_mentions_a_role_is_unknown(fake: FakeGitHub) -> None:
    code, out, _ = run(fake, [comment(report(A), EARLY), comment("", html="<p>ROLE: reviewer")])
    assert code == 2 and "cannot be read" in out and "FRESH" not in out


def test_an_unreadable_comment_with_no_role_in_it_is_ignored(fake: FakeGitHub) -> None:
    assert run(fake, [comment(report(A), EARLY), comment("", html="<p>just text")])[0] == 0


def test_an_unreadable_comment_by_an_untrusted_author_or_a_minimized_one_is_ignored(fake: FakeGitHub) -> None:
    bad = "<p>ROLE: reviewer"
    assert run(fake, [comment(report(A), EARLY), comment("", html=bad, assoc="NONE")])[0] == 0
    assert run(fake, [comment(report(A), EARLY), comment("", html=bad, minimized=True)])[0] == 0


def test_a_comment_over_the_html_cap_that_mentions_a_role_is_unknown(
    fake: FakeGitHub, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(handoff, "MAX_HTML", 200)
    big = "<p>ROLE: " + "x" * 300 + "</p>"
    code, out, _ = run(fake, [comment(report(A), EARLY), comment("", html=big)])
    assert code == 2 and "FRESH" not in out
    assert run(fake, [comment(report(A), EARLY), comment("", html="<p>" + "x" * 300 + "</p>")])[0] == 0


@pytest.mark.parametrize("value", [None, 5, ["x"], {"a": 1}])
def test_a_missing_or_mistyped_body_html_is_unknown(fake: FakeGitHub, value: Any) -> None:
    code, out, _ = run(fake, [comment(report(A)), {**comment("x"), "bodyHTML": value}])
    assert code == 2 and "FRESH" not in out
    node = comment("x")
    del node["bodyHTML"]
    assert run(fake, [comment(report(A)), node])[0] == 2


def test_nothing_from_the_html_reaches_the_output(fake: FakeGitHub) -> None:
    html = para(*HEADER, "<script>alert(1)</script>", "::error::boom")
    code, out, _ = run(fake, [comment("", html=html)], head=B)
    assert code == 1 and "boom" not in out and "script" not in out and "<" not in out
