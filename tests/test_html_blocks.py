# SPDX-License-Identifier: Apache-2.0
"""The shared Markdown block scanner: which lines are inside a fence or an HTML block (CommonMark types 1 to 7)."""

from __future__ import annotations

from typing import Any

import pytest

from safo.evidence import lesson_sections
from safo.profile import block_constructs


def marks(text: str) -> list[str]:
    return block_constructs(text.split("\n"))


@pytest.mark.parametrize(
    "text",
    [
        "<span>\n### Hidden evidence\n\n### Seen",
        '<custom-tag attr="x" other>\n### Hidden evidence\n\n### Seen',
        "</span>\n### Hidden evidence\n\n### Seen",
        "<br/>\n### Hidden evidence\n\n### Seen",
        "  <a href='x'>  \n### Hidden evidence\n\n### Seen",
    ],
)
def test_a_type_7_block_hides_headings_until_the_blank_line(text: str) -> None:
    assert set(lesson_sections(text)) == {"seen"}


@pytest.mark.parametrize(
    "text",
    [
        "text\n<span>\n### Real heading\n",
        "text\n</span>\n### Real heading\n",
        "line one\nline two\n<custom-tag>\n### Real heading\n",
    ],
)
def test_type_7_does_not_interrupt_a_paragraph(text: str) -> None:
    assert set(lesson_sections(text)) == {"real-heading"}


def test_after_a_heading_or_a_blank_line_a_type_7_line_starts_a_block() -> None:
    assert set(lesson_sections("### One\n<span>\n### Hidden\n\n### Two\n")) == {"one", "two"}
    assert set(lesson_sections("text\n\n<span>\n### Hidden\n")) == set()


@pytest.mark.parametrize(
    "line",
    [
        "<span> trailing text",  # text after the tag: not a type 7 start
        "<span",
        "<span attr=>",
        "<1span>",
        '<span a="unclosed>',
        "< span>",
        "<span></span> x",
    ],
)
def test_not_a_complete_tag_alone_on_its_line_is_ordinary_text(line: str) -> None:
    assert marks(f"{line}\n### Heading") == ["", ""]


def test_a_type_7_block_ends_at_the_blank_line_and_the_blank_is_not_a_heading() -> None:
    assert marks("<span>\nx\n\ny") == ["", "html", "html", ""]


def test_type_6_and_type_7_in_a_template_reject_a_placeholder_inside() -> None:
    assert marks("<span>\n{{task}}") == ["", "html"]


def test_a_hostile_attribute_line_is_scanned_in_bounded_time() -> None:
    import time

    line = "<a " + "b " * 20000 + "c=" + "\n### H"
    start = time.monotonic()
    block_constructs(line.split("\n"))
    assert time.monotonic() - start < 10


def test_markdown_it_agrees_when_it_is_installed() -> None:
    md = pytest.importorskip("markdown_it")
    parser = md.MarkdownIt("commonmark")
    cases = [
        "<span>\n### Hidden\n\n### Seen\n",
        "text\n<span>\n### Real\n",
        "</span>\n### Hidden\n\nafter\n",
        '<custom-tag a="b">\n### Hidden\n',
        "<div>\n### Hidden\n\n### Seen\n",
        "<!--\n### Hidden\n-->\n### Seen\n",
        "### One\n<span>\n### Hidden\n",
        "<span> x\n### Seen\n",
    ]
    for text in cases:
        heads = {t.content for t in _heading_tokens(parser, text)}
        got = {c for c in (lesson_sections(text)[k].heading for k in lesson_sections(text))}
        assert got == heads, text


def _heading_tokens(parser: Any, text: str) -> list[Any]:
    tokens = parser.parse(text)
    return [tokens[i + 1] for i, t in enumerate(tokens) if t.type == "heading_open"]


def test_a_one_line_html_block_is_not_paragraph_text_for_the_next_line() -> None:
    assert set(lesson_sections("<!-- note -->\n<span>\n### Hidden\n\n### Seen\n")) == {"seen"}
