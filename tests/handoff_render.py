# SPDX-License-Identifier: Apache-2.0
"""A small stand-in for GitHub's Markdown renderer, for the handoff tests.

UNVERIFIED against GitHub's renderer: it covers only the shapes the handoff tests need (paragraphs with hard breaks,
fenced and indented code, blockquotes, list items, raw HTML blocks, HTML comments). The output shapes are copied from
the real renderings kept in tests/data/handoff_html (see SOURCES.md there). The code under test never sees Markdown.
"""

from __future__ import annotations

import html
import re

RAW_BLOCKS = ("<pre", "<details", "<div", "<table", "<script", "<style", "<template", "<p ", "<p>")
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")


def render(markdown: str) -> str:
    text = markdown.replace("\r\n", "\n")
    text = re.sub(r"<!--.*?(-->|\Z)", "", text, flags=re.DOTALL)  # GitHub drops HTML comments from the output
    lines = text.split("\n")
    out: list[str] = []
    paragraph: list[str] = []
    index = 0

    def flush() -> None:
        if paragraph:
            body = "<br>\n".join(html.escape(line.strip(), quote=False) for line in paragraph)
            out.append(f'<p dir="auto">{body}</p>')
            paragraph.clear()

    while index < len(lines):
        line = lines[index]
        opener = FENCE.match(line)
        if opener:
            flush()
            fence = opener.group(1)
            index += 1
            code: list[str] = []
            while index < len(lines):
                closing = FENCE.match(lines[index])
                if closing and closing.group(1)[0] == fence[0] and len(closing.group(1)) >= len(fence):
                    break
                code.append(lines[index])
                index += 1
            index += 1
            out.append(f'<pre class="notranslate"><code>{html.escape(chr(10).join(code), quote=False)}\n</code></pre>')
            continue
        if not line.strip():
            flush()
        elif not paragraph and line.startswith(("    ", "\t")):
            code = []
            while index < len(lines) and (lines[index].startswith(("    ", "\t")) or not lines[index].strip()):
                code.append(lines[index][1:] if lines[index].startswith("\t") else lines[index][4:])
                index += 1
            out.append(
                f'<pre class="notranslate"><code>{html.escape(chr(10).join(code).rstrip(), quote=False)}\n</code></pre>'
            )
            continue
        elif line.startswith(RAW_BLOCKS) and not paragraph:
            block = []
            while index < len(lines) and lines[index].strip():
                block.append(lines[index])
                index += 1
            out.append("\n".join(block))
            continue
        elif line.startswith(">"):
            flush()
            quoted = []
            while index < len(lines) and lines[index].startswith(">"):
                quoted.append(lines[index][1:].strip())
                index += 1
            inner = "<br>\n".join(html.escape(item, quote=False) for item in quoted)
            out.append(f'<blockquote>\n<p dir="auto">{inner}</p>\n</blockquote>')
            continue
        elif re.match(r"^(- |\* |\d+\. )", line):
            flush()
            items = []
            while index < len(lines) and re.match(r"^(- |\* |\d+\. )", lines[index]):
                items.append(re.sub(r"^(- |\* |\d+\. )", "", lines[index]))
                index += 1
            rows = "\n".join(f"<li>{html.escape(item, quote=False)}</li>" for item in items)
            out.append(f'<ul dir="auto">\n{rows}\n</ul>')
            continue
        else:
            paragraph.append(line)
        index += 1
    flush()
    return "\n".join(out)
