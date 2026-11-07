# SPDX-License-Identifier: Apache-2.0
"""report-not-found (#353): the SHAPE of a report that says it could not find something.

A report that says "not found", "unverified", "blocked", "403", "could not read", "not read" or "no statement found"
must show how it looked: at least two distinct `query:` or `search:` lines, or a named fallback source (a `fallback:`,
`archive:`, `second source:` or `alternate source:` line with a value). Otherwise it is flagged.

This checks the shape of the text, never whether the claim is true or whether the queries were run: a report can list
two queries it never ran. Warn only; nothing here blocks anything. The core is a pure function over text.
"""

from __future__ import annotations

import re

MIN_QUERIES = 2
TRIGGER = re.compile(
    r"\b(?:not found|could not find|unverified|blocked|403|could not read|not read|no statement found)\b",
    re.IGNORECASE,
)
QUERY_LINE = re.compile(r"^[ \t>*-]*(?:query|search):[ \t]*(\S.*)$", re.IGNORECASE | re.MULTILINE)
FALLBACK_LINE = re.compile(
    r"^[ \t>*-]*(?:fallback|archive|second source|alternate source|other source):[ \t]*(\S.{3,})$",
    re.IGNORECASE | re.MULTILINE,
)


def queries(text: str) -> list[str]:
    """The distinct listed queries, compared without case and with white space collapsed."""
    seen: dict[str, None] = {}
    for found in QUERY_LINE.findall(text):
        seen.setdefault(" ".join(found.lower().split()), None)
    return list(seen)


def check(text: str) -> list[str]:
    """Warnings for one report text; empty when the report is fine or says nothing was missing."""
    hits = sorted({m.group(0).lower() for m in TRIGGER.finditer(text)})
    if not hits:
        return []
    if len(queries(text)) >= MIN_QUERIES or FALLBACK_LINE.search(text):
        return []
    return [
        "report-not-found: the report says "
        + ", ".join(f'"{h}"' for h in hits)
        + " but lists fewer than two distinct search queries (`query:` or `search:` lines) and names no fallback "
        "source (`fallback:`, `archive:` or `second source:`). Try another route (a web search, an archive copy, a "
        "second source) before reporting it. This checks the report's shape, not whether it is true."
    ]
