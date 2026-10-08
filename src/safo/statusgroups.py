# SPDX-License-Identifier: MIT
"""Group a board's cards for a status update. Code groups and counts; a model never does.

The rule this module exists to keep: the grouping and every number in a status update are computed here, from the
board's own fields, and a language model (when one is used at all) writes only the one-line headline over a structure
that is already correct. A local model that miscounted would otherwise post a wrong number under the maintainer's name.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from safo.schema import Board

SECTION_LIMIT = 12
TITLE_LIMIT = 80
ZERO_WIDTH_SPACE = chr(0x200B)  # after an @, it stops GitHub treating the title as a mention
HEADLINE_LIMIT = 160
# Control characters, line and paragraph separators, zero-width and bidirectional marks: none belong in a title.
_UNSAFE = re.compile("[\\x00-\\x1f\\x7f-\\x9f\\u200b-\\u200f\\u2028-\\u202e\\u2060-\\u2069\\ufeff]")


@dataclass(frozen=True)
class Row:
    """One card as the board read returned it."""

    repo: str  # owner/name, or "" for a draft card
    number: int
    title: str
    status: str
    agent: str
    when: dt.date | None  # closed or merged date; for a draft card, the day it was last updated

    @property
    def ref(self) -> str:
        return f"{self.repo}#{self.number}" if self.repo else "draft"


@dataclass(frozen=True)
class Groups:
    since: dt.date
    done: tuple[Row, ...]
    progress: tuple[Row, ...]
    waiting: tuple[Row, ...]
    upcoming: tuple[Row, ...]

    def counts(self) -> dict[str, int]:
        return {
            "done": len(self.done),
            "progress": len(self.progress),
            "waiting": len(self.waiting),
            "next": len(self.upcoming),
        }


def group_rows(rows: Iterable[Row], board: Board, since: dt.date, human_agent: str = "You") -> Groups:
    """One group per card, first match wins: Done since the date, waiting on the maintainer, in progress, next.

    Done is the board's closed and merged statuses with a date on or after `since`. Waiting is the statuses in
    `agents.waiting`, plus a working card whose Agent is `human_agent` (the maintainer holds it). In progress is the
    first of `agents.working`; any other working status is next. Everything else (Backlog) is left out.
    """
    done_statuses = {board.rules.status.closed, board.rules.status.merged}
    waiting_statuses = set(board.agents.waiting)
    working = board.agents.working
    in_progress, upcoming_statuses = set(working[:1]), set(working[1:])
    done: list[Row] = []
    progress: list[Row] = []
    waiting: list[Row] = []
    upcoming: list[Row] = []
    for row in sorted(rows, key=lambda r: (r.repo, r.number, r.title)):
        if row.status in done_statuses:
            if row.when is not None and row.when >= since:
                done.append(row)
        elif row.status in waiting_statuses or (human_agent and row.agent == human_agent and row.status in working):
            waiting.append(row)
        elif row.status in in_progress:
            progress.append(row)
        elif row.status in upcoming_statuses:
            upcoming.append(row)
    return Groups(since, tuple(done), tuple(progress), tuple(waiting), tuple(upcoming))


def template_headline(groups: Groups) -> str:
    """The headline when no model writes one: the four counts, in words."""
    c = groups.counts()
    return (
        f"{c['done']} done since {groups.since.isoformat()}, {c['progress']} in progress, "
        f"{c['waiting']} waiting on the maintainer, {c['next']} next."
    )


PROSE_CLAUSES = ("A steady week.", "A quiet week.", "Work continues.")


def headline_acceptable(text: str, groups: Groups) -> bool:
    """Only an exact, fixed prose clause is permitted; no model-supplied counts or claims."""
    del groups  # the clauses carry no number, so nothing here depends on the counts
    return text in PROSE_CLAUSES


def plain(text: str) -> str:
    """Text from GitHub made safe for a Markdown list line: one line, no control characters, no mention."""
    one_line = " ".join(_UNSAFE.sub(" ", text).split())
    return one_line


def _line(row: Row) -> str:
    title = plain(row.title)[:TITLE_LIMIT]
    title = re.sub(r"@(?=\w)", f"@{ZERO_WIDTH_SPACE}", title)  # a title cannot ping anyone from a status update
    agent = re.sub(r"@(?=\w)", f"@{ZERO_WIDTH_SPACE}", plain(row.agent)[:TITLE_LIMIT])
    suffix = f" ({agent})" if agent and agent != "unassigned" else ""
    return f"- {row.ref} {title}{suffix}"


def render_body(headline: str, groups: Groups, limit: int = SECTION_LIMIT, notes: Sequence[str] = ()) -> str:
    """Headline, then one section per group: the count in the heading, up to `limit` cards, the rest counted.

    `notes` are sentences the code wrote about what the update could not cover; they close the body.
    """
    base = template_headline(groups)
    clause = headline.removeprefix(base + " ")
    lines = [base + (" " + clause if headline_acceptable(clause, groups) else ""), ""]
    for heading, rows in (
        (f"Done since {groups.since.isoformat()}", groups.done),
        ("In progress", groups.progress),
        ("Waiting on the maintainer", groups.waiting),
        ("Next", groups.upcoming),
    ):
        lines.append(f"**{heading}** ({len(rows)})")
        lines += [_line(r) for r in rows[:limit]]
        if len(rows) > limit:
            lines.append(f"- ...and {len(rows) - limit} more")
        lines.append("")
    lines += [f"Note: {note}" for note in notes]
    return "\n".join(lines).rstrip("\n") + "\n"
