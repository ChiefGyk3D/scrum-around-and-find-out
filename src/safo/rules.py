# SPDX-License-Identifier: MIT
"""The decisions: which status an item should hold, which area it belongs to.

Pure functions over the board.yaml rules; no GitHub access. Ported from GYST's
project_sync.py (statuses by event, drafts, reopening) and the maintainer's
board_reconcile.py (Area by repository and by title), with the names taken from
board.yaml instead of being written into the code.
"""

from __future__ import annotations

import datetime as dt

from safo.items import Content
from safo.schema import Repository, Rules


def done_names(rules: Rules) -> set[str]:
    return {rules.status.closed, rules.status.merged}


def done_status(rules: Rules, content: Content) -> str:
    return rules.status.merged if content.state == "merged" else rules.status.closed


def open_status(rules: Rules, content: Content) -> str:
    """The status of an item that has just opened (or is open and has none)."""
    s = rules.status
    if content.kind == "issue":
        return s.opened
    if content.draft:
        return s.draft_pr or s.opened
    return s.opened_pr or s.opened


def target_status(rules: Rules, content: Content, action: str, current: str | None) -> str | None:
    """The status this content should move to, or None to leave it where it is.

    `action` is the event's action ("opened", "reopened", "closed", ...) or "reconcile".
    An open item that already holds a status keeps it, except a reopened issue leaving Done and a
    pull request whose draft state just changed.
    """
    s = rules.status
    if content.state in ("closed", "merged"):
        wanted = done_status(rules, content)
        return None if current == wanted else wanted
    if content.kind == "issue":
        if current is None:
            return s.opened
        if current in done_names(rules) and action == "reopened":
            return s.reopened
        return None
    wanted = open_status(rules, content)
    if action in ("opened", "ready_for_review", "converted_to_draft", "reopened"):
        return wanted if current != wanted else None
    return wanted if current is None else None


def area_for(repo: Repository, content: Content) -> str | None:
    """First matching area rule (case-insensitive substring of the title or a label), else the repository default."""
    text = f"{content.title} {' '.join(content.labels)}".lower()
    for rule in repo.area_rules:
        if rule.match.lower() in text:
            return rule.area
    return repo.default_area


def done_day(content: Content, today: dt.date) -> str:
    return content.closed_day or today.isoformat()
