# SPDX-License-Identifier: Apache-2.0
"""Threat model before build, read side: issues carrying the AI-surface label that name no usable threat model.

An issue with the configured label (`rules.threat_model.label`) must hold a line of its own, either
`threat-model: <path or https URL>` or `threat-model: n/a - <reason>`. Only the line is read: that the file exists, is a
Threat Dragon model, and moved with the change is the job of the `threat-model.yml` workflow in git-your-ship-together.
An empty label is "not configured": the check is skipped and says so, never silently passed. Everything here only reads.
"""

from __future__ import annotations

import datetime as dt
import re

from safo.errors import MalformedDataError, NotFoundError
from safo.graphql import JSON, Client
from safo.items import _canonical_repo
from safo.schema import Board
from safo.values import whole_number

Q_THREAT_ISSUES = """query RepoThreatIssues($owner: String!, $name: String!, $label: String!, $endCursor: String) {
  repository(owner: $owner, name: $name) {
    issues(
      labels: [$label], states: [OPEN, CLOSED], first: 100, after: $endCursor,
      orderBy: {field: UPDATED_AT, direction: DESC}
    ) {
      pageInfo { hasNextPage endCursor }
      nodes { number state closedAt body repository { nameWithOwner } }
    }
  }
}"""

# The line is anchored to its own line: a sentence that mentions it, or a quote, does not count. The value is trimmed in
# code, not in the pattern: a lazy group followed by optional trailing space is quadratic on a hostile line.
LINE = re.compile(r"^[ \t]*threat-model:(.*)$", re.IGNORECASE | re.MULTILINE)
LONGEST = 300  # a path, a URL or a reason this long is not one; the cap also bounds every match below
NOT_APPLICABLE = re.compile(r"n/a[ \t]*[-\u2013\u2014][ \t]*(\S.{6,})", re.IGNORECASE)
URL = re.compile(r"https://[^\s<>\"']+")
# A repository-relative path: no leading slash, no `..` segment, and it has to look like a file or a directory.
PATH = re.compile(r"(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9_][A-Za-z0-9_./@+-]*")
PLACEHOLDERS = frozenset({"tbd", "todo", "none", "n/a", "na", "pending", "later", "wip", "path", "url"})


def judge(value: str) -> str | None:
    """None when the value after `threat-model:` is usable, else why it is not."""
    if len(value) > LONGEST:
        return f"the value is longer than {LONGEST} characters"
    if NOT_APPLICABLE.fullmatch(value):
        return None
    if value.lower().startswith("n/a"):
        return "`n/a` needs a reason after a dash, a short sentence"
    if URL.fullmatch(value) or (
        PATH.fullmatch(value) and ("/" in value or "." in value) and value.lower() not in PLACEHOLDERS
    ):
        return None
    return "name the model as a repository path or an https URL, or write `n/a - <reason>`"


def verdict(body: str) -> str | None:
    """None when the body carries a usable threat-model line; else a sentence saying what is wrong."""
    found = [value for m in LINE.finditer(body) if (value := m.group(1).strip())]
    if not found:
        return "has no `threat-model:` line"
    problems = [judge(value) for value in found]
    if any(p is None for p in problems):
        return None
    return f"its `threat-model:` line is not usable: {problems[0]}"


def unthreatened_issues(client: Client, board: Board, today: dt.date) -> tuple[list[tuple[str, str]], list[str]]:
    """((issue, what is wrong) for each labeled issue without a usable line, repositories that could not be read).

    Open issues always count; closed ones within `add_closed_days` of today, as for pull requests.
    """
    rule = board.rules.threat_model
    if not rule.label:
        return [], []
    days = board.rules.add_closed_days
    try:
        since = today - dt.timedelta(days=days) if days else None
    except OverflowError:
        since = dt.date.min
    exempt = {r.lower() for r in rule.exempt_repos}
    found: list[tuple[str, str]] = []
    unreachable: list[str] = []
    for repo in board.repositories:
        if repo.full_name.lower() in exempt:
            continue
        variables: JSON = {"owner": repo.owner, "name": repo.name, "label": rule.label}
        try:
            for node in client.nodes(Q_THREAT_ISSUES, variables, ("repository", "issues"), ("number", "state")):
                state = node.get("state")
                if state not in ("OPEN", "CLOSED"):
                    raise MalformedDataError(f"an issue of {repo.full_name}: state is missing or malformed")
                number = whole_number(node.get("number"), f"an issue number of {repo.full_name}")
                if state == "CLOSED":
                    closed = node.get("closedAt")
                    if since is None or not isinstance(closed, str) or closed[:10] < since.isoformat():
                        continue  # closed before the window: history, not a finding
                body = node.get("body")
                if body is not None and not isinstance(body, str):
                    raise MalformedDataError(f"issue {repo.full_name}#{number}: the body is not text")
                why = verdict(body or "")
                if why is not None:
                    name = _canonical_repo(node, f"an issue of {repo.full_name}")
                    found.append((f"{name}#{number}", why))
        except NotFoundError:
            unreachable.append(repo.full_name)
    return found, unreachable
