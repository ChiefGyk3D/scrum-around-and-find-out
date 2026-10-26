# SPDX-License-Identifier: Apache-2.0
"""No hidden work, read side: pull requests that link no issue, and cards that lack Kind, Epic, Effort or Area.

Field names come from board.yaml (`rules.tracking`, `rules.area_field`). A field the board does not define is "not
configured": its check is skipped and says so, never silently passed. Only presence is read for Kind, Epic and
Effort, so the field may be any type. Everything here only reads; `audit` reports the findings and `reconcile`
lists them as needing a human, because no rule can pick an Epic or an Effort.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from safo.errors import MalformedDataError, NotFoundError
from safo.graphql import JSON, Client
from safo.items import ItemState, _canonical_repo
from safo.live import LiveBoard
from safo.rules import area_for
from safo.schema import Board, Repository
from safo.values import whole_number

Q_PULL_LINKS = """query RepoPullRefs($owner: String!, $name: String!, $endCursor: String) {
  repository(owner: $owner, name: $name) {
    pullRequests(states: [OPEN, MERGED], first: 100, after: $endCursor, orderBy: {field: UPDATED_AT, direction: DESC}) {
      pageInfo { hasNextPage endCursor }
      nodes {
        id number state merged closedAt body repository { nameWithOwner }
        closingIssuesReferences(first: 1) { totalCount }
      }
    }
  }
}"""

Q_PULL_LINK = """query PullRefs($id: ID!) {
  node(id: $id) {
    ... on PullRequest {
      id number body repository { nameWithOwner }
      closingIssuesReferences(first: 1) { totalCount }
    }
  }
}"""

# `Refs #7`, `Closes acme/widgets#7`, `Fixes: #7` ... any of these names an issue the pull request serves
LINK = re.compile(
    r"\b(?:refs?|references?|closes?|closed|fix(?:es|ed)?|resolves?|resolved)\b:?[ \t]+(?:([\w.-]+/[\w.-]+))?#([0-9]+)",
    re.IGNORECASE,
)


def tracked_names(board: Board) -> list[tuple[str, str]]:
    """(label, field name) of each Kind/Epic/Effort field board.yaml defines; the rest are not configured."""
    t = board.rules.tracking
    pairs = (("Kind", t.kind_field), ("Epic", t.epic_field), ("Effort", t.effort_field))
    return [(label, name) for label, name in pairs if name and board.field_named(name) is not None]


def not_configured(board: Board) -> list[str]:
    """One note per check the board cannot run, so a skipped check is stated and never reads as a pass."""
    t = board.rules.tracking
    notes = []
    for label, name in (("Kind", t.kind_field), ("Epic", t.epic_field), ("Effort", t.effort_field)):
        if not name or board.field_named(name) is None:
            notes.append(f"{label} check not configured: board.yaml defines no {label} field (rules.tracking)")
    if not board.rules.done_date_field:
        notes.append("Done-on check not configured: rules.done_date_field is empty")
    if board.field_named(board.rules.area_field) is None:
        notes.append(f"Area check not configured: board.yaml defines no {board.rules.area_field!r} field")
    if not board.rules.threat_model.label:
        notes.append("Threat-model check not configured: rules.threat_model.label is empty")
    return notes


def tracked_query(count: int) -> str:
    declarations = "".join(f", $t{i}: String!" for i in range(count))
    selections = "".join(f"\n      t{i}: fieldValueByName(name: $t{i}) {{ __typename }}" for i in range(count))
    return f"""query TrackedItems($id: ID!, $endCursor: String{declarations}) {{
  node(id: $id) {{ ... on ProjectV2 {{ items(first: 100, after: $endCursor) {{
    pageInfo {{ hasNextPage endCursor }}
    nodes {{
      id{selections}
    }}
  }} }} }}
}}"""


def read_tracked(client: Client, board: Board, live: LiveBoard) -> dict[str, set[str]]:
    """Card id -> the labels (Kind, Epic, Effort) that hold a value. Empty when the board configures none."""
    names = tracked_names(board)
    if not names:
        return {}
    variables: JSON = {"id": live.id, **{f"t{i}": name for i, (_, name) in enumerate(names)}}
    held: dict[str, set[str]] = {}
    for node in client.nodes(tracked_query(len(names)), variables, ("node", "items"), ("id",)):
        item_id = node.get("id")
        if not isinstance(item_id, str) or not item_id:
            raise MalformedDataError("TrackedItems: a card has no id")
        present: set[str] = set()
        for i, (label, _) in enumerate(names):
            key = f"t{i}"
            if key not in node:
                raise MalformedDataError(f"TrackedItems: the {label} value was not sent")
            if node[key] is not None:
                if not isinstance(node[key], dict):
                    raise MalformedDataError(f"TrackedItems: the {label} value is not an object")
                present.add(label)
        held[item_id] = present
    return held


@dataclass(frozen=True)
class Pull:
    repo: str
    number: int
    linked: bool


def links_issue(body: str, repo: str, number: int) -> bool:
    """True when the text names an issue other than the pull request itself."""
    for found in LINK.finditer(body):
        target_repo, target = found.group(1), int(found.group(2))
        if target == number and (target_repo is None or target_repo.lower() == repo.lower()):
            continue  # a pull request that refers to itself serves no issue
        return True
    return False


def _pull(node: JSON, repo: str, since: dt.date | None) -> Pull | None:
    state, merged = node.get("state"), node.get("merged")
    if state not in ("OPEN", "MERGED", "CLOSED") or not isinstance(merged, bool):
        raise MalformedDataError(f"a pull request of {repo}: state or merged is missing or malformed")
    # The boolean `merged` decides, not the spelling of `state`: a merged pull request counts either way.
    if state == "CLOSED" and not merged:
        return None  # closed without merging: no work shipped
    if merged or state == "MERGED":
        closed = node.get("closedAt")
        if since is None or not isinstance(closed, str) or closed[:10] < since.isoformat():
            return None  # merged before the window: history, not a finding
    number = whole_number(node.get("number"), f"a pull request number of {repo}")
    body = node.get("body")
    if body is not None and not isinstance(body, str):
        raise MalformedDataError(f"pull request {repo}#{number}: the body is not text")
    refs = node.get("closingIssuesReferences")
    count = refs.get("totalCount") if isinstance(refs, dict) else None
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        raise MalformedDataError(f"pull request {repo}#{number}: closingIssuesReferences has no count")
    return Pull(repo, number, count > 0 or links_issue(body or "", repo, number))


def unlinked_pulls(client: Client, board: Board, today: dt.date) -> tuple[list[str], list[str]]:
    """(open or recently merged pull requests that link no issue, repositories that could not be read).

    Merged ones count within `add_closed_days` of today; with 0, only open pull requests are checked.
    """
    days = board.rules.add_closed_days
    try:
        since = today - dt.timedelta(days=days) if days else None
    except OverflowError:
        since = dt.date.min
    exempt = {r.lower() for r in board.rules.tracking.exempt_repos}
    found: list[str] = []
    unreachable: list[str] = []
    for repo in board.repositories:
        if repo.full_name.lower() in exempt:
            continue
        variables = {"owner": repo.owner, "name": repo.name}
        try:
            for node in client.nodes(Q_PULL_LINKS, variables, ("repository", "pullRequests"), ("number", "state")):
                pull = _pull(node, _canonical_repo(node, f"a pull request of {repo.full_name}"), since)
                if pull is not None and not pull.linked:
                    found.append(f"{pull.repo}#{pull.number}")
        except NotFoundError:
            unreachable.append(repo.full_name)
    return found, unreachable


def pull_is_linked(client: Client, node_id: str) -> bool | None:
    """Whether one pull request links an issue; None when the node is not a pull request."""
    data = client.execute(Q_PULL_LINK, {"id": node_id})
    node = data.get("node")
    if not isinstance(node, dict) or "number" not in node:
        return None
    repo = _canonical_repo(node, "a pull request")
    pull = _pull({**node, "state": "OPEN", "merged": False}, repo, None)
    return None if pull is None else pull.linked


def card_findings(
    board: Board, items: Sequence[ItemState], held: Mapping[str, set[str]], repos: Mapping[str, Repository]
) -> list[str]:
    """Cards that miss Kind, Epic, Effort or Area, each named. Status and Done-on gaps are in the reconcile plan."""
    names = tracked_names(board)
    area_configured = board.field_named(board.rules.area_field) is not None
    out: list[str] = []
    for item in items:
        c = item.content
        if c is not None and c.repo.lower() not in repos:
            continue  # work of a repository board.yaml does not list is none of our business
        label = f"{c.repo}#{c.number}" if c else f"card {item.id}"
        have = held.get(item.id, set())
        out += [f"MISSING {field_name} on {label}" for kind, field_name in names if kind not in have]
        # A draft has no title rule or repository to ask; the plan already fills Area where a rule applies.
        if c is not None and area_configured and item.area is None and area_for(repos[c.repo.lower()], c) is None:
            out.append(f"MISSING Area on {label}: no area rule or default applies, set it by hand")
    return out
