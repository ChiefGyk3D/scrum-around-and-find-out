# SPDX-License-Identifier: MIT
"""Issues, pull requests and board items: the read side shared by audit, reconcile and sync."""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator
from dataclasses import dataclass, field

from safo.errors import ApiError, NotFoundError
from safo.graphql import JSON, Client
from safo.live import LiveBoard
from safo.schema import Board, Repository

_CONTENT = """
        content {
          __typename
          ... on Issue {
            id number title state closedAt repository { nameWithOwner } labels(first: 20) { nodes { name } }
          }
          ... on PullRequest {
            id number title state isDraft merged closedAt
            repository { nameWithOwner } labels(first: 20) { nodes { name } }
          }
        }"""

Q_ITEMS = (
    """query ProjectItems(
  $id: ID!, $statusField: String!, $doneField: String!, $areaField: String!, $withDone: Boolean!, $endCursor: String
) {
  node(id: $id) { ... on ProjectV2 { items(first: 100, after: $endCursor) {
    pageInfo { hasNextPage endCursor }
    nodes {
      id
      status: fieldValueByName(name: $statusField) { ... on ProjectV2ItemFieldSingleSelectValue { name } }
      done: fieldValueByName(name: $doneField) @include(if: $withDone) { ... on ProjectV2ItemFieldDateValue { date } }
      area: fieldValueByName(name: $areaField) { ... on ProjectV2ItemFieldSingleSelectValue { name } }"""
    + _CONTENT
    + """
    }
  } } }
}"""
)

Q_OPEN_ISSUES = """query RepoOpenIssues($owner: String!, $name: String!, $endCursor: String) {
  repository(owner: $owner, name: $name) { issues(states: OPEN, first: 100, after: $endCursor) {
    pageInfo { hasNextPage endCursor }
    nodes { id number title state closedAt labels(first: 20) { nodes { name } } }
  } }
}"""

Q_OPEN_PULLS = """query RepoOpenPulls($owner: String!, $name: String!, $endCursor: String) {
  repository(owner: $owner, name: $name) { pullRequests(states: OPEN, first: 100, after: $endCursor) {
    pageInfo { hasNextPage endCursor }
    nodes { id number title state isDraft merged closedAt labels(first: 20) { nodes { name } } }
  } }
}"""

Q_CLOSED_ISSUES = """query RepoClosedIssues($owner: String!, $name: String!, $endCursor: String) {
  repository(owner: $owner, name: $name) {
    issues(states: CLOSED, first: 100, after: $endCursor, orderBy: {field: UPDATED_AT, direction: DESC}) {
      pageInfo { hasNextPage endCursor }
      nodes { id number title state closedAt labels(first: 20) { nodes { name } } }
    }
  }
}"""

Q_CLOSED_PULLS = """query RepoClosedPulls($owner: String!, $name: String!, $endCursor: String) {
  repository(owner: $owner, name: $name) {
    pullRequests(
      states: [CLOSED, MERGED], first: 100, after: $endCursor, orderBy: {field: UPDATED_AT, direction: DESC}
    ) {
      pageInfo { hasNextPage endCursor }
      nodes { id number title state isDraft merged closedAt labels(first: 20) { nodes { name } } }
    }
  }
}"""


@dataclass(frozen=True)
class Content:
    id: str
    kind: str  # issue | pr
    state: str  # open | closed | merged
    draft: bool
    closed_at: str | None
    number: int
    repo: str
    title: str = ""
    labels: tuple[str, ...] = ()

    @property
    def is_open(self) -> bool:
        return self.state == "open"

    @property
    def closed_day(self) -> str | None:
        return self.closed_at[:10] if self.closed_at else None


@dataclass
class ItemState:
    id: str
    content: Content | None  # None for a draft issue, or content the token cannot read
    status: str | None
    done: str | None
    area: str | None
    content_type: str | None = None
    values: dict[str, str | None] = field(default_factory=dict)


def content_from_node(node: JSON, repo: str, typename: str) -> Content:
    kind = "pr" if typename == "PullRequest" else "issue"
    state = "merged" if node.get("merged") else str(node["state"]).lower()
    labels = tuple(str(label["name"]) for label in (node.get("labels") or {}).get("nodes") or [] if label)
    return Content(
        str(node["id"]),
        kind,
        state,
        bool(node.get("isDraft")),
        node.get("closedAt"),
        int(node["number"]),
        repo,
        str(node.get("title", "")),
        labels,
    )


def list_board_items(client: Client, board: Board, live: LiveBoard) -> list[ItemState]:
    """One walk of the board. The listing can lag behind `live.items_total` for a while after an add."""
    rules = board.rules
    variables = {
        "id": live.id,
        "statusField": rules.status_field,
        "doneField": rules.done_date_field or "-",
        "areaField": rules.area_field,
        "withDone": bool(rules.done_date_field),
    }
    items: list[ItemState] = []
    for node in client.nodes(Q_ITEMS, variables, ("node", "items")):
        raw = node.get("content") or {}
        typename = raw.get("__typename")
        content = None
        if typename in ("Issue", "PullRequest"):
            content = content_from_node(raw, str(raw["repository"]["nameWithOwner"]), typename)
        items.append(
            ItemState(
                str(node["id"]),
                content,
                (node.get("status") or {}).get("name"),
                (node.get("done") or {}).get("date"),
                (node.get("area") or {}).get("name"),
                typename,
            )
        )
    return items


def list_repo_work(client: Client, repo: Repository, *, closed_since: dt.date | None = None) -> Iterator[Content]:
    """Open issues and pull requests of one repository, plus closed ones since a date when asked.

    Raises NotFoundError when the repository does not exist or the token's installation does not cover it.
    """
    variables = {"owner": repo.owner, "name": repo.name}
    full = repo.full_name
    for node in client.nodes(Q_OPEN_ISSUES, variables, ("repository", "issues")):
        yield content_from_node(node, full, "Issue")
    for node in client.nodes(Q_OPEN_PULLS, variables, ("repository", "pullRequests")):
        yield content_from_node(node, full, "PullRequest")
    if closed_since is None:
        return
    for doc, key, typename in ((Q_CLOSED_ISSUES, "issues", "Issue"), (Q_CLOSED_PULLS, "pullRequests", "PullRequest")):
        for node in client.nodes(doc, variables, ("repository", key)):
            content = content_from_node(node, full, typename)
            if content.closed_day and content.closed_day >= closed_since.isoformat():
                yield content


def collect_work(client: Client, board: Board, today: dt.date) -> tuple[dict[str, list[Content]], list[str]]:
    """Every listed repository's work, keyed by lower-case owner/name, and the names it could not read.

    A repository the token's installation does not cover answers NOT_FOUND; it is reported, never skipped silently.
    """
    days = board.rules.add_closed_days
    since = today - dt.timedelta(days=days) if days else None
    work: dict[str, list[Content]] = {}
    unreachable: list[str] = []
    for repo in board.repositories:
        try:
            work[repo.full_name.lower()] = list(list_repo_work(client, repo, closed_since=since))
        except NotFoundError:
            unreachable.append(repo.full_name)
    return work, unreachable


Q_ITEM_LOOKUP = """query ItemLookup(
  $id: ID!, $statusField: String!, $doneField: String!, $withDone: Boolean!, $areaField: String!, $endCursor: String
) {
  node(id: $id) {
    ... on Issue { projectItems(first: 50, after: $endCursor) { ...Items } }
    ... on PullRequest { projectItems(first: 50, after: $endCursor) { ...Items } }
  }
}
fragment Items on ProjectV2ItemConnection {
  pageInfo { hasNextPage endCursor }
  nodes {
    id
    project { id }
    area: fieldValueByName(name: $areaField) { ... on ProjectV2ItemFieldSingleSelectValue { name } }
    status: fieldValueByName(name: $statusField) { ... on ProjectV2ItemFieldSingleSelectValue { name } }
    done: fieldValueByName(name: $doneField) @include(if: $withDone) { ... on ProjectV2ItemFieldDateValue { date } }
  }
}"""


Q_ITEM_VALUE = """query ItemValue($id: ID!, $name: String!) {
  node(id: $id) { ... on ProjectV2Item {
    value: fieldValueByName(name: $name) { ... on ProjectV2ItemFieldSingleSelectValue { name } }
  } }
}"""

Q_CONTENT_EXISTS = """query ContentExists($id: ID!) { node(id: $id) { id } }"""


def find_item(client: Client, board: Board, live: LiveBoard, content_id: str) -> ItemState | None:
    rules = board.rules
    variables = {
        "id": content_id,
        "statusField": rules.status_field,
        "doneField": rules.done_date_field or "-",
        "withDone": bool(rules.done_date_field),
        "areaField": rules.area_field,
    }
    for node in client.nodes(Q_ITEM_LOOKUP, variables, ("node", "projectItems")):
        if node["project"]["id"] == live.id:
            values = {}
            for name, _ in rules.new_item_defaults:
                raw = client.execute(Q_ITEM_VALUE, {"id": node["id"], "name": name}).get("node")
                if raw is None:
                    raise NotFoundError("cannot read item values")
                values[name] = (raw.get("value") or {}).get("name")
            return ItemState(
                str(node["id"]),
                None,
                (node.get("status") or {}).get("name"),
                (node.get("done") or {}).get("date"),
                (node.get("area") or {}).get("name"),
                values=values,
            )
    return None


def content_exists(client: Client, content_id: str) -> bool:
    return bool(client.execute(Q_CONTENT_EXISTS, {"id": content_id}).get("node"))
