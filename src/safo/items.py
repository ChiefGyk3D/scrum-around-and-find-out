# SPDX-License-Identifier: MIT
"""Issues, pull requests and board items: the read side shared by audit, reconcile and sync."""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from safo.errors import MalformedDataError, NotFoundError
from safo.graphql import JSON, Client, check_connection
from safo.live import LiveBoard
from safo.schema import Board, Repository
from safo.values import iso_day, whole_number

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


ISSUE_KEYS = ("id", "number", "state")


def content_from_node(node: JSON, repo: str, typename: str) -> Content:
    try:
        return _content_from_node(node, repo, typename)
    except MalformedDataError:
        raise
    except (KeyError, TypeError, AttributeError, ValueError):
        raise MalformedDataError(f"an {typename} of {repo} from GitHub is not shaped as expected") from None


STATES = {"OPEN": "open", "CLOSED": "closed", "MERGED": "merged"}


def _closed_at(value: object, what: str) -> str | None:
    """GitHub's closedAt: null, or a timestamp whose first ten characters are a real day."""
    if value is None:
        return None
    if isinstance(value, str) and len(value) >= 10 and value[10:11] in ("", "T"):
        iso_day(value[:10], what)
        return value
    raise MalformedDataError(f"{what}: expected a timestamp, got {type(value).__name__}")


def _content_from_node(node: JSON, repo: str, typename: str) -> Content:
    kind = "pr" if typename == "PullRequest" else "issue"
    raw_state = STATES.get(node["state"]) if isinstance(node["state"], str) else None
    if raw_state is None:
        raise MalformedDataError(f"{typename} state of {repo}: expected OPEN, CLOSED or MERGED")
    state = "merged" if node.get("merged") is True else raw_state
    labels = tuple(str(label["name"]) for label in (node.get("labels") or {}).get("nodes") or [] if label)
    return Content(
        str(node["id"]),
        kind,
        state,
        bool(node.get("isDraft")),
        _closed_at(node.get("closedAt"), f"a {typename} closedAt of {repo}"),
        whole_number(node["number"], f"a {typename} number of {repo}"),
        repo,
        str(node.get("title", "")),
        labels,
    )


def _value(node: JSON, key: str, what: str) -> JSON:
    """A `fieldValueByName` answer: null, or an object."""
    raw = node.get(key)
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise MalformedDataError(f"{what}: the {key} value is {type(raw).__name__}, not an object")
    return raw


def _option(node: JSON, key: str, what: str) -> str | None:
    name = _value(node, key, what).get("name")
    if name is not None and not isinstance(name, str):
        raise MalformedDataError(f"{what}: the {key} name is {type(name).__name__}, not text")
    return name


def _done(node: JSON, what: str) -> str | None:
    day = _value(node, "done", what).get("date")
    if day is None:
        return None
    iso_day(day, f"{what}: the Done date")
    return str(day)


def _state(node: JSON, content: Content | None, typename: str | None, what: str) -> ItemState:
    return ItemState(
        str(node["id"]),
        content,
        _option(node, "status", what),
        _done(node, what),
        _option(node, "area", what),
        typename,
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
    for node in client.nodes(Q_ITEMS, variables, ("node", "items"), ("id",)):
        raw = node.get("content") or {}
        if not isinstance(raw, dict):
            raise MalformedDataError("a board item's content from GitHub is not an object")
        typename = raw.get("__typename")
        content = None
        if typename in ("Issue", "PullRequest"):
            try:
                repo_name = str(raw["repository"]["nameWithOwner"])
            except (KeyError, TypeError):
                raise MalformedDataError("a board item's content has no repository from GitHub") from None
            content = content_from_node(raw, repo_name, typename)
        items.append(_state(node, content, typename, "a board item"))
    return items


def list_repo_work(client: Client, repo: Repository, *, closed_since: dt.date | None = None) -> Iterator[Content]:
    """Open issues and pull requests of one repository, plus closed ones since a date when asked.

    Raises NotFoundError when the repository does not exist or the token's installation does not cover it.
    """
    variables = {"owner": repo.owner, "name": repo.name}
    full = repo.full_name
    for node in client.nodes(Q_OPEN_ISSUES, variables, ("repository", "issues"), ISSUE_KEYS):
        yield content_from_node(node, full, "Issue")
    for node in client.nodes(Q_OPEN_PULLS, variables, ("repository", "pullRequests"), ISSUE_KEYS):
        yield content_from_node(node, full, "PullRequest")
    if closed_since is None:
        return
    for doc, key, typename in ((Q_CLOSED_ISSUES, "issues", "Issue"), (Q_CLOSED_PULLS, "pullRequests", "PullRequest")):
        for node in client.nodes(doc, variables, ("repository", key), ISSUE_KEYS):
            content = content_from_node(node, full, typename)
            if content.closed_day and content.closed_day >= closed_since.isoformat():
                yield content


def collect_work(client: Client, board: Board, today: dt.date) -> tuple[dict[str, list[Content]], list[str]]:
    """Every listed repository's work, keyed by lower-case owner/name, and the names it could not read.

    A repository the token's installation does not cover answers NOT_FOUND; it is reported, never skipped silently.
    """
    days = board.rules.add_closed_days
    try:
        since = today - dt.timedelta(days=days) if days else None
    except OverflowError:
        since = dt.date.min  # a window longer than the calendar: every closed item counts
    work: dict[str, list[Content]] = {}
    unreachable: list[str] = []
    for repo in board.repositories:
        try:
            work[repo.full_name.lower()] = list(list_repo_work(client, repo, closed_since=since))
        except NotFoundError:
            unreachable.append(repo.full_name)
    return work, unreachable


_ITEMS_FRAGMENT = """fragment Items on ProjectV2ItemConnection {
  pageInfo { hasNextPage endCursor }
  nodes {
    id
    project { id }
    area: fieldValueByName(name: $areaField) { ... on ProjectV2ItemFieldSingleSelectValue { name } }
    status: fieldValueByName(name: $statusField) { ... on ProjectV2ItemFieldSingleSelectValue { name } }
    done: fieldValueByName(name: $doneField) @include(if: $withDone) { ... on ProjectV2ItemFieldDateValue { date } }
  }
}"""

Q_ITEM_LOOKUP = (
    """query ItemLookup(
  $id: ID!, $statusField: String!, $doneField: String!, $withDone: Boolean!, $areaField: String!, $endCursor: String
) {
  node(id: $id) {
    ... on Issue { projectItems(first: 50, after: $endCursor) { ...Items } }
    ... on PullRequest { projectItems(first: 50, after: $endCursor) { ...Items } }
  }
}
"""
    + _ITEMS_FRAGMENT
)

Q_BATCH_ITEMS = (
    """query BatchItems(
  $ids: [ID!]!, $statusField: String!, $doneField: String!, $withDone: Boolean!, $areaField: String!,
  $endCursor: String
) {
  nodes(ids: $ids) {
    ... on Issue { projectItems(first: 50, after: $endCursor) { ...Items } }
    ... on PullRequest { projectItems(first: 50, after: $endCursor) { ...Items } }
  }
}
"""
    + _ITEMS_FRAGMENT
)


Q_ITEM_VALUE = """query ItemValue($id: ID!, $name: String!) {
  node(id: $id) { ... on ProjectV2Item {
    value: fieldValueByName(name: $name) { ... on ProjectV2ItemFieldSingleSelectValue { name } }
  } }
}"""

Q_CONTENT_EXISTS = """query ContentExists($id: ID!) { node(id: $id) { id } }"""


def _lookup_variables(board: Board) -> dict[str, Any]:
    rules = board.rules
    return {
        "statusField": rules.status_field,
        "doneField": rules.done_date_field or "-",
        "withDone": bool(rules.done_date_field),
        "areaField": rules.area_field,
    }


def _row_project_id(row: JSON) -> str:
    project = row["project"]
    if not isinstance(project, dict) or not isinstance(project.get("id"), str):
        raise MalformedDataError("a project item from GitHub has no project id")
    return str(project["id"])


def read_defaults(client: Client, board: Board, item_id: str) -> dict[str, str | None]:
    """The current option of each `new_item_defaults` field on one item."""
    values: dict[str, str | None] = {}
    for name, _ in board.rules.new_item_defaults:
        raw = client.execute(Q_ITEM_VALUE, {"id": item_id, "name": name}).get("node")
        if raw is None:
            raise NotFoundError("cannot read item values")
        if not isinstance(raw, dict):
            raise MalformedDataError("an item's field value from GitHub is not an object")
        values[name] = _option(raw, "value", "an item's field value")
    return values


def find_item(client: Client, board: Board, live: LiveBoard, content_id: str) -> ItemState | None:
    """The card for one issue or pull request on this board, read through the content (never a lagging listing)."""
    variables = {"id": content_id, **_lookup_variables(board)}
    for node in client.nodes(Q_ITEM_LOOKUP, variables, ("node", "projectItems"), ("id", "project")):
        if _row_project_id(node) == live.id:
            state = _state(node, None, None, "a project item")
            state.values = read_defaults(client, board, state.id)
            return state
    return None


def discover_items(client: Client, board: Board, live: LiveBoard, ids: list[str]) -> dict[str, ItemState]:
    """Batch the identities of issues and pull requests not seen in the listing.

    A content that is gone answers null and is simply absent from the result. A connection that is cut
    (hasNextPage) is continued one content at a time. Any answer not shaped as asked is MalformedDataError.
    """
    found: dict[str, ItemState] = {}
    for offset in range(0, len(ids), 50):
        batch = ids[offset : offset + 50]
        data = client.execute(Q_BATCH_ITEMS, {"ids": batch, **_lookup_variables(board)})
        nodes = data.get("nodes")
        if not isinstance(nodes, list) or len(nodes) != len(batch):
            raise MalformedDataError("BatchItems: the answer does not match the ids asked for")
        for content_id, node in zip(batch, nodes, strict=True):
            if node is None:
                continue
            if not isinstance(node, dict):
                raise MalformedDataError("BatchItems: an answer is not an object")
            if "projectItems" not in node:
                continue  # an id that is neither an issue nor a pull request has no cards
            connection = check_connection("BatchItems", node["projectItems"], ("id", "project"))
            if connection["pageInfo"]["hasNextPage"]:
                item = find_item(client, board, live, content_id)
                if item is not None:
                    found[content_id] = item
                continue
            for row in connection["nodes"]:
                if _row_project_id(row) == live.id:
                    found[content_id] = _state(row, None, None, "a project item")
                    break
    return found


def content_exists(client: Client, content_id: str) -> bool:
    return bool(client.execute(Q_CONTENT_EXISTS, {"id": content_id}).get("node"))
