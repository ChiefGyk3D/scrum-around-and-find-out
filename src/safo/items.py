# SPDX-License-Identifier: MIT
"""Issues, pull requests and board items: the read side shared by audit, reconcile and sync.

Every answer is read strictly. A key that is missing, an empty object where a field value was asked for, a
count that contradicts its list, a timestamp without an offset: each is MalformedDataError, never "blank".
Only an explicit null means a field is empty.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any

from safo.errors import MalformedDataError, NotFoundError
from safo.graphql import JSON, Client, check_connection
from safo.live import LiveBoard
from safo.schema import Board, Repository
from safo.values import iso_day, utc_timestamp, whole_number

_LABELS = "labels(first: 20) { totalCount pageInfo { hasNextPage endCursor } nodes { name } }"

_CONTENT = (
    """
        content {
          __typename
          ... on Issue {
            id number title state closedAt repository { nameWithOwner } """
    + _LABELS
    + """
          }
          ... on PullRequest {
            id number title state isDraft merged closedAt
            repository { nameWithOwner } """
    + _LABELS
    + """
          }
        }"""
)

_SELECT = "{ ... on ProjectV2ItemFieldSingleSelectValue { name } }"
_DATE = "{ ... on ProjectV2ItemFieldDateValue { date } }"


def _default_declarations(count: int) -> str:
    return "".join(f", $default{i}: String!" for i in range(count))


def _default_selections(count: int) -> str:
    return "".join(f"\n      d{i}: fieldValueByName(name: $default{i}) {_SELECT}" for i in range(count))


def items_query(defaults: int) -> str:
    """The board walk, with one aliased read per `new_item_defaults` field, so no card is read twice."""
    return (
        f"""query ProjectItems(
  $id: ID!, $statusField: String!, $doneField: String!, $areaField: String!, $withDone: Boolean!,
  $endCursor: String{_default_declarations(defaults)}
) {{
  node(id: $id) {{ ... on ProjectV2 {{ items(first: 100, after: $endCursor) {{
    pageInfo {{ hasNextPage endCursor }}
    nodes {{
      id
      status: fieldValueByName(name: $statusField) {_SELECT}
      done: fieldValueByName(name: $doneField) @include(if: $withDone) {_DATE}
      area: fieldValueByName(name: $areaField) {_SELECT}{_default_selections(defaults)}"""
        + _CONTENT
        + """
    }
  } } }
}"""
    )


def _items_fragment(defaults: int) -> str:
    return f"""fragment Items on ProjectV2ItemConnection {{
  pageInfo {{ hasNextPage endCursor }}
  nodes {{
    id
    project {{ id }}
    area: fieldValueByName(name: $areaField) {_SELECT}
    status: fieldValueByName(name: $statusField) {_SELECT}
    done: fieldValueByName(name: $doneField) @include(if: $withDone) {_DATE}{_default_selections(defaults)}
  }}
}}"""


def lookup_query(defaults: int) -> str:
    return f"""query ItemLookup(
  $id: ID!, $statusField: String!, $doneField: String!, $withDone: Boolean!, $areaField: String!,
  $endCursor: String{_default_declarations(defaults)}
) {{
  node(id: $id) {{
    ... on Issue {{ projectItems(first: 50, after: $endCursor) {{ ...Items }} }}
    ... on PullRequest {{ projectItems(first: 50, after: $endCursor) {{ ...Items }} }}
  }}
}}
""" + _items_fragment(defaults)


def batch_query(defaults: int) -> str:
    return f"""query BatchItems(
  $ids: [ID!]!, $statusField: String!, $doneField: String!, $withDone: Boolean!, $areaField: String!,
  $endCursor: String{_default_declarations(defaults)}
) {{
  nodes(ids: $ids) {{
    id
    ... on Issue {{ projectItems(first: 50, after: $endCursor) {{ ...Items }} }}
    ... on PullRequest {{ projectItems(first: 50, after: $endCursor) {{ ...Items }} }}
  }}
}}
""" + _items_fragment(defaults)


Q_ITEMS = items_query(0)
Q_ITEM_LOOKUP = lookup_query(0)
Q_BATCH_ITEMS = batch_query(0)

_REPO_NODE = "id number title state closedAt repository { nameWithOwner } " + _LABELS
_PULL_NODE = "id number title state isDraft merged closedAt repository { nameWithOwner } " + _LABELS

Q_OPEN_ISSUES = (
    """query RepoOpenIssues($owner: String!, $name: String!, $endCursor: String) {
  repository(owner: $owner, name: $name) { issues(states: OPEN, first: 100, after: $endCursor) {
    pageInfo { hasNextPage endCursor }
    nodes { """
    + _REPO_NODE
    + """ }
  } }
}"""
)

Q_OPEN_PULLS = (
    """query RepoOpenPulls($owner: String!, $name: String!, $endCursor: String) {
  repository(owner: $owner, name: $name) { pullRequests(states: OPEN, first: 100, after: $endCursor) {
    pageInfo { hasNextPage endCursor }
    nodes { """
    + _PULL_NODE
    + """ }
  } }
}"""
)

Q_CLOSED_ISSUES = (
    """query RepoClosedIssues($owner: String!, $name: String!, $endCursor: String) {
  repository(owner: $owner, name: $name) {
    issues(states: CLOSED, first: 100, after: $endCursor, orderBy: {field: UPDATED_AT, direction: DESC}) {
      pageInfo { hasNextPage endCursor }
      nodes { """
    + _REPO_NODE
    + """ }
    }
  }
}"""
)

Q_CLOSED_PULLS = (
    """query RepoClosedPulls($owner: String!, $name: String!, $endCursor: String) {
  repository(owner: $owner, name: $name) {
    pullRequests(
      states: [CLOSED, MERGED], first: 100, after: $endCursor, orderBy: {field: UPDATED_AT, direction: DESC}
    ) {
      pageInfo { hasNextPage endCursor }
      nodes { """
    + _PULL_NODE
    + """ }
    }
  }
}"""
)

Q_CONTENT_LABELS = """query ContentLabels($id: ID!, $endCursor: String) {
  node(id: $id) {
    ... on Issue {
      labels(first: 100, after: $endCursor) { totalCount pageInfo { hasNextPage endCursor } nodes { name } }
    }
    ... on PullRequest {
      labels(first: 100, after: $endCursor) { totalCount pageInfo { hasNextPage endCursor } nodes { name } }
    }
  }
}"""

Q_CONTENT_EXISTS = """query ContentExists($id: ID!) { node(id: $id) { id } }"""


@dataclass(frozen=True)
class Content:
    id: str
    kind: str  # issue | pr
    state: str  # open | closed | merged
    draft: bool
    closed_at: str | None  # normalised to UTC: YYYY-MM-DDTHH:MM:SSZ
    number: int
    repo: str  # the repository GitHub says the content belongs to (canonical name)
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
    values: dict[str, str | None] = field(default_factory=dict)  # new_item_defaults fields -> current option


_REPO_NAME = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
ISSUE_KEYS = ("id", "number", "state", "repository", "labels")
STATES = {"OPEN": "open", "CLOSED": "closed", "MERGED": "merged"}


def content_from_node(node: JSON, repo: str, typename: str) -> Content:
    try:
        return _content_from_node(node, repo, typename)
    except MalformedDataError:
        raise
    except (KeyError, TypeError, AttributeError, ValueError):
        raise MalformedDataError(f"an {typename} of {repo} from GitHub is not shaped as expected") from None


def _closed_at(value: object, what: str) -> str | None:
    """GitHub's closedAt: null, or an RFC 3339 timestamp with an offset, held in UTC."""
    if value is None:
        return None
    return utc_timestamp(value, what).strftime("%Y-%m-%dT%H:%M:%SZ")


def _content_from_node(node: JSON, repo: str, typename: str) -> Content:
    kind = "pr" if typename == "PullRequest" else "issue"
    raw_state = STATES.get(node["state"]) if isinstance(node["state"], str) else None
    if raw_state is None:
        raise MalformedDataError(f"{typename} state of {repo}: expected OPEN, CLOSED or MERGED")
    merged = node.get("merged")
    if merged is not None and not isinstance(merged, bool):
        raise MalformedDataError(f"{typename} of {repo}: merged is {type(merged).__name__}, not a boolean")
    state = "merged" if merged is True else raw_state
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


def _label_page(connection: Any, what: str) -> tuple[list[str], bool, int]:
    """(names on this page, whether more follow, the total) of a labels connection, or MalformedDataError."""
    if not isinstance(connection, dict):
        raise MalformedDataError(f"{what}: the labels are not an object")
    info = connection.get("pageInfo")
    rows = connection.get("nodes")
    if not isinstance(info, dict) or not isinstance(info.get("hasNextPage"), bool) or not isinstance(rows, list):
        raise MalformedDataError(f"{what}: the labels have no page information")
    total = whole_number(connection.get("totalCount"), f"{what}: the label count")
    names: list[str] = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str):
            raise MalformedDataError(f"{what}: a label has no name")
        names.append(row["name"])
    _distinct(names, what)
    more = info["hasNextPage"]
    if total < len(names) or (not more and total != len(names)):
        raise MalformedDataError(f"{what}: the label count contradicts the labels listed")
    return names, more, total


def with_all_labels(client: Client, node: JSON, content: Content) -> Content:
    """The content with every label, paginating when the first page was not all of them.

    The Area rule matches a label anywhere in the list, so a label on page two must count.
    """
    what = f"the labels of an {content.kind} of {content.repo}"
    if "labels" not in node:
        raise MalformedDataError(f"{what}: GitHub sent no labels")
    names, more, total = _label_page(node["labels"], what)
    if not more:
        return dataclasses.replace(content, labels=tuple(names))
    names = []
    for page in client.pages(Q_CONTENT_LABELS, {"id": content.id}, ("node", "labels"), ("name",)):
        if whole_number(page.get("totalCount"), f"{what}: the label count") != total:
            raise MalformedDataError(f"{what}: the label count changes between pages")
        for row in page["nodes"]:
            if not isinstance(row.get("name"), str):
                raise MalformedDataError(f"{what}: a label has no name")
            names.append(row["name"])
    if total != len(names):
        raise MalformedDataError(f"{what}: the label count contradicts the labels listed")
    _distinct(names, what)
    return dataclasses.replace(content, labels=tuple(names))


def _distinct(names: Sequence[str], what: str) -> None:
    """A label appears once: a repeat (compared without case) means a page was replayed and another hidden."""
    if len({n.casefold() for n in names}) != len(names):
        raise MalformedDataError(f"{what}: a label is listed twice")


def _canonical_repo(node: JSON, what: str) -> str:
    repo = node.get("repository")
    name = repo.get("nameWithOwner") if isinstance(repo, dict) else None
    if not isinstance(name, str) or not _REPO_NAME.fullmatch(name) or any(p in (".", "..") for p in name.split("/")):
        raise MalformedDataError(f"{what}: GitHub names no usable repository for it")
    return name


def _field_value(node: JSON, key: str, sub: str, what: str) -> str | None:
    """A `fieldValueByName` answer: an explicit null is blank; anything else must carry `sub` as text.

    A missing key, an empty object or the wrong shape is never "blank": a blank is what reconcile fills in.
    """
    if key not in node:
        raise MalformedDataError(f"{what}: the {key} value was not sent")
    raw = node[key]
    if raw is None:
        return None
    if not isinstance(raw, dict) or not isinstance(raw.get(sub), str):
        raise MalformedDataError(f"{what}: the {key} value is not shaped as asked (an empty or foreign object)")
    return str(raw[sub])


def _state(
    node: JSON, content: Content | None, typename: str | None, what: str, board: Board, defaults: Sequence[str]
) -> ItemState:
    done: str | None = None
    if board.rules.done_date_field:
        done = _field_value(node, "done", "date", what)
        if done is not None:
            iso_day(done, f"{what}: the Done date")
    item_id = node["id"]
    if not isinstance(item_id, str) or not item_id:
        raise MalformedDataError(f"{what}: its id is not a non-empty string")
    return ItemState(
        item_id,
        content,
        _field_value(node, "status", "name", what),
        done,
        _field_value(node, "area", "name", what),
        typename,
        {name: _field_value(node, f"d{i}", "name", what) for i, name in enumerate(defaults)},
    )


def _default_names(board: Board) -> list[str]:
    return [name for name, _ in board.rules.new_item_defaults]


EXPECTED_TYPES = {"single_select", "date"}


def mismatched_fields(board: Board, live: LiveBoard) -> dict[str, str]:
    """Field name -> live type, for each field a card read would ask for as one type when the project holds another.

    A value read through the wrong type's fragment comes back as an empty object, which is indistinguishable from
    a malformed answer. Such a field is not asked for (the name `-` matches nothing, so it reads as blank):
    audit reports the type drift on its own, and reconcile refuses to write the field.
    """
    rules = board.rules
    wanted = {rules.status_field: "single_select", rules.area_field: "single_select"}
    if rules.done_date_field:
        wanted[rules.done_date_field] = "date"
    for name, _ in rules.new_item_defaults:
        wanted.setdefault(name, "single_select")
    return {
        name: live.fields[name].type
        for name, kind in wanted.items()
        if name in live.fields and live.fields[name].type != kind
    }


def _read_variables(board: Board, live: LiveBoard) -> dict[str, Any]:
    rules = board.rules
    bad = mismatched_fields(board, live)

    def name_of(field_name: str) -> str:
        return "-" if field_name in bad else field_name

    out: dict[str, Any] = {
        "statusField": name_of(rules.status_field),
        "doneField": name_of(rules.done_date_field) if rules.done_date_field else "-",
        "withDone": bool(rules.done_date_field),
        "areaField": name_of(rules.area_field),
    }
    for i, name in enumerate(_default_names(board)):
        out[f"default{i}"] = name_of(name)
    return out


def list_board_items(client: Client, board: Board, live: LiveBoard) -> list[ItemState]:
    """One walk of the board. The listing can lag behind `live.items_total` for a while after an add."""
    defaults = _default_names(board)
    variables = {"id": live.id, **_read_variables(board, live)}
    items: list[ItemState] = []
    for node in client.nodes(items_query(len(defaults)), variables, ("node", "items"), ("id",)):
        raw = node.get("content") or {}
        if not isinstance(raw, dict):
            raise MalformedDataError("a board item's content from GitHub is not an object")
        typename = raw.get("__typename")
        content = None
        if typename in ("Issue", "PullRequest"):
            content = content_from_node(raw, _canonical_repo(raw, "a board item's content"), typename)
            content = with_all_labels(client, raw, content)
        items.append(_state(node, content, typename, "a board item", board, defaults))
    return items


def list_repo_work(client: Client, repo: Repository, *, closed_since: dt.date | None = None) -> Iterator[Content]:
    """Open issues and pull requests of one repository, plus closed ones since a date when asked.

    A content carries the repository GitHub says it belongs to, which can differ from the one asked (a
    repository that was renamed or transferred); the caller compares. Raises NotFoundError when the repository
    does not exist or the token's installation does not cover it.
    """
    variables = {"owner": repo.owner, "name": repo.name}

    def parse(node: JSON, typename: str) -> Content:
        content = content_from_node(node, _canonical_repo(node, f"an {typename} of {repo.full_name}"), typename)
        return with_all_labels(client, node, content)

    for node in client.nodes(Q_OPEN_ISSUES, variables, ("repository", "issues"), ISSUE_KEYS):
        yield parse(node, "Issue")
    for node in client.nodes(Q_OPEN_PULLS, variables, ("repository", "pullRequests"), ISSUE_KEYS):
        yield parse(node, "PullRequest")
    if closed_since is None:
        return
    for doc, key, typename in ((Q_CLOSED_ISSUES, "issues", "Issue"), (Q_CLOSED_PULLS, "pullRequests", "PullRequest")):
        for node in client.nodes(doc, variables, ("repository", key), ISSUE_KEYS):
            content = parse(node, typename)
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


def _row_project_id(row: JSON) -> str:
    project = row["project"]
    if not isinstance(project, dict) or not isinstance(project.get("id"), str):
        raise MalformedDataError("a project item from GitHub has no project id")
    return str(project["id"])


def find_item(client: Client, board: Board, live: LiveBoard, content_id: str) -> ItemState | None:
    """The card for one issue or pull request on this board, read through the content (never a lagging listing)."""
    defaults = _default_names(board)
    variables = {"id": content_id, **_read_variables(board, live)}
    for node in client.nodes(lookup_query(len(defaults)), variables, ("node", "projectItems"), ("id", "project")):
        if _row_project_id(node) == live.id:
            return _state(node, None, None, "a project item", board, defaults)
    return None


def discover_items(client: Client, board: Board, live: LiveBoard, ids: list[str]) -> dict[str, ItemState]:
    """Batch the identities of issues and pull requests not seen in the listing.

    Answers are matched to the ids asked for by the `id` each carries, never by position. A requested id that
    is absent must be accounted for by a null (a deleted content); an unrequested or repeated id, a count that
    does not match, or any other shape is MalformedDataError. A connection that is cut (hasNextPage) is
    continued one content at a time.
    """
    defaults = _default_names(board)
    found: dict[str, ItemState] = {}
    for offset in range(0, len(ids), BATCH):
        batch = ids[offset : offset + BATCH]
        data = client.execute(batch_query(len(defaults)), {"ids": batch, **_read_variables(board, live)})
        nodes = data.get("nodes")
        if not isinstance(nodes, list) or len(nodes) != len(batch):
            raise MalformedDataError("BatchItems: the answer does not match the ids asked for")
        by_id: dict[str, JSON] = {}
        for node in nodes:
            if node is None:
                continue  # a deleted content answers null; the follow-up existence read decides what it means
            if not isinstance(node, dict):
                raise MalformedDataError("BatchItems: an answer is not an object")
            node_id = node.get("id")
            if not isinstance(node_id, str) or node_id not in batch or node_id in by_id:
                raise MalformedDataError("BatchItems: an answer names an id that was not asked for, or twice")
            by_id[node_id] = node
        for content_id, node in by_id.items():
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
                    found[content_id] = _state(row, None, None, "a project item", board, defaults)
                    break
    return found


BATCH = 50  # GitHub accepts at most 100 ids in `nodes(ids:)`


def content_exists(client: Client, node_id: str) -> bool:
    """Whether a node exists. Only a clean answer of exactly `node: null` says it is gone.

    A NOT_FOUND error (even beside data), an empty object or another node's id is not evidence of deletion:
    it is MalformedDataError or ApiError, and the caller cannot tell.
    """
    data = client.execute(Q_CONTENT_EXISTS, {"id": node_id})
    if data == {"node": None}:
        return False
    node = data.get("node")
    if isinstance(node, dict) and node.get("id") == node_id:
        return True
    raise MalformedDataError("ContentExists: the answer is neither the node nor a clean null")
