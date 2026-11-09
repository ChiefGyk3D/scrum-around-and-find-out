# SPDX-License-Identifier: Apache-2.0
"""Open pull requests that cannot merge as they stand: CONFLICTING (drift) and BEHIND their base (a note).

One read per listed repository (the open pull requests, `mergeable` and `mergeStateStatus`), never a listing of the
whole project, so it costs a few GraphQL points per repository. GitHub computes `mergeable` lazily: `UNKNOWN` or null
means "not computed yet", which is counted and shown but is never drift.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from safo.errors import MalformedDataError, NotFoundError
from safo.graphql import Client
from safo.items import _canonical_repo
from safo.schema import Board
from safo.values import whole_number

Q_PULL_MERGEABLE = """query RepoPullMergeable($owner: String!, $name: String!, $endCursor: String) {
  repository(owner: $owner, name: $name) {
    pullRequests(states: [OPEN], first: 100, after: $endCursor, orderBy: {field: UPDATED_AT, direction: DESC}) {
      pageInfo { hasNextPage endCursor }
      nodes { number state repository { nameWithOwner } mergeable mergeStateStatus }
    }
  }
}"""

MERGEABLE = {"MERGEABLE", "CONFLICTING", "UNKNOWN"}
STATES = {"BEHIND", "BLOCKED", "CLEAN", "DIRTY", "DRAFT", "HAS_HOOKS", "UNKNOWN", "UNSTABLE"}


@dataclass
class Mergeability:
    open: int = 0
    conflicting: list[str] = field(default_factory=list)
    behind: list[str] = field(default_factory=list)
    uncomputed: int = 0
    unreadable: list[str] = field(default_factory=list)  # repositories that could not be read (named, not drift)
    malformed: list[str] = field(default_factory=list)

    def count_line(self) -> str:
        return (
            f"mergeability: {self.open} open pull requests, {len(self.conflicting)} conflicting, "
            f"{len(self.behind)} behind, {self.uncomputed} not yet computed"
        )


def _enum(node: dict[str, object], key: str, allowed: set[str], what: str) -> str | None:
    value = node.get(key)
    if value is None:
        return None  # GitHub sends null while it computes
    if not isinstance(value, str) or value not in allowed:
        raise MalformedDataError(f"{what}: {key} is {value!r}, not one of {sorted(allowed)}")
    return value


def read_mergeability(client: Client, board: Board) -> Mergeability:
    out = Mergeability()
    for repo in board.repositories:
        variables = {"owner": repo.owner, "name": repo.name}
        try:
            for node in client.nodes(Q_PULL_MERGEABLE, variables, ("repository", "pullRequests"), ("number", "state")):
                name = _canonical_repo(node, f"a pull request of {repo.full_name}")
                label = f"{name}#{whole_number(node.get('number'), f'a pull request number of {repo.full_name}')}"
                mergeable = _enum(node, "mergeable", MERGEABLE, f"pull request {label}")
                state = _enum(node, "mergeStateStatus", STATES, f"pull request {label}")
                out.open += 1
                if mergeable == "CONFLICTING":
                    out.conflicting.append(label)
                elif mergeable in (None, "UNKNOWN"):
                    out.uncomputed += 1
                elif state == "BEHIND":
                    out.behind.append(label)
        except NotFoundError:
            out.unreadable.append(repo.full_name)  # `collect_work` already reports it as UNKNOWN
        except MalformedDataError as err:
            out.malformed.append(f"{repo.full_name}: {err}")
    return out
