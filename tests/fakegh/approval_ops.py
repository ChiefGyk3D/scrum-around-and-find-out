# SPDX-License-Identifier: Apache-2.0
"""The batched, aliased issue read of `safo.approvals`: `r0`, `r1`, ... for the variables `o0 n0 i0`, `o1 n1 i1`."""

from __future__ import annotations

import copy

from fakegh.core import JSON, FakeGitHub, GqlError, handler

OK_ACTOR: JSON = {"__typename": "User", "login": "approver-one", "databaseId": 1001}


def closed_event(**over: object) -> JSON:
    """The newest CLOSED_EVENT as GitHub sends it: a manual close, completed, by a `User`."""
    event: JSON = {
        "createdAt": "2026-11-05T12:00:00Z",
        "stateReason": "COMPLETED",
        "closer": None,
        "duplicateOf": None,
        "actor": dict(OK_ACTOR),
    }
    event.update(over)
    return event


def issue_node(repo: str = "acme/gates", number: int = 21, **over: object) -> JSON:
    """A CLOSED issue approved by a `User`, whose text names acme/app#55. Keys in `over` replace the defaults."""
    node: JSON = {
        "__typename": "Issue",
        "number": number,
        "state": "CLOSED",
        "title": f"Change: add acme/app#55 to Build ({number})",
        "body": "Approved.\n\nEntry: acme/app#55\n",
        "createdAt": "2026-11-03T09:00:00Z",
        "lastEditedAt": None,
        "authorAssociation": "OWNER",
        "repository": {"nameWithOwner": repo},
        "timelineItems": {"totalCount": 1, "nodes": [closed_event()]},
        "changes": {"totalCount": 0, "nodes": []},  # the newest rename or reopen
    }
    node.update(over)
    return node


def put(fake: FakeGitHub, node: JSON, repo: str | None = None, number: int | None = None) -> JSON:
    """Serve `node` at repo#number (default: where it says it is)."""
    name = repo or str(node["repository"]["nameWithOwner"])
    fake.approval_issues[(name.lower(), int(number if number is not None else node["number"]))] = node
    return node


@handler("ApprovalIssues")
def approval_issues(fake: FakeGitHub, v: JSON) -> JSON:
    data: JSON = {}
    missing: list[list[str]] = []
    i = 0
    while f"o{i}" in v:
        node = fake.approval_issues.get((f"{v[f'o{i}']}/{v[f'n{i}']}".lower(), int(v[f"i{i}"])))
        data[f"r{i}"] = {"issueOrPullRequest": copy.deepcopy(node)}
        if node is None:
            missing.append([f"r{i}", "issueOrPullRequest"])
        i += 1
    if missing:
        raise GqlError("NOT_FOUND", "Could not resolve to an issue or pull request.", data, missing)
    return data
