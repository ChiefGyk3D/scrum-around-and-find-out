# SPDX-License-Identifier: MIT
"""Operations sync and status use. (ItemLookup and ContentExists are in item_ops.)"""

from __future__ import annotations

from fakegh.core import JSON, FakeGitHub, GqlError, handler
from fakegh.reads import _value


@handler("StatusUpdate")
def status_update(fake: FakeGitHub, v: JSON) -> JSON:
    if str(v["input"]["projectId"]) not in fake.projects:
        raise GqlError("NOT_FOUND", "Could not resolve to a ProjectV2")
    return {"createProjectV2StatusUpdate": {"statusUpdate": {"id": fake.new_id("PVTSU")}}}


@handler("StatusItems")
def status_items(fake: FakeGitHub, v: JSON) -> JSON:
    project = fake.projects.get(str(v["id"]))
    if project is None:
        raise GqlError("NOT_FOUND", "no such project", {"node": None})
    nodes: list[JSON] = []
    for item in project.items:
        content = fake.content(item.content_id) if item.content_id else None
        card: JSON | None
        if item.unreadable:
            card = None
        elif content is None:
            card = {"__typename": "DraftIssue", "title": "A draft card", "updatedAt": None}
        else:
            card = {
                "__typename": content.kind,
                "number": content.number,
                "title": content.title,
                "closedAt": content.closed_at,
                "repository": {"nameWithOwner": content.repo},
            }
            if content.kind == "PullRequest":
                card["mergedAt"] = content.closed_at if content.state == "MERGED" else None
        nodes.append(
            {
                "id": item.id,
                "status": _value(project, item, str(v["statusField"])),
                "agent": _value(project, item, str(v["agentField"])),
                "content": card,
            }
        )
    return {"node": {"items": fake.connection(nodes, v, total=len(nodes))}}
