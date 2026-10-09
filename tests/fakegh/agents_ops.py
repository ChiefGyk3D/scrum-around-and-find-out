# SPDX-License-Identifier: MIT
"""The board read agents-status makes."""

from __future__ import annotations

from fakegh.core import JSON, FakeGitHub, GqlError, handler
from fakegh.reads import _value, content_json


@handler("AgentItems")
def agent_items(fake: FakeGitHub, v: JSON) -> JSON:
    project = fake.projects.get(str(v["id"]))
    if project is None:
        raise GqlError("NOT_FOUND", "no such project", {"node": None})
    nodes: list[JSON] = []
    for item in project.items:
        content = fake.content(item.content_id) if item.content_id else None
        nodes.append(
            {
                "status": _value(project, item, str(v["statusField"])),
                "agent": _value(project, item, str(v["agentField"])),
                "content": {**content_json(content, with_repo=True), "url": f"https://example.invalid/{content.number}"}
                if content
                else {"__typename": "DraftIssue"},
            }
        )
    return {"node": {"items": fake.connection(nodes, v)}}
