# SPDX-License-Identifier: MIT
"""Read operations: project meta, fields, views, board items and a repository's issues and pull requests."""

from __future__ import annotations

from fakegh.core import JSON, FakeGitHub, FContent, FField, FItem, FProject, GqlError, handler


def project_for(fake: FakeGitHub, owner_type: str, v: JSON) -> FProject | None:
    return fake.project_by_number(owner_type, str(v["login"]), int(v["number"]))


def _owner_read(fake: FakeGitHub, owner_type: str, v: JSON, pick: str) -> JSON:
    root = "organization" if owner_type == "organization" else "user"
    if (owner_type, str(v["login"])) not in fake.owners:
        raise GqlError(
            "NOT_FOUND", f"Could not resolve to an {root.title()} with the login of '{v['login']}'.", {root: None}
        )
    project = project_for(fake, owner_type, v)
    if project is None:
        return {root: {"projectV2": None}}
    if pick == "meta":
        return {
            root: {
                "projectV2": {
                    "id": project.id,
                    "title": project.title,
                    "number": project.number,
                    "items": {"totalCount": len(project.items)},
                }
            }
        }
    if pick == "fields":
        return {root: {"projectV2": {"fields": fake.connection([_field_json(f) for f in project.fields], v)}}}
    views = [{"id": x.id, "name": x.name, "layout": x.layout, "filter": x.filter} for x in project.views]
    return {root: {"projectV2": {"views": fake.connection(views, v)}}}


def _field_json(f: FField) -> JSON:
    out: JSON = {
        "__typename": "ProjectV2SingleSelectField" if f.options else "ProjectV2Field",
        "id": f.id,
        "name": f.name,
        "dataType": f.data_type,
    }
    if f.data_type == "SINGLE_SELECT":
        out["options"] = [
            {"id": o.id, "name": o.name, "color": o.color, "description": o.description} for o in f.options
        ]
    if f.data_type == "ITERATION":
        out["configuration"] = {"duration": f.duration, "iterations": f.iterations, "completedIterations": []}
    return out


@handler("ProjectMetaOrg")
def meta_org(fake: FakeGitHub, v: JSON) -> JSON:
    return _owner_read(fake, "organization", v, "meta")


@handler("ProjectMetaUser")
def meta_user(fake: FakeGitHub, v: JSON) -> JSON:
    return _owner_read(fake, "user", v, "meta")


@handler("ProjectFieldsOrg")
def fields_org(fake: FakeGitHub, v: JSON) -> JSON:
    return _owner_read(fake, "organization", v, "fields")


@handler("ProjectFieldsUser")
def fields_user(fake: FakeGitHub, v: JSON) -> JSON:
    return _owner_read(fake, "user", v, "fields")


@handler("ProjectViewsOrg")
def views_org(fake: FakeGitHub, v: JSON) -> JSON:
    return _owner_read(fake, "organization", v, "views")


@handler("ProjectViewsUser")
def views_user(fake: FakeGitHub, v: JSON) -> JSON:
    return _owner_read(fake, "user", v, "views")


def _value(project: FProject, item: FItem, field_name: str) -> JSON | None:
    f = next((x for x in project.fields if x.name == field_name), None)
    if f is None or f.id not in item.values:
        return None
    raw = item.values[f.id]
    if f.data_type == "DATE":
        return {"date": raw}
    return {"name": next((o.name for o in f.options if o.id == raw), str(raw))}


def labels_json(c: FContent) -> JSON:
    """The first page of 20 labels, with the total and whether more follow, as GitHub sends them."""
    return {
        "totalCount": len(c.labels),
        "pageInfo": {"hasNextPage": len(c.labels) > 20, "endCursor": "20"},
        "nodes": [{"name": n} for n in c.labels[:20]],
    }


def content_json(c: FContent, *, with_repo: bool = True) -> JSON:
    out: JSON = {
        "__typename": c.kind,
        "id": c.id,
        "number": c.number,
        "title": c.title,
        "state": c.state if c.kind == "Issue" else ("MERGED" if c.state == "MERGED" else c.state),
        "closedAt": c.closed_at,
        "labels": labels_json(c),
        "repository": {"nameWithOwner": c.repo},
    }
    if c.kind == "PullRequest":
        out["isDraft"] = c.draft
        out["merged"] = c.state == "MERGED"
    return out


def defaults_json(project: FProject, item: FItem, v: JSON) -> JSON:
    """The aliased reads of `new_item_defaults`: d0, d1, ... for the variables default0, default1, ..."""
    out: JSON = {}
    i = 0
    while f"default{i}" in v:
        out[f"d{i}"] = _value(project, item, str(v[f"default{i}"]))
        i += 1
    return out


@handler("ProjectItems")
def project_items(fake: FakeGitHub, v: JSON) -> JSON:
    project = fake.projects.get(str(v["id"]))
    if project is None:
        raise GqlError("NOT_FOUND", f"Could not resolve to a node with the global id of '{v['id']}'.", {"node": None})
    first_page = not v.get("endCursor")
    visible: list[FItem] = []
    for item in project.items:
        if item.hidden_for > 0:
            if first_page:
                item.hidden_for -= 1
            continue
        visible.append(item)
    nodes: list[JSON] = []
    for item in visible:
        content = fake.content(item.content_id) if item.content_id else None
        node: JSON = {
            "id": item.id,
            "status": _value(project, item, str(v["statusField"])),
            "area": _value(project, item, str(v["areaField"])),
            "content": (
                None if item.unreadable else content_json(content) if content else {"__typename": "DraftIssue"}
            ),
            **defaults_json(project, item, v),
        }
        if v.get("withDone"):
            node["done"] = _value(project, item, str(v["doneField"]))
        nodes.append(node)
    return {"node": {"items": fake.connection(nodes, v)}}


def _repo_read(fake: FakeGitHub, v: JSON, key: str, kinds: tuple[str, ...], states: tuple[str, ...]) -> JSON:
    repo = fake.repos.get(f"{v['owner']}/{v['name']}".lower())
    if repo is None or not repo.installed:
        raise GqlError(
            "NOT_FOUND",
            f"Could not resolve to a Repository with the name '{v['owner']}/{v['name']}'.",
            {"repository": None},
        )
    rows = [content_json(c, with_repo=False) for c in repo.contents if c.kind in kinds and c.state in states]
    return {"repository": {key: fake.connection(rows, v)}}


@handler("RepoOpenIssues")
def open_issues(fake: FakeGitHub, v: JSON) -> JSON:
    return _repo_read(fake, v, "issues", ("Issue",), ("OPEN",))


@handler("RepoOpenPulls")
def open_pulls(fake: FakeGitHub, v: JSON) -> JSON:
    return _repo_read(fake, v, "pullRequests", ("PullRequest",), ("OPEN",))


@handler("RepoClosedIssues")
def closed_issues(fake: FakeGitHub, v: JSON) -> JSON:
    return _repo_read(fake, v, "issues", ("Issue",), ("CLOSED",))


@handler("RepoClosedPulls")
def closed_pulls(fake: FakeGitHub, v: JSON) -> JSON:
    return _repo_read(fake, v, "pullRequests", ("PullRequest",), ("CLOSED", "MERGED"))
