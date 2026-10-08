# SPDX-License-Identifier: MIT
"""Item writes: add (idempotent), set a select or date by item node id, clear."""

from __future__ import annotations

from fakegh.core import JSON, FakeGitHub, FItem, FProject, GqlError, handler
from fakegh.reads import _value, defaults_json


def _gone(node_id: object) -> GqlError:
    return GqlError("NOT_FOUND", f"Could not resolve to a node with the global id of '{node_id}'.")


@handler("AddItem")
def add_item(fake: FakeGitHub, v: JSON) -> JSON:
    project = fake.projects[str(v["projectId"])]
    content = fake.content(str(v["contentId"]))
    if content is None or str(v["contentId"]) in fake.vanished:
        raise _gone(v["contentId"])
    existing = next((i for i in project.items if i.content_id == content.id), None)
    if existing is None:
        existing = FItem(fake.new_id("PVTI"), content.id, hidden_for=fake.listing_lag)
        project.items.append(existing)
    return {"addProjectV2ItemById": {"item": {"id": existing.id}}}


def _item(fake: FakeGitHub, v: JSON) -> tuple[FProject, FItem]:
    project = fake.projects[str(v["projectId"])]
    item = next((i for i in project.items if i.id == v["itemId"]), None)
    if item is None or item.id in fake.vanished:
        raise _gone(v["itemId"])
    return project, item


@handler("SetSelect")
def set_select(fake: FakeGitHub, v: JSON) -> JSON:
    project, item = _item(fake, v)
    f = next((x for x in project.fields if x.id == v["fieldId"]), None)
    if f is None or not any(o.id == v["optionId"] for o in f.options):
        raise GqlError("UNPROCESSABLE", f"The option id {v['optionId']} is not valid for field {v['fieldId']}")
    item.values[f.id] = v["optionId"]
    return {"updateProjectV2ItemFieldValue": {"projectV2Item": {"id": item.id}}}


@handler("SetDate")
def set_date(fake: FakeGitHub, v: JSON) -> JSON:
    project, item = _item(fake, v)
    f = next((x for x in project.fields if x.id == v["fieldId"]), None)
    if f is None or f.data_type != "DATE":
        raise GqlError("UNPROCESSABLE", f"Field {v['fieldId']} is not a date field")
    item.values[f.id] = v["date"]
    return {"updateProjectV2ItemFieldValue": {"projectV2Item": {"id": item.id}}}


@handler("ClearField")
def clear_field(fake: FakeGitHub, v: JSON) -> JSON:
    _, item = _item(fake, v)
    item.values.pop(str(v["fieldId"]), None)
    return {"clearProjectV2ItemFieldValue": {"projectV2Item": {"id": item.id}}}


def _present(fake: FakeGitHub, content_id: object) -> bool:
    return fake.content(str(content_id)) is not None and str(content_id) not in fake.vanished


def _cards(fake: FakeGitHub, v: JSON, content_id: object) -> JSON | None:
    """The `projectItems` of one content, or None when the content is gone (GitHub answers a null node)."""
    if not _present(fake, content_id):
        return None
    rows: list[JSON] = []
    for project in fake.projects.values():
        for item in project.items:
            if item.content_id != content_id or item.id in fake.vanished:
                continue
            row: JSON = {
                "id": item.id,
                "project": {"id": project.id},
                "status": _value(project, item, str(v["statusField"])),
                "area": _value(project, item, str(v["areaField"])),
                **defaults_json(project, item, v),
            }
            if v.get("withDone"):
                row["done"] = _value(project, item, str(v["doneField"]))
            rows.append(row)
    return {"projectItems": fake.connection(rows, v)}


@handler("ItemLookup")
def item_lookup(fake: FakeGitHub, v: JSON) -> JSON:
    return {"node": _cards(fake, v, v["id"])}


@handler("ContentExists")
def content_exists(fake: FakeGitHub, v: JSON) -> JSON:
    node_id = str(v["id"])
    if any(i.id == node_id and i.id not in fake.vanished for p in fake.projects.values() for i in p.items):
        return {"node": {"id": node_id}}
    return {"node": {"id": node_id} if _present(fake, node_id) else None}


BATCH_LIMIT = 100  # GitHub refuses `nodes(ids:)` with more than 100 ids


@handler("BatchItems")
def batch_items(fake: FakeGitHub, v: JSON) -> JSON:
    ids = list(v["ids"])
    if len(ids) > BATCH_LIMIT:
        raise GqlError("MAX_NODE_LIMIT_EXCEEDED", f"Requested {len(ids)} nodes; the limit is {BATCH_LIMIT}.")
    nodes: list[JSON | None] = []
    for content_id in ids:
        cards = _cards(fake, v, content_id)
        nodes.append(None if cards is None else {"id": content_id, **cards})
    return {"nodes": nodes}


@handler("ContentLabels")
def content_labels(fake: FakeGitHub, v: JSON) -> JSON:
    content = fake.content(str(v["id"]))
    if content is None:
        return {"node": None}
    rows = [{"name": n} for n in content.labels]
    return {"node": {"labels": fake.connection(rows, v, total=len(rows))}}
