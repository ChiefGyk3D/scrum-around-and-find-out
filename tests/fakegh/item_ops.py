# SPDX-License-Identifier: MIT
"""Item writes: add (idempotent), set a select or date by item node id, clear."""

from __future__ import annotations

from fakegh.core import JSON, FakeGitHub, FItem, FProject, GqlError, handler
from fakegh.reads import _value


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


@handler("ItemLookup")
def item_lookup(fake: FakeGitHub, v: JSON) -> JSON:
    rows: list[JSON] = []
    for project in fake.projects.values():
        for item in project.items:
            if item.content_id != v["id"] or item.id in fake.vanished or item.content_id in fake.vanished:
                continue
            row: JSON = {
                "id": item.id,
                "project": {"id": project.id},
                "status": _value(project, item, str(v["statusField"])),
                "area": _value(project, item, str(v["areaField"])),
            }
            if v.get("withDone"):
                row["done"] = _value(project, item, str(v["doneField"]))
            rows.append(row)
    return {"node": {"projectItems": fake.connection(rows, v)}}


@handler("ItemValue")
def item_value(fake: FakeGitHub, v: JSON) -> JSON:
    for project in fake.projects.values():
        for item in project.items:
            if item.id == v["id"] and item.id not in fake.vanished:
                return {"node": {"value": _value(project, item, str(v["name"]))}}
    return {"node": None}


@handler("ContentExists")
def content_exists(fake: FakeGitHub, v: JSON) -> JSON:
    content = fake.content(str(v["id"]))
    return {"node": {"id": content.id} if content and content.id not in fake.vanished else None}


@handler("BatchItems")
def batch_items(fake: FakeGitHub, v: JSON) -> JSON:
    return {"nodes": [item_lookup(fake, {**v, "id": content_id})["node"] for content_id in v["ids"]]}
