# SPDX-License-Identifier: MIT
"""Write operations bootstrap uses, with the API's real restrictions."""

from __future__ import annotations

from fakegh.core import JSON, FakeGitHub, FField, FOption, GqlError, handler

DATA_TYPES = {"TEXT", "SINGLE_SELECT", "DATE", "NUMBER", "ITERATION"}
LAYOUTS = {"BOARD_LAYOUT", "TABLE_LAYOUT", "ROADMAP_LAYOUT"}


@handler("OwnerOrg")
def owner_org(fake: FakeGitHub, v: JSON) -> JSON:
    return _owner(fake, "organization", v)


@handler("OwnerUser")
def owner_user(fake: FakeGitHub, v: JSON) -> JSON:
    return _owner(fake, "user", v)


def _owner(fake: FakeGitHub, owner_type: str, v: JSON) -> JSON:
    root = "organization" if owner_type == "organization" else "user"
    node = fake.owners.get((owner_type, str(v["login"])))
    if node is None:
        raise GqlError("NOT_FOUND", f"Could not resolve to a User with the login of '{v['login']}'.", {root: None})
    return {root: {"id": node, "login": v["login"]}}


@handler("CreateProject")
def create_project(fake: FakeGitHub, v: JSON) -> JSON:
    owner_id = str(v["input"]["ownerId"])
    (owner_type, login) = next(k for k, node in fake.owners.items() if node == owner_id)
    number = 1 + max((p.number for p in fake.projects.values() if p.owner == login), default=0)
    project = fake.add_project(owner_type, login, number, str(v["input"]["title"]))
    return {"createProjectV2": {"projectV2": {"id": project.id, "number": number}}}


@handler("CreateField")
def create_field(fake: FakeGitHub, v: JSON) -> JSON:
    spec: JSON = v["input"]
    project = fake.projects[str(spec["projectId"])]
    if spec.get("dataType") not in DATA_TYPES:
        raise GqlError("INVALID", f"Expected {spec.get('dataType')!r} to be one of {sorted(DATA_TYPES)}")
    if any(f.name == spec["name"] for f in project.fields):
        raise GqlError("UNPROCESSABLE", "Name has already been taken")
    made = FField(fake.new_id("PVTF"), str(spec["name"]), str(spec["dataType"]))
    for o in spec.get("singleSelectOptions") or []:
        if "color" not in o or "description" not in o:
            raise GqlError(
                "INVALID", "Expected value to not be null: color and description are required on every option"
            )
        made.options.append(FOption(fake.new_id("OPT"), str(o["name"]), str(o["color"]), str(o["description"])))
    config = spec.get("iterationConfiguration")
    if config:
        made.duration = int(config["duration"])
        made.iterations = [
            {"id": fake.new_id("ITER"), "title": i["title"], "startDate": i["startDate"], "duration": i["duration"]}
            for i in config["iterations"]
        ]
    project.fields.append(made)
    return {"createProjectV2Field": {"projectV2Field": {"id": made.id, "name": made.name}}}


@handler("CreateView")
def create_view(fake: FakeGitHub, v: JSON) -> JSON:
    spec: JSON = v["input"]
    if "filter" in spec:
        raise GqlError("argumentNotAccepted", "InputObject 'CreateProjectV2ViewInput' doesn't accept argument 'filter'")
    if spec.get("layout") not in LAYOUTS:
        raise GqlError("INVALID", f"Expected {spec.get('layout')!r} to be one of {sorted(LAYOUTS)}")
    project = fake.projects[str(spec["projectId"])]
    made = fake.add_view(project, str(spec["name"]), str(spec["layout"]))
    return {"createProjectV2View": {"projectV2View": {"id": made.id, "name": made.name, "layout": made.layout}}}


@handler("UpdateView")
def update_view(fake: FakeGitHub, v: JSON) -> JSON:
    spec: JSON = v["input"]
    for project in fake.projects.values():
        for view in project.views:
            if view.id == spec["viewId"]:
                view.filter = str(spec["filter"])
                return {"updateProjectV2View": {"projectV2View": {"id": view.id, "filter": view.filter}}}
    raise GqlError("NOT_FOUND", f"Could not resolve to a node with the global id of '{spec['viewId']}'.")


@handler("DiscoverProjectsOrg")
def discover_projects_org(fake: FakeGitHub, v: JSON) -> JSON:
    rows = [
        {"id": p.id, "number": p.number, "title": p.title}
        for p in fake.projects.values()
        if p.owner == v["login"] and p.owner_type == "organization"
    ]
    return {"organization": {"projectsV2": fake.connection(rows, v)}}


@handler("DiscoverProjectsUser")
def discover_projects_user(fake: FakeGitHub, v: JSON) -> JSON:
    rows = [
        {"id": p.id, "number": p.number, "title": p.title}
        for p in fake.projects.values()
        if p.owner == v["login"] and p.owner_type == "user"
    ]
    return {"user": {"projectsV2": fake.connection(rows, v)}}
