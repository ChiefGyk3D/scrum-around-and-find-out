# SPDX-License-Identifier: MIT
"""bootstrap: create what board.yaml names and the project lacks; refuse to edit what exists.

`updateProjectV2Field` with `singleSelectOptions` replaces every option with a new id and wipes each
item's value, so an existing field is never touched through the API: a missing option is reported with
the UI step that adds it safely. A view is created with its layout, then its filter is set with
`updateProjectV2View`, because `createProjectV2View` takes no filter.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
from typing import Any

from safo.context import Context
from safo.errors import EXIT_DRIFT, EXIT_OK, EXIT_UNKNOWN, ConfigError, UnknownOutcomeError
from safo.graphql import JSON
from safo.live import DATA_TYPES, LAYOUT_ENUMS, LiveBoard, _both, _root, load_live, owner_id
from safo.modes import Mode, register
from safo.mutation import mutate
from safo.schema import Board, Field, Project, View
from safo.values import whole_number

M_CREATE_PROJECT = """mutation CreateProject($input: CreateProjectV2Input!) {
  createProjectV2(input: $input) { projectV2 { id number } }
}"""

M_CREATE_FIELD = """mutation CreateField($input: CreateProjectV2FieldInput!) {
  createProjectV2Field(input: $input) { projectV2Field { ... on ProjectV2FieldCommon { id name } } }
}"""

M_CREATE_VIEW = """mutation CreateView($input: CreateProjectV2ViewInput!) {
  createProjectV2View(input: $input) { projectV2View { id name layout } }
}"""

M_UPDATE_VIEW = """mutation UpdateView($input: UpdateProjectV2ViewInput!) {
  updateProjectV2View(input: $input) { projectV2View { id filter } }
}"""

Q_DISCOVER_ORG, Q_DISCOVER_USER = _both(
    """query DiscoverProjects__SFX__($login: String!, $endCursor: String) {
  __ROOT__(login: $login) { projectsV2(first: 100, after: $endCursor) {
    pageInfo { hasNextPage endCursor }
    nodes { id number title }
  } }
}"""
)


def discover(ctx: Context) -> list[JSON]:
    project = ctx.board.project
    doc = Q_DISCOVER_ORG if project.owner_type == "organization" else Q_DISCOVER_USER
    return [
        n
        for n in ctx.client.nodes(doc, {"login": project.owner}, (_root(project.owner_type), "projectsV2"))
        if n["title"] == project.title
    ]


DATA_TYPE_ENUMS = {v: k for k, v in DATA_TYPES.items()}


def field_input(project_id: str, f: Field) -> dict[str, Any]:
    """The createProjectV2Field input for a field that does not exist yet."""
    body: dict[str, Any] = {"projectId": project_id, "name": f.name, "dataType": DATA_TYPE_ENUMS[f.type]}
    if f.type == "single_select":
        body["singleSelectOptions"] = [
            {"name": o.name, "color": o.color, "description": o.description} for o in f.options
        ]
    if f.type == "iteration" and f.start is not None:
        body["iterationConfiguration"] = {
            "startDate": f.start.isoformat(),
            "duration": f.duration_days,
            "iterations": [
                {
                    "title": f"{f.title_prefix} {i + 1}",
                    "startDate": (f.start + dt.timedelta(days=f.duration_days * i)).isoformat(),
                    "duration": f.duration_days,
                }
                for i in range(f.count)
            ],
        }
    return body


@dataclasses.dataclass
class Report:
    created: list[str] = dataclasses.field(default_factory=list)
    refused: list[str] = dataclasses.field(default_factory=list)
    left: list[str] = dataclasses.field(default_factory=list)


def check_existing_field(f: Field, live: LiveBoard, report: Report) -> None:
    """An existing field is never changed. Say what is missing and how to add it in the UI."""
    found = live.fields[f.name]
    if found.type != f.type:
        report.refused.append(
            f"REFUSED field {f.name!r} is {found.type} on the project but {f.type} in board.yaml. "
            "A field's type cannot change: rename or delete it in the project's settings, then run bootstrap again."
        )
        return
    if f.type == "single_select":
        for o in f.options:
            if found.option(o.name) is None:
                report.refused.append(
                    f"REFUSED field {f.name!r} lacks the option {o.name!r}. In the project: Settings > {f.name} > "
                    f"Add option > {o.name!r}. The API would replace every option id and wipe each item's value."
                )
    elif f.type == "iteration":
        if any(i.duration != f.duration_days for i in found.iterations):
            report.refused.append(
                f"REFUSED field {f.name!r} has the wrong duration. In the project: "
                f"Settings > {f.name} > Edit iteration duration to {f.duration_days} days."
            )
        have = {i.start for i in found.iterations}
        if f.start is not None:
            for i in range(f.count):
                start = (f.start + dt.timedelta(days=f.duration_days * i)).isoformat()
                if start not in have:
                    report.refused.append(
                        f"REFUSED field {f.name!r} lacks the iteration starting {start}. In the project: "
                        f"Settings > {f.name} > Add iteration. The API rewrites the whole iteration list."
                    )


@dataclasses.dataclass
class State:
    """What `run` needs to re-read after an unknown outcome: the project in use and the write in flight."""

    project: Project
    attempt: tuple[str, str] | None = None  # ("project" | "field" | "view" | "filter", name)


def create_view(ctx: Context, project_id: str, v: View, report: Report, state: State) -> None:
    state.attempt = ("view", v.name)
    created = mutate(
        ctx.client,
        M_CREATE_VIEW,
        {"input": {"projectId": project_id, "name": v.name, "layout": LAYOUT_ENUMS[v.layout]}},
        dry_result={"createProjectV2View": {"projectV2View": {"id": "DRY_RUN"}}},
        returns=("createProjectV2View", "projectV2View"),
    )
    view_id = str(created["createProjectV2View"]["projectV2View"]["id"])
    if v.filter:
        # createProjectV2View takes no filter; it is set afterwards.
        state.attempt = ("filter", v.name)
        mutate(
            ctx.client,
            M_UPDATE_VIEW,
            {"input": {"viewId": view_id, "filter": v.filter}},
            returns=("updateProjectV2View", "projectV2View"),
        )
    report.created.append(f"view {v.name!r} ({v.layout}" + (f", filter {v.filter!r})" if v.filter else ")"))


def _extras(board: Board, live: LiveBoard) -> int:
    """How many live options and views board.yaml does not list. Bootstrap manages none of them."""
    count = sum(1 for v in live.views if v not in {x.name for x in board.views})
    for f in board.fields:
        found = live.fields.get(f.name)
        if found and f.type == "single_select":
            count += sum(1 for o in found.options if o.name not in {x.name for x in f.options})
    return count


def _run(ctx: Context, args: argparse.Namespace, state: State) -> int:
    board = ctx.board
    report = Report()
    dry = ctx.client.dry_run
    project = state.project
    if project.number is None:
        state.attempt = ("project", project.title)
        owner = owner_id(ctx.client, project)
        matches = discover(ctx)
        if len(matches) > 1:
            raise ConfigError("multiple projects match the title; set project.number before creating or writing")
        if not matches and dry:
            mutate(
                ctx.client,
                M_CREATE_PROJECT,
                {"input": {"ownerId": owner, "title": project.title}},
                dry_result={"createProjectV2": {"projectV2": {"id": "DRY_RUN", "number": 0}}},
            )
            ctx.say(f"WOULD CREATE project {project.title!r}")
            ctx.say("dry run: nothing exists to read yet, so the fields and views are not planned")
            return EXIT_DRIFT
        made = (
            matches[0]
            if matches
            else mutate(
                ctx.client,
                M_CREATE_PROJECT,
                {"input": {"ownerId": owner, "title": project.title}},
                returns=("createProjectV2", "projectV2"),
            )["createProjectV2"]["projectV2"]
        )
        number = whole_number(made.get("number"), "createProjectV2.projectV2.number")
        verb = "adopted existing project" if matches else "created project"
        ctx.say(f"{verb} {project.title!r}: number {number}.")
        ctx.say(f"Write `number: {number}` under project: in board.yaml.")
        project = dataclasses.replace(project, number=number)
        state.project = project
    live = load_live(ctx.client, project)
    for f in board.fields:
        if f.name in live.fields:
            check_existing_field(f, live, report)
            found = live.fields[f.name]
            if f.type == "single_select":
                for o in f.options:
                    have = found.option(o.name)
                    if have and have.color != o.color:
                        report.left.append(f"field {f.name!r} option {o.name!r} keeps its live colour {have.color}")
                    elif have and have.description != o.description:
                        report.left.append(f"field {f.name!r} option {o.name!r} keeps its live description")
            continue
        state.attempt = ("field", f.name)
        mutate(
            ctx.client,
            M_CREATE_FIELD,
            {"input": field_input(live.id, f)},
            returns=("createProjectV2Field", "projectV2Field"),
        )
        report.created.append(f"field {f.name!r} ({f.type})")
    for v in board.views:
        found_view = live.views.get(v.name)
        if found_view is None:
            create_view(ctx, live.id, v, report, state)
        elif found_view.layout != v.layout:
            report.refused.append(
                f"REFUSED view {v.name!r} is a {found_view.layout} layout on the project but {v.layout} in board.yaml. "
                "A layout cannot change: delete the view in the project, then run bootstrap again."
            )
        elif " ".join(found_view.filter.split()) != " ".join(v.filter.split()):
            report.refused.append(
                f"REFUSED view {v.name!r} exists with the filter {found_view.filter!r}; "
                "left alone; repair its filter in the project UI, then re-run bootstrap"
            )
    state.attempt = None
    for text in report.created:
        ctx.say(f"{'WOULD CREATE' if dry else 'CREATED'} {text}")
    for text in report.left:
        ctx.say(f"LEFT    {text}")
    for text in report.refused:
        ctx.say(text)
    extras = _extras(board, live)
    if extras:
        ctx.say(f"NOTE    {extras} live option(s) or view(s) are not in board.yaml; `safo audit` reports them")
    if not (report.created or report.refused):
        ctx.say("nothing to create: the project already has everything board.yaml names")
    if board.ui_only:
        ctx.say("UI-only settings (no API can set these; do them once by hand):")
        for text in board.ui_only:
            ctx.say(f"  [ ] {text}")
    # A real run that made everything exits 0; a dry run with work pending exits 1, as a refusal does.
    return EXIT_DRIFT if report.refused or (dry and report.created) else EXIT_OK


def _observe(ctx: Context, state: State) -> None:
    """Re-read the board after an unknown outcome and say what the thing in flight looks like now."""
    project = state.project
    kind, name = state.attempt or ("", "")
    if project.number is None:
        matches = discover(ctx)
        if not matches:
            ctx.say(f"observed: no project titled {project.title!r} exists, so the create did not land")
            return
        if len(matches) > 1:
            ctx.say(f"observed: {len(matches)} projects are titled {project.title!r}; set project.number")
            return
        number = whole_number(matches[0].get("number"), "projectsV2.nodes.number")
        ctx.say(f"observed: project {project.title!r} exists as number {number}")
        ctx.say(f"Write `number: {number}` under project: in board.yaml.")
        project = dataclasses.replace(project, number=number)
    live = load_live(ctx.client, project)
    if kind == "field":
        found = live.fields.get(name)
        ctx.say(f"observed: field {name!r} " + (f"exists as {found.type}" if found else "does not exist"))
    elif kind in ("view", "filter"):
        view = live.views.get(name)
        ctx.say(f"observed: view {name!r} " + (f"exists with the filter {view.filter!r}" if view else "does not exist"))
    else:
        ctx.say(f"observed: the project has {len(live.fields)} fields and {len(live.views)} views")


def run(ctx: Context, args: argparse.Namespace) -> int:
    state = State(ctx.board.project)
    try:
        return _run(ctx, args, state)
    except UnknownOutcomeError as err:
        ctx.say(f"unknown outcome: {err}")
        # No dependent writes, even if the reread proves that the write landed.
        try:
            _observe(ctx, state)
        except Exception:
            # Any failure of the reread, even one nobody foresaw, still ends in a visible line and exit 2.
            ctx.say("live reread failed; no further writes")
        else:
            ctx.say("re-read the live board after the unknown outcome; no further writes were sent")
        ctx.say("unknown outcome: re-run after checking the board")
        return EXIT_UNKNOWN


def add_arguments(parser: argparse.ArgumentParser) -> None:
    del parser


register(
    Mode(
        "bootstrap",
        "create the project's missing fields, views and iterations (never edits existing options)",
        add_arguments,
        run,
    )
)


__all__ = ["JSON", "run"]
