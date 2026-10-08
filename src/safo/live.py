# SPDX-License-Identifier: MIT
"""Read the live board: its fields (with option ids and colours), views and item count."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any

from safo.errors import ConfigError, MalformedDataError, NotFoundError
from safo.graphql import JSON, Client
from safo.schema import Project


def _both(template: str) -> tuple[str, str]:
    """The same document rooted at an organization and at a user."""
    return (
        template.replace("__ROOT__", "organization").replace("__SFX__", "Org"),
        template.replace("__ROOT__", "user").replace("__SFX__", "User"),
    )


Q_OWNER_ORG, Q_OWNER_USER = _both("query Owner__SFX__($login: String!) { __ROOT__(login: $login) { id login } }")

Q_META_ORG, Q_META_USER = _both(
    """query ProjectMeta__SFX__($login: String!, $number: Int!) {
  __ROOT__(login: $login) { projectV2(number: $number) { id title number items { totalCount } } }
}"""
)

Q_FIELDS_ORG, Q_FIELDS_USER = _both(
    """query ProjectFields__SFX__($login: String!, $number: Int!, $endCursor: String) {
  __ROOT__(login: $login) { projectV2(number: $number) {
    fields(first: 100, after: $endCursor) {
      pageInfo { hasNextPage endCursor }
      nodes {
        __typename
        ... on ProjectV2FieldCommon { id name dataType }
        ... on ProjectV2SingleSelectField { options { id name color description } }
        ... on ProjectV2IterationField {
          configuration {
            duration
            iterations { id title startDate duration }
            completedIterations { id title startDate duration }
          }
        }
      }
    }
  } }
}"""
)

Q_VIEWS_ORG, Q_VIEWS_USER = _both(
    """query ProjectViews__SFX__($login: String!, $number: Int!, $endCursor: String) {
  __ROOT__(login: $login) { projectV2(number: $number) {
    views(first: 50, after: $endCursor) {
      pageInfo { hasNextPage endCursor }
      nodes { id name layout filter }
    }
  } }
}"""
)

LAYOUT_NAMES = {"BOARD_LAYOUT": "board", "TABLE_LAYOUT": "table", "ROADMAP_LAYOUT": "roadmap"}
LAYOUT_ENUMS = {v: k for k, v in LAYOUT_NAMES.items()}
DATA_TYPES = {
    "SINGLE_SELECT": "single_select",
    "ITERATION": "iteration",
    "DATE": "date",
    "TEXT": "text",
    "NUMBER": "number",
}


@dataclass(frozen=True)
class LiveOption:
    id: str
    name: str
    color: str
    description: str


@dataclass(frozen=True)
class LiveIteration:
    id: str
    title: str
    start: str
    duration: int


@dataclass(frozen=True)
class LiveField:
    id: str
    name: str
    type: str  # a board.yaml type, or the raw GitHub data type for built-in fields
    options: tuple[LiveOption, ...] = ()
    iterations: tuple[LiveIteration, ...] = ()

    def option(self, name: str) -> LiveOption | None:
        return next((o for o in self.options if o.name == name), None)


@dataclass(frozen=True)
class LiveView:
    id: str
    name: str
    layout: str
    filter: str


@dataclass
class LiveBoard:
    id: str
    title: str
    number: int
    items_total: int
    fields: dict[str, LiveField] = field(default_factory=dict)
    views: dict[str, LiveView] = field(default_factory=dict)

    def field(self, name: str) -> LiveField:
        found = self.fields.get(name)
        if found is None:
            raise ConfigError(
                f"the project has no field named {name!r} (its fields: {', '.join(self.fields)}); "
                "run `safo bootstrap` to create it"
            )
        return found

    def option_id(self, field_name: str, option: str) -> str:
        f = self.field(field_name)
        found = f.option(option)
        if found is None:
            raise ConfigError(
                f"the field {field_name!r} has no option named {option!r} "
                f"(its options: {', '.join(o.name for o in f.options)}); add it in the project's own settings, "
                "because safo never edits an existing field's options"
            )
        return found.id


def _int(value: Any, where: str) -> int:
    """An integer from a live value, or MalformedDataError naming where it came from."""
    if isinstance(value, bool):
        raise MalformedDataError(f"{where} is {value!r} on the project, not an integer")
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        raise MalformedDataError(f"{where} is {str(value)[:40]!r} on the project, not an integer") from None


def _date(value: Any, where: str) -> str:
    """A YYYY-MM-DD string from a live value, or MalformedDataError naming where it came from."""
    try:
        dt.date.fromisoformat(str(value))
    except ValueError:
        raise MalformedDataError(f"{where} is {str(value)[:40]!r} on the project, not a date (YYYY-MM-DD)") from None
    return str(value)


def _root(owner_type: str) -> str:
    return "organization" if owner_type == "organization" else "user"


def _documents(owner_type: str) -> tuple[str, str, str, str]:
    if owner_type == "organization":
        return Q_OWNER_ORG, Q_META_ORG, Q_FIELDS_ORG, Q_VIEWS_ORG
    return Q_OWNER_USER, Q_META_USER, Q_FIELDS_USER, Q_VIEWS_USER


def owner_id(client: Client, project: Project) -> str:
    data = client.execute(_documents(project.owner_type)[0], {"login": project.owner})
    node = data.get(_root(project.owner_type))
    if not node:
        raise NotFoundError(f"no {project.owner_type} named {project.owner}, or the token cannot see it")
    return str(node["id"])


def load_live(client: Client, project: Project) -> LiveBoard:
    """Three reads: meta, fields (paginated), views (paginated). Needs `project.number`."""
    if project.number is None:
        raise ConfigError(
            "project.number is not set; run `safo bootstrap` to create the project, then write its number in board.yaml"
        )
    root = _root(project.owner_type)
    _, meta_doc, fields_doc, views_doc = _documents(project.owner_type)
    variables = {"login": project.owner, "number": project.number}
    owner = client.execute(meta_doc, variables).get(root)
    node = owner and owner.get("projectV2")
    if not node:
        raise NotFoundError(f"no project {project.number} under {project.owner}, or the token cannot see it")
    live = LiveBoard(
        str(node["id"]),
        str(node["title"]),
        _int(node["number"], "the project number"),
        _int(node["items"]["totalCount"], "the project's items totalCount"),
    )
    for page in client.pages(fields_doc, variables, (root, "projectV2", "fields")):
        for raw in page["nodes"]:
            if raw:
                parsed = _parse_field(raw)
                live.fields[parsed.name] = parsed
    for page in client.pages(views_doc, variables, (root, "projectV2", "views")):
        for raw in page["nodes"]:
            if raw:
                live.views[str(raw["name"])] = LiveView(
                    str(raw["id"]),
                    str(raw["name"]),
                    LAYOUT_NAMES.get(str(raw["layout"]), str(raw["layout"])),
                    str(raw.get("filter") or ""),
                )
    return live


def _parse_field(raw: JSON) -> LiveField:
    ftype = DATA_TYPES.get(str(raw.get("dataType", "")), str(raw.get("dataType", "")))
    options = tuple(
        LiveOption(str(o["id"]), str(o["name"]), str(o.get("color") or ""), str(o.get("description") or ""))
        for o in raw.get("options") or []
    )
    iterations: tuple[LiveIteration, ...] = ()
    config: Any = raw.get("configuration")
    if config:
        rows = list(config.get("completedIterations") or []) + list(config.get("iterations") or [])
        name = str(raw.get("name"))
        iterations = tuple(
            LiveIteration(
                str(i["id"]),
                str(i["title"]),
                _date(i["startDate"], f"an iteration startDate of field {name!r}"),
                _int(i["duration"], f"an iteration duration of field {name!r}"),
            )
            for i in rows
        )
    return LiveField(str(raw["id"]), str(raw["name"]), ftype, options, iterations)
