# SPDX-License-Identifier: MIT
"""board.yaml: the schema, the loader and a validator that names the offending key.

PyYAML is the one runtime dependency and is loaded through a custom SafeLoader subclass
that refuses duplicate keys, anchors, aliases, and merge keys, and enforces depth and size limits.
Every error is a `ConfigError` whose message starts with `<file>: <key path>:`.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
import yaml.constructor
import yaml.events
import yaml.nodes

from safo.errors import ConfigError

COLORS = ("GRAY", "BLUE", "GREEN", "YELLOW", "ORANGE", "RED", "PINK", "PURPLE")
FIELD_TYPES = ("single_select", "iteration", "date", "text", "number")
LAYOUTS = ("board", "table", "roadmap")
OWNER_TYPES = ("organization", "user")
LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
REPO_NAME = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_MAX_YAML_SIZE = 1024 * 1024  # 1 MiB
_MAX_YAML_DEPTH = 64


@dataclass(frozen=True)
class Project:
    owner: str
    owner_type: str
    number: int | None
    title: str


@dataclass(frozen=True)
class AreaRule:
    match: str  # case-insensitive substring of the title or a label
    area: str


@dataclass(frozen=True)
class Repository:
    owner: str
    name: str
    default_area: str | None = None
    area_rules: tuple[AreaRule, ...] = ()

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"


@dataclass(frozen=True)
class Option:
    name: str
    color: str = "GRAY"
    description: str = ""


@dataclass(frozen=True)
class Field:
    name: str
    type: str
    options: tuple[Option, ...] = ()
    start: dt.date | None = None  # iteration fields
    duration_days: int = 0
    count: int = 0
    title_prefix: str = ""


@dataclass(frozen=True)
class View:
    name: str
    layout: str
    filter: str = ""


@dataclass(frozen=True)
class StatusRules:
    opened: str = "Backlog"  # an issue that opens
    reopened: str = "Backlog"  # an issue reopened out of Done
    closed: str = "Done"
    merged: str = "Done"
    opened_pr: str | None = None  # defaults to `opened`
    draft_pr: str | None = None  # defaults to `opened`


@dataclass(frozen=True)
class Rules:
    status_field: str = "Status"
    area_field: str = "Area"
    status: StatusRules = field(default_factory=StatusRules)
    done_date_field: str = ""  # empty disables the date
    new_item_defaults: tuple[tuple[str, str], ...] = ()  # (field, option) set on items safo adds
    add_closed_days: int = 0  # reconcile also adds items closed or merged within this many days, as Done


@dataclass(frozen=True)
class AgentsView:
    field: str = "Agent"
    working: tuple[str, ...] = ("In progress", "Next")
    waiting: tuple[str, ...] = ("Blocked",)


@dataclass(frozen=True)
class Board:
    project: Project
    repositories: tuple[Repository, ...]
    fields: tuple[Field, ...]
    views: tuple[View, ...]
    rules: Rules
    agents: AgentsView
    ui_only: tuple[str, ...] = ()

    def field_named(self, name: str) -> Field | None:
        return next((f for f in self.fields if f.name == name), None)


# -- YAML loader with safety guards against hostile input --------------------


class _SafeLoader(yaml.SafeLoader):
    """A YAML loader that refuses duplicate keys, aliases, anchors, merge keys, and limits depth/size."""

    def __init__(self, stream: Any, source: str = "board.yaml") -> None:
        super().__init__(stream)
        self._compose_depth = 0
        self._source = source

    def check_event(self, *args: Any, **kwargs: Any) -> bool:
        # Refuse alias events
        if isinstance(self.current_event, yaml.events.AliasEvent):
            start_mark = self.current_event.start_mark
            line = start_mark.line + 1 if start_mark else 0
            raise ConfigError(f"{self._source}: line {line}: aliases are not allowed")
        # Refuse anchors (attached to scalar/sequence/mapping start events)
        if hasattr(self.current_event, "anchor") and self.current_event.anchor is not None:
            start_mark = self.current_event.start_mark
            line = start_mark.line + 1 if start_mark else 0
            raise ConfigError(f"{self._source}: line {line}: anchors are not allowed")
        return super().check_event(*args, **kwargs)

    def compose_node(self, parent: Any, index: Any) -> Any:
        """Track composition depth and refuse nesting over the limit."""
        self._compose_depth += 1
        if self._compose_depth > _MAX_YAML_DEPTH:
            raise ConfigError(f"{self._source}: nesting exceeds maximum depth ({_MAX_YAML_DEPTH})")
        try:
            return super().compose_node(parent, index)
        finally:
            self._compose_depth -= 1

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[str, Any]:  # type: ignore[override]
        if not isinstance(node, yaml.MappingNode):
            raise ConfigError("expected a mapping")

        # Check for merge keys and track duplicates
        mapping: dict[str, Any] = {}
        for key_node, value_node in node.value:
            # Extract key
            key = self.construct_object(key_node, deep=deep)

            # Refuse non-string keys
            if not isinstance(key, str):
                key_type = type(key).__name__
                line = key_node.start_mark.line + 1
                msg = f"{self._source}: line {line}: mapping key must be a string, not {key_type}"
                raise ConfigError(msg)

            # Refuse merge keys
            if key == "<<":
                line = key_node.start_mark.line + 1
                raise ConfigError(f"{self._source}: line {line}: merge keys (<<) are not allowed")

            # Refuse duplicate keys
            if key in mapping:
                line = key_node.start_mark.line + 1
                raise ConfigError(f"{self._source}: line {line}: duplicate key {key!r}")

            mapping[key] = self.construct_object(value_node, deep=deep)

        return mapping


def _safe_load(text: str, source: str = "board.yaml") -> object:
    """Load YAML with duplicate key, anchor, alias, and depth checking."""
    # Check size
    if len(text) > _MAX_YAML_SIZE:
        raise ConfigError(f"{source}: file exceeds maximum size ({_MAX_YAML_SIZE} bytes)")

    try:
        from io import StringIO

        loader_instance = _SafeLoader(StringIO(text), source)
        return loader_instance.get_single_data()
    except yaml.YAMLError as err:
        raise ConfigError(f"{source}: not valid YAML ({err.__class__.__name__})") from None
    except ConfigError:
        raise
    except RecursionError:
        raise ConfigError(f"{source}: nested too deeply") from None


# -- validation helpers ------------------------------------------------------------


class Reader:
    def __init__(self, source: str) -> None:
        self.source = source

    def fail(self, path: str, message: str) -> ConfigError:
        return ConfigError(f"{self.source}: {path}: {message}")

    def mapping(
        self, value: object, path: str, allowed: set[str], required: set[str] | None = None
    ) -> Mapping[str, Any]:
        if not isinstance(value, Mapping):
            raise self.fail(path, f"expected a mapping, got {type(value).__name__}")
        for key in value:
            if key not in allowed:
                raise self.fail(
                    f"{path}.{key}" if path else str(key), f"unknown key (allowed: {', '.join(sorted(allowed))})"
                )
        for key in sorted(required or set()):
            if key not in value:
                raise self.fail(f"{path}.{key}" if path else key, "required")
        return value

    def seq(self, value: object, path: str) -> list[Any]:
        if not isinstance(value, list):
            raise self.fail(path, f"expected a list, got {type(value).__name__}")
        return value

    def string(self, value: object, path: str, *, empty: bool = False) -> str:
        if not isinstance(value, str) or (not empty and not value.strip()):
            raise self.fail(path, "expected a non-empty string")
        return value

    def integer(self, value: object, path: str, *, minimum: int = 0) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            raise self.fail(path, f"expected an integer >= {minimum}")
        return value

    def choice(self, value: object, path: str, choices: tuple[str, ...]) -> str:
        if not isinstance(value, str) or value not in choices:
            raise self.fail(path, f"{value!r} is not one of {', '.join(choices)}")
        return value

    def date(self, value: object, path: str) -> dt.date:
        if isinstance(value, dt.datetime):
            raise self.fail(path, "expected a date (YYYY-MM-DD), got a timestamp")
        if isinstance(value, dt.date):
            return value
        if isinstance(value, str):
            try:
                return dt.date.fromisoformat(value)
            except ValueError:
                pass
        raise self.fail(path, "expected a date (YYYY-MM-DD)")


def parse_board(data: object, source: str = "board.yaml", *, check_fields: bool = True) -> Board:
    """Validate a loaded document. `check_fields=False` skips the cross-checks against `fields`."""
    r = Reader(source)
    top = r.mapping(
        data,
        "",
        {"version", "project", "repositories", "fields", "views", "rules", "agents", "ui_only"},
        {"version", "project", "repositories"},
    )

    # Check version is int 1 (not bool True)
    version_val = top["version"]
    if isinstance(version_val, bool) or not isinstance(version_val, int) or version_val != 1:
        raise r.fail("version", "only version 1 is supported")

    p = r.mapping(
        top["project"], "project", {"owner", "owner_type", "number", "title"}, {"owner", "owner_type", "title"}
    )
    owner = r.string(p["owner"], "project.owner")
    if not LOGIN.match(owner):
        raise r.fail("project.owner", f"{owner!r} is not a GitHub login")
    number = None if p.get("number") is None else r.integer(p["number"], "project.number", minimum=1)
    project = Project(
        owner,
        r.choice(p["owner_type"], "project.owner_type", OWNER_TYPES),
        number,
        r.string(p["title"], "project.title"),
    )

    repos: list[Repository] = []
    for i, raw in enumerate(r.seq(top["repositories"], "repositories")):
        path = f"repositories[{i}]"
        m = r.mapping(raw, path, {"owner", "name", "default_area", "area_rules"}, {"owner", "name"})
        rules_raw = r.seq(m.get("area_rules", []), f"{path}.area_rules")
        area_rules = []
        for j, rule in enumerate(rules_raw):
            rm = r.mapping(rule, f"{path}.area_rules[{j}]", {"match", "area"}, {"match", "area"})
            area_rules.append(
                AreaRule(
                    r.string(rm["match"], f"{path}.area_rules[{j}].match"),
                    r.string(rm["area"], f"{path}.area_rules[{j}].area"),
                )
            )
        repo = Repository(
            r.string(m["owner"], f"{path}.owner"),
            r.string(m["name"], f"{path}.name"),
            None if m.get("default_area") is None else r.string(m["default_area"], f"{path}.default_area"),
            tuple(area_rules),
        )
        if not LOGIN.match(repo.owner) or not REPO_NAME.match(repo.name):
            raise r.fail(path, f"{repo.full_name!r} is not an owner/name pair")
        if any(x.full_name.lower() == repo.full_name.lower() for x in repos):
            raise r.fail(path, f"{repo.full_name} is listed twice")
        repos.append(repo)

    fields: list[Field] = []
    for i, raw in enumerate(r.seq(top.get("fields", []), "fields")):
        path = f"fields[{i}]"
        m = r.mapping(
            raw, path, {"name", "type", "options", "start", "duration_days", "count", "title_prefix"}, {"name", "type"}
        )
        name = r.string(m["name"], f"{path}.name")
        ftype = r.choice(m["type"], f"{path}.type", FIELD_TYPES)
        if any(f.name == name for f in fields):
            raise r.fail(f"{path}.name", f"field {name!r} is defined twice")
        options: list[Option] = []
        if ftype == "single_select":
            raw_options = r.seq(m.get("options"), f"{path}.options") if "options" in m else []
            if not raw_options:
                raise r.fail(f"{path}.options", "a single_select field needs at least one option")
            for j, o in enumerate(raw_options):
                opath = f"{path}.options[{j}]"
                om = r.mapping(o, opath, {"name", "color", "description"}, {"name"})
                option = Option(
                    r.string(om["name"], f"{opath}.name"),
                    r.choice(om.get("color", "GRAY"), f"{opath}.color", COLORS),
                    r.string(om.get("description", ""), f"{opath}.description", empty=True),
                )
                if any(x.name == option.name for x in options):
                    raise r.fail(f"{opath}.name", f"option {option.name!r} is defined twice in {name!r}")
                options.append(option)
        elif "options" in m:
            raise r.fail(f"{path}.options", f"only a single_select field has options, not {ftype}")
        start = None
        duration = count = 0
        if ftype == "iteration":
            for key in ("start", "duration_days", "count"):
                if key not in m:
                    raise r.fail(f"{path}.{key}", "required for an iteration field")
            start = r.date(m["start"], f"{path}.start")
            duration = r.integer(m["duration_days"], f"{path}.duration_days", minimum=1)
            count = r.integer(m["count"], f"{path}.count", minimum=1)
        else:
            for key in ("start", "duration_days", "count", "title_prefix"):
                if key in m:
                    raise r.fail(f"{path}.{key}", "only an iteration field has this key")
        fields.append(Field(name, ftype, tuple(options), start, duration, count, str(m.get("title_prefix", name))))

    views: list[View] = []
    for i, raw in enumerate(r.seq(top.get("views", []), "views")):
        path = f"views[{i}]"
        m = r.mapping(raw, path, {"name", "layout", "filter"}, {"name", "layout"})
        view = View(
            r.string(m["name"], f"{path}.name"),
            r.choice(m["layout"], f"{path}.layout", LAYOUTS),
            r.string(m.get("filter", ""), f"{path}.filter", empty=True),
        )
        if any(v.name == view.name for v in views):
            raise r.fail(f"{path}.name", f"view {view.name!r} is defined twice")
        views.append(view)

    rules = _parse_rules(r, top.get("rules", {}))
    agents = _parse_agents(r, top.get("agents", {}))
    ui_only = tuple(r.string(s, f"ui_only[{i}]") for i, s in enumerate(r.seq(top.get("ui_only", []), "ui_only")))
    board = Board(project, tuple(repos), tuple(fields), tuple(views), rules, agents, ui_only)
    if check_fields:
        _cross_check(r, board, agents_present="agents" in top)
    return board


def _parse_rules(r: Reader, raw: object) -> Rules:
    m = r.mapping(
        raw,
        "rules",
        {"status_field", "area_field", "status", "done_date_field", "new_item_defaults", "add_closed_days"},
    )
    s = r.mapping(
        m.get("status", {}), "rules.status", {"opened", "reopened", "closed", "merged", "opened_pr", "draft_pr"}
    )
    defaults = StatusRules()
    status = StatusRules(
        r.string(s.get("opened", defaults.opened), "rules.status.opened"),
        r.string(s.get("reopened", defaults.reopened), "rules.status.reopened"),
        r.string(s.get("closed", defaults.closed), "rules.status.closed"),
        r.string(s.get("merged", defaults.merged), "rules.status.merged"),
        None if s.get("opened_pr") is None else r.string(s["opened_pr"], "rules.status.opened_pr"),
        None if s.get("draft_pr") is None else r.string(s["draft_pr"], "rules.status.draft_pr"),
    )
    nid_raw = m.get("new_item_defaults", {})
    if not isinstance(nid_raw, Mapping):
        raise r.fail("rules.new_item_defaults", "expected a mapping")
    nid: dict[str, str] = {}
    for k, v in nid_raw.items():
        if not isinstance(k, str):
            raise r.fail("rules.new_item_defaults", f"key must be a string, not {type(k).__name__}")
        nid[k] = r.string(v, f"rules.new_item_defaults.{k}")
    return Rules(
        r.string(m.get("status_field", "Status"), "rules.status_field"),
        r.string(m.get("area_field", "Area"), "rules.area_field"),
        status,
        r.string(m.get("done_date_field", ""), "rules.done_date_field", empty=True),
        tuple((str(k), v) for k, v in nid.items()),
        r.integer(m.get("add_closed_days", 0), "rules.add_closed_days"),
    )


def _parse_agents(r: Reader, raw: object) -> AgentsView:
    m = r.mapping(raw, "agents", {"field", "working", "waiting"})
    d = AgentsView()

    def names(key: str, default: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            r.string(x, f"agents.{key}[{i}]") for i, x in enumerate(r.seq(m.get(key, list(default)), f"agents.{key}"))
        )

    return AgentsView(
        r.string(m.get("field", d.field), "agents.field"), names("working", d.working), names("waiting", d.waiting)
    )


def _cross_check(r: Reader, board: Board, agents_present: bool = False) -> None:
    rules = board.rules

    def option_exists(field_name: str, option: str, path: str) -> None:
        f = board.field_named(field_name)
        if f is None:
            raise r.fail(path, f"names field {field_name!r}, which is not in fields")
        if f.type != "single_select":
            raise r.fail(path, f"field {field_name!r} is {f.type}, not single_select")
        if option not in {o.name for o in f.options}:
            raise r.fail(
                path, f"{option!r} is not an option of {field_name!r} (options: {', '.join(o.name for o in f.options)})"
            )

    s = rules.status
    for key in ("opened", "reopened", "closed", "merged", "opened_pr", "draft_pr"):
        value = getattr(s, key)
        if value is not None:
            option_exists(rules.status_field, value, f"rules.status.{key}")
    if rules.done_date_field:
        f = board.field_named(rules.done_date_field)
        if f is None or f.type != "date":
            raise r.fail("rules.done_date_field", f"{rules.done_date_field!r} must be a date field in fields")
    for name, option in rules.new_item_defaults:
        option_exists(name, option, f"rules.new_item_defaults.{name}")
    for i, repo in enumerate(board.repositories):
        if repo.default_area is not None:
            option_exists(rules.area_field, repo.default_area, f"repositories[{i}].default_area")
        for j, rule in enumerate(repo.area_rules):
            option_exists(rules.area_field, rule.area, f"repositories[{i}].area_rules[{j}].area")

    # Cross-check agents only when agents key is present in the document
    if agents_present:
        agents_field = board.field_named(board.agents.field)
        if agents_field is None:
            raise r.fail("agents.field", f"field {board.agents.field!r} is not in fields")
        if agents_field.type != "single_select":
            raise r.fail("agents.field", f"field {board.agents.field!r} is {agents_field.type}, not single_select")

        # Check agents.working and agents.waiting are valid status options
        status_field = board.field_named(rules.status_field)
        if status_field and status_field.type == "single_select":
            status_options = {o.name for o in status_field.options}
            for i, ws in enumerate(board.agents.working):
                if ws not in status_options:
                    raise r.fail(f"agents.working[{i}]", f"{ws!r} is not an option of {rules.status_field!r}")
            for i, ws in enumerate(board.agents.waiting):
                if ws not in status_options:
                    raise r.fail(f"agents.waiting[{i}]", f"{ws!r} is not an option of {rules.status_field!r}")


def load_board(path: str | Path, *, check_fields: bool = True) -> Board:
    """Read and validate a board.yaml. Uses a custom YAML loader that refuses hostile inputs."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as err:
        raise ConfigError(f"{p}: cannot read the board file ({err.strerror})") from None

    data = _safe_load(text, str(p))
    return parse_board(data, str(p), check_fields=check_fields)
