# SPDX-License-Identifier: Apache-2.0
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
METHODS = ("agile", "waterfall")
DEPENDENCIES = ("none", "blocked_by")
# `owner/repo#N`, the guard's own pattern (tracking.GITHUB_REF); fullmatch only, every quantifier bounded, none nested
REF = re.compile(r"([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9._-]{1,100})#([1-9][0-9]{0,8})")
_PLAIN_KEY = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_MAX_VALUE_SHOWN = 40
# caps, so a hostile file cannot turn one audit into many API calls (spec 2.5)
MAX_PHASES = 16
MAX_GATES = 32
MAX_APPROVERS = 32
MAX_ACTIVE_STATUSES = 16
_MAX_USER_ID = 2**63 - 1
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
    method: str | None = None  # None: the board's process.method

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
class Tracking:
    """The no-hidden-work rule: which fields every card must hold, and the repositories that opt out of it.

    A field name left empty, or one board.yaml does not define, is "not configured": audit skips that check and says so.
    """

    kind_field: str = "Kind"
    epic_field: str = "Epic"
    effort_field: str = "Effort"
    exempt_repos: tuple[str, ...] = ()  # owner/name: pull requests there need no linked issue


@dataclass(frozen=True)
class ThreatModel:
    """The threat-model-before-build rule: issues with `label` must name a threat model or say why none applies.

    An empty label is "not configured": audit skips the check and says so.
    """

    label: str = ""
    exempt_repos: tuple[str, ...] = ()  # owner/name: issues there need no threat-model line


@dataclass(frozen=True)
class Rules:
    status_field: str = "Status"
    area_field: str = "Area"
    status: StatusRules = field(default_factory=StatusRules)
    done_date_field: str = ""  # empty disables the date
    new_item_defaults: tuple[tuple[str, str], ...] = ()  # (field, option) set on items safo adds
    add_closed_days: int = 0  # reconcile also adds items closed or merged within this many days, as Done
    tracking: Tracking = field(default_factory=Tracking)
    threat_model: ThreatModel = field(default_factory=ThreatModel)


@dataclass(frozen=True)
class Approver:
    """A person whose manual close of a gate counts: the login is for people, the immutable id is what is compared."""

    login: str
    id: int


@dataclass(frozen=True)
class Gate:
    """The exit gate of a phase: `issue` is `owner/repo#N`, a repository of the board."""

    phase: str
    issue: str


@dataclass(frozen=True)
class Process:
    """The process method. The default is what an absent `process` key means: agile, and nothing else is read."""

    method: str = "agile"
    active_statuses: tuple[str, ...] = ()  # waterfall only
    dependencies: str = "none"
    phase_field: str = ""  # waterfall only
    approvers: tuple[Approver, ...] = ()  # waterfall only
    gates: tuple[Gate, ...] = ()  # waterfall only


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
    process: Process = field(default_factory=Process)

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


def show(value: object) -> str:
    """Text for a value in an error message: ASCII only, cut short, and a foreign value named by its type.

    Nothing from the file reaches a log line unescaped or unbounded (the log may be public).
    """
    if isinstance(value, str):
        text = ascii(value[:_MAX_VALUE_SHOWN])
        return text if len(value) <= _MAX_VALUE_SHOWN else f"{text[:-1]}...{text[-1]}"
    if value is None or isinstance(value, bool):
        return repr(value)
    if isinstance(value, int) and abs(value) < 10**15:
        return repr(value)
    return f"a {type(value).__name__}"


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
                shown = key if _PLAIN_KEY.fullmatch(key) else show(key)
                allowed_text = ", ".join(sorted(allowed))
                raise self.fail(f"{path}.{shown}" if path else shown, f"unknown key (allowed: {allowed_text})")
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
            raise self.fail(path, f"{show(value)} is not one of {', '.join(choices)}")
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
        {"version", "project", "repositories", "fields", "views", "rules", "agents", "ui_only", "process"},
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
    if not LOGIN.fullmatch(owner):
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
        m = r.mapping(raw, path, {"owner", "name", "default_area", "area_rules", "method"}, {"owner", "name"})
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
            r.choice(m["method"], f"{path}.method", METHODS) if "method" in m else None,
        )
        if not LOGIN.fullmatch(repo.owner) or not REPO_NAME.fullmatch(repo.name):
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
    process = _parse_process(r, top.get("process", {}), tuple(repos), rules)
    board = Board(project, tuple(repos), tuple(fields), tuple(views), rules, agents, ui_only, process)
    if check_fields:
        _cross_check(r, board, agents_present="agents" in top)
    return board


def _parse_rules(r: Reader, raw: object) -> Rules:
    m = r.mapping(
        raw,
        "rules",
        {
            "status_field",
            "area_field",
            "status",
            "done_date_field",
            "new_item_defaults",
            "add_closed_days",
            "tracking",
            "threat_model",
        },
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
        _parse_tracking(r, m.get("tracking", {})),
        _parse_threat_model(r, m.get("threat_model", {})),
    )


def _parse_tracking(r: Reader, raw: object) -> Tracking:
    m = r.mapping(raw, "rules.tracking", {"kind_field", "epic_field", "effort_field", "exempt_repos"})
    d = Tracking()
    exempt: list[str] = []
    for i, name in enumerate(r.seq(m.get("exempt_repos", []), "rules.tracking.exempt_repos")):
        text = r.string(name, f"rules.tracking.exempt_repos[{i}]")
        owner, _, repo = text.partition("/")
        if not (LOGIN.fullmatch(owner) and REPO_NAME.fullmatch(repo)):
            raise r.fail(f"rules.tracking.exempt_repos[{i}]", "expected owner/name")
        exempt.append(text)
    return Tracking(
        r.string(m.get("kind_field", d.kind_field), "rules.tracking.kind_field", empty=True),
        r.string(m.get("epic_field", d.epic_field), "rules.tracking.epic_field", empty=True),
        r.string(m.get("effort_field", d.effort_field), "rules.tracking.effort_field", empty=True),
        tuple(exempt),
    )


def _parse_threat_model(r: Reader, raw: object) -> ThreatModel:
    m = r.mapping(raw, "rules.threat_model", {"label", "exempt_repos"})
    label = r.string(m.get("label", ""), "rules.threat_model.label", empty=True)
    if label != label.strip() or len(label) > 50 or any(ord(c) < 32 or c == "," for c in label):
        raise r.fail("rules.threat_model.label", "expected a GitHub label name: at most 50 characters, no comma")
    exempt: list[str] = []
    for i, name in enumerate(r.seq(m.get("exempt_repos", []), "rules.threat_model.exempt_repos")):
        text = r.string(name, f"rules.threat_model.exempt_repos[{i}]")
        owner, _, repo = text.partition("/")
        if not (LOGIN.fullmatch(owner) and REPO_NAME.fullmatch(repo)):
            raise r.fail(f"rules.threat_model.exempt_repos[{i}]", "expected owner/name")
        exempt.append(text)
    return ThreatModel(label, tuple(exempt))


def _parse_process(r: Reader, raw: object, repos: tuple[Repository, ...], rules: Rules) -> Process:
    """The `process` block: its structure and the references that need no `fields` (those are in _cross_check)."""
    m = r.mapping(raw, "process", {"method", "active_statuses", "dependencies", "phase_field", "approvers", "gates"})
    method = r.choice(m["method"], "process.method", METHODS) if "method" in m else "agile"
    dependencies = r.choice(m["dependencies"], "process.dependencies", DEPENDENCIES) if "dependencies" in m else "none"
    if method != "waterfall" and not any(repo.method == "waterfall" for repo in repos):
        for key in ("active_statuses", "phase_field", "approvers", "gates"):
            if key in m:
                raise r.fail(f"process.{key}", "only used when the method or a repository is waterfall")
        return Process(method, dependencies=dependencies)

    if "phase_field" not in m:
        raise r.fail("process.phase_field", "required when a repository is waterfall")
    phase_field = r.string(m["phase_field"], "process.phase_field")
    if rules.add_closed_days < 1:
        raise r.fail(
            "rules.add_closed_days",
            "must be at least 1 when a repository is waterfall (the gate rule reads recently closed cards)",
        )

    active: list[str] = []
    if "active_statuses" not in m or m["active_statuses"] == []:
        raise r.fail("process.active_statuses", "required when a repository is waterfall")
    for i, name in enumerate(_capped(r, m["active_statuses"], "process.active_statuses", MAX_ACTIVE_STATUSES)):
        status = r.string(name, f"process.active_statuses[{i}]")
        if status in active:
            raise r.fail(f"process.active_statuses[{i}]", f"{show(status)} is listed twice")
        active.append(status)

    if "approvers" not in m or m["approvers"] == []:
        raise r.fail("process.approvers", "required (at least one) when the method or a repository is waterfall")
    approvers: list[Approver] = []
    for i, item in enumerate(_capped(r, m["approvers"], "process.approvers", MAX_APPROVERS)):
        path = f"process.approvers[{i}]"
        if not isinstance(item, Mapping) or set(item) != {"login", "id"}:
            raise r.fail(path, "expected {login, id}")
        login = r.string(item["login"], f"{path}.login")
        if not LOGIN.fullmatch(login):
            raise r.fail(f"{path}.login", f"{show(login)} is not a GitHub login")
        uid = item["id"]
        if isinstance(uid, bool) or not isinstance(uid, int) or not 0 < uid <= _MAX_USER_ID:
            raise r.fail(f"{path}.id", "expected a positive integer (the user's databaseId)")
        if any(a.login.lower() == login.lower() for a in approvers):
            raise r.fail(f"{path}.login", f"{show(login)} is listed twice")
        if any(a.id == uid for a in approvers):
            raise r.fail(f"{path}.id", f"{uid} is listed twice")
        approvers.append(Approver(login, uid))

    in_repositories = {repo.full_name.lower() for repo in repos}
    gates: list[Gate] = []
    for i, item in enumerate(_capped(r, m.get("gates", []), "process.gates", MAX_GATES)):
        path = f"process.gates[{i}]"
        g = r.mapping(item, path, {"phase", "issue"}, {"phase", "issue"})
        phase = r.string(g["phase"], f"{path}.phase")
        issue = r.string(g["issue"], f"{path}.issue")
        match = REF.fullmatch(issue)
        if match is None:
            raise r.fail(f"{path}.issue", "expected owner/repo#N")
        if f"{match[1]}/{match[2]}".lower() not in in_repositories:
            raise r.fail(f"{path}.issue", f"{match[1]}/{match[2]} is not in repositories")
        for j, earlier in enumerate(gates):
            if earlier.phase == phase:
                raise r.fail(f"{path}.phase", f"phase {show(phase)} has a gate already (gates[{j}])")
            if earlier.issue.lower() == issue.lower():
                raise r.fail(f"{path}.issue", f"{issue} is a gate already (gates[{j}])")
        gates.append(Gate(phase, issue))
    return Process(method, tuple(active), dependencies, phase_field, tuple(approvers), tuple(gates))


def _capped(r: Reader, value: object, path: str, limit: int) -> list[Any]:
    items = r.seq(value, path)
    if len(items) > limit:
        raise r.fail(path, f"at most {limit} entries")
    return items


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

    if board.process.phase_field:  # only a waterfall board has one (_parse_process)
        _cross_check_process(r, board)

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


def _cross_check_process(r: Reader, board: Board) -> None:
    process, rules = board.process, board.rules
    phase = board.field_named(process.phase_field)
    if phase is None:
        raise r.fail("process.phase_field", f"names field {show(process.phase_field)}, which is not in fields")
    if phase.type != "single_select":
        raise r.fail("process.phase_field", f"field {show(phase.name)} is {phase.type}, not single_select")
    for role, name in (("status", rules.status_field), ("area", rules.area_field)):
        if phase.name == name:
            raise r.fail("process.phase_field", f"{show(name)} is the {role} field, not a phase field")
    if len(phase.options) > MAX_PHASES:
        count = len(phase.options)
        shown = show(phase.name)
        raise r.fail("process.phase_field", f"field {shown} has {count} options, at most {MAX_PHASES} phases")
    status = board.field_named(rules.status_field)
    status_options = {o.name for o in status.options} if status and status.type == "single_select" else set()
    done = {rules.status.closed, rules.status.merged}
    for i, name in enumerate(process.active_statuses):
        path = f"process.active_statuses[{i}]"
        if name not in status_options:
            raise r.fail(path, f"{show(name)} is not an option of {show(rules.status_field)}")
        if name in done:
            raise r.fail(path, f"{show(name)} is a done status (rules.status.closed or merged)")
    names = [o.name for o in phase.options]
    for i, gate in enumerate(process.gates):
        path = f"process.gates[{i}].phase"
        if gate.phase not in names:
            listed = ", ".join(names)
            raise r.fail(path, f"{show(gate.phase)} is not an option of {show(phase.name)} (options: {listed})")
        if gate.phase == names[-1]:
            raise r.fail(path, f"{show(gate.phase)} is the last phase, so its gate would gate nothing")


def load_board(path: str | Path, *, check_fields: bool = True) -> Board:
    """Read and validate a board.yaml. Uses a custom YAML loader that refuses hostile inputs."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as err:
        raise ConfigError(f"{p}: cannot read the board file ({err.strerror})") from None

    data = _safe_load(text, str(p))
    return parse_board(data, str(p), check_fields=check_fields)
