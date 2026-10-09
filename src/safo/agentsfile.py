# SPDX-License-Identifier: MIT
"""agents.yaml: who does what, how much room each has, and which agent a task shape goes to.

Validated like board.yaml (every error names the key) and read with `yaml.safe_load` only. `docs/routing.md` is
generated from it by `scripts/gen_routing.py`, and `safo route` reads it with the live headroom.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from safo import netguard
from safo.errors import ConfigError
from safo.schema import Reader, _safe_load

KINDS = ("claude", "codex", "copilot", "ollama", "human")
ROLES = ("general", "embedding", "guard")
METERS = ("five_hour", "weekly", "monthly_percent")


@dataclass(frozen=True)
class Endpoint:
    """One Ollama server. The URL comes from configuration; a real one lives in a git-ignored local file."""

    id: str
    url: str = field(repr=False)
    roles: tuple[str, ...]
    models: tuple[str, ...]  # the only models safo will ever ask this endpoint for
    num_ctx_max: int
    think: bool  # the default for a request; cheap tasks send false
    protected_models: tuple[str, ...] = ()  # resident for other services: never evicted
    shared_with_production: bool = False
    note: str = ""
    # the num_ctx each resident model is loaded with: send exactly this
    loaded_num_ctx: tuple[tuple[str, int], ...] = ()
    # allowed beside the protected residents, loaded when asked for and unloaded after keep_alive; never resident
    on_demand_models: tuple[str, ...] = ()
    keep_alive: str = ""

    def loaded_ctx(self, model: str) -> int | None:
        return next((n for name, n in self.loaded_num_ctx if name == model), None)

    def keep_alive_for(self, model: str) -> str:
        return self.keep_alive if model in self.on_demand_models else ""

    def ctx_for(self, model: str) -> int:
        """The num_ctx to send: a resident model's loaded value, else the endpoint's cap."""
        return self.loaded_ctx(model) or self.num_ctx_max


@dataclass(frozen=True)
class Agent:
    id: str
    name: str
    kind: str
    role: str
    model: str = ""
    approval_required: bool = False
    limits: tuple[tuple[str, str], ...] = ()
    strengths: tuple[str, ...] = ()
    constraints: tuple[str, ...] = ()
    endpoints: tuple[Endpoint, ...] = ()

    def limit(self, key: str) -> str | None:
        return next((v for k, v in self.limits if k == key), None)


@dataclass(frozen=True)
class Shape:
    name: str
    description: str
    prefer: tuple[str, ...]
    fallback: tuple[str, ...]
    reviewer: tuple[str, ...]
    note: str = ""
    local_role: str = ""  # for a shape the local agent can take: which kind of endpoint
    local_model: str = ""  # optional: a specific model (an embedding model, say)

    @property
    def chain(self) -> tuple[str, ...]:
        return self.prefer + self.fallback


@dataclass(frozen=True)
class Threshold:
    agent: str
    meter: str
    above: float
    then: str


@dataclass(frozen=True)
class Hooks:
    """What the Claude Code hooks (`safo hooks`) enforce. All of it is configuration; nothing here is a secret."""

    # a brief for an approval_required model must contain this marker, which is typed by hand and is not a credential
    approval_token: str = "OPUS-APPROVED"  # noqa: S105
    max_state_age_seconds: int = 300  # how long a probe is trusted; past it the guard re-probes lazily, bounded
    local_step_markers: tuple[str, ...] = ("safo local run", "llm-local")  # any one names the brief's local step
    na_marker: str = "local-llm: n/a -"  # followed by a reason, it says why the brief has no local step


@dataclass(frozen=True)
class AgentsFile:
    agents: tuple[Agent, ...]
    shapes: tuple[Shape, ...]
    thresholds: tuple[Threshold, ...]
    rules_of_thumb: tuple[str, ...]
    warnings: tuple[str, ...] = ()  # a problem that falls back instead of failing
    hooks: Hooks = field(default_factory=Hooks)

    def agent(self, agent_id: str) -> Agent:
        found = next((a for a in self.agents if a.id == agent_id), None)
        if found is None:
            raise ConfigError(f"agents.yaml has no agent {agent_id!r} (agents: {', '.join(a.id for a in self.agents)})")
        return found

    def shape(self, name: str) -> Shape:
        found = next((s for s in self.shapes if s.name == name), None)
        if found is None:
            raise ConfigError(f"agents.yaml has no shape {name!r} (shapes: {', '.join(s.name for s in self.shapes)})")
        return found

    def monthly_allowance(self) -> int | None:
        for a in self.agents:
            raw = a.limit("monthly_ai_credits")
            if a.kind == "copilot" and raw and raw.isdigit():
                return int(raw)
        return None


MAX_KEEP_ALIVE_SECONDS = 600  # an on-demand model must not linger on a shared GPU


def _short_duration(text: str) -> bool:
    match = re.fullmatch(r"([1-9][0-9]{0,5})([sm])", text)
    if match is None:
        return False
    return int(match[1]) * (60 if match[2] == "m" else 1) <= MAX_KEEP_ALIVE_SECONDS


def _strings(r: Reader, value: object, path: str) -> tuple[str, ...]:
    return tuple(r.string(x, f"{path}[{i}]") for i, x in enumerate(r.seq(value if value is not None else [], path)))


def _endpoints(r: Reader, value: object, path: str) -> tuple[Endpoint, ...]:
    out: list[Endpoint] = []
    for i, raw in enumerate(r.seq(value if value is not None else [], path)):
        p = f"{path}[{i}]"
        m = r.mapping(
            raw,
            p,
            {
                "id",
                "url",
                "roles",
                "models",
                "protected_models",
                "num_ctx_max",
                "loaded_num_ctx",
                "on_demand_models",
                "keep_alive",
                "think",
                "shared_with_production",
                "note",
            },
            {"id", "url", "roles", "models", "num_ctx_max"},
        )
        url = r.string(m["url"], f"{p}.url")
        parts = urlsplit(url)
        if (
            parts.scheme not in ("http", "https")
            or not parts.hostname
            or parts.username
            or parts.password
            or parts.query
            or parts.fragment
        ):
            raise r.fail(f"{p}.url", "expected http(s)://host:port with no credentials in it")
        if netguard.literal_blocked(parts.hostname):
            raise r.fail(
                f"{p}.url", "expected a loopback or private LAN address, not link-local, unspecified or metadata"
            )
        roles = _strings(r, m["roles"], f"{p}.roles")
        for j, role in enumerate(roles):
            r.choice(role, f"{p}.roles[{j}]", ROLES)
        models = _strings(r, m["models"], f"{p}.models")
        protected = _strings(r, m.get("protected_models"), f"{p}.protected_models")
        if not models:
            raise r.fail(f"{p}.models", "needs at least one model")
        on_demand = _strings(r, m.get("on_demand_models"), f"{p}.on_demand_models")
        for name in on_demand:
            if name not in models:
                raise r.fail(f"{p}.on_demand_models", f"{name!r} is not an allowed model")
            if name in protected:
                raise r.fail(f"{p}.on_demand_models", f"{name!r} is also protected; a model is resident or on demand")
        keep_alive = r.string(m.get("keep_alive", ""), f"{p}.keep_alive", empty=True)
        if (on_demand or keep_alive) and not _short_duration(keep_alive):
            raise r.fail(f"{p}.keep_alive", "expected a short duration such as 30s or 5m (at most 10 minutes)")
        evicting = [x for x in models if protected and x not in protected and x not in on_demand]
        if evicting:
            raise r.fail(
                f"{p}.models",
                f"{evicting[0]!r} is not a protected model; loading it on an endpoint with protected models "
                "would evict one",
            )
        raw_ctx = m.get("loaded_num_ctx") or {}
        loaded_raw = r.mapping(raw_ctx, f"{p}.loaded_num_ctx", set(raw_ctx))
        loaded = tuple((str(k), r.integer(v, f"{p}.loaded_num_ctx.{k}", minimum=256)) for k, v in loaded_raw.items())
        cap = r.integer(m["num_ctx_max"], f"{p}.num_ctx_max", minimum=256)
        if any(n > cap for _, n in loaded):
            raise r.fail(f"{p}.loaded_num_ctx", "loaded context exceeds num_ctx_max")
        for name, _ in loaded:
            if name not in models:
                raise r.fail(f"{p}.loaded_num_ctx", f"{name!r} is not an allowed model")
        unpinned = [x for x in models if protected and x not in dict(loaded)]
        if unpinned:
            raise r.fail(
                f"{p}.loaded_num_ctx",
                f"{unpinned[0]!r} is on an endpoint with protected models, so it needs the num_ctx it is loaded "
                "with: any other value reloads it and can evict a resident",
            )
        flags = {}
        for key in ("think", "shared_with_production"):
            flags[key] = m.get(key, False)
            if not isinstance(flags[key], bool):
                raise r.fail(f"{p}.{key}", "expected true or false")
        out.append(
            Endpoint(
                r.string(m["id"], f"{p}.id"),
                url.rstrip("/"),
                roles,
                models,
                r.integer(m["num_ctx_max"], f"{p}.num_ctx_max", minimum=256),
                flags["think"],
                protected,
                flags["shared_with_production"],
                r.string(m.get("note", ""), f"{p}.note", empty=True),
                loaded,
                on_demand,
                keep_alive,
            )
        )
    ids = [e.id for e in out]
    if len(set(ids)) != len(ids):
        raise r.fail(path, "endpoint ids must be unique")
    return tuple(out)


def _hooks(r: Reader, value: object) -> Hooks:
    default = Hooks()
    m = r.mapping(
        value if value is not None else {},
        "hooks",
        {"approval_token", "max_state_age_seconds", "local_step_markers", "na_marker"},
    )
    token = r.string(m.get("approval_token", default.approval_token), "hooks.approval_token")
    if len(token) < 8 or token != token.strip() or any(c.isspace() for c in token):
        raise r.fail("hooks.approval_token", "expected at least 8 characters with no whitespace")
    age = r.integer(
        m.get("max_state_age_seconds", default.max_state_age_seconds), "hooks.max_state_age_seconds", minimum=60
    )
    if age > 7 * 86400:
        raise r.fail("hooks.max_state_age_seconds", "expected at most a week (604800)")
    markers = _strings(r, m.get("local_step_markers", list(default.local_step_markers)), "hooks.local_step_markers")
    if not markers:
        raise r.fail("hooks.local_step_markers", "needs at least one marker")
    na = r.string(m.get("na_marker", default.na_marker), "hooks.na_marker")
    return Hooks(token, age, tuple(x.lower() for x in markers), na.strip().lower())


def parse_agents(data: object, source: str = "agents.yaml") -> AgentsFile:
    r = Reader(source)
    top = r.mapping(
        data,
        "",
        {"version", "agents", "shapes", "thresholds", "rules_of_thumb", "hooks"},
        {"version", "agents", "shapes"},
    )
    if top["version"] != 1:
        raise r.fail("version", "only version 1 is supported")

    agents: list[Agent] = []
    for agent_id, raw in r.mapping(top["agents"], "agents", set(top["agents"] or {})).items():
        path = f"agents.{agent_id}"
        m = r.mapping(
            raw,
            path,
            {"name", "kind", "role", "model", "approval_required", "limits", "strengths", "constraints", "endpoints"},
            {"name", "kind", "role"},
        )
        limits_raw = r.mapping(m.get("limits", {}), f"{path}.limits", set(m.get("limits") or {}))
        approval = m.get("approval_required", False)
        if not isinstance(approval, bool):
            raise r.fail(f"{path}.approval_required", "expected true or false")
        endpoints = _endpoints(r, m.get("endpoints"), f"{path}.endpoints")
        kind = r.choice(m["kind"], f"{path}.kind", KINDS)
        if kind == "ollama" and not endpoints:
            raise r.fail(f"{path}.endpoints", "an ollama agent needs at least one endpoint")
        if kind != "ollama" and endpoints:
            raise r.fail(f"{path}.endpoints", "only an ollama agent has endpoints")
        agents.append(
            Agent(
                str(agent_id),
                r.string(m["name"], f"{path}.name"),
                kind,
                r.string(m["role"], f"{path}.role"),
                r.string(m.get("model", ""), f"{path}.model", empty=True),
                approval,
                tuple((str(k), str(v)) for k, v in limits_raw.items()),
                _strings(r, m.get("strengths"), f"{path}.strengths"),
                _strings(r, m.get("constraints"), f"{path}.constraints"),
                endpoints,
            )
        )
    known = {a.id for a in agents}

    def agent_ids(value: object, path: str) -> tuple[str, ...]:
        ids = _strings(r, value, path)
        for i, x in enumerate(ids):
            if x not in known:
                raise r.fail(f"{path}[{i}]", f"{x!r} is not an agent in agents (agents: {', '.join(sorted(known))})")
        return ids

    warnings: list[str] = []
    shapes: list[Shape] = []
    for name, raw in r.mapping(top["shapes"], "shapes", set(top["shapes"] or {})).items():
        path = f"shapes.{name}"
        m = r.mapping(
            raw, path, {"description", "prefer", "fallback", "reviewer", "note", "local"}, {"description", "prefer"}
        )
        prefer = agent_ids(m["prefer"], f"{path}.prefer")
        if not prefer:
            raise r.fail(f"{path}.prefer", "needs at least one agent")
        fallback = agent_ids(m.get("fallback"), f"{path}.fallback")
        local = r.mapping(m.get("local", {}), f"{path}.local", {"role", "model"})
        local_role = r.choice(local.get("role", "general"), f"{path}.local.role", ROLES) if m.get("local") else ""
        local_agent = next((a for a in agents if a.kind == "ollama" and a.id in prefer + fallback), None)
        if local_role and local_agent is None:
            raise r.fail(f"{path}.local", "names a local endpoint role, but no ollama agent is in prefer or fallback")
        local_model = r.string(local.get("model", ""), f"{path}.local.model", empty=True)
        if local_agent and local_model:
            hosts = [e for e in local_agent.endpoints if local_role in e.roles]
            if not any(local_model in e.models for e in hosts):
                warnings.append(
                    f"{path}.local.model: {local_model!r} is not an allowed model of any {local_role} endpoint; "
                    "falling back to the endpoint's first allowed model"
                )
                local_model = ""
        shapes.append(
            Shape(
                str(name),
                r.string(m["description"], f"{path}.description"),
                prefer,
                fallback,
                agent_ids(m.get("reviewer"), f"{path}.reviewer"),
                r.string(m.get("note", ""), f"{path}.note", empty=True),
                local_role,
                local_model,
            )
        )

    thresholds: list[Threshold] = []
    for i, raw in enumerate(r.seq(top.get("thresholds", []), "thresholds")):
        path = f"thresholds[{i}]"
        m = r.mapping(raw, path, {"agent", "meter", "above", "then"}, {"agent", "meter", "above", "then"})
        above = m["above"]
        if isinstance(above, bool) or not isinstance(above, int | float) or not 0 <= above <= 100:
            raise r.fail(f"{path}.above", "expected a percentage from 0 to 100")
        thresholds.append(
            Threshold(
                agent_ids([m["agent"]], f"{path}.agent")[0],
                r.choice(m["meter"], f"{path}.meter", METERS),
                float(above),
                agent_ids([m["then"]], f"{path}.then")[0],
            )
        )
    return AgentsFile(
        tuple(agents),
        tuple(shapes),
        tuple(thresholds),
        _strings(r, top.get("rules_of_thumb"), "rules_of_thumb"),
        tuple(warnings),
        _hooks(r, top.get("hooks")),
    )


def load_agents(path: str | Path) -> AgentsFile:
    p = Path(path)
    return parse_agents(_read_yaml(p), str(p))


def merge(base: Any, over: Any) -> Any:
    """Mappings merge key by key; anything else (a list, a string) in `over` replaces the base value."""
    if isinstance(base, dict) and isinstance(over, dict):
        return {**base, **{k: merge(base[k], v) if k in base else v for k, v in over.items()}}
    return over


def load_agents_merged(path: str | Path, local: str | Path | None) -> AgentsFile:
    """agents.yaml with an optional local file merged over it: where real endpoints live, git-ignored."""
    base = Path(path)
    data = _read_yaml(base)
    source = str(base)
    if local is not None and Path(local).exists():
        data = merge(data, _read_yaml(Path(local)))
        source = f"{base} (merged with {Path(local).name})"
    return parse_agents(data, source)


def _read_yaml(p: Path) -> Any:
    try:
        from safo.guardlog import bounded_read

        try:
            raw = bounded_read(p)
        except ValueError:
            raise ConfigError("agents file exceeds maximum size or is not regular") from None
        if len(raw) > 1_048_576:
            raise ConfigError("agents file exceeds maximum size")
        text = raw.decode("utf-8")
        # Inspect events before construction so alias and merge refusals have distinct diagnostics.
        for event in yaml.parse(text):
            if isinstance(event, yaml.events.AliasEvent):
                raise ConfigError("agents file: aliases are not allowed")
            if isinstance(event, yaml.events.ScalarEvent) and event.value == "<<":
                raise ConfigError("agents file: merge keys (<<) are not allowed")
        return _safe_load(text, "agents file")
    except yaml.YAMLError:
        raise ConfigError("agents file: not valid YAML") from None
    except (OSError, UnicodeError, ValueError):
        raise ConfigError("cannot read the agents file") from None
