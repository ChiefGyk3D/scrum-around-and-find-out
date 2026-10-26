# SPDX-License-Identifier: Apache-2.0
"""Resolving the evidence pointers of the profiles (spec 1.5): `load_verified_agents` and what it returns.

`parse_agents` checks the FORM of every pointer and which claim it may support, and reads no evidence file. This module
is the second stage. It reads the files named by `evidence_sources` (the lessons, the outcomes log), confined to the
directory of agents.yaml and never through a symbolic link, and the base agents.yaml itself for `config:` pointers, and
it resolves every pointer:

- `lessons:<slug>` names a heading of the lessons file (the slug function is `profile.slugify`);
- `outcomes:v1:<range>:<subject>:<metric><op><number>` is computed with `outcomes.query_outcomes`, and the claim must be
  true of the log; no data is reported as such, never as zero;
- `config:<RFC 6901 pointer>` addresses the BASE agents.yaml (never the merge with the local override) and resolves only
  through a per-setting allowlist, to the citing agent's own endpoint.

A resolution problem is never raised from here. It is attributed to the agent that cites the pointer and returned in
`errors_by_agent`; a form error is global and raises before any file is read. Strict callers (the generator, `safo
profiles verify`, `safo validate`) call `require_clean()`. `safo route` reads the same object and degrades only the
agents listed in `errors_by_agent`, so there is no second, unverified load path.

What this proves is that a cited measurement exists and says what the pointer states. Whether it is relevant to the
claim is a human judgement (docs/limits.md).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Any

from safo.agentsfile import Agent, AgentsFile, load_with_base
from safo.errors import ConfigError
from safo.outcomes import MAX_LOG_BYTES, Outcome, compare, parse_log, query_outcomes
from safo.profile import (
    CONFIG_FIELDS,
    ENDPOINT_INDEX,
    METRIC,
    Evidence,
    ModelLayer,
    Profile,
    block_constructs,
    read_confined,
    slugify,
)

MAX_LESSONS = 1024 * 1024
MAX_SHOWN = 20  # problems named in the message of require_clean
MAX_HEADING_TEXT = 2000  # a longer heading cannot be cited (a pointer's slug is at most 200 characters)
INDEX = re.compile(r"0|[1-9][0-9]*")


class EvidenceError(Exception):
    """One pointer does not resolve; the message says why and never carries the evidence file's text."""


@dataclass(frozen=True)
class Resolution:
    """A resolved pointer: where it was cited, its kind, what it resolved to, and a digest of that evidence."""

    field: str
    kind: str
    subject: str
    excerpt_digest: str


@dataclass(frozen=True)
class Item:
    """One pointer in a profile, with the claim it supports."""

    field: str  # a dotted path, such as agents.codex.profile.dont[0]
    claim: str  # claim, context_ceiling, output_cap or thinking: the row of the compatibility table
    text: str  # the claim as a reader sees it
    evidence: Evidence


@dataclass(frozen=True)
class VerifiedAgents:
    agents: AgentsFile
    resolutions: tuple[Resolution, ...]
    errors_by_agent: dict[str, tuple[str, ...]]

    def require_clean(self) -> None:
        """ConfigError naming every agent with a problem; the strict callers have no way around this."""
        if not self.errors_by_agent:
            return
        lines = [f"{agent}: {problem}" for agent, problems in self.errors_by_agent.items() for problem in problems]
        more = f" (and {len(lines) - MAX_SHOWN} more)" if len(lines) > MAX_SHOWN else ""
        raise ConfigError("evidence does not resolve: " + "; ".join(lines[:MAX_SHOWN]) + more)

    def status_of(self, agent_id: str) -> str:
        """profiled, unmeasured, migrating (no profile yet, allowed until the migration ends) or none (a human)."""
        agent = self.agents.agent(agent_id)
        if agent.kind == "human":
            return "none"
        if agent_id in self.errors_by_agent:
            return "unmeasured"
        if agent.profile is None:
            return "migrating" if agent_id in self.agents.profile_migration else "unmeasured"
        return agent.profile.status


# -- the pieces of a profile that carry a pointer ---------------------------------------------------------------------


def iter_evidence(agent: Agent) -> Iterator[Item]:
    """Every pointer of the agent's profile, in a fixed order, with the claim it supports."""
    p = agent.profile
    if p is None:
        return
    base = f"agents.{agent.id}.profile"
    yield from _profile_items(base, p)
    for model, layer in p.models:
        yield from _layer_items(f"{base}.models.{model}", layer)


def _profile_items(base: str, p: Profile) -> Iterator[Item]:
    for key in ("context_ceiling", "output_cap"):
        limit = getattr(p, key)
        if limit is not None:
            yield Item(f"{base}.{key}", key, f"{key} {limit.value}", limit.evidence)
    yield from _layer_items(base, p)
    if p.review_gate is not None:
        for i, check in enumerate(p.review_gate.checks):
            yield Item(f"{base}.review_gate.checks[{i}]", "claim", f"review check {check.code}", check.evidence)


def _layer_items(base: str, layer: Profile | ModelLayer) -> Iterator[Item]:
    if layer.thinking is not None:
        yield Item(f"{base}.thinking", "thinking", f"thinking {layer.thinking.value}", layer.thinking.evidence)
    for key in ("do", "dont"):
        for i, c in enumerate(getattr(layer, key)):
            yield Item(f"{base}.{key}[{i}]", "claim", c.text, c.evidence)
    for i, m in enumerate(layer.must_not_get):
        yield Item(f"{base}.must_not_get[{i}]", "claim", f"must not get {m.shape}", m.evidence)


def heading_text(line: str) -> str:
    """The text of an ATX heading line, or '' when it is not one. A hand parse, linear in the line: no backtracking."""
    body = line.lstrip(" ")
    if len(line) - len(body) > 3:
        return ""
    hashes = len(body) - len(body.lstrip("#"))
    if not 1 <= hashes <= 6 or len(body) == hashes or body[hashes] not in " \t":
        return ""
    text = body[hashes:].strip(" \t")
    stripped = text.rstrip("#")
    if len(stripped) < len(text) and (not stripped or stripped[-1] in " \t"):
        text = stripped.rstrip(" \t")  # the optional closing sequence
    return text


# -- lessons ---------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Section:
    heading: str
    first_line: str
    digest: str


def lesson_sections(text: str) -> dict[str, Section]:
    """The headings of a Markdown file by GitHub slug: fenced code is not searched, a repeated slug gets -1, -2, ..."""
    found: dict[str, Section] = {}
    seen: dict[str, int] = {}
    current: tuple[str, str, list[str]] | None = None  # slug, heading, body lines

    def close() -> None:
        if current is None:
            return
        slug, heading, body = current
        first = next((x.strip() for x in body if x.strip()), "")
        digest = hashlib.sha256((heading + "\n" + "\n".join(body).strip()).encode()).hexdigest()
        found[slug] = Section(heading, first[:200], digest)

    lines = text.splitlines()
    for line, inside in zip(lines, block_constructs(lines), strict=True):
        if not inside:
            title = heading_text(line)
            if title and len(title) <= MAX_HEADING_TEXT:
                close()
                slug = slugify(title)
                count = seen.get(slug, 0)
                seen[slug] = count + 1
                current = (slug if count == 0 else f"{slug}-{count}", title, [])
                continue
        if current is not None:
            current[2].append(line)
    close()
    return found


# -- config pointers ---------------------------------------------------------------------------------------------------


def _segments(ref: str) -> list[str]:
    if ref == "":
        return []
    if not ref.startswith("/"):
        raise EvidenceError("a JSON Pointer is empty or starts with /")
    out = []
    for raw in ref[1:].split("/"):
        if re.search(r"~(?![01])", raw):
            raise EvidenceError("a ~ in a JSON Pointer is followed by 0 or 1")
        out.append(raw.replace("~1", "/").replace("~0", "~"))
    return out


def pointer_get(data: object, ref: str) -> Any:
    """RFC 6901: the value `ref` addresses in `data`, or EvidenceError. `-` and non-canonical indexes do not resolve."""
    cur = data
    for seg in _segments(ref):
        if isinstance(cur, Mapping):
            key = next((k for k in cur if k == seg or (not isinstance(k, str) and str(k) == seg)), None)
            if key is None:
                raise EvidenceError("the pointer names a key that is not there")
            cur = cur[key]
        elif isinstance(cur, list):
            if INDEX.fullmatch(seg) is None or int(seg) >= len(cur):
                raise EvidenceError("the pointer names a list index that is not there")
            cur = cur[int(seg)]
        else:
            raise EvidenceError("the pointer goes into a value that has no members")
    return cur


def resolve_config(base: object, ref: str, claim: str, agent_id: str) -> tuple[str, str]:
    """(subject, digest) of an allowlisted endpoint field of `agent_id`, read from the base document."""
    seg = _segments(ref)
    fields = CONFIG_FIELDS.get(claim, {})
    if not (
        len(seg) >= 5
        and seg[0] == "agents"
        and seg[2] == "endpoints"
        and ENDPOINT_INDEX.fullmatch(seg[3])
        and fields.get(seg[4]) == len(seg)
        and all(seg)
    ):
        allowed = ", ".join(f"an endpoint {f}" for f in fields) or "none"
        raise EvidenceError(f"the pointer is not on the allowlist for {claim} (allowed: {allowed})")
    if seg[1] != agent_id:
        raise EvidenceError("a config pointer must address the citing agent's own endpoint")
    value = pointer_get(base, ref)
    name = seg[4]
    if name == "think":
        if not isinstance(value, bool):
            raise EvidenceError("think is not a boolean")
        subject = f"think = {'true' if value else 'false'}"
    else:
        if isinstance(value, bool) or not isinstance(value, int):
            raise EvidenceError(f"{name} is not an integer")
        subject = f"{name} = {value}" if name == "num_ctx_max" else f"{name}[{seg[5]}] = {value}"
    return subject, hashlib.sha256(f"config:{ref}={subject}".encode()).hexdigest()


# -- outcomes ----------------------------------------------------------------------------------------------------------


def _shown(value: Fraction) -> str:
    return str(value.numerator) if value.denominator == 1 else f"{float(value):.6g}"


def resolve_outcomes(ref: str, rows: list[Outcome], doc: AgentsFile) -> tuple[str, str]:
    """(subject, digest) when the log makes the statement true; else EvidenceError (no data, false, bad subject)."""
    _, span, subject, expression = ref.split(":", 3)
    m = METRIC.fullmatch(expression)
    if m is None:
        raise EvidenceError("the outcomes statement is not <metric><op><number>")
    metric, op, number = m.groups()
    agent_id, _, model = subject.partition("/")
    try:
        agent = doc.agent(agent_id)
    except ConfigError:
        raise EvidenceError(f"the outcomes subject names an unknown agent {agent_id!r}") from None
    if model and model not in {name for name, _ in (agent.profile.models if agent.profile else ())}:
        raise EvidenceError(f"the outcomes subject names {model!r}, which is not a model layer of {agent_id}")
    result = query_outcomes(rows, span, agent_id, model or None)
    value = result.value(metric)
    where = f"{subject} {span}"
    if value is None:
        raise EvidenceError(f"no data: {where} has no value for {metric} ({result.records} matching records)")
    if not compare(value, op, number):
        raise EvidenceError(f"the claim is false: {where}: {metric} = {_shown(value)}, not {op}{number}")
    digest = hashlib.sha256(f"{where}|{metric}|{value}|{result.records}".encode()).hexdigest()
    return f"{where}: {metric} = {_shown(value)} (claim {metric}{op}{number} holds)", digest


# -- the entry point ---------------------------------------------------------------------------------------------------


class _Sources:
    """The evidence files, each read once, each either its content or the reason it cannot be used."""

    def __init__(self, root: Path, doc: AgentsFile) -> None:
        self.root = root
        self.doc = doc
        self._lessons: dict[str, Section] | str | None = None
        self._outcomes: list[Outcome] | str | None = None

    def lessons(self) -> dict[str, Section] | str:
        if self._lessons is None:
            rel = self.doc.evidence_sources.lessons
            try:
                raw = read_confined(self.root, rel, MAX_LESSONS)
                if len(raw) > MAX_LESSONS:
                    self._lessons = f"the lessons file {rel} is larger than {MAX_LESSONS} bytes"
                else:
                    self._lessons = lesson_sections(raw.decode("utf-8"))
            except UnicodeDecodeError:
                self._lessons = f"the lessons file {rel} is not valid UTF-8"
            except OSError:
                self._lessons = f"cannot read the lessons file {rel} (missing, a symbolic link or not a regular file)"
        return self._lessons

    def outcomes(self) -> list[Outcome] | str:
        if self._outcomes is None:
            self._outcomes = read_outcomes(self.root, self.doc)
        return self._outcomes


def read_outcomes(root: Path, doc: AgentsFile) -> list[Outcome] | str:
    """The records of the outcomes source, or the reason it cannot be used. Confined to `root`, never through a link."""
    rel = doc.evidence_sources.outcomes
    if not rel:
        return "no outcomes source: set evidence_sources.outcomes in agents.yaml"
    try:
        raw = read_confined(root, rel, MAX_LOG_BYTES)
        if len(raw) > MAX_LOG_BYTES:
            return f"the outcomes log {rel} is larger than {MAX_LOG_BYTES} bytes"
        return parse_log(raw, rel)
    except ConfigError as err:
        return f"the outcomes log {rel} is not valid: {err}"
    except OSError:
        return f"cannot read the outcomes log {rel} (missing, a symbolic link or not a regular file)"


def _resolve(item: Item, agent_id: str, sources: _Sources, base: object) -> tuple[str, str]:
    ev = item.evidence
    if ev.kind == "lessons":
        sections = sources.lessons()
        if isinstance(sections, str):
            raise EvidenceError(sections)
        found = sections.get(ev.ref)
        if found is None:
            raise EvidenceError(f"lessons:{ev.ref} names no heading of {sources.doc.evidence_sources.lessons}")
        return f"{found.heading}: {found.first_line}", found.digest
    if ev.kind == "outcomes":
        rows = sources.outcomes()
        if isinstance(rows, str):
            raise EvidenceError(rows)
        return resolve_outcomes(ev.ref, rows, sources.doc)
    return resolve_config(base, ev.ref, item.claim, agent_id)


def verify_document(doc: AgentsFile, base: object, root: Path) -> VerifiedAgents:
    """Resolve every pointer of a parsed document. `base` is the base agents.yaml data and `root` its directory."""
    sources = _Sources(root, doc)
    resolutions: list[Resolution] = []
    errors: dict[str, list[str]] = {}
    for agent in doc.agents:
        for item in iter_evidence(agent):
            try:
                subject, digest = _resolve(item, agent.id, sources, base)
            except EvidenceError as err:
                errors.setdefault(agent.id, []).append(f"{item.field}: {err}")
                continue
            resolutions.append(Resolution(item.field, item.evidence.kind, subject, digest))
    return VerifiedAgents(doc, tuple(resolutions), {k: tuple(v) for k, v in errors.items()})


def load_verified_agents(path: str | Path, local: str | Path | None = None, *, trusted: bool = True) -> VerifiedAgents:
    """Load agents.yaml (and an optional local override) and resolve every evidence pointer.

    A form error raises ConfigError, as for any agents file. A pointer that does not resolve is returned in
    `errors_by_agent`, attributed to the agent that cites it. `trusted` is the policy for a person's private file
    (spec 7.2, rule 2); False is for a repository checkout, where review is the control.
    """
    doc, base = load_with_base(path, local, trusted=trusted)
    return verify_document(doc, base, Path(path).parent)
