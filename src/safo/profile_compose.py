# SPDX-License-Identifier: Apache-2.0
"""The composition check for the generated pairs (issue #107): a model file and its caller file, from one source.

Every profiled agent renders a MODEL file (what the model reads) and a CALLER file under `caller/` (guidance for whoever
briefs it). This module re-derives, from the verified profile alone, what each must hold and what must stay out of it,
and compares that with the rendered text. It is a second line behind the byte comparison of `--check`: that catches
drift between the files and the renderer; this catches a renderer that puts a sentence in the wrong audience's file.

- the caller file holds every section the profile requires (limits, do, do not, shapes, gate, layers, the unmeasured
  line) and the instructions for using the model file;
- the model file holds the fixed instructions of its harness, the persona and the brief;
- no sentence that is for the caller is in the model file, and none that is for the model is in the caller file. The
  one line both carry is the generated header, which is inert metadata and is removed before the comparison.

Pure functions; nothing here touches a file.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from safo.agentsfile import Agent
from safo.errors import ConfigError
from safo.evidence import VerifiedAgents
from safo.profile import BOUNDARY_PARAGRAPH, GENERATED_MARKER, Claim, ModelLayer, Profile
from safo.profile_render import (
    CALL_SETTING,
    CALLER_DIR,
    CALLER_USE,
    REVIEW_RULES,
    REVIEW_WORDING,
    SCOPE_RULES,
    TRACKING_RULE,
    UNMEASURED_LINE,
    Rendered,
    model_reads_gate,
    split_persona,
)

# the lines the local wrapper always carries, before the profile (kept in step with profile_render._local by the tests)
LOCAL_FIXED = (
    "You are a local model working on one task.",
    "Reply in exactly the format the task asks for, and nothing else.",
    "Code does the grouping and the counting; do not group, count or total anything yourself.",
)
# the shape of a rendered evidence pointer: no pointer is ever shown to a model
_POINTER = re.compile(r"\(`(?:lessons:|outcomes:v1:|config:/)")
_HEADING_CALLER = ("### Limits", "### Do", "### Do not", "### Must not be given", "### Review gate", "### Model layer:")
_HEADING_MODEL = ("### Brief", "### Review focus", "## Scope rules", "## Review rules", "## Task")


def caller_path(harness: str, agent_id: str) -> str:
    return f"{CALLER_DIR}/{harness}/{agent_id}.md"


def _norm(text: str) -> str:
    return " ".join(text.split())


def _body(rendered: Rendered) -> str:
    """The text of a file for comparison: the header line removed, whitespace collapsed."""
    lines = [x for x in rendered.data.decode("utf-8").split("\n") if GENERATED_MARKER not in x]
    return _norm("\n".join(lines))


def _lines(rendered: Rendered) -> list[str]:
    return [x.strip() for x in rendered.data.decode("utf-8").split("\n") if GENERATED_MARKER not in x]


def _claims(claims: tuple[Claim, ...]) -> list[str]:
    return [x for c in claims for x in (c.text, c.evidence.raw)]


def _traits(layer: Profile | ModelLayer) -> list[str]:
    return [
        *_claims(layer.do),
        *_claims(layer.dont),
        *[x for m in layer.must_not_get for x in (m.shape, m.evidence.raw)],
    ]


def caller_fragments(agent: Agent, p: Profile, harness: str, model_path: str) -> tuple[list[str], list[str]]:
    """(headings, sentences) the caller file must hold and the model file must not."""
    headings: list[str] = ["## Use"]
    parts: list[str] = [CALLER_USE[harness].format(model=model_path)]
    if p.status == "unmeasured":
        parts.append(UNMEASURED_LINE)
    if p.context_ceiling or p.output_cap or p.thinking:
        headings.append("### Limits")
        parts += [x.evidence.raw for x in (p.context_ceiling, p.output_cap, p.thinking) if x is not None]
    if p.do:
        headings.append("### Do")
    if p.dont:
        headings.append("### Do not")
    if p.must_not_get:
        headings.append("### Must not be given")
    parts += _traits(p)
    if p.review_gate is not None:
        headings.append("### Review gate")
        for c in p.review_gate.checks:
            parts.append(c.evidence.raw)
            parts.append(f"`{c.code}`" if model_reads_gate(p) else REVIEW_WORDING[c.code])
    for name, layer in p.models:
        headings.append(f"### Model layer: {name}")
        parts += _traits(layer)
        if layer.thinking is not None:
            parts.append(layer.thinking.evidence.raw)
        if layer.status == "unmeasured":
            parts.append(UNMEASURED_LINE)
    if harness == "local" and p.thinking is not None and p.thinking.value in ("off", "on"):
        parts.append(CALL_SETTING.format(flag="false" if p.thinking.value == "off" else "true"))
    return headings, parts


def model_fragments(agent: Agent, p: Profile, harness: str) -> tuple[list[str], list[str]]:
    """(headings, sentences) the model file must hold and the caller file must not."""
    headings: list[str] = []
    parts: list[str] = [BOUNDARY_PARAGRAPH]
    if harness == "claude":
        parts.append(TRACKING_RULE)
        if p.persona:
            parts.append(split_persona(p.persona_text, agent.id)[1])
    elif harness == "codex":
        parts.append(TRACKING_RULE)
    elif harness == "local":
        parts += [*LOCAL_FIXED, "{{task}}"]
    elif p.harness_mode == "review":
        headings.append("## Review rules")
        parts += REVIEW_RULES
    else:
        headings.append("## Scope rules")
        parts += [TRACKING_RULE, *SCOPE_RULES]
    brief = ""
    if p.brief is not None:
        brief = (p.brief.inline or p.brief.template_text).strip()
    if brief:
        headings.append("### Brief")
        parts.append(brief)
    if model_reads_gate(p) and p.review_gate is not None:
        headings.append("### Review focus")
        parts += [REVIEW_WORDING[c.code] for c in p.review_gate.checks]
    return headings, [x for x in parts if x.strip()]


def _has(normalized: str, needle: str) -> bool:
    return _norm(needle) in normalized


def composition_problems(v: VerifiedAgents, files: Mapping[str, Rendered]) -> list[str]:
    """What is wrong with the model/caller pairs among `files`. [] when every pair composes."""
    problems: list[str] = []
    expected_callers: set[str] = set()
    for agent in v.agents.agents:
        p = agent.profile
        if p is None or agent.kind == "human":
            continue
        harness = {"claude": "claude", "codex": "codex", "ollama": "local", "copilot": "copilot"}.get(agent.kind)
        if harness is None:
            continue
        model = next(
            (
                r
                for r in files.values()
                if r.agent_id == agent.id
                and r.role == "model"
                and r.harness == harness
                and r.path.endswith((".md", ".txt"))
            ),
            None,
        )
        path = caller_path(harness, agent.id)
        expected_callers.add(path)
        caller = files.get(path)
        if model is None or caller is None:
            problems.append(f"{agent.id}: the {'model' if model is None else 'caller'} file of the pair is missing")
            continue
        try:
            c_heads, c_parts = caller_fragments(agent, p, harness, model.path)
            m_heads, m_parts = model_fragments(agent, p, harness)
        except ConfigError as err:
            problems.append(f"{agent.id}: {err}")
            continue
        model_text, caller_text = _body(model), _body(caller)
        model_lines, caller_lines = _lines(model), _lines(caller)
        for what, text, lines, heads, parts in (
            ("caller", caller_text, caller_lines, c_heads, c_parts),
            ("model", model_text, model_lines, m_heads, m_parts),
        ):
            file = caller.path if what == "caller" else model.path
            for h in heads:
                if h not in lines:
                    problems.append(f"{file}: required {what} section {h!r} is missing")
            for s in parts:
                if not _has(text, s):
                    problems.append(f"{file}: required {what} text is missing: {_short(s)}")
        for s in c_parts:
            if _has(model_text, s):
                problems.append(f"{model.path}: caller-only text leaked into the model file: {_short(s)}")
        for s in m_parts:
            if _has(caller_text, s):
                problems.append(f"{caller.path}: model instruction leaked into the caller file: {_short(s)}")
        for line in model_lines:
            if any(line.startswith(h) for h in _HEADING_CALLER):
                problems.append(f"{model.path}: caller section heading in the model file: {line!r}")
        for line in caller_lines:
            if any(line.startswith(h) for h in _HEADING_MODEL):
                problems.append(f"{caller.path}: model section heading in the caller file: {line!r}")
        if _POINTER.search(model_text):
            problems.append(f"{model.path}: an evidence pointer is in the model file")
    for path, r in files.items():
        if r.role == "caller" and path not in expected_callers:
            problems.append(f"{path}: a caller file with no model file to pair with")
    return problems


def _short(text: str) -> str:
    one = _norm(text)
    return repr(one if len(one) <= 60 else one[:57] + "...")
