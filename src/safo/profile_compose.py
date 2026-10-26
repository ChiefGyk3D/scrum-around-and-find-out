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
from safo.profile import BOUNDARY_PARAGRAPH, Claim, ModelLayer, Profile
from safo.profile_render import (
    CALL_SETTING,
    CALLER_DIR,
    CALLER_USE,
    HARNESS_OF_KIND,
    REVIEW_RULES,
    REVIEW_WORDING,
    SCOPE_RULES,
    TRACKING_RULE,
    UNMEASURED_LINE,
    Rendered,
    model_reads_gate,
    split_header,
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
# Reserved section names, by whole name (lower case, one space between words), at any level and in any heading form.
# A name that merely begins with one of these ("Done criteria") is not reserved.
RESERVED_CALLER = frozenset(
    {"limits", "do", "do not", "must not be given", "review gate", "briefing guidance", "model layer:"}
)
RESERVED_MODEL = frozenset({"brief", "review focus", "scope rules", "review rules", "task", "model profile"})
# a model-side fragment shorter than this is not looked for in the caller file: a one-word brief is not a quotation
MIN_LEAK = 20
_ATX = re.compile(r"^ {0,3}#{1,6}[ \t]+(.*?)[ \t]*#*[ \t]*$")
_SETEXT = re.compile(r"^ {0,3}(?:=+|-+)[ \t]*$")
_HTML_HEADING = re.compile(r"<h[1-6](?:\s[^>]*)?>(.*?)</h[1-6]\s*>", re.IGNORECASE | re.DOTALL)
_TAG = re.compile(r"<[^>]*>")


def caller_path(harness: str, agent_id: str) -> str:
    return f"{CALLER_DIR}/{harness}/{agent_id}.md"


def _norm(text: str) -> str:
    return " ".join(text.split())


def _text(rendered: Rendered) -> str:
    """The file without its one header line, which split_header identifies strictly (a second marker is an error)."""
    body, _, _ = split_header(rendered.path, rendered.data)
    return body.decode("utf-8")


def heading_names(text: str) -> list[str]:
    """The names of every heading in `text`, normalized: ATX (any level), setext and HTML forms."""
    lines = text.split("\n")
    names: list[str] = []
    for i, line in enumerate(lines):
        m = _ATX.match(line)
        if m:
            names.append(_norm(m[1]).lower())
        if i and line.strip() and _SETEXT.match(line) and lines[i - 1].strip():
            names.append(_norm(lines[i - 1]).lower())
    names += [_norm(_TAG.sub("", m[1])).lower() for m in _HTML_HEADING.finditer(text)]
    return names


def _reserved(names: list[str], reserved: frozenset[str]) -> list[str]:
    return [n for n in names if n in reserved or any(n.startswith(r) for r in reserved if r.endswith(":"))]


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


def _quoted(normalized: str, needle: str) -> bool:
    """True when `needle` is in the text on word boundaries, whatever spacing or line breaks sit between its words."""
    return re.search(r"(?<!\w)" + re.escape(_norm(needle)) + r"(?!\w)", normalized) is not None


def composition_problems(v: VerifiedAgents, files: Mapping[str, Rendered]) -> list[str]:
    """What is wrong with the model/caller pairs among `files`. [] when every pair composes."""
    problems: list[str] = []
    expected_callers: set[str] = set()
    kinds = {a.id: a.kind for a in v.agents.agents}
    for path, r in files.items():
        if r.agent_id in kinds and kinds[r.agent_id] not in HARNESS_OF_KIND:
            problems.append(
                f"{path}: {r.agent_id} is kind {kinds[r.agent_id]!r}, which has no harness, but was rendered"
            )
    for agent in v.agents.agents:
        p = agent.profile
        harness = HARNESS_OF_KIND.get(agent.kind)
        if p is None or harness is None:
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
            model_raw, caller_raw = _text(model), _text(caller)
        except ConfigError as err:  # includes a header that is missing, doubled or not alone on its line
            problems.append(f"{agent.id}: {err}")
            continue
        model_text, caller_text = _norm(model_raw), _norm(caller_raw)
        model_lines, caller_lines = (
            [x.strip() for x in model_raw.split("\n")],
            [x.strip() for x in caller_raw.split("\n")],
        )
        for what, file, text, lines, heads, parts in (
            ("caller", caller.path, caller_text, caller_lines, c_heads, c_parts),
            ("model", model.path, model_text, model_lines, m_heads, m_parts),
        ):
            for h in heads:
                n = lines.count(h)
                if n == 0:
                    problems.append(f"{file}: required {what} section {h!r} is missing")
                elif n > 1:
                    problems.append(f"{file}: required {what} section {h!r} appears {n} times")
            for s in parts:
                if not _has(text, s):
                    problems.append(f"{file}: required {what} text is missing: {_short(s)}")
        for s in c_parts:
            if _quoted(model_text, s):
                problems.append(f"{model.path}: caller-only text leaked into the model file: {_short(s)}")
        for s in m_parts:
            if len(_norm(s)) >= MIN_LEAK and _quoted(caller_text, s):
                problems.append(f"{caller.path}: model instruction leaked into the caller file: {_short(s)}")
        for name in _reserved(heading_names(model_raw), RESERVED_CALLER):
            problems.append(f"{model.path}: caller section heading in the model file: {name!r}")
        for name in _reserved(heading_names(caller_raw), RESERVED_MODEL):
            problems.append(f"{caller.path}: model section heading in the caller file: {name!r}")
        if _POINTER.search(model_text):
            problems.append(f"{model.path}: an evidence pointer is in the model file")
    for path, r in files.items():
        if r.role == "caller" and path not in expected_callers:
            problems.append(f"{path}: a caller file with no model file to pair with")
    return problems


def _short(text: str) -> str:
    one = _norm(text)
    return repr(one if len(one) <= 60 else one[:57] + "...")
