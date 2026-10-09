# SPDX-License-Identifier: MIT
"""Render docs/routing.md from agents.yaml. The page is generated; a `--check` test keeps it from drifting."""

from __future__ import annotations

from safo.agentsfile import AgentsFile

METER_LABELS = {
    "five_hour": "the 5-hour window",
    "weekly": "the weekly window",
    "monthly_percent": "the month's AI credits",
}


def _names(doc: AgentsFile, ids: tuple[str, ...], empty: str = "none") -> str:
    return ", ".join(f"{doc.agent(i).name}" for i in ids) or empty


def render_routing(doc: AgentsFile) -> str:
    lines = [
        "# Routing",
        "",
        "> Generated from `agents.yaml` by `scripts/gen_routing.py`. Do not edit this page: edit `agents.yaml` and run",
        "> `python scripts/gen_routing.py --write`. `safo route <shape>` applies these rules to the live headroom",
        "> that `safo usage` measures; see [Usage](usage.md).",
        "",
        "## Task shapes",
        "",
        "Find the shape of the task, then take the first agent that has headroom. The reviewer is never the author.",
        "",
        "| Shape | What it is | Prefer | Fallback | Reviewer |",
        "|---|---|---|---|---|",
    ]
    for s in doc.shapes:
        what = s.description + (f" {s.note}" if s.note else "")
        lines.append(
            f"| `{s.name}` | {what} | {_names(doc, s.prefer)} | {_names(doc, s.fallback)} | {_names(doc, s.reviewer)} |"
        )
    lines += ["", "## When an agent is short of headroom", ""]
    if doc.thresholds:
        for t in doc.thresholds:
            agent, then = doc.agent(t.agent).name, doc.agent(t.then).name
            lines.append(f"- {agent} above {t.above:g}% of {METER_LABELS[t.meter]}: use {then} instead.")
    else:
        lines.append("- No thresholds are set.")
    lines += ["", "## The agents", ""]
    for a in doc.agents:
        lines += [f"### {a.name}", "", a.role, ""]
        if a.approval_required:
            lines += ["Needs the maintainer's OK before it is used.", ""]
        if a.limits:
            lines += ["Limits:", ""] + [f"- {k.replace('_', ' ')}: {v}" for k, v in a.limits] + [""]
        if a.strengths:
            lines += ["Strengths:", ""] + [f"- {x}" for x in a.strengths] + [""]
        if a.constraints:
            lines += ["Constraints:", ""] + [f"- {x}" for x in a.constraints] + [""]
        if a.endpoints:
            lines += ["Endpoints (placeholders here; real ones go in the git-ignored local file):", ""]
            for e in a.endpoints:
                shared = "; shared with production" if e.shared_with_production else ""
                protected = f"; protected, never evicted: {', '.join(e.protected_models)}" if e.protected_models else ""
                pinned = ", ".join(f"{name}={n}" for name, n in e.loaded_num_ctx)
                ctx = f"send exactly the loaded num_ctx ({pinned})" if pinned else f"num_ctx at most {e.num_ctx_max}"
                demand = (
                    f"; on demand (keep_alive {e.keep_alive}): {', '.join(e.on_demand_models)}" if e.keep_alive else ""
                )
                lines.append(
                    f"- `{e.id}` at `{e.url}`: roles {', '.join(e.roles)}; allowed models {', '.join(e.models)}; "
                    f"{ctx}; think {'on' if e.think else 'off'} by default{demand}{shared}{protected}"
                )
                if e.note:
                    lines.append(f"  - {e.note}")
            lines.append("")
    if doc.rules_of_thumb:
        lines += ["## Rules of thumb", ""] + [f"- {x}" for x in doc.rules_of_thumb] + [""]
    return "\n".join(lines).rstrip("\n") + "\n"
