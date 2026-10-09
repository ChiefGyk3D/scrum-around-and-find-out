# SPDX-License-Identifier: MIT
"""Rules plus live headroom: which agent a task shape should go to, and why.

Pure functions. `safo route` prints the answer for the lead to put on the card's Agent field; nothing here
dispatches anything. A local (Ollama) agent is used only when its endpoint is reachable and the request cannot
evict a protected model.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from safo.agentsfile import Agent, AgentsFile, Endpoint, Shape, Threshold
from safo.ollama import Probe

CARD_LABELS = {"claude": "Claude", "codex": "Codex", "copilot": "Copilot", "ollama": "Claude", "human": "You"}
METER_NAMES = {
    "five_hour": "the 5-hour window",
    "weekly": "the weekly window",
    "monthly_percent": "the month's AI credits",
}


@dataclass(frozen=True)
class ReviewGate:
    reviewer: str
    available: bool
    reason: str


@dataclass(frozen=True)
class Recommendation:
    shape: str
    agent: str | None
    why: str
    skipped: tuple[str, ...] = ()
    reviewer: str | None = None
    reviewer_why: str = ""
    needs_approval: bool = False
    unknown: tuple[str, ...] = ()
    endpoint: str = ""
    model: str = ""
    note: str = ""
    card_label: str = ""
    fallback_chain: tuple[str, ...] = field(default_factory=tuple)
    reviews: tuple[ReviewGate, ...] = ()
    local_role: str = ""


def tripped(doc: AgentsFile, agent_id: str, headroom: Mapping[str, float | None]) -> Threshold | None:
    for t in doc.thresholds:
        value = headroom.get(t.meter)
        if t.agent == agent_id and value is not None and value > t.above:
            return t
    return None


def unknown_meters(doc: AgentsFile, agent_id: str, headroom: Mapping[str, float | None]) -> list[str]:
    return [t.meter for t in doc.thresholds if t.agent == agent_id and headroom.get(t.meter) is None]


def resolve_endpoint(
    agent: Agent,
    shape: Shape,
    probes: Mapping[str, Probe],
    *,
    model: str = "",
    num_ctx: int | None = None,
    endpoint_id: str = "",
) -> tuple[Endpoint | None, str, list[str]]:
    """The endpoint and model a request may use, or why none can. Endpoints not shared with production come first."""
    role = shape.local_role or "general"
    wanted = model or shape.local_model
    skipped: list[str] = []
    for e in sorted(agent.endpoints, key=lambda x: x.shared_with_production):
        if endpoint_id and e.id != endpoint_id:
            continue
        if role not in e.roles:
            skipped.append(f"{e.id}: not a {role} endpoint")
            continue
        state = probes.get(e.id)
        if state is None or not state.reachable:
            skipped.append(f"{e.id}: unreachable")
            continue
        chosen = wanted or (e.models[0] if role == "general" else "")
        if not chosen:
            skipped.append(f"{e.id}: this shape needs a model named (an embedding model)")
            continue
        if chosen not in e.models:
            why = (
                "it would load a model that could evict a protected one"
                if e.protected_models
                else "it is not an allowed model"
            )
            skipped.append(f"{e.id}: {chosen} is not allowed here: {why}")
            continue
        if "guard" in e.roles and chosen in e.protected_models:
            skipped.append(f"{e.id}: {chosen} is a guard model for a production service and is never routed to")
            continue
        loaded = e.loaded_ctx(chosen)
        if num_ctx is not None and loaded is not None and num_ctx != loaded:
            skipped.append(
                f"{e.id}: num_ctx {num_ctx} is not the {loaded} {chosen} is loaded with; "
                "any other value reloads it and can evict another resident"
            )
            continue
        if (num_ctx or loaded or e.num_ctx_max) > e.num_ctx_max:
            skipped.append(f"{e.id}: num_ctx {num_ctx} is above the cap of {e.num_ctx_max}")
            continue
        if e.protected_models and chosen not in state.loaded and chosen not in e.on_demand_models:
            skipped.append(f"{e.id}: {chosen} is not resident now, and loading it could evict a protected model")
            continue
        return e, chosen, skipped
    return None, "", skipped


def recommend(
    doc: AgentsFile,
    shape_name: str,
    headroom: Mapping[str, float | None],
    probes: Mapping[str, Probe] | None = None,
    *,
    model: str = "",
    num_ctx: int | None = None,
) -> Recommendation:
    shape = doc.shape(shape_name)
    probes = probes or {}
    order = list(shape.chain)
    seen: set[str] = set()
    skipped: list[str] = []
    chosen: Agent | None = None
    endpoint: Endpoint | None = None
    chosen_model = ""
    index = 0
    while index < len(order):
        agent = doc.agent(order[index])
        index += 1
        if agent.id in seen:
            continue
        seen.add(agent.id)
        trip = tripped(doc, agent.id, headroom)
        if trip:
            used = headroom[trip.meter]
            skipped.append(f"{agent.id}: {METER_NAMES[trip.meter]} is at {used:g}%, above {trip.above:g}%")
            if trip.then not in order[index:]:
                order.insert(index, trip.then)
            continue
        if agent.kind == "ollama":
            endpoint, chosen_model, why_not = resolve_endpoint(agent, shape, probes, model=model, num_ctx=num_ctx)
            if endpoint is None:
                skipped += [f"{agent.id} ({x})" for x in why_not] or [f"{agent.id}: no endpoint fits"]
                continue
        chosen = agent
        break
    chain = tuple(dict.fromkeys(order))
    if chosen is None:
        return Recommendation(
            shape.name,
            None,
            "every agent in the chain is short of headroom: wait for a reset or ask the maintainer",
            tuple(skipped),
            fallback_chain=chain,
            note=shape.note,
        )
    why = f"first in the chain with headroom ({', '.join(chain)})" if not skipped else "; ".join(skipped)
    reviewer, reviewer_why = _reviewer(doc, shape, chosen, headroom)
    return Recommendation(
        shape.name,
        chosen.id,
        why,
        tuple(skipped),
        reviewer,
        reviewer_why,
        chosen.approval_required,
        tuple(m for m in unknown_meters(doc, chosen.id, headroom)),
        endpoint.id if endpoint else "",
        chosen_model,
        shape.note,
        CARD_LABELS[chosen.kind],
        chain,
        tuple(
            ReviewGate(
                candidate,
                candidate != chosen.id and not tripped(doc, candidate, headroom),
                "independent reviewer"
                if candidate != chosen.id and not tripped(doc, candidate, headroom)
                else "required gate unavailable: ask for a fresh identity or wait",
            )
            for candidate in shape.reviewer
        ),
        shape.local_role,
    )


def _reviewer(
    doc: AgentsFile, shape: Shape, author: Agent, headroom: Mapping[str, float | None]
) -> tuple[str | None, str]:
    """A different agent from the author, and one that is not short of headroom."""
    for candidate in shape.reviewer:
        if candidate == author.id:
            continue
        if tripped(doc, candidate, headroom):
            continue
        return candidate, "a fresh reviewer: not the author, with headroom"
    if not shape.reviewer:
        return None, "no review is defined for this shape"
    return None, "no other reviewer has headroom: ask the maintainer or wait for a reset"


def probes_by_id(probes: Sequence[Probe]) -> dict[str, Probe]:
    return {p.endpoint_id: p for p in probes}
