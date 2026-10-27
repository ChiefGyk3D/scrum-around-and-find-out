# SPDX-License-Identifier: Apache-2.0
"""How many of an agent's recorded outcomes count toward measured status (spec 6.1). Nothing in selection reads this.

`qualify` returns a typed result, not a number, so the reader can see why a record did not count. The rules are chosen
so the result does not depend on the order of the log:

- scope: with no model, all of the agent's records, deduplicated on (agent, card); with a model, only that model's
  records, deduplicated on (agent, model, card);
- records of one key that agree on every material field (date, shape, review rounds, findings, model,
  outcome) collapse to
  one; if they disagree on any, the key is a conflict and none of its records counts. Duplicates are judged before
  the other rules, so a copy that differs only in its review rounds still voids the key;
- an abandoned record (outcome `abandoned`) never counts; its outcome is a material field, so it never collapses
  with an accepted record of the same card (that pair is a conflict);
- a surviving record counts when it has a review round and a date within the window, today included, no later than
  today.

This is a speed bump and not proof (spec 6.1, docs/limits.md): outcomes are self-reported into a file the user owns,
and whoever can append ten plausible records can promote an agent. The card URL ties each record to something a reviewer
can open; SAFO does not fetch it.
"""

from __future__ import annotations

import datetime as dt
from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

from safo.agentsfile import AgentsFile
from safo.outcomes import Outcome

UNKNOWN_AGENT = "unknown agent"
UNKNOWN_MODEL = "unknown model"
NO_CARD = "no card"
NO_REVIEW = "no review round"
FUTURE = "future date"
OUTSIDE_WINDOW = "outside the window"
DUPLICATE = "duplicate of a counted record"
CONFLICT = "conflicting duplicates"
ABANDONED = "abandoned task"


@dataclass(frozen=True)
class Qualification:
    qualified: bool
    counted: int
    distinct_cards: int
    distinct_dates: int
    rejected: tuple[tuple[str, int], ...]  # (reason, number of records), sorted by reason


def _material(o: Outcome) -> tuple[object, ...]:
    return (o.date, o.shape, o.review_rounds, tuple(sorted(o.findings.items())), o.model, o.outcome)


def qualify(
    outcomes: Sequence[Outcome], doc: AgentsFile, agent_id: str, model: str | None = None, *, today: dt.date
) -> Qualification:
    """The qualifying records of `agent_id` (and of `model`, a layer of its profile) and whether they suffice."""
    rejected: Counter[str] = Counter()
    mine = [o for o in outcomes if o.agent == agent_id]

    def result(counted: list[Outcome]) -> Qualification:
        p = doc.promotion
        dates = len({o.date for o in counted})
        return Qualification(
            len(counted) >= p.min_outcomes and dates >= p.min_distinct_dates,
            len(counted),
            len({o.card for o in counted}),
            dates,
            tuple(sorted(rejected.items())),
        )

    agent = next((a for a in doc.agents if a.id == agent_id), None)
    if agent is None:
        rejected[UNKNOWN_AGENT] += len(mine)
        return result([])
    scoped = mine
    if model is not None:
        scoped = [o for o in mine if o.model == model]
        if model not in {name for name, _ in (agent.profile.models if agent.profile else ())}:
            rejected[UNKNOWN_MODEL] += len(scoped)
            return result([])
    groups: dict[tuple[str | None, ...], list[Outcome]] = defaultdict(list)
    for o in scoped:
        if o.card is None:
            rejected[NO_CARD] += 1
        else:
            groups[(o.agent, model, o.card)].append(o)
    survivors: list[Outcome] = []
    for rows in groups.values():
        if len({_material(o) for o in rows}) > 1:
            rejected[CONFLICT] += len(rows)
            continue
        rejected[DUPLICATE] += len(rows) - 1
        survivors.append(rows[0])
    oldest = today - dt.timedelta(days=doc.promotion.window_days)
    counted: list[Outcome] = []
    for o in survivors:
        day = dt.date.fromisoformat(o.date)
        if o.abandoned:
            rejected[ABANDONED] += 1
        elif o.review_rounds < 1:
            rejected[NO_REVIEW] += 1
        elif day > today:
            rejected[FUTURE] += 1
        elif day < oldest:
            rejected[OUTSIDE_WINDOW] += 1
        else:
            counted.append(o)
    rejected = Counter({k: v for k, v in rejected.items() if v})
    return result(counted)
