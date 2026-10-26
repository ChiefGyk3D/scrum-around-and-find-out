# SPDX-License-Identifier: Apache-2.0
"""Spec test 21 (the item 4 seam): qualify() returns a typed Qualification and does not depend on log order."""

from __future__ import annotations

import datetime as dt
import itertools
from dataclasses import replace
from typing import Any

import pytest

from evdata import TODAY, rec
from profiledata import claim, doc, profile
from safo import qualify as q
from safo.agentsfile import AgentsFile, parse_agents
from safo.outcomes import Outcome
from safo.qualify import Qualification, qualify


def agents() -> AgentsFile:
    d = doc()
    profile(d, "copilot").update(status="profiled", do=[claim("Small pull requests.")])
    profile(d, "copilot")["models"] = {"gpt-5.1": {"status": "unmeasured"}, "gpt-5.2": {"status": "unmeasured"}}
    return parse_agents(d)


A = agents()


def days_ago(n: int) -> str:
    return (TODAY - dt.timedelta(days=n)).isoformat()


def run(rows: list[Outcome], agent: str = "copilot", model: str | None = None) -> Qualification:
    return qualify(rows, A, agent, model, today=TODAY)


def spread(count: int, dates: int, **kw: Any) -> list[Outcome]:
    return [rec(i + 1, date=days_ago(1 + i % dates), **kw) for i in range(count)]


def reasons(result: Qualification) -> dict[str, int]:
    return dict(result.rejected)


def test_ten_records_on_distinct_dates_qualify() -> None:
    r = run(spread(10, 10))
    assert (r.qualified, r.counted, r.distinct_cards, r.distinct_dates, r.rejected) == (True, 10, 10, 10, ())


def test_ten_records_on_one_date_count_but_do_not_qualify() -> None:
    r = run(spread(10, 1))
    assert (r.qualified, r.counted, r.distinct_dates) == (False, 10, 1)


def test_the_thresholds_are_exact_at_their_edges() -> None:
    assert not run(spread(9, 9)).qualified
    assert not run(spread(10, 2)).qualified
    assert run(spread(10, 3)).qualified
    assert run(spread(30, 3)).qualified


def test_the_thresholds_come_from_the_promotion_block() -> None:
    d = doc()
    profile(d, "copilot").update(status="profiled", do=[claim("Small pull requests.")])
    d["promotion"] = {"min_outcomes": 3, "min_distinct_dates": 1, "window_days": 30}
    small = parse_agents(d)
    rows = [rec(1, date=days_ago(1)), rec(2, date=days_ago(2)), rec(3, date=days_ago(31))]
    r = qualify(rows, small, "copilot", None, today=TODAY)
    assert (r.counted, r.qualified, dict(r.rejected)) == (2, False, {q.OUTSIDE_WINDOW: 1})
    r = qualify([*rows[:2], rec(3, date=days_ago(30))], small, "copilot", None, today=TODAY)
    assert (r.counted, r.qualified) == (3, True)


def test_an_unknown_agent_never_qualifies() -> None:
    r = run(spread(10, 10, agent="ghost"), "ghost")
    assert (r.qualified, r.counted) == (False, 0) and reasons(r) == {q.UNKNOWN_AGENT: 10}


def test_a_record_without_a_card_or_a_review_round_does_not_count() -> None:
    rows = [*spread(10, 10), rec(50, card=None), rec(51, card=None), rec(52, rounds=0)]
    r = run(rows)
    assert r.counted == 10 and reasons(r) == {q.NO_CARD: 2, q.NO_REVIEW: 1}


def test_duplicate_cards_that_agree_count_once() -> None:
    rows = spread(10, 10)
    r = run([*rows, rows[0], rows[0]])
    assert r.counted == 10 and r.distinct_cards == 10 and reasons(r) == {q.DUPLICATE: 2}


@pytest.mark.parametrize(
    "change",
    [{"date": days_ago(9)}, {"rounds": 2}, {"shape": "research"}, {"findings": {"minor": 1}}, {"model": "gpt-5.1"}],
    ids=["date", "review_rounds", "shape", "findings", "model"],
)
def test_conflicting_duplicates_void_the_key(change: dict[str, Any]) -> None:
    rows = spread(10, 10)
    twin = rec(1, **{"date": days_ago(1), **change})
    assert rows[0].date == twin.date or "date" in change
    r = run([*rows, twin])
    assert r.counted == 9 and reasons(r) == {q.CONFLICT: 2}


def test_a_duplicate_with_no_review_rounds_conflicts_rather_than_being_filtered_away() -> None:
    rows = spread(10, 10)
    r = run([*rows, rec(1, date=days_ago(1), rounds=0)])
    assert r.counted == 9 and reasons(r) == {q.CONFLICT: 2}


def test_the_window_is_inclusive_at_both_edges_and_a_future_date_is_its_own_reason() -> None:
    rows = [
        rec(1, date=days_ago(180)),  # the first day inside
        rec(2, date=days_ago(181)),  # one day too old
        rec(3, date=days_ago(0)),  # today
        rec(4, date=(TODAY + dt.timedelta(days=1)).isoformat()),
    ]
    r = run(rows)
    assert r.counted == 2 and reasons(r) == {q.OUTSIDE_WINDOW: 1, q.FUTURE: 1}


def test_distinct_dates_are_counted_over_counted_records_only() -> None:
    rows = spread(10, 1) + [rec(60 + i, date=days_ago(200 + i)) for i in range(5)]
    r = run(rows)
    assert (r.counted, r.distinct_dates, r.qualified) == (10, 1, False)


def test_the_model_layer_counts_only_its_own_model_and_deduplicates_per_model() -> None:
    rows = spread(10, 5, model="gpt-5.1") + spread(4, 4, model="gpt-5.2") + spread(3, 3)
    r = run(rows, model="gpt-5.1")
    assert (r.counted, r.qualified) == (10, True)
    assert run(rows, model="gpt-5.2").counted == 4


def test_a_model_that_is_not_a_layer_of_the_agent_does_not_qualify() -> None:
    r = run(spread(10, 10, model="gpt-9"), model="gpt-9")
    assert (r.counted, r.qualified) == (0, False) and reasons(r) == {q.UNKNOWN_MODEL: 10}


def test_the_same_card_under_two_models_is_a_conflict_for_the_harness_and_counts_once_per_model() -> None:
    rows = [rec(1, model="gpt-5.1"), rec(1, model="gpt-5.2")]
    harness = run(rows)
    assert harness.counted == 0 and reasons(harness) == {q.CONFLICT: 2}
    assert run(rows, model="gpt-5.1").counted == 1
    assert run(rows, model="gpt-5.2").counted == 1


def test_other_agents_records_are_out_of_scope_not_rejected() -> None:
    r = run(spread(10, 10) + spread(5, 5, agent="codex"))
    assert r.counted == 10 and r.rejected == ()


def test_the_result_does_not_depend_on_log_order() -> None:
    rows = [
        *spread(6, 3),
        rec(1, date=days_ago(1)),
        rec(2, rounds=2, date=days_ago(2)),
        rec(70, card=None),
        rec(71, date=days_ago(400)),
    ]
    want = run(rows)
    for perm in itertools.islice(itertools.permutations(rows), 200):
        assert run(list(perm)) == want
    assert run(list(reversed(rows))) == want


def test_every_rejection_is_reported_with_a_count_in_a_stable_order() -> None:
    rows = [rec(1, card=None), rec(2, rounds=0), rec(3, date=days_ago(400)), rec(4, date=days_ago(-5))]
    r = run(rows)
    assert r.rejected == tuple(sorted(r.rejected)) and sum(n for _, n in r.rejected) == 4


def _abandon(o: Outcome) -> Outcome:
    return replace(o, outcome="abandoned", review_rounds=0)


def test_abandoned_records_never_count_toward_promotion() -> None:
    rows = [*spread(9, 9), _abandon(rec(40)), _abandon(rec(41)), replace(rec(42), outcome="accepted")]
    r = run(rows)
    assert r.counted == 10 and reasons(r) == {q.ABANDONED: 2}
    assert not run([*spread(8, 8), _abandon(rec(40)), _abandon(rec(41))]).qualified


def test_an_abandoned_record_on_the_same_card_never_collapses_with_an_accepted_one() -> None:
    both = [rec(1, date=days_ago(2)), replace(rec(1, date=days_ago(2)), outcome="abandoned")]
    r = run(both)
    assert r.counted == 0 and reasons(r) == {q.CONFLICT: 2}, "different outcomes are not duplicates"
    assert all(run(list(p)).counted == 0 for p in itertools.permutations(both))
