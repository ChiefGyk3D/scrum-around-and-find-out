# SPDX-License-Identifier: MIT
"""Spec test 5: query_outcomes aggregates across months; a metric with no data is unsupported, never zero."""

from __future__ import annotations

import inspect
from fractions import Fraction

import pytest

from evdata import rec
from safo import outcomes
from safo.errors import ConfigError
from safo.outcomes import compare, query_outcomes

ROWS = [
    rec(1, date="2026-07-31"),  # before the range
    rec(2, date="2026-08-01", rounds=2, findings={"important": 1, "minor": 2}, credits=10),
    rec(3, date="2026-09-15", rounds=1, credits=20),
    rec(4, date="2026-10-31", rounds=3, findings={"critical": 1, "unrated": 4}, credits=None),
    rec(5, date="2026-11-01"),  # after the range
    rec(6, agent="codex", date="2026-09-01", findings={"minor": 9}),
    rec(7, date="2026-09-20", model="gpt-5.1", rounds=1, credits=30),
]


def value(span: str, agent: str, model: str | None, metric: str) -> Fraction | None:
    return query_outcomes(ROWS, span, agent, model).value(metric)


def test_a_range_spans_months_and_leaves_the_ends_out() -> None:
    q = query_outcomes(ROWS, "2026-08..2026-10", "copilot", None)
    assert q.records == 4  # 2, 3, 4 and the gpt-5.1 run; not July, not November, not codex
    assert query_outcomes(ROWS, "2026-08", "copilot", None).records == 1
    assert query_outcomes(ROWS, "2026-07..2026-11", "copilot", None).records == 6


def test_the_metrics_over_several_months() -> None:
    assert value("2026-08..2026-10", "copilot", None, "runs") == 4
    assert value("2026-08..2026-10", "copilot", None, "fix_share") == Fraction(2, 4)  # runs 2 and 4 needed fixes
    assert value("2026-08..2026-10", "copilot", None, "rounds_per_run") == Fraction(2 + 1 + 3 + 1, 4)
    assert value("2026-08..2026-10", "copilot", None, "credits_per_run") == Fraction(10 + 20 + 30, 3)


def test_findings_are_totals_over_the_range() -> None:
    span = "2026-08..2026-10"
    assert value(span, "copilot", None, "findings.important") == 1
    assert value(span, "copilot", None, "findings.minor") == 2
    assert value(span, "copilot", None, "findings.critical") == 1
    assert value(span, "copilot", None, "findings.unrated") == 4
    assert value(span, "codex", None, "findings.minor") == 9


def test_a_model_subject_selects_only_that_model() -> None:
    assert value("2026-08..2026-10", "copilot", "gpt-5.1", "runs") == 1
    assert value("2026-08..2026-10", "copilot", "gpt-5.1", "credits_per_run") == 30
    assert value("2026-08..2026-10", "copilot", "other", "runs") is None


def test_no_records_means_unsupported_for_every_metric() -> None:
    for metric in outcomes.METRICS:
        assert value("2026-01", "copilot", None, metric) is None, metric
        assert value("2026-09", "nobody", None, metric) is None, metric


def test_unknown_credits_are_unsupported_not_zero() -> None:
    rows = [rec(1, credits=None), rec(2, credits=None)]
    q = query_outcomes(rows, "2026-10", "copilot", None)
    assert q.value("runs") == 2
    assert q.value("credits_per_run") is None
    assert q.value("findings.critical") == 0  # records exist and none carries a finding: a real zero


@pytest.mark.parametrize(
    ("op", "number", "expected"),
    [
        (">=", "5", True),
        (">=", "5.000001", False),
        (">", "5", False),
        (">", "4.999999", True),
        ("<=", "5", True),
        ("<=", "4.999999", False),
        ("<", "5", False),
        ("<", "5.000001", True),
        ("=", "5", True),
        ("=", "5.0", True),
        ("=", "5.000001", False),
    ],
)
def test_every_operator_at_its_boundary(op: str, number: str, expected: bool) -> None:
    assert compare(Fraction(5), op, number) is expected


def test_a_third_is_compared_exactly_not_as_a_float() -> None:
    third = Fraction(1, 3)
    assert compare(third, "<", "0.333334") and compare(third, ">", "0.333333")
    assert not compare(third, "=", "0.333333")


@pytest.mark.parametrize(
    "span",
    ["2026-1", "2026-13", "2026-00", "2026-10..2026-09", "2025-10..2026-10", "x", "", "2026-01..2026-02..2026-03"],
)
def test_a_bad_range_is_a_config_error(span: str) -> None:
    with pytest.raises(ConfigError):
        query_outcomes(ROWS, span, "copilot", None)


def test_twelve_months_is_the_longest_range() -> None:
    assert query_outcomes(ROWS, "2025-11..2026-10", "copilot", None).records == 5
    with pytest.raises(ConfigError, match="12 months"):
        query_outcomes(ROWS, "2025-10..2026-10", "copilot", None)


def test_an_unknown_metric_or_operator_is_a_config_error() -> None:
    q = query_outcomes(ROWS, "2026-10", "copilot", None)
    with pytest.raises(ConfigError):
        q.value("speed")
    with pytest.raises(ConfigError):
        compare(Fraction(1), "!=", "1")
    with pytest.raises(ConfigError):
        compare(Fraction(1), "=", "1e3")


def test_the_result_does_not_depend_on_log_order() -> None:
    a = query_outcomes(ROWS, "2026-08..2026-10", "copilot", None)
    b = query_outcomes(list(reversed(ROWS)), "2026-08..2026-10", "copilot", None)
    assert a == b


def test_summarise_models_is_untouched() -> None:
    assert (
        str(inspect.signature(outcomes.summarise_models))
        == "(outcomes: 'list[Outcome]', month: 'str') -> 'list[ModelSummary]'"
    )
    got = outcomes.summarise_models(ROWS, "2026-09")
    assert [(m.agent, m.model, m.runs) for m in got] == [
        ("codex", "unknown", 1),
        ("copilot", "gpt-5.1", 1),
        ("copilot", "unknown", 1),
    ]
    with pytest.raises(ConfigError, match="YYYY-MM"):
        outcomes.summarise_models(ROWS, "2026-08..2026-10")
