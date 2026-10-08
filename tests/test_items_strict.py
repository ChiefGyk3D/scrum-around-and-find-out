# SPDX-License-Identifier: MIT
"""The shared reads (audit and reconcile) refuse an answer that is not shaped as asked: exit 2, never a clean audit."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import pytest

from fakegh import FakeGitHub
from fakegh.core import HANDLERS
from safo.cli import main
from safo.errors import MalformedDataError
from safo.graphql import Client
from safo.values import utc_timestamp
from world import build_world

BOARD_FILE = str(Path(__file__).parent / "data" / "board.yaml")


def audit(client: Client) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(["--board", BOARD_FILE, "audit"], env={}, client_factory=lambda b, e, d: client, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def damage(fake: FakeGitHub, op: str, change: Any) -> None:
    real = HANDLERS[op]

    def handler(f: FakeGitHub, v: dict[str, Any]) -> dict[str, Any]:
        data = real(f, v)
        change(data)
        return data

    fake.handlers[op] = handler


def nodes_of(data: dict[str, Any], *path: str) -> list[dict[str, Any]]:
    node: Any = data
    for key in path:
        node = node[key]
    return list(node["nodes"])


@pytest.mark.parametrize("state", ["BOGUS", None, 5, "open", ""])
def test_audit_exits_2_for_an_issue_in_an_unknown_state(fake: FakeGitHub, client: Client, state: Any) -> None:
    build_world(fake)
    fake.add_content("acme/widgets", "Issue", 1)

    def change(data: dict[str, Any]) -> None:
        for n in nodes_of(data, "repository", "issues"):
            n["state"] = state

    damage(fake, "RepoOpenIssues", change)
    code, out, err = audit(client)
    assert code == 2 and "clean" not in out.splitlines(), (out, err)


@pytest.mark.parametrize("stamp", ["garbage", "2026-13-45T00:00:00Z", 5, "2026-10-03", "2026-10-03T08:00:00"])
def test_audit_exits_2_for_a_malformed_closed_at_on_a_board_card(fake: FakeGitHub, client: Client, stamp: Any) -> None:
    _, project = build_world(fake)
    card = fake.add_content("acme/widgets", "Issue", 1, state="CLOSED", closed_at="2026-10-03T00:00:00Z")
    fake.add_item(project, card, Status="Done", Area="Core", Priority="P2 later", Done_on="2026-10-03")

    def change(data: dict[str, Any]) -> None:
        for n in nodes_of(data, "node", "items"):
            n["content"]["closedAt"] = stamp

    damage(fake, "ProjectItems", change)
    code, out, err = audit(client)
    assert code == 2 and "clean" not in out.splitlines(), (out, err)


@pytest.mark.parametrize("day", ["soon", "20261003", "2026-02-30"])
def test_audit_exits_2_for_a_done_date_that_is_not_a_date(fake: FakeGitHub, client: Client, day: str) -> None:
    _, project = build_world(fake)
    card = fake.add_content("acme/widgets", "Issue", 1, state="CLOSED", closed_at="2026-10-03T00:00:00Z")
    fake.add_item(project, card, Status="Done", Area="Core", Priority="P2 later", Done_on=day)
    code, out, err = audit(client)
    assert code == 2 and "clean" not in out.splitlines(), (out, err)


@pytest.mark.parametrize("key", ["status", "area", "done", "d0"])
def test_audit_exits_2_when_a_field_value_was_not_sent(fake: FakeGitHub, client: Client, key: str) -> None:
    _, project = build_world(fake)
    card = fake.add_content("acme/widgets", "Issue", 1)
    fake.add_item(project, card, Status="Backlog", Area="Core", Priority="P2 later")

    def change(data: dict[str, Any]) -> None:
        for n in nodes_of(data, "node", "items"):
            del n[key]

    damage(fake, "ProjectItems", change)
    code, out, err = audit(client)
    assert code == 2 and "clean" not in out.splitlines(), (out, err)


def test_audit_still_calls_a_matching_board_clean(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    card = fake.add_content("acme/widgets", "Issue", 1)
    fake.add_item(project, card, Status="Backlog", Area="Core", Priority="P2 later")
    assert audit(client)[0] == 0


@pytest.mark.parametrize(
    ("stamp", "day"),
    [
        ("2026-10-03T08:00:00Z", "2026-10-03"),
        ("2026-10-03T23:30:00-02:00", "2026-10-04"),
        ("2026-10-03T00:30:00+02:00", "2026-10-02"),
        ("2026-10-03T08:00:00.5Z", "2026-10-03"),
        ("2026-10-03T08:00:00+00:00", "2026-10-03"),
    ],
)
def test_a_timestamp_is_read_in_utc(stamp: str, day: str) -> None:
    assert utc_timestamp(stamp, "t").date().isoformat() == day


@pytest.mark.parametrize(
    "stamp", ["", "2026-10-03", "2026-10-03T08:00:00", "2026-10-03T25:00:00Z", None, 5, "2026-10-03T08:00:00Zx"]
)
def test_a_timestamp_that_is_not_rfc_3339_is_refused(stamp: Any) -> None:
    with pytest.raises(MalformedDataError):
        utc_timestamp(stamp, "t")


def test_audit_reports_a_field_of_the_wrong_type_as_drift_not_as_an_unreadable_answer(
    fake: FakeGitHub, client: Client
) -> None:
    _, project = build_world(fake)
    card = fake.add_content("acme/widgets", "Issue", 1)
    fake.add_item(project, card, Status="Backlog", Area="Core", Priority="P2 later")
    fake.field(project, "Priority").data_type = "TEXT"
    fake.field(project, "Priority").options = []
    for item in project.items:
        item.values[fake.field(project, "Priority").id] = "high"  # a populated text value
    code, out, err = audit(client)
    assert code == 1, (out, err)
    assert "field 'Priority' is text on the project but single_select in board.yaml" in out


@pytest.mark.parametrize(
    "stamp",
    [
        "2026-10-03T00:30:00+00:60",
        "2026-10-03T00:30:00-00:99",
        "2026-10-03T00:30:00+24:00",
        "2026-10-03T00:30:00 +01:00",
        "2026-10-03T00:30:00+1:00",
        "2026-10-03T00:30:00.Z",
        "2026-10-03T00:30:00+0100",
        "2026-10-03T00:30:00",
    ],
)
def test_an_offset_is_validated_before_python_can_normalise_it(stamp: str) -> None:
    from safo.values import _STAMP

    assert _STAMP.fullmatch(stamp) is None, "the pattern itself refuses it, whatever the interpreter would do"
    with pytest.raises(MalformedDataError):
        utc_timestamp(stamp, "t")


def test_any_number_of_fractional_digits_is_accepted() -> None:
    assert utc_timestamp("2026-10-03T08:00:00.123456789012Z", "t").isoformat() == "2026-10-03T08:00:00+00:00"
    assert utc_timestamp("2026-10-03T23:59:59.9999999999999-02:00", "t").date().isoformat() == "2026-10-04"
    assert utc_timestamp("2026-10-03T08:00:00.1+23:59", "t").isoformat() == "2026-10-02T08:01:00+00:00"


def test_a_reconciled_close_time_with_a_bad_offset_is_refused_before_any_write(
    fake: FakeGitHub, client: Client
) -> None:
    import argparse
    import dataclasses

    from safo.modes.reconcile import run
    from world import load_test_board, make_context

    board = load_test_board()
    board = dataclasses.replace(board, rules=dataclasses.replace(board.rules, add_closed_days=30))
    build_world(fake, board)
    fake.add_content("acme/widgets", "Issue", 1, state="CLOSED", closed_at="2026-10-03T00:30:00+00:60")
    ctx, _ = make_context(fake, board, client)
    with pytest.raises(MalformedDataError):
        run(ctx, argparse.Namespace())
    assert fake.mutations == []
