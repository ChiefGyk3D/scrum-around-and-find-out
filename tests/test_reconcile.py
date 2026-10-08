# SPDX-License-Identifier: MIT
"""reconcile: add the missing, finish the closed, fill the blank; idempotent; survives the failures adopters hit."""

from __future__ import annotations

import argparse
import dataclasses
import io
from pathlib import Path
from typing import Any

import pytest

from fakegh import FakeGitHub
from fakegh.core import HANDLERS, Fault, FProject
from safo.cli import main
from safo.errors import ConfigError
from safo.graphql import Client
from safo.modes.reconcile import run
from safo.schema import Board, Repository
from world import build_world, load_test_board, make_context

ARGS = argparse.Namespace()


def reconcile(fake: FakeGitHub, client: Client, board: Board | None = None) -> tuple[int, str]:
    ctx, out = make_context(fake, board or load_test_board(), client)
    return run(ctx, ARGS), out.getvalue()


def snapshot(fake: FakeGitHub, project: FProject) -> dict[str, dict[str, str | None]]:
    names = ("Status", "Area", "Priority", "Done on")
    return {
        (c.repo + "#" + str(c.number) if (c := fake.content(i.content_id or "")) else i.id): {
            n: fake.value(project, i, n) for n in names
        }
        for i in project.items
    }


def test_missing_open_work_is_added_with_status_area_and_the_new_item_defaults(
    fake: FakeGitHub, client: Client
) -> None:
    _, project = build_world(fake)
    fake.add_content("acme/widgets", "Issue", 1, "A bug")
    fake.add_content("acme/widgets", "PullRequest", 2, "Add thing")
    fake.add_content("acme/widgets", "PullRequest", 3, "WIP", draft=True)
    fake.add_content("acme/widgets", "Issue", 4, "Fix docs page")  # an area rule: "docs"
    fake.add_content("acme/manuals", "Issue", 5, "Typo")
    code, text = reconcile(fake, client)
    assert code == 0, text
    assert snapshot(fake, project) == {
        "acme/widgets#1": {"Status": "Backlog", "Area": "Core", "Priority": "P2 later", "Done on": None},
        "acme/widgets#2": {"Status": "In progress", "Area": "Core", "Priority": "P2 later", "Done on": None},
        "acme/widgets#3": {"Status": "Backlog", "Area": "Core", "Priority": "P2 later", "Done on": None},
        "acme/widgets#4": {"Status": "Backlog", "Area": "Docs", "Priority": "P2 later", "Done on": None},
        "acme/manuals#5": {"Status": "Backlog", "Area": "Docs", "Priority": "P2 later", "Done on": None},
    }
    assert "acme/widgets#2: Status = In progress" in text


def test_a_second_run_changes_nothing(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    fake.add_content("acme/widgets", "Issue", 1)
    fake.add_content("acme/widgets", "Issue", 2, state="CLOSED", closed_at="2026-10-02T00:00:00Z")
    reconcile(fake, client)
    fake.mutations.clear()
    code, text = reconcile(fake, client)
    assert code == 0 and fake.mutations == []
    assert "nothing to do: the board is current" in text


def test_closed_and_merged_items_become_done_with_their_close_date(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    shut = fake.add_content("acme/widgets", "Issue", 1, state="CLOSED", closed_at="2026-10-03T08:00:00Z")
    merged = fake.add_content("acme/widgets", "PullRequest", 2, state="MERGED", closed_at="2026-10-04T09:00:00Z")
    done_no_date = fake.add_content("acme/widgets", "Issue", 3, state="CLOSED", closed_at="2026-10-05T09:00:00Z")
    fake.add_item(project, shut, Status="In progress", Area="Core")
    fake.add_item(project, merged, Status="In progress", Area="Core")
    fake.add_item(project, done_no_date, Status="Done", Area="Core")
    code, text = reconcile(fake, client)
    assert code == 0, text
    snap = snapshot(fake, project)
    assert snap["acme/widgets#1"]["Status"] == "Done" and snap["acme/widgets#1"]["Done on"] == "2026-10-03"
    assert snap["acme/widgets#2"]["Done on"] == "2026-10-04"
    assert snap["acme/widgets#3"]["Done on"] == "2026-10-05"


def test_blank_area_and_status_are_filled_and_an_existing_value_is_never_overwritten(
    fake: FakeGitHub, client: Client
) -> None:
    _, project = build_world(fake)
    blank = fake.add_content("acme/widgets", "Issue", 1)
    kept = fake.add_content("acme/widgets", "Issue", 2, "Fix docs page")
    fake.add_item(project, blank)
    fake.add_item(project, kept, Status="Blocked", Area="Core")
    reconcile(fake, client)
    snap = snapshot(fake, project)
    assert snap["acme/widgets#1"]["Status"] == "Backlog" and snap["acme/widgets#1"]["Area"] == "Core"
    assert snap["acme/widgets#2"]["Status"] == "Blocked" and snap["acme/widgets#2"]["Area"] == "Core"


def test_an_open_item_in_done_is_reported_and_never_reopened(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    card = fake.add_content("acme/widgets", "Issue", 1)
    fake.add_item(project, card, Status="Done", Area="Core", Done_on="2026-10-01")
    code, text = reconcile(fake, client)
    assert code == 1 and "NOTE acme/widgets#1 is open but its status is Done" in text
    assert not fake.mutations_named("SetDate")


def test_the_item_is_edited_by_the_node_id_the_add_returned_even_while_the_listing_lags(
    fake: FakeGitHub, client: Client
) -> None:
    """Fields are set by item node id after the add; a fresh item can be missing from listings."""
    fake.listing_lag = 5
    _, project = build_world(fake)
    fake.add_content("acme/widgets", "Issue", 1)
    code, _ = reconcile(fake, client)
    assert code == 0
    item = project.items[0]
    assert fake.value(project, item, "Status") == "Backlog" and fake.value(project, item, "Area") == "Core"
    assert {m.variables["itemId"] for m in fake.mutations if m.op == "SetSelect"} == {item.id}


def test_a_run_right_after_another_does_not_fail_verification_when_the_listing_lags(
    fake: FakeGitHub, client: Client
) -> None:
    fake.listing_lag = 5
    build_world(fake)
    fake.add_content("acme/widgets", "Issue", 1)
    fake.add_content("acme/widgets", "Issue", 2)
    assert reconcile(fake, client)[0] == 0
    project = next(iter(fake.projects.values()))
    item = project.items[0]
    priority = fake.field(project, "Priority")
    item.values[priority.id] = priority.options[0].id
    before = dict(item.values)
    fake.mutations.clear()
    code, text = reconcile(fake, client)
    assert code == 0, text
    assert fake.mutations == [] and item.values == before
    assert fake.mutations_named("AddItem") == []


def test_adds_are_verified_with_total_count_so_an_add_that_stored_nothing_is_a_failure(
    fake: FakeGitHub, client: Client
) -> None:
    build_world(fake)
    fake.add_content("acme/widgets", "Issue", 1)

    def phantom(f: FakeGitHub, v: dict[str, object]) -> dict[str, object]:
        return {"addProjectV2ItemById": {"item": {"id": "PVTI_phantom"}}}  # success, but nothing is stored

    fake.handlers["AddItem"] = phantom
    code, text = reconcile(fake, client)
    assert code == 2 and "unknown outcome" in text


def test_a_dry_run_sends_no_mutation_and_does_not_verify(fake: FakeGitHub, sleeps: list[float]) -> None:
    build_world(fake)
    fake.add_content("acme/widgets", "Issue", 1)
    sent = io.StringIO()
    dry = Client(fake.token, fake.url, dry_run=True, sleep=sleeps.append, out=sent)
    code, text = reconcile(fake, dry)
    assert code == 1 and fake.mutations == []
    assert "dry run: would AddItem" in sent.getvalue() and "dry run: would SetSelect" in sent.getvalue()
    assert "WOULD ADD acme/widgets#1: Status = Backlog; Area = Core; Priority = P2 later" in text


def test_board_and_repositories_are_read_a_page_at_a_time(fake: FakeGitHub, client: Client) -> None:
    fake.page_size = 2
    _, project = build_world(fake)
    for n in range(1, 6):
        c = fake.add_content("acme/widgets", "Issue", n)
        if n <= 3:
            fake.add_item(project, c, Status="Backlog", Area="Core")
    code, _ = reconcile(fake, client)
    assert code == 0
    assert {c.number for c in fake.repos["acme/widgets"].contents} == {1, 2, 3, 4, 5}
    assert len(project.items) == 5
    assert fake.requests.count("ProjectItems") == 5  # initial two pages, then three pages after the adds


def test_a_repository_owned_by_someone_else_is_covered_without_linking_it(fake: FakeGitHub, client: Client) -> None:
    """A personal repository cannot be linked to an organization project; reconcile still adds its items."""
    board = load_test_board()
    board = dataclasses.replace(
        board, repositories=(*board.repositories, Repository("someone", "personal", default_area="Core"))
    )
    _, project = build_world(fake, board)
    fake.add_content("someone/personal", "Issue", 7, "Mine")
    code, _ = reconcile(fake, client, board)
    assert code == 0
    assert snapshot(fake, project)["someone/personal#7"]["Area"] == "Core"
    assert not any("Link" in op for op in fake.requests)


def test_secondary_rate_limit_refusals_are_waited_out_and_reconcile_finishes(
    fake: FakeGitHub, client: Client, sleeps: list[float]
) -> None:
    """Review focus 2: a 403 secondary rate limit after some writes already landed."""
    _, project = build_world(fake)
    for n in range(1, 5):
        fake.add_content("acme/widgets", "Issue", n)
    fake.faults.append(
        Fault(403, {"Retry-After": "5"}, '{"message": "secondary rate limit"}', times=2, op="SetSelect", after=3)
    )
    code, _ = reconcile(fake, client)
    assert code == 0 and sleeps == [5.0, 5.0]
    assert len(fake.mutations_named("AddItem")) == 4
    fake.faults.clear()
    assert reconcile(fake, client)[0] == 0
    expected = {
        f"acme/widgets#{n}": {"Status": "Backlog", "Area": "Core", "Priority": "P2 later", "Done on": None}
        for n in range(1, 5)
    }
    assert snapshot(fake, project) == expected


def test_a_rate_limit_that_does_not_clear_stops_the_run_names_the_rest_and_the_next_run_converges(
    fake: FakeGitHub, client: Client, sleeps: list[float]
) -> None:
    _, project = build_world(fake)
    for n in range(1, 5):
        fake.add_content("acme/widgets", "Issue", n)
    fake.faults.append(Fault(429, {"Retry-After": "1"}, "{}", times=999, op="SetSelect", after=2))
    code, text = reconcile(fake, client)
    assert code == 1 and sleeps
    assert "FAILED" in text and "stopped: still rate limited" in text
    assert len(fake.mutations_named("AddItem")) == 1, "no further adds are attempted once the limit will not clear"
    fake.faults.clear()
    code, text = reconcile(fake, client)
    assert code == 0, text
    assert {s["Status"] for s in snapshot(fake, project).values()} == {"Backlog"} and len(project.items) == 4


def test_a_repository_the_app_is_not_installed_on_is_named_and_the_others_are_still_done(
    fake: FakeGitHub, client: Client
) -> None:
    """Review focus 3: the listed repository answers NOT_FOUND to this token."""
    _, project = build_world(fake)
    fake.repos["acme/manuals"].installed = False
    fake.add_content("acme/widgets", "Issue", 1)
    fake.add_content("acme/manuals", "Issue", 2)
    code, text = reconcile(fake, client)
    assert code == 2
    assert "UNREACHABLE acme/manuals: the token cannot read it" in text
    assert list(snapshot(fake, project)) == ["acme/widgets#1"]


def test_a_card_deleted_after_it_was_listed_is_named_and_skipped_and_the_rest_are_done(
    fake: FakeGitHub, client: Client
) -> None:
    """Review focus 4: a read finds the card gone; there is nothing left to fix, so the run carries on."""
    _, project = build_world(fake)
    gone = fake.add_content("acme/widgets", "Issue", 1, state="CLOSED", closed_at="2026-10-03T00:00:00Z")
    fine = fake.add_content("acme/widgets", "Issue", 2, state="CLOSED", closed_at="2026-10-03T00:00:00Z")
    item = fake.add_item(project, gone, Status="In progress", Area="Core")
    fake.add_item(project, fine, Status="In progress", Area="Core")
    fake.vanished.add(item.id)
    code, text = reconcile(fake, client)
    assert code == 0, text
    assert "VANISHED acme/widgets#1" in text
    assert snapshot(fake, project)["acme/widgets#2"]["Status"] == "Done"
    assert {m.variables["itemId"] for m in fake.mutations} == {project.items[1].id}


def test_a_card_deleted_during_a_write_is_an_unknown_outcome_that_stops_further_writes(
    fake: FakeGitHub, client: Client
) -> None:
    """The edit itself answers NOT_FOUND: that is an error on a write, so the outcome is unknown. The re-read
    proves the card is gone, the run names it, sends nothing further and exits 2; the next run finishes the rest."""
    board = load_test_board()
    board = dataclasses.replace(board, rules=dataclasses.replace(board.rules, new_item_defaults=()))
    _, project = build_world(fake, board)
    gone = fake.add_content("acme/widgets", "Issue", 1, state="CLOSED", closed_at="2026-10-03T00:00:00Z")
    fine = fake.add_content("acme/widgets", "Issue", 2, state="CLOSED", closed_at="2026-10-03T00:00:00Z")
    item = fake.add_item(project, gone, Status="In progress", Area="Core")
    fake.add_item(project, fine, Status="In progress", Area="Core")
    fake.vanished.add(item.id)
    code, text = reconcile(fake, client, board)
    assert code == 2, text
    assert "VANISHED acme/widgets#1" in text and "unknown outcome" in text
    assert "NOT ATTEMPTED acme/widgets#2" in text
    assert len(fake.mutations) == 1, "nothing is sent after an unknown outcome"
    assert snapshot(fake, project)["acme/widgets#2"]["Status"] == "In progress"
    project.items.remove(item)  # GitHub stops listing a deleted card
    assert reconcile(fake, client, board)[0] == 0
    assert snapshot(fake, project)["acme/widgets#2"]["Status"] == "Done"


def test_an_issue_deleted_between_listing_and_add_is_skipped(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    gone = fake.add_content("acme/widgets", "Issue", 1)
    fake.add_content("acme/widgets", "Issue", 2)
    fake.vanished.add(gone.id)
    code, text = reconcile(fake, client)
    assert code == 0 and "VANISHED acme/widgets#1" in text


def test_a_status_the_project_does_not_have_is_refused_before_anything_is_changed(
    fake: FakeGitHub, client: Client
) -> None:
    _, project = build_world(fake)
    fake.field(project, "Status").options = [
        o for o in fake.field(project, "Status").options if o.name != "In progress"
    ]
    fake.add_content("acme/widgets", "Issue", 1)
    with pytest.raises(ConfigError, match=r"no option named 'In progress'.*its options: Backlog, Next, Blocked, Done"):
        reconcile(fake, client)
    assert fake.mutations == []


def test_a_field_the_project_does_not_have_is_refused_before_anything_is_changed(
    fake: FakeGitHub, client: Client
) -> None:
    _, project = build_world(fake)
    project.fields = [f for f in project.fields if f.name != "Done on"]
    with pytest.raises(ConfigError, match="no field named 'Done on'"):
        reconcile(fake, client)
    assert fake.mutations == []


def test_closed_work_is_added_as_done_within_add_closed_days_only(fake: FakeGitHub, client: Client) -> None:
    board = load_test_board()
    board = dataclasses.replace(board, rules=dataclasses.replace(board.rules, add_closed_days=30))
    _, project = build_world(fake, board)
    fake.add_content("acme/widgets", "Issue", 1, state="CLOSED", closed_at="2026-10-01T00:00:00Z")
    fake.add_content("acme/widgets", "PullRequest", 2, state="MERGED", closed_at="2026-09-20T00:00:00Z")
    fake.add_content("acme/widgets", "Issue", 3, state="CLOSED", closed_at="2026-01-01T00:00:00Z")
    code, _ = reconcile(fake, client, board)
    assert code == 0
    snap = snapshot(fake, project)
    assert set(snap) == {"acme/widgets#1", "acme/widgets#2"}
    assert snap["acme/widgets#2"]["Status"] == "Done" and snap["acme/widgets#2"]["Done on"] == "2026-09-20"


@pytest.mark.parametrize("boundary", ["AddItem", "Status", "Area", "Priority", "SetDate", "ClearField"])
def test_unknown_at_each_boundary_stops_item_and_next_run_repairs_only_blanks(
    fake: FakeGitHub, client: Client, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    from safo.errors import UnknownOutcomeError
    from safo.items import content_from_node, find_item
    from safo.live import load_live
    from safo.modes.reconcile import initialize

    board = load_test_board()
    if boundary == "SetDate":
        board = dataclasses.replace(board, rules=dataclasses.replace(board.rules, add_closed_days=30))
    board, project = build_world(fake, board)
    closed = boundary == "SetDate"
    content = fake.add_content(
        "acme/widgets",
        "Issue",
        1,
        state="CLOSED" if closed else "OPEN",
        closed_at="2026-10-03T00:00:00Z" if closed else None,
    )
    if boundary == "ClearField":
        fake.add_item(project, content, Status="Done", Area="Core", Done_on="2026-10-03")
    real = client.execute
    lost = False
    after_loss = []

    def execute(document: str, variables: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        nonlocal lost
        if lost:
            after_loss.append("write" if document.lstrip().startswith("mutation") else "read")
        data = real(document, variables, **kwargs)
        op = document.split("(", 1)[0].split()[-1]
        field_name = next((f.name for f in project.fields if f.id == variables.get("fieldId")), "")
        if not lost and (op == boundary or field_name == boundary):
            lost = True
            raise UnknownOutcomeError("lost", data=data, errors=[{"type": "INTERNAL"}], status=502)
        return data

    monkeypatch.setattr(client, "execute", execute)
    if boundary == "ClearField":
        # This branch is exercised in T7's sync tests; T6 directly exercises the shared initializer.
        live = load_live(client, board.project)
        item = find_item(client, board, live, content.id)
        assert item is not None
        node = {"id": content.id, "number": 1, "state": "OPEN"}
        with pytest.raises(UnknownOutcomeError):
            initialize(
                make_context(fake, board, client)[0],
                live,
                board.repositories[0],
                content_from_node(node, "acme/widgets", "Issue"),
                item,
                "reopened",
            )
        find_item(client, board, live, content.id)
        assert after_loss and set(after_loss) == {"read"}
        return
    code, text = reconcile(fake, client, board)
    assert lost and code == 2 and "unknown outcome: re-run after checking the board" in text
    assert after_loss and set(after_loss) == {"read"}
    assert reconcile(fake, client, board)[0] == 0
    assert len(project.items) == 1
    values = snapshot(fake, project)["acme/widgets#1"]
    assert values["Status"] == ("Done" if closed else "Backlog")
    assert values["Area"] == "Core" and values["Priority"] == "P2 later"
    assert not closed or values["Done on"] == "2026-10-03"


@pytest.mark.parametrize("mask", ["unrelated", "hidden-existing"])
def test_phantom_identity_cannot_be_masked_by_total_count(fake: FakeGitHub, client: Client, mask: str) -> None:
    _, project = build_world(fake)
    fake.add_content("acme/widgets", "Issue", 1)
    other = fake.add_content("acme/widgets", "Issue", 9)
    if mask == "hidden-existing":
        item = fake.add_item(project, other, Status="Backlog", Area="Core", Priority="P2 later")
        item.hidden_for = 99

    def phantom(f: FakeGitHub, variables: dict[str, Any]) -> dict[str, Any]:
        if mask == "unrelated":
            f.add_item(project, other, Status="Backlog", Area="Core", Priority="P2 later")
        return {"addProjectV2ItemById": {"item": {"id": "phantom"}}}

    fake.handlers["AddItem"] = phantom
    code, text = reconcile(fake, client)
    assert code == 2 and "unknown outcome" in text
    assert not fake.mutations_named("SetSelect")


@pytest.mark.parametrize("hidden", [True, False])
def test_a_listing_that_hides_cards_nobody_looked_up_is_never_reported_current(
    fake: FakeGitHub, client: Client, hidden: bool
) -> None:
    """Review of T4: the board holds a closed card that is not Done; the listing lags and shows nothing."""
    _, project = build_world(fake)
    old = fake.add_content("acme/widgets", "Issue", 7, state="CLOSED", closed_at="2026-01-01T00:00:00Z")
    item = fake.add_item(project, old, Status="Backlog", Area="Core", Priority="P2 later")
    item.hidden_for = 99 if hidden else 0
    code, text = reconcile(fake, client)
    if hidden:
        assert code == 2 and "1 of 1 items on the project were not read" in text
        assert "nothing to do" not in text
    else:
        assert code == 0 and "were not read" not in text


def test_reconcile_corrects_closed_to_merged_status(fake: FakeGitHub, client: Client) -> None:
    board = load_test_board()
    board = dataclasses.replace(
        board, rules=dataclasses.replace(board.rules, status=dataclasses.replace(board.rules.status, merged="Next"))
    )
    _, project = build_world(fake, board)
    content = fake.add_content("acme/widgets", "PullRequest", 1, state="MERGED")
    fake.add_item(project, content, Status="Done", Area="Core")
    assert reconcile(fake, client, board)[0] == 0
    assert snapshot(fake, project)["acme/widgets#1"]["Status"] == "Next"


def test_reconcile_not_found_mutation_is_unknown_and_rereads_deletion(
    fake: FakeGitHub, client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    from safo.errors import UnknownOutcomeError

    _, project = build_world(fake)
    content = fake.add_content("acme/widgets", "Issue", 1, state="CLOSED")
    item = fake.add_item(project, content, Status="Backlog", Area="Core")
    real = client.execute

    def execute(document: str, variables: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        if document.lstrip().startswith("mutation"):
            fake.vanished.update([content.id, item.id])
            raise UnknownOutcomeError("not found", data=None, errors=[{"type": "NOT_FOUND"}], status=200)
        return real(document, variables, **kwargs)

    monkeypatch.setattr(client, "execute", execute)
    code, text = reconcile(fake, client)
    assert code == 2 and "VANISHED acme/widgets#1" in text and "unknown outcome" in text


def test_existing_item_discovery_is_one_board_walk_without_per_content_lookups(
    fake: FakeGitHub, client: Client
) -> None:
    _, project = build_world(fake)
    for n in range(1, 4):
        content = fake.add_content("acme/widgets", "Issue", n)
        fake.add_item(project, content, Status="Backlog", Area="Core", Priority="P2 later")
    assert reconcile(fake, client)[0] == 0
    assert fake.requests.count("ProjectItems") == 1  # one walk, all three items on one page
    assert "ItemLookup" not in fake.requests and "BatchItems" not in fake.requests


def test_missing_item_discovery_is_batched_and_the_board_is_reread_once_after_adds(
    fake: FakeGitHub, client: Client
) -> None:
    _, project = build_world(fake)
    for n in range(1, 4):
        fake.add_content("acme/widgets", "Issue", n)
    assert reconcile(fake, client)[0] == 0
    assert len(project.items) == 3
    assert fake.requests.count("BatchItems") == 1
    assert fake.requests.count("ProjectItems") == 2  # initial walk and one reread after adds
    assert fake.requests.count("ItemLookup") == 3  # one identity verification per acknowledged add


# -- exit codes, refusals and hostile inputs ---------------------------------------------------------------------

BOARD_FILE = str(Path(__file__).parent / "data" / "board.yaml")


def via_cli(client: Client, *flags: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(
        ["--board", BOARD_FILE, *flags, "reconcile"], env={}, client_factory=lambda b, e, d: client, out=out, err=err
    )
    return code, out.getvalue(), err.getvalue()


def wrap(fake: FakeGitHub, op: str, change: Any) -> None:
    """Let the real handler answer, then let `change` damage the answer."""
    real = HANDLERS[op]

    def handler(f: FakeGitHub, v: dict[str, Any]) -> dict[str, Any]:
        data = real(f, v)
        change(data, v)
        return data

    fake.handlers[op] = handler


def test_a_dry_run_with_nothing_to_change_exits_0(fake: FakeGitHub, sleeps: list[float]) -> None:
    build_world(fake)
    sent = io.StringIO()
    dry = Client(fake.token, fake.url, dry_run=True, sleep=sleeps.append, out=sent)
    code, text = reconcile(fake, dry)
    assert code == 0 and "nothing to do" in text and "WOULD" not in text


def test_a_dry_run_names_what_it_would_change_on_an_existing_card_and_exits_1(
    fake: FakeGitHub, sleeps: list[float]
) -> None:
    _, project = build_world(fake)
    card = fake.add_content("acme/widgets", "Issue", 1, state="CLOSED", closed_at="2026-10-03T00:00:00Z")
    fake.add_item(project, card, Status="In progress", Area="Core", Priority="P2 later")
    dry = Client(fake.token, fake.url, dry_run=True, sleep=sleeps.append, out=io.StringIO())
    code, text = reconcile(fake, dry)
    assert code == 1 and fake.mutations == []
    assert "WOULD UPDATE acme/widgets#1: Status = Done; Done date filled" in text


@pytest.mark.parametrize(
    ("op", "payload", "closed"),
    [
        ("AddItem", {"addProjectV2ItemById": {"item": {}}}, False),
        ("AddItem", {"addProjectV2ItemById": {"item": {"id": ""}}}, False),
        ("AddItem", {"addProjectV2ItemById": {"item": None}}, False),
        ("SetSelect", {"updateProjectV2ItemFieldValue": {"clientMutationId": None}}, False),
        ("SetSelect", {"updateProjectV2ItemFieldValue": {"projectV2Item": None}}, False),
        ("SetSelect", {"updateProjectV2ItemFieldValue": None}, False),
        ("SetDate", {"updateProjectV2ItemFieldValue": {"clientMutationId": None}}, True),
    ],
    ids=["add-no-id", "add-empty-id", "add-null-item", "select-no-id", "select-null-item", "select-null", "date-no-id"],
)
def test_a_write_whose_reply_carries_no_id_is_an_unknown_outcome_and_nothing_more_is_sent(
    fake: FakeGitHub, client: Client, op: str, payload: dict[str, Any], closed: bool
) -> None:
    build_world(fake)
    for n in (1, 2):
        fake.add_content(
            "acme/widgets",
            "Issue",
            n,
            state="CLOSED" if closed else "OPEN",
            closed_at="2026-10-03T00:00:00Z" if closed else None,
        )
    board = load_test_board()
    if closed:
        board = dataclasses.replace(board, rules=dataclasses.replace(board.rules, add_closed_days=30))
    real = HANDLERS[op]
    calls = 0

    def handler(f: FakeGitHub, v: dict[str, Any]) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        real(f, v)  # the write lands; only the reply is damaged
        return payload

    fake.handlers[op] = handler
    code, text = reconcile(fake, client, board)
    assert code == 2 and "unknown outcome: re-run after checking the board" in text
    assert calls == 1 and fake.mutations[-1].op == op, "no write follows the one whose outcome is unknown"
    assert "NOT ATTEMPTED acme/widgets#2" in text


def test_a_write_acknowledged_for_another_item_is_an_unknown_outcome(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    fake.add_content("acme/widgets", "Issue", 1)
    real = HANDLERS["SetSelect"]

    def handler(f: FakeGitHub, v: dict[str, Any]) -> dict[str, Any]:
        real(f, v)
        return {"updateProjectV2ItemFieldValue": {"projectV2Item": {"id": "PVTI_someone_else"}}}

    fake.handlers["SetSelect"] = handler
    code, text = reconcile(fake, client)
    assert code == 2 and "unknown outcome" in text
    assert len(fake.mutations_named("SetSelect")) == 1


def test_after_an_unknown_outcome_the_run_rereads_shows_what_it_saw_and_sends_nothing_more(
    fake: FakeGitHub, client: Client
) -> None:
    _, project = build_world(fake)
    first = fake.add_content("acme/widgets", "Issue", 1)
    second = fake.add_content("acme/widgets", "Issue", 2)
    fake.add_item(project, first, Status="Blocked")  # the Area is blank, so the first write is SetSelect
    fake.add_item(project, second)
    fake.faults.append(Fault(502, {}, "{}", times=1, op="SetSelect"))
    code, text = reconcile(fake, client)
    assert code == 2
    assert "observed acme/widgets#1: on the board, Status 'Blocked', Area None" in text
    assert "NOT ATTEMPTED acme/widgets#2" in text
    assert fake.mutations == [], "the refused write was never applied and nothing else was sent"


def test_the_observed_state_cannot_forge_a_log_line(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    card = fake.add_content("acme/widgets", "Issue", 1)
    fake.add_item(project, card, Status="Blocked\n::error::forged", Area="Core")
    fake.faults.append(Fault(502, {}, "{}", times=1, op="SetSelect"))
    code, text = reconcile(fake, client)
    assert code == 2
    assert not any(line.startswith("::") for line in text.splitlines())
    assert "observed acme/widgets#1" in text


def test_a_reread_that_cannot_be_read_still_ends_in_a_visible_exit_2(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    card = fake.add_content("acme/widgets", "Issue", 1)
    fake.add_item(project, card)
    fake.faults.append(Fault(502, {}, "{}", times=1, op="SetSelect"))
    fake.handlers["ItemLookup"] = lambda f, v: {"node": {"projectItems": 5}}
    code, text = reconcile(fake, client)
    assert code == 2 and "live reread failed; no further writes" in text
    assert "unknown outcome: re-run after checking the board" in text


def test_a_reread_that_finds_the_content_gone_names_it_vanished(fake: FakeGitHub, client: Client) -> None:
    board = load_test_board()
    board = dataclasses.replace(board, rules=dataclasses.replace(board.rules, new_item_defaults=()))
    _, project = build_world(fake, board)
    card = fake.add_content("acme/widgets", "Issue", 1)
    item = fake.add_item(project, card)
    fake.faults.append(Fault(502, {}, "{}", times=1, op="SetSelect"))
    fake.vanished.update([card.id, item.id])
    fake.handlers["ItemLookup"] = lambda f, v: {"node": None}  # GitHub answers null for a deleted issue
    code, text = reconcile(fake, client, board)
    assert code == 2 and "VANISHED acme/widgets#1" in text


def test_a_rate_limit_that_does_not_clear_names_every_card_it_did_not_reach(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    for n in range(1, 4):
        fake.add_content("acme/widgets", "Issue", n)
    fake.faults.append(Fault(429, {"Retry-After": "1"}, "{}", times=999, op="SetSelect"))
    code, text = reconcile(fake, client)
    assert code == 1
    assert "FAILED acme/widgets#1: stopped: still rate limited" in text
    assert "NOT ATTEMPTED acme/widgets#2, acme/widgets#3" in text
    assert "ADDED acme/widgets#1" in text, "the add that did land is reported, not hidden"


@pytest.mark.parametrize(
    ("what", "change"),
    [
        ("state", lambda n: n.update(state="BOGUS")),
        ("state-null", lambda n: n.update(state=None)),
        ("closed-at-int", lambda n: n.update(closedAt=5)),
        ("closed-at-text", lambda n: n.update(closedAt="garbage")),
        ("closed-at-month", lambda n: n.update(closedAt="2026-13-45T00:00:00Z")),
        ("closed-at-short", lambda n: n.update(closedAt="2026")),
        ("number-bool", lambda n: n.update(number=True)),
        ("number-negative", lambda n: n.update(number=-1)),
        ("labels-not-objects", lambda n: n.update(labels={"nodes": [5]})),
    ],
)
def test_malformed_work_is_exit_2_before_any_write_and_the_value_is_not_echoed(
    fake: FakeGitHub, client: Client, what: str, change: Any
) -> None:
    build_world(fake)
    fake.add_content("acme/widgets", "Issue", 1)
    wrap(fake, "RepoOpenIssues", lambda data, v: change(data["repository"]["issues"]["nodes"][0]))
    code, out, err = via_cli(client)
    assert code == 2, (out, err)
    assert fake.mutations == [], "a repository that cannot be read in full is not worked on"
    assert "BOGUS" not in out + err and "garbage" not in out + err and "-1" not in out + err
    assert "nothing to do" not in out


def test_a_card_with_an_unrecognised_state_is_never_marked_done(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    card = fake.add_content("acme/widgets", "Issue", 1)
    fake.add_item(project, card, Status="Backlog", Area="Core", Priority="P2 later")
    wrap(fake, "ProjectItems", lambda data, v: data["node"]["items"]["nodes"][0]["content"].update(state="ARCHIVED"))
    code, out, _ = via_cli(client)
    assert code == 2 and fake.mutations == [] and "nothing to do" not in out


@pytest.mark.parametrize(
    ("field_name", "bad"),
    [(f, b) for f in ("status", "area") for b in ("text", 5, ["x"], {"name": 5})]
    + [("done", b) for b in ("text", 5, ["x"], {"date": 5}, {"date": "soon"})],
    ids=repr,
)
def test_a_field_value_of_the_wrong_shape_on_the_board_is_exit_2_and_nothing_is_sent(
    fake: FakeGitHub, client: Client, field_name: str, bad: Any
) -> None:
    _, project = build_world(fake)
    card = fake.add_content("acme/widgets", "Issue", 1)
    fake.add_item(project, card, Status="Backlog", Area="Core", Priority="P2 later")
    wrap(fake, "ProjectItems", lambda data, v: data["node"]["items"]["nodes"][0].update({field_name: bad}))
    code, out, err = via_cli(client)
    assert code == 2 and fake.mutations == [], (out, err)
    assert "nothing to do" not in out


@pytest.mark.parametrize("day", ["yesterday", "20261003", "2026-W41-4", "2026-02-30", ""])
def test_a_done_date_that_is_not_a_date_is_exit_2_and_never_treated_as_filled(
    fake: FakeGitHub, client: Client, day: str
) -> None:
    _, project = build_world(fake)
    card = fake.add_content("acme/widgets", "Issue", 1, state="CLOSED", closed_at="2026-10-03T00:00:00Z")
    fake.add_item(project, card, Status="Done", Area="Core", Priority="P2 later", Done_on=day)
    code, out, err = via_cli(client)
    assert code == 2 and fake.mutations == [], (out, err)
    assert day not in err or day == ""


@pytest.mark.parametrize(
    "answer",
    [
        [5],
        [[]],
        [{"projectItems": 5}],
        [{"projectItems": {"nodes": [], "pageInfo": {"hasNextPage": "no"}}}],
        [{"projectItems": {"nodes": [], "pageInfo": None}}],
        [{"projectItems": {"nodes": [5], "pageInfo": {"hasNextPage": False}}}],
        [{"projectItems": {"nodes": [{"id": "x", "project": 5}], "pageInfo": {"hasNextPage": False}}}],
        [{"projectItems": {"nodes": [{"id": "x"}], "pageInfo": {"hasNextPage": False}}}],
        [{"projectItems": {"nodes": [{"project": {"id": "p"}}], "pageInfo": {"hasNextPage": False}}}],
        [],
        [None, None],
    ],
    ids=repr,
)
def test_a_malformed_batched_identity_answer_is_exit_2_and_nothing_is_written(
    fake: FakeGitHub, client: Client, answer: list[Any]
) -> None:
    build_world(fake)
    fake.add_content("acme/widgets", "Issue", 1)
    fake.handlers["BatchItems"] = lambda f, v: {"nodes": answer}
    code, out, err = via_cli(client)
    assert code == 2 and fake.mutations == [], (out, err)
    assert "nothing to do" not in out


def test_a_null_batched_node_means_not_on_the_board_and_the_card_is_added(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    fake.add_content("acme/widgets", "Issue", 1)
    fake.handlers["BatchItems"] = lambda f, v: {"nodes": [None]}
    code, text = reconcile(fake, client)
    assert code == 0, text
    assert len(project.items) == 1


def test_a_page_of_cards_for_one_issue_beyond_the_first_is_followed(fake: FakeGitHub, client: Client) -> None:
    """An issue on many projects: the batch shows hasNextPage, the card on this board is on a later page."""
    fake.page_size = 1
    _, project = build_world(fake)
    other = fake.add_project("organization", "acme", 2, "Other")
    card = fake.add_content("acme/widgets", "Issue", 1)
    fake.add_item(other, card)
    fake.add_item(project, card, Status="Backlog", Area="Core", Priority="P2 later").hidden_for = 99
    code, text = reconcile(fake, client)
    assert code == 0, text
    assert fake.mutations == [] and len(project.items) == 1


def test_a_huge_add_closed_days_is_not_an_overflow(fake: FakeGitHub, client: Client) -> None:
    board = load_test_board()
    board = dataclasses.replace(board, rules=dataclasses.replace(board.rules, add_closed_days=999_999_999))
    _, project = build_world(fake, board)
    fake.add_content("acme/widgets", "Issue", 1, state="CLOSED", closed_at="1999-01-01T00:00:00Z")
    code, text = reconcile(fake, client, board)
    assert code == 0, text
    assert snapshot(fake, project)["acme/widgets#1"]["Done on"] == "1999-01-01"


def test_two_cards_for_one_issue_are_reported_and_exit_1(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    card = fake.add_content("acme/widgets", "Issue", 1)
    for _ in range(2):
        fake.add_item(project, card, Status="Backlog", Area="Core", Priority="P2 later")
    code, text = reconcile(fake, client)
    assert code == 1 and "NOTE acme/widgets#1 is on the board 2 times" in text


def test_cards_for_unlisted_repositories_and_drafts_are_left_alone(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    fake.add_repo("someone/else")
    elsewhere = fake.add_content("someone/else", "Issue", 1)
    fake.add_item(project, elsewhere)
    fake.add_item(project, None)
    code, text = reconcile(fake, client)
    assert code == 0 and fake.mutations == [], text


def test_cards_the_listing_hides_are_reported_as_unread_after_the_known_work_was_still_done(
    fake: FakeGitHub, client: Client
) -> None:
    """Accepted: idempotent writes for work the run knows are applied before the unread cards are reported."""
    _, project = build_world(fake)
    hidden = fake.add_content("acme/widgets", "Issue", 7, state="CLOSED", closed_at="2026-01-01T00:00:00Z")
    fake.add_item(project, hidden, Status="Backlog", Area="Core", Priority="P2 later").hidden_for = 99
    seen = fake.add_content("acme/widgets", "Issue", 8, state="CLOSED", closed_at="2026-01-02T00:00:00Z")
    fake.add_item(project, seen, Status="In progress", Area="Core", Priority="P2 later")
    code, text = reconcile(fake, client)
    assert code == 2
    assert "UPDATED acme/widgets#8: Status = Done" in text
    assert "UNKNOWN 1 of 2 items on the project were not read" in text
    assert "1 read from the listing" in text and "those changes were applied" in text
    assert snapshot(fake, project)["acme/widgets#7"]["Status"] == "Backlog"


def test_an_item_count_that_is_not_a_number_is_exit_2(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    wrap(fake, "ProjectMetaOrg", lambda data, v: data["organization"]["projectV2"]["items"].update(totalCount="many"))
    code, out, err = via_cli(client)
    assert code == 2 and fake.mutations == [], (out, err)
