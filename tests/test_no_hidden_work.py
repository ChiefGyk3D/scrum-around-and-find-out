# SPDX-License-Identifier: Apache-2.0
"""No hidden work, board side: audit finds it, reconcile and sync repair what is mechanical and list the rest."""

from __future__ import annotations

import argparse
import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from fakegh import FakeGitHub
from fakegh.core import FItem, FProject
from safo.coverage import links_issue
from safo.errors import ConfigError, MalformedDataError
from safo.graphql import Client
from safo.modes import audit, reconcile, sync
from safo.schema import Board, Field, Option, Tracking, parse_board
from world import DATA, build_world, load_test_board, make_context

KIND = Field("Kind", "single_select", (Option("Feature"), Option("Bug")))
EPIC = Field("Epic", "text")
EFFORT = Field("Effort", "number")
CARD = {"Status": "Backlog", "Area": "Core", "Priority": "P2 later"}  # a card that misses only what a test is about


def full_board() -> Board:
    board = load_test_board()
    return dataclasses.replace(board, fields=(*board.fields, KIND, EPIC, EFFORT))


def with_tracking(board: Board, tracking: Tracking, **rules: Any) -> Board:
    return dataclasses.replace(board, rules=dataclasses.replace(board.rules, tracking=tracking, **rules))


def run_audit(fake: FakeGitHub, client: Client, board: Board) -> tuple[int, str]:
    ctx, out = make_context(fake, board, client)
    code = audit.run(ctx, argparse.Namespace())
    assert fake.mutations == [], "audit must never mutate"
    return code, out.getvalue()


def run_reconcile(fake: FakeGitHub, client: Client, board: Board) -> tuple[int, str]:
    ctx, out = make_context(fake, board, client)
    return reconcile.run(ctx, argparse.Namespace()), out.getvalue()


def by_number(fake: FakeGitHub, project: FProject) -> dict[int, FItem]:
    found = {}
    for item in project.items:
        content = fake.content(item.content_id) if item.content_id else None
        if content is not None:
            found[content.number] = item
    return found


# -- the link a pull request carries ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    ["Refs #5", "closes #5", "Fixes: #5", "Resolves acme/widgets#5", "text\n\nCloses acme/other#5\n", "REFERENCES #5"],
)
def test_a_body_that_names_an_issue_links_it(body: str) -> None:
    assert links_issue(body, "acme/widgets", 9)


@pytest.mark.parametrize(
    "body", ["", "no link", "see #5", "Closes #9", "Refs acme/widgets#9", "Closes nothing", "Refs #"]
)
def test_a_body_without_another_issue_links_nothing(body: str) -> None:
    assert not links_issue(body, "acme/widgets", 9), "a pull request that names only itself serves no issue"


# -- audit -----------------------------------------------------------------------------------------------


def test_a_pull_request_with_no_linked_issue_is_drift_and_is_named(fake: FakeGitHub, client: Client) -> None:
    board, project = build_world(fake)
    linked = fake.add_content("acme/widgets", "PullRequest", 2, body="Closes #1")
    sidebar = fake.add_content("acme/widgets", "PullRequest", 3, body="", closing=1)
    bare = fake.add_content("acme/widgets", "PullRequest", 4, body="Just a change")
    for c in (linked, sidebar, bare):
        fake.add_item(project, c, Status="In progress", Area="Core", Priority="P2 later")
    code, text = run_audit(fake, client, board)
    assert code == 1
    assert "DRIFT   PULL acme/widgets#4 has no linked issue" in text
    assert "#2 has no linked" not in text and "#3 has no linked" not in text


def test_a_merged_pull_request_counts_inside_the_window_only(fake: FakeGitHub, client: Client) -> None:
    board, project = build_world(fake)
    board = dataclasses.replace(board, rules=dataclasses.replace(board.rules, add_closed_days=7))
    shapes = ((2, "MERGED", "2026-10-05"), (3, "MERGED", "2026-08-01"), (4, "CLOSED", "2026-10-05"))
    for number, state, day in shapes:
        pr = fake.add_content("acme/widgets", "PullRequest", number, state=state, closed_at=f"{day}T00:00:00Z", body="")
        fake.add_item(project, pr, Status="Done", Area="Core", Priority="P2 later", Done_on=day)
    code, text = run_audit(fake, client, board)
    assert code == 1 and "PULL acme/widgets#2 has no linked" in text
    assert "#3 has no linked" not in text and "#4 has no linked" not in text


def test_an_exempt_repository_is_not_checked_for_links(fake: FakeGitHub, client: Client) -> None:
    board, project = build_world(fake)
    board = with_tracking(board, Tracking(exempt_repos=("acme/widgets",)))
    pr = fake.add_content("acme/widgets", "PullRequest", 2, body="")
    fake.add_item(project, pr, Status="In progress", Area="Core", Priority="P2 later")
    assert "has no linked" not in run_audit(fake, client, board)[1]


def test_a_repository_that_cannot_be_read_is_unknown_not_clean(fake: FakeGitHub, client: Client) -> None:
    board, _ = build_world(fake)
    fake.repos["acme/manuals"].installed = False
    code, text = run_audit(fake, client, board)
    assert code == 2 and "UNKNOWN repository acme/manuals" in text


def test_cards_missing_kind_epic_and_effort_are_each_named(fake: FakeGitHub, client: Client) -> None:
    board, project = build_world(fake, full_board())
    whole = fake.add_content("acme/widgets", "Issue", 1)
    gap = fake.add_content("acme/widgets", "Issue", 2)
    fake.add_item(project, whole, **CARD, Kind="Bug", Epic="E1", Effort="3")
    fake.add_item(project, gap, **CARD, Kind="Bug")
    fake.add_item(project, None, Status="Backlog", Area="Core")
    code, text = run_audit(fake, client, board)
    lines = text.splitlines()
    assert code == 1
    assert "DRIFT   MISSING Epic on acme/widgets#2" in lines and "DRIFT   MISSING Effort on acme/widgets#2" in lines
    assert not any("acme/widgets#2" in line and "Kind" in line for line in lines)
    assert not any("MISSING" in line and "acme/widgets#1" in line for line in lines)
    assert sum("MISSING Kind on card" in line for line in lines) == 1, "a draft card is named by its card id"


def test_a_board_without_those_fields_skips_the_checks_and_says_so(fake: FakeGitHub, client: Client) -> None:
    board, project = build_world(fake)
    fake.add_item(project, fake.add_content("acme/widgets", "Issue", 1), **CARD)
    code, text = run_audit(fake, client, board)
    assert code == 0 and text.splitlines()[-1] == "clean"
    for label in ("Kind", "Epic", "Effort"):
        assert f"NOTE    {label} check not configured" in text
    assert "TrackedItems" not in fake.requests, "no read is made for a field the board does not define"


def test_a_field_named_empty_in_board_yaml_is_not_configured_even_when_it_exists(
    fake: FakeGitHub, client: Client
) -> None:
    board, project = build_world(fake, with_tracking(full_board(), Tracking(epic_field="")))
    fake.add_item(project, fake.add_content("acme/widgets", "Issue", 1), **CARD, Kind="Bug", Effort="1")
    code, text = run_audit(fake, client, board)
    assert code == 0 and "Epic check not configured" in text


def test_the_field_names_come_from_board_yaml(fake: FakeGitHub, client: Client) -> None:
    base = load_test_board()
    board = dataclasses.replace(
        base, fields=(*base.fields, Field("Type", "single_select", (Option("A"),)), Field("Size", "number"))
    )
    board, project = build_world(
        fake, with_tracking(board, Tracking(kind_field="Type", epic_field="", effort_field="Size"))
    )
    fake.add_item(project, fake.add_content("acme/widgets", "Issue", 1), **CARD, Type="A")
    code, text = run_audit(fake, client, board)
    assert code == 1 and "MISSING Size on acme/widgets#1" in text and "MISSING Kind" not in text


def test_a_card_whose_area_no_rule_can_fill_is_named(fake: FakeGitHub, client: Client) -> None:
    board = load_test_board()
    board = dataclasses.replace(
        board, repositories=(dataclasses.replace(board.repositories[0], default_area=None, area_rules=()),)
    )
    board, project = build_world(fake, board)
    fake.add_item(project, fake.add_content("acme/widgets", "Issue", 1), Status="Backlog", Priority="P2 later")
    code, text = run_audit(fake, client, board)
    assert code == 1 and "MISSING Area on acme/widgets#1: no area rule or default applies" in text


def test_the_checks_that_already_existed_still_fire(fake: FakeGitHub, client: Client) -> None:
    board, project = build_world(fake)
    shut = {"state": "CLOSED", "closed_at": "2026-10-05T00:00:00Z"}
    fake.add_item(project, fake.add_content("acme/widgets", "Issue", 1, **shut), **{**CARD, "Status": "In progress"})
    fake.add_item(project, fake.add_content("acme/widgets", "Issue", 2, **shut), **{**CARD, "Status": "Done"})
    fake.add_content("acme/widgets", "Issue", 3)
    fake.add_item(project, fake.add_content("acme/widgets", "Issue", 4), Area="Core", Priority="P2 later")
    code, text = run_audit(fake, client, board)
    assert code == 1
    for expected in ("DONE acme/widgets#1", "DATE acme/widgets#2", "ADD acme/widgets#3", "STATUS acme/widgets#4"):
        assert expected in text


def test_a_malformed_presence_answer_cannot_be_read_as_clean(fake: FakeGitHub, client: Client) -> None:
    board, project = build_world(fake, full_board())
    fake.add_item(project, fake.add_content("acme/widgets", "Issue", 1), **CARD)
    fake.handlers["TrackedItems"] = lambda f, v: {"node": {"items": f.connection([{"id": "x"}], v)}}
    with pytest.raises(MalformedDataError, match="was not sent"):
        run_audit(fake, client, board)


# -- board.yaml --------------------------------------------------------------------------------------------


def board_data() -> dict[str, Any]:
    data = yaml.safe_load((DATA / "board.yaml").read_text())
    assert isinstance(data, dict)
    return data


def test_board_yaml_reads_the_tracking_section() -> None:
    data = board_data()
    data["rules"]["tracking"] = {"kind_field": "Type", "epic_field": "", "exempt_repos": ["acme/widgets"]}
    t = parse_board(data, check_fields=False).rules.tracking
    assert t == Tracking("Type", "", "Effort", ("acme/widgets",))


@pytest.mark.parametrize(
    "bad",
    [
        {"exempt_repos": ["widgets"]},
        {"exempt_repos": ["a/b/c"]},
        {"exempt_repos": [3]},
        {"unknown": 1},
        {"kind_field": 3},
    ],
)
def test_board_yaml_refuses_a_bad_tracking_section(bad: dict[str, Any]) -> None:
    data = board_data()
    data["rules"]["tracking"] = bad
    with pytest.raises(ConfigError, match=r"rules\.tracking"):
        parse_board(data, check_fields=False)


def test_the_defaults_name_kind_epic_and_effort_and_exempt_nothing() -> None:
    assert load_test_board().rules.tracking == Tracking("Kind", "Epic", "Effort", ())


# -- reconcile --------------------------------------------------------------------------------------------


def test_reconcile_repairs_the_mechanical_gaps_and_lists_what_needs_a_human(fake: FakeGitHub, client: Client) -> None:
    board, project = build_world(fake, full_board())
    fake.add_content("acme/widgets", "Issue", 1)  # not on the board: reconcile adds it
    shut = fake.add_content("acme/widgets", "Issue", 2, state="CLOSED", closed_at="2026-10-05T00:00:00Z")
    fake.add_item(project, shut, **{**CARD, "Status": "In progress"})  # closed, not Done
    bare = fake.add_content("acme/widgets", "PullRequest", 3, body="nothing")
    fake.add_item(project, bare, **{**CARD, "Status": "In progress"})
    code, text = run_reconcile(fake, client, board)
    cards = by_number(fake, project)
    assert 1 in cards, "the missing card was added"
    assert (
        fake.value(project, cards[2], "Status") == "Done" and fake.value(project, cards[2], "Done on") == "2026-10-05"
    )
    assert code == 1
    assert "HUMAN acme/widgets#3 is a pull request with no linked issue" in text
    assert "HUMAN MISSING Epic on acme/widgets#3" in text
    assert {m.op for m in fake.mutations} <= {"AddItem", "SetSelect", "SetDate"}, "no field or option is ever edited"


def test_reconcile_stays_clean_when_nothing_is_hidden(fake: FakeGitHub, client: Client) -> None:
    board, project = build_world(fake, full_board())
    fake.add_item(project, fake.add_content("acme/widgets", "Issue", 1), **CARD, Kind="Bug", Epic="E", Effort="1")
    code, text = run_reconcile(fake, client, board)
    assert code == 0 and "nothing to do: the board is current" in text and "HUMAN" not in text


# -- sync -------------------------------------------------------------------------------------------------


def pull_event(tmp_path: Path, number: int, node_id: str) -> Path:
    pull = {"number": number, "node_id": node_id, "state": "open", "draft": False, "merged": False, "closed_at": None}
    payload = {"action": "opened", "pull_request": pull, "repository": {"full_name": "acme/widgets"}}
    path = tmp_path / "event.json"
    path.write_text(json.dumps(payload))
    return path


def run_sync(fake: FakeGitHub, client: Client, path: Path, board: Board) -> tuple[int, str]:
    ctx, out = make_context(fake, board, client)
    args = argparse.Namespace(event_path=str(path), event_name="pull_request")
    return sync.run(ctx, args), out.getvalue()


def test_sync_adds_the_card_and_reports_a_pull_request_with_no_linked_issue(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    board, project = build_world(fake)
    pr = fake.add_content("acme/widgets", "PullRequest", 5, body="no link")
    code, text = run_sync(fake, client, pull_event(tmp_path, 5, pr.id), board)
    assert code == 1 and len(project.items) == 1
    assert fake.value(project, project.items[0], "Status") == "In progress"
    assert "HUMAN acme/widgets#5 is a pull request with no linked issue" in text


def test_sync_is_clean_for_a_linked_pull_request(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    board, _ = build_world(fake)
    pr = fake.add_content("acme/widgets", "PullRequest", 5, body="Closes #2")
    code, text = run_sync(fake, client, pull_event(tmp_path, 5, pr.id), board)
    assert code == 0 and "HUMAN" not in text


def test_sync_does_not_flag_an_exempt_repository(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    board, _ = build_world(fake)
    board = with_tracking(board, Tracking(exempt_repos=("acme/widgets",)))
    pr = fake.add_content("acme/widgets", "PullRequest", 5, body="no link")
    assert run_sync(fake, client, pull_event(tmp_path, 5, pr.id), board)[0] == 0


# -- the shapes GitHub sends, and the cards a run adds ---------------------------------------------------


@pytest.mark.parametrize("state", ["MERGED", "CLOSED"])
def test_a_merged_pull_request_is_checked_whichever_way_its_state_is_spelled(
    fake: FakeGitHub, client: Client, state: str
) -> None:
    """`merged` is the boolean that decides; a CLOSED state beside merged=true is still a merged pull request."""
    board, project = build_world(fake)
    board = dataclasses.replace(board, rules=dataclasses.replace(board.rules, add_closed_days=7))
    pr = fake.add_content("acme/widgets", "PullRequest", 2, state="MERGED", closed_at="2026-10-05T00:00:00Z", body="")
    fake.add_item(project, pr, Status="Done", Area="Core", Priority="P2 later", Done_on="2026-10-05")

    def pulls(f: FakeGitHub, v: dict[str, Any]) -> dict[str, Any]:
        row = {
            "id": pr.id, "number": 2, "state": state, "merged": True, "closedAt": pr.closed_at, "body": "",
            "repository": {"nameWithOwner": "acme/widgets"}, "closingIssuesReferences": {"totalCount": 0},
        }  # fmt: skip
        return {"repository": {"pullRequests": f.connection([row], v)}}

    fake.handlers["RepoPullRefs"] = pulls
    code, text = run_audit(fake, client, board)
    assert code == 1 and "PULL acme/widgets#2 has no linked issue" in text


def test_a_pull_request_closed_without_merging_is_not_a_finding(fake: FakeGitHub, client: Client) -> None:
    board, _ = build_world(fake)
    board = dataclasses.replace(board, rules=dataclasses.replace(board.rules, add_closed_days=7))

    def pulls(f: FakeGitHub, v: dict[str, Any]) -> dict[str, Any]:
        row = {
            "id": "x", "number": 2, "state": "CLOSED", "merged": False, "closedAt": "2026-10-05T00:00:00Z",
            "body": "", "repository": {"nameWithOwner": "acme/widgets"}, "closingIssuesReferences": {"totalCount": 0},
        }  # fmt: skip
        return {"repository": {"pullRequests": f.connection([row], v)}}

    fake.handlers["RepoPullRefs"] = pulls
    assert "has no linked issue" not in run_audit(fake, client, board)[1]


def test_a_first_reconcile_reports_the_cards_it_adds(fake: FakeGitHub, client: Client) -> None:
    board, _ = build_world(fake, full_board())
    fake.add_content("acme/widgets", "Issue", 1)  # not on the board: this run adds it
    code, text = run_reconcile(fake, client, board)
    assert code == 1
    for name in ("Kind", "Epic", "Effort"):
        assert f"HUMAN MISSING {name} on acme/widgets#1" in text


def test_a_dry_run_reports_the_cards_it_would_add(fake: FakeGitHub) -> None:
    board, _ = build_world(fake, full_board())
    fake.add_content("acme/widgets", "Issue", 1)
    dry = Client(fake.token, fake.url, dry_run=True)
    code, text = run_reconcile(fake, dry, board)
    assert code == 1 and "HUMAN MISSING Kind on acme/widgets#1" in text


def test_sync_reports_a_new_card_with_no_kind_epic_or_effort(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    board, project = build_world(fake, full_board())
    issue = fake.add_content("acme/widgets", "Issue", 1)
    payload = {
        "action": "opened",
        "issue": {"number": 1, "node_id": issue.id, "state": "open", "closed_at": None},
        "repository": {"full_name": "acme/widgets"},
    }
    path = tmp_path / "event.json"
    path.write_text(json.dumps(payload))
    ctx, out = make_context(fake, board, client)
    code = sync.run(ctx, argparse.Namespace(event_path=str(path), event_name="issues"))
    text = out.getvalue()
    assert code == 1 and len(project.items) == 1
    for name in ("Kind", "Epic", "Effort"):
        assert f"HUMAN MISSING {name} on acme/widgets#1" in text


def test_sync_is_clean_for_a_card_that_holds_every_field(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    board, project = build_world(fake, full_board())
    issue = fake.add_content("acme/widgets", "Issue", 1)
    fake.add_item(project, issue, **CARD, Kind="Bug", Epic="E", Effort="1")
    payload = {
        "action": "edited",
        "issue": {"number": 1, "node_id": issue.id, "state": "open", "closed_at": None},
        "repository": {"full_name": "acme/widgets"},
    }
    path = tmp_path / "event.json"
    path.write_text(json.dumps(payload))
    ctx, out = make_context(fake, board, client)
    assert sync.run(ctx, argparse.Namespace(event_path=str(path), event_name="issues")) == 0
    assert "HUMAN" not in out.getvalue()
