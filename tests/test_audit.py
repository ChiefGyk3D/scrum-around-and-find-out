# SPDX-License-Identifier: MIT
"""audit: exit 0 clean, 1 drift, 2 cannot tell; and it never changes anything."""

from __future__ import annotations

import argparse
import io
from pathlib import Path
from typing import Any

import pytest

from fakegh import FakeGitHub
from fakegh.core import FOption
from safo.cli import main
from safo.graphql import Client
from safo.modes.audit import run
from world import build_world, make_context


def run_audit(fake: FakeGitHub, client: Client) -> tuple[int, str]:
    from world import load_test_board

    ctx, out = make_context(fake, load_test_board(), client)
    code = run(ctx, argparse.Namespace())
    assert fake.mutations == [], "audit must never mutate"
    return code, out.getvalue()


def test_a_board_that_matches_is_clean(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    code, text = run_audit(fake, client)
    assert code == 0 and text.splitlines()[-1] == "clean"
    assert "UI-only settings" in text and "Zoom = Quarter" in text


def test_a_missing_field_is_drift(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    project.fields = [f for f in project.fields if f.name != "Agent"]
    code, text = run_audit(fake, client)
    assert code == 1 and "DRIFT   field 'Agent' is missing from the project" in text


def test_a_field_of_the_wrong_type_is_drift(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    fake.field(project, "Done on").data_type = "TEXT"
    code, text = run_audit(fake, client)
    assert code == 1 and "field 'Done on' is text on the project but date in board.yaml" in text


def test_a_missing_and_an_extra_option_are_drift_and_safo_says_it_will_not_edit_them(
    fake: FakeGitHub, client: Client
) -> None:
    _, project = build_world(fake)
    status = fake.field(project, "Status")
    status.options = [o for o in status.options if o.name != "Blocked"]
    fake.field(project, "Area").options.append(FOption("OPT_X", "Triage"))
    code, text = run_audit(fake, client)
    assert code == 1
    assert "lacks the option 'Blocked'" in text and "never edits an existing field's options" in text
    assert "has the option 'Triage', which board.yaml does not list" in text


def test_an_option_that_differs_only_in_colour_or_description_is_a_note_not_drift(
    fake: FakeGitHub, client: Client
) -> None:
    """Review focus 1: the option exists live with another colour. safo cannot change it, so it must not fail."""
    _, project = build_world(fake)
    fake.field(project, "Status").options[0].color = "PINK"
    fake.field(project, "Status").options[1].description = "Changed in the UI"
    code, text = run_audit(fake, client)
    assert code == 0
    assert "NOTE    field 'Status' option 'Backlog': live colour/description PINK/" in text
    assert "NOTE    field 'Status' option 'Next'" in text
    assert text.splitlines()[-1] == "clean"


def test_options_in_another_order_are_a_note(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    fake.field(project, "Area").options.reverse()
    code, text = run_audit(fake, client)
    assert code == 0 and "different order" in text


def test_views_are_compared_by_layout_and_filter_and_a_missing_one_is_drift(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    project.views[0].filter = "status:Done"
    project.views[1].layout = "TABLE_LAYOUT"
    fake.add_view(project, "Extra", "TABLE_LAYOUT")
    code, text = run_audit(fake, client)
    assert code == 1
    assert "view 'Board' has the filter 'status:Done'" in text
    assert "view 'Roadmap' is a table layout on the project but roadmap" in text
    assert "NOTE    view 'Extra' exists on the project but not in board.yaml" in text
    project.views.pop(0)
    assert "view 'Board' is missing" in run_audit(fake, client)[1]


def test_whitespace_in_a_filter_is_not_drift(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    project.views[0].filter = "-status:Done  "
    assert run_audit(fake, client)[0] == 0


def test_missing_iterations_are_drift(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    fake.field(project, "Sprint").iterations.pop()
    code, text = run_audit(fake, client)
    assert code == 1 and "lacks the iterations starting 2026-11-03" in text


def test_an_open_issue_missing_from_the_board_is_drift(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    fake.add_content("acme/widgets", "Issue", 1, "A bug")
    fake.add_content("acme/manuals", "PullRequest", 2, "Fix typo", draft=True)
    code, text = run_audit(fake, client)
    assert code == 1
    assert "DRIFT   ADD acme/widgets#1 -> Backlog, Core" in text
    assert "DRIFT   ADD acme/manuals#2 -> Backlog, Docs" in text  # a draft takes draft_pr


def test_a_closed_item_that_is_not_done_and_an_open_item_in_done_are_drift(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    shut = fake.add_content("acme/widgets", "Issue", 3, state="CLOSED", closed_at="2026-10-05T10:00:00Z")
    fake.add_item(project, shut, Status="In progress", Area="Core")
    wrongly = fake.add_content("acme/widgets", "Issue", 4)
    fake.add_item(project, wrongly, Status="Done", Area="Core", Done_on="2026-10-01")
    code, text = run_audit(fake, client)
    assert code == 1
    assert "DONE acme/widgets#3 In progress -> Done on 2026-10-05" in text
    assert "acme/widgets#4 is open but its status is Done; safo never reopens a card" in text


def test_a_repository_the_token_cannot_read_is_unknown_and_named_not_clean(fake: FakeGitHub, client: Client) -> None:
    """Review focus 3: an App not installed on a listed repository. Exit 2, the others still audited."""
    build_world(fake)
    fake.repos["acme/manuals"].installed = False
    fake.add_content("acme/widgets", "Issue", 1)
    code, text = run_audit(fake, client)
    assert code == 2
    assert "UNKNOWN repository acme/manuals cannot be read with this token" in text
    assert "DRIFT   ADD acme/widgets#1" in text


def test_content_the_token_cannot_read_is_unknown(fake: FakeGitHub, client: Client) -> None:
    from fakegh.reads import project_items

    _, project = build_world(fake)
    fake.add_item(project, None, Status="Backlog")

    def redacted(f: FakeGitHub, v: dict[str, Any]) -> dict[str, Any]:
        data = project_items(f, v)
        for node in data["node"]["items"]["nodes"]:
            node["content"] = None
        return data

    fake.handlers["ProjectItems"] = redacted
    code, text = run_audit(fake, client)
    assert code == 2 and "inaccessible content" in text


def test_items_of_an_unlisted_repository_are_none_of_our_business(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    fake.add_repo("other/thing")
    other = fake.add_content("other/thing", "Issue", 1, state="CLOSED", closed_at="2026-10-05T00:00:00Z")
    fake.add_item(project, other, Status="Backlog")
    assert run_audit(fake, client)[0] == 0


def test_a_listing_of_more_than_one_page_is_read_in_full(fake: FakeGitHub, client: Client) -> None:
    fake.page_size = 2
    _, project = build_world(fake)
    for n in range(1, 6):
        c = fake.add_content("acme/widgets", "Issue", n)
        fake.add_item(project, c, Status="Backlog", Area="Core")
    code, _ = run_audit(fake, client)
    assert code == 0
    assert fake.requests.count("ProjectItems") == 3 and fake.requests.count("RepoOpenIssues") >= 3


def test_a_project_that_does_not_exist_is_unknown(fake: FakeGitHub, client: Client) -> None:
    fake.add_owner("organization", "acme")
    code, text = run_audit(fake, client)
    assert code == 2 and "UNKNOWN no project 1 under acme" in text


def test_add_closed_days_lists_recently_closed_work_as_adds_with_a_done_date(fake: FakeGitHub, client: Client) -> None:
    from dataclasses import replace

    from world import load_test_board

    board = load_test_board()
    board = replace(board, rules=replace(board.rules, add_closed_days=30))
    build_world(fake, board)
    fake.add_content("acme/widgets", "Issue", 8, state="CLOSED", closed_at="2026-10-01T00:00:00Z")
    fake.add_content("acme/widgets", "Issue", 9, state="CLOSED", closed_at="2026-01-01T00:00:00Z")
    ctx, out = make_context(fake, board, client)
    assert run(ctx, argparse.Namespace()) == 1
    assert "ADD acme/widgets#8 -> Done, Core" in out.getvalue()
    assert "#9" not in out.getvalue()


def test_the_command_line_runs_audit_and_returns_its_exit_code(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    out, err = io.StringIO(), io.StringIO()
    board_file = str(Path(__file__).parent / "data" / "board.yaml")
    code = main(["--board", board_file, "audit"], env={}, client_factory=lambda b, e, d: client, out=out, err=err)
    assert code == 0 and "audit acme/1" in out.getvalue()


def test_context_repr_never_contains_the_environment_token(fake: FakeGitHub, client: Client) -> None:
    from world import load_test_board

    ctx, _ = make_context(fake, load_test_board(), client)
    ctx.env = {"SAFO_TOKEN": "sentinel-credential"}
    assert "sentinel-credential" not in repr(ctx)


def test_intentional_draft_is_distinct_from_inaccessible_content(
    fake: FakeGitHub, client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    from safo.items import ItemState
    from safo.modes import audit

    build_world(fake)
    monkeypatch.setattr(
        audit, "list_board_items", lambda *a: [ItemState("draft", None, None, None, None, "DraftIssue")]
    )
    assert run_audit(fake, client)[0] == 0


def test_wrong_finished_status_is_drift_even_when_both_are_done(fake: FakeGitHub, client: Client) -> None:
    import dataclasses

    from world import load_test_board

    board = load_test_board()
    rules = dataclasses.replace(board.rules, status=dataclasses.replace(board.rules.status, merged="Next"))
    board = dataclasses.replace(board, rules=rules)
    _, project = build_world(fake, board)
    content = fake.add_content("acme/widgets", "PullRequest", 1, state="MERGED")
    fake.add_item(project, content, Status="Done", Area="Core")
    ctx, out = make_context(fake, board, client)
    assert run(ctx, argparse.Namespace()) == 1
    assert "Done -> Next" in out.getvalue()


def test_iteration_duration_alone_is_drift(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    fake.field(project, "Sprint").iterations[0]["duration"] = 7
    code, text = run_audit(fake, client)
    assert code == 1 and "duration is not 14 days" in text
