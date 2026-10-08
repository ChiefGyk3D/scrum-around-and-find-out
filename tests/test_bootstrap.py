# SPDX-License-Identifier: MIT
"""bootstrap: create only what is missing, never edit an existing field's options, filter after create."""

from __future__ import annotations

import argparse
import dataclasses
import io
from typing import Any

import pytest

from fakegh import FakeGitHub, GqlError
from fakegh.core import FField, FOption, FProject
from safo.errors import ApiError, UnknownOutcomeError
from safo.graphql import Client
from safo.modes.audit import run as audit_run
from safo.modes.bootstrap import M_CREATE_VIEW, run
from safo.schema import Board
from world import load_test_board, make_context

ARGS = argparse.Namespace()


def empty_project(fake: FakeGitHub, board: Board) -> FProject:
    fake.add_owner(board.project.owner_type, board.project.owner)
    for repo in board.repositories:
        fake.add_repo(repo.full_name)
    return fake.add_project(board.project.owner_type, board.project.owner, 1, board.project.title)


def bootstrap(fake: FakeGitHub, client: Client, board: Board) -> tuple[int, str]:
    ctx, out = make_context(fake, board, client)
    return run(ctx, ARGS), out.getvalue()


def test_an_empty_project_gets_every_field_and_view_and_then_audits_clean(fake: FakeGitHub, client: Client) -> None:
    board = load_test_board()
    empty_project(fake, board)
    code, text = bootstrap(fake, client, board)
    assert code == 0
    assert (
        "CREATED field 'Status' (single_select)" in text
        and "CREATED view 'Board' (board, filter '-status:Done')" in text
    )
    assert "[ ] Roadmap: Date fields" in text
    ctx, out = make_context(fake, board, client)
    assert audit_run(ctx, ARGS) == 0, out.getvalue()


def test_each_view_filter_is_set_by_update_after_the_create_and_never_sent_on_create(
    fake: FakeGitHub, client: Client
) -> None:
    board = load_test_board()
    empty_project(fake, board)
    bootstrap(fake, client, board)
    ops = [m.op for m in fake.mutations if m.op in ("CreateView", "UpdateView")]
    assert ops == ["CreateView", "UpdateView", "CreateView", "UpdateView"]
    for m in fake.mutations_named("CreateView"):
        assert "filter" not in m.variables["input"]
    assert [m.variables["input"]["filter"] for m in fake.mutations_named("UpdateView")] == ["-status:Done"] * 2


def test_the_fake_really_refuses_a_filter_on_create(fake: FakeGitHub, client: Client) -> None:
    """The model of the API quirk is itself tested, so a regression in the code cannot hide behind it."""
    project = fake.add_project("organization", "acme", 1, "T")
    with pytest.raises(ApiError, match="doesn't accept argument 'filter'"):
        client.execute(
            M_CREATE_VIEW, {"input": {"projectId": project.id, "name": "V", "layout": "BOARD_LAYOUT", "filter": "x"}}
        )


def test_a_second_run_creates_nothing(fake: FakeGitHub, client: Client) -> None:
    board = load_test_board()
    empty_project(fake, board)
    bootstrap(fake, client, board)
    sent = len(fake.mutations)
    code, text = bootstrap(fake, client, board)
    assert code == 0 and len(fake.mutations) == sent
    assert "nothing to create" in text


def test_only_what_is_missing_is_created(fake: FakeGitHub, client: Client) -> None:
    board = load_test_board()
    project = empty_project(fake, board)
    for f in board.fields[:3]:  # Status, Area, Priority already exist
        fake.add_field(project, f.name, "SINGLE_SELECT", [(o.name, o.color, o.description) for o in f.options])
    fake.add_view(project, "Board", "BOARD_LAYOUT", "-status:Done")
    bootstrap(fake, client, board)
    created = [m.variables["input"]["name"] for m in fake.mutations_named("CreateField")]
    assert created == ["Agent", "Sprint", "Done on"]
    assert [m.variables["input"]["name"] for m in fake.mutations_named("CreateView")] == ["Roadmap"]


def test_a_new_single_select_carries_colour_and_description_on_every_option(fake: FakeGitHub, client: Client) -> None:
    board = load_test_board()
    empty_project(fake, board)
    bootstrap(fake, client, board)
    status = next(m for m in fake.mutations_named("CreateField") if m.variables["input"]["name"] == "Status")
    assert status.variables["input"]["singleSelectOptions"][3] == {
        "name": "Blocked",
        "color": "RED",
        "description": "Needs the maintainer",
    }


def test_an_iteration_field_is_created_with_its_whole_list(fake: FakeGitHub, client: Client) -> None:
    board = load_test_board()
    empty_project(fake, board)
    bootstrap(fake, client, board)
    sprint = next(m for m in fake.mutations_named("CreateField") if m.variables["input"]["name"] == "Sprint")
    cfg = sprint.variables["input"]["iterationConfiguration"]
    assert cfg["startDate"] == "2026-10-06" and cfg["duration"] == 14
    assert [i["startDate"] for i in cfg["iterations"]] == ["2026-10-06", "2026-10-20", "2026-11-03"]
    assert cfg["iterations"][0]["title"] == "Sprint 1"


def test_a_missing_option_on_an_existing_field_is_refused_and_nothing_is_sent_to_it(
    fake: FakeGitHub, client: Client
) -> None:
    """The lesson that cost a board its values: the option update replaces every option id."""
    board = load_test_board()
    project = empty_project(fake, board)
    status = fake.add_field(project, "Status", "SINGLE_SELECT", [("Backlog", "GRAY", ""), ("Done", "GREEN", "")])
    card = fake.add_content("acme/widgets", "Issue", 1)
    item = fake.add_item(project, card, Status="Done")
    before = dict(item.values)
    code, text = bootstrap(fake, client, board)
    assert code == 1
    assert "REFUSED field 'Status' lacks the option 'Next'" in text
    assert "Settings > Status > Add option" in text
    assert all(m.variables["input"].get("name") != "Status" for m in fake.mutations_named("CreateField"))
    assert "UpdateField" not in fake.requests
    assert item.values == before and [o.name for o in status.options] == ["Backlog", "Done"]


def test_an_iteration_field_that_is_short_is_refused_with_the_ui_step(fake: FakeGitHub, client: Client) -> None:
    board = load_test_board()
    project = empty_project(fake, board)
    sprint = fake.add_field(project, "Sprint", "ITERATION")
    sprint.iterations = [{"id": "I1", "title": "Sprint 1", "startDate": "2026-10-06", "duration": 14}]
    code, text = bootstrap(fake, client, board)
    assert code == 1 and "REFUSED field 'Sprint' lacks the iteration starting 2026-10-20" in text
    assert "Add iteration" in text


def test_a_field_of_the_wrong_type_is_refused(fake: FakeGitHub, client: Client) -> None:
    board = load_test_board()
    project = empty_project(fake, board)
    fake.add_field(project, "Done on", "TEXT")
    code, text = bootstrap(fake, client, board)
    assert code == 1 and "REFUSED field 'Done on' is text on the project but date in board.yaml" in text


def test_an_existing_view_with_another_layout_is_refused_and_with_another_filter_is_left_alone(
    fake: FakeGitHub, client: Client
) -> None:
    board = load_test_board()
    project = empty_project(fake, board)
    fake.add_view(project, "Board", "TABLE_LAYOUT", "-status:Done")
    fake.add_view(project, "Roadmap", "ROADMAP_LAYOUT", "something else")
    code, text = bootstrap(fake, client, board)
    assert code == 1 and "REFUSED view 'Board' is a table layout" in text
    assert "REFUSED view 'Roadmap' exists with the filter 'something else'" in text
    assert fake.mutations_named("UpdateView") == []


def test_an_option_with_another_colour_is_left_alone_and_is_not_a_refusal(fake: FakeGitHub, client: Client) -> None:
    """Review focus 1 at bootstrap: same name, other colour. Nothing to create, nothing to refuse."""
    board = load_test_board()
    empty_project(fake, board)
    bootstrap(fake, client, board)
    project = next(iter(fake.projects.values()))
    fake.field(project, "Status").options[0].color = "PINK"
    fake.mutations.clear()
    code, text = bootstrap(fake, client, board)
    assert code == 0 and fake.mutations == []
    assert "LEFT    field 'Status' option 'Backlog' keeps its live colour PINK" in text


def test_a_project_with_no_number_is_created_and_its_number_printed(fake: FakeGitHub, client: Client) -> None:
    board = load_test_board()
    board = dataclasses.replace(board, project=dataclasses.replace(board.project, number=None))
    fake.add_owner("organization", "acme")
    code, text = bootstrap(fake, client, board)
    assert code == 0 and "created project 'Acme board': number 1." in text
    assert "Write `number: 1` under project:" in text
    assert fake.mutations[0].op == "CreateProject"
    project = fake.project_by_number("organization", "acme", 1)
    assert project and {f.name for f in project.fields} >= {"Status", "Sprint"}


def test_a_created_project_with_a_malformed_number_is_a_named_error_not_a_traceback(
    fake: FakeGitHub, client: Client
) -> None:
    board = load_test_board()
    board = dataclasses.replace(board, project=dataclasses.replace(board.project, number=None))
    fake.add_owner("organization", "acme")
    fake.handlers["CreateProject"] = lambda f, v: {"createProjectV2": {"projectV2": {"id": "P", "number": "soon"}}}
    with pytest.raises(ApiError, match=r"createProjectV2\.projectV2\.number: expected a whole number"):
        bootstrap(fake, client, board)


def test_a_dry_run_sends_nothing(fake: FakeGitHub, sleeps: list[float]) -> None:
    board = load_test_board()
    empty_project(fake, board)
    sent = io.StringIO()
    dry = Client(fake.token, fake.url, dry_run=True, sleep=sleeps.append, out=sent)
    ctx, _ = make_context(fake, board, dry)
    assert run(ctx, ARGS) == 1  # work is pending, so a dry run is not clean
    assert fake.mutations == [] and "dry run: would CreateField" in sent.getvalue()
    assert "dry run: would UpdateView" in sent.getvalue()


def test_a_rejected_create_is_not_swallowed(fake: FakeGitHub, client: Client) -> None:
    def forbidden(f: FakeGitHub, v: dict[str, object]) -> dict[str, object]:
        raise GqlError("FORBIDDEN", "Resource not accessible by integration")

    fake.handlers["CreateField"] = forbidden
    board = load_test_board()
    empty_project(fake, board)
    code, text = bootstrap(fake, client, board)
    assert code == 2 and "unknown outcome: re-run after checking the board" in text


def test_field_inputs_never_name_a_field_that_exists(fake: FakeGitHub, client: Client) -> None:
    board = load_test_board()
    project = empty_project(fake, board)
    existing: FField = fake.add_field(project, "Area", "SINGLE_SELECT", [("Core", "BLUE", ""), ("Docs", "PURPLE", "")])
    bootstrap(fake, client, board)
    assert "Area" not in [m.variables["input"]["name"] for m in fake.mutations_named("CreateField")]
    assert existing.options[0].name == "Core"


def test_project_stored_then_response_lost_is_discovered_on_rerun(
    fake: FakeGitHub, client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    from safo.errors import UnknownOutcomeError

    board = load_test_board()
    board = dataclasses.replace(board, project=dataclasses.replace(board.project, number=None))
    fake.add_owner("organization", "acme")
    real = client.execute
    lost = False

    def execute(document: str, variables: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        nonlocal lost
        data = real(document, variables, **kwargs)
        if "mutation CreateProject(" in document and not lost:
            lost = True
            raise UnknownOutcomeError("lost response", data=data, errors=[], status=502)
        return data

    monkeypatch.setattr(client, "execute", execute)
    code, text = bootstrap(fake, client, board)
    assert code == 2 and "unknown outcome: re-run after checking the board" in text
    assert len(fake.projects) == 1 and len(fake.mutations) == 1
    code, text = bootstrap(fake, client, board)
    assert code == 0 and len(fake.projects) == 1
    assert len(fake.mutations_named("CreateProject")) == 1


def test_view_filter_lost_response_requires_reread_and_never_reports_clean_mismatch(
    fake: FakeGitHub, client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    from safo.errors import UnknownOutcomeError

    board = load_test_board()
    empty_project(fake, board)
    real = client.execute
    failed = False

    def execute(document: str, variables: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        nonlocal failed
        if "mutation UpdateView(" in document and not failed:
            failed = True
            raise UnknownOutcomeError("filter response lost", data=None, errors=[], status=502)
        return real(document, variables, **kwargs)

    monkeypatch.setattr(client, "execute", execute)
    code, text = bootstrap(fake, client, board)
    assert code == 2 and "unknown outcome" in text
    assert fake.requests.count("ProjectViewsOrg") >= 2
    count = len(fake.mutations_named("CreateView"))
    code, text = bootstrap(fake, client, board)
    assert code == 1 and "repair its filter" in text
    assert len(fake.mutations_named("CreateView")) == count + 1  # only the other missing view is created


def test_bootstrap_refuses_wrong_iteration_duration_without_updating_field(fake: FakeGitHub, client: Client) -> None:
    board = load_test_board()
    from world import build_world

    _, project = build_world(fake, board)
    fake.field(project, "Sprint").iterations[0]["duration"] = 7
    code, text = bootstrap(fake, client, board)
    assert code == 1 and "Edit iteration duration to 14 days" in text
    assert fake.mutations == []


def test_a_matching_existing_project_is_reported_as_adopted(fake: FakeGitHub, client: Client) -> None:
    board = load_test_board()
    empty_project(fake, board)
    assert bootstrap(fake, client, board)[0] == 0
    board = dataclasses.replace(board, project=dataclasses.replace(board.project, number=None))
    code, text = bootstrap(fake, client, board)
    assert code == 0 and "adopted existing project 'Acme board': number 1." in text
    assert "created project" not in text and not fake.mutations_named("CreateProject")


def test_an_unknown_create_is_never_replayed_and_stops_every_later_write(fake: FakeGitHub, client: Client) -> None:
    def forbidden(f: FakeGitHub, v: dict[str, object]) -> dict[str, object]:
        raise GqlError("FORBIDDEN", "Resource not accessible by integration")

    fake.handlers["CreateField"] = forbidden
    board = load_test_board()
    empty_project(fake, board)
    code, text = bootstrap(fake, client, board)
    assert code == 2 and "unknown outcome" in text
    assert fake.requests.count("CreateField") == 1
    assert [m.op for m in fake.mutations] == ["CreateField"]  # no second field, no view
    assert "re-read the live board after the unknown outcome" in text


def test_an_unknown_outcome_whose_reread_also_fails_says_so_and_still_exits_2(
    fake: FakeGitHub, client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    from safo.errors import UnknownOutcomeError

    board = load_test_board()
    empty_project(fake, board)
    real = client.execute
    lost = False

    def execute(document: str, variables: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        nonlocal lost
        if "mutation CreateField(" in document:
            lost = True
            raise UnknownOutcomeError("lost response", data=None, errors=[], status=502)
        if "query ProjectFieldsOrg(" in document and lost:
            raise ApiError("reread unavailable")
        return real(document, variables, **kwargs)

    monkeypatch.setattr(client, "execute", execute)
    code, text = bootstrap(fake, client, board)
    assert code == 2 and "live reread failed; no further writes" in text and "unknown outcome" in text
    assert "re-read the live board" not in text


def test_a_description_only_difference_is_left_alone_and_named_as_such(fake: FakeGitHub, client: Client) -> None:
    board = load_test_board()
    empty_project(fake, board)
    bootstrap(fake, client, board)
    project = next(iter(fake.projects.values()))
    fake.field(project, "Status").options[0].description = "changed in the UI"
    fake.mutations.clear()
    code, text = bootstrap(fake, client, board)
    assert code == 0 and fake.mutations == []
    assert "LEFT    field 'Status' option 'Backlog' keeps its live description" in text


def test_a_malformed_live_value_is_exit_2_from_the_command_line_not_a_traceback(
    fake: FakeGitHub, client: Client
) -> None:
    from pathlib import Path

    from safo.cli import main
    from world import build_world

    _, project = build_world(fake)
    fake.field(project, "Sprint").iterations[0]["startDate"] = "not-a-date"
    out, err = io.StringIO(), io.StringIO()
    board_file = str(Path(__file__).parent / "data" / "board.yaml")
    code = main(["--board", board_file, "bootstrap"], env={}, client_factory=lambda b, e, d: client, out=out, err=err)
    assert code == 2 and "startDate" in err.getvalue() and "not a date" in err.getvalue()
    assert fake.mutations == []


def test_the_cli_exit_code_for_a_refusal_is_1(fake: FakeGitHub, client: Client) -> None:
    from pathlib import Path

    from safo.cli import main

    board = load_test_board()
    project = empty_project(fake, board)
    fake.add_field(project, "Status", "SINGLE_SELECT", [("Backlog", "GRAY", "")])
    out, err = io.StringIO(), io.StringIO()
    board_file = str(Path(__file__).parent / "data" / "board.yaml")
    code = main(["--board", board_file, "bootstrap"], env={}, client_factory=lambda b, e, d: client, out=out, err=err)
    assert code == 1 and "REFUSED field 'Status' lacks the option 'Next'" in out.getvalue()
    assert "UpdateField" not in fake.requests


def _cli(fake: FakeGitHub, client: Client, *argv: str) -> tuple[int, str, str]:
    from pathlib import Path

    from safo.cli import main

    out, err = io.StringIO(), io.StringIO()
    board_file = str(Path(__file__).parent / "data" / "board.yaml")
    code = main(["--board", board_file, *argv], env={}, client_factory=lambda b, e, d: client, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


@pytest.mark.parametrize(
    ("op", "payload", "prefilled"),
    [
        ("CreateField", {"createProjectV2Field": None}, False),
        ("CreateField", {"createProjectV2Field": {"projectV2Field": {"name": "no id"}}}, False),
        ("CreateView", {"createProjectV2View": None}, True),
        ("CreateView", {"createProjectV2View": {"projectV2View": {"name": "no id"}}}, True),
        ("UpdateView", {"updateProjectV2View": None}, True),
        ("UpdateView", {"updateProjectV2View": {"projectV2View": {"filter": "x"}}}, True),
    ],
)
def test_a_mutation_answered_with_null_or_no_id_is_an_unknown_outcome_never_created(
    fake: FakeGitHub, client: Client, op: str, payload: dict[str, object], prefilled: bool
) -> None:
    board = load_test_board()
    project = empty_project(fake, board)
    if prefilled:  # reach the view mutations without a CreateField in the way
        for f in board.fields:
            if f.type == "single_select":
                fake.add_field(project, f.name, "SINGLE_SELECT", [(o.name, o.color, o.description) for o in f.options])
        fake.add_field(project, "Sprint", "ITERATION").iterations = [
            {"id": f"I{n}", "title": f"Sprint {n}", "startDate": d, "duration": 14}
            for n, d in enumerate(["2026-10-06", "2026-10-20", "2026-11-03"])
        ]
        fake.add_field(project, "Done on", "DATE")
    fake.handlers[op] = lambda f, v: payload
    code, text = bootstrap(fake, client, board)
    assert code == 2 and "unknown outcome" in text and "CREATED" not in text
    assert "observed:" in text
    assert [m.op for m in fake.mutations][-1] == op and fake.requests.count(op) == 1


def test_a_null_create_project_payload_is_unknown_and_the_reread_says_nothing_landed(
    fake: FakeGitHub, client: Client
) -> None:
    board = load_test_board()
    board = dataclasses.replace(board, project=dataclasses.replace(board.project, number=None))
    fake.add_owner("organization", "acme")
    fake.handlers["CreateProject"] = lambda f, v: {"createProjectV2": None}
    code, text = bootstrap(fake, client, board)
    assert code == 2 and "created project" not in text and len(fake.mutations) == 1
    assert "observed: no project titled 'Acme board' exists" in text


def test_a_malformed_reread_after_an_unknown_outcome_is_exit_2_with_a_line_not_a_traceback(
    fake: FakeGitHub, client: Client
) -> None:
    from fakegh.reads import meta_org

    board = load_test_board()
    empty_project(fake, board)

    def forbidden(f: FakeGitHub, v: dict[str, object]) -> dict[str, object]:
        raise GqlError("FORBIDDEN", "Resource not accessible by integration")

    def broken(f: FakeGitHub, v: dict[str, Any]) -> dict[str, Any]:
        data = meta_org(f, v)
        if f.mutations:
            data["organization"]["projectV2"]["items"] = None
        return data

    fake.handlers["CreateField"] = forbidden
    fake.handlers["ProjectMetaOrg"] = broken
    code, out, err = _cli(fake, client, "bootstrap")
    assert code == 2 and err == "" and "live reread failed; no further writes" in out


def test_load_live_turns_a_missing_key_into_malformed_data(fake: FakeGitHub, client: Client) -> None:
    from fakegh.reads import meta_org
    from safo.errors import MalformedDataError
    from safo.live import load_live

    board = load_test_board()
    empty_project(fake, board)

    def broken(f: FakeGitHub, v: dict[str, Any]) -> dict[str, Any]:
        data = meta_org(f, v)
        del data["organization"]["projectV2"]["items"]
        return data

    fake.handlers["ProjectMetaOrg"] = broken
    with pytest.raises(MalformedDataError, match="not shaped as expected"):
        load_live(client, board.project)


def _lose_reply(client: Client, monkeypatch: pytest.MonkeyPatch, operation: str, *, apply: bool) -> None:
    real = client.execute

    def execute(document: str, variables: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        if f"mutation {operation}(" in document:
            if apply:
                real(document, variables, **kwargs)
            raise UnknownOutcomeError("reply lost", data=None, errors=[], status=502)
        return real(document, variables, **kwargs)

    monkeypatch.setattr(client, "execute", execute)


@pytest.mark.parametrize(("apply", "seen"), [(True, "exists as single_select"), (False, "does not exist")])
def test_the_reread_after_a_lost_field_create_says_whether_the_field_exists(
    fake: FakeGitHub, client: Client, monkeypatch: pytest.MonkeyPatch, apply: bool, seen: str
) -> None:
    board = load_test_board()
    empty_project(fake, board)
    _lose_reply(client, monkeypatch, "CreateField", apply=apply)
    code, text = bootstrap(fake, client, board)
    assert code == 2 and f"observed: field 'Status' {seen}" in text


@pytest.mark.parametrize(("apply", "seen"), [(True, "'-status:Done'"), (False, "''")])
def test_the_reread_after_a_lost_filter_update_shows_the_live_filter(
    fake: FakeGitHub, client: Client, monkeypatch: pytest.MonkeyPatch, apply: bool, seen: str
) -> None:
    board = load_test_board()
    empty_project(fake, board)
    _lose_reply(client, monkeypatch, "UpdateView", apply=apply)
    code, text = bootstrap(fake, client, board)
    assert code == 2 and f"observed: view 'Board' exists with the filter {seen}" in text


def test_a_reread_that_finds_several_projects_says_so(
    fake: FakeGitHub, client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    board = load_test_board()
    board = dataclasses.replace(board, project=dataclasses.replace(board.project, number=None))
    fake.add_owner("organization", "acme")
    real = client.execute

    def execute(document: str, variables: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        if "mutation CreateProject(" in document:
            fake.add_project("organization", "acme", 1, "Acme board")
            fake.add_project("organization", "acme", 2, "Acme board")
            raise UnknownOutcomeError("reply lost", data=None, errors=[], status=502)
        return real(document, variables, **kwargs)

    monkeypatch.setattr(client, "execute", execute)
    code, text = bootstrap(fake, client, board)
    assert code == 2 and "observed: 2 projects are titled 'Acme board'; set project.number" in text
    assert "re-read the live board" not in text and "no board was loaded" in text


def test_a_dry_run_with_nothing_to_create_exits_0(fake: FakeGitHub, sleeps: list[float]) -> None:
    board = load_test_board()
    empty_project(fake, board)
    sent = io.StringIO()
    real = Client(fake.token, fake.url, sleep=sleeps.append, out=sent)
    ctx, _ = make_context(fake, board, real)
    assert run(ctx, ARGS) == 0
    dry = Client(fake.token, fake.url, dry_run=True, sleep=sleeps.append, out=sent)
    ctx, out = make_context(fake, board, dry)
    assert run(ctx, ARGS) == 0 and "nothing to create" in out.getvalue()


def test_a_dry_run_says_would_create_never_created(fake: FakeGitHub, sleeps: list[float]) -> None:
    board = load_test_board()
    empty_project(fake, board)
    dry = Client(fake.token, fake.url, dry_run=True, sleep=sleeps.append, out=io.StringIO())
    ctx, out = make_context(fake, board, dry)
    assert run(ctx, ARGS) == 1
    assert "WOULD CREATE field 'Status' (single_select)" in out.getvalue() and "CREATED" not in out.getvalue()


def test_a_dry_run_that_would_create_the_project_says_so_and_exits_1(fake: FakeGitHub, sleeps: list[float]) -> None:
    board = load_test_board()
    board = dataclasses.replace(board, project=dataclasses.replace(board.project, number=None))
    fake.add_owner("organization", "acme")
    dry = Client(fake.token, fake.url, dry_run=True, sleep=sleeps.append, out=io.StringIO())
    ctx, out = make_context(fake, board, dry)
    assert run(ctx, ARGS) == 1 and "WOULD CREATE project 'Acme board'" in out.getvalue()
    assert "created project" not in out.getvalue() and fake.mutations == []


def test_live_extras_get_one_note_pointing_at_audit_and_do_not_change_the_exit(
    fake: FakeGitHub, client: Client
) -> None:
    board = load_test_board()
    empty_project(fake, board)
    bootstrap(fake, client, board)
    project = next(iter(fake.projects.values()))
    fake.field(project, "Status").options.append(FOption("OPT_X", "Extra", "GRAY", ""))
    fake.add_view(project, "Mine", "TABLE_LAYOUT")
    code, text = bootstrap(fake, client, board)
    assert code == 0 and text.count("NOTE") == 1
    assert "2 live option(s) or view(s) are not in board.yaml; `safo audit` reports them" in text


def _reread_raises(client: Client, monkeypatch: pytest.MonkeyPatch, error: BaseException) -> None:
    real = client.execute
    lost = False

    def execute(document: str, variables: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        nonlocal lost
        if "mutation CreateField(" in document:
            lost = True
            raise UnknownOutcomeError("lost response", data=None, errors=[], status=502)
        if "query ProjectFieldsOrg(" in document and lost:
            raise error
        return real(document, variables, **kwargs)

    monkeypatch.setattr(client, "execute", execute)


def test_a_failed_reread_names_the_error_type_and_a_safo_errors_own_message(
    fake: FakeGitHub, client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    board = load_test_board()
    empty_project(fake, board)
    _reread_raises(client, monkeypatch, ApiError("reread unavailable"))
    code, text = bootstrap(fake, client, board)
    assert code == 2 and "live reread failed; no further writes (ApiError: reread unavailable)" in text


def test_a_failed_reread_with_a_foreign_error_prints_the_type_only(
    fake: FakeGitHub, client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    board = load_test_board()
    empty_project(fake, board)
    _reread_raises(client, monkeypatch, RuntimeError("sentinel-payload-value"))
    code, text = bootstrap(fake, client, board)
    assert code == 2 and "live reread failed; no further writes (RuntimeError)" in text
    assert "sentinel-payload-value" not in text


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit(3)])
def test_an_interrupt_during_the_reread_still_propagates(
    fake: FakeGitHub, client: Client, monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    board = load_test_board()
    empty_project(fake, board)
    _reread_raises(client, monkeypatch, error)
    with pytest.raises(type(error)):
        bootstrap(fake, client, board)
