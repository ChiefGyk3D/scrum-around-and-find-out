# SPDX-License-Identifier: MIT
"""sync: one event, one card. Ported from GYST's project_sync tests, plus the adopter mistakes and hostile payloads."""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import threading
from pathlib import Path
from typing import Any

import pytest

from fakegh import FakeGitHub
from fakegh.core import HANDLERS, Fault, FContent, FProject
from safo.errors import ConfigError, SafoError, UnknownOutcomeError
from safo.graphql import Client
from safo.modes.sync import run
from safo.schema import Board
from world import build_world, load_test_board, make_context


def event(tmp_path: Path, kind: str, action: str, content: FContent, **over: Any) -> Path:
    body: dict[str, Any] = {
        "number": content.number,
        "node_id": content.id,
        "state": "open" if content.state == "OPEN" else "closed",
        "closed_at": content.closed_at,
        "title": "IGNORE docs ME",
    }
    if kind == "pull_request":
        body["draft"] = content.draft
        body["merged"] = content.state == "MERGED"
    body.update(over)
    payload = {"action": action, kind: body, "repository": {"full_name": content.repo}}
    path = tmp_path / "event.json"
    path.write_text(json.dumps(payload))
    return path


def raw_event(tmp_path: Path, payload: Any) -> Path:
    path = tmp_path / "raw.json"
    path.write_text(json.dumps(payload))
    return path


def sync(
    fake: FakeGitHub, client: Client, path: Path, board: Board | None = None, event_name: str = "issues"
) -> tuple[int, str]:
    ctx, out = make_context(fake, board or load_test_board(), client)
    args = argparse.Namespace(event_path=str(path), event_name=event_name)
    return run(ctx, args), out.getvalue()


def values(fake: FakeGitHub, project: FProject) -> dict[str, str | None]:
    item = project.items[0]
    return {n: fake.value(project, item, n) for n in ("Status", "Area", "Priority", "Done on")}


def test_an_opened_issue_is_added_with_the_open_status_the_repository_area_and_the_defaults(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    _, project = build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    code, text = sync(fake, client, event(tmp_path, "issue", "opened", issue))
    assert code == 0 and text.startswith("added #1; Status = Backlog; Area = Core")
    assert values(fake, project) == {"Status": "Backlog", "Area": "Core", "Priority": "P2 later", "Done on": None}


def test_the_title_is_never_read_so_the_repository_default_area_wins_over_an_area_rule(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    _, project = build_world(fake)
    pr = fake.add_content("acme/widgets", "PullRequest", 2, "docs docs docs")
    sync(fake, client, event(tmp_path, "pull_request", "opened", pr))
    assert values(fake, project)["Area"] == "Core"  # reconcile would say Docs; an event never reads the title


def test_an_edit_adds_a_missing_card_and_changes_nothing_on_a_present_one(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    _, project = build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    sync(fake, client, event(tmp_path, "issue", "edited", issue))
    fake.mutations.clear()
    code, text = sync(fake, client, event(tmp_path, "issue", "edited", issue))
    assert code == 0 and fake.mutations == [] and text.strip() == "#1: already current"
    assert len(project.items) == 1


def test_a_status_already_set_on_an_open_issue_is_left_alone(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    _, project = build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    fake.add_item(project, issue, Status="Blocked", Area="Core")
    sync(fake, client, event(tmp_path, "issue", "edited", issue))
    assert values(fake, project)["Status"] == "Blocked"


def test_a_reopened_issue_that_was_done_goes_back_and_loses_its_date(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    _, project = build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    fake.add_item(project, issue, Status="Done", Area="Core", Priority="P2 later", Done_on="2026-10-01")
    code, text = sync(fake, client, event(tmp_path, "issue", "reopened", issue))
    assert code == 0 and "Status = Backlog" in text and "Done on cleared" in text
    assert values(fake, project)["Status"] == "Backlog" and values(fake, project)["Done on"] is None


def test_an_edit_never_moves_a_done_open_item(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    _, project = build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    fake.add_item(project, issue, Status="Done", Area="Core", Priority="P2 later", Done_on="2026-10-01")
    sync(fake, client, event(tmp_path, "issue", "edited", issue))
    assert fake.mutations == []


def test_a_pull_request_takes_its_status_from_its_draft_state_and_follows_it(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    _, project = build_world(fake)
    pr = fake.add_content("acme/widgets", "PullRequest", 2, draft=True)
    sync(fake, client, event(tmp_path, "pull_request", "opened", pr))
    assert values(fake, project)["Status"] == "Backlog"
    pr.draft = False
    sync(fake, client, event(tmp_path, "pull_request", "ready_for_review", pr))
    assert values(fake, project)["Status"] == "In progress"
    pr.draft = True
    sync(fake, client, event(tmp_path, "pull_request", "converted_to_draft", pr))
    assert values(fake, project)["Status"] == "Backlog"


def test_a_closed_issue_is_done_with_its_close_date(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    _, project = build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1, state="CLOSED", closed_at="2026-10-03T08:00:00Z")
    fake.add_item(project, issue, Status="In progress", Area="Core")
    sync(fake, client, event(tmp_path, "issue", "closed", issue))
    assert values(fake, project)["Status"] == "Done" and values(fake, project)["Done on"] == "2026-10-03"


def test_a_merged_pull_request_is_done_with_the_merge_date(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    _, project = build_world(fake)
    pr = fake.add_content("acme/widgets", "PullRequest", 2, state="MERGED", closed_at="2026-10-04T09:00:00Z")
    fake.add_item(project, pr, Status="In progress", Area="Core")
    sync(fake, client, event(tmp_path, "pull_request", "closed", pr))
    assert values(fake, project)["Status"] == "Done" and values(fake, project)["Done on"] == "2026-10-04"


def test_a_closed_item_that_is_not_on_the_board_is_added_as_done(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    _, project = build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1, state="CLOSED", closed_at="2026-10-03T08:00:00Z")
    sync(fake, client, event(tmp_path, "issue", "closed", issue))
    assert values(fake, project)["Status"] == "Done" and values(fake, project)["Done on"] == "2026-10-03"


def test_closing_a_done_item_that_has_its_date_changes_nothing(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    _, project = build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1, state="CLOSED", closed_at="2026-10-03T08:00:00Z")
    fake.add_item(project, issue, Status="Done", Area="Core", Priority="P2 later", Done_on="2026-10-03")
    code, text = sync(fake, client, event(tmp_path, "issue", "closed", issue))
    assert code == 0 and fake.mutations == [] and "already current" in text


def test_an_empty_done_date_field_disables_the_date(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    board = load_test_board()
    board = dataclasses.replace(board, rules=dataclasses.replace(board.rules, done_date_field=""))
    build_world(fake, board)
    issue = fake.add_content("acme/widgets", "Issue", 1, state="CLOSED", closed_at="2026-10-03T08:00:00Z")
    sync(fake, client, event(tmp_path, "issue", "closed", issue), board)
    assert not fake.mutations_named("SetDate")


def test_an_item_on_another_project_does_not_count_as_ours(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    _, project = build_world(fake)
    other = fake.add_project("organization", "acme", 2, "Other")
    fake.add_field(other, "Status", "SINGLE_SELECT", [("Done", "GREEN", "")])
    issue = fake.add_content("acme/widgets", "Issue", 1)
    fake.add_item(other, issue, Status="Done")
    sync(fake, client, event(tmp_path, "issue", "opened", issue))
    assert len(project.items) == 1 and values(fake, project)["Status"] == "Backlog"


# -- the repository: compared without case, and an unlisted one is a NOTE that sends nothing --------------------------


def test_an_event_for_a_repository_board_yaml_does_not_list_is_a_note_that_touches_nothing(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    build_world(fake)
    fake.add_repo("acme/elsewhere")
    issue = fake.add_content("acme/elsewhere", "Issue", 1)
    code, text = sync(fake, client, event(tmp_path, "issue", "opened", issue))
    assert code == 1 and "NOTE repository acme/elsewhere is not listed in board.yaml" in text
    assert fake.requests == []


def test_the_repository_is_matched_without_case(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    _, project = build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    path = event(tmp_path, "issue", "opened", issue)
    payload = json.loads(path.read_text())
    payload["repository"]["full_name"] = "ACME/Widgets"
    path.write_text(json.dumps(payload))
    code, _ = sync(fake, client, path)
    assert code == 0 and values(fake, project)["Area"] == "Core"


def test_an_unlisted_repository_name_is_escaped_clipped_and_cannot_start_a_command(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    path = event(tmp_path, "issue", "opened", issue)
    payload = json.loads(path.read_text())
    payload["repository"]["full_name"] = "x/y\n::error::forged\x1b[2J" + "z" * 500
    path.write_text(json.dumps(payload))
    code, text = sync(fake, client, path)
    assert code == 1 and fake.requests == []
    assert not any(line.startswith("::") for line in text.splitlines()) and "\x1b" not in text
    assert "\\x0a:\\x3aerror:\\x3aforged" in text and "..." in text and "z" * 200 not in text


def test_a_notice_about_an_action_cannot_start_with_a_command_even_from_the_event_name(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    code, text = sync(
        fake, client, event(tmp_path, "issue", "labeled", issue), event_name="::warning::boom\n::error::x"
    )
    assert code == 0 and not any(line.startswith("::") for line in text.splitlines())


@pytest.mark.parametrize("action", ["labeled", "assigned", "deleted", "transferred", "synchronize"])
def test_an_action_that_does_not_change_a_card_is_ignored_without_a_request(
    fake: FakeGitHub, client: Client, tmp_path: Path, action: str
) -> None:
    build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    code, text = sync(fake, client, event(tmp_path, "issue", action, issue))
    assert code == 0 and "nothing to do" in text and fake.requests == []


def test_a_pull_request_only_action_does_not_change_an_issue(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    code, text = sync(fake, client, event(tmp_path, "issue", "ready_for_review", issue))
    assert code == 0 and "nothing to do" in text and fake.requests == []


def test_a_payload_with_neither_an_issue_nor_a_pull_request_is_a_config_error(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    build_world(fake)
    path = tmp_path / "e.json"
    path.write_text(json.dumps({"action": "opened", "repository": {"full_name": "acme/widgets"}}))
    with pytest.raises(ConfigError, match="neither an issue nor a pull request"):
        sync(fake, client, path)


def test_a_missing_payload_file_is_a_config_error(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    build_world(fake)
    with pytest.raises(ConfigError, match="cannot read the event payload"):
        sync(fake, client, tmp_path / "nope.json")


def run_with_timeout(call: Any, seconds: float = 5.0) -> Any:
    """Run `call` on a thread: a hang is a failure, not a stuck test run."""
    box: dict[str, Any] = {}

    def target() -> None:
        try:
            box["result"] = call()
        except BaseException as err:
            box["error"] = err

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(seconds)
    assert not thread.is_alive(), "the call hung"
    if "error" in box:
        raise box["error"]
    return box["result"]


def test_a_payload_path_that_is_a_fifo_is_refused_without_blocking(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    build_world(fake)
    fifo = tmp_path / "pipe.json"
    os.mkfifo(fifo)
    with pytest.raises(ConfigError, match="not a regular file"):
        run_with_timeout(lambda: sync(fake, client, fifo))
    assert fake.requests == []


def test_a_payload_path_that_is_a_symlink_is_refused(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    real = event(tmp_path, "issue", "opened", issue)
    link = tmp_path / "link.json"
    link.symlink_to(real)
    with pytest.raises(ConfigError, match="cannot read the event payload"):
        run_with_timeout(lambda: sync(fake, client, link))
    assert fake.requests == []


def test_the_payload_path_comes_from_the_environment_when_no_flag_is_given(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    _, project = build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    path = event(tmp_path, "issue", "opened", issue)
    ctx, _ = make_context(fake, load_test_board(), client)
    ctx.env = {"GITHUB_EVENT_PATH": str(path), "GITHUB_EVENT_NAME": "issues"}
    assert run(ctx, argparse.Namespace(event_path="", event_name="")) == 0 and len(project.items) == 1
    ctx.env = {}
    with pytest.raises(ConfigError, match="no payload file"):
        run(ctx, argparse.Namespace(event_path="", event_name=""))


def test_an_issue_deleted_after_the_event_is_named_and_exits_2(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    fake.vanished.add(issue.id)
    code, text = sync(fake, client, event(tmp_path, "issue", "opened", issue))
    assert code == 2 and "VANISHED" in text and "(confirmed by read)" in text and fake.mutations == []


# -- hostile payloads: refused before any request ---------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "[]",
        '{"issue": []}',
        "[" * 65 + "0" + "]" * 65,
        json.dumps(
            {
                "action": "labeled",
                "repository": {"full_name": "acme/widgets"},
                "issue": {"node_id": "I_1", "number": 1, "state": "open"},
            }
        )
        + " " * 1_048_577,
    ],
    ids=["nonobject", "bad-issue", "depth", "oversize-valid-json"],
)
def test_event_bounds_and_shape_errors_exit_2_without_mutation(
    fake: FakeGitHub, client: Client, tmp_path: Path, raw: str
) -> None:
    from cliutil import BOARD, run_cli

    build_world(fake)
    path = tmp_path / "invalid.json"
    path.write_text(raw)
    code, _, _ = run_cli("--board", BOARD, "sync", "--event-path", str(path), client=client)
    assert code == 2 and fake.mutations == []


def good_payload(**issue: Any) -> dict[str, Any]:
    body: dict[str, Any] = {"node_id": "I_1", "number": 1, "state": "open", "closed_at": None}
    body.update(issue)
    return {"action": "opened", "repository": {"full_name": "acme/widgets"}, "issue": body}


def bad_payloads() -> list[tuple[str, dict[str, Any]]]:
    """What the pointer must carry: an action, the repository's full name, and the node id."""
    cases: list[tuple[str, dict[str, Any]]] = []
    for name, value in (("missing", None), ("int", 5), ("list", ["acme/widgets"])):
        payload = good_payload()
        if value is None:
            del payload["repository"]["full_name"]
        else:
            payload["repository"]["full_name"] = value
        cases.append((f"full_name-{name}", payload))
    no_repo = good_payload()
    del no_repo["repository"]
    cases.append(("no-repository", no_repo))
    cases.append(("action-int", {**good_payload(), "action": 7}))
    for node_id in ("", 5, None, ["I_1"]):
        cases.append((f"node_id-{node_id!r}", good_payload(node_id=node_id)))
    cases.append(("issue-list", {**good_payload(), "issue": ["x"]}))
    return cases


@pytest.mark.parametrize("payload", [p for _, p in bad_payloads()], ids=[n for n, _ in bad_payloads()])
def test_a_payload_that_is_not_shaped_as_asked_is_refused_before_any_request(
    fake: FakeGitHub, client: Client, tmp_path: Path, payload: dict[str, Any]
) -> None:
    build_world(fake)
    with pytest.raises(SafoError) as caught:
        sync(fake, client, raw_event(tmp_path, payload))
    assert caught.value.exit_code == 2 and fake.requests == [] and fake.mutations == []


@pytest.mark.parametrize(
    "lies",
    [
        {"number": 99, "state": "closed", "closed_at": "garbage"},
        {"number": 0, "state": "OPEN", "closed_at": 5},
        {"number": True, "state": None, "closed_at": "2026-10-03"},
        {"merged": "yes", "draft": "maybe"},
    ],
)
def test_the_payload_is_only_a_pointer_so_its_other_fields_are_not_believed(
    fake: FakeGitHub, client: Client, tmp_path: Path, lies: dict[str, Any]
) -> None:
    _, project = build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    code, text = sync(fake, client, event(tmp_path, "issue", "opened", issue, **lies))
    assert code == 0 and text.startswith("added #1; Status = Backlog")
    assert values(fake, project)["Done on"] is None


def test_a_missing_draft_flag_in_the_payload_does_not_make_a_draft_pull_request_ready(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    _, project = build_world(fake)
    pr = fake.add_content("acme/widgets", "PullRequest", 2, draft=True)
    path = raw_event(
        tmp_path,
        {
            "action": "opened",
            "repository": {"full_name": "acme/widgets"},
            "pull_request": {"node_id": pr.id},
        },
    )
    assert sync(fake, client, path)[0] == 0 and values(fake, project)["Status"] == "Backlog"


def test_the_number_in_the_output_is_the_live_one(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 7)
    code, text = sync(fake, client, event(tmp_path, "issue", "opened", issue, number=99))
    assert code == 0 and text.startswith("added #7;") and "99" not in text


def test_a_close_date_is_converted_to_utc_from_its_offset(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    _, project = build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1, state="CLOSED", closed_at="2026-10-03T23:30:00-05:00")
    sync(fake, client, event(tmp_path, "issue", "closed", issue, closed_at="2026-10-03T08:00:00Z"))
    assert values(fake, project)["Done on"] == "2026-10-04"
    other = fake.add_content("acme/widgets", "Issue", 2, state="CLOSED", closed_at="2026-10-04T01:30:00.250+03:00")
    sync(fake, client, event(tmp_path, "issue", "closed", other))
    assert fake.value(project, project.items[1], "Done on") == "2026-10-03"


@pytest.mark.parametrize(
    "stamp", ["2026-10-20T00:00:00Z", "2026-10-03", "2026-10-03T08:00:00", "2026-10-03T08:00:00+25:00"]
)
def test_a_live_close_date_that_is_wrong_stops_before_anything_is_written(
    fake: FakeGitHub, client: Client, tmp_path: Path, stamp: str
) -> None:
    build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1, state="CLOSED", closed_at=stamp)
    from safo.errors import MalformedDataError

    with pytest.raises(MalformedDataError):
        sync(fake, client, event(tmp_path, "issue", "closed", issue))
    assert fake.mutations == []


# -- one second run sends nothing; one desired value per field ---------------------------------------------------


@pytest.mark.parametrize(
    "kind,action,seed",
    [
        ("issue", "opened", {}),
        ("issue", "closed", {"state": "CLOSED", "closed_at": "2026-10-03T08:00:00Z"}),
        ("pull_request", "closed", {"kind": "PullRequest", "state": "MERGED", "closed_at": "2026-10-04T09:00:00Z"}),
        ("pull_request", "opened", {"kind": "PullRequest", "draft": True}),
        ("pull_request", "ready_for_review", {"kind": "PullRequest"}),
    ],
)
def test_a_second_run_of_the_same_event_sends_no_mutation(
    fake: FakeGitHub, client: Client, tmp_path: Path, kind: str, action: str, seed: dict[str, Any]
) -> None:
    _, project = build_world(fake)
    content_kind = seed.pop("kind", "Issue")
    content = fake.add_content("acme/widgets", content_kind, 1, **seed)
    path = event(tmp_path, kind, action, content)
    assert sync(fake, client, path)[0] == 0 and fake.mutations
    first = values(fake, project)
    fake.mutations.clear()
    code, text = sync(fake, client, path)
    assert code == 0 and fake.mutations == [] and "already current" in text
    assert values(fake, project) == first and len(project.items) == 1


def test_a_default_never_overwrites_the_status_or_area_role(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    board = load_test_board()
    rules = dataclasses.replace(
        board.rules, new_item_defaults=(("Priority", "P1 soon"), ("Status", "Next"), ("Area", "Docs"))
    )
    board = dataclasses.replace(board, rules=rules)
    _, project = build_world(fake, board)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    # The status and Area roles belong to the rules; a default naming them is never written.
    sync(fake, client, event(tmp_path, "issue", "opened", issue), board)
    item = project.items[0]
    assert fake.value(project, item, "Status") == "Backlog" and fake.value(project, item, "Area") == "Core"
    assert fake.value(project, item, "Priority") == "P1 soon"
    selects = [m.variables["fieldId"] for m in fake.mutations_named("SetSelect")]
    assert len(selects) == len(set(selects)), "one write per field"


# -- dry run -----------------------------------------------------------------------------------------------------


def test_a_dry_run_says_what_would_happen_sends_nothing_and_exits_1(
    fake: FakeGitHub, tmp_path: Path, sleeps: list[float]
) -> None:
    _, project = build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    dry = Client(fake.token, fake.url, dry_run=True, sleep=sleeps.append)
    code, text = sync(fake, dry, event(tmp_path, "issue", "opened", issue))
    assert code == 1 and text.startswith("WOULD add #1; Status = Backlog; Area = Core")
    assert fake.mutations == [] and project.items == []


def test_a_dry_run_on_a_card_that_is_current_exits_0(fake: FakeGitHub, tmp_path: Path, sleeps: list[float]) -> None:
    _, project = build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    fake.add_item(project, issue, Status="Backlog", Area="Core", Priority="P2 later")
    dry = Client(fake.token, fake.url, dry_run=True, sleep=sleeps.append)
    code, text = sync(fake, dry, event(tmp_path, "issue", "edited", issue))
    assert code == 0 and "already current" in text and fake.mutations == []


def test_a_dry_run_on_a_present_card_lists_the_updates(fake: FakeGitHub, tmp_path: Path, sleeps: list[float]) -> None:
    _, project = build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    fake.add_item(project, issue, Status="Done", Area="Core", Priority="P2 later", Done_on="2026-10-01")
    dry = Client(fake.token, fake.url, dry_run=True, sleep=sleeps.append)
    code, text = sync(fake, dry, event(tmp_path, "issue", "reopened", issue))
    assert code == 1 and text.startswith("WOULD update #1: Status = Backlog; Done on cleared")
    assert fake.mutations == []


# -- stops: an unknown outcome is never replayed, and the rest is named -----------------------------------------


@pytest.mark.parametrize("boundary", ["Area", "ClearField"])
def test_sync_rerun_recovers_partial_initialization_and_reopen(
    fake: FakeGitHub, client: Client, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    _, project = build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    if boundary == "ClearField":
        fake.add_item(project, issue, Status="Done", Area="Core", Priority="P2 later", Done_on="2026-10-03")
    path = event(tmp_path, "issue", "reopened" if boundary == "ClearField" else "opened", issue)
    real = client.execute
    lost = False

    def execute(document: str, variables: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        nonlocal lost
        name = next((f.name for f in project.fields if f.id == variables.get("fieldId")), "")
        if not lost and (name == boundary or ("mutation ClearField(" in document and boundary == "ClearField")):
            lost = True
            raise UnknownOutcomeError("lost", data=None, errors=[], status=502)
        return real(document, variables, **kwargs)

    monkeypatch.setattr(client, "execute", execute)
    code, text = sync(fake, client, path)
    assert code == 2 and "unknown outcome" in text
    assert "NOT ATTEMPTED" in text or boundary == "ClearField"
    assert sync(fake, client, path)[0] == 0
    item = project.items[0]
    assert len(project.items) == 1 and fake.value(project, item, "Status") == "Backlog"
    assert fake.value(project, item, "Area") == "Core"
    assert fake.value(project, item, "Priority") == "P2 later"
    assert fake.value(project, item, "Done on") is None


def test_sync_mutation_not_found_is_unknown_until_deletion_is_read(
    fake: FakeGitHub, client: Client, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, project = build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1, state="CLOSED", closed_at="2026-10-03T08:00:00Z")
    item = fake.add_item(project, issue, Status="Backlog", Area="Core")
    path = event(tmp_path, "issue", "closed", issue)
    real = client.execute

    def execute(document: str, variables: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        if document.lstrip().startswith("mutation"):
            fake.vanished.update([issue.id, item.id])
            raise UnknownOutcomeError("not found", data=None, errors=[{"type": "NOT_FOUND"}], status=200)
        return real(document, variables, **kwargs)

    monkeypatch.setattr(client, "execute", execute)
    code, text = sync(fake, client, path)
    assert code == 2 and "VANISHED acme/widgets#1" in text and "unknown outcome" in text
    assert "NOT ATTEMPTED Done date filled" in text


def test_sync_merged_uses_merged_status_even_when_current_is_closed_status(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    board = load_test_board()
    board = dataclasses.replace(
        board, rules=dataclasses.replace(board.rules, status=dataclasses.replace(board.rules.status, merged="Next"))
    )
    _, project = build_world(fake, board)
    pr = fake.add_content("acme/widgets", "PullRequest", 1, state="MERGED")
    fake.add_item(project, pr, Status="Done", Area="Core")
    assert sync(fake, client, event(tmp_path, "pull_request", "closed", pr), board)[0] == 0
    assert fake.value(project, project.items[0], "Status") == "Next"


def test_a_reply_naming_another_item_stops_the_run_and_the_rest_is_not_attempted(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    _, project = build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    fake.handlers["SetSelect"] = lambda f, v: {"updateProjectV2ItemFieldValue": {"projectV2Item": {"id": "PVTI_other"}}}
    code, text = sync(fake, client, event(tmp_path, "issue", "opened", issue))
    assert code == 2 and "unknown outcome" in text
    assert "NOT ATTEMPTED Area = Core; Priority = P2 later" in text
    assert [m.op for m in fake.mutations] == ["AddItem", "SetSelect"], "the failed write is not sent again"
    assert "observed acme/widgets#1: on the board" in text and "Status None" in text
    assert "acme/widgets#1: Status = Backlog: unknown" in text
    assert project.items


def test_an_add_whose_reply_carries_no_id_is_unknown_and_nothing_follows(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    fake.handlers["AddItem"] = lambda f, v: {"addProjectV2ItemById": {"item": {}}}
    code, text = sync(fake, client, event(tmp_path, "issue", "opened", issue))
    assert code == 2 and "unknown outcome" in text and "NOT ATTEMPTED every field write for acme/widgets#1" in text
    assert [m.op for m in fake.mutations] == ["AddItem"]


def test_an_add_acknowledged_with_another_id_than_the_card_found_is_unknown(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    _, project = build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)

    def add(f: FakeGitHub, v: dict[str, Any]) -> dict[str, Any]:
        HANDLERS["AddItem"](f, v)
        return {"addProjectV2ItemById": {"item": {"id": "PVTI_not_this_one"}}}

    fake.handlers["AddItem"] = add
    code, text = sync(fake, client, event(tmp_path, "issue", "opened", issue))
    assert code == 2 and "unknown outcome" in text and "NOT ATTEMPTED every field write" in text
    assert [m.op for m in fake.mutations] == ["AddItem"] and len(project.items) == 1


def test_a_rate_limit_after_a_write_was_sent_is_an_unknown_outcome_exit_2_and_names_the_rest(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    _, project = build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    fake.faults.append(Fault(403, {"retry-after": "0"}, "{}", times=50, op="SetSelect"))
    code, text = sync(fake, client, event(tmp_path, "issue", "opened", issue))
    assert code == 2 and "unknown outcome" in text and "NOT ATTEMPTED Area = Core" in text
    assert fake.mutations_named("SetSelect") == [] and project.items


@pytest.mark.parametrize("op", ["ProjectMetaOrg", "SyncContent", "ItemLookup"])
def test_a_rate_limit_before_any_write_was_sent_is_exit_1_and_nothing_changed(
    fake: FakeGitHub, client: Client, tmp_path: Path, op: str
) -> None:
    build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    fake.faults.append(Fault(403, {"retry-after": "0"}, "{}", times=50, op=op))
    code, text = sync(fake, client, event(tmp_path, "issue", "opened", issue))
    assert code == 1 and "rate limited" in text and "try again later" in text and fake.mutations == []


def test_a_read_that_keeps_failing_is_exit_2_and_nothing_is_written(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    from cliutil import BOARD, run_cli

    build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    fake.faults.append(Fault(502, op="ItemLookup", times=50))
    path = event(tmp_path, "issue", "opened", issue)
    code, _, err = run_cli("--board", BOARD, "sync", "--event-path", str(path), client=client)
    assert code == 2 and fake.mutations == [] and "502" in err


def test_error_text_from_github_cannot_start_a_command_on_the_error_line(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    from cliutil import BOARD, run_cli
    from fakegh.core import GqlError

    build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)

    def refuse(f: FakeGitHub, v: dict[str, Any]) -> dict[str, Any]:
        raise GqlError("INTERNAL", "boom\n::error::forged\x1b[2J")

    fake.handlers["ItemLookup"] = refuse
    path = event(tmp_path, "issue", "opened", issue)
    code, _, err = run_cli(
        "--board", BOARD, "sync", "--event-path", str(path), env={"GITHUB_ACTIONS": "true"}, client=client
    )
    assert code == 2 and len(err.splitlines()) == 1 and "\x1b" not in err and "\\x0a:\\x3aerror:\\x3aforged" in err


# -- malformed answers are "cannot tell", never "blank" ---------------------------------------------------------


def lookup_with(**connection: Any) -> Any:
    def handler(f: FakeGitHub, v: dict[str, Any]) -> dict[str, Any]:
        return {"node": {"projectItems": connection}}

    return handler


@pytest.mark.parametrize(
    "connection",
    [
        {"nodes": []},
        {"pageInfo": {"hasNextPage": "no"}, "nodes": []},
        {"pageInfo": {"hasNextPage": False}},
        {"pageInfo": {"hasNextPage": False}, "nodes": ["x"]},
        {"pageInfo": {"hasNextPage": False}, "nodes": [{}]},
    ],
    ids=["no-pageinfo", "string-bool", "no-nodes", "non-object-node", "empty-node"],
)
def test_a_card_read_that_is_not_shaped_as_asked_is_exit_2_and_writes_nothing(
    fake: FakeGitHub, client: Client, tmp_path: Path, connection: dict[str, Any]
) -> None:
    from cliutil import BOARD, run_cli

    _, project = build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    fake.handlers["ItemLookup"] = lookup_with(**connection)
    path = event(tmp_path, "issue", "opened", issue)
    code, _, _ = run_cli("--board", BOARD, "sync", "--event-path", str(path), client=client)
    assert code == 2 and fake.mutations == [] and project.items == []


def test_an_empty_status_object_is_not_read_as_blank_and_the_card_is_left_alone(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    from cliutil import BOARD, run_cli

    _, project = build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    item = fake.add_item(project, issue, Status="Done", Area="Core")

    def lookup(f: FakeGitHub, v: dict[str, Any]) -> dict[str, Any]:
        row = {"id": item.id, "project": {"id": project.id}, "status": {}, "area": None, "d0": None, "done": None}
        return {"node": {"projectItems": f.connection([row], v)}}

    fake.handlers["ItemLookup"] = lookup
    path = event(tmp_path, "issue", "edited", issue)
    code, _, _ = run_cli("--board", BOARD, "sync", "--event-path", str(path), client=client)
    assert code == 2 and fake.mutations == []


def test_a_default_field_of_another_type_is_not_written_and_does_not_stop_the_run(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    _, project = build_world(fake)
    fake.field(project, "Priority").data_type = "TEXT"
    issue = fake.add_content("acme/widgets", "Issue", 1)
    code, text = sync(fake, client, event(tmp_path, "issue", "opened", issue))
    assert code == 0 and "Priority" not in text
    assert [m.op for m in fake.mutations] == ["AddItem", "SetSelect", "SetSelect"]


def test_a_card_that_disappears_during_an_unknown_outcome_is_named_as_gone(
    fake: FakeGitHub, client: Client, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, project = build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    item = fake.add_item(project, issue, Status="Backlog", Area="Core", Priority="P2 later")
    real = client.execute

    def execute(document: str, variables: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        if document.lstrip().startswith("mutation"):
            fake.vanished.add(item.id)  # the card is deleted, the issue stays
            raise UnknownOutcomeError("lost", data=None, errors=[], status=502)
        return real(document, variables, **kwargs)

    monkeypatch.setattr(client, "execute", execute)
    issue.state, issue.closed_at = "CLOSED", "2026-10-03T08:00:00Z"
    code, text = sync(fake, client, event(tmp_path, "issue", "closed", issue))
    assert code == 2 and "the card no longer exists" in text


# -- the live content decides: the payload is a pointer ---------------------------------------------------------


def note_free(text: str) -> bool:
    return "::" not in text


def test_a_node_that_belongs_to_another_repository_than_the_payload_names_is_a_note_and_writes_nothing(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    _, project = build_world(fake)
    fake.add_repo("outside/moved")
    stray = fake.add_content("outside/moved", "Issue", 19)
    path = event(tmp_path, "issue", "opened", stray)
    payload = json.loads(path.read_text())
    payload["repository"]["full_name"] = "acme/widgets"
    path.write_text(json.dumps(payload))
    code, text = sync(fake, client, path)
    assert code == 1 and "NOTE" in text and "outside/moved" in text and "acme/widgets" in text
    assert fake.mutations == [] and project.items == []


def test_a_node_in_another_listed_repository_than_the_payload_names_is_also_a_note(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    build_world(fake)
    other = fake.add_content("acme/manuals", "Issue", 3)
    path = event(tmp_path, "issue", "opened", other)
    payload = json.loads(path.read_text())
    payload["repository"]["full_name"] = "acme/widgets"
    path.write_text(json.dumps(payload))
    code, text = sync(fake, client, path)
    assert code == 1 and "acme/manuals" in text and "acme/widgets" in text and fake.mutations == []


def test_a_live_repository_that_differs_only_in_case_is_the_same_repository(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    _, project = build_world(fake)
    issue = fake.add_content("ACME/Widgets", "Issue", 1)
    path = event(tmp_path, "issue", "opened", issue)
    payload = json.loads(path.read_text())
    payload["repository"]["full_name"] = "acme/WIDGETS"
    path.write_text(json.dumps(payload))
    assert sync(fake, client, path)[0] == 0 and values(fake, project)["Area"] == "Core"


def test_a_live_repository_board_yaml_does_not_list_is_a_note_even_when_the_payload_says_it_is_listed(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    build_world(fake)
    fake.add_repo("acme/elsewhere")
    stray = fake.add_content("acme/elsewhere", "Issue", 1)
    path = event(tmp_path, "issue", "opened", stray)
    payload = json.loads(path.read_text())
    payload["repository"]["full_name"] = "acme/elsewhere"
    path.write_text(json.dumps(payload))
    code, text = sync(fake, client, path)
    assert code == 1 and "not listed in board.yaml" in text and fake.requests == []


def test_a_node_of_the_other_kind_than_the_payload_names_is_a_note(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    build_world(fake)
    pr = fake.add_content("acme/widgets", "PullRequest", 2)
    path = event(tmp_path, "pull_request", "opened", pr)
    payload = json.loads(path.read_text())
    payload["issue"] = payload.pop("pull_request")
    path.write_text(json.dumps(payload))
    code, text = sync(fake, client, path)
    assert code == 1 and "NOTE" in text and fake.mutations == []


def test_a_replayed_ready_event_after_the_pull_request_went_back_to_draft_writes_nothing(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    _, project = build_world(fake)
    pr = fake.add_content("acme/widgets", "PullRequest", 2, draft=True)
    assert sync(fake, client, event(tmp_path, "pull_request", "opened", pr))[0] == 0
    pr.draft = False
    ready = tmp_path / "ready.json"
    ready.write_text(event(tmp_path, "pull_request", "ready_for_review", pr).read_text())
    assert sync(fake, client, ready)[0] == 0 and values(fake, project)["Status"] == "In progress"
    pr.draft = True
    assert sync(fake, client, event(tmp_path, "pull_request", "converted_to_draft", pr))[0] == 0
    assert values(fake, project)["Status"] == "Backlog"
    fake.mutations.clear()
    code, text = sync(fake, client, ready)
    assert code == 1 and "NOTE" in text and "ready_for_review" in text
    assert fake.mutations == [] and values(fake, project)["Status"] == "Backlog"


@pytest.mark.parametrize(
    "kind,action,live",
    [
        ("issue", "closed", {}),
        ("issue", "reopened", {"state": "CLOSED", "closed_at": "2026-10-03T08:00:00Z"}),
        ("issue", "opened", {"state": "CLOSED", "closed_at": "2026-10-03T08:00:00Z"}),
        ("pull_request", "closed", {"kind": "PullRequest"}),
        ("pull_request", "converted_to_draft", {"kind": "PullRequest"}),
        ("pull_request", "ready_for_review", {"kind": "PullRequest", "draft": True}),
        ("pull_request", "opened", {"kind": "PullRequest", "state": "MERGED", "closed_at": "2026-10-03T08:00:00Z"}),
        ("pull_request", "reopened", {"kind": "PullRequest", "state": "CLOSED", "closed_at": "2026-10-03T08:00:00Z"}),
    ],
)
def test_an_action_that_contradicts_the_live_state_is_a_note_and_writes_nothing(
    fake: FakeGitHub, client: Client, tmp_path: Path, kind: str, action: str, live: dict[str, Any]
) -> None:
    _, project = build_world(fake)
    content_kind = live.pop("kind", "Issue")
    content = fake.add_content("acme/widgets", content_kind, 1, **live)
    code, text = sync(fake, client, event(tmp_path, kind, action, content))
    assert code == 1 and "NOTE" in text and fake.mutations == [] and project.items == []


def test_an_edit_event_is_taken_at_whatever_state_the_issue_has_now(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    _, project = build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1, state="CLOSED", closed_at="2026-10-03T08:00:00Z")
    assert sync(fake, client, event(tmp_path, "issue", "edited", issue))[0] == 0
    assert values(fake, project)["Status"] == "Done"


@pytest.mark.parametrize(
    "node",
    [
        {
            "id": "ISSUE_other",
            "number": 1,
            "state": "OPEN",
            "closedAt": None,
            "repository": {"nameWithOwner": "acme/widgets"},
        },
        {"id": "X", "state": "OPEN", "closedAt": None, "repository": {"nameWithOwner": "acme/widgets"}},
        {"id": "X", "number": 1, "closedAt": None, "repository": {"nameWithOwner": "acme/widgets"}},
        {"id": "X", "number": 1, "state": "WEIRD", "closedAt": None, "repository": {"nameWithOwner": "acme/widgets"}},
        {"id": "X", "number": 1, "state": "OPEN", "closedAt": None},
        {"id": "X", "number": 1, "state": "OPEN", "closedAt": None, "repository": {"nameWithOwner": "../x"}},
        {"id": "X", "number": True, "state": "OPEN", "closedAt": None, "repository": {"nameWithOwner": "acme/widgets"}},
        {
            "id": "X",
            "number": 1,
            "state": "OPEN",
            "closedAt": None,
            "isDraft": "no",
            "__typename": "PullRequest",
            "merged": False,
            "repository": {"nameWithOwner": "acme/widgets"},
        },
    ],
    ids=[
        "other-id",
        "no-number",
        "no-state",
        "bad-state",
        "no-repository",
        "bad-repository",
        "bool-number",
        "bad-draft",
    ],
)
def test_a_live_read_that_is_not_shaped_as_asked_is_exit_2_and_writes_nothing(
    fake: FakeGitHub, client: Client, tmp_path: Path, node: dict[str, Any]
) -> None:
    from cliutil import BOARD, run_cli

    build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    served = {"__typename": "Issue", **node, "id": issue.id if node["id"] == "X" else node["id"]}
    fake.handlers["SyncContent"] = lambda f, v: {"node": served}
    path = event(tmp_path, "issue", "opened", issue)
    code, _, _ = run_cli("--board", BOARD, "sync", "--event-path", str(path), client=client)
    assert code == 2 and fake.mutations == []


def test_a_card_that_cannot_be_read_though_the_issue_exists_is_not_called_vanished(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    fake.handlers["ItemLookup"] = lambda f, v: {"node": None}
    code, text = sync(fake, client, event(tmp_path, "issue", "opened", issue))
    assert code == 2 and "could not be read, though the issue or pull request exists" in text
    assert "VANISHED" not in text and fake.mutations == []


@pytest.mark.parametrize("bad", [[], 1, "", None, {"a": 1}])
def test_a_card_id_that_is_not_a_string_stops_the_run_with_exit_2_not_a_traceback(
    fake: FakeGitHub, client: Client, tmp_path: Path, bad: Any
) -> None:
    from cliutil import BOARD, run_cli

    _, project = build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)

    def lookup(f: FakeGitHub, v: dict[str, Any]) -> dict[str, Any]:
        row = {"id": bad, "project": {"id": project.id}, "status": None, "area": None, "d0": None, "done": None}
        return {"node": {"projectItems": f.connection([row], v)}}

    fake.handlers["ItemLookup"] = lookup
    path = event(tmp_path, "issue", "opened", issue)
    code, _, _ = run_cli("--board", BOARD, "sync", "--event-path", str(path), client=client)
    assert code == 2 and fake.mutations == []


# -- text that GitHub or a payload sent never reaches a log as a command --------------------------------------


MID_LINE = "x/y ::error::forged %0A::warning::w ::stop-commands::tok"


def test_a_double_colon_anywhere_in_a_notice_is_neutralised(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    path = event(tmp_path, "issue", "opened", issue)
    payload = json.loads(path.read_text())
    payload["repository"]["full_name"] = MID_LINE
    path.write_text(json.dumps(payload))
    code, text = sync(fake, client, path)
    assert code == 1 and note_free(text) and "error" in text


def test_a_double_colon_in_the_action_or_event_name_is_neutralised(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 1)
    path = event(tmp_path, "issue", MID_LINE, issue)
    code, text = sync(fake, client, path, event_name=MID_LINE)
    assert code == 0 and note_free(text)


def test_a_dry_run_line_cannot_carry_a_command_from_a_value_in_the_request(
    fake: FakeGitHub, tmp_path: Path, sleeps: list[float]
) -> None:
    import io

    build_world(fake)
    buf = io.StringIO()
    dry = Client(fake.token, fake.url, dry_run=True, sleep=sleeps.append, out=buf)
    dry.execute("mutation M($b: String!) { x(b: $b) { id } }", {"b": MID_LINE})
    assert buf.getvalue().startswith("dry run: would M ") and note_free(buf.getvalue())
    assert "error" in buf.getvalue()
