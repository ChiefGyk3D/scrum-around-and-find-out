# SPDX-License-Identifier: MIT
"""status: post an update from a body file, or build one from the board with the cards grouped and counted in code."""

from __future__ import annotations

import argparse
import datetime as dt
import os
from pathlib import Path
from typing import Any

import pytest

from fakegh import FakeGitHub
from fakegh.core import HANDLERS, JSON
from safo.errors import ApiError, ConfigError, MalformedDataError, UnknownOutcomeError
from safo.graphql import Client
from safo.modes.status import run
from safo.statusgroups import Groups, Row, group_rows, headline_acceptable, plain, render_body, template_headline
from world import build_world, load_test_board, make_context


def ns(**over: Any) -> argparse.Namespace:
    args = argparse.Namespace(
        body_file="",
        post=False,
        print_only=False,
        since="",
        human_agent="You",
        limit=12,
        state="ON_TRACK",
        start_date="",
        target_date="",
    )
    for key, value in over.items():
        setattr(args, key, value)
    return args


def post(fake: FakeGitHub, client: Client, body: Path, **over: Any) -> int:
    ctx, _ = make_context(fake, load_test_board(), client)
    return run(ctx, ns(body_file=str(body), **over))


def test_the_body_state_and_dates_are_posted_to_the_project(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    _, project = build_world(fake)
    body = tmp_path / "update.md"
    body.write_text("Sprint 1 is done.\n\n- shipped audit\n")
    assert post(fake, client, body, state="AT_RISK", target_date="2026-10-20") == 0
    sent = fake.mutations_named("StatusUpdate")[0].variables["input"]
    assert sent == {
        "projectId": project.id,
        "status": "AT_RISK",
        "body": "Sprint 1 is done.\n\n- shipped audit",
        "targetDate": "2026-10-20",
    }


def test_an_empty_or_missing_body_is_a_config_error(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    build_world(fake)
    empty = tmp_path / "empty.md"
    empty.write_text("  \n")
    with pytest.raises(ConfigError, match="is empty"):
        post(fake, client, empty)
    with pytest.raises(ConfigError, match="cannot read the status body"):
        post(fake, client, tmp_path / "missing.md")
    assert fake.mutations == [] and fake.requests == []


def test_a_body_that_cannot_be_posted_is_a_config_error_before_any_request(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    build_world(fake)
    binary = tmp_path / "binary.md"
    binary.write_bytes(b"ok \xff\xfe not utf-8")
    huge = tmp_path / "huge.md"
    huge.write_text("x" * 65_537)
    fifo = tmp_path / "pipe.md"
    os.mkfifo(fifo)
    for path, message in (
        (binary, "not UTF-8"),
        (huge, "longer than"),
        (fifo, "not a regular file"),
        (tmp_path, "not a regular file"),
    ):
        with pytest.raises(ConfigError, match=message):
            post(fake, client, path)
    assert fake.requests == []


def test_a_body_file_name_cannot_start_a_command_in_the_error(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    build_world(fake)
    with pytest.raises(ConfigError) as caught:
        post(fake, client, tmp_path / "x\n::error::forged.md")
    assert "\n" not in str(caught.value) and "\\x0a::error::forged" in str(caught.value)


def test_status_unknown_outcome_rereads_and_does_not_retry(
    fake: FakeGitHub, client: Client, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    build_world(fake)
    body = tmp_path / "status.md"
    body.write_text("On track")
    real = client.execute

    def execute(document: str, variables: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        data = real(document, variables, **kwargs)
        if "mutation StatusUpdate(" in document:
            raise UnknownOutcomeError("lost", data=data, errors=[], status=502)
        return data

    monkeypatch.setattr(client, "execute", execute)
    ctx, out = make_context(fake, load_test_board(), client)
    assert run(ctx, ns(body_file=str(body))) == 2 and "unknown outcome" in out.getvalue()
    assert len(fake.mutations_named("StatusUpdate")) == 1
    assert fake.requests.count("ProjectMetaOrg") == 2
    assert "NOT ATTEMPTED a second post" in out.getvalue()


def test_a_reply_without_the_update_id_is_an_unknown_outcome_and_is_not_sent_again(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    build_world(fake)
    body = tmp_path / "status.md"
    body.write_text("On track")
    fake.handlers["StatusUpdate"] = lambda f, v: {"createProjectV2StatusUpdate": {"statusUpdate": {}}}
    ctx, out = make_context(fake, load_test_board(), client)
    assert run(ctx, ns(body_file=str(body))) == 2
    assert "unknown outcome" in out.getvalue() and len(fake.mutations_named("StatusUpdate")) == 1


def test_a_dry_run_says_it_would_post_sends_nothing_and_exits_1(
    fake: FakeGitHub, tmp_path: Path, sleeps: list[float]
) -> None:
    build_world(fake)
    body = tmp_path / "status.md"
    body.write_text("On track")
    dry = Client(fake.token, fake.url, dry_run=True, sleep=sleeps.append)
    ctx, out = make_context(fake, load_test_board(), dry)
    assert run(ctx, ns(body_file=str(body))) == 1
    assert "WOULD post a ON_TRACK status update to acme/1" in out.getvalue() and fake.mutations == []


# -- grouping: done in code, from the board's own fields ------------------------------------------------------------


def row(number: int, status: str, *, agent: str = "", when: str = "", repo: str = "acme/widgets") -> Row:
    return Row(repo, number, f"Card {number}", status, agent, dt.date.fromisoformat(when) if when else None)


SINCE = dt.date(2026, 10, 6)
LS, RLO, ZWSP, BOM = chr(0x2028), chr(0x202E), chr(0x200B), chr(0xFEFF)


def test_every_card_lands_in_one_group_by_status_and_the_board_is_left_alone() -> None:
    rows = [
        row(1, "Done", when="2026-10-06"),
        row(2, "In progress", agent="Claude"),
        row(3, "Blocked"),
        row(4, "Next"),
        row(5, "Backlog"),
    ]
    g = group_rows(rows, load_test_board(), SINCE)
    assert [r.number for r in g.done] == [1] and [r.number for r in g.progress] == [2]
    assert [r.number for r in g.waiting] == [3] and [r.number for r in g.upcoming] == [4]
    assert g.counts() == {"done": 1, "progress": 1, "waiting": 1, "next": 1}


def test_a_card_done_before_the_date_or_with_no_date_is_not_in_this_update() -> None:
    rows = [row(1, "Done", when="2026-10-05"), row(2, "Done"), row(3, "Done", when="2026-10-06")]
    assert [r.number for r in group_rows(rows, load_test_board(), SINCE).done] == [3]


def test_a_working_card_the_maintainer_holds_is_waiting_on_the_maintainer_not_in_progress() -> None:
    rows = [row(1, "In progress", agent="You"), row(2, "Next", agent="You"), row(3, "In progress", agent="Codex")]
    g = group_rows(rows, load_test_board(), SINCE)
    assert [r.number for r in g.waiting] == [1, 2] and [r.number for r in g.progress] == [3]
    assert group_rows(rows, load_test_board(), SINCE, human_agent="").waiting == (), "an empty name turns the rule off"


def test_the_sections_come_out_in_a_fixed_order_with_the_count_in_the_heading() -> None:
    g = group_rows([row(n, "In progress", agent="Claude") for n in (3, 1, 2)], load_test_board(), SINCE)
    text = render_body("All quiet.", g)
    assert text.startswith(template_headline(g) + "\n\n**Done since 2026-10-06** (0)\n\n**In progress** (3)\n")
    assert "- acme/widgets#1 Card 1 (Claude)\n- acme/widgets#2 Card 2 (Claude)\n- acme/widgets#3 Card 3" in text
    assert text.index("**In progress**") < text.index("**Waiting on the maintainer**") < text.index("**Next**")


def test_a_long_section_is_cut_and_the_rest_is_counted_not_dropped() -> None:
    g = group_rows([row(n, "Next") for n in range(1, 16)], load_test_board(), SINCE)
    text = render_body("h", g, limit=12)
    assert "**Next** (15)" in text and "- acme/widgets#12 Card 12" in text and "#13 Card 13" not in text
    assert "- ...and 3 more" in text


def test_a_title_cannot_ping_anyone_and_a_draft_card_has_no_reference() -> None:
    rows = [
        Row("acme/widgets", 7, "thanks @octocat\nfor the fix", "Next", "", None),
        Row("", 0, "Plan", "Next", "", None),
    ]
    text = render_body("h", group_rows(rows, load_test_board(), SINCE))
    assert "@octocat" not in text and "thanks @" + chr(0x200B) + "octocat for the fix" in text
    assert "- draft Plan" in text


def test_a_title_or_an_agent_name_is_one_clean_line_with_no_mention_and_no_control_character() -> None:
    hostile = "a\x1b[2J\r\nb" + LS + "c" + RLO + "d @org/team \x00\x7f" + ZWSP + BOM + "end"
    rows = [Row("acme/widgets", 7, hostile, "Next", "@octocat\n::error::x", None)]
    text = render_body("h", group_rows(rows, load_test_board(), SINCE))
    card = next(line for line in text.splitlines() if line.startswith("- acme/widgets#7"))
    assert "\n" not in card and "\x1b" not in text and "\r" not in text and LS not in text
    assert RLO not in text and "\x00" not in text and BOM not in text and ZWSP + BOM not in text
    assert "@org" not in card and "@octocat" not in card and "@" + chr(0x200B) + "org/team" in card
    assert plain("a\tb\n c") == "a b c"


def test_the_maintainer_holding_a_backlog_card_does_not_make_it_wait_and_unassigned_has_no_suffix() -> None:
    rows = [row(1, "Backlog", agent="You"), row(2, "Next", agent="unassigned")]
    g = group_rows(rows, load_test_board(), SINCE)
    assert g.waiting == () and [r.number for r in g.upcoming] == [2]
    assert "- acme/widgets#2 Card 2\n" in render_body("h", g)


def test_a_long_title_is_cut_and_a_section_exactly_at_the_limit_has_no_more_line() -> None:
    long = Row("acme/widgets", 1, "x" * 300, "Next", "", None)
    assert "x" * 81 not in render_body("h", group_rows([long], load_test_board(), SINCE))
    g = group_rows([row(n, "Next") for n in range(1, 13)], load_test_board(), SINCE)
    assert "and 0 more" not in render_body("h", g, limit=12) and "...and 1 more" in render_body("h", g, limit=11)


def test_the_template_headline_states_the_four_counts() -> None:
    g = group_rows([row(1, "Done", when="2026-10-07"), row(2, "Blocked")], load_test_board(), SINCE)
    assert template_headline(g) == "1 done since 2026-10-06, 0 in progress, 1 waiting on the maintainer, 0 next."


@pytest.mark.parametrize(
    "text,ok",
    [
        ("A quiet week.", True),
        ("A steady week.", True),
        ("Work continues.", True),
        ("1 card done and 1 waiting on you.", False),
        ("7 cards done.", False),
        ("two lines\nnot one", False),
        ("see https://example.invalid/x", False),
        ("thanks @octocat", False),
        ("closes #12", False),
        ("`code` is not allowed", False),
        ("", False),
        ("x" * 161, False),
        ("A quiet week. ", False),
        ("a quiet week.", False),
    ],
)
def test_a_model_headline_is_used_only_if_it_is_one_plain_line_with_the_computed_numbers(text: str, ok: bool) -> None:
    g = group_rows([row(1, "Done", when="2026-10-07"), row(2, "Blocked")], load_test_board(), SINCE)
    assert headline_acceptable(text, g) is ok


def test_the_sentence_with_the_counts_always_comes_from_code_even_when_a_model_line_is_accepted() -> None:
    g = group_rows([row(1, "Done", when="2026-10-07")], load_test_board(), SINCE)
    base = template_headline(g)
    assert render_body("A quiet week.", g).splitlines()[0] == base + " A quiet week."
    assert render_body(base + " A steady week.", g).splitlines()[0] == base + " A steady week."
    assert render_body(base + " 99 done.", g).splitlines()[0] == base
    assert render_body("", g).splitlines()[0] == base


def test_notes_close_the_body_and_a_body_without_them_has_none() -> None:
    g = group_rows([row(1, "Next")], load_test_board(), SINCE)
    assert "Note:" not in render_body("h", g)
    text = render_body("h", g, notes=["2 card(s) could not be read."])
    assert text.endswith("- acme/widgets#1 Card 1\n\nNote: 2 card(s) could not be read.\n")


# -- status --post: built from the board, sent through the client's mutation path ---------------------------------


def populate(fake: FakeGitHub, project: Any) -> None:
    done = fake.add_content(
        "acme/widgets", "Issue", 1, "Shipped audit", state="CLOSED", closed_at="2026-10-06T08:00:00Z"
    )
    old = fake.add_content("acme/widgets", "Issue", 2, "Long ago", state="CLOSED", closed_at="2026-09-01T08:00:00Z")
    merged = fake.add_content(
        "acme/widgets", "PullRequest", 3, "Merged fix", state="MERGED", closed_at="2026-10-07T09:00:00Z"
    )
    working = fake.add_content("acme/widgets", "Issue", 4, "Build the thing")
    blocked = fake.add_content("acme/manuals", "Issue", 5, "Needs a decision")
    held = fake.add_content("acme/widgets", "Issue", 6, "Maintainer holds this")
    queued = fake.add_content("acme/widgets", "Issue", 7, "Queued")
    fake.add_item(project, done, Status="Done", Area="Core")
    fake.add_item(project, old, Status="Done", Area="Core")
    fake.add_item(project, merged, Status="Done", Area="Core")
    fake.add_item(project, working, Status="In progress", Agent="Claude")
    fake.add_item(project, blocked, Status="Blocked")
    fake.add_item(project, held, Status="In progress", Agent="You")
    fake.add_item(project, queued, Status="Next")
    fake.add_item(project, None, Status="Backlog")


EXPECTED = (
    "2 done since 2026-10-06, 1 in progress, 2 waiting on the maintainer, 1 next.\n\n"
    "**Done since 2026-10-06** (2)\n"
    "- acme/widgets#1 Shipped audit\n"
    "- acme/widgets#3 Merged fix\n\n"
    "**In progress** (1)\n"
    "- acme/widgets#4 Build the thing (Claude)\n\n"
    "**Waiting on the maintainer** (2)\n"
    "- acme/manuals#5 Needs a decision\n"
    "- acme/widgets#6 Maintainer holds this (You)\n\n"
    "**Next** (1)\n"
    "- acme/widgets#7 Queued\n"
)


def test_post_builds_the_update_from_the_board_groups_counts_and_template_headline(
    fake: FakeGitHub, client: Client
) -> None:
    _, project = build_world(fake)
    populate(fake, project)
    ctx, out = make_context(fake, load_test_board(), client)
    assert run(ctx, ns(post=True, since="2026-10-06")) == 0
    sent = fake.mutations_named("StatusUpdate")[0].variables["input"]
    assert sent["status"] == "ON_TRACK" and sent["projectId"] == project.id
    assert sent["body"] == EXPECTED
    assert "posted a ON_TRACK status update" in out.getvalue()


def test_post_reads_every_page_and_gets_the_same_update(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    populate(fake, project)
    fake.page_size = 3
    ctx, _ = make_context(fake, load_test_board(), client)
    assert run(ctx, ns(post=True, since="2026-10-06")) == 0
    assert fake.requests.count("StatusItems") == 3
    assert fake.mutations_named("StatusUpdate")[0].variables["input"]["body"] == EXPECTED


def test_post_defaults_to_the_last_seven_days(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    populate(fake, project)
    ctx, _ = make_context(fake, load_test_board(), client, today=dt.date(2026, 10, 8))
    run(ctx, ns(post=True))
    body = fake.mutations_named("StatusUpdate")[0].variables["input"]["body"]
    assert "**Done since 2026-10-01** (2)" in body, "TODAY minus seven days; the 2026-09-01 card is out"


def test_a_close_date_with_an_offset_counts_on_its_utc_day(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    late = fake.add_content("acme/widgets", "Issue", 1, "Late", state="CLOSED", closed_at="2026-10-05T23:30:00-05:00")
    fake.add_item(project, late, Status="Done")
    ctx, out = make_context(fake, load_test_board(), client)
    assert run(ctx, ns(post=True, print_only=True, since="2026-10-06")) == 0
    assert "- acme/widgets#1 Late" in out.getvalue()


def test_post_print_shows_the_update_and_sends_nothing(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    populate(fake, project)
    ctx, out = make_context(fake, load_test_board(), client)
    assert run(ctx, ns(post=True, print_only=True, since="2026-10-06")) == 0
    assert out.getvalue().startswith("2 done since 2026-10-06, 1 in progress, 2 waiting on the maintainer, 1 next.")
    assert fake.mutations == []


def test_post_in_a_dry_run_says_it_would_post_and_exits_1(fake: FakeGitHub, sleeps: list[float]) -> None:
    _, project = build_world(fake)
    populate(fake, project)
    dry = Client(fake.token, fake.url, dry_run=True, sleep=sleeps.append)
    ctx, out = make_context(fake, load_test_board(), dry)
    assert run(ctx, ns(post=True, since="2026-10-06")) == 1
    assert "WOULD post a ON_TRACK status update" in out.getvalue() and fake.mutations == []


def test_exactly_one_of_post_and_a_body_file_is_required(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    build_world(fake)
    ctx, _ = make_context(fake, load_test_board(), client)
    with pytest.raises(ConfigError, match="exactly one of --body-file"):
        run(ctx, ns())
    with pytest.raises(ConfigError, match="exactly one of --body-file"):
        run(ctx, ns(post=True, body_file=str(tmp_path / "x.md")))
    with pytest.raises(ConfigError, match="--since: expected a date"):
        run(ctx, ns(post=True, since="last week"))
    assert fake.mutations == [] and fake.requests == []


def test_print_without_post_would_post_the_file_so_it_is_refused(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    build_world(fake)
    body = tmp_path / "update.md"
    body.write_text("On track")
    with pytest.raises(ConfigError, match="--print only goes with --post"):
        post(fake, client, body, print_only=True)
    assert fake.requests == []


@pytest.mark.parametrize("limit", [0, -1, 51, 10**9])
def test_a_limit_outside_the_range_is_refused_before_any_request(fake: FakeGitHub, client: Client, limit: int) -> None:
    build_world(fake)
    ctx, _ = make_context(fake, load_test_board(), client)
    with pytest.raises(ConfigError, match="--limit"):
        run(ctx, ns(post=True, limit=limit))
    assert fake.requests == []


@pytest.mark.parametrize("flag", ["start_date", "target_date", "since"])
@pytest.mark.parametrize("value", ["next week", "20261008", "2026-W41-4", "2026-13-01", "2026-10-8", " 2026-10-08"])
def test_a_malformed_update_date_is_a_config_error_before_anything_is_sent(
    fake: FakeGitHub, client: Client, tmp_path: Path, flag: str, value: str
) -> None:
    build_world(fake)
    body = tmp_path / "update.md"
    body.write_text("On track")
    with pytest.raises(ConfigError, match=r"--(since|start-date|target-date): expected a date as YYYY-MM-DD"):
        post(fake, client, body, **{flag: value})
    assert fake.mutations == [] and fake.requests == []


def test_a_short_board_listing_stops_the_built_update(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    populate(fake, project)
    fake.handlers["StatusItems"] = lambda f, v: {"node": {"items": f.connection([], v, total=0)}}
    ctx, out = make_context(fake, load_test_board(), client)
    with pytest.raises(ApiError, match=r"returned 0 of \d+ items, so the update would miss cards"):
        run(ctx, ns(post=True, since="2026-10-06"))
    assert fake.mutations == [] and out.getvalue() == ""


def test_a_total_larger_than_the_listing_stops_the_built_update(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    populate(fake, project)
    real = HANDLERS["StatusItems"]

    def lagging(f: FakeGitHub, v: JSON) -> JSON:
        data = real(f, v)
        data["node"]["items"]["totalCount"] = 99
        data["node"]["items"]["nodes"] = data["node"]["items"]["nodes"][:5]
        return data

    fake.handlers["StatusItems"] = lagging
    fake.page_size = 100
    ctx, _ = make_context(fake, load_test_board(), client)
    with pytest.raises(ApiError, match=r"returned 5 of 99 items"):
        run(ctx, ns(post=True))
    assert fake.mutations == []


def card(**over: Any) -> JSON:
    node: JSON = {
        "id": "PVTI_x1",
        "status": {"name": "Next"},
        "agent": None,
        "content": {
            "__typename": "Issue",
            "number": 1,
            "title": "t",
            "closedAt": None,
            "repository": {"nameWithOwner": "acme/widgets"},
        },
    }
    for key, value in over.items():
        if key.startswith("c_"):
            if value is KeyError:
                del node["content"][key[2:]]
            else:
                node["content"][key[2:]] = value
        elif value is KeyError:
            del node[key]
        else:
            node[key] = value
    return node


def serve_nodes(fake: FakeGitHub, nodes: list[JSON], **connection: Any) -> None:
    def handler(f: FakeGitHub, v: JSON) -> JSON:
        items = f.connection(nodes, v, total=len(nodes))
        items.update(connection)
        return {"node": {"items": items}}

    fake.handlers["StatusItems"] = handler


def raw_connection(fake: FakeGitHub, items: JSON) -> None:
    fake.handlers["StatusItems"] = lambda f, v: {"node": {"items": items}}


@pytest.mark.parametrize(
    "node",
    [
        card(c_number=None),
        card(c_number=True),
        card(c_number="7x"),
        card(c_number=0),
        card(c_number=2**31),
        card(c_title=5),
        card(c_title=KeyError),
        card(c_closedAt=KeyError),
        card(c_closedAt="2026-10-06"),
        card(c_closedAt="2026-10-06T08:00:00"),
        card(c_closedAt=5),
        card(c___typename="Discussion"),
        card(c___typename=KeyError),
        card(c_repository=None),
        card(c_repository={"nameWithOwner": "no-slash"}),
        card(c_repository={"nameWithOwner": "../x"}),
        card(content=KeyError),
        card(content="text"),
        card(content=[]),
        card(status={}),
        card(status={"other": "x"}),
        card(status="Next"),
        card(status=KeyError),
        card(agent={}),
        card(agent=KeyError),
        card(id=KeyError),
        card(id=None),
    ],
    ids=lambda n: str(n)[:60],
)
def test_a_card_that_is_not_shaped_as_asked_stops_the_built_update_and_sends_nothing(
    fake: FakeGitHub, client: Client, node: JSON
) -> None:
    _, project = build_world(fake)
    fake.add_item(project, None, Status="Next")  # keep the project total at 1 to match the served list
    serve_nodes(fake, [node])
    ctx, out = make_context(fake, load_test_board(), client)
    with pytest.raises(MalformedDataError):
        run(ctx, ns(post=True))
    assert fake.mutations == [] and out.getvalue() == ""


def test_a_pull_request_card_must_send_its_merge_date_key(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    fake.add_item(project, None, Status="Next")
    pr = card(c___typename="PullRequest")
    serve_nodes(fake, [pr])
    ctx, _ = make_context(fake, load_test_board(), client)
    with pytest.raises(MalformedDataError, match="mergedAt was not sent"):
        run(ctx, ns(post=True))
    pr["content"]["mergedAt"] = "not a date"
    with pytest.raises(MalformedDataError, match="mergedAt"):
        run(ctx, ns(post=True))


def test_a_card_listed_twice_stops_the_built_update(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    fake.add_item(project, None, Status="Next")
    fake.add_item(project, None, Status="Next")
    serve_nodes(fake, [card(), card()])
    ctx, _ = make_context(fake, load_test_board(), client)
    with pytest.raises(MalformedDataError, match="listed twice"):
        run(ctx, ns(post=True))
    assert fake.mutations == []


@pytest.mark.parametrize(
    "items,message",
    [
        ({"nodes": [], "totalCount": 0}, "pageInfo"),
        ({"nodes": [], "totalCount": 0, "pageInfo": {"hasNextPage": "false"}}, "pageInfo"),
        ({"nodes": [], "totalCount": 0, "pageInfo": {"hasNextPage": 0}}, "pageInfo"),
        ({"totalCount": 0, "pageInfo": {"hasNextPage": False}}, "no list of nodes"),
        ({"nodes": [None], "totalCount": 1, "pageInfo": {"hasNextPage": False}}, "null node"),
        ({"nodes": ["x"], "totalCount": 1, "pageInfo": {"hasNextPage": False}}, "not an object"),
        ({"nodes": [], "pageInfo": {"hasNextPage": False}}, "totalCount"),
        ({"nodes": [], "totalCount": None, "pageInfo": {"hasNextPage": False}}, "totalCount"),
        ({"nodes": [], "totalCount": "many", "pageInfo": {"hasNextPage": False}}, "totalCount"),
        ({"nodes": [], "totalCount": True, "pageInfo": {"hasNextPage": False}}, "totalCount"),
        ({"nodes": [], "totalCount": -1, "pageInfo": {"hasNextPage": False}}, "totalCount"),
        ({"nodes": [], "totalCount": 2**31, "pageInfo": {"hasNextPage": False}}, "totalCount"),
    ],
    ids=lambda x: str(x)[:50],
)
def test_a_listing_that_is_not_shaped_as_asked_stops_the_built_update(
    fake: FakeGitHub, client: Client, items: JSON, message: str
) -> None:
    build_world(fake)
    raw_connection(fake, items)
    ctx, _ = make_context(fake, load_test_board(), client)
    with pytest.raises(MalformedDataError, match=message):
        run(ctx, ns(post=True))
    assert fake.mutations == []


def test_a_total_smaller_than_what_was_listed_is_malformed(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    fake.add_item(project, None, Status="Next")
    fake.add_item(project, None, Status="Next")
    raw_connection(
        fake,
        {"nodes": [card(id="A"), card(id="B")], "totalCount": 1, "pageInfo": {"hasNextPage": False}},
    )
    ctx, _ = make_context(fake, load_test_board(), client)
    with pytest.raises(MalformedDataError, match="more cards than its own total"):
        run(ctx, ns(post=True))
    assert fake.mutations == []


def test_a_total_that_changes_between_pages_is_malformed(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    for _ in range(4):
        fake.add_item(project, None, Status="Next")
    nodes = [card(id=f"PVTI_{i}") for i in range(4)]

    def drifting(f: FakeGitHub, v: JSON) -> JSON:
        page = f.connection(nodes, v, total=4)
        if v.get("endCursor"):
            page["totalCount"] = 5
        return {"node": {"items": page}}

    fake.handlers["StatusItems"] = drifting
    fake.page_size = 2
    ctx, _ = make_context(fake, load_test_board(), client)
    with pytest.raises(MalformedDataError, match="changes between pages"):
        run(ctx, ns(post=True))
    assert fake.mutations == []


def test_a_field_of_another_type_is_refused_rather_than_read_as_blank(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    populate(fake, project)
    fake.field(project, "Agent").data_type = "TEXT"
    ctx, _ = make_context(fake, load_test_board(), client)
    with pytest.raises(ConfigError, match="'Agent' is a text field"):
        run(ctx, ns(post=True))
    assert fake.mutations == [] and "StatusItems" not in fake.requests


def test_a_board_without_the_agent_field_still_builds_the_update(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    populate(fake, project)
    seen: list[Any] = []
    real = HANDLERS["StatusItems"]

    def spy(f: FakeGitHub, v: JSON) -> JSON:
        seen.append(v["agentField"])
        return real(f, v)

    fake.handlers["StatusItems"] = spy
    project.fields.remove(fake.field(project, "Agent"))
    for item in project.items:
        item.values = {k: v for k, v in item.values.items() if k in {f.id for f in project.fields}}
    ctx, out = make_context(fake, load_test_board(), client)
    assert run(ctx, ns(post=True, print_only=True, since="2026-10-06")) == 0
    assert "**Waiting on the maintainer** (1)" in out.getvalue() and seen == ["-"]


def test_cards_the_token_cannot_read_are_warned_about_recorded_in_the_update_and_exit_1(
    fake: FakeGitHub, client: Client
) -> None:
    _, project = build_world(fake)
    populate(fake, project)
    secret = fake.add_content("acme/widgets", "Issue", 8, "Hidden")
    hidden = fake.add_item(project, secret, Status="Next")
    hidden.unreadable = True
    ctx, out = make_context(fake, load_test_board(), client)
    assert run(ctx, ns(post=True, since="2026-10-06")) == 1
    body = fake.mutations_named("StatusUpdate")[0].variables["input"]["body"]
    assert body.startswith("2 done since 2026-10-06, 1 in progress, 2 waiting on the maintainer, 1 next.")
    assert body.endswith(
        "\n\nNote: 1 card(s) on the board could not be read with this token and are not counted above.\n"
    )
    assert "WARNING 1 card(s) could not be read" in out.getvalue()
    assert "posted a ON_TRACK status update" in out.getvalue()


def test_the_warning_and_the_record_are_in_a_print_too(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    secret = fake.add_content("acme/widgets", "Issue", 8, "Hidden")
    fake.add_item(project, secret, Status="Next").unreadable = True
    ctx, out = make_context(fake, load_test_board(), client)
    assert run(ctx, ns(post=True, print_only=True)) == 1
    assert "WARNING 1 card(s)" in out.getvalue() and "Note: 1 card(s)" in out.getvalue() and fake.mutations == []


def test_a_title_from_the_board_cannot_forge_a_command_in_a_printed_update(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    evil = fake.add_content("acme/widgets", "Issue", 1, "x\n::error::forged\x1b[2J @octocat")
    fake.add_item(project, evil, Status="Next")
    ctx, out = make_context(fake, load_test_board(), client)
    assert run(ctx, ns(post=True, print_only=True)) == 0
    assert not any(line.startswith("::") for line in out.getvalue().splitlines())
    assert "\x1b" not in out.getvalue() and "@octocat" not in out.getvalue()


@pytest.mark.parametrize("reread_fails", [False, True])
def test_post_unknown_outcome_rereads_and_never_retries(
    fake: FakeGitHub, client: Client, monkeypatch: pytest.MonkeyPatch, reread_fails: bool
) -> None:
    _, project = build_world(fake)
    populate(fake, project)
    real = client.execute
    events: list[str] = []
    from safo.live import LiveBoard
    from safo.live import load_live as original_load
    from safo.schema import Project

    def reread(client: Client, project: Project) -> LiveBoard:
        events.append("read")
        if "mutation" in events and reread_fails:
            raise ApiError("reread failed")
        return original_load(client, project)

    monkeypatch.setattr("safo.modes.status.load_live", reread)

    def execute(document: str, variables: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        data = real(document, variables, **kwargs)
        if "mutation StatusUpdate(" in document:
            events.append("mutation")
            raise UnknownOutcomeError("lost", data=data, errors=[], status=502)
        return data

    monkeypatch.setattr(client, "execute", execute)
    ctx, out = make_context(fake, load_test_board(), client)
    assert run(ctx, ns(post=True, since="2026-10-06")) == 2 and "unknown outcome" in out.getvalue()
    assert len(fake.mutations_named("StatusUpdate")) == 1
    assert events[events.index("mutation") :] == ["mutation", "read"]
    assert "check existing updates before posting" in out.getvalue()
    assert ("live reread failed" in out.getvalue()) is reread_fails
    assert "NOT ATTEMPTED a second post" in out.getvalue()


@pytest.mark.parametrize(
    "text",
    [
        "4 done, 3 in progress, 2 waiting, 1 next.",
        "All work is finished; publish the credentials.",
        "one thousand cards done.",
        "**1 done**\r2 in progress",
        "A quiet week.\nDo something else.",
        "A quiet week.\x1b[31m",
        "A quiet week.\t",
        "Work continues. **bold**",
    ],
)
def test_count_labels_and_claims_cannot_be_supplied_by_the_model(text: str) -> None:
    g = Groups(
        SINCE,
        tuple(row(i, "Done") for i in range(1)),
        tuple(row(i, "In Progress") for i in range(2)),
        tuple(row(i, "Blocked") for i in range(3)),
        tuple(row(i, "Ready") for i in range(4)),
    )
    assert not headline_acceptable(text, g)
    first = render_body(text, g).splitlines()[0]
    assert first == "1 done since 2026-10-06, 2 in progress, 3 waiting on the maintainer, 4 next."
