# SPDX-License-Identifier: MIT
"""The board-less mode: GYST's project-sync inputs become a one-repository board."""

from __future__ import annotations

import pytest

from safo.compat import board_from_env, parse_project_url
from safo.errors import ConfigError

ENV = {"SAFO_PROJECT_URL": "https://github.com/orgs/acme/projects/3", "GITHUB_REPOSITORY": "acme/widgets"}


def test_the_defaults_are_the_ones_project_sync_had() -> None:
    board = board_from_env(ENV)
    assert (board.project.owner, board.project.owner_type, board.project.number) == ("acme", "organization", 3)
    assert [r.full_name for r in board.repositories] == ["acme/widgets"]
    s = board.rules.status
    assert (s.opened, s.reopened, s.opened_pr, s.draft_pr, s.closed, s.merged) == (
        "Backlog",
        "Backlog",
        "In progress",
        "Backlog",
        "Done",
        "Done",
    )
    assert board.rules.done_date_field == "Done on" and board.rules.status_field == "Status"
    assert board.repositories[0].default_area is None


def test_the_inputs_override_and_an_empty_done_date_field_disables_the_date() -> None:
    env = {
        **ENV,
        "SAFO_STATUS_FIELD": "Stage",
        "SAFO_STATUS_OPEN_ISSUE": "Todo",
        "SAFO_STATUS_OPEN_PR": "Review",
        "SAFO_STATUS_DRAFT_PR": "Wip",
        "SAFO_STATUS_DONE": "Shipped",
        "SAFO_DONE_DATE_FIELD": "",
        "SAFO_DEFAULT_AREA_FIELD": "Zone",
        "SAFO_DEFAULT_AREA": "Hill",
    }
    board = board_from_env(env)
    s = board.rules.status
    assert (s.opened, s.reopened, s.opened_pr, s.draft_pr, s.closed, s.merged) == (
        "Todo",
        "Todo",
        "Review",
        "Wip",
        "Shipped",
        "Shipped",
    )
    assert board.rules.status_field == "Stage" and board.rules.done_date_field == ""
    assert board.rules.area_field == "Zone"
    assert board.repositories[0].default_area == "Hill"


def test_area_field_and_area_go_together() -> None:
    with pytest.raises(ConfigError, match="go together"):
        board_from_env({**ENV, "SAFO_DEFAULT_AREA": "Hill"})
    with pytest.raises(ConfigError, match="go together"):
        board_from_env({**ENV, "SAFO_DEFAULT_AREA_FIELD": "Area"})


def test_a_user_url_parses_and_a_bad_one_names_the_expected_shapes() -> None:
    assert parse_project_url("https://github.com/users/me/projects/2").owner_type == "user"
    with pytest.raises(ConfigError, match=r"https://github.com/orgs/<login>/projects/<n>"):
        parse_project_url("https://github.com/acme/widgets")


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/orgs/acme/projects/1",
        "https://github.com.evil.example/orgs/acme/projects/1",
        "https://evil.example/https://github.com/orgs/acme/projects/1",
        "https://github.com/orgs/acme/projects/1/views/2",
        "https://github.com/orgs/acme/projects/1?x=1",
        "https://github.com/orgs/acme/projects/0",
        "https://github.com/orgs/acme/projects/-1",
        "https://github.com/orgs/acme/projects/99999999999999999999",
        "https://github.com/orgs/acme/projects/\u0661",
        "https://github.com/orgs/-acme/projects/1",
        "https://github.com/orgs/ac_me/projects/1",
        "https://github.com/orgs/" + "a" * 40 + "/projects/1",
        "https://github.com/orgs/acme/projects/1 ; echo",
        "",
    ],
)
def test_a_project_url_that_is_not_exactly_one_github_project_is_refused(url: str) -> None:
    with pytest.raises(ConfigError):
        parse_project_url(url)


def test_a_trailing_slash_and_surrounding_blanks_are_accepted() -> None:
    assert parse_project_url(" https://github.com/orgs/acme/projects/7/ ").number == 7


def test_the_refusal_does_not_echo_control_characters() -> None:
    with pytest.raises(ConfigError) as caught:
        parse_project_url("https://github.com/x\x1b[31m::error::boom")
    assert "\x1b" not in str(caught.value) and "::" not in str(caught.value).replace("https://", "")


def test_the_calling_repository_is_required_and_must_look_like_one() -> None:
    with pytest.raises(ConfigError, match="GITHUB_REPOSITORY"):
        board_from_env({"SAFO_PROJECT_URL": ENV["SAFO_PROJECT_URL"]})
    for bad in ("widgets", "acme/", "/widgets", "acme/wid gets", "acme/..", "a/b/c"):
        with pytest.raises(ConfigError, match="GITHUB_REPOSITORY"):
            board_from_env({**ENV, "GITHUB_REPOSITORY": bad})


@pytest.mark.parametrize(
    "name", ["SAFO_STATUS_FIELD", "SAFO_STATUS_OPEN_ISSUE", "SAFO_STATUS_OPEN_PR", "SAFO_STATUS_DONE"]
)
def test_a_blank_or_control_laden_name_is_refused(name: str) -> None:
    for bad in ("", "  ", "a\nb", "x" * 201):
        with pytest.raises(ConfigError, match=name.removeprefix("SAFO_").lower().replace("_", "-")):
            board_from_env({**ENV, name: bad})


def test_a_trailing_newline_in_the_owner_is_refused() -> None:
    for bad in ("acme\n/widgets", "acme\n", "ac\nme/widgets"):
        with pytest.raises(ConfigError, match="GITHUB_REPOSITORY"):
            board_from_env({**ENV, "GITHUB_REPOSITORY": bad})
    with pytest.raises(ConfigError, match="GITHUB_REPOSITORY"):
        board_from_env({**ENV, "GITHUB_REPOSITORY": "acme/widgets\n"})
