# SPDX-License-Identifier: MIT
"""Credentials on the command line: refusals before any request, no token in the output, the board-less path."""

from __future__ import annotations

import json
from pathlib import Path

from cliutil import BOARD, run_cli
from fakegh import FakeGitHub
from world import build_world


def test_a_pat_on_an_organization_board_is_refused_before_a_single_request(fake: FakeGitHub) -> None:
    build_world(fake)
    env = {"SAFO_TOKEN": fake.token, "SAFO_TOKEN_KIND": "token", "GITHUB_GRAPHQL_URL": fake.url}
    code, _, err = run_cli("--board", BOARD, "audit", env=env)
    assert code == 2 and "refused for an organization-owned project" in err and fake.requests == []
    assert fake.token not in err


def test_an_app_token_on_a_user_board_is_refused_before_a_single_request(fake: FakeGitHub) -> None:
    env = {
        "SAFO_TOKEN": fake.token,
        "SAFO_TOKEN_KIND": "app",
        "GITHUB_GRAPHQL_URL": fake.url,
        "SAFO_PROJECT_URL": "https://github.com/users/me/projects/1",
        "GITHUB_REPOSITORY": "me/widgets",
    }
    code, _, err = run_cli("sync", env=env)
    assert code == 2 and "cannot write a user-owned project" in err and fake.requests == []


def test_the_allow_flag_lets_a_pat_through(fake: FakeGitHub) -> None:
    build_world(fake)
    env = {
        "SAFO_TOKEN": fake.token,
        "SAFO_TOKEN_KIND": "token",
        "SAFO_ALLOW_TOKEN_FOR_ORG": "true",
        "GITHUB_GRAPHQL_URL": fake.url,
    }
    code, out, err = run_cli("--board", BOARD, "audit", env=env)
    assert code == 0 and "refused" not in err, out + err


def test_the_token_never_reaches_the_output(fake: FakeGitHub) -> None:
    build_world(fake)
    env = {"SAFO_TOKEN": fake.token, "SAFO_TOKEN_KIND": "gh", "GITHUB_GRAPHQL_URL": fake.url}
    code, out, err = run_cli("--board", BOARD, "audit", env=env)
    assert code == 0 and fake.token not in out + err and fake.requests


def test_the_board_less_inputs_drive_a_sync(fake: FakeGitHub, tmp_path: Path) -> None:
    _, project = build_world(fake)
    issue = fake.add_content("acme/widgets", "Issue", 4)
    payload = {
        "action": "opened",
        "issue": {"node_id": issue.id, "number": 4, "state": "open", "closed_at": None},
        "repository": {"full_name": "acme/widgets"},
    }
    event = tmp_path / "event.json"
    event.write_text(json.dumps(payload))
    env = {
        "SAFO_TOKEN": fake.token,
        "SAFO_TOKEN_KIND": "app",
        "GITHUB_GRAPHQL_URL": fake.url,
        "SAFO_PROJECT_URL": "https://github.com/orgs/acme/projects/1",
        "GITHUB_REPOSITORY": "acme/widgets",
        "GITHUB_EVENT_PATH": str(event),
        "GITHUB_EVENT_NAME": "issues",
        "SAFO_DEFAULT_AREA_FIELD": "Area",
        "SAFO_DEFAULT_AREA": "Core",
    }
    code, out, err = run_cli("sync", env=env)
    assert code == 0, out + err
    assert fake.value(project, project.items[0], "Status") == "Backlog"
    assert fake.value(project, project.items[0], "Area") == "Core"


def test_safo_board_in_the_environment_names_the_board(fake: FakeGitHub) -> None:
    build_world(fake)
    env = {"SAFO_BOARD": BOARD, "SAFO_TOKEN": fake.token, "SAFO_TOKEN_KIND": "gh", "GITHUB_GRAPHQL_URL": fake.url}
    code, out, err = run_cli("audit", env=env)
    assert code == 0 and "audit acme/1" in out, out + err


def test_the_flag_beats_the_environment() -> None:
    code, out, _ = run_cli("--board", BOARD, "validate", env={"SAFO_BOARD": "/nonexistent/board.yaml"})
    assert code == 0 and "configuration valid" in out


def test_a_credentialless_live_dry_run_reports_unknown() -> None:
    """A live dry run still needs credentials to establish board state."""
    code, out, err = run_cli("--board", BOARD, "--dry-run", "audit")
    assert code == 2 and "UNKNOWN no token: nothing read" in out and err == ""


def test_a_credentialless_live_run_is_an_error_naming_the_variable() -> None:
    code, out, err = run_cli("--board", BOARD, "audit")
    assert code == 2 and "set SAFO_TOKEN" in err and out == ""


def test_offline_validate_is_separate_from_credentialless_live_audit(fake: FakeGitHub) -> None:
    code, out, err = run_cli("--board", BOARD, "validate", env={"GITHUB_GRAPHQL_URL": fake.url})
    assert code == 0 and "live board not audited" in out and err == "" and fake.requests == []
    for mode in ("audit", "bootstrap", "reconcile"):
        assert run_cli("--board", BOARD, "--dry-run", mode)[0] == 2


def test_validate_still_reads_the_board_and_fails_on_a_bad_one() -> None:
    code, _, err = run_cli("--board", "/nonexistent/board.yaml", "validate")
    assert code == 2 and "cannot read the board file" in err


def test_validate_with_a_token_makes_no_request(fake: FakeGitHub) -> None:
    env = {"SAFO_TOKEN": fake.token, "SAFO_TOKEN_KIND": "token", "GITHUB_GRAPHQL_URL": fake.url}
    code, _, _ = run_cli("--board", BOARD, "validate", env=env)
    assert code == 0 and fake.requests == []


def test_a_hostile_project_url_is_one_escaped_annotation() -> None:
    env = {
        "GITHUB_ACTIONS": "true",
        "SAFO_PROJECT_URL": "https://example.org/x\n::set-output name=a::b",
        "GITHUB_REPOSITORY": "acme/widgets",
    }
    code, out, err = run_cli("validate", env=env)
    assert code == 2 and out == "" and err.count("\n") == 1 and err.startswith("::error title=safo::")
    assert "\n::set-output" not in err
