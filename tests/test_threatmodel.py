# SPDX-License-Identifier: Apache-2.0
"""Threat model before build: the line an AI-surface issue must carry, and what audit and reconcile say about it."""

from __future__ import annotations

import argparse
import dataclasses
from typing import Any

import pytest
import yaml

from fakegh import FakeGitHub
from safo.errors import ConfigError, MalformedDataError
from safo.graphql import Client
from safo.modes import audit, reconcile
from safo.schema import Board, ThreatModel, parse_board
from safo.threatmodel import Q_THREAT_ISSUES, judge, unthreatened_issues, verdict
from world import DATA, build_world, load_test_board, make_context

LABEL = "ai-surface"
CARD = {"Status": "Backlog", "Area": "Core", "Priority": "P2 later"}


def configured(board: Board, **rule: Any) -> Board:
    rule = {"label": LABEL, **rule}
    return dataclasses.replace(board, rules=dataclasses.replace(board.rules, threat_model=ThreatModel(**rule)))


def run_audit(fake: FakeGitHub, client: Client, board: Board) -> tuple[int, str]:
    ctx, out = make_context(fake, board, client)
    code = audit.run(ctx, argparse.Namespace())
    assert fake.mutations == [], "audit must never mutate"
    return code, out.getvalue()


def run_reconcile(fake: FakeGitHub, client: Client, board: Board) -> tuple[int, str]:
    ctx, out = make_context(fake, board, client)
    return reconcile.run(ctx, argparse.Namespace()), out.getvalue()


def labeled_issue(fake: FakeGitHub, project: Any, number: int, body: str, **extra: Any) -> None:
    issue = fake.add_content("acme/widgets", "Issue", number, labels=[LABEL], body=body, **extra)
    fake.add_item(project, issue, **CARD)


# -- the line ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        "threat-model: docs/threat-model/app.threat-dragon.json",
        "threat-model: docs/threat-model/",
        "threat-model: model.json",
        "threat-model: https://example.invalid/models/app",
        "threat-model: n/a - typo in a comment, nothing new crosses a boundary",
        "threat-model: n/a \u2013 renamed a file, no behavior change",
        "  Threat-Model:   N/A \u2014 reviewed, no new trust boundary",
        "intro\n\nthreat-model: docs/tm.json\n\nmore",
        "threat-model: <path>\nthreat-model: docs/tm.json",
    ],
)
def test_a_usable_line_is_accepted(body: str) -> None:
    assert verdict(body) is None


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        ("", "has no `threat-model:` line"),
        ("no line here", "has no `threat-model:` line"),
        ("we wrote the threat-model: docs/tm.json yesterday", "has no `threat-model:` line"),
        ("> threat-model: docs/tm.json", "has no `threat-model:` line"),
        ("threat-model:", "has no `threat-model:` line"),
        ("threat-model: n/a", "needs a reason"),
        ("threat-model: n/a - ", "needs a reason"),
        ("threat-model: n/a - ok", "needs a reason"),
        ("threat-model: n/a because", "needs a reason"),
        ("threat-model: TBD", "repository path or an https URL"),
        ("threat-model: todo", "repository path or an https URL"),
        ("threat-model: none", "repository path or an https URL"),
        ("threat-model: <path or URL>", "repository path or an https URL"),
        ("threat-model: /etc/passwd", "repository path or an https URL"),
        ("threat-model: ../outside/tm.json", "repository path or an https URL"),
        ("threat-model: docs/../../tm.json", "repository path or an https URL"),
        ("threat-model: http://example.invalid/m", "repository path or an https URL"),
        ("threat-model: see the wiki", "repository path or an https URL"),
        ("threat-model: file.json and more words", "repository path or an https URL"),
    ],
)
def test_an_unusable_line_is_refused_with_a_reason(body: str, reason: str) -> None:
    got = verdict(body)
    assert got is not None and reason in got


def test_a_single_word_without_a_dot_or_slash_is_not_a_path() -> None:
    assert judge("model") is not None and judge("model.json") is None and judge("docs/model") is None


# -- board.yaml -------------------------------------------------------------------------------------------


def board_data() -> dict[str, Any]:
    data = yaml.safe_load((DATA / "board.yaml").read_text())
    assert isinstance(data, dict)
    return data


def test_the_default_is_not_configured() -> None:
    assert load_test_board().rules.threat_model == ThreatModel("", ())


def test_board_yaml_reads_the_section() -> None:
    data = board_data()
    data["rules"]["threat_model"] = {"label": "ai-surface", "exempt_repos": ["acme/widgets"]}
    assert parse_board(data, check_fields=False).rules.threat_model == ThreatModel("ai-surface", ("acme/widgets",))


@pytest.mark.parametrize(
    "bad",
    [
        {"label": 3},
        {"label": "a,b"},
        {"label": " padded "},
        {"label": "x" * 51},
        {"label": "ai\nsurface"},
        {"exempt_repos": ["widgets"]},
        {"exempt_repos": [3]},
        {"unknown": 1},
    ],
)
def test_board_yaml_refuses_a_bad_section(bad: dict[str, Any]) -> None:
    data = board_data()
    data["rules"]["threat_model"] = bad
    with pytest.raises(ConfigError, match=r"rules\.threat_model"):
        parse_board(data, check_fields=False)


# -- audit ------------------------------------------------------------------------------------------------


def test_audit_names_each_labeled_issue_without_a_usable_line(fake: FakeGitHub, client: Client) -> None:
    board, project = build_world(fake, configured(load_test_board()))
    labeled_issue(fake, project, 1, "threat-model: docs/threat-model/app.threat-dragon.json")
    labeled_issue(fake, project, 2, "nothing about it")
    labeled_issue(fake, project, 3, "threat-model: n/a")
    code, text = run_audit(fake, client, board)
    lines = text.splitlines()
    assert code == 1
    assert any(line.startswith("DRIFT   THREAT acme/widgets#2 is labeled 'ai-surface' and has no") for line in lines)
    assert any("THREAT acme/widgets#3" in line and "needs a reason" in line for line in lines)
    assert not any("acme/widgets#1" in line and "THREAT" in line for line in lines)


def test_an_unlabeled_issue_is_not_asked_for_a_line(fake: FakeGitHub, client: Client) -> None:
    board, project = build_world(fake, configured(load_test_board()))
    fake.add_item(project, fake.add_content("acme/widgets", "Issue", 1, labels=["bug"], body=""), **CARD)
    code, text = run_audit(fake, client, board)
    assert code == 0 and "THREAT" not in text


def test_a_clean_board_reports_clean_with_the_check_configured(fake: FakeGitHub, client: Client) -> None:
    board, project = build_world(fake, configured(load_test_board()))
    labeled_issue(fake, project, 1, "threat-model: docs/tm.json")
    code, text = run_audit(fake, client, board)
    assert code == 0 and text.splitlines()[-1] == "clean"
    assert "Threat-model check not configured" not in text


def test_an_unconfigured_board_skips_the_check_and_says_so(fake: FakeGitHub, client: Client) -> None:
    board, project = build_world(fake)
    labeled_issue(fake, project, 1, "")
    code, text = run_audit(fake, client, board)
    assert code == 0 and "THREAT" not in text
    assert "NOTE    Threat-model check not configured: rules.threat_model.label is empty" in text
    assert "RepoThreatIssues" not in fake.requests, "no read is made for a check that is not configured"


def test_the_label_comes_from_board_yaml(fake: FakeGitHub, client: Client) -> None:
    board, project = build_world(fake, configured(load_test_board(), label="llm"))
    issue = fake.add_content("acme/widgets", "Issue", 1, labels=["llm"], body="")
    fake.add_item(project, issue, **CARD)
    labeled_issue(fake, project, 2, "")  # carries ai-surface, which this board does not ask about
    code, text = run_audit(fake, client, board)
    assert code == 1 and "THREAT acme/widgets#1 is labeled 'llm'" in text and "#2" not in text


def test_an_exempt_repository_is_not_checked(fake: FakeGitHub, client: Client) -> None:
    board, project = build_world(fake, configured(load_test_board(), exempt_repos=("acme/widgets",)))
    labeled_issue(fake, project, 1, "")
    code, text = run_audit(fake, client, board)
    assert code == 0 and "THREAT" not in text


def test_a_closed_issue_counts_inside_the_window_only(fake: FakeGitHub, client: Client) -> None:
    board = configured(load_test_board())
    board = dataclasses.replace(board, rules=dataclasses.replace(board.rules, add_closed_days=7))
    board, project = build_world(fake, board)
    for number, day in ((1, "2026-10-05"), (2, "2026-08-01")):
        issue = fake.add_content(
            "acme/widgets", "Issue", number, state="CLOSED", closed_at=f"{day}T00:00:00Z", labels=[LABEL], body=""
        )
        fake.add_item(project, issue, Status="Done", Area="Core", Priority="P2 later", Done_on=day)
    code, text = run_audit(fake, client, board)
    assert code == 1 and "THREAT acme/widgets#1" in text and "THREAT acme/widgets#2" not in text


def test_a_closed_issue_is_ignored_when_the_window_is_zero(fake: FakeGitHub, client: Client) -> None:
    board, _ = build_world(fake, configured(load_test_board()))
    fake.add_content("acme/widgets", "Issue", 1, state="CLOSED", closed_at="2026-10-05T00:00:00Z", labels=[LABEL])
    ctx, _ = make_context(fake, board, client)
    assert unthreatened_issues(client, board, ctx.today) == ([], [])


def test_a_repository_that_cannot_be_read_is_reported_not_passed(fake: FakeGitHub, client: Client) -> None:
    board, _ = build_world(fake, configured(load_test_board()))
    fake.repos["acme/manuals"].installed = False
    ctx, _ = make_context(fake, board, client)
    _, unreachable = unthreatened_issues(client, board, ctx.today)
    assert unreachable == ["acme/manuals"]


def test_a_malformed_answer_cannot_be_read_as_clean(fake: FakeGitHub, client: Client) -> None:
    board, project = build_world(fake, configured(load_test_board()))
    labeled_issue(fake, project, 1, "")
    row = {"number": 1, "state": "OPEN", "closedAt": None, "body": 7, "repository": {"nameWithOwner": "acme/widgets"}}
    fake.handlers["RepoThreatIssues"] = lambda f, v: {"repository": {"issues": f.connection([row], v)}}
    with pytest.raises(MalformedDataError, match="the body is not text"):
        run_audit(fake, client, board)


def test_a_null_body_is_a_missing_line_not_a_crash(fake: FakeGitHub, client: Client) -> None:
    board, project = build_world(fake, configured(load_test_board()))
    labeled_issue(fake, project, 1, "")
    row = {
        "number": 1,
        "state": "OPEN",
        "closedAt": None,
        "body": None,
        "repository": {"nameWithOwner": "acme/widgets"},
    }
    fake.handlers["RepoThreatIssues"] = lambda f, v: {"repository": {"issues": f.connection([row], v)}}
    code, text = run_audit(fake, client, board)
    assert code == 1 and "THREAT acme/widgets#1" in text


def test_the_label_reaches_github_as_a_variable_never_inside_the_query(fake: FakeGitHub, client: Client) -> None:
    board, _ = build_world(fake, configured(load_test_board(), label='x"]) { evil'))
    ctx, _ = make_context(fake, board, client)
    unthreatened_issues(client, board, ctx.today)
    assert "evil" not in Q_THREAT_ISSUES and fake.requests.count("RepoThreatIssues") >= 1


# -- reconcile --------------------------------------------------------------------------------------------


def test_reconcile_lists_the_issue_for_a_person_and_writes_nothing_for_it(fake: FakeGitHub, client: Client) -> None:
    board, project = build_world(fake, configured(load_test_board()))
    labeled_issue(fake, project, 1, "")
    code, text = run_reconcile(fake, client, board)
    assert code == 1
    assert "HUMAN acme/widgets#1 has no `threat-model:` line: add `threat-model: <path or URL>`" in text
    assert {m.op for m in fake.mutations} <= {"AddItem", "SetSelect", "SetDate"}


def test_reconcile_stays_clean_when_the_line_is_there(fake: FakeGitHub, client: Client) -> None:
    board, project = build_world(fake, configured(load_test_board()))
    labeled_issue(fake, project, 1, "threat-model: n/a - documentation only, no behavior change")
    code, text = run_reconcile(fake, client, board)
    assert code == 0 and "HUMAN" not in text
