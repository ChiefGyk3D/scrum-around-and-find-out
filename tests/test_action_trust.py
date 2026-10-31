# SPDX-License-Identifier: Apache-2.0
"""What the Action trusts from its caller: an allow-list of events that fails closed, and board and status-body files
read from a bound revision. Real git repositories; nothing here is faked."""

from __future__ import annotations

from pathlib import Path

import pytest

from gitrepo import git, make_repo
from safo import action_preflight, action_trust
from safo.errors import ConfigError

ROOT = Path(__file__).parent.parent
BOARD_TEXT = (ROOT / "tests" / "data" / "board.yaml").read_text()

# Event names are assembled from pieces so that no line of this file is a recipe; the table is data, not a story.
PR = "pull" + "_request"
PRT = PR + "_target"
WFR = "workflow" + "_run"
DISPATCH = "workflow" + "_dispatch"
COMMENT = "issue" + "_comment"
MAIN, TAG, FEATURE = "refs/heads/main", "refs/tags/v1.2.3", "refs/heads/feature/x"
PULL = "refs/pull/7/merge"


def trust_env(event: str, ref: str, fork: str = "false", **more: str) -> dict[str, str]:
    return {
        "EVENT_NAME": event,
        "GITHUB_REF": ref,
        "DEFAULT_BRANCH": "main",
        "IS_FORK": fork,
        "REPO_IS_FORK": "false",
        **more,
    }


# (event, ref, fork flag, accepted)
TABLE = [
    ("push", MAIN, "false", True),
    ("push", TAG, "false", True),
    ("push", FEATURE, "false", False),
    ("push", MAIN, "true", False),
    ("schedule", MAIN, "false", True),
    ("schedule", FEATURE, "false", False),
    (DISPATCH, MAIN, "false", True),
    (DISPATCH, TAG, "false", True),
    (DISPATCH, FEATURE, "false", True),
    (DISPATCH, PULL, "false", False),
    (DISPATCH, MAIN, "true", False),
    ("issues", MAIN, "false", True),
    ("issues", FEATURE, "false", False),
    (WFR, MAIN, "false", True),
    (WFR, MAIN, "true", False),
    (WFR, FEATURE, "false", False),
    (PR, PULL, "false", True),
    (PR, PULL, "true", False),
    (PR, MAIN, "false", False),
    (PRT, MAIN, "false", True),
    (PRT, MAIN, "true", False),
    (PRT, FEATURE, "false", False),
    # events the Action cannot classify
    (COMMENT, MAIN, "false", False),
    ("pull_request_review", PULL, "false", False),
    ("pull_request_review_comment", PULL, "false", False),
    ("workflow_call", MAIN, "false", False),
    ("repository_dispatch", MAIN, "false", False),
    ("check_run", MAIN, "false", False),
    ("fork", MAIN, "false", False),
    ("discussion", MAIN, "false", False),
    ("", MAIN, "false", False),
    ("anything-new", MAIN, "false", False),
    # case and unicode: exact match only, no folding, trimming or normalization
    ("Push", MAIN, "false", False),
    ("PUSH", MAIN, "false", False),
    ("push ", MAIN, "false", False),
    ("push\n", MAIN, "false", False),
    ("pu\u0455h", MAIN, "false", False),  # a Cyrillic letter in the middle
    ("push", "refs/heads/MAIN", "false", False),
    ("push", "refs/heads/main​", "false", False),
    ("push", "refs/heads/main ", "false", False),
    ("push", "refs/tags/", "false", False),
    ("push", "refs/tags/v1\n", "false", False),
    (PRT, "refs/heads/main\n", "false", False),
    (PR.upper(), PULL, "false", False),
]


@pytest.mark.parametrize(("event", "ref", "fork", "accepted"), TABLE)
def test_the_event_and_ref_table(event: str, ref: str, fork: str, accepted: bool) -> None:
    if accepted:
        assert action_trust.classify(trust_env(event, ref, fork)).event == event
    else:
        with pytest.raises(ConfigError):
            action_trust.classify(trust_env(event, ref, fork))


def test_the_table_has_both_outcomes_and_every_accepted_event_is_in_it() -> None:
    assert sum(row[3] for row in TABLE) >= 10 and sum(not row[3] for row in TABLE) >= 20
    assert {row[0] for row in TABLE if row[3]} == {"push", "schedule", DISPATCH, "issues", WFR, PR, PRT}


@pytest.mark.parametrize("missing", ["EVENT_NAME", "GITHUB_REF", "DEFAULT_BRANCH", "IS_FORK", "REPO_IS_FORK"])
def test_a_missing_value_is_refused_not_assumed(missing: str) -> None:
    env = trust_env("push", MAIN)
    del env[missing]
    with pytest.raises(ConfigError):
        action_trust.classify(env)


@pytest.mark.parametrize("default", ["", "Main", "ma in", "main\n", "m\u0430in"])
def test_a_schedule_needs_a_valid_default_branch_and_an_exact_match(default: str) -> None:
    with pytest.raises(ConfigError):
        action_trust.classify({**trust_env("schedule", MAIN), "DEFAULT_BRANCH": default})


@pytest.mark.parametrize("event", ["push", "schedule", DISPATCH, "issues", WFR, PR, PRT])
def test_a_repository_that_is_itself_a_fork_gets_no_credential_unless_the_caller_allows_it(event: str) -> None:
    ref = {PR: PULL, DISPATCH: MAIN}.get(event, MAIN)
    env = {**trust_env(event, ref), "REPO_IS_FORK": "true"}
    with pytest.raises(ConfigError, match="itself a fork"):
        action_trust.classify(env)
    with pytest.raises(ConfigError, match="itself a fork"):
        action_trust.classify({**env, "ALLOW_FORK_REPO": "TRUE"})
    assert action_trust.classify({**env, "ALLOW_FORK_REPO": "true"}).event == event


@pytest.mark.parametrize("flag", ["", "True", "1"])
def test_the_repository_fork_flag_is_exactly_true_or_false(flag: str) -> None:
    with pytest.raises(ConfigError, match="repository fork flag"):
        probe = {**trust_env("push", MAIN), "REPO_IS_FORK": flag}
        action_trust.classify(probe)


@pytest.mark.parametrize("flag", ["", "True", "1", "yes", "false "])
def test_the_fork_flag_is_exactly_true_or_false(flag: str) -> None:
    with pytest.raises(ConfigError, match="fork flag"):
        action_trust.classify(trust_env("push", MAIN, flag))


def test_an_unclassified_event_is_refused_for_every_credential_mode_and_names_what_is_trusted() -> None:
    env = {
        "SAFO_MODE": "audit",
        "SAFO_BOARD": "b.yaml",
        "HAS_PRIVATE_KEY": "true",
        "CLIENT_ID": "Iv23liTEST",
        "SAFO_DRY_RUN": "false",
        **trust_env(COMMENT, MAIN),
    }
    for mode in ("audit", "sync", "reconcile", "status", "bootstrap"):
        with pytest.raises(ConfigError, match="not one the Action can classify as trusted"):
            action_preflight.check({**env, "SAFO_MODE": mode})


def test_validate_needs_no_trust_because_it_uses_no_credential() -> None:
    env = {
        "SAFO_MODE": "validate",
        "SAFO_BOARD": "tests/data/board.yaml",
        "GITHUB_WORKSPACE": str(ROOT),
        "SAFO_DRY_RUN": "false",
        **trust_env(COMMENT, MAIN),
    }
    assert action_preflight.check(env) == ""


def test_a_fork_pull_request_target_needs_the_explicit_opt_in() -> None:
    fork = trust_env(PRT, MAIN, "true")
    with pytest.raises(ConfigError, match="allow-fork-pull-request-target"):
        action_trust.classify(fork)
    with pytest.raises(ConfigError):
        action_trust.classify({**fork, "ALLOW_FORK_PRT": "TRUE"})
    assert "allowed by the caller" in action_trust.classify({**fork, "ALLOW_FORK_PRT": "true"}).why
    # the opt-in does not open any other event
    with pytest.raises(ConfigError):
        action_trust.classify({**trust_env("push", FEATURE, "true"), "ALLOW_FORK_PRT": "true"})
    with pytest.raises(ConfigError):
        action_trust.classify({**trust_env(PR, PULL, "true"), "ALLOW_FORK_PRT": "true"})


# -- the trusted revision --------------------------------------------------------------------------------------------


@pytest.fixture
def repo(tmp_path: Path) -> tuple[Path, str]:
    ws = tmp_path / "ws"
    sha = make_repo(
        ws,
        {"board.yaml": BOARD_TEXT, "reports/update.md": "all good\n", "bin/run.sh": "x"},
        {"link.yaml": "board.yaml"},
    )
    return ws, sha


def revision_env(ws: Path, sha: str, event: str = "push", ref: str = MAIN, **more: str) -> dict[str, str]:
    return {
        **trust_env(event, ref),
        "GITHUB_WORKSPACE": str(ws),
        "GITHUB_SHA": sha,
        "RUNNER_TEMP": str(ws.parent),
        **more,
    }


def revision_of(ws: Path, sha: str, **more: str) -> action_trust.Revision:
    env = revision_env(ws, sha, **more)
    return action_trust.trusted_revision(env, action_trust.classify(env))


def test_a_file_is_read_from_the_commit_not_from_the_working_tree(repo: tuple[Path, str]) -> None:
    ws, sha = repo
    (ws / "board.yaml").write_text("project: {}\n# edited after the commit\n")
    (ws / "reports" / "update.md").unlink()
    rev = revision_of(ws, sha)
    assert rev.blob("board.yaml", "board-file", 10**6).decode() == BOARD_TEXT
    assert rev.blob("reports/update.md", "status-body-file", 100) == b"all good\n"


def test_a_file_added_only_to_the_working_tree_does_not_exist(repo: tuple[Path, str]) -> None:
    ws, sha = repo
    (ws / "extra.yaml").write_text(BOARD_TEXT)
    with pytest.raises(ConfigError, match="not a file in the trusted revision"):
        revision_of(ws, sha).blob("extra.yaml", "board-file", 10**6)


def test_a_link_is_refused_whatever_it_points_at(repo: tuple[Path, str]) -> None:
    ws, sha = repo
    outside = ws.parent / "outside.yaml"
    outside.write_text(BOARD_TEXT)
    sha = make_repo(ws, {}, {"to-outside.yaml": str(outside), "dir-link": ".", "up.yaml": "../outside.yaml"})
    rev = revision_of(ws, sha)
    for path in ("link.yaml", "to-outside.yaml", "up.yaml", "dir-link/board.yaml", "dir-link"):
        with pytest.raises(ConfigError, match="trusted revision"):
            rev.blob(path, "board-file", 10**6)


def test_a_directory_and_a_missing_path_are_not_files(repo: tuple[Path, str]) -> None:
    ws, sha = repo
    rev = revision_of(ws, sha)
    for path in ("reports", "reports/nothing.md", "nothing.yaml", "BOARD.YAML"):
        with pytest.raises(ConfigError, match="trusted revision"):
            rev.blob(path, "board-file", 10**6)


@pytest.mark.parametrize(
    "path",
    [
        "",
        "/etc/passwd",
        "../board.yaml",
        "reports/../board.yaml",
        "./board.yaml",
        "reports//update.md",
        "reports/",
        "-x",
        "~/x",
        "a\\b",
        "a\nb",
        "a\x00b",
        ".",
    ],
)
def test_a_path_outside_or_not_plain_is_refused(repo: tuple[Path, str], path: str) -> None:
    ws, sha = repo
    with pytest.raises(ConfigError, match="plain relative path"):
        revision_of(ws, sha).blob(path, "board-file", 10**6)


def test_a_file_over_the_limit_is_refused(repo: tuple[Path, str]) -> None:
    ws, sha = repo
    with pytest.raises(ConfigError, match="longer than"):
        revision_of(ws, sha).blob("board.yaml", "board-file", 10)


def test_a_workspace_without_a_checkout_cannot_supply_a_file(tmp_path: Path) -> None:
    ws = tmp_path / "plain"
    ws.mkdir()
    (ws / "board.yaml").write_text(BOARD_TEXT)
    rev = revision_of(ws, "b" * 40)
    assert not rev.has_repo
    with pytest.raises(ConfigError, match="checked out"):
        rev.blob("board.yaml", "board-file", 10**6)


def test_a_checkout_of_some_other_commit_is_refused(repo: tuple[Path, str]) -> None:
    ws, sha = repo
    make_repo(ws, {"board.yaml": BOARD_TEXT + "# other\n"}, message="other")
    env = revision_env(ws, sha)
    with pytest.raises(ConfigError, match="checked-out commit is not the trusted revision"):
        action_trust.trusted_revision(env, action_trust.classify(env))
    git(ws, "checkout", "-q", sha)
    assert revision_of(ws, sha).sha == sha


@pytest.mark.parametrize("sha", ["", "abc", "A" * 40, "g" * 40, "a" * 39, "a" * 41])
def test_a_malformed_run_commit_is_refused(repo: tuple[Path, str], sha: str) -> None:
    ws, _ = repo
    env = revision_env(ws, sha)
    with pytest.raises(ConfigError, match=r"github\.sha"):
        action_trust.trusted_revision(env, action_trust.classify(env))


def test_trusted_ref_binds_the_revision(repo: tuple[Path, str]) -> None:
    ws, sha = repo
    assert revision_of(ws, sha, TRUSTED_REF=sha).sha == sha
    assert revision_of(ws, sha, TRUSTED_REF=MAIN).sha == sha
    git(ws, "tag", "v1.2.3")
    assert revision_of(ws, sha, TRUSTED_REF=TAG).sha == sha


@pytest.mark.parametrize(
    "given",
    [
        "main",
        "HEAD",
        "--all",
        "refs/heads/main^",
        "refs/heads/nope",
        "refs/pull/7/head",
        "a" * 40,
        "refs/heads/-x",
        "refs/heads/main\n",
        "origin/main",
        "refs/remotes/origin/main",
    ],
)
def test_trusted_ref_must_be_a_full_name_or_commit_the_checkout_holds(repo: tuple[Path, str], given: str) -> None:
    ws, sha = repo
    env = revision_env(ws, sha, TRUSTED_REF=given)
    with pytest.raises(ConfigError, match="trusted-ref"):
        action_trust.trusted_revision(env, action_trust.classify(env))


def test_trusted_ref_for_a_run_that_carries_outside_content_must_be_the_run_commit(repo: tuple[Path, str]) -> None:
    ws, sha = repo
    other = make_repo(ws, {"board.yaml": BOARD_TEXT + "# next\n"}, message="next")
    git(ws, "checkout", "-q", sha)
    for event in (PRT, WFR, "issues"):
        env = revision_env(ws, sha, event, MAIN, TRUSTED_REF=other)
        with pytest.raises(ConfigError, match="must be the commit this run is on"):
            action_trust.trusted_revision(env, action_trust.classify(env))
        env = revision_env(ws, sha, event, MAIN, TRUSTED_REF=sha)
        assert action_trust.trusted_revision(env, action_trust.classify(env)).sha == sha


def test_trusted_ref_is_never_the_head_of_the_pull_request_under_test(repo: tuple[Path, str]) -> None:
    ws, _ = repo
    other = make_repo(ws, {"board.yaml": BOARD_TEXT + "# head\n"}, message="head")
    git(ws, "checkout", "-q", other)
    env = revision_env(ws, other, DISPATCH, MAIN, TRUSTED_REF=other, PR_HEAD_SHA=other.upper())
    with pytest.raises(ConfigError, match="head commit of the pull request"):
        action_trust.trusted_revision(env, action_trust.classify(env))
    env = revision_env(ws, other, DISPATCH, MAIN, TRUSTED_REF=other)
    assert action_trust.trusted_revision(env, action_trust.classify(env)).sha == other


def test_omitting_trusted_ref_binds_the_commit_the_run_is_on(repo: tuple[Path, str]) -> None:
    ws, sha = repo
    assert revision_of(ws, sha).sha == sha and "TRUSTED_REF" not in revision_env(ws, sha)


def test_a_replacement_object_does_not_change_what_is_read(repo: tuple[Path, str]) -> None:
    ws, sha = repo
    blob = git(ws, "rev-parse", f"{sha}:board.yaml")
    fake = ws.parent / "fake.yaml"
    fake.write_text("not: the board\n")
    fake_oid = git(ws, "hash-object", "-w", str(fake))
    git(ws, "replace", blob, fake_oid)
    assert revision_of(ws, sha).blob("board.yaml", "board-file", 10**6).decode() == BOARD_TEXT


# -- through check(), with the real reads ----------------------------------------------------------------------------


def full_env(ws: Path, sha: str, **more: str) -> dict[str, str]:
    return {
        "SAFO_MODE": "audit",
        "SAFO_BOARD": "board.yaml",
        "HAS_PRIVATE_KEY": "true",
        "CLIENT_ID": "Iv23liTEST",
        "GITHUB_REPOSITORY": "acme/widgets",
        "REPOSITORY_OWNER": "acme",
        "REPO_PRIVATE": "true",
        "SAFO_DRY_RUN": "false",
        **revision_env(ws, sha),
        **more,
    }


def test_the_board_the_token_scope_comes_from_is_the_committed_one_not_the_edited_one(repo: tuple[Path, str]) -> None:
    ws, sha = repo
    (ws / "board.yaml").write_text(BOARD_TEXT.replace("widgets", "elsewhere"))
    outputs: dict[str, str] = {}
    assert action_preflight.check(full_env(ws, sha), outputs) == "widgets,manuals"
    assert Path(outputs["board-file"]).read_text() == BOARD_TEXT
    assert not Path(outputs["board-file"]).is_relative_to(ws)
    assert outputs["credentials"] == "allowed" and "trusted revision" in outputs["trust"]


def test_the_status_body_comes_from_the_commit_too(repo: tuple[Path, str]) -> None:
    ws, sha = repo
    (ws / "reports" / "update.md").write_text("changed")
    outputs: dict[str, str] = {}
    action_preflight.check(full_env(ws, sha, SAFO_MODE="status", SAFO_STATUS_BODY_FILE="reports/update.md"), outputs)
    assert Path(outputs["status-body-file"]).read_text() == "all good\n"


def test_a_linked_board_file_is_refused_end_to_end(repo: tuple[Path, str]) -> None:
    ws, sha = repo
    with pytest.raises(ConfigError, match="trusted revision"):
        action_preflight.check(full_env(ws, sha, SAFO_BOARD="link.yaml"))
    with pytest.raises(ConfigError, match="trusted revision"):
        action_preflight.check(full_env(ws, sha, SAFO_MODE="status", SAFO_STATUS_BODY_FILE="link.yaml"))


def test_an_unclassified_event_never_reaches_the_file_read_or_the_credential_path(repo: tuple[Path, str]) -> None:
    ws, sha = repo
    outputs: dict[str, str] = {}
    env = full_env(ws, sha, EVENT_NAME=COMMENT)
    with pytest.raises(ConfigError, match="classify"):
        action_preflight.check(env, outputs)
    assert outputs == {}


def test_validate_reads_the_workspace_and_sets_no_credential_output(repo: tuple[Path, str]) -> None:
    ws, sha = repo
    outputs: dict[str, str] = {}
    assert (
        action_preflight.check(
            full_env(ws, sha, SAFO_MODE="validate", EVENT_NAME=COMMENT, HAS_PRIVATE_KEY="false"), outputs
        )
        == ""
    )
    assert "credentials" not in outputs
