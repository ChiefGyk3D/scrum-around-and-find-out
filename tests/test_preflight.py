# SPDX-License-Identifier: MIT
"""The checks that run before any token is minted: every refusal here costs no request and no secret."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from safo import action_preflight
from safo.errors import ConfigError

ROOT = Path(__file__).parent.parent
BOARD = "tests/data/board.yaml"  # an organization board, relative to the repository root as the workspace is

BASE = {
    "SAFO_MODE": "audit",
    "SAFO_BOARD": BOARD,
    "HAS_PRIVATE_KEY": "true",
    "CLIENT_ID": "Iv23liTEST",
    "GITHUB_REPOSITORY": "acme/widgets",
    "REPOSITORY_OWNER": "acme",
    "REPO_PRIVATE": "true",
    "DRY_RUN": "false",
}


@pytest.fixture(autouse=True)
def _workspace(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(ROOT)


def env(**changes: str) -> dict[str, str]:
    merged = {**BASE, **changes}
    return {k: v for k, v in merged.items() if v != "<unset>"}


def refused(match: str, **changes: str) -> None:
    with pytest.raises(ConfigError, match=match):
        action_preflight.check(env(**changes))


def test_the_baseline_app_audit_passes() -> None:
    action_preflight.check(env())


def test_the_modes_it_knows_are_the_modes_that_exist_plus_validate() -> None:
    from safo.modes import load_all

    assert frozenset(load_all()) | {"validate"} == action_preflight.MODES


@pytest.mark.parametrize("mode", ["", "agents-status", "AUDIT", "audit; id", "sync\n", "route"])
def test_an_unknown_mode_is_refused(mode: str) -> None:
    refused("mode", SAFO_MODE=mode)


@pytest.mark.parametrize("value", ["", "yes", "TRUE ", "1"])
def test_dry_run_is_true_or_false(value: str) -> None:
    refused("dry-run", DRY_RUN=value)


def test_no_credential_is_refused_unless_validating() -> None:
    refused("no credential", HAS_PRIVATE_KEY="false")
    action_preflight.check(env(HAS_PRIVATE_KEY="false", SAFO_MODE="validate"))


def test_a_key_and_a_token_together_are_refused() -> None:
    refused("not both", HAS_TOKEN="true")


def test_a_key_needs_an_app_identifier() -> None:
    refused("client-id", CLIENT_ID="")
    action_preflight.check(env(CLIENT_ID="", APP_ID="123456"))


def test_an_app_id_must_be_a_whole_number() -> None:
    for bad in ("abc", "-1", "1.5", "1e3", "١٢", "99999999999999999999"):
        refused("app-id", CLIENT_ID="", APP_ID=bad)


def test_a_client_id_is_a_short_identifier() -> None:
    for bad in ("a b", "x\ny", "$(id)", "a" * 65, "a;b"):
        refused("client-id", CLIENT_ID=bad)


def test_an_app_for_a_user_board_is_refused_before_minting() -> None:
    refused(
        "cannot write a user-owned project",
        SAFO_BOARD="",
        SAFO_PROJECT_URL="https://github.com/users/me/projects/1",
        SAFO_MODE="sync",
    )


def test_a_token_for_an_organization_board_is_refused_unless_allowed() -> None:
    kw = {"HAS_PRIVATE_KEY": "false", "HAS_TOKEN": "true"}
    refused("refused for an organization-owned project", **kw)
    action_preflight.check(env(**kw, SAFO_ALLOW_TOKEN_FOR_ORG="true"))
    refused("allow-token-for-org", **kw, SAFO_ALLOW_TOKEN_FOR_ORG="yes")


def test_a_token_for_a_user_board_passes() -> None:
    action_preflight.check(
        env(
            HAS_PRIVATE_KEY="false",
            HAS_TOKEN="true",
            SAFO_BOARD="",
            SAFO_PROJECT_URL="https://github.com/users/me/projects/1",
            SAFO_MODE="sync",
        )
    )


# -- the board source ---------------------------------------------------------------------------------------------


def test_one_board_source_is_required_and_only_one() -> None:
    refused("board-file", SAFO_BOARD="")
    refused("not both", SAFO_PROJECT_URL="https://github.com/orgs/acme/projects/1")


@pytest.mark.parametrize("path", ["/etc/passwd", "../board.yaml", "a/../../b.yaml", "a/\x00b", "~/x.yaml", "-x.yaml"])
def test_a_board_file_must_stay_inside_the_workspace(path: str) -> None:
    refused("board-file", SAFO_BOARD=path)


def test_the_board_less_inputs_work_for_sync_and_reconcile_and_not_for_a_structural_mode() -> None:
    kw = {"SAFO_BOARD": "", "SAFO_PROJECT_URL": "https://github.com/orgs/acme/projects/1"}
    for mode in ("sync", "reconcile", "status", "validate"):
        action_preflight.check(env(**kw, SAFO_MODE=mode))
    for mode in ("audit", "bootstrap"):
        refused("needs board-file", **kw, SAFO_MODE=mode)


def test_the_board_less_url_is_validated() -> None:
    refused("project-url", SAFO_BOARD="", SAFO_PROJECT_URL="https://example.org/orgs/acme/projects/1", SAFO_MODE="sync")


@pytest.mark.parametrize("path", ["/etc/passwd", "../x.md", "a/../../x.md", "~/x.md", "-x.md", "a\nb"])
def test_a_status_body_file_must_stay_inside_the_workspace(path: str) -> None:
    refused("status-body-file", SAFO_STATUS_BODY_FILE=path)
    action_preflight.check(env(SAFO_STATUS_BODY_FILE="reports/update.md"))


# -- app-owner: GYST issue 139 -------------------------------------------------------------------------------------


def test_a_foreign_app_owner_needs_a_public_repository() -> None:
    refused("public", APP_OWNER="other-org", REPO_PRIVATE="true")
    refused("public", APP_OWNER="other-org", REPO_PRIVATE="")
    refused("public", APP_OWNER="other-org", REPO_PRIVATE="<unset>")
    refused("public", APP_OWNER="other-org", REPO_PRIVATE="TRUE")
    action_preflight.check(env(APP_OWNER="other-org", REPO_PRIVATE="false"))


def test_the_owner_comparison_ignores_case_and_a_same_owner_needs_no_public_repository() -> None:
    action_preflight.check(env(APP_OWNER="ACME", REPO_PRIVATE="true"))
    action_preflight.check(env(APP_OWNER="acme", REPO_PRIVATE="true"))
    action_preflight.check(env(APP_OWNER="", REPO_PRIVATE="true"))


@pytest.mark.parametrize("owner", ["-x", "x-" + "y" * 40, "a b", "a/b", "a\nb", "a;b", "$(id)", "a_b"])
def test_app_owner_must_be_a_login(owner: str) -> None:
    refused("app-owner", APP_OWNER=owner, REPO_PRIVATE="false")


def test_an_app_owner_is_meaningless_with_a_token() -> None:
    refused(
        "app-owner",
        HAS_PRIVATE_KEY="false",
        HAS_TOKEN="true",
        APP_OWNER="other-org",
        REPO_PRIVATE="false",
        SAFO_ALLOW_TOKEN_FOR_ORG="true",
    )


@pytest.mark.parametrize("repositories", ["a b", "a,,b", "a/b", "..", ".", "a,..", "x;y", "a\nb", ",a"])
def test_the_repository_list_is_names_only(repositories: str) -> None:
    refused("repositories", REPOSITORIES=repositories)


def test_a_repository_list_passes() -> None:
    action_preflight.check(env(REPOSITORIES="widgets, manuals"))


# -- Doppler ------------------------------------------------------------------------------------------------------

IDENTITY = "123e4567-e89b-12d3-a456-426614174000"
DOPPLER = {
    "HAS_PRIVATE_KEY": "false",
    "DOPPLER_IDENTITY_ID": IDENTITY,
    "DOPPLER_PROJECT": "projects",
    "DOPPLER_CONFIG": "prd",
}


def test_the_key_may_come_from_doppler_instead_of_an_input() -> None:
    action_preflight.check(env(**DOPPLER))


def test_doppler_needs_all_three_settings() -> None:
    for drop in ("DOPPLER_PROJECT", "DOPPLER_CONFIG"):
        refused("doppler", **{**DOPPLER, drop: ""})
    refused("doppler", **{**DOPPLER, "DOPPLER_IDENTITY_ID": ""})


def test_a_literal_key_and_doppler_together_are_refused() -> None:
    refused("not both", **{**DOPPLER, "HAS_PRIVATE_KEY": "true"})


@pytest.mark.parametrize(
    "field,bad",
    [
        ("DOPPLER_IDENTITY_ID", "not-a-uuid"),
        ("DOPPLER_IDENTITY_ID", IDENTITY + "x"),
        ("DOPPLER_PROJECT", "a b"),
        ("DOPPLER_PROJECT", "a;b"),
        ("DOPPLER_CONFIG", "$(id)"),
        ("DOPPLER_CONFIG", "x" * 65),
    ],
)
def test_doppler_settings_are_validated(field: str, bad: str) -> None:
    refused("doppler", **{**DOPPLER, field: bad})


def test_doppler_is_not_used_for_a_token() -> None:
    refused("doppler", **{**DOPPLER, "HAS_TOKEN": "true"})


def test_a_fork_pull_request_never_fetches_the_key() -> None:
    refused("fork", **DOPPLER, EVENT_NAME="pull_request", IS_FORK="true")
    action_preflight.check(env(**DOPPLER, EVENT_NAME="pull_request", IS_FORK="false"))


# -- through the shell entry point --------------------------------------------------------------------------------


def run_main(**changes: str) -> subprocess.CompletedProcess[str]:
    full = {
        "PATH": str(Path(sys.executable).parent) + ":/usr/bin:/bin",
        "PYTHONPATH": str(ROOT / "src"),
        **env(**changes),
    }
    return subprocess.run(
        [sys.executable, "-m", "safo.action_preflight"], env=full, capture_output=True, text=True, cwd=ROOT
    )


def test_main_exits_0_clean_and_2_with_one_annotation() -> None:
    ok = run_main()
    assert ok.returncode == 0 and ok.stdout == "" and ok.stderr == ""
    bad = run_main(HAS_PRIVATE_KEY="false")
    assert bad.returncode == 2 and bad.stdout == ""
    assert bad.stderr.startswith("::error title=safo::") and bad.stderr.count("\n") == 1


def test_main_never_echoes_a_hostile_input_as_a_command() -> None:
    bad = run_main(SAFO_MODE="x\n::set-output name=a::b")
    assert bad.returncode == 2
    assert bad.stderr.count("\n") == 1 and "\n::set-output" not in bad.stderr


def test_the_preflight_is_handed_booleans_for_the_key_and_the_token_never_the_values() -> None:
    assert "HAS_PRIVATE_KEY" in action_preflight.READS and "HAS_TOKEN" in action_preflight.READS
    assert not {"PRIVATE_KEY", "TOKEN", "SAFO_TOKEN", "PROJECTS_APP_PRIVATE_KEY"} & set(action_preflight.READS)
