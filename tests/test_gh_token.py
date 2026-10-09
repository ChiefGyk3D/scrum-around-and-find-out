# SPDX-License-Identifier: MIT
"""The command line's token source: the caller's `gh auth token`, through a fake gh on a private PATH."""

from __future__ import annotations

import io
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest

from cliutil import BOARD, run_cli
from fakegh import FakeGitHub
from safo import credentials
from safo.cli import main
from safo.credentials import GH, Credentials
from safo.errors import ConfigError
from world import build_world


def fake_gh(tmp_path: Path, script: str, mode: int = stat.S_IXUSR) -> dict[str, str]:
    """A `gh` that runs the given shell body; returns an env whose PATH is only that directory."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    gh = bin_dir / "gh"
    gh.write_text("#!/bin/sh\n" + script)
    gh.chmod(gh.stat().st_mode | mode)
    return {"PATH": str(bin_dir)}


def test_the_active_accounts_token_is_read_with_a_fixed_argument_list(tmp_path: Path) -> None:
    log = tmp_path / "argv.txt"
    env = fake_gh(tmp_path, f'echo "$@" > {log}\necho gho_FAKE\n')
    assert credentials.from_gh(env) == Credentials("gho_FAKE", GH)
    assert log.read_text().strip() == "auth token --hostname github.com"


def test_a_named_account_is_requested_with_user(tmp_path: Path) -> None:
    log = tmp_path / "argv.txt"
    env = fake_gh(tmp_path, f'echo "$@" > {log}\necho gho_FAKE\n')
    credentials.from_gh(env, "someone")
    assert log.read_text().strip() == "auth token --hostname github.com --user someone"


def test_an_empty_user_means_the_active_account(tmp_path: Path) -> None:
    log = tmp_path / "argv.txt"
    env = fake_gh(tmp_path, f'echo "$@" > {log}\necho gho_FAKE\n')
    credentials.from_gh(env, "")
    assert log.read_text().strip() == "auth token --hostname github.com"


@pytest.mark.parametrize("user", ["-x", "--hostname", "a b", "a;b", "a$(id)", "a\nb", "x" * 100, "a/b", "né"])
def test_a_user_that_is_not_a_login_is_refused_before_gh_runs(tmp_path: Path, user: str) -> None:
    marker = tmp_path / "ran"
    env = fake_gh(tmp_path, f"echo x > {marker}\necho gho_FAKE\n")
    with pytest.raises(ConfigError, match="gh-user"):
        credentials.from_gh(env, user)
    assert not marker.exists()


def test_no_gh_or_a_failing_gh_is_none_and_its_stderr_is_not_repeated(tmp_path: Path) -> None:
    assert credentials.from_gh({"PATH": str(tmp_path / "empty")}) is None
    assert credentials.from_gh({}) is None
    assert credentials.from_gh({"PATH": ""}) is None
    env = fake_gh(tmp_path, "echo 'gho_LEAK not logged in' >&2\nexit 1\n")
    assert credentials.from_gh(env) is None


def test_a_successful_gh_that_prints_nothing_is_none(tmp_path: Path) -> None:
    assert credentials.from_gh(fake_gh(tmp_path, "exit 0\n")) is None
    assert credentials.from_gh(fake_gh(tmp_path, "echo '   '\n")) is None


def test_surrounding_whitespace_is_stripped(tmp_path: Path) -> None:
    assert credentials.from_gh(fake_gh(tmp_path, "printf '  gho_FAKE \\n\\n'\n")) == Credentials("gho_FAKE", GH)


@pytest.mark.parametrize(
    "body",
    [
        "printf 'gho_A\\ngho_B\\n'",  # two lines: not one token
        "printf 'gho_A gho_B\\n'",  # inner space
        "printf 'gho_A\\r\\nX-Evil: 1\\n'",  # header injection
        "printf 'gho_\\001\\n'",  # control byte
        "printf 'gho_%09000d\\n' 0",  # absurdly long
    ],
)
def test_output_that_is_not_one_plain_token_is_none(tmp_path: Path, body: str) -> None:
    assert credentials.from_gh(fake_gh(tmp_path, body + "\n")) is None


def test_a_gh_that_hangs_is_none(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(credentials, "GH_TIMEOUT_SECONDS", 0.3)
    assert credentials.from_gh(fake_gh(tmp_path, "while :; do :; done\n")) is None


def test_gh_is_not_given_the_terminal_to_ask_on(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}
    real = subprocess.run

    def spy(argv: list[str], **kwargs: Any) -> Any:
        seen.update(kwargs)
        return real(argv, **kwargs)

    monkeypatch.setattr(subprocess, "run", spy)
    credentials.from_gh(fake_gh(tmp_path, "echo gho_FAKE\n"))
    assert seen["stdin"] is subprocess.DEVNULL and seen.get("shell") is not True


def test_a_gh_that_cannot_be_executed_is_none(tmp_path: Path) -> None:
    assert credentials.from_gh(fake_gh(tmp_path, "echo gho_FAKE\n", mode=0)) is None
    (tmp_path / "dirbin" / "gh").mkdir(parents=True)
    assert credentials.from_gh({"PATH": str(tmp_path / "dirbin")}) is None


def test_a_relative_path_entry_never_finds_a_planted_gh(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    marker = tmp_path / "ran"
    fake_gh(tmp_path, f"echo x > {marker}\necho gho_PLANTED\n")
    monkeypatch.chdir(tmp_path)
    for entry in ("bin", ".", ""):
        assert credentials.from_gh({"PATH": entry}) is None
        assert credentials.from_gh({"PATH": f"{entry}:{tmp_path / 'nothing'}"}) is None
    assert not marker.exists()


def test_the_token_is_not_in_what_a_failure_raises_or_prints(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    env = fake_gh(tmp_path, "echo gho_LEAK; echo gho_LEAK >&2; exit 3\n")
    assert credentials.from_gh(env) is None
    seen = capsys.readouterr()
    assert "gho_LEAK" not in seen.out + seen.err


def test_the_cli_falls_back_to_gh_when_no_token_is_set(
    fake: FakeGitHub, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    build_world(fake)
    monkeypatch.setattr("safo.cli.GRAPHQL_URL", fake.url)  # the pinned constant, not the environment, is the seam
    env = fake_gh(tmp_path, f"echo {fake.token}\n")
    code, out, err = run_cli("--board", BOARD, "audit", env=env)
    assert code == 0, out + err
    assert fake.token not in out + err


def test_safo_token_wins_and_gh_is_never_run(fake: FakeGitHub, tmp_path: Path) -> None:
    build_world(fake)
    marker = tmp_path / "ran"
    env = fake_gh(tmp_path, f"echo x > {marker}\necho gho_OTHER\n") | {
        "SAFO_TOKEN": fake.token,
        "SAFO_TOKEN_KIND": "app",
        "GITHUB_GRAPHQL_URL": fake.url,
    }
    code, out, err = run_cli("--board", BOARD, "audit", env=env)
    assert code == 0, out + err
    assert not marker.exists()


def test_a_gh_that_is_not_logged_in_is_the_no_token_message(tmp_path: Path) -> None:
    env = fake_gh(tmp_path, "echo 'gho_LEAK' >&2\nexit 1\n")
    code, _, err = run_cli("--board", BOARD, "audit", env=env)
    assert code == 2 and "gh auth login" in err and "gho_LEAK" not in err


def test_the_gh_user_flag_selects_the_account(
    fake: FakeGitHub, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    build_world(fake)
    monkeypatch.setattr("safo.cli.GRAPHQL_URL", fake.url)
    log = tmp_path / "argv.txt"
    env = fake_gh(tmp_path, f'echo "$@" > {log}\necho {fake.token}\n')
    main(["--board", BOARD, "--gh-user", "work-alt", "audit"], env=env, out=io.StringIO())
    assert log.read_text().strip() == "auth token --hostname github.com --user work-alt"


def test_an_empty_gh_user_flag_is_the_active_account(
    fake: FakeGitHub, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    build_world(fake)
    monkeypatch.setattr("safo.cli.GRAPHQL_URL", fake.url)
    log = tmp_path / "argv.txt"
    env = fake_gh(tmp_path, f'echo "$@" > {log}\necho {fake.token}\n')
    main(["--board", BOARD, "--gh-user", "", "audit"], env=env, out=io.StringIO())
    assert log.read_text().strip() == "auth token --hostname github.com"


def test_the_gh_user_environment_variable_works_like_the_flag(
    fake: FakeGitHub, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    build_world(fake)
    monkeypatch.setattr("safo.cli.GRAPHQL_URL", fake.url)
    log = tmp_path / "argv.txt"
    env = fake_gh(tmp_path, f'echo "$@" > {log}\necho {fake.token}\n') | {
        "SAFO_GH_USER": "from-env",
    }
    main(["--board", BOARD, "audit"], env=env, out=io.StringIO())
    assert log.read_text().strip() == "auth token --hostname github.com --user from-env"


def test_a_hostile_gh_user_flag_is_a_configuration_error_not_a_crash(tmp_path: Path) -> None:
    marker = tmp_path / "ran"
    env = fake_gh(tmp_path, f"echo x > {marker}\necho gho_X\n")
    code, _, err = run_cli("--board", BOARD, "--gh-user=--hostname=evil", "audit", env=env)
    assert code == 2 and "gh-user" in err and not marker.exists()


# -- T9a fix 1 (review findings) ------------------------------------------------------------------------------------


def test_a_gh_token_is_never_sent_to_an_overridden_endpoint(tmp_path: Path) -> None:
    for env_extra in ({}, {"SAFO_TOKEN": "gho_X", "SAFO_TOKEN_KIND": "gh"}):
        env = fake_gh(tmp_path, "echo gho_SENTINEL\n") | {"GITHUB_GRAPHQL_URL": "https://attacker.example/graphql"}
        env |= env_extra
        code, out, err = run_cli("--board", BOARD, "audit", env=env)
        assert code == 2 and "GITHUB_GRAPHQL_URL" in err, out + err
        assert "gho_SENTINEL" not in out + err and "gho_X" not in out + err
        assert "attacker.example" not in out  # nothing was printed as a result


def test_a_gh_token_may_name_the_real_endpoint_explicitly(fake: FakeGitHub, tmp_path: Path) -> None:
    from safo.cli import default_client
    from safo.graphql import GRAPHQL_URL
    from safo.schema import load_board

    env = fake_gh(tmp_path, "echo gho_FAKE\n") | {"GITHUB_GRAPHQL_URL": GRAPHQL_URL}
    assert default_client(load_board(BOARD), env, True) is not None


def test_gh_is_asked_for_github_com_only_and_ambient_token_variables_are_dropped(tmp_path: Path) -> None:
    log = tmp_path / "seen.txt"
    body = (
        f'echo "$@" > {log}\n'
        f'echo "GH_HOST=${{GH_HOST-unset}} GH_TOKEN=${{GH_TOKEN-unset}} '
        f"GH_ENTERPRISE_TOKEN=${{GH_ENTERPRISE_TOKEN-unset}} "
        f'GITHUB_TOKEN=${{GITHUB_TOKEN-unset}} GITHUB_ENTERPRISE_TOKEN=${{GITHUB_ENTERPRISE_TOKEN-unset}}" >> {log}\n'
        "echo gho_FAKE\n"
    )
    env = fake_gh(tmp_path, body) | {
        "GH_HOST": "ghe.example",
        "GH_TOKEN": "gho_AMBIENT",
        "GH_ENTERPRISE_TOKEN": "gho_E",
        "GITHUB_TOKEN": "gho_G",
        "GITHUB_ENTERPRISE_TOKEN": "gho_GE",
    }
    assert credentials.from_gh(env, "someone") == Credentials("gho_FAKE", GH)
    first, second = log.read_text().splitlines()
    assert first == "auth token --hostname github.com --user someone"
    assert second == (
        "GH_HOST=unset GH_TOKEN=unset GH_ENTERPRISE_TOKEN=unset GITHUB_TOKEN=unset GITHUB_ENTERPRISE_TOKEN=unset"
    )


def test_a_gh_inside_the_working_directory_is_never_run_and_the_next_path_entry_wins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkout = tmp_path / "checkout"
    (checkout / "bin").mkdir(parents=True)
    marker = tmp_path / "ran"
    hostile = checkout / "bin" / "gh"
    hostile.write_text(f"#!/bin/sh\necho x > {marker}\necho gho_HOSTILE\n")
    hostile.chmod(0o755)
    monkeypatch.chdir(checkout)
    assert credentials.from_gh({"PATH": str(checkout / "bin")}) is None
    assert not marker.exists()
    good = fake_gh(tmp_path / "good", "echo gho_GOOD\n")["PATH"]
    assert credentials.from_gh({"PATH": f"{checkout / 'bin'}:{good}"}) == Credentials("gho_GOOD", GH)
    assert not marker.exists()


def test_a_gh_inside_the_workspace_or_the_repository_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws = tmp_path / "ws"
    (ws / "tools").mkdir(parents=True)
    gh = ws / "tools" / "gh"
    gh.write_text("#!/bin/sh\necho gho_HOSTILE\n")
    gh.chmod(0o755)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    path = str(ws / "tools")
    assert credentials.from_gh({"PATH": path, "GITHUB_WORKSPACE": str(ws)}) is None
    assert credentials.find_gh({"PATH": path}) == str(gh)  # control: without the workspace it is found
    assert credentials.find_gh({"PATH": path}, repo=ws) is None


def test_a_symlink_into_the_working_directory_is_resolved_and_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    target = checkout / "evil"
    target.write_text("#!/bin/sh\necho gho_HOSTILE\n")
    target.chmod(0o755)
    link_dir = tmp_path / "links"
    link_dir.mkdir()
    (link_dir / "gh").symlink_to(target)
    monkeypatch.chdir(checkout)
    assert credentials.find_gh({"PATH": str(link_dir)}) is None


def test_gh_is_not_a_credential_source_under_github_actions(tmp_path: Path) -> None:
    marker = tmp_path / "ran"
    env = fake_gh(tmp_path, f"echo x > {marker}\necho gho_FAKE\n") | {"GITHUB_ACTIONS": "true"}
    assert credentials.from_gh(env) is None and not marker.exists()
    assert credentials.from_gh(env | {"GITHUB_ACTIONS": "false"}) == Credentials("gho_FAKE", GH)
