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
    bin_dir.mkdir(exist_ok=True)
    gh = bin_dir / "gh"
    gh.write_text("#!/bin/sh\n" + script)
    gh.chmod(gh.stat().st_mode | mode)
    return {"PATH": str(bin_dir)}


def test_the_active_accounts_token_is_read_with_a_fixed_argument_list(tmp_path: Path) -> None:
    log = tmp_path / "argv.txt"
    env = fake_gh(tmp_path, f'echo "$@" > {log}\necho gho_FAKE\n')
    assert credentials.from_gh(env) == Credentials("gho_FAKE", GH)
    assert log.read_text().strip() == "auth token"


def test_a_named_account_is_requested_with_user(tmp_path: Path) -> None:
    log = tmp_path / "argv.txt"
    env = fake_gh(tmp_path, f'echo "$@" > {log}\necho gho_FAKE\n')
    credentials.from_gh(env, "someone")
    assert log.read_text().strip() == "auth token --user someone"


def test_an_empty_user_means_the_active_account(tmp_path: Path) -> None:
    log = tmp_path / "argv.txt"
    env = fake_gh(tmp_path, f'echo "$@" > {log}\necho gho_FAKE\n')
    credentials.from_gh(env, "")
    assert log.read_text().strip() == "auth token"


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


def test_the_cli_falls_back_to_gh_when_no_token_is_set(fake: FakeGitHub, tmp_path: Path) -> None:
    build_world(fake)
    env = fake_gh(tmp_path, f"echo {fake.token}\n") | {"GITHUB_GRAPHQL_URL": fake.url}
    code, out, err = run_cli("--board", BOARD, "audit", env=env)
    assert code == 0, out + err
    assert fake.token not in out + err


def test_safo_token_wins_and_gh_is_never_run(fake: FakeGitHub, tmp_path: Path) -> None:
    build_world(fake)
    marker = tmp_path / "ran"
    env = fake_gh(tmp_path, f"echo x > {marker}\necho gho_OTHER\n") | {
        "SAFO_TOKEN": fake.token,
        "SAFO_TOKEN_KIND": "gh",
        "GITHUB_GRAPHQL_URL": fake.url,
    }
    code, out, err = run_cli("--board", BOARD, "audit", env=env)
    assert code == 0, out + err
    assert not marker.exists()


def test_a_gh_that_is_not_logged_in_is_the_no_token_message(tmp_path: Path) -> None:
    env = fake_gh(tmp_path, "echo 'gho_LEAK' >&2\nexit 1\n")
    code, _, err = run_cli("--board", BOARD, "audit", env=env)
    assert code == 2 and "gh auth login" in err and "gho_LEAK" not in err


def test_the_gh_user_flag_selects_the_account(fake: FakeGitHub, tmp_path: Path) -> None:
    build_world(fake)
    log = tmp_path / "argv.txt"
    env = fake_gh(tmp_path, f'echo "$@" > {log}\necho {fake.token}\n') | {"GITHUB_GRAPHQL_URL": fake.url}
    main(["--board", BOARD, "--gh-user", "work-alt", "audit"], env=env, out=io.StringIO())
    assert log.read_text().strip() == "auth token --user work-alt"


def test_an_empty_gh_user_flag_is_the_active_account(fake: FakeGitHub, tmp_path: Path) -> None:
    build_world(fake)
    log = tmp_path / "argv.txt"
    env = fake_gh(tmp_path, f'echo "$@" > {log}\necho {fake.token}\n') | {"GITHUB_GRAPHQL_URL": fake.url}
    main(["--board", BOARD, "--gh-user", "", "audit"], env=env, out=io.StringIO())
    assert log.read_text().strip() == "auth token"


def test_the_gh_user_environment_variable_works_like_the_flag(fake: FakeGitHub, tmp_path: Path) -> None:
    build_world(fake)
    log = tmp_path / "argv.txt"
    env = fake_gh(tmp_path, f'echo "$@" > {log}\necho {fake.token}\n') | {
        "GITHUB_GRAPHQL_URL": fake.url,
        "SAFO_GH_USER": "from-env",
    }
    main(["--board", BOARD, "audit"], env=env, out=io.StringIO())
    assert log.read_text().strip() == "auth token --user from-env"


def test_a_hostile_gh_user_flag_is_a_configuration_error_not_a_crash(tmp_path: Path) -> None:
    marker = tmp_path / "ran"
    env = fake_gh(tmp_path, f"echo x > {marker}\necho gho_X\n")
    code, _, err = run_cli("--board", BOARD, "--gh-user=--hostname=evil", "audit", env=env)
    assert code == 2 and "gh-user" in err and not marker.exists()
