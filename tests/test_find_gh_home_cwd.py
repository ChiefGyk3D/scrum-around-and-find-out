# SPDX-License-Identifier: Apache-2.0
"""The guard's `gh` lookup from a session whose working directory is the home directory (#357).

`find_executable` skips a candidate whose real path is inside the working directory, because a hostile checkout can
put its own `bin` on an absolute PATH. A user's `gh` often lives in `~/.local/bin`, which is inside `$HOME`, so from
`$HOME` itself the guard found no `gh` and said "could not confirm". The home directory is not a checkout: when the
working directory IS `$HOME` (exactly), the guard's lookup does not count it as a checkout root. Everything else, the
default for other callers included, is unchanged.
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from safo.context import LocalContext
from safo.credentials import find_gh


def make_gh(folder: Path) -> Path:
    folder.mkdir(parents=True)
    gh = folder / "gh"
    gh.write_text("#!/bin/sh\n")
    gh.chmod(gh.stat().st_mode | stat.S_IXUSR)
    return gh


def env_for(home: Path, *path: Path) -> dict[str, str]:
    return {"HOME": str(home), "PATH": ":".join(str(p) for p in path)}


def test_from_the_home_directory_a_gh_under_home_is_found_when_asked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    gh = make_gh(home / ".local" / "bin")
    monkeypatch.chdir(home)
    env = env_for(home, gh.parent)
    assert find_gh(env, home_ok=True) == str(gh)


def test_the_default_is_unchanged_for_other_callers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    gh = make_gh(home / ".local" / "bin")
    monkeypatch.chdir(home)
    assert find_gh(env_for(home, gh.parent)) is None


def test_a_checkout_below_home_still_cannot_supply_gh(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    checkout = home / "src" / "hostile"
    make_gh(checkout / "bin")
    monkeypatch.chdir(checkout)
    assert find_gh(env_for(home, checkout / "bin"), home_ok=True) is None


def test_another_directory_is_not_taken_for_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    elsewhere = tmp_path / "other"
    gh = make_gh(elsewhere / "bin")
    monkeypatch.chdir(elsewhere)
    assert find_gh(env_for(home, gh.parent), home_ok=True) is None, "cwd is not HOME: the checkout rule applies"


def test_no_home_in_the_environment_changes_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    here = tmp_path / "here"
    gh = make_gh(here / "bin")
    monkeypatch.chdir(here)
    assert find_gh({"PATH": str(gh.parent)}, home_ok=True) is None


def test_the_guards_context_finds_gh_from_the_home_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import datetime as dt
    import io

    home = tmp_path / "home"
    gh = make_gh(home / ".local" / "bin")
    monkeypatch.chdir(home)
    ctx = LocalContext(io.StringIO(), env_for(home, gh.parent), dt.datetime.now(dt.UTC))
    assert ctx.which("gh") == str(gh)
