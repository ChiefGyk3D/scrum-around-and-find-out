# SPDX-License-Identifier: MIT
"""SAFO's own directories: made private, and not trusted when another user could have changed them.

A lock is a pathname's current inode, so a directory another user can write to lets them unlink a held lock and make
a second one; the mode, probe and log files are replaced the same way. The hooks therefore refuse a state or config
directory that is not owned by the effective user or is group/world-writable, and say so (a visible degraded allow).
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from hooksdata import agents_file, dispatch, hooks, read_log, set_mode, set_probe, state_folder
from safo import guardlog
from safo.guardlog import WARNING, file_lock, write_text


def mode_of(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def guard(home: Path, payload: str | None = None) -> tuple[int, str, str]:
    agents = agents_file(home.parent / "agents-dirs.yaml")
    return hooks("guard", "--agents", str(agents), home=home, stdin=payload or dispatch(model="sonnet"))


def test_the_state_and_config_directories_are_made_private_whatever_the_umask(
    _private_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    os.umask(0)
    assert guard(_private_home)[0] == 0
    assert mode_of(state_folder(_private_home)) == 0o700, "the folder the log and locks live in"
    assert mode_of(state_folder(_private_home).parent) == 0o700
    assert hooks("mode", "block", home=_private_home)[0] == 0
    assert mode_of(_private_home / ".config" / "safo") == 0o700
    assert (_private_home / ".config" / "safo" / "mode").read_text() == "block\n"


@pytest.mark.parametrize("bad", [0o775, 0o757, 0o777, 0o770])
def test_a_group_or_world_writable_state_folder_degrades_the_guard_visibly_and_is_not_used(
    _private_home: Path, bad: int
) -> None:
    set_probe(_private_home, reachable=True)
    state_folder(_private_home).chmod(bad)
    code, out, _ = guard(_private_home)
    data = json.loads(out)
    assert code == 0 and WARNING in data["systemMessage"]
    assert not (state_folder(_private_home) / "log.jsonl").exists(), "nothing is written into an untrusted folder"
    assert not list(state_folder(_private_home).glob("*.lock")), "no lock is made there either"
    assert '"log-write"' in data["hookSpecificOutput"]["additionalContext"]


def test_an_untrusted_state_folder_is_not_read_for_the_probe_state_or_the_log(_private_home: Path) -> None:
    set_probe(_private_home, reachable=True)
    assert guard(_private_home, dispatch(model="sonnet", prompt="no local step named"))[0] == 0
    assert read_log(_private_home)[0]["rules"] == ["no-local-step"], "while trusted, the saved probe state is used"
    state_folder(_private_home).chmod(0o777)
    # The reachable probe saved there is ignored: the local-step rule is off (state unknown), not applied from it.
    out = guard(_private_home, dispatch(model="sonnet", prompt="no local step named"))[1]
    assert "no local step" not in out, "the rule is off, not applied from the untrusted folder's saved state"
    assert guardlog.read_log(state_folder(_private_home) / "log.jsonl") == []
    status = hooks("status", home=_private_home)[1]
    assert "health: degraded" in status or "no dispatches logged yet" in status


@pytest.mark.parametrize("bad", [0o775, 0o777])
def test_an_untrusted_config_folder_means_the_mode_file_is_not_trusted_and_the_guard_warns_instead_of_blocking(
    _private_home: Path, bad: int
) -> None:
    set_mode(_private_home, "block")
    set_probe(_private_home, reachable=False)
    (_private_home / ".config" / "safo").chmod(bad)
    assert guardlog.mode_health({"HOME": str(_private_home)}) == ("warn", "degraded")
    agents = agents_file(_private_home.parent / "agents-dirs2.yaml")
    code, out, _ = hooks("guard", "--agents", str(agents), home=_private_home, stdin=dispatch(model="opus"))
    data = json.loads(out)
    assert code == 0 and WARNING in data["systemMessage"]
    assert "permissionDecision" not in data["hookSpecificOutput"], "warn mode, because the block setting is not trusted"
    assert read_log(_private_home)[-1]["health"] == "degraded"


def test_a_folder_the_effective_user_does_not_own_is_not_trusted(
    _private_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_probe(_private_home)
    set_mode(_private_home, "block")
    assert guardlog.mode_health({"HOME": str(_private_home)}) == ("block", "healthy")
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(_private_home).st_uid + 1)
    assert guardlog.mode_health({"HOME": str(_private_home)}) == ("warn", "degraded")
    code, out, _ = guard(_private_home)
    assert code == 0 and WARNING in json.loads(out)["systemMessage"]
    assert len(read_log(_private_home)) == 0, "nothing was appended to a folder somebody else owns"


def test_the_lock_and_the_writer_refuse_an_untrusted_folder_and_accept_a_private_one(tmp_path: Path) -> None:
    folder = tmp_path / "work"
    folder.mkdir()
    folder.chmod(0o700)
    with file_lock(folder / "x.lock"):
        pass
    write_text(folder / "x.txt", "ok")
    folder.chmod(0o770)
    with pytest.raises(PermissionError), file_lock(folder / "y.lock"):
        pass
    with pytest.raises(PermissionError):
        write_text(folder / "y.txt", "no")
    assert not (folder / "y.lock").exists() and not (folder / "y.txt").exists()


def test_a_lock_in_a_folder_the_caller_opts_out_of_checking_still_works(tmp_path: Path) -> None:
    folder = tmp_path / "shared"
    folder.mkdir()
    folder.chmod(0o777)
    with file_lock(folder / "z.lock", check_dir=False):
        pass


def test_the_installer_still_works_in_a_shared_folder_such_as_a_temporary_directory(tmp_path: Path) -> None:
    """The settings file's folder is the user's choice (the docs suggest /tmp); only SAFO's own folders are checked."""
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    settings = shared / "try.json"
    assert hooks("install", "--settings", str(settings), home=tmp_path)[0] == 0
    assert "safo hooks guard" in settings.read_text()
