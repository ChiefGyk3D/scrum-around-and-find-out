# SPDX-License-Identifier: MIT
"""Spec test 17: the policy for local private files that carry a profile (7.2), separate from guardlog.trusted_dir."""

from __future__ import annotations

import os
import signal
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from profiledata import doc, write
from safo import trust
from safo.agentsfile import load_agents, load_agents_merged
from safo.errors import ConfigError
from safo.trust import read_trusted_regular_file, trusted_regular_file


@pytest.fixture(autouse=True)
def _alarm() -> Iterator[None]:
    def boom(signum: int, frame: Any) -> None:
        raise TimeoutError("opened a FIFO and waited")

    old = signal.signal(signal.SIGALRM, boom)
    signal.alarm(5)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


@pytest.fixture
def safe(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    path = home / "agents.yaml"
    path.write_text("version: 1\n")
    path.chmod(0o600)
    return path


def test_a_private_file_in_private_directories_is_trusted(safe: Path) -> None:
    trusted_regular_file(safe)
    assert read_trusted_regular_file(safe, 1024) == b"version: 1\n"


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o400, 0o600, 0o755])
def test_owner_only_write_is_enough(safe: Path, mode: int) -> None:
    safe.chmod(mode)
    trusted_regular_file(safe)


@pytest.mark.parametrize("mode", [0o660, 0o620, 0o666, 0o602, 0o664])
def test_a_group_or_world_writable_file_is_refused(safe: Path, mode: int) -> None:
    safe.chmod(mode)
    with pytest.raises(ConfigError, match="writable by its group or by others"):
        trusted_regular_file(safe)
    with pytest.raises(ConfigError, match="writable by its group or by others"):
        read_trusted_regular_file(safe, 1024)


def test_a_symlinked_file_is_refused(safe: Path) -> None:
    link = safe.parent / "link.yaml"
    link.symlink_to(safe)
    with pytest.raises(ConfigError, match=r"symbolic link|cannot be opened"):
        trusted_regular_file(link)


def test_a_symlinked_parent_is_refused(safe: Path, tmp_path: Path) -> None:
    alias = tmp_path / "alias"
    alias.symlink_to(safe.parent)
    with pytest.raises(ConfigError, match=r"symbolic link|cannot be opened"):
        trusted_regular_file(alias / "agents.yaml")


def test_a_symlinked_grandparent_is_refused(safe: Path, tmp_path: Path) -> None:
    (safe.parent / "deep").mkdir(mode=0o700)
    target = safe.parent / "deep" / "agents.yaml"
    target.write_text("x")
    target.chmod(0o600)
    alias = tmp_path / "alias"
    alias.symlink_to(safe.parent)
    with pytest.raises(ConfigError):
        trusted_regular_file(alias / "deep" / "agents.yaml")


def test_a_fifo_is_refused_without_hanging(safe: Path) -> None:
    fifo = safe.parent / "fifo"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(ConfigError, match="not a regular file"):
        trusted_regular_file(fifo)


def test_the_root_itself_and_a_file_directly_under_it_are_judged_not_waved_through(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not a regular file"):
        trusted_regular_file(Path("/"))
    with pytest.raises(ConfigError, match="cannot be opened"):
        trusted_regular_file(Path("/no-such-file-directly-under-root"))


def test_a_directory_and_a_missing_path_are_typed_errors(safe: Path) -> None:
    with pytest.raises(ConfigError, match="not a regular file"):
        trusted_regular_file(safe.parent)
    with pytest.raises(ConfigError, match="cannot be opened"):
        trusted_regular_file(safe.parent / "absent.yaml")


def test_a_file_owned_by_someone_else_is_refused(safe: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(trust, "effective_uid", lambda: os.geteuid() + 12345)
    with pytest.raises(ConfigError, match="not owned by this user"):
        trusted_regular_file(safe)


def test_a_file_owned_by_root_is_refused_for_an_ordinary_user(safe: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real = os.fstat

    def as_root(fd: int) -> os.stat_result:
        info = real(fd)
        if stat.S_ISREG(info.st_mode):
            fields = list(info)
            fields[4] = 0
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(os, "fstat", as_root)
    with pytest.raises(ConfigError, match="not owned by this user"):
        trusted_regular_file(safe)


def test_a_world_writable_parent_without_the_sticky_bit_is_refused(safe: Path) -> None:
    safe.parent.chmod(0o777)
    try:
        with pytest.raises(ConfigError, match=r"directory .* writable by its group or by others"):
            trusted_regular_file(safe)
    finally:
        safe.parent.chmod(0o700)


def test_a_group_writable_parent_is_refused(safe: Path) -> None:
    safe.parent.chmod(0o770)
    try:
        with pytest.raises(ConfigError, match=r"directory .* writable by its group or by others"):
            trusted_regular_file(safe)
    finally:
        safe.parent.chmod(0o700)


def test_a_sticky_world_writable_parent_owned_by_the_user_is_still_refused(safe: Path) -> None:
    # only a root-owned sticky directory (like /tmp) is tolerated
    safe.parent.chmod(0o1777)
    try:
        with pytest.raises(ConfigError, match=r"directory .* writable by its group or by others"):
            trusted_regular_file(safe)
    finally:
        safe.parent.chmod(0o700)


def test_a_parent_owned_by_another_user_is_refused(safe: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real = os.fstat
    seen: list[int] = []

    def parent_owner(fd: int) -> os.stat_result:
        info = real(fd)
        if stat.S_ISDIR(info.st_mode) and info.st_ino == os.stat(safe.parent).st_ino:
            seen.append(fd)
            fields = list(info)
            fields[4] = os.geteuid() + 777
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(os, "fstat", parent_owner)
    with pytest.raises(ConfigError, match=r"directory .* not owned by this user or root"):
        trusted_regular_file(safe)
    assert seen


def test_the_errors_do_not_echo_the_path(safe: Path) -> None:
    safe.chmod(0o666)
    with pytest.raises(ConfigError) as caught:
        trusted_regular_file(safe)
    assert str(safe.parent) not in str(caught.value)


def test_a_relative_path_is_judged_by_its_absolute_form(safe: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(safe.parent)
    trusted_regular_file(Path("agents.yaml"))
    safe.chmod(0o666)
    with pytest.raises(ConfigError):
        trusted_regular_file(Path("agents.yaml"))


def test_read_is_bounded(safe: Path) -> None:
    safe.write_bytes(b"x" * 100)
    safe.chmod(0o600)
    assert read_trusted_regular_file(safe, 100) == b"x" * 100
    with pytest.raises(ConfigError, match="larger than 99 bytes"):
        read_trusted_regular_file(safe, 99)


# -- where it applies --------------------------------------------------------------------------------------


def test_the_local_path_applies_it_to_a_profile_bearing_file_and_the_repository_path_does_not(tmp_path: Path) -> None:
    path = write(tmp_path / "private" / "agents.yaml", doc(), mode=0o664)
    (tmp_path / "private").chmod(0o700)
    assert load_agents(path).agent("codex").profile is not None  # repository generation: review is the control
    with pytest.raises(ConfigError, match="writable by its group or by others"):
        load_agents_merged(path, None)
    path.chmod(0o600)
    assert load_agents_merged(path, None).agent("codex").profile is not None


def test_a_profile_less_file_is_loaded_as_before_even_when_group_writable(tmp_path: Path) -> None:
    d = doc()
    for agent in d["agents"].values():
        agent.pop("profile", None)
    del d["profile_migration"]
    path = write(tmp_path / "private" / "agents.yaml", d, mode=0o664)
    assert load_agents_merged(path, None).agent("codex").profile is None


def test_a_profile_bearing_symlinked_agents_file_is_refused_on_the_local_path(tmp_path: Path) -> None:
    real = write(tmp_path / "private" / "real.yaml", doc())
    link = tmp_path / "private" / "agents.yaml"
    link.symlink_to(real)
    with pytest.raises(ConfigError):
        load_agents_merged(link, None)


def test_the_trust_check_judges_the_file_that_was_parsed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = write(tmp_path / "private" / "agents.yaml", doc())
    calls: list[Path] = []
    real = trust.read_trusted_regular_file

    def spy(p: Path, limit: int) -> bytes:
        calls.append(p)
        return real(p, limit)

    monkeypatch.setattr("safo.agentsfile.read_trusted_regular_file", spy)
    load_agents_merged(path, None)
    assert calls == [path]
