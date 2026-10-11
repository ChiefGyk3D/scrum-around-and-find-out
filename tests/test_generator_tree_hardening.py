# SPDX-License-Identifier: MIT
"""Ancestors, stale deletion, work caps and path rules of the output tree (the fix round after the Codex review)."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

import safo.harness_tree as ht
from gendata import scratch, snapshot
from renderdata import verified
from safo.profile_render import render_harness
from test_generator_filesystem import FakeEntry, bounded, run


def deep(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, levels: str = "a/b/c") -> tuple[ModuleType, Path, Path]:
    """The script aimed at repo/<levels>/harness, with the directories above it real and an external tree beside."""
    script, _ = scratch(tmp_path, monkeypatch)
    repo = tmp_path / "repo"
    out = repo / levels / "harness"
    monkeypatch.setattr(script, "OUT", out)
    (repo / levels).mkdir(parents=True)
    external = tmp_path / "external"
    external.mkdir()
    (external / "keep.txt").write_text("outside\n")
    return script, out, external


@pytest.mark.parametrize("level", ["a", "a/b", "a/b/c"])
def test_a_symlinked_ancestor_of_the_output_directory_is_never_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], level: str
) -> None:
    script, _, external = deep(tmp_path, monkeypatch)
    link = tmp_path / "repo" / level
    moved = tmp_path / "moved"
    link.rename(moved)
    link.symlink_to(external)
    before = snapshot(tmp_path)
    for flag in ("--write", "--check"):
        code, err = run(script, flag, capsys)
        assert code == 1 and f"{level}: a symbolic link or not a directory" in err, err
    assert snapshot(tmp_path) == before, "nothing outside was written and nothing was removed"
    assert sorted(p.name for p in external.iterdir()) == ["keep.txt"]


def test_an_ancestor_swapped_for_a_symlink_between_steps_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, _, external = deep(tmp_path, monkeypatch)
    b = tmp_path / "repo" / "a" / "b"

    def swap(stage: str, name: str) -> None:
        if stage == "before-open" and name == "a/b" and not b.is_symlink():
            b.rename(tmp_path / "b-real")
            b.symlink_to(external)

    monkeypatch.setattr(ht, "_seam", swap)
    code, err = run(script, "--write", capsys)
    assert code == 1 and "a/b" in err
    assert sorted(p.name for p in external.iterdir()) == ["keep.txt"]


def test_a_component_replaced_after_it_was_opened_is_caught_by_the_identity_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, _, external = deep(tmp_path, monkeypatch)
    c = tmp_path / "repo" / "a" / "b" / "c"

    def swap(stage: str, name: str) -> None:
        if stage == "after-open" and name == "a/b/c" and not c.is_symlink():
            c.rename(tmp_path / "c-real")
            c.symlink_to(external)

    monkeypatch.setattr(ht, "_seam", swap)
    code, err = run(script, "--write", capsys)
    assert code == 1 and "changed while it was being opened" in err
    assert sorted(p.name for p in external.iterdir()) == ["keep.txt"]


def test_missing_ancestors_are_created_one_directory_at_a_time_without_following(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, _ = scratch(tmp_path, monkeypatch)
    out = tmp_path / "repo" / "x" / "y" / "harness"
    monkeypatch.setattr(script, "OUT", out)
    opened: list[str] = []
    real_mkdir = os.mkdir

    def spy(path: Any, mode: int = 0o777, *, dir_fd: int | None = None) -> None:
        opened.append(f"{path}:{dir_fd is not None}")
        real_mkdir(path, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "mkdir", spy)
    assert run(script, "--write", capsys)[0] == 0
    assert opened and all(entry.endswith(":True") for entry in opened)
    assert opened[:3] == ["x:True", "y:True", "harness:True"], "relative names against descriptors, never a full path"
    assert (out / "codex" / "codex.prompt.md").is_file()


def test_an_output_path_outside_the_root_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, _ = scratch(tmp_path, monkeypatch)
    monkeypatch.setattr(script, "OUT", tmp_path / "elsewhere")
    code, err = run(script, "--write", capsys)
    assert code == 1 and "inside the repository" in err and not (tmp_path / "elsewhere").exists()


# -- stale files ------------------------------------------------------------------------------------------------------


def stale_setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[ModuleType, Path, Path, bytes]:
    script, out = scratch(tmp_path, monkeypatch)
    assert script.main(["--write"]) == 0
    good = (out / "codex" / "codex.prompt.md").read_bytes()
    old = out / "legacy" / "old.prompt.md"
    old.parent.mkdir()
    old.write_bytes(good)
    return script, out, old, good


def test_a_file_with_a_valid_looking_header_and_wrong_digests_is_a_users_file_and_is_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, _, old, good = stale_setup(tmp_path, monkeypatch)
    old.write_bytes(good.replace(b"Prepend", b"My own words"))  # the header is intact, the body no longer matches
    before = snapshot(tmp_path)
    code, err = run(script, "--write", capsys)
    assert code == 1 and "legacy/old.prompt.md: not a generated file" in err
    assert snapshot(tmp_path) == before


def test_a_stale_file_whose_manifest_no_longer_resolves_but_whose_body_digest_holds_is_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out, _, _ = stale_setup(tmp_path, monkeypatch)
    assert run(script, "--write", capsys)[0] == 0 and not (out / "legacy").exists()


@pytest.mark.parametrize("stage", ["before-open", "after-read"])
def test_a_stale_file_swapped_for_another_inode_is_not_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], stage: str
) -> None:
    script, _, old, good = stale_setup(tmp_path, monkeypatch)
    seen: list[str] = []

    def swap(where: str, name: str) -> None:
        if where == f"stale:{stage}" and name == "legacy/old.prompt.md" and not seen:
            seen.append(where)
            replacement = old.parent / "replacement"
            replacement.write_bytes(good)  # a new file, so a new inode
            os.rename(replacement, old)

    monkeypatch.setattr(ht, "_seam", swap)
    code, err = run(script, "--write", capsys)
    assert seen and code == 1 and "legacy/old.prompt.md: changed since the inventory, so it is not removed" in err
    assert old.exists()


def test_a_stale_file_swapped_for_a_symlink_is_not_followed_or_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, _, old, _ = stale_setup(tmp_path, monkeypatch)
    target = tmp_path / "precious.txt"
    target.write_text("precious\n")

    def swap(where: str, name: str) -> None:
        if where == "stale:before-open" and not old.is_symlink():
            old.unlink()
            old.symlink_to(target)

    monkeypatch.setattr(ht, "_seam", swap)
    code, err = run(script, "--write", capsys)
    assert code == 1 and "not removed" in err and old.is_symlink() and target.read_text() == "precious\n"


# -- work caps and path rules -----------------------------------------------------------------------------------------


def test_the_entry_cap_stops_iterating_the_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = tmp_path / "out"
    out.mkdir()
    consumed = 0

    def endless() -> Iterator[FakeEntry]:
        nonlocal consumed
        for i in range(200_000):
            consumed += 1
            yield FakeEntry(f"f{i}", stat.S_IFREG)

    class Scan:
        def __enter__(self) -> Iterator[FakeEntry]:
            return endless()

        def __exit__(self, *_: object) -> None:
            return None

    monkeypatch.setattr(os, "scandir", lambda fd: Scan())
    tree = ht.scan(tmp_path, "out")
    assert consumed <= ht.MAX_ENTRIES + 1
    assert [p for p in tree.problems if "more than" in p] == [
        f"the tree has more than {ht.MAX_ENTRIES} entries; the walk stopped"
    ]


BAD_PATHS = ["/abs.md", "a//b.md", "./x.md", "a/./x.md", "../x.md", "a/../b.md", "a\x00b.md", "", "a/", "x/.."]


@pytest.mark.parametrize("bad", BAD_PATHS)
def test_write_tree_rejects_unsafe_output_paths_whatever_the_renderer_says(tmp_path: Path, bad: str) -> None:
    r = next(iter(render_harness(verified(tmp_path / "v")).values()))
    root = tmp_path / "root"
    root.mkdir()
    problems, changes = ht.write_tree(root, "out", {bad: replace(r, path=bad)})
    assert problems and changes == [] and "not a safe relative path" in problems[0]
    assert list(root.iterdir()) == [] and not (tmp_path / "x").exists()
    assert ht.check_tree(root, "out", {bad: replace(r, path=bad)})


@pytest.mark.parametrize("bad", ["/abs", "../out", "a/./b", "a//b", "", "a\x00"])
def test_write_tree_rejects_an_unsafe_output_directory_name(tmp_path: Path, bad: str) -> None:
    r = next(iter(render_harness(verified(tmp_path / "v")).values()))
    root = tmp_path / "root"
    root.mkdir()
    problems, changes = ht.write_tree(root, bad, {"ok.md": r})
    assert problems and changes == [] and "not a safe relative path" in problems[0]
    assert list(root.iterdir()) == []


def test_a_real_symlink_named_as_a_regular_file_is_not_opened_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The file open carries O_NOFOLLOW: a file at lstat time and a link at open time is a problem."""
    out = tmp_path / "out"
    out.mkdir()
    (tmp_path / "target.txt").write_text("secret\n")
    (out / "link").symlink_to(tmp_path / "target.txt")

    class Scan:
        def __enter__(self) -> list[FakeEntry]:
            return [FakeEntry("link", stat.S_IFREG)]

        def __exit__(self, *_: object) -> None:
            return None

    monkeypatch.setattr(os, "scandir", lambda fd: Scan())
    with bounded():
        tree = ht.scan(tmp_path, "out")
    assert tree.problems == ["link: changed while it was being read, or is not a regular file"] and tree.files == {}


def test_a_fifo_swapped_in_for_a_file_does_not_hang_the_read(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "pipe")
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with bounded(5):
            assert ht._read_file(fd, "pipe") is None
    finally:
        os.close(fd)
