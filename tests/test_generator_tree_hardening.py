# SPDX-License-Identifier: MIT
"""Ancestors, stale deletion, work caps and path rules of the output tree (the fix round after the Codex review)."""

from __future__ import annotations

import ast
import os
import shutil
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


# -- nothing is ever deleted -----------------------------------------------------------------------------------------


def test_write_deletes_nothing_and_reports_every_entry_that_is_not_in_the_render(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = scratch(tmp_path, monkeypatch)
    assert script.main(["--write"]) == 0
    good = (out / "codex" / "codex.prompt.md").read_bytes()
    precious = out / "claude" / "notes.md"
    precious.write_text("my own notes\n")
    forged = out / "legacy" / "forged.prompt.md"
    forged.parent.mkdir()
    forged.write_bytes(good.replace(b"Prepend", b"My own words"))  # a valid-looking header over different text
    stale = out / "legacy" / "old.prompt.md"
    stale.write_bytes(good)  # a real generated file at a retired path
    hollow = out / "hollow"
    hollow.mkdir()
    (out / "local" / "ollama.wrapper.txt").write_text("edited\n")
    keep = snapshot(tmp_path)
    keep = {k: v for k, v in keep.items() if "ollama.wrapper.txt" not in k}
    code, err = run(script, "--write", capsys)
    assert code == 1
    assert "claude/notes.md: unexpected file (not a generated file)" in err
    assert "legacy/forged.prompt.md: unexpected file (not a generated file)" in err
    assert "legacy/old.prompt.md: unexpected file (looks generated but is not expected)" in err
    assert "hollow: unexpected directory" in err and "legacy: unexpected directory" in err
    for hint in (
        "git rm -- examples/harness/claude/notes.md",
        "git rm -r -- examples/harness/legacy",
        "rmdir -- examples/harness/hollow",
    ):
        assert hint in err
    after = snapshot(tmp_path)
    assert all(after.get(k) == v for k, v in keep.items()), "every unexpected entry survived byte for byte"
    assert (out / "local" / "ollama.wrapper.txt").read_bytes() != b"edited\n", "the expected files were still written"
    # once the owner removes them (as `git rm` would), the run is clean
    precious.unlink()
    shutil.rmtree(out / "legacy")
    hollow.rmdir()
    assert script.main(["--write"]) == 0 and script.main(["--check"]) == 0


def test_the_generator_has_no_way_to_delete() -> None:
    """The module has no call that removes a file or directory, except the writer's own temporary file."""
    tree = ast.parse(Path(ht.__file__).read_text())
    removers = {"unlink", "rmdir", "remove", "removedirs", "rmtree", "rename", "replace"}
    found = []
    for func in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        for call in [n for n in ast.walk(func) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)]:
            if isinstance(call.func, ast.Attribute) and call.func.attr in removers:
                found.append((func.name, call.func.attr))
    assert sorted(set(found)) == [("_write_file", "rename"), ("_write_file", "unlink")], found


def test_a_failed_write_still_unlinks_only_its_own_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = scratch(tmp_path, monkeypatch)
    assert script.main(["--write"]) == 0
    mine = out / "codex" / "keep.md"
    mine.write_text("mine\n")
    monkeypatch.setattr(os, "write", lambda fd, data: (_ for _ in ()).throw(OSError(28, "no space left")))
    (out / "local" / "ollama.wrapper.txt").write_text("edited\n")
    assert run(script, "--write", capsys)[0] == 1
    assert mine.read_text() == "mine\n" and not [p for p in out.rglob(".*.tmp")]


# -- the output directory moving during the run -----------------------------------------------------------------------


def test_an_output_directory_moved_outside_the_root_before_the_first_write_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = scratch(tmp_path, monkeypatch)
    away = tmp_path / "away"
    moves: list[str] = []

    def move(stage: str, name: str) -> None:
        if stage == "write" and not moves:
            moves.append(name)
            out.rename(away)

    monkeypatch.setattr(ht, "_seam", move)
    out.mkdir(parents=True)
    code, err = run(script, "--write", capsys)
    assert moves and code == 1 and "the output directory moved during the run" in err
    assert list(away.rglob("*")) == [], "nothing was written before the move was seen"


def test_an_output_directory_moved_after_some_writes_fails_the_run_and_the_early_files_went_with_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = scratch(tmp_path, monkeypatch)
    away = tmp_path / "away"
    calls: list[str] = []

    def move(stage: str, name: str) -> None:
        if stage == "write":
            calls.append(name)
            if len(calls) == 3:
                out.rename(away)

    monkeypatch.setattr(ht, "_seam", move)
    code, err = run(script, "--write", capsys)
    assert code == 1 and "the output directory moved during the run" in err
    written = sorted(str(p.relative_to(away)) for p in away.rglob("*") if p.is_file())
    assert len(written) == 2 and not out.exists(), "two files landed in the directory that was moved; none after"


def test_an_output_directory_moved_at_the_very_end_is_still_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = scratch(tmp_path, monkeypatch)
    away = tmp_path / "away"

    def move(stage: str, name: str) -> None:
        if stage == "end":
            out.rename(away)

    monkeypatch.setattr(ht, "_seam", move)
    code, err = run(script, "--write", capsys)
    assert code == 1 and "the output directory moved during the run" in err
    assert len([p for p in away.rglob("*") if p.is_file()]) == 6


def test_an_ancestor_replaced_by_a_link_to_the_same_place_during_the_run_is_caught(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = scratch(tmp_path, monkeypatch)
    examples = out.parent
    real = tmp_path / "examples-real"

    def swap(stage: str, name: str) -> None:
        if stage == "end":
            examples.rename(real)
            examples.symlink_to(real)

    monkeypatch.setattr(ht, "_seam", swap)
    code, err = run(script, "--write", capsys)
    assert code == 1 and "the output directory moved during the run" in err


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


# -- survivors of the sweep over the fix round -------------------------------------------------------------------------


def test_a_directory_that_vanishes_after_it_was_opened_is_a_changed_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, _, _ = deep(tmp_path, monkeypatch)
    c = tmp_path / "repo" / "a" / "b" / "c"

    def vanish(stage: str, name: str) -> None:
        if stage == "after-open" and name == "a/b/c" and c.exists():
            c.rename(tmp_path / "c-gone")

    monkeypatch.setattr(ht, "_seam", vanish)
    code, err = run(script, "--write", capsys)
    assert code == 1 and "a/b/c: changed while it was being opened" in err


def test_the_root_must_be_an_openable_directory_and_not_a_link(tmp_path: Path) -> None:
    assert "the repository root cannot be opened" in ht.scan(tmp_path / "nope", "out").problems[0]
    real = tmp_path / "real"
    (real / "out").mkdir(parents=True)
    link = tmp_path / "link"
    link.symlink_to(real)
    assert "the repository root cannot be opened" in ht.scan(link, "out").problems[0]
    assert ht.scan(real, "out").problems == [] and ht.scan(real, "out").exists


def test_scanning_never_creates_a_missing_path(tmp_path: Path) -> None:
    assert ht.scan(tmp_path, "x/y/z").problems == [] and not (tmp_path / "x").exists()
    assert ht.check_tree(tmp_path, "x/y/z", {}) == [] and not (tmp_path / "x").exists()


def test_a_directory_that_cannot_be_created_is_an_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(path: Any, mode: int = 0o777, *, dir_fd: int | None = None) -> None:
        raise OSError(13, "Permission denied")

    monkeypatch.setattr(os, "mkdir", refuse)
    with pytest.raises(ht.TreeError, match="x: cannot be created"):
        ht.open_out(tmp_path, "x", True)


def test_no_descriptor_leaks_when_the_path_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real")
    before = len(os.listdir("/proc/self/fd"))
    with pytest.raises(ht.TreeError):
        ht.open_out(tmp_path, "link/out", False)
    with pytest.raises(ht.TreeError):
        ht.open_out(tmp_path / "absent-root", "x", False)
    (tmp_path / "real" / "sub").mkdir()

    def swap(stage: str, name: str) -> None:
        if stage == "after-open" and name == "real/sub":
            (tmp_path / "real" / "sub").rename(tmp_path / "real" / "gone")

    monkeypatch.setattr(ht, "_seam", swap)
    with pytest.raises(ht.TreeError, match="changed while"):
        ht.open_out(tmp_path, "real/sub", False)
    assert len(os.listdir("/proc/self/fd")) == before
