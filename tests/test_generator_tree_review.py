# SPDX-License-Identifier: MIT
"""Codex review of PR 37: final inventory, file modes, temp-file mode, and the documented rename boundary (spec 2.6)."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Any

import pytest

import safo.harness_tree as ht
from safo.profile_render import Rendered, header_line


def rendered(path: str = "p.txt", body: bytes = b"hello\n") -> Rendered:
    manifest = "0" * 64
    digest = hashlib.sha256(body).hexdigest()
    data = (header_line(path, manifest, digest) + "\n").encode() + body
    return Rendered(path, "x", "x", data, manifest, digest)


def mode_of(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


@pytest.fixture
def repo(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "repo"
    (root / "out").mkdir(parents=True)
    return root, root / "out"


# -- finding 1: a rename of the output directory is an unsupported boundary; the detection still fires --


def test_a_rename_after_the_last_check_is_still_detected_and_reported(
    repo: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Documents the boundary: the post-write re-resolution reports the move, it cannot prevent it (spec 2.6)."""
    root, out = repo
    moved = root.parent / "moved"
    real = ht._reverify
    calls: list[int] = []

    def race(r: Path, rel: str, ident: tuple[int, int]) -> None:
        real(r, rel, ident)
        calls.append(1)
        if len(calls) == 1:
            os.rename(out, moved)

    monkeypatch.setattr(ht, "_reverify", race)
    problems, _ = ht.write_tree(root, "out", {"p.txt": rendered()})
    assert problems == ["the output directory moved during the run"]


# -- finding 2: the final inventory is fresh --


def test_an_unchanged_file_swapped_for_a_symlink_after_the_scan_is_reported(
    repo: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    root, out = repo
    item = rendered()
    (out / "p.txt").write_bytes(item.data)
    os.chmod(out / "p.txt", 0o644)
    target = root.parent / "outside"
    target.write_bytes(b"outside\n")
    real_scan = ht.scan
    n: list[int] = []

    def swap_after_scan(r: Path, rel: str) -> ht.Tree:
        tree = real_scan(r, rel)
        n.append(1)
        if len(n) == 1:
            (out / "p.txt").unlink()
            (out / "p.txt").symlink_to(target)
        return tree

    monkeypatch.setattr(ht, "scan", swap_after_scan)
    problems, _ = ht.write_tree(root, "out", {"p.txt": item})
    assert problems and any("p.txt" in p and "symbolic link" in p for p in problems), problems
    assert target.read_bytes() == b"outside\n"


def test_a_special_entry_added_after_the_scan_is_reported(
    repo: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    root, out = repo
    item = rendered()

    def add_fifo(stage: str, name: str) -> None:
        if stage == "end":
            os.mkfifo(out / "pipe")

    monkeypatch.setattr(ht, "_seam", add_fifo)
    problems, _ = ht.write_tree(root, "out", {"p.txt": item})
    assert any("pipe" in p and "FIFO" in p for p in problems), problems


def test_an_unchanged_file_replaced_by_another_inode_during_the_run_is_reported(
    repo: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    root, out = repo
    keep, change = rendered("keep.txt"), rendered("change.txt", b"new\n")
    (out / "keep.txt").write_bytes(keep.data)
    os.chmod(out / "keep.txt", 0o644)
    (out / "change.txt").write_bytes(b"old\n")

    def replace(stage: str, name: str) -> None:
        if stage == "end":
            (out / "keep.txt.new").write_bytes(keep.data)
            os.chmod(out / "keep.txt.new", 0o644)
            os.replace(out / "keep.txt.new", out / "keep.txt")

    monkeypatch.setattr(ht, "_seam", replace)
    problems, _ = ht.write_tree(root, "out", {"keep.txt": keep, "change.txt": change})
    assert any("keep.txt" in p and "replaced during the run" in p for p in problems), problems


def test_a_clean_run_still_reports_nothing(repo: tuple[Path, Path]) -> None:
    root, _ = repo
    assert ht.write_tree(root, "out", {"p.txt": rendered()}) == ([], ["wrote p.txt"])
    assert ht.write_tree(root, "out", {"p.txt": rendered()}) == ([], [])


# -- finding 3: expected files are mode 0644 -----------------------------------------------------------------------


@pytest.mark.parametrize("bad", [0o600, 0o666, 0o755, 0o664, 0o4644])
def test_an_identical_file_with_another_mode_fails_check_and_is_repaired_by_write(
    repo: tuple[Path, Path], bad: int
) -> None:
    root, out = repo
    item = rendered()
    assert ht.write_tree(root, "out", {"p.txt": item}) == ([], ["wrote p.txt"])
    os.chmod(out / "p.txt", bad)
    problems = ht.check_tree(root, "out", {"p.txt": item})
    assert any("p.txt" in p and "0644" in p for p in problems), problems
    assert ht.write_tree(root, "out", {"p.txt": item}) == ([], ["wrote p.txt"])
    assert mode_of(out / "p.txt") == 0o644
    assert (out / "p.txt").read_bytes() == item.data
    assert ht.check_tree(root, "out", {"p.txt": item}) == []


# -- finding 4: the temporary file is 0600 until the data is synced --


def test_the_temporary_file_is_created_0600_and_made_0644_only_after_the_data_is_synced(
    repo: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _ = repo
    old = os.umask(0o022)
    created: list[int] = []
    events: list[str] = []
    real_open, real_fchmod, real_fsync = os.open, os.fchmod, os.fsync

    def spy_open(path: Any, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        if isinstance(path, str) and path.endswith(".tmp"):
            created.append(mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    def spy_fchmod(fd: int, mode: int) -> None:
        events.append(f"fchmod {stat.S_IMODE(os.fstat(fd).st_mode):04o}->{mode:04o} size={os.fstat(fd).st_size}")
        real_fchmod(fd, mode)

    def spy_fsync(fd: int) -> None:
        if stat.S_ISREG(os.fstat(fd).st_mode):
            events.append(f"fsync {stat.S_IMODE(os.fstat(fd).st_mode):04o}")
        real_fsync(fd)

    monkeypatch.setattr(os, "open", spy_open)
    monkeypatch.setattr(os, "fchmod", spy_fchmod)
    monkeypatch.setattr(os, "fsync", spy_fsync)
    item = rendered()
    try:
        assert ht.write_tree(root, "out", {"p.txt": item}) == ([], ["wrote p.txt"])
    finally:
        os.umask(old)
    assert created == [0o600]
    assert events == ["fsync 0600", f"fchmod 0600->0644 size={len(item.data)}"]
