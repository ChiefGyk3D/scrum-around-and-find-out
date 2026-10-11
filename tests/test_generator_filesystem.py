# SPDX-License-Identifier: MIT
"""The generator's filesystem rules (spec 2.6, 8.15): non-following inventory, exact path sets, no-follow writes."""

from __future__ import annotations

import os
import signal
import socket
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType

import pytest

import safo.harness_tree as ht
from gendata import scratch, snapshot
from safo.errors import SafoError

Hostile = Callable[[Path], Path]


@contextmanager
def bounded(seconds: int = 60) -> Iterator[None]:
    """A generous alarm around the one call that could hang if a FIFO were opened for reading."""

    def boom(*_: object) -> None:
        raise TimeoutError("the generator hung")

    old = signal.signal(signal.SIGALRM, boom)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def run(script: ModuleType, flag: str, capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    capsys.readouterr()
    with bounded():
        code = script.main([flag])
    return code, capsys.readouterr().err


def good(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[ModuleType, Path]:
    script, out = scratch(tmp_path, monkeypatch)
    assert script.main(["--write"]) == 0
    return script, out


def make_symlink(out: Path) -> Path:
    target = out.parent / "elsewhere.txt"
    target.write_text("outside\n")
    link = out / "claude" / "link.md"
    link.symlink_to(target)
    return link


def make_dir_symlink(out: Path) -> Path:
    elsewhere = out.parent / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "x.md").write_text("outside\n")
    link = out / "linkdir"
    link.symlink_to(elsewhere)
    return link


def make_fifo(out: Path) -> Path:
    path = out / "claude" / "pipe.md"
    os.mkfifo(path)
    return path


def make_socket(out: Path) -> Path:
    path = out / "codex" / "sock"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(path))
    s.close()
    return path


def make_oversize(out: Path) -> Path:
    path = out / "claude" / "big.md"
    path.write_bytes(b"x" * (64 * 1024 + 1))
    return path


def make_dir_for_file(out: Path) -> Path:
    path = out / "codex" / "codex.prompt.md"
    path.unlink()
    path.mkdir()
    return path


def make_symlinked_expected_file(out: Path) -> Path:
    path = out / "codex" / "codex.prompt.md"
    other = out.parent / "target.md"
    other.write_text("precious\n")
    path.unlink()
    path.symlink_to(other)
    return path


HOSTILE: dict[str, Hostile] = {
    "symlink": make_symlink,
    "directory symlink": make_dir_symlink,
    "fifo": make_fifo,
    "socket": make_socket,
    "oversize": make_oversize,
    "directory where a file belongs": make_dir_for_file,
    "symlink where a file belongs": make_symlinked_expected_file,
}


@pytest.mark.parametrize("kind", HOSTILE)
def test_check_reports_a_hostile_entry_as_an_error_without_hanging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], kind: str
) -> None:
    script, out = good(tmp_path, monkeypatch)
    entry = HOSTILE[kind](out)
    code, err = run(script, "--check", capsys)
    assert code == 1 and err.startswith("error:"), err
    assert str(entry.relative_to(out)) in err


@pytest.mark.parametrize("kind", HOSTILE)
def test_write_refuses_a_hostile_entry_and_changes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], kind: str
) -> None:
    script, out = good(tmp_path, monkeypatch)
    entry = HOSTILE[kind](out)
    # make the tree differ from the render too, so a write would have something to do
    (out / "local" / "ollama.wrapper.txt").write_text("edited\n")
    before = snapshot(tmp_path)
    code, err = run(script, "--write", capsys)
    assert code == 1 and str(entry.relative_to(out)) in err, err
    assert snapshot(tmp_path) == before, "a refused write leaves every byte and every link as it was"


def test_a_symlink_at_an_output_path_is_never_written_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = good(tmp_path, monkeypatch)
    link = make_symlinked_expected_file(out)
    code, _ = run(script, "--write", capsys)
    assert code == 1 and link.is_symlink()
    assert (out.parent / "target.md").read_text() == "precious\n"


def test_out_itself_being_a_symlink_is_an_error_for_check_and_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = good(tmp_path, monkeypatch)
    real = out.parent / "real-harness"
    out.rename(real)
    out.symlink_to(real)
    before = snapshot(tmp_path)
    for flag in ("--check", "--write"):
        code, err = run(script, flag, capsys)
        assert code == 1 and "symbolic link" in err
    assert snapshot(tmp_path) == before and out.is_symlink()


def test_a_file_where_a_directory_belongs_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = scratch(tmp_path, monkeypatch)
    out.mkdir(parents=True)
    (out / "claude").write_text("not a directory\n")  # no generated header: it is not ours to remove
    before = snapshot(tmp_path)
    code, err = run(script, "--check", capsys)
    assert code == 1 and "claude" in err
    code, err = run(script, "--write", capsys)
    assert code == 1 and "claude" in err
    assert snapshot(tmp_path) == before


def test_a_generated_file_where_a_directory_belongs_is_replaced_because_it_is_a_stale_generated_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = good(tmp_path, monkeypatch)
    (out / "local" / "ollama.wrapper.txt").unlink()
    (out / "local").rmdir()
    (out / "local").write_bytes((out / "codex" / "codex.prompt.md").read_bytes())
    assert run(script, "--write", capsys)[0] == 0
    assert (out / "local" / "ollama.wrapper.txt").is_file()
    assert run(script, "--check", capsys)[0] == 0


def test_a_stale_file_without_the_header_is_not_removed_and_blocks_the_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = good(tmp_path, monkeypatch)
    mine = out / "claude" / "notes.md"
    mine.write_text("# my notes\n")
    (out / "local" / "ollama.wrapper.txt").write_text("edited\n")
    before = snapshot(tmp_path)
    code, err = run(script, "--write", capsys)
    assert code == 1 and "claude/notes.md" in err and "generated header" in err
    assert snapshot(tmp_path) == before and mine.read_text() == "# my notes\n"


def test_a_stale_file_that_only_mentions_the_header_text_is_not_a_generated_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = good(tmp_path, monkeypatch)
    notes = out / "claude" / "notes.md"
    notes.write_text("# notes\n\nThe header says GENERATED by scripts/gen_profiles.py from agents.yaml; do not edit.\n")
    assert run(script, "--write", capsys)[0] == 1 and notes.exists()


def test_a_non_empty_unexpected_directory_is_refused_and_left_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = good(tmp_path, monkeypatch)
    keep = out / "unexpected" / "inner" / "mine.txt"
    keep.parent.mkdir(parents=True)
    keep.write_text("mine\n")
    before = snapshot(tmp_path)
    code, err = run(script, "--write", capsys)
    assert code == 1 and "unexpected/inner/mine.txt" in err
    assert snapshot(tmp_path) == before


def test_a_stale_generated_file_inside_an_unexpected_directory_is_removed_with_the_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = good(tmp_path, monkeypatch)
    old = out / "gone" / "a" / "b.prompt.md"
    old.parent.mkdir(parents=True)
    old.write_bytes((out / "codex" / "codex.prompt.md").read_bytes())
    assert run(script, "--write", capsys)[0] == 0
    assert not (out / "gone").exists()


def test_an_empty_unexpected_directory_is_an_error_for_check_and_is_removed_by_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = good(tmp_path, monkeypatch)
    (out / "hollow").mkdir()
    code, err = run(script, "--check", capsys)
    assert code == 1 and "hollow" in err and "unexpected" in err
    assert run(script, "--write", capsys)[0] == 0 and not (out / "hollow").exists()


def test_write_creates_a_missing_output_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = scratch(tmp_path, monkeypatch)
    assert not out.exists()
    code, err = run(script, "--check", capsys)
    assert code == 1 and "missing" in err
    assert run(script, "--write", capsys)[0] == 0 and out.is_dir()


def test_files_are_written_without_group_or_world_write_and_leave_no_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, out = good(tmp_path, monkeypatch)
    for p in out.rglob("*"):
        mode = p.stat().st_mode & 0o777
        assert mode & 0o022 == 0, (p, oct(mode))
    assert not [p for p in out.rglob("*") if p.name.endswith(".tmp")]


def test_a_failed_write_removes_its_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = scratch(tmp_path, monkeypatch)

    def boom(fd: int) -> None:
        raise OSError(5, "disk on fire")

    monkeypatch.setattr(os, "fsync", boom)
    code, err = run(script, "--write", capsys)
    assert code == 1 and "disk on fire" in err
    assert not [p for p in out.rglob("*") if p.is_file()], "no temporary file and no half-written output stays behind"


def test_the_walk_is_bounded_in_depth_and_entries(tmp_path: Path) -> None:
    out = tmp_path / "out"
    deep = out
    for i in range(ht.MAX_DEPTH + 2):
        deep = deep / f"d{i}"
    deep.mkdir(parents=True)
    tree = ht.scan(out)
    assert any("deeper than" in p for p in tree.problems)
    wide = tmp_path / "wide"
    wide.mkdir()
    for i in range(ht.MAX_ENTRIES + 1):
        (wide / f"f{i}").write_text("x")
    assert any("more than" in p for p in ht.scan(wide).problems)


def test_a_scan_of_a_missing_tree_is_empty_and_of_a_file_is_a_problem(tmp_path: Path) -> None:
    assert ht.scan(tmp_path / "absent").problems == []
    plain = tmp_path / "plain"
    plain.write_text("x")
    assert ht.scan(plain).problems and isinstance(ht.TreeError("x"), SafoError)
