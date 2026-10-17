# SPDX-License-Identifier: MIT
"""The generator's filesystem rules (spec 2.6, 8.15): non-following inventory, exact path sets, no-follow writes."""

from __future__ import annotations

import os
import re
import signal
import socket
import stat
import subprocess
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

import safo.harness_tree as ht
from gendata import scratch, snapshot
from safo.errors import SafoError

Hostile = Callable[[Path], Path]


class Hung(BaseException):
    """Not an Exception: the code under test catches OSError, and a hang must not be swallowed as one."""


def scan_path(path: Path) -> ht.Tree:
    return ht.scan(path.parent, path.name)


@contextmanager
def bounded(seconds: int = 60) -> Iterator[None]:
    """A generous alarm around the one call that could hang if a FIFO were opened for reading."""

    def boom(*_: object) -> None:
        raise Hung("the generator hung")

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
    # AF_UNIX rejects pathnames over ~108 bytes, and a deep TMPDIR blows that budget. Bcwd to the
    # folder and bind the bare name so the test exercises a socket wherever the suite is checked out.
    cwd = os.getcwd()
    try:
        os.chdir(path.parent)
        s.bind(path.name)
    finally:
        os.chdir(cwd)
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


HOSTILE: dict[str, tuple[Hostile, str]] = {
    "symlink": (make_symlink, "a symbolic link"),
    "directory symlink": (make_dir_symlink, "a symbolic link"),
    "fifo": (make_fifo, "a FIFO"),
    "socket": (make_socket, "a socket"),
    "oversize": (make_oversize, "larger than 64 KiB"),
    "directory where a file belongs": (make_dir_for_file, "a directory where a generated file belongs"),
    "symlink where a file belongs": (make_symlinked_expected_file, "a symbolic link"),
}


@pytest.mark.parametrize("kind", HOSTILE)
def test_check_reports_a_hostile_entry_as_an_error_without_hanging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], kind: str
) -> None:
    script, out = good(tmp_path, monkeypatch)
    make, phrase = HOSTILE[kind]
    entry = make(out)
    code, err = run(script, "--check", capsys)
    assert code == 1 and err.startswith("error:"), err
    rel = str(entry.relative_to(out))
    assert f"{rel}: {phrase}" in err, err
    assert f"{rel}: missing" not in err, "an entry that is named for what it is is not also reported as missing"


@pytest.mark.parametrize("kind", HOSTILE)
def test_write_refuses_a_hostile_entry_and_changes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], kind: str
) -> None:
    script, out = good(tmp_path, monkeypatch)
    make, phrase = HOSTILE[kind]
    entry = make(out)
    # make the tree differ from the render too, so a write would have something to do
    (out / "local" / "ollama.wrapper.txt").write_text("edited\n")
    before = snapshot(tmp_path)
    code, err = run(script, "--write", capsys)
    assert code == 1 and f"{entry.relative_to(out)}: {phrase}" in err, err
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
    assert code == 1 and "claude: a file where a directory belongs" in err
    code, err = run(script, "--write", capsys)
    assert code == 1 and "claude: a file where a directory belongs" in err
    assert snapshot(tmp_path) == before


def test_a_generated_file_where_a_directory_belongs_is_not_deleted_either(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = good(tmp_path, monkeypatch)
    (out / "local" / "ollama.wrapper.txt").unlink()
    (out / "local").rmdir()
    (out / "local").write_bytes((out / "codex" / "codex.prompt.md").read_bytes())
    before = snapshot(tmp_path)
    code, err = run(script, "--write", capsys)
    assert code == 1 and "local: a file where a directory belongs" in err
    assert snapshot(tmp_path) == before


def test_a_stale_file_without_the_header_survives_and_is_reported_while_the_expected_files_are_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = good(tmp_path, monkeypatch)
    mine = out / "claude" / "notes.md"
    mine.write_text("# my notes\n")
    (out / "local" / "ollama.wrapper.txt").write_text("edited\n")
    code, err = run(script, "--write", capsys)
    assert code == 1 and "claude/notes.md: unexpected file (not a generated file)" in err
    assert "git rm -- examples/harness/claude/notes.md" in err
    assert mine.read_text() == "# my notes\n"
    assert (out / "local" / "ollama.wrapper.txt").read_text() != "edited\n", "the expected files are still written"


def test_a_stale_file_that_only_mentions_the_header_text_is_not_a_generated_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = good(tmp_path, monkeypatch)
    notes = out / "claude" / "notes.md"
    notes.write_text("# notes\n\nThe header says GENERATED by scripts/gen_profiles.py from agents.yaml; do not edit.\n")
    assert run(script, "--write", capsys)[0] == 1 and notes.exists()


def test_a_non_empty_unexpected_directory_survives_and_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = good(tmp_path, monkeypatch)
    keep = out / "unexpected" / "inner" / "mine.txt"
    keep.parent.mkdir(parents=True)
    keep.write_text("mine\n")
    before = snapshot(tmp_path)
    code, err = run(script, "--write", capsys)
    assert code == 1 and "unexpected/inner/mine.txt: unexpected file" in err
    assert "unexpected: unexpected directory" in err and "git rm -r -- examples/harness/unexpected" in err
    assert snapshot(tmp_path) == before


def test_an_empty_unexpected_directory_is_reported_by_check_and_write_and_never_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = good(tmp_path, monkeypatch)
    (out / "hollow").mkdir()
    code, err = run(script, "--check", capsys)
    assert code == 1 and "hollow" in err and "unexpected" in err
    code, err = run(script, "--write", capsys)
    assert code == 1 and "hollow: unexpected directory" in err and "rmdir -- examples/harness/hollow" in err
    assert (out / "hollow").is_dir()


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
    tree = scan_path(out)
    assert any("deeper than" in p for p in tree.problems)
    wide = tmp_path / "wide"
    wide.mkdir()
    for i in range(ht.MAX_ENTRIES + 1):
        (wide / f"f{i}").write_text("x")
    assert any("more than" in p for p in scan_path(wide).problems)


def test_a_scan_of_a_missing_tree_is_empty_and_of_a_file_is_a_problem(tmp_path: Path) -> None:
    assert scan_path(tmp_path / "absent").problems == []
    plain = tmp_path / "plain"
    plain.write_text("x")
    assert scan_path(plain).problems and isinstance(ht.TreeError("x"), SafoError)


# -- bounds, races and the writer's details --------------------------------------------------------------------------


def open_fds() -> int:
    return len(os.listdir("/proc/self/fd"))


class FakeEntry:
    def __init__(self, name: str, mode: int) -> None:
        self.name = name
        self.mode = mode

    def stat(self, follow_symlinks: bool = True) -> os.stat_result:
        if self.mode == 0:
            raise OSError(5, "gone")
        return os.stat_result((self.mode, 0, 0, 1, 0, 0, 0, 0, 0, 0))


class FakeScan:
    def __init__(self, entries: list[FakeEntry]) -> None:
        self.entries = entries

    def __enter__(self) -> list[FakeEntry]:
        return self.entries

    def __exit__(self, *_: object) -> None:
        return None


def test_a_file_of_exactly_64_kib_is_accepted_and_one_byte_more_is_not(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "exact.md").write_bytes(b"x" * ht.MAX_FILE)
    assert scan_path(out).problems == [] and len(scan_path(out).files["exact.md"]) == ht.MAX_FILE
    (out / "over.md").write_bytes(b"x" * (ht.MAX_FILE + 1))
    assert scan_path(out).problems == ["over.md: larger than 64 KiB"]


def test_depth_and_entry_limits_are_inclusive_and_reported_once(tmp_path: Path) -> None:
    chain = tmp_path / "chain"
    deep = chain
    for i in range(ht.MAX_DEPTH):
        deep = deep / f"d{i}"
    deep.mkdir(parents=True)
    assert scan_path(chain).problems == []
    (deep / "more").mkdir()
    assert [p for p in scan_path(chain).problems if "deeper than" in p] == [
        f"{'/'.join(f'd{i}' for i in range(ht.MAX_DEPTH))}/more: the tree is deeper than {ht.MAX_DEPTH} levels; "
        "the walk stopped here"
    ]
    full = tmp_path / "full"
    full.mkdir()
    for i in range(ht.MAX_ENTRIES):
        (full / f"f{i:04}").write_text("x")
    assert scan_path(full).problems == []
    spread = tmp_path / "spread"
    for name in ("a", "b", "c"):
        (spread / name).mkdir(parents=True)
        for i in range(ht.MAX_ENTRIES // 2):
            (spread / name / f"f{i:04}").write_text("x")
    assert len([p for p in scan_path(spread).problems if "more than" in p]) == 1


def test_an_entry_that_cannot_be_inspected_or_opened_or_read_is_a_problem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import stat as st

    out = tmp_path / "out"
    out.mkdir()
    (out / "a-pipe").write_text("not a pipe really")
    entries = [
        FakeEntry("broken", 0),
        FakeEntry("vanished-dir", st.S_IFDIR),
        FakeEntry("a-pipe-that-is-a-fifo", st.S_IFREG),
    ]
    os.mkfifo(out / "a-pipe-that-is-a-fifo")
    monkeypatch.setattr(os, "scandir", lambda fd: FakeScan(entries))
    with bounded():
        problems = scan_path(out).problems
    assert "broken: cannot be inspected" in problems
    assert "vanished-dir: a directory that cannot be opened without following a link" in problems
    assert "a-pipe-that-is-a-fifo: changed while it was being read, or is not a regular file" in problems


def test_a_file_read_refuses_what_is_not_a_regular_file_without_hanging(tmp_path: Path) -> None:
    (tmp_path / "plain").write_bytes(b"abc")
    os.mkfifo(tmp_path / "pipe")
    (tmp_path / "dir").mkdir()
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with bounded(10):
            got = ht._read_file(fd, "plain")
            assert got is not None and got[0] == b"abc"
            assert ht._read_file(fd, "pipe") is None
            assert ht._read_file(fd, "dir") is None
            assert ht._read_file(fd, "absent") is None
    finally:
        os.close(fd)


def test_the_output_directory_that_cannot_be_opened_is_a_problem_naming_why(tmp_path: Path) -> None:
    problems = scan_path(tmp_path / ("x" * 5000)).problems
    assert len(problems) == 1 and "cannot be opened (File name too long)" in problems[0]


def test_opening_a_missing_directory_without_create_neither_succeeds_nor_creates_it(tmp_path: Path) -> None:
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        before = open_fds()
        with pytest.raises(FileNotFoundError):
            ht._open_dir(fd, "a/b", False)
        assert open_fds() == before, "the failed walk closes the descriptors it opened"
        assert not (tmp_path / "a").exists()
        sub = ht._open_dir(fd, "a/b", True)
        os.close(sub)
        assert (tmp_path / "a" / "b").is_dir() and (os.stat(tmp_path / "a").st_mode & 0o777) == 0o755 & ~_umask()
    finally:
        os.close(fd)


def _umask() -> int:
    current = os.umask(0)
    os.umask(current)
    return current


def test_modes_are_fixed_by_the_writer_not_by_luck(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    old = os.umask(0o022)
    try:
        _, out = good(tmp_path, monkeypatch)
    finally:
        os.umask(old)
    for p in [out, *out.rglob("*")]:
        assert (p.stat().st_mode & 0o777) == (0o755 if p.is_dir() else 0o644), p


def test_the_temporary_name_is_hidden_random_and_created_exclusively(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[str, int]] = []
    real = os.open

    def spy(path: Any, flags: int, mode: int = 0o600, *, dir_fd: int | None = None) -> int:
        if isinstance(path, str) and path.endswith(".tmp"):
            seen.append((path, flags))
        return real(path, flags, mode, dir_fd=dir_fd)

    script, _ = scratch(tmp_path, monkeypatch)
    monkeypatch.setattr(os, "open", spy)
    assert script.main(["--write"]) == 0
    assert len(seen) == 6 and len({n for n, _ in seen}) == 6
    for name, flags in seen:
        assert re.fullmatch(r"\.[a-z0-9.-]+\.[0-9a-f]{16}\.tmp", name), name
        assert flags & os.O_EXCL and flags & os.O_NOFOLLOW and flags & os.O_CREAT


def test_each_file_and_its_directory_are_synced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    kinds: list[bool] = []
    real = os.fsync

    def spy(fd: int) -> None:
        kinds.append(stat.S_ISDIR(os.fstat(fd).st_mode))
        real(fd)

    script, _ = scratch(tmp_path, monkeypatch)
    monkeypatch.setattr(os, "fsync", spy)
    assert script.main(["--write"]) == 0
    assert kinds.count(False) == 6 and kinds.count(True) == 6


def test_a_failed_data_write_is_an_error_and_leaves_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = scratch(tmp_path, monkeypatch)

    def boom(fd: int, data: object) -> int:
        raise OSError(28, "no space left")

    monkeypatch.setattr(os, "write", boom)
    code, err = run(script, "--write", capsys)
    assert code == 1 and "no space left" in err
    assert not [p for p in out.rglob("*") if p.is_file()]


def test_no_descriptor_is_leaked_by_a_scan_a_check_a_write_or_a_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = scratch(tmp_path, monkeypatch)
    before = open_fds()
    assert script.main(["--write"]) == 0
    assert script.main(["--check"]) == 0
    (out / "claude" / "stray.md").write_bytes((out / "codex" / "codex.prompt.md").read_bytes())
    (out / "gone" / "deep").mkdir(parents=True)
    (out / "local" / "ollama.wrapper.txt").write_text("edited\n")
    assert script.main(["--write"]) == 1  # the stray entries are reported, the edited file is repaired
    os.mkfifo(out / "pipe")
    capsys.readouterr()
    with bounded():
        assert script.main(["--write"]) == 1
        assert script.main(["--check"]) == 1
    assert open_fds() == before


def test_the_changes_are_printed_one_per_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = scratch(tmp_path, monkeypatch)
    assert script.main(["--write"]) == 0
    first = capsys.readouterr().out.splitlines()
    assert "wrote claude/claude-haiku.md" in first and first[-1] == "ok: examples/harness is 6 generated files"
    (out / "gone" / "deep").mkdir(parents=True)
    (out / "gone" / "deep" / "x.md").write_bytes((out / "codex" / "codex.prompt.md").read_bytes())
    (out / "local" / "ollama.wrapper.txt").write_text("edited\n")
    assert script.main(["--write"]) == 1
    seen = capsys.readouterr()
    assert seen.out.splitlines() == ["wrote local/ollama.wrapper.txt"]
    assert "gone/deep/x.md: unexpected file (looks generated but is not expected)" in seen.err
    assert (out / "gone" / "deep" / "x.md").is_file(), "nothing is deleted"


def test_the_script_runs_as_a_program() -> None:
    root = Path(__file__).parent.parent
    done = subprocess.run(  # noqa: S603
        [sys.executable, str(root / "scripts" / "gen_profiles.py"), "--check"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert done.returncode == 0 and done.stdout.startswith("ok: examples/harness matches agents.yaml"), done.stderr


def test_the_caps_are_the_ones_the_docs_and_the_spec_state() -> None:
    assert ht.MAX_FILE == 64 * 1024  # spec 2.6
    assert (ht.MAX_DEPTH, ht.MAX_ENTRIES) == (8, 500)  # the bounds on a hostile tree, stated in the module docstring
