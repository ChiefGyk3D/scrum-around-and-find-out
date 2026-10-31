# SPDX-License-Identifier: Apache-2.0
"""The client's safe image writer (#260, phase 4a): hostile names, links, races, crashes and a full disk.

The bytes are untrusted output. The writer picks the type from the first bytes, makes the file name itself, creates the
file relative to a directory descriptor and never overwrites. These tests plant links, FIFOs and existing files, swap
the directory between steps through the injected step hook, and raise at every step; none of them depends on timing.
"""

from __future__ import annotations

import builtins
import errno
import io
import os
import re
import stat
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from safo.broker import imagewrite
from safo.broker.imagewrite import (
    ALLOWED_TYPES,
    DIR_STEPS,
    MAX_IMAGE_BYTES,
    STEPS,
    ImageRejected,
    ImageWriteError,
    UnsafeDirectory,
    default_output_dir,
    print_summary,
    sniff_image_type,
    write_image,
)

PNG = b"\x89PNG\r\n\x1a\n" + b"p" * 24
JPEG = b"\xff\xd8\xff\xe0" + b"j" * 24
WEBP = b"RIFF\x20\x00\x00\x00WEBPVP8 " + b"w" * 16
NAME = re.compile(r"^[A-Za-z0-9_-]{1,48}-[0-9a-f]{8}\.(png|jpg|webp)$")


class Boom(BaseException):
    """Not an Exception: what a crash, a SystemExit or a signal handler looks like to the code."""


def make_dir(path: Path, mode: int = 0o700) -> Path:
    path.mkdir()
    path.chmod(mode)
    return path


@pytest.fixture
def out(tmp_path: Path) -> Path:
    return make_dir(tmp_path / "out")


def names(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir())


def raiser(step: str, exc: BaseException) -> Callable[[str], None]:
    def hook(name: str) -> None:
        if name == step:
            raise exc

    return hook


# -- the type comes from the first bytes ---------------------------------------------------------------------------


@pytest.mark.parametrize(("data", "kind"), [(PNG, "png"), (JPEG, "jpeg"), (WEBP, "webp")])
def test_sniff(data: bytes, kind: str) -> None:
    assert sniff_image_type(data) == kind


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"GIF89a" + b"x" * 20,
        b"<svg xmlns='http://www.w3.org/2000/svg'/>",
        b"%PDF-1.7\n",
        b"\x7fELF" + b"\0" * 20,
        b"<html><script>alert(1)</script>",
        b"\x89PNG\r\n\x1a",  # one byte short of the signature
        b"\x89PNG\r\n\x1a\x0b" + b"x" * 20,  # one byte wrong
        b"\xff\xd8",  # truncated JPEG signature
        b"\xff\xd9\xff" + b"x" * 20,
        b"RIFX\x20\x00\x00\x00WEBPVP8 " + b"x" * 16,  # one byte off RIFF
        b"RIFF\x20\x00\x00\x00WEBX" + b"x" * 20,  # RIFF but not WebP
        b"RIFF\x20\x00\x00\x00WAVEfmt " + b"x" * 20,
        b"RIFF\x20\x00\x00\x00WEB",  # truncated
        b"xxxx\x20\x00\x00\x00WEBPVP8 " + b"x" * 16,  # right tail, wrong head
        b" \x89PNG\r\n\x1a\n",  # leading space
    ],
)
def test_sniff_refuses_everything_else(data: bytes) -> None:
    assert sniff_image_type(data) is None


@pytest.mark.parametrize("value", ["\x89PNG\r\n\x1a\n", None, 5])
def test_sniff_takes_only_bytes(value: Any) -> None:
    assert sniff_image_type(value) is None


def test_defaults_documented() -> None:
    assert ALLOWED_TYPES == ("png", "jpeg", "webp")
    assert MAX_IMAGE_BYTES == 24 * 1024 * 1024
    assert imagewrite.EXTENSIONS == {"png": "png", "jpeg": "jpg", "webp": "webp"}


# -- the happy path ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(("data", "ext"), [(PNG, "png"), (JPEG, "jpg"), (WEBP, "webp")])
def test_writes_and_returns_only_the_path(out: Path, data: bytes, ext: str) -> None:
    path = write_image(data, str(out), "cat")
    assert isinstance(path, str)
    assert os.path.dirname(path) == str(out)
    assert os.path.basename(path).endswith("." + ext)
    assert NAME.match(os.path.basename(path))
    assert Path(path).read_bytes() == data
    assert names(out) == [os.path.basename(path)]  # no temporary file is left


def test_mode_is_exactly_0600(out: Path) -> None:
    path = write_image(PNG, str(out), "cat")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


@pytest.mark.parametrize("mask", [0o000, 0o077, 0o277, 0o022])
def test_umask_does_not_change_the_mode(out: Path, mask: int) -> None:
    previous = os.umask(mask)
    try:
        path = write_image(PNG, str(out), "cat")
    finally:
        os.umask(previous)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_two_writes_of_one_stem_never_collide(out: Path) -> None:
    first = write_image(PNG, str(out), "cat")
    second = write_image(JPEG, str(out), "cat")
    assert first != second
    assert Path(first).read_bytes() == PNG
    assert Path(second).read_bytes() == JPEG


def test_accepts_a_path_object_and_a_trailing_slash(out: Path) -> None:
    assert write_image(PNG, out, "cat").startswith(str(out))
    assert write_image(PNG, str(out) + "/", "cat").startswith(str(out))


def test_every_step_fires_in_order(out: Path) -> None:
    seen: list[str] = []
    write_image(PNG, str(out), "cat", _step=seen.append)
    assert seen == list(STEPS)
    assert set(DIR_STEPS) <= set(STEPS)


# -- refusals happen before the file system is touched --------------------------------------------------------------


def never_opened(name: str) -> None:
    if name in DIR_STEPS or name == "tmp-created":
        raise AssertionError("the file system was touched for a refused image")


@pytest.mark.parametrize(
    "data",
    [b"", b"GIF89a" + b"x" * 20, b"\x89PNG\r\n\x1a", b"x" * 100, b"<svg/>", "\x89PNG\r\n\x1a\n", None, bytearray(PNG)],
)
def test_refuses_empty_other_types_and_non_bytes(out: Path, data: Any) -> None:
    with pytest.raises(ImageRejected):
        write_image(data, str(out), "cat", _step=never_opened)
    assert names(out) == []


def test_size_cap_is_exact(out: Path) -> None:
    big = PNG + b"x" * (100 - len(PNG))
    assert len(big) == 100
    write_image(big, str(out), "a", max_bytes=100)
    with pytest.raises(ImageRejected):
        write_image(big + b"x", str(out), "b", max_bytes=100, _step=never_opened)
    assert len(names(out)) == 1


def test_default_cap_is_24_mib(out: Path) -> None:
    with pytest.raises(ImageRejected):
        write_image(PNG + b"\0" * MAX_IMAGE_BYTES, str(out), "big", _step=never_opened)
    assert names(out) == []


def test_allowed_parameter_narrows(out: Path) -> None:
    write_image(PNG, str(out), "a", allowed=("png",))
    with pytest.raises(ImageRejected):
        write_image(JPEG, str(out), "b", allowed=("png",), _step=never_opened)
    with pytest.raises(ImageRejected):
        write_image(WEBP, str(out), "c", allowed=(), _step=never_opened)


@pytest.mark.parametrize("allowed", [("gif",), ("png", "svg"), "png"])
def test_unknown_allowed_entry_is_a_config_error(out: Path, allowed: Any) -> None:
    with pytest.raises(ImageWriteError) as caught:
        write_image(PNG, str(out), "a", allowed=allowed, _step=never_opened)
    assert type(caught.value) is ImageWriteError


@pytest.mark.parametrize("cap", [0, -1, True, False, "100", 1.5, None])
def test_bad_cap_is_refused(out: Path, cap: Any) -> None:
    with pytest.raises(ImageWriteError) as caught:
        write_image(PNG, str(out), "a", max_bytes=cap, _step=never_opened)
    assert type(caught.value) is ImageWriteError  # a config error, not a "too big" refusal


# -- the name is made here -----------------------------------------------------------------------------------------

HOSTILE_STEMS = [
    "../../etc/passwd",
    "..",
    ".",
    "",
    "/abs/path",
    "a/b",
    "a\\b",
    "a\x00b",
    "\x00",
    ".hidden",
    "cat.png",
    "cat.png\x00.exe",
    "a b",
    "a\nb",
    "\u202egnp.exe",  # right-to-left override
    "\u2025\u2025/",  # two-dot leader
    "\uff0e\uff0e/\uff0e\uff0e",  # fullwidth dots and slash
    "\u212a",  # Kelvin sign
    "\uff41\uff42\uff43",  # fullwidth letters
    "\u00e9\u00e8",
    "e\u0301",  # combining accent
    "\U0001f600",
    "a" * 10_000,
    "-rf",
    "~",
    "$(id)",
    "con",
]


@pytest.mark.parametrize("stem", HOSTILE_STEMS)
def test_hostile_stem_cannot_reach_the_file_system(out: Path, stem: str) -> None:
    path = write_image(PNG, str(out), stem)
    base = os.path.basename(path)
    assert NAME.match(base), base
    assert not base.startswith(("-", "."))  # never an option for a tool, never a hidden file
    assert os.path.dirname(path) == str(out)
    assert names(out) == [base]
    assert not (out.parent / "passwd").exists()


def test_stem_keeps_the_small_character_set(out: Path) -> None:
    path = write_image(PNG, str(out), "Job_1-final")
    assert os.path.basename(path).startswith("Job_1-final-")


def test_stem_is_cut_at_48(out: Path) -> None:
    path = write_image(PNG, str(out), "a" * 200)
    assert os.path.basename(path).startswith("a" * 48 + "-")
    assert len(os.path.basename(path)) < 70


@pytest.mark.parametrize("stem", [b"cat", None, 5, ["cat"]])
def test_non_text_stem_is_refused(out: Path, stem: Any) -> None:
    with pytest.raises(ImageWriteError) as caught:
        write_image(PNG, str(out), stem, _step=never_opened)
    assert type(caught.value) is ImageWriteError


def test_type_and_name_from_the_caller_are_ignored(out: Path) -> None:
    # The only caller input that reaches a name is the sanitized stem; the extension follows the bytes.
    path = write_image(JPEG, str(out), "cat.png")
    assert path.endswith(".jpg")
    assert os.path.basename(path).startswith("cat_png-")


# -- the directory -------------------------------------------------------------------------------------------------


def test_relative_directory_is_refused(out: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(out)
    with pytest.raises(UnsafeDirectory):
        write_image(PNG, ".", "cat")
    with pytest.raises(UnsafeDirectory):
        write_image(PNG, "", "cat")
    assert names(out) == []


def test_dotdot_component_is_refused(out: Path) -> None:
    with pytest.raises(UnsafeDirectory):
        write_image(PNG, str(out / ".." / "out"), "cat")
    assert names(out) == []


@pytest.mark.parametrize("bad", ["/no/such/dir/anywhere", "/dev/null", "/dev", "\x00", "/etc/passwd/"])
def test_missing_special_and_foreign_directories(bad: str) -> None:
    with pytest.raises(UnsafeDirectory):
        write_image(PNG, bad, "cat")


def test_bytes_directory_is_refused(out: Path) -> None:
    bad: Any = os.fsencode(str(out))
    with pytest.raises(UnsafeDirectory):
        write_image(PNG, bad, "cat")


def test_file_in_place_of_directory(tmp_path: Path) -> None:
    f = tmp_path / "file"
    f.write_bytes(b"x")
    with pytest.raises(UnsafeDirectory):
        write_image(PNG, str(f), "cat")
    assert f.read_bytes() == b"x"


def test_fifo_in_place_of_directory_does_not_hang(tmp_path: Path) -> None:
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(UnsafeDirectory):
        write_image(PNG, str(fifo), "cat")


def test_directory_that_is_a_symlink(tmp_path: Path, out: Path) -> None:
    link = tmp_path / "link"
    link.symlink_to(out)
    with pytest.raises(UnsafeDirectory):
        write_image(PNG, str(link), "cat")
    assert names(out) == []


def test_parent_that_is_a_symlink(tmp_path: Path) -> None:
    real = make_dir(tmp_path / "real")
    make_dir(real / "inner")
    (tmp_path / "plink").symlink_to(real)
    with pytest.raises(UnsafeDirectory):
        write_image(PNG, str(tmp_path / "plink" / "inner"), "cat")
    assert names(real / "inner") == []


def test_middle_component_that_is_a_symlink(tmp_path: Path) -> None:
    real = make_dir(tmp_path / "real")
    deep = make_dir(real / "a")
    make_dir(deep / "b")
    (tmp_path / "l").symlink_to(deep)
    with pytest.raises(UnsafeDirectory):
        write_image(PNG, str(tmp_path / "l" / "b"), "cat")
    assert names(deep / "b") == []


def test_dangling_symlink_directory(tmp_path: Path) -> None:
    (tmp_path / "d").symlink_to(tmp_path / "nowhere")
    with pytest.raises(UnsafeDirectory):
        write_image(PNG, str(tmp_path / "d"), "cat")
    assert not (tmp_path / "nowhere").exists()


@pytest.mark.parametrize("mode", [0o770, 0o707, 0o777, 0o720, 0o702, 0o2770])
def test_group_or_world_writable_directory_is_refused(tmp_path: Path, mode: int) -> None:
    d = make_dir(tmp_path / "w", mode)
    with pytest.raises(UnsafeDirectory):
        write_image(PNG, str(d), "cat")
    assert names(d) == []


@pytest.mark.parametrize("mode", [0o1777, 0o1770, 0o1707, 0o1722])
def test_writable_with_sticky_bit_and_owned_by_us_is_accepted(tmp_path: Path, mode: int) -> None:
    d = make_dir(tmp_path / "sticky", mode)
    assert write_image(PNG, str(d), "cat").startswith(str(d))


@pytest.mark.parametrize("mode", [0o700, 0o750, 0o755])
def test_private_or_readable_directory_is_accepted(tmp_path: Path, mode: int) -> None:
    d = make_dir(tmp_path / "ok", mode)
    assert write_image(PNG, str(d), "cat").startswith(str(d))


def test_directory_owned_by_someone_else_is_refused(out: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(out).st_uid + 1)
    with pytest.raises(UnsafeDirectory):
        write_image(PNG, str(out), "cat")
    assert names(out) == []


def test_sticky_world_writable_owned_by_someone_else_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = make_dir(tmp_path / "s", 0o1777)
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(d).st_uid + 1)
    with pytest.raises(UnsafeDirectory):
        write_image(PNG, str(d), "cat")


# -- races between steps -------------------------------------------------------------------------------------------


def swap_for_symlink(directory: Path, attacker: Path) -> None:
    directory.rename(directory.with_name(directory.name + ".moved"))
    directory.symlink_to(attacker)


def test_directory_swapped_before_it_is_opened(tmp_path: Path, out: Path) -> None:
    attacker = make_dir(tmp_path / "attacker")

    def hook(step: str) -> None:
        if step == "dir-resolved":
            swap_for_symlink(out, attacker)

    with pytest.raises(UnsafeDirectory):
        write_image(PNG, str(out), "cat", _step=hook)
    assert names(attacker) == []
    assert names(tmp_path / "out.moved") == []


def test_parent_swapped_before_it_is_opened(tmp_path: Path) -> None:
    parent = make_dir(tmp_path / "parent")
    make_dir(parent / "out")
    attacker = make_dir(tmp_path / "attacker")
    make_dir(attacker / "out")

    def hook(step: str) -> None:
        if step == "dir-resolved":
            swap_for_symlink(parent, attacker)

    with pytest.raises(UnsafeDirectory):
        write_image(PNG, str(parent / "out"), "cat", _step=hook)
    assert names(attacker / "out") == []


def test_directory_swapped_after_it_is_opened_still_writes_to_the_opened_one(tmp_path: Path, out: Path) -> None:
    attacker = make_dir(tmp_path / "attacker")

    def hook(step: str) -> None:
        if step == "dir-opened":
            swap_for_symlink(out, attacker)

    write_image(PNG, str(out), "cat", _step=hook)
    assert names(attacker) == []
    assert len(names(tmp_path / "out.moved")) == 1


def test_directory_swapped_while_the_file_is_made_stays_bound(tmp_path: Path, out: Path) -> None:
    attacker = make_dir(tmp_path / "attacker")

    def hook(step: str) -> None:
        if step == "tmp-created":
            swap_for_symlink(out, attacker)

    write_image(PNG, str(out), "cat", _step=hook)
    assert names(attacker) == []
    assert len(names(tmp_path / "out.moved")) == 1


# -- the final name is never overwritten and never followed ---------------------------------------------------------


def fixed_suffix(monkeypatch: pytest.MonkeyPatch, *values: str) -> None:
    it: Iterator[str] = iter(values)
    last = values[-1]
    monkeypatch.setattr(imagewrite, "_random_suffix", lambda: next(it, last))


def test_existing_file_is_never_overwritten(out: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixed_suffix(monkeypatch, "deadbeef")
    (out / "cat-deadbeef.png").write_bytes(b"precious")
    with pytest.raises(ImageWriteError):
        write_image(PNG, str(out), "cat")
    assert (out / "cat-deadbeef.png").read_bytes() == b"precious"
    assert names(out) == ["cat-deadbeef.png"]


def test_collision_picks_another_name_and_keeps_the_old_file(out: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (out / "cat-aaaaaaaa.png").write_bytes(b"precious")
    fixed_suffix(monkeypatch, "00000000", "aaaaaaaa", "bbbbbbbb")
    path = write_image(PNG, str(out), "cat")
    assert os.path.basename(path) == "cat-bbbbbbbb.png"
    assert (out / "cat-aaaaaaaa.png").read_bytes() == b"precious"
    assert Path(path).read_bytes() == PNG


def test_existing_read_only_file_is_kept(out: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixed_suffix(monkeypatch, "deadbeef")
    target = out / "cat-deadbeef.png"
    target.write_bytes(b"precious")
    target.chmod(0o400)
    with pytest.raises(ImageWriteError):
        write_image(PNG, str(out), "cat")
    assert target.read_bytes() == b"precious"


def test_symlink_at_the_final_name_is_not_followed(tmp_path: Path, out: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    victim = tmp_path / "victim"
    victim.write_bytes(b"victim")
    (out / "cat-deadbeef.png").symlink_to(victim)
    fixed_suffix(monkeypatch, "deadbeef")
    with pytest.raises(ImageWriteError):
        write_image(PNG, str(out), "cat")
    assert victim.read_bytes() == b"victim"
    assert names(out) == ["cat-deadbeef.png"]


def test_dangling_symlink_at_the_final_name_is_not_created_through(
    tmp_path: Path, out: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (out / "cat-deadbeef.png").symlink_to(tmp_path / "created-by-attacker")
    fixed_suffix(monkeypatch, "deadbeef")
    with pytest.raises(ImageWriteError):
        write_image(PNG, str(out), "cat")
    assert not (tmp_path / "created-by-attacker").exists()


def test_symlink_to_a_device_at_the_final_name(out: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (out / "cat-deadbeef.png").symlink_to("/dev/null")
    fixed_suffix(monkeypatch, "deadbeef")
    with pytest.raises(ImageWriteError):
        write_image(PNG, str(out), "cat")
    assert names(out) == ["cat-deadbeef.png"]


def test_fifo_at_the_final_name_does_not_hang_or_open(out: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    os.mkfifo(out / "cat-deadbeef.png")
    fixed_suffix(monkeypatch, "deadbeef")
    with pytest.raises(ImageWriteError):
        write_image(PNG, str(out), "cat")
    assert stat.S_ISFIFO(os.lstat(out / "cat-deadbeef.png").st_mode)


def test_fifo_at_the_temporary_name_is_skipped(out: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    os.mkfifo(out / ".tmp-aaaaaaaa")
    os.symlink("/dev/null", out / ".tmp-bbbbbbbb")
    fixed_suffix(monkeypatch, "aaaaaaaa", "bbbbbbbb", "cccccccc", "dddddddd")
    path = write_image(PNG, str(out), "cat")
    assert Path(path).read_bytes() == PNG
    assert stat.S_ISFIFO(os.lstat(out / ".tmp-aaaaaaaa").st_mode)
    assert os.readlink(out / ".tmp-bbbbbbbb") == "/dev/null"


def test_exhausted_names_end_in_an_error(out: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixed_suffix(monkeypatch, "same0000")
    (out / ".tmp-same0000").write_bytes(b"x")
    with pytest.raises(ImageWriteError):
        write_image(PNG, str(out), "cat")
    assert names(out) == [".tmp-same0000"]


# -- failure leaves nothing -----------------------------------------------------------------------------------------

watched: set[int] = set()


def only_our_fd(real: Callable[..., Any], fake: Callable[..., Any]) -> Callable[..., Any]:
    def call(fd: int, *args: Any) -> Any:
        if fd in watched:
            return fake(fd, *args)
        return real(fd, *args)

    return call


def watch_fds(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remember every descriptor the writer creates, so a fake os.write only fires for those."""
    real_open = os.open
    watched.clear()

    def spy(path: Any, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        fd = real_open(path, flags, mode, dir_fd=dir_fd)
        if flags & os.O_CREAT:
            watched.add(fd)
        return fd

    monkeypatch.setattr(os, "open", spy)


def test_disk_full_on_write_leaves_no_file(out: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    watch_fds(monkeypatch)

    def full(fd: int, data: Any) -> int:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(os, "write", only_our_fd(os.write, full))
    with pytest.raises(ImageWriteError) as caught:
        write_image(PNG, str(out), "cat")
    assert names(out) == []
    assert "ENOSPC" in str(caught.value)
    assert str(out) not in str(caught.value)


def test_disk_full_after_a_partial_write_leaves_no_file(out: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    watch_fds(monkeypatch)
    real_write = os.write
    state = {"n": 0}

    def half(fd: int, data: Any) -> int:
        state["n"] += 1
        if state["n"] == 1:
            return real_write(fd, bytes(data)[:4])
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(os, "write", only_our_fd(os.write, half))
    with pytest.raises(ImageWriteError):
        write_image(PNG, str(out), "cat")
    assert names(out) == []


def test_short_writes_are_continued(out: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    watch_fds(monkeypatch)
    real_write = os.write

    def three(fd: int, data: Any) -> int:
        return real_write(fd, bytes(data)[:3])

    monkeypatch.setattr(os, "write", only_our_fd(os.write, three))
    path = write_image(PNG, str(out), "cat")
    assert Path(path).read_bytes() == PNG


def test_a_write_that_makes_no_progress_is_an_error_not_a_loop(out: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    watch_fds(monkeypatch)
    monkeypatch.setattr(os, "write", only_our_fd(os.write, lambda fd, data: 0))
    with pytest.raises(ImageWriteError):
        write_image(PNG, str(out), "cat")
    assert names(out) == []


@pytest.mark.parametrize("fn", ["fsync", "fchmod", "link"])
def test_a_failing_call_leaves_no_file(out: Path, monkeypatch: pytest.MonkeyPatch, fn: str) -> None:
    def fail(*args: Any, **kwargs: Any) -> Any:
        raise OSError(errno.EIO, "I/O error")

    monkeypatch.setattr(os, fn, fail)
    with pytest.raises(ImageWriteError):
        write_image(PNG, str(out), "cat")
    monkeypatch.undo()
    assert names(out) == []


def test_directory_fsync_failure_leaves_no_file(out: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real = os.fsync
    state = {"n": 0}

    def second_fails(fd: int) -> None:
        state["n"] += 1
        if state["n"] == 2:  # the first is the file, the second is the directory
            raise OSError(errno.EIO, "I/O error")
        real(fd)

    monkeypatch.setattr(os, "fsync", second_fails)
    with pytest.raises(ImageWriteError):
        write_image(PNG, str(out), "cat")
    monkeypatch.undo()
    assert names(out) == []


def test_file_fsync_comes_before_the_link(out: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []
    real_fsync, real_link = os.fsync, os.link

    def fsync(fd: int) -> None:
        events.append("fsync")
        real_fsync(fd)

    def link(*args: Any, **kwargs: Any) -> None:
        events.append("link")
        real_link(*args, **kwargs)

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "link", link)
    write_image(PNG, str(out), "cat")
    assert events == ["fsync", "link", "fsync"]


def test_link_unsupported_leaves_nothing(out: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def nolink(*args: Any, **kwargs: Any) -> None:
        raise OSError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(os, "link", nolink)
    with pytest.raises(ImageWriteError):
        write_image(PNG, str(out), "cat")
    assert names(out) == []


def test_unwritable_directory_leaves_nothing(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root ignores directory modes")
    d = make_dir(tmp_path / "ro", 0o500)
    with pytest.raises(ImageWriteError):
        write_image(PNG, str(d), "cat")
    assert names(d) == []


@pytest.mark.parametrize("step", STEPS)
@pytest.mark.parametrize("exc", [Boom(), KeyboardInterrupt(), SystemExit(3)])
def test_a_crash_at_every_step_leaves_no_file(out: Path, step: str, exc: BaseException) -> None:
    with pytest.raises(type(exc)):
        write_image(PNG, str(out), "cat", _step=raiser(step, exc))
    assert names(out) == []


@pytest.mark.parametrize("step", STEPS)
def test_an_ordinary_error_at_every_step_leaves_no_file(out: Path, step: str) -> None:
    with pytest.raises(RuntimeError):
        write_image(PNG, str(out), "cat", _step=raiser(step, RuntimeError("x")))
    assert names(out) == []


def test_descriptors_are_all_closed_after_a_crash_and_after_success(out: Path) -> None:
    def open_fds() -> set[str]:
        return set(os.listdir("/proc/self/fd"))

    base = open_fds()
    for step in STEPS:
        with pytest.raises(Boom):
            write_image(PNG, str(out), "cat", _step=raiser(step, Boom()))
    write_image(PNG, str(out), "cat")
    # listing /proc/self/fd opens one descriptor of its own, so compare the sets without it
    assert len(open_fds() - base) <= 1


def test_crash_after_the_link_does_not_unlink_a_replaced_final(out: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixed_suffix(monkeypatch, "00000000", "feedface")
    final = out / "cat-feedface.png"

    def hook(step: str) -> None:
        if step == "linked":
            final.unlink()
            final.write_bytes(b"someone else")
            raise Boom

    with pytest.raises(Boom):
        write_image(PNG, str(out), "cat", _step=hook)
    assert final.read_bytes() == b"someone else"


def test_error_messages_are_fixed_sentences(out: Path) -> None:
    secret = "SECRET-NAME-\u202e"
    with pytest.raises(ImageRejected) as caught:
        write_image(b"nope", str(out), secret)
    assert secret not in str(caught.value)
    with pytest.raises(UnsafeDirectory) as caught2:
        write_image(PNG, "/no/such/" + secret, "cat")
    assert secret not in str(caught2.value)


# -- the default output directory ----------------------------------------------------------------------------------


def test_default_dir_is_created_private(tmp_path: Path) -> None:
    state = make_dir(tmp_path / "state")
    d = default_output_dir(state_home=str(state), home=str(tmp_path))
    assert d == str(state / "safo" / "gemini-images")
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(state / "safo").st_mode) == 0o700
    assert default_output_dir(state_home=str(state), home=str(tmp_path)) == d  # idempotent
    assert write_image(PNG, d, "cat").startswith(d)


def test_default_dir_creates_a_missing_base_private(tmp_path: Path) -> None:
    d = default_output_dir(state_home=None, home=str(tmp_path))
    assert d == str(tmp_path / ".local" / "state" / "safo" / "gemini-images")
    for part in (".local", ".local/state", ".local/state/safo", ".local/state/safo/gemini-images"):
        assert stat.S_IMODE(os.stat(tmp_path / part).st_mode) == 0o700


@pytest.mark.parametrize("mask", [0o000, 0o077, 0o277])
def test_default_dir_mode_ignores_umask(tmp_path: Path, mask: int) -> None:
    previous = os.umask(mask)
    try:
        d = default_output_dir(state_home=None, home=str(tmp_path))
    finally:
        os.umask(previous)
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(Path(d).parent).st_mode) == 0o700


def test_default_dir_reads_xdg_state_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = make_dir(tmp_path / "xdg")
    monkeypatch.setenv("XDG_STATE_HOME", str(state))
    assert default_output_dir(home=str(tmp_path)).startswith(str(state))
    monkeypatch.setenv("XDG_STATE_HOME", "relative/dir")  # the XDG spec: a relative value is invalid and ignored
    assert default_output_dir(home=str(tmp_path)).startswith(str(tmp_path / ".local"))
    monkeypatch.setenv("XDG_STATE_HOME", "")
    assert default_output_dir(home=str(tmp_path)).startswith(str(tmp_path / ".local"))


def test_default_dir_refuses_a_symlinked_final(tmp_path: Path) -> None:
    state = make_dir(tmp_path / "state")
    elsewhere = make_dir(tmp_path / "elsewhere")
    make_dir(state / "safo")
    (state / "safo" / "gemini-images").symlink_to(elsewhere)
    with pytest.raises(UnsafeDirectory):
        default_output_dir(state_home=str(state), home=str(tmp_path))
    assert names(elsewhere) == []


def test_default_dir_refuses_a_symlinked_middle(tmp_path: Path) -> None:
    state = make_dir(tmp_path / "state")
    elsewhere = make_dir(tmp_path / "elsewhere")
    (state / "safo").symlink_to(elsewhere)
    with pytest.raises(UnsafeDirectory):
        default_output_dir(state_home=str(state), home=str(tmp_path))
    assert names(elsewhere) == []


def test_default_dir_refuses_a_symlinked_base(tmp_path: Path) -> None:
    elsewhere = make_dir(tmp_path / "elsewhere")
    (tmp_path / "state").symlink_to(elsewhere)
    with pytest.raises(UnsafeDirectory):
        default_output_dir(state_home=str(tmp_path / "state"), home=str(tmp_path))
    assert names(elsewhere) == []


def test_default_dir_refuses_a_symlinked_ancestor_of_the_base(tmp_path: Path) -> None:
    elsewhere = make_dir(tmp_path / "elsewhere")
    make_dir(elsewhere / "state")
    (tmp_path / "link").symlink_to(elsewhere)
    with pytest.raises(UnsafeDirectory):
        default_output_dir(state_home=str(tmp_path / "link" / "state"), home=str(tmp_path))
    assert names(elsewhere / "state") == []


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o770, 0o707, 0o777])
def test_default_dir_refuses_a_loose_existing_final(tmp_path: Path, mode: int) -> None:
    state = make_dir(tmp_path / "state")
    make_dir(state / "safo")
    make_dir(state / "safo" / "gemini-images", mode)
    with pytest.raises(UnsafeDirectory):
        default_output_dir(state_home=str(state), home=str(tmp_path))


def test_default_dir_refuses_a_loose_existing_middle(tmp_path: Path) -> None:
    state = make_dir(tmp_path / "state")
    make_dir(state / "safo", 0o777)
    with pytest.raises(UnsafeDirectory):
        default_output_dir(state_home=str(state), home=str(tmp_path))


def test_default_dir_refuses_a_loose_existing_base(tmp_path: Path) -> None:
    state = make_dir(tmp_path / "state", 0o777)
    with pytest.raises(UnsafeDirectory):
        default_output_dir(state_home=str(state), home=str(tmp_path))


def test_default_dir_refuses_the_wrong_owner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = make_dir(tmp_path / "state")
    default_output_dir(state_home=str(state), home=str(tmp_path))
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(state).st_uid + 1)
    with pytest.raises(UnsafeDirectory):
        default_output_dir(state_home=str(state), home=str(tmp_path))


def test_default_dir_refuses_a_file_in_the_way(tmp_path: Path) -> None:
    state = make_dir(tmp_path / "state")
    (state / "safo").write_bytes(b"x")
    with pytest.raises(UnsafeDirectory):
        default_output_dir(state_home=str(state), home=str(tmp_path))


def test_default_dir_refuses_a_fifo_in_the_way(tmp_path: Path) -> None:
    state = make_dir(tmp_path / "state")
    os.mkfifo(state / "safo")
    with pytest.raises(UnsafeDirectory):
        default_output_dir(state_home=str(state), home=str(tmp_path))


def test_default_dir_race_swap_to_symlink(tmp_path: Path) -> None:
    state = make_dir(tmp_path / "state")
    make_dir(state / "safo")
    attacker = make_dir(tmp_path / "attacker")

    def hook(step: str) -> None:
        if step == "dir-resolved":
            swap_for_symlink(state / "safo", attacker)

    with pytest.raises(UnsafeDirectory):
        default_output_dir(state_home=str(state), home=str(tmp_path), _step=hook)
    assert names(attacker) == []


def test_default_dir_leaves_what_it_did_not_make(tmp_path: Path) -> None:
    state = make_dir(tmp_path / "state")
    make_dir(state / "safo", 0o777)
    with pytest.raises(UnsafeDirectory):
        default_output_dir(state_home=str(state), home=str(tmp_path))
    assert (state / "safo").is_dir()


@pytest.mark.parametrize("bad", ["relative", "/a/../b"])
def test_default_dir_bad_base_is_refused(tmp_path: Path, bad: str) -> None:
    with pytest.raises(UnsafeDirectory):
        default_output_dir(state_home=bad, home=str(tmp_path))


@pytest.mark.parametrize("home", ["relative", "", "/a/../b"])
def test_default_dir_bad_home_is_refused(home: str) -> None:
    with pytest.raises(UnsafeDirectory):
        default_output_dir(state_home=None, home=home)


# -- the one-line summary ------------------------------------------------------------------------------------------


def test_summary_is_one_line_with_size_and_type() -> None:
    buf = io.StringIO()
    line = print_summary("/x/cat-0123abcd.png", PNG, file=buf)
    assert line == f"saved {len(PNG)} bytes, type png: /x/cat-0123abcd.png"
    assert buf.getvalue() == line + "\n"


@pytest.mark.parametrize(("data", "kind"), [(PNG, "png"), (JPEG, "jpeg"), (WEBP, "webp"), (b"junk", "unknown")])
def test_summary_names_the_sniffed_type(data: bytes, kind: str) -> None:
    assert f"type {kind}:" in print_summary("/x/a", data, file=io.StringIO())


def test_summary_escapes_control_characters_in_the_path() -> None:
    line = print_summary("/x/\x1b[31mred\nnext\r\u202e", PNG, file=io.StringIO())
    assert "\n" not in line
    assert "\r" not in line
    assert "\x1b" not in line
    assert "\u202e" not in line


def test_summary_goes_to_stdout_by_default(capsys: pytest.CaptureFixture[str]) -> None:
    print_summary("/x/a.png", PNG)
    assert capsys.readouterr().out == f"saved {len(PNG)} bytes, type png: /x/a.png\n"


def test_summary_never_touches_the_file_system(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("the summary touched the file system")

    for target in (builtins, os):
        for name in ("open", "stat", "lstat", "listdir", "scandir", "readlink", "access"):
            if hasattr(target, name):
                monkeypatch.setattr(target, name, refuse)
    monkeypatch.setattr(Path, "open", refuse)
    monkeypatch.setattr(Path, "stat", refuse)
    print_summary("/x/a.png", PNG, file=io.StringIO())


# -- sibling cases the first mutation sweep found --------------------------------------------------------------------


def test_empty_image_has_its_own_refusal(out: Path) -> None:
    with pytest.raises(ImageRejected, match="empty"):
        write_image(b"", str(out), "cat", _step=never_opened)


@pytest.mark.parametrize("bad", [5, None, 1.5, ["/tmp"], b"/tmp"])
def test_directory_of_the_wrong_type_is_unsafe_not_a_type_error(bad: Any) -> None:
    with pytest.raises(UnsafeDirectory):
        write_image(PNG, bad, "cat")


def test_directory_with_a_nul_inside_is_unsafe_not_a_value_error(out: Path) -> None:
    with pytest.raises(UnsafeDirectory):
        write_image(PNG, str(out) + "\x00/x", "cat")
    with pytest.raises(UnsafeDirectory):
        default_output_dir(state_home=str(out) + "\x00/x")


def test_dot_components_are_dropped_from_the_returned_path(out: Path) -> None:
    path = write_image(PNG, str(out) + "/././/", "cat")
    assert os.path.dirname(path) == str(out)


def test_a_missing_directory_is_not_created_by_the_writer(tmp_path: Path) -> None:
    with pytest.raises(UnsafeDirectory):
        write_image(PNG, str(tmp_path / "new" / "deeper"), "cat")
    assert names(tmp_path) == []


def test_created_directories_are_made_private_from_the_start(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    modes: list[int] = []
    real_mkdir = os.mkdir

    def spy(path: Any, mode: int = 0o777, *, dir_fd: int | None = None) -> None:
        modes.append(mode)
        real_mkdir(path, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "mkdir", spy)
    default_output_dir(state_home=None, home=str(tmp_path))
    assert modes == [0o700] * 4


def test_the_temporary_file_is_created_private_from_the_start(out: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    modes: list[int] = []
    real_open = os.open

    def spy(path: Any, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        if flags & os.O_CREAT:
            modes.append(mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", spy)
    write_image(PNG, str(out), "cat")
    assert modes == [0o600]


def test_a_crash_inside_the_directory_walk_closes_every_descriptor(out: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fds() -> set[str]:
        return set(os.listdir("/proc/self/fd"))

    before = fds()

    def boom(fd: int) -> os.stat_result:
        raise Boom

    with monkeypatch.context() as patch:
        patch.setattr(os, "fstat", boom)
        with pytest.raises(Boom):
            write_image(PNG, str(out), "cat")
    assert len(fds() - before) <= 1  # the listing itself holds one


def fake_stat(mode: int, uid: int) -> os.stat_result:
    return os.stat_result((stat.S_IFDIR | mode, 1, 1, 1, uid, 0, 0, 0, 0, 0))


MINE = os.geteuid()
OTHER = MINE + 1


@pytest.mark.parametrize(
    ("mode", "uid", "ok"),
    [
        (0o700, MINE, True),
        (0o755, MINE, True),
        (0o700, OTHER, False),
        (0o755, OTHER, False),
        (0o770, MINE, False),
        (0o707, MINE, False),
        (0o720, MINE, False),
        (0o702, MINE, False),
        (0o1777, MINE, True),
        (0o1777, OTHER, False),
        (0o1770, MINE, True),
        (0o2770, MINE, False),
    ],
)
def test_write_directory_rule_table(mode: int, uid: int, ok: bool) -> None:
    if ok:
        imagewrite._check_write_dir(fake_stat(mode, uid))
    else:
        with pytest.raises(UnsafeDirectory):
            imagewrite._check_write_dir(fake_stat(mode, uid))


@pytest.mark.parametrize(
    ("mode", "uid", "ok"),
    [
        (0o700, MINE, True),
        (0o755, MINE, True),
        (0o700, OTHER, False),
        (0o770, MINE, False),
        (0o707, MINE, False),
        (0o1777, MINE, False),
        (0o720, MINE, False),
        (0o702, MINE, False),
    ],
)
def test_lenient_directory_rule_table(mode: int, uid: int, ok: bool) -> None:
    if ok:
        imagewrite._check_lenient(fake_stat(mode, uid))
    else:
        with pytest.raises(UnsafeDirectory):
            imagewrite._check_lenient(fake_stat(mode, uid))


@pytest.mark.parametrize(
    ("mode", "uid", "ok"),
    [
        (0o700, MINE, True),
        (0o500, MINE, True),
        (0o700, OTHER, False),
        (0o750, MINE, False),
        (0o710, MINE, False),
        (0o705, MINE, False),
        (0o701, MINE, False),
        (0o740, MINE, False),
        (0o704, MINE, False),
        (0o755, MINE, False),
        (0o1700, MINE, True),
    ],
)
def test_private_directory_rule_table(mode: int, uid: int, ok: bool) -> None:
    if ok:
        imagewrite._check_private(fake_stat(mode, uid))
    else:
        with pytest.raises(UnsafeDirectory):
            imagewrite._check_private(fake_stat(mode, uid))


def test_a_base_directory_that_is_group_readable_is_accepted(tmp_path: Path) -> None:
    state = make_dir(tmp_path / "state", 0o755)
    assert default_output_dir(state_home=str(state), home=str(tmp_path)).startswith(str(state))


def test_default_dir_refuses_the_wrong_owner_below_the_base(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = make_dir(tmp_path / "state")
    default_output_dir(state_home=str(state), home=str(tmp_path))
    real_mine = imagewrite._mine
    calls = {"n": 0}

    def mine_until_base(st: os.stat_result) -> bool:
        calls["n"] += 1
        return real_mine(st) if calls["n"] == 1 else False  # the base passes, safo is "someone else's"

    monkeypatch.setattr(imagewrite, "_mine", mine_until_base)
    with pytest.raises(UnsafeDirectory):
        default_output_dir(state_home=str(state), home=str(tmp_path))
