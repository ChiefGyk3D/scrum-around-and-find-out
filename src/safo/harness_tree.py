# SPDX-License-Identifier: MIT
"""The filesystem half of `scripts/gen_profiles.py`: inventory, check and write of the output tree (spec 2.6).

`scripts/gen_routing.py` reads and writes one file with `Path.read_text` and `write_text`. This tree holds files that
agents obey, and the directory is one a contributor's pull request can fill, so every step is stricter:

- the INVENTORY is a non-following walk on directory descriptors (`O_NOFOLLOW | O_DIRECTORY`). A symbolic link, FIFO,
  socket, device or other special entry anywhere under the tree, or the tree root itself being a link, is a problem; so
  is a file over 64 KiB. Nothing is ever opened for reading unless `lstat` said it is a regular file, and it is opened
  `O_NOFOLLOW | O_NONBLOCK` and checked with `fstat` on the descriptor, so a swap between the two cannot hang the read;
- the comparison is of EXACT path sets: a missing file, an unexpected file and a stale file all fail;
- WRITES go through directory descriptors: a temporary file created `O_EXCL | O_NOFOLLOW` in the destination directory,
  `fsync`, rename, `fsync` of the directory. A directory or a link is never replaced or removed. A stale file is removed
  only when it is a regular file that carries the generated header; then the directories left empty and no longer
  expected are removed bottom-up. Anything else stops the whole write, before the first change, with an error naming it.

POSIX only (descriptors and `dir_fd`). The walk is capped at 8 levels and 500 entries, and a file at 64 KiB, so a
hostile tree cannot make it expensive.
"""

from __future__ import annotations

import contextlib
import errno
import os
import secrets
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from safo.errors import ConfigError
from safo.profile_render import Rendered, compare, has_header

MAX_FILE = 64 * 1024
MAX_DEPTH = 8
MAX_ENTRIES = 500
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class TreeError(ConfigError):
    """The output tree cannot be handled safely."""


@dataclass
class Tree:
    """What is on disk under the output directory: regular files with their bytes, directories, and what is wrong."""

    exists: bool = False
    files: dict[str, bytes] = field(default_factory=dict)
    dirs: set[str] = field(default_factory=set)
    problems: list[str] = field(default_factory=list)
    entries: int = 0


def _kind(mode: int) -> str:
    for test, name in (
        (stat.S_ISLNK, "a symbolic link"),
        (stat.S_ISFIFO, "a FIFO"),
        (stat.S_ISSOCK, "a socket"),
        (stat.S_ISBLK, "a block device"),
        (stat.S_ISCHR, "a character device"),
    ):
        if test(mode):
            return name
    return "a special entry"


def _read_file(dir_fd: int, name: str) -> bytes | None:
    """At most MAX_FILE + 1 bytes of the regular file `name` of the directory, or None when it is not one any more."""
    try:
        fd = os.open(name, _FILE_FLAGS, dir_fd=dir_fd)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_FILE:
            chunk = os.read(fd, MAX_FILE + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _walk(fd: int, rel: str, depth: int, tree: Tree) -> None:
    with os.scandir(fd) as it:
        entries = sorted(it, key=lambda e: e.name)
    for entry in entries:
        tree.entries += 1
        if tree.entries > MAX_ENTRIES:
            if tree.entries == MAX_ENTRIES + 1:
                tree.problems.append(f"the tree has more than {MAX_ENTRIES} entries; the walk stopped")
            return
        path = f"{rel}/{entry.name}" if rel else entry.name
        try:
            mode = entry.stat(follow_symlinks=False).st_mode
        except OSError:
            tree.problems.append(f"{path}: cannot be inspected")
            continue
        if stat.S_ISDIR(mode):
            if depth >= MAX_DEPTH:
                tree.problems.append(f"{path}: the tree is deeper than {MAX_DEPTH} levels; the walk stopped here")
                continue
            try:
                sub = os.open(entry.name, _DIR_FLAGS, dir_fd=fd)
            except OSError:
                tree.problems.append(f"{path}: a directory that cannot be opened without following a link")
                continue
            try:
                tree.dirs.add(path)
                _walk(sub, path, depth + 1, tree)
            finally:
                os.close(sub)
        elif stat.S_ISREG(mode):
            data = _read_file(fd, entry.name)
            if data is None:
                tree.problems.append(f"{path}: changed while it was being read, or is not a regular file")
            elif len(data) > MAX_FILE:
                tree.problems.append(f"{path}: larger than {MAX_FILE // 1024} KiB")
            else:
                tree.files[path] = data
        else:
            tree.problems.append(f"{path}: {_kind(mode)}, which a generated tree never holds")


def scan(out: Path) -> Tree:
    """Inventory `out` without following a link. A missing tree is empty; a link or a file in its place is a problem."""
    tree = Tree()
    try:
        fd = os.open(out, _DIR_FLAGS)
    except FileNotFoundError:
        return tree
    except OSError as err:
        if err.errno in (errno.ELOOP, errno.ENOTDIR):
            tree.problems.append(f"{out.name}: the output directory is a symbolic link or not a directory")
        else:
            tree.problems.append(f"{out.name}: the output directory cannot be opened ({err.strerror})")
        return tree
    tree.exists = True
    try:
        _walk(fd, "", 0, tree)
    finally:
        os.close(fd)
    return tree


def _parents(paths: Mapping[str, object]) -> set[str]:
    out: set[str] = set()
    for p in paths:
        parts = p.split("/")[:-1]
        out.update("/".join(parts[: i + 1]) for i in range(len(parts)))
    return out


def check_tree(out: Path, expected: Mapping[str, Rendered]) -> list[str]:
    """Every difference between the tree and the render, one line each. [] when the tree is exactly the render."""
    tree = scan(out)
    problems = list(tree.problems)
    expected_dirs = _parents(expected)
    for path, rendered in expected.items():
        if path in tree.dirs:
            problems.append(f"{path}: a directory where a generated file belongs")
        elif path not in tree.files:
            if not any(p.startswith(path + ":") for p in tree.problems):  # a link or FIFO there is already named
                problems.append(f"{path}: missing")
        else:
            problems += compare(rendered, tree.files[path])
    for d in sorted(expected_dirs & set(tree.files)):
        problems.append(f"{d}: a file where a directory belongs")
    for path in sorted(set(tree.files) - set(expected) - expected_dirs):
        problems.append(f"{path}: unexpected file (a stale output or a stray)")
    for d in sorted(tree.dirs - expected_dirs - set(expected)):
        problems.append(f"{d}: unexpected directory")
    return problems


# -- writing -----------------------------------------------------------------------------------------------------------


def _plan(expected: Mapping[str, Rendered], tree: Tree) -> tuple[list[str], list[str], list[str]]:
    """(problems that stop the write, stale files to remove, unexpected directories to remove)."""
    problems = list(tree.problems)
    expected_dirs = _parents(expected)
    stale: list[str] = []
    for path in sorted(set(tree.files) - set(expected)):
        if has_header(tree.files[path]):
            stale.append(path)
        else:
            problems.append(f"{path}: not a generated file (it has no generated header), so it is not removed")
    for path in expected:
        if path in tree.dirs:
            problems.append(f"{path}: a directory where a generated file belongs; it is never replaced")
    stale_dirs = sorted(tree.dirs - expected_dirs - set(expected), key=lambda d: (-d.count("/"), d))
    return problems, stale, stale_dirs


def _open_dir(root_fd: int, rel: str, create: bool) -> int:
    """A descriptor for the directory `rel` under root_fd, creating it when `create`; never through a link."""
    fd = os.dup(root_fd)
    try:
        for part in [x for x in rel.split("/") if x]:
            try:
                nxt = os.open(part, _DIR_FLAGS, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o755, dir_fd=fd)
                nxt = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def _write_file(root_fd: int, rel: str, data: bytes) -> None:
    head, _, name = rel.rpartition("/")
    dir_fd = _open_dir(root_fd, head, True)
    tmp = f".{name}.{secrets.token_hex(8)}.tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644, dir_fd=dir_fd)
        try:
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view) :]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.rename(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        except BaseException:
            with contextlib.suppress(OSError):  # the original error is the one to report
                os.unlink(tmp, dir_fd=dir_fd)
            raise
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def write_tree(out: Path, expected: Mapping[str, Rendered]) -> tuple[list[str], list[str]]:
    """Make the tree exactly the render. Returns (problems, changes); with problems, nothing was changed."""
    tree = scan(out)
    problems, stale, stale_dirs = _plan(expected, tree)
    if problems:
        return problems, []
    changes: list[str] = []
    if not tree.exists:
        out.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.mkdir(out, 0o755)
        except FileExistsError:
            return [f"{out.name}: appeared while the write was starting; run it again"], []
    try:
        root_fd = os.open(out, _DIR_FLAGS)
    except OSError:
        return [f"{out.name}: the output directory cannot be opened without following a link"], []
    try:
        for path in stale:
            head, _, name = path.rpartition("/")
            dir_fd = _open_dir(root_fd, head, False)
            try:
                os.unlink(name, dir_fd=dir_fd)
            finally:
                os.close(dir_fd)
            changes.append(f"removed {path}")
        for path, rendered in expected.items():
            if tree.files.get(path) == rendered.data:
                continue
            _write_file(root_fd, path, rendered.data)
            changes.append(f"wrote {path}")
        for path in stale_dirs:
            head, _, name = path.rpartition("/")
            dir_fd = _open_dir(root_fd, head, False)
            try:
                os.rmdir(name, dir_fd=dir_fd)
            except OSError as err:
                return [f"{path}: not removed ({err.strerror})"], changes
            finally:
                os.close(dir_fd)
            changes.append(f"removed directory {path}")
    except OSError as err:
        return [f"{out.name}: the write stopped ({err.strerror})"], changes
    finally:
        os.close(root_fd)
    return [], changes
