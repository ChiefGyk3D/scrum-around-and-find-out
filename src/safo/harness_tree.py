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
  `fsync`, rename, `fsync` of the directory. Before each write, and at the end, the path from the repository root is
  resolved again component by component and must name the directory the descriptor holds, else the run fails with "the
  output directory moved during the run";
- NOTHING IS EVER DELETED. `--write` writes and updates the expected files only. A stale file (with a generated header
  or without), an unexpected directory (empty or not) and anything else not in the render is reported by name with the
  `git rm` command to run, and the exit status is 1. A header or a digest is tamper evidence for a reader, never the
  authority to remove a file. An entry that blocks a write (a link, a FIFO, a directory where a file belongs) stops the
  whole write before the first change.

POSIX only (descriptors and `dir_fd`). The walk is capped at 8 levels and 500 entries, and a file at 64 KiB, so a
hostile tree cannot make it expensive.
"""

from __future__ import annotations

import contextlib
import errno
import itertools
import os
import re
import secrets
import shlex
import stat
import unicodedata
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
_UNSAFE = "not a safe relative path (it must be non-empty, relative, and without empty, . or .. components or a NUL)"


class TreeError(ConfigError):
    """The output tree cannot be handled safely."""


@dataclass
class Tree:
    """What is on disk under the output directory: regular files with their bytes, directories, and what is wrong."""

    exists: bool = False
    files: dict[str, bytes] = field(default_factory=dict)
    ids: dict[str, tuple[int, int]] = field(default_factory=dict)  # (st_dev, st_ino) of each file as it was read
    dirs: set[str] = field(default_factory=set)
    problems: list[str] = field(default_factory=list)
    entries: int = 0


MAX_SHOWN = 120
_PLAIN = re.compile(r"[ -~]+")  # printable ASCII: the only names a ready-to-paste command is built for


def shown(name: str) -> str:
    """A name from the output tree made safe to print: control, bidi, format, line-separator and DEL characters and
    backslashes are written as \\x.., \\u.... or \\U........ escapes (so one name is always one line), leading colons
    cannot start a workflow command (`::error::`), and a long name is cut. Names come from a directory a pull request
    can fill: untrusted."""
    out = []
    for i, c in enumerate(name):
        n = ord(c)
        if c == "\\":
            out.append("\\\\")
        elif c == ":" and (i == 0 or name[:i] == ":" * i):
            out.append("\\x3a")  # a run of colons at the start: `::error::` is a workflow command
        elif n < 0x20 or n == 0x7F or unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp", "Cs", "Co", "Cn"):
            out.append(f"\\x{n:02x}" if n < 0x100 else f"\\u{n:04x}" if n < 0x10000 else f"\\U{n:08x}")
        else:
            out.append(c)
    text = "".join(out)
    return text if len(text) <= MAX_SHOWN else text[: MAX_SHOWN - 3] + "..."


def _quoted(rel: str, path: str) -> str | None:
    """The shell-quoted repository path of an entry, or None when its name needed escaping (no command then)."""
    full = f"{rel}/{path}"
    if _PLAIN.fullmatch(full) is None or shown(full) != full or len(full) > MAX_SHOWN:
        return None
    return shlex.quote(full)


def _seam(stage: str, name: str) -> None:
    """A no-op hook between two steps; a test replaces it to swap an entry at the exact moment that matters."""


def components(rel: str) -> list[str]:
    """The components of a relative path, or TreeError: no absolute path, no empty, . or .. component, no NUL."""
    parts = rel.split("/")
    if not rel or "\0" in rel or any(p in ("", ".", "..") for p in parts):
        raise TreeError(f"{rel!r}: {_UNSAFE}")
    return parts


def _verify(fd: int, parent_fd: int, name: str, walked: str) -> None:
    """The descriptor still names the directory that `name` is in its parent: same device and inode, a directory."""
    here = os.fstat(fd)
    try:
        there = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        raise TreeError(f"{shown(walked)}: changed while it was being opened") from None
    if not stat.S_ISDIR(here.st_mode) or (here.st_dev, here.st_ino) != (there.st_dev, there.st_ino):
        raise TreeError(f"{shown(walked)}: changed while it was being opened")


def open_out(root: Path, rel: str, create: bool) -> int | None:
    """A descriptor for the output directory `rel` under the trusted directory `root`, or None when it is missing.

    `root` is opened once; every component after it is opened (or made, when `create`) relative to the descriptor of the
    one above with O_NOFOLLOW | O_DIRECTORY, then checked against its parent entry. The full pathname is never opened
    again, so a symbolic link at any level is a TreeError and cannot redirect a read or a write.
    """
    parts = components(rel)
    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as err:
        raise TreeError(f"the repository root cannot be opened ({err.strerror})") from None
    walked = ""
    try:
        for part in parts:
            walked = f"{walked}/{part}" if walked else part
            _seam("before-open", walked)
            try:
                nxt = os.open(part, _DIR_FLAGS, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    os.close(fd)
                    return None
                try:
                    os.mkdir(part, 0o755, dir_fd=fd)
                    nxt = os.open(part, _DIR_FLAGS, dir_fd=fd)
                except OSError as err:
                    raise TreeError(f"{shown(walked)}: cannot be created ({err.strerror})") from None
            except OSError as err:
                if err.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise TreeError(
                        f"{shown(walked)}: a symbolic link or not a directory, so it is not followed"
                    ) from None
                raise TreeError(f"{shown(walked)}: cannot be opened ({err.strerror})") from None
            try:
                _seam("after-open", walked)
                _verify(nxt, fd, part, walked)
            except BaseException:
                os.close(nxt)
                raise
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


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


def _read_file(dir_fd: int, name: str) -> tuple[bytes, int, int] | None:
    """(at most MAX_FILE + 1 bytes, st_dev, st_ino) of the regular file `name`; None when it is not one."""
    try:
        fd = os.open(name, _FILE_FLAGS, dir_fd=dir_fd)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_FILE:
            chunk = os.read(fd, MAX_FILE + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks), info.st_dev, info.st_ino
    finally:
        os.close(fd)


def _walk(fd: int, rel: str, depth: int, tree: Tree) -> None:
    remaining = MAX_ENTRIES + 1 - tree.entries
    if remaining <= 0:
        return
    with os.scandir(fd) as it:  # at most `remaining` entries are taken from the iterator: the cap bounds the work
        entries = sorted(itertools.islice(it, remaining), key=lambda e: e.name)
    for entry in entries:
        tree.entries += 1
        if tree.entries > MAX_ENTRIES:
            if tree.entries == MAX_ENTRIES + 1:
                tree.problems.append(f"the tree has more than {MAX_ENTRIES} entries; the walk stopped")
            return
        path = f"{rel}/{entry.name}" if rel else entry.name
        sp = shown(path)
        try:
            mode = entry.stat(follow_symlinks=False).st_mode
        except OSError:
            tree.problems.append(f"{sp}: cannot be inspected")
            continue
        if stat.S_ISDIR(mode):
            if depth >= MAX_DEPTH:
                tree.problems.append(f"{sp}: the tree is deeper than {MAX_DEPTH} levels; the walk stopped here")
                continue
            try:
                sub = os.open(entry.name, _DIR_FLAGS, dir_fd=fd)
            except OSError:
                tree.problems.append(f"{sp}: a directory that cannot be opened without following a link")
                continue
            try:
                tree.dirs.add(path)
                _walk(sub, path, depth + 1, tree)
            finally:
                os.close(sub)
        elif stat.S_ISREG(mode):
            got = _read_file(fd, entry.name)
            if got is None:
                tree.problems.append(f"{sp}: changed while it was being read, or is not a regular file")
            elif len(got[0]) > MAX_FILE:
                tree.problems.append(f"{sp}: larger than {MAX_FILE // 1024} KiB")
            else:
                tree.files[path] = got[0]
                tree.ids[path] = (got[1], got[2])
        else:
            tree.problems.append(f"{sp}: {_kind(mode)}, which a generated tree never holds")


def scan(root: Path, rel: str) -> Tree:
    """Inventory `rel` under `root` without following a link. A missing tree is empty; a link or file is a problem."""
    tree = Tree()
    try:
        fd = open_out(root, rel, False)
    except TreeError as err:
        tree.problems.append(str(err))
        return tree
    if fd is None:
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


def _check_expected(expected: Mapping[str, Rendered]) -> None:
    for path in expected:
        components(path)


def check_tree(root: Path, rel: str, expected: Mapping[str, Rendered]) -> list[str]:
    """Every difference between the tree and the render, one line each. [] when the tree is exactly the render."""
    try:
        _check_expected(expected)
    except TreeError as err:
        return [str(err)]
    tree = scan(root, rel)
    problems = list(tree.problems)
    expected_dirs = _parents(expected)
    for path, rendered in expected.items():
        if path in tree.dirs:
            problems.append(f"{shown(path)}: a directory where a generated file belongs")
        elif path not in tree.files:
            if not any(p.startswith(shown(path) + ":") for p in tree.problems):  # a link or FIFO there is already named
                problems.append(f"{shown(path)}: missing")
        else:
            problems += compare(rendered, tree.files[path])
    for d in sorted(expected_dirs & set(tree.files)):
        problems.append(f"{shown(d)}: a file where a directory belongs")
    return problems + _unexpected(tree, expected, rel)


def _file_hint(rel: str, path: str) -> str:
    q = _quoted(rel, path)
    return f"remove it with: git rm -- {q}" if q else f"remove it by hand: {shown(f'{rel}/{path}')}"


def _dir_hint(rel: str, path: str) -> str:
    q = _quoted(rel, path)
    if q is None:
        return f"remove it by hand: {shown(f'{rel}/{path}')}"
    return f"remove it with: git rm -r -- {q} (an empty untracked directory: rmdir -- {q})"


def _unexpected(tree: Tree, expected: Mapping[str, Rendered], rel: str) -> list[str]:
    """The entries that are not in the render, each with the command that removes it. Nothing here deletes anything."""
    expected_dirs = _parents(expected)
    out = []
    for path in sorted(set(tree.files) - set(expected) - expected_dirs):
        what = "looks generated but is not expected" if has_header(tree.files[path]) else "not a generated file"
        out.append(f"{shown(path)}: unexpected file ({what}); it is never deleted for you; {_file_hint(rel, path)}")
    for d in sorted(tree.dirs - expected_dirs - set(expected)):
        out.append(f"{shown(d)}: unexpected directory; it is never deleted for you; {_dir_hint(rel, d)}")
    return out


# -- writing -----------------------------------------------------------------------------------------------------------


def _blocking(expected: Mapping[str, Rendered], tree: Tree) -> list[str]:
    """What stops a write before its first change: a link or special entry, or an entry in the way of a file."""
    problems = list(tree.problems)
    for path in expected:
        if path in tree.dirs:
            problems.append(f"{shown(path)}: a directory where a generated file belongs; it is never replaced")
    for d in sorted(_parents(expected) & set(tree.files)):
        problems.append(f"{shown(d)}: a file where a directory belongs; it is never replaced")
    return problems


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
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dir_fd)
        try:
            try:
                os.fchmod(fd, 0o644)  # generated docs are committed files: a fixed mode, whatever the umask
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


def _reverify(root: Path, rel: str, ident: tuple[int, int]) -> None:
    """The path from the root still resolves, with no link followed, to the directory the run holds open."""
    moved = TreeError("the output directory moved during the run")
    try:
        fd = open_out(root, rel, False)
    except TreeError:
        raise moved from None
    if fd is None:
        raise moved
    try:
        here = os.fstat(fd)
    finally:
        os.close(fd)
    if (here.st_dev, here.st_ino) != ident:
        raise moved


def write_tree(root: Path, rel: str, expected: Mapping[str, Rendered]) -> tuple[list[str], list[str]]:
    """Write the expected files. Returns (problems, changes). A problem is an entry that is not in the render (never
    deleted: the problem names the git command) or a failure. If an entry blocks the write, nothing is changed."""
    try:
        components(rel)
        _check_expected(expected)
    except TreeError as err:
        return [str(err)], []
    tree = scan(root, rel)
    blocking = _blocking(expected, tree)
    if blocking:
        return blocking + _unexpected(tree, expected, rel), []
    changes: list[str] = []
    try:
        root_fd = open_out(root, rel, True)
    except TreeError as err:
        return [str(err)], []
    if root_fd is None:
        return [f"{rel}: could not be created"], []
    try:
        held = os.fstat(root_fd)
        ident = (held.st_dev, held.st_ino)
        for path, rendered in expected.items():
            if tree.files.get(path) == rendered.data:
                continue
            _seam("write", path)
            _reverify(root, rel, ident)
            _write_file(root_fd, path, rendered.data)
            changes.append(f"wrote {path}")
        _seam("end", "")
        _reverify(root, rel, ident)
    except TreeError as err:
        return [str(err)], changes
    except OSError as err:
        return [f"{rel}: the write stopped ({err.strerror})"], changes
    finally:
        os.close(root_fd)
    return _unexpected(tree, expected, rel), changes
