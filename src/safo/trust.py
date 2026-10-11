# SPDX-License-Identifier: MIT
"""The trust policy for a local private file that carries a profile (spec section 7.2, rule 2).

This is not `guardlog.trusted_dir`. That function judges one directory, follows a symlink to it and never looks at the
file. A profile is text that ends up in files an agent obeys, so the file itself and every directory above it matter:
whoever can write to either can change what the profile says.

`trusted_regular_file(path)` walks the absolute path one component at a time from the root, each opened relative to the
directory above it without following a symlink, and judges everything on the open descriptors, not on the path:

- the file is a regular file (a FIFO is opened `O_NONBLOCK`, so it cannot hang us, and is then refused), owned by the
  effective user, and not writable by its group or by others;
- every directory above it is owned by the effective user or by root and is not writable by its group or by others,
  unless it is root-owned with the sticky bit (as `/tmp` is).

Every failure is a `ConfigError` that names the rule and never the path. A repository checkout does not go through this
policy: its files belong to the runner, and the control there is review (section 7.2, rule 1).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from safo.errors import ConfigError

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
GROUP_OR_OTHER_WRITE = stat.S_IWGRP | stat.S_IWOTH


def effective_uid() -> int:
    return os.geteuid()


def _check_directory(fd: int) -> None:
    info = os.fstat(fd)
    if info.st_uid not in (effective_uid(), 0):
        raise ConfigError("a directory above the file is not owned by this user or root")
    if info.st_mode & GROUP_OR_OTHER_WRITE and not (info.st_mode & stat.S_ISVTX and info.st_uid == 0):
        raise ConfigError("a directory above the file is writable by its group or by others")


def _check_file(fd: int) -> None:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        raise ConfigError("the file is not a regular file")
    if info.st_uid != effective_uid():
        raise ConfigError("the file is not owned by this user")
    if info.st_mode & GROUP_OR_OTHER_WRITE:
        raise ConfigError("the file is writable by its group or by others")


def _open_checked(path: Path) -> int:
    """A descriptor for the file, opened through checked directories; the caller closes it."""
    parts = Path(os.path.abspath(path)).parts
    dir_fd: int | None = None
    try:
        dir_fd = os.open(parts[0], _DIR_FLAGS)
        _check_directory(dir_fd)
        for part in parts[1:-1]:
            nxt = os.open(part, _DIR_FLAGS, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = nxt
            _check_directory(dir_fd)
        file_fd = os.open(parts[-1], _FILE_FLAGS, dir_fd=dir_fd)
    except OSError:
        raise ConfigError(
            "the file cannot be opened without following a symbolic link (a link, a missing path or no permission)"
        ) from None
    finally:
        if dir_fd is not None:
            os.close(dir_fd)
    try:
        _check_file(file_fd)
    except BaseException:
        os.close(file_fd)
        raise
    return file_fd


def trusted_regular_file(path: Path) -> None:
    """Raise ConfigError unless `path` passes the policy above; return None when it does."""
    os.close(_open_checked(path))


def read_trusted_regular_file(path: Path, limit: int) -> bytes:
    """The bytes of a file that passes the policy, judged on the descriptor that is read; at most `limit` bytes."""
    fd = _open_checked(path)
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65_536, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                break
    except OSError:
        raise ConfigError("the file cannot be read") from None
    finally:
        os.close(fd)
    if total > limit:
        raise ConfigError(f"the file is larger than {limit} bytes")
    return b"".join(chunks)
