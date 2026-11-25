# SPDX-License-Identifier: Apache-2.0
"""The process, environment and file plumbing of `safo-file` (issue #443), kept apart from its rules.

Nothing here reads a secret or edits a shared module; the checks that `safo.credentials` does not make are made here:

* `child_env`: a minimal ALLOWLIST, one per child. The memory command gets PATH, HOME, USER, LOGNAME, LANG, LC_*, TERM
  and TZ; `gh` also gets the XDG_* names, DBUS_SESSION_BUS_ADDRESS and GH_CONFIG_DIR (a stored or keyring login), never
  GH_HOST. PATH keeps only absolute directories that pass the directory trust policy (else /usr/bin:/bin). `SAFO_*`,
  cloud credentials, private-key variables and `GH_TOKEN`-style variables never reach either child.
* `trusted_executable`: an absolute path, not inside the working directory, a regular executable file, and neither it
  nor any directory above it (before or after resolving links) owned by another user (root is fine) or writable by
  its group or others (a root-owned sticky DIRECTORY such as /tmp is fine; a file never gets that exemption).
* `run_bounded`: one child in its own session, stdin from a pipe or nothing, stdout and stderr read in pieces up to a
  cap, a deadline. After a normal exit nothing is signalled; on a timeout or a cap the whole process group is killed
  BEFORE the leader is reaped, then reaped (a descendant holding a pipe included).
* `open_ledger`: the ledger opened through directory descriptors, no link followed at any component, the parent
  owned by the effective user and not group/other-writable, the file created 0600 and checked on the descriptor.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from safo.errors import SafoError

ENV_BASE = frozenset({"PATH", "HOME", "USER", "LOGNAME", "LANG", "TERM", "TZ"})
ENV_GH_EXTRA = frozenset(
    {
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "XDG_CACHE_HOME",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",  # a keyring-stored gh login is reached through it
        "GH_CONFIG_DIR",
    }
)
FALLBACK_PATH = "/usr/bin:/bin"
REAP_SECONDS = 5
READ_PIECE = 65_536
GROUP_OR_OTHER_WRITE = stat.S_IWGRP | stat.S_IWOTH
SAFE_LC = re.compile(r"LC_[A-Z_]{1,30}")


def effective_uid() -> int:
    return os.geteuid()


def _untrusted(info: os.stat_result | SimpleNamespace, *, directory: bool) -> str:
    """Why this is not trusted, or "". Only a root-owned sticky DIRECTORY may be group or other writable."""
    if info.st_uid not in (effective_uid(), 0):
        return "owned by another user"
    sticky_root = directory and info.st_mode & stat.S_ISVTX and info.st_uid == 0
    if info.st_mode & GROUP_OR_OTHER_WRITE and not sticky_root:
        return "writable by its group or by others"
    return ""


def _dir_trusted(path: str) -> bool:
    """The directory and every directory above it pass the trust policy."""
    for target in (*_chain(path), path):
        try:
            info = os.stat(target)
        except OSError:
            return False
        if not stat.S_ISDIR(info.st_mode) or _untrusted(info, directory=True):
            return False
    return True


def absolute_path(value: str) -> str:
    return os.pathsep.join(e for e in value.split(os.pathsep) if e and os.path.isabs(e))


def lookup_env(env: Mapping[str, str]) -> dict[str, str]:
    """Only used to FIND an executable: absolute PATH entries; the executable itself then passes trusted_executable."""
    return {"PATH": absolute_path(env.get("PATH", ""))}


def child_env(env: Mapping[str, str], kind: str) -> dict[str, str]:
    """The allowlisted environment for `kind` ("gh" or "memory"); PATH keeps only trusted absolute directories."""
    allowed = ENV_BASE | ENV_GH_EXTRA if kind == "gh" else ENV_BASE
    out = {k: v for k, v in env.items() if k in allowed or SAFE_LC.fullmatch(k)}
    kept = [e for e in absolute_path(out.get("PATH", "")).split(os.pathsep) if e and _dir_trusted(e)]
    out["PATH"] = os.pathsep.join(kept) or FALLBACK_PATH
    return out


def _chain(path: str) -> list[str]:
    parts = Path(path).parts
    return [str(Path(*parts[: i + 1])) for i in range(len(parts) - 1)]  # every directory above the file


def trusted_executable(path: str, what: str) -> str:
    """The absolute, resolved path of an executable fit to run, or a SafoError that names the rule."""
    if not os.path.isabs(path):
        raise SafoError(f"{what} must be an absolute path")
    real = os.path.realpath(path)
    cwd = os.path.realpath(os.getcwd())
    if real == cwd or real.startswith(cwd.rstrip(os.sep) + os.sep):
        raise SafoError(f"{what} is inside the current directory")
    if not (os.path.isfile(real) and os.access(real, os.X_OK)):
        raise SafoError(f"{what} is not an executable file")
    for candidate in (real, os.path.normpath(path)):
        for target in (*_chain(candidate), candidate):
            try:
                info = os.stat(target)
            except OSError:
                raise SafoError(f"{what} cannot be checked") from None
            bad = _untrusted(info, directory=target != candidate)
            if bad:
                raise SafoError(f"{what}: {Path(target).name or target} is {bad}")
    return real


def resolve_command(name: str, env: Mapping[str, str], what: str) -> str:
    """A command word to a trusted absolute executable: a path must already be absolute, a bare name is looked up on
    the absolute PATH entries; both then pass `trusted_executable`."""
    if "/" in name:
        return trusted_executable(name, what)
    found = shutil.which(name, path=lookup_env(env)["PATH"])
    if not found:
        raise SafoError(f"{what} was not found on PATH")
    return trusted_executable(found, what)


@dataclass
class Ran:
    rc: int | None
    out: bytes
    err: bytes
    out_capped: bool
    err_capped: bool
    timed_out: bool


def run_bounded(
    argv: Sequence[str],
    *,
    env: Mapping[str, str],
    stdin_text: str = "",
    out_cap: int,
    err_cap: int,
    timeout: float,
) -> Ran:
    """Run one child to completion, or until a cap or the deadline; its process group never outlives the call.
    `err_cap` 0 sends stderr to nowhere."""
    try:
        proc = subprocess.Popen(  # noqa: S603 - a fixed argument list, an absolute executable, no shell
            list(argv),
            stdin=subprocess.PIPE if stdin_text else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE if err_cap else subprocess.DEVNULL,
            env=dict(env),
            start_new_session=True,
        )
    except OSError as problem:
        raise SafoError(f"the command could not start: {problem.strerror}") from None
    sel = selectors.DefaultSelector()
    bufs = {"out": b"", "err": b""}
    caps = {"out": out_cap, "err": err_cap}
    capped = {"out": False, "err": False}
    pending = stdin_text.encode()
    sent = 0
    timed_out = False
    deadline = time.monotonic() + timeout
    streams = {"out": proc.stdout, "err": proc.stderr if err_cap else None}
    need_kill = True  # until the leader has exited by itself and been reaped, its group may still hold descendants
    try:
        if proc.stdin is not None:
            os.set_blocking(proc.stdin.fileno(), False)
            sel.register(proc.stdin, selectors.EVENT_WRITE, "in")
        for name, stream in streams.items():
            if stream is not None:
                sel.register(stream, selectors.EVENT_READ, name)
        stop = False
        while sel.get_map() and not stop:
            left = deadline - time.monotonic()
            if left <= 0:
                timed_out = True
                break
            for key, _ in sel.select(left):
                name = key.data
                if name == "in":
                    assert proc.stdin is not None  # noqa: S101 - registered only when it exists
                    try:
                        sent += os.write(proc.stdin.fileno(), pending[sent : sent + READ_PIECE])
                    except BlockingIOError:
                        continue
                    except OSError:
                        sent = len(pending)
                    if sent >= len(pending):
                        sel.unregister(proc.stdin)
                        proc.stdin.close()
                    continue
                stream = streams[name]
                assert stream is not None  # noqa: S101 - registered only when it exists
                chunk = os.read(stream.fileno(), caps[name] + 1 - len(bufs[name]))
                if not chunk:
                    sel.unregister(stream)
                    continue
                bufs[name] += chunk
                if len(bufs[name]) > caps[name]:
                    capped[name] = True
                    bufs[name] = bufs[name][: caps[name]]
                    stop = True
        if not (timed_out or stop):
            try:
                proc.wait(timeout=max(0.1, min(REAP_SECONDS, deadline - time.monotonic())))
            except subprocess.TimeoutExpired:
                timed_out = True
            else:
                need_kill = False  # a normal exit reaped the leader; the group is never signalled afterwards
    finally:
        sel.close()
        if need_kill:  # the leader is not reaped yet, so its pid cannot name another group
            with contextlib.suppress(OSError):
                os.killpg(proc.pid, signal.SIGKILL)
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream is not None:
                with contextlib.suppress(OSError):
                    stream.close()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=REAP_SECONDS)
    return Ran(proc.returncode, bufs["out"], bufs["err"], capped["out"], capped["err"], timed_out)


def write_all(fd: int, data: bytes, write=os.write) -> None:  # type: ignore[no-untyped-def]
    """Write every byte of one record, looping over short writes and retrying an interrupted one without advancing.
    An exclusive lock on the descriptor is held for the whole record, so concurrent writers cannot interleave."""
    view = memoryview(data)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        while view:
            try:
                n = write(fd, view)
            except InterruptedError:
                continue
            if n <= 0:
                raise OSError("no progress writing")
            view = view[n:]
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)


def open_ledger(path: Path) -> int:
    """A descriptor to append to; see the module docstring. Every failure is a SafoError and nothing was filed."""
    flags_dir = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parts = Path(os.path.abspath(path)).parts
    fd = -1
    try:
        dir_fd = os.open(parts[0], flags_dir)
        try:
            for i, part in enumerate(parts[1:-1], start=1):
                try:
                    nxt = os.open(part, flags_dir, dir_fd=dir_fd)
                except FileNotFoundError:
                    os.mkdir(part, 0o700, dir_fd=dir_fd)
                    nxt = os.open(part, flags_dir, dir_fd=dir_fd)
                os.close(dir_fd)
                dir_fd = nxt
                last = i == len(parts) - 2
                info = os.fstat(dir_fd)
                if last and info.st_uid != effective_uid():
                    raise SafoError("the ledger directory is not owned by this user")
                bad = _untrusted(info, directory=True)
                if bad:
                    raise SafoError(f"a directory above the ledger is {bad}")
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            fd = os.open(parts[-1], flags, 0o600, dir_fd=dir_fd)
        finally:
            os.close(dir_fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise SafoError("the ledger is not a regular file")
        if info.st_uid != effective_uid():
            raise SafoError("the ledger is not owned by this user")
        if info.st_mode & GROUP_OR_OTHER_WRITE:
            raise SafoError("the ledger is writable by its group or by others")
    except SafoError:
        if fd >= 0:
            os.close(fd)
        raise
    except OSError as problem:
        if fd >= 0:
            os.close(fd)
        raise SafoError(f"the ledger cannot be opened for appending ({problem.strerror})") from None
    return fd
