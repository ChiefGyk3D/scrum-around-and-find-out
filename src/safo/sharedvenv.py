# SPDX-License-Identifier: Apache-2.0
"""safo-shared-venv: one read-only, hash-locked venv per lockfile, shared by every agent (#534, epic #518).

`safo-shared-venv LOCKFILE` prints the interpreter of a venv keyed by the lockfile's sha256 together with the trusted
interpreter identity and the acquisition policy. A missing venv is built under a file lock (two callers never build the
same one), from `pip install --require-hashes --no-deps` only, never with system site-packages, then made read-only and
renamed into place in one step. A changed lockfile is a new key, so a new venv; the old one stays until
`--gc --max-age-days N` lists it (and `--delete` removes it).

Trust boundary: the shared root must be owned by the current user and not writable by any other account. A hostile
process running as the same user is out of scope (filesystem modes cannot authenticate against it). The lockfile content
is trusted input: its hashes are the trust anchor. The strict grammar defends against parser smuggling and malformed
input, not against a hostile but valid lockfile.
Exit codes: 0 done, 1 a build or lock failure, 2 a refusal or bad usage.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import functools
import hashlib
import json
import math
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import NoReturn, ParamSpec, TypeVar

ROOT_ENV = "SAFO_SHARED_VENV_ROOT"
EXIT_OK, EXIT_FAIL, EXIT_REFUSED = 0, 1, 2
MARKER = ".safo-lock-sha256"
BUILD_MARK = ".safo-build"
BUILD_NAME = re.compile(r"\.build-[A-Za-z0-9_]{8}")
KEY = re.compile(r"[0-9a-f]{64}")
MAX_LOCKFILE = 4 * 1024 * 1024
LOCK_TIMEOUT = 900.0
VENV_TIMEOUT = 600.0
PIP_TIMEOUT = 1800.0
IDENTITY_TIMEOUT = 60.0
STAGE_PREFIX = ".stage-"
BUILD_MARK_TEXT = "safo-shared-venv build 1\n"
_MARKER_RE = re.compile(rb"[0-9a-f]{64}\n[0-9a-f]{64}\n")
STAGE_NAME = re.compile(r"\.stage-[A-Za-z0-9_]{8}")
MAX_AGE_DAYS = 36500.0
MAX_TIMEOUT = 7 * 86400.0
IDENTITY_CODE = (
    "import json,os,sys,sysconfig\n"
    "try:\n    import ensurepip; pip = ensurepip.version()\nexcept Exception:\n    pip = 'none'\n"
    "print(json.dumps([sys.implementation.name, list(sys.version_info[:2]), sys.implementation.cache_tag,"
    " sysconfig.get_platform(), getattr(sys, 'abiflags', ''), pip,"
    " os.path.realpath(getattr(sys, '_base_executable', sys.executable))]))\n"
)


def parse_marker(data: bytes) -> tuple[str, str] | None:
    """The lock marker is exactly two 64-hex lines, each ending in a newline, and nothing else, or it is not ours."""
    if not _MARKER_RE.fullmatch(data):
        return None
    key, manifest_hex = data.decode("ascii").split("\n")[:2]
    return key, manifest_hex


class Refused(Exception):
    """A lockfile, location or venv this command will not use."""


class Failed(Exception):
    """A build or lock step failed."""


_P = ParamSpec("_P")
_R = TypeVar("_R")


def _boundary(func: Callable[_P, _R]) -> Callable[_P, _R]:
    """Across a public boundary only fixed errors leave, and never with a cause or a context.

    A Refused or Failed is re-raised as a fresh copy of itself (its text is already fixed). A filesystem error becomes a
    Failed carrying the errno number only; any other unexpected error becomes a Failed carrying the class name only.
    The new error is raised after the handler has ended, so nothing the original carried (a path, a message) is chained.
    """

    @functools.wraps(func)
    def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        kind: type[Exception] = Failed
        text = ""
        try:
            return func(*args, **kwargs)
        except (Refused, Failed) as exc:
            kind, text = type(exc), str(exc)
        except OSError as exc:
            text = f"a filesystem operation failed (errno {exc.errno})"
        except Exception as exc:
            text = f"an unexpected error occurred ({type(exc).__name__})"
        raise kind(text)

    return wrapper


def check_plain(value: str | os.PathLike[str]) -> None:
    """Refuse whitespace, control and non-printable characters in a caller-supplied argument, with a fixed message."""
    text = os.fspath(value)
    if not text.isprintable() or any(ch.isspace() for ch in text):
        raise Refused("an argument holds whitespace, control or non-printable characters")


def default_root(env: dict[str, str] | os._Environ[str] = os.environ) -> Path:
    if env.get(ROOT_ENV):
        return Path(env[ROOT_ENV])
    return Path(env.get("HOME", str(Path.home()))) / ".local" / "share" / "safo-venvs"


def read_lockfile(path: Path) -> bytes:
    """Read the lockfile once, through one descriptor, refusing a symbolic link or a special file."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as exc:
        raise Refused("the lockfile cannot be opened (a symbolic link or missing?)") from exc
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise Refused("the lockfile is not a regular file")
        data = handle.read(MAX_LOCKFILE + 1)
    if len(data) > MAX_LOCKFILE:
        raise Refused("the lockfile is larger than 4 MiB")
    return data


_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
_VERSION = r"[0-9][A-Za-z0-9.!+_]*"
_ENTRY = re.compile(rf"{_NAME}=={_VERSION}(?: --hash=sha256:[0-9a-f]{{64}})+")
_REFUSED_CHARS = ("$", "\r", chr(0), "\t")


def check_hashes(data: bytes) -> int:
    """Accept only a strict grammar and return the requirement count; refuse everything else.

    A line is blank, `# comment` at column 0 (no backslash), or part of one entry: `name==version` then one or more
    `--hash=sha256:HEX`, split across lines only by a trailing backslash. No other token, no `$`, `@`, URL, extra,
    marker, option, tab, carriage return, NUL or comment inside an entry, so no parser can read the file differently.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Refused("the lockfile is not UTF-8") from exc
    if any(ch in text for ch in _REFUSED_CHARS):
        raise Refused("the lockfile holds a character this command refuses ($, tab, carriage return or NUL)")
    count = 0
    pending: list[str] = []
    for number, raw in enumerate(text.split("\n"), 1):
        continued = raw.endswith("\\")
        body = raw[:-1] if continued else raw
        plain_comment = not pending and body.startswith("#") and not continued
        if "\\" in body or ("#" in body and not plain_comment):
            raise Refused(f"line {number}: a backslash or comment where the grammar allows none")
        if plain_comment or (not pending and not continued and not body.strip(" ")):
            continue
        if not pending and body != body.lstrip(" "):
            raise Refused(f"line {number}: an entry may not start with a space")
        pending.append(body.strip(" "))
        if continued:
            continue
        joined = " ".join(part for part in pending if part)
        pending = []
        if not _ENTRY.fullmatch(joined):
            raise Refused(f"line {number}: not `name==version` with sha256 hashes")
        count += 1
    if pending:
        raise Refused("the lockfile ends inside a continued line")
    if count == 0:
        raise Refused("the lockfile holds no requirements")
    return count


_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HTTPS = re.compile(
    rf"https://(?P<host>{_LABEL}(?:\.{_LABEL})*)(?::(?P<port>[0-9]{{1,5}}))?(?P<path>/[A-Za-z0-9._~/+-]*)"
)
_LOCAL = re.compile(r"/[A-Za-z0-9._/+-]*")
MAX_SOURCE = 1024
_PIP_FLAGS = ("--index-url", "--find-links")


def source_is_allowed(value: str) -> bool:
    """True only for the two whitelisted forms; nothing is parsed, anything else is simply not allowed.

    (a) `https://HOST[:PORT]/PATH`: HOST a lowercase DNS name or IPv4 address, PORT 1 to 65535, PATH from
        `[A-Za-z0-9._~/+-]`; (b) an absolute local directory path from `[A-Za-z0-9._/+-]`. Neither may hold a `..`
        segment or `//`. No userinfo, query, fragment, percent-encoding, IPv6, other scheme or relative path.
    """
    if not isinstance(value, str) or not value or len(value) > MAX_SOURCE:
        return False
    match = _HTTPS.fullmatch(value)
    if match:
        host, port, path = match["host"], match["port"], match["path"]
        if len(host) > 253 or (port is not None and not 1 <= int(port) <= 65535):
            return False
    elif _LOCAL.fullmatch(value):
        path = value
    else:
        return False
    return "//" not in path and ".." not in path.split("/")


def check_source(value: str) -> str:
    if not source_is_allowed(value):
        # the value is never echoed: it may carry a secret
        raise Refused("an index or links value must be https://HOST[:PORT]/PATH or an absolute local directory path")
    return value


def parse_pip_args(pip_args: Sequence[str]) -> list[str]:
    """Accept only `--no-index`, `--index-url SOURCE` and `--find-links SOURCE`; return the validated sources."""
    urls: list[str] = []
    items = list(pip_args)
    i = 0
    while i < len(items):
        if items[i] == "--no-index":
            i += 1
        elif items[i] in _PIP_FLAGS and i + 1 < len(items):
            urls.append(check_source(items[i + 1]))
            i += 2
        else:
            raise Refused("an acquisition argument outside --no-index, --index-url SOURCE and --find-links SOURCE")
    return urls


def check_timeout(value: float) -> float:
    if isinstance(value, bool) or not (math.isfinite(value) and 0 <= value <= MAX_TIMEOUT):
        raise Refused(f"the lock timeout must be a finite number of seconds from 0 to {MAX_TIMEOUT:g}")
    return value


def _check_chain(path: Path, what: str) -> None:
    """Every existing ancestor of `path`: a real directory (no symbolic link), owned by this user or root, not writable
    by group or others (a root-owned sticky directory such as /tmp is the one allowed exception)."""
    for ancestor in reversed(Path(os.path.abspath(path)).parents):
        try:
            info = ancestor.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise Refused(f"a symbolic link on the path to {what}")
        if not stat.S_ISDIR(info.st_mode):
            raise Refused(f"a non-directory on the path to {what}")
        if info.st_uid not in (os.geteuid(), 0):
            raise Refused(f"an ancestor of {what} is owned by another user")
        if info.st_mode & 0o022 and not (info.st_mode & stat.S_ISVTX and info.st_uid == 0):
            raise Refused(f"an ancestor of {what} is writable by group or others")


def _check_ancestors(root: Path) -> None:
    _check_chain(root, "the venv root")


class RootHandle:
    """The validated root held by descriptor; `check()` refuses if the path now names a different directory."""

    def __init__(self, path: Path, fd: int, ident: tuple[int, int]) -> None:
        self.path, self.fd, self.ident = path, fd, ident

    def check(self) -> None:
        try:
            info = self.path.lstat()
        except OSError as exc:
            raise Refused("the venv root was replaced or removed") from exc
        if stat.S_ISLNK(info.st_mode) or (info.st_dev, info.st_ino) != self.ident:
            raise Refused("the venv root was replaced after it was validated")

    def close(self) -> None:
        os.close(self.fd)


def _after_mkdir(path: Path) -> None:
    """A seam right after a root component is created (replaced by a test)."""


def _make_missing(root: Path) -> None:
    """Create each missing component one at a time (mode 0700), verifying every one by lstat after creating it."""
    absolute = Path(os.path.abspath(root))
    missing: list[Path] = []
    for candidate in (absolute, *absolute.parents):
        if os.path.lexists(candidate):
            break
        missing.append(candidate)
    for component in reversed(missing):
        with contextlib.suppress(FileExistsError):  # another agent made it first: verified like our own below
            os.mkdir(component, 0o700)
        _after_mkdir(component)
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            raise Refused("a venv root component is not a plain directory of this user")


@_boundary
def open_root(root: Path) -> RootHandle:
    check_plain(root)
    _check_ancestors(root)
    if root.is_symlink():
        raise Refused("the venv root is a symbolic link")
    _make_missing(root)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise Refused("the venv root is not a directory")
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise Refused("the venv root must be owned by this user and not writable by others")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    held = os.fstat(fd)
    handle = RootHandle(root, fd, (held.st_dev, held.st_ino))
    try:
        if (held.st_dev, held.st_ino) != (info.st_dev, info.st_ino):
            raise Refused("the venv root changed while it was opened")
        _check_ancestors(root)
        handle.check()
    except Refused:
        handle.close()
        raise
    return handle


def _after_flock(path: Path) -> None:
    """A seam between taking the flock and checking which file it is on (replaced by a test)."""


class Lock:
    """An exclusive flock on `root/.lock`, waited for in bounded polls.

    After the flock is taken, the descriptor is compared with the path; if the file was replaced meanwhile, the lock is
    dropped and taken again on the new file. This narrows the race for a same-user writer, it does not remove it.
    """

    def __init__(self, root: Path, timeout: float) -> None:
        self.path, self.timeout, self.fd = root / ".lock", check_timeout(timeout), -1

    @_boundary
    def __enter__(self) -> Lock:
        deadline = time.monotonic() + self.timeout
        while True:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(fd)
                if time.monotonic() >= deadline:
                    raise Failed("timed out waiting for the venv lock") from None
                time.sleep(0.05)
                continue
            _after_flock(self.path)
            try:
                same = os.fstat(fd).st_ino == os.stat(self.path, follow_symlinks=False).st_ino
            except OSError:
                same = False
            if same:
                self.fd = fd
                return self
            os.close(fd)  # the lock file was replaced while we waited: lock the new one
            if time.monotonic() >= deadline:
                raise Failed("timed out waiting for the venv lock")

    def __exit__(self, *exc: object) -> None:
        os.close(self.fd)  # closing releases the flock


def _walk_chmod(path: Path, writable: bool) -> None:
    """Add or remove the write bit on a tree, never following a symbolic link."""
    for here, dirs, files in os.walk(path, topdown=writable, followlinks=False):
        for name in [*dirs, *files, ""]:
            target = Path(here) / name if name else Path(here)
            if target.is_symlink():
                continue
            mode = target.stat().st_mode
            target.chmod(mode | 0o200 if writable else mode & ~0o222)


def _remove_tree(path: Path) -> None:
    if path.is_symlink():
        path.unlink()
        return
    _walk_chmod(path, True)
    shutil.rmtree(path)


def _clean_env(home: Path) -> dict[str, str]:
    """An allowlist for the children: the caller's secrets and pip settings never reach them."""
    env = {name: os.environ[name] for name in ("PATH", "LANG", "LC_ALL") if name in os.environ}
    env["HOME"] = str(home)
    env["PIP_CONFIG_FILE"] = os.devnull
    return env


def _exe_signature(resolved: str) -> tuple[str, int, int, int]:
    """Open the interpreter file once (no symbolic link), refuse it unless it and every ancestor directory belong to
    root or this user and are not writable by group or others, and return its sha256, inode, device and mtime."""
    try:
        fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise Refused("the interpreter cannot be opened (a symbolic link or missing?)") from exc
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise Refused("the interpreter is not a regular file")
        if info.st_uid not in (os.geteuid(), 0):
            raise Refused("the interpreter is owned by another user")
        if info.st_mode & 0o022:
            raise Refused("the interpreter is writable by group or others")
        _check_chain(Path(resolved), "the interpreter")
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    return digest, info.st_ino, info.st_dev, info.st_mtime_ns


Signature = tuple[str, int, int, int]


def _run_child(
    cmd: Sequence[str], *, env: dict[str, str], timeout: float, pass_fds: tuple[int, ...] = ()
) -> tuple[int | None, bytes, bytes]:
    """Run a child with its output captured. Returns (status, stdout, stderr); the status is None on a timeout.

    A timeout exception carries the partial output and the command line, so it is never allowed to escape: it is
    caught, emptied, and the caller raises its own fixed error outside the handler (no cause, no context).
    """
    timed_out = False
    done: subprocess.CompletedProcess[bytes] | None = None
    try:
        done = subprocess.run(  # noqa: S603 - fixed argument list built here, no shell
            list(cmd), env=env, timeout=timeout, capture_output=True, pass_fds=pass_fds, check=False
        )
    except subprocess.TimeoutExpired as exc:
        exc.stdout = exc.stderr = exc.output = None
        exc.cmd = ""
        timed_out = True
    if timed_out or done is None:
        return None, b"", b""
    return done.returncode, done.stdout, done.stderr


def identity(python: str) -> tuple[str, Signature, list[object]]:
    """Resolve the interpreter once to its final real path, record its signature and run ONLY that path."""
    found = shutil.which(python)
    if found is None or not os.access(found, os.X_OK):
        raise Refused("the interpreter does not exist or is not executable")
    resolved = os.path.realpath(found)
    signature = _exe_signature(resolved)
    report: list[object] | None = None
    try:
        code, out, _ = _run_child(
            [resolved, "-I", "-c", IDENTITY_CODE], env=_clean_env(Path("/nonexistent")), timeout=IDENTITY_TIMEOUT
        )
        if code == 0:
            lines = out.decode(errors="replace").strip().splitlines()
            report = json.loads(lines[-1]) if lines else None
    except (OSError, ValueError):
        report = None
    if not isinstance(report, list):
        raise Refused("the interpreter did not report its identity")
    return resolved, signature, report


def cache_key(lock_sha: str, python: str, pip_args: Sequence[str]) -> tuple[str, str, Signature, str, Signature]:
    """The key, the resolved interpreter, its signature, the base interpreter it builds on and that signature.

    The key covers the lockfile hash, the interpreter identity (with the sha256 of its file and of its base) and the
    acquisition policy.
    """
    resolved, signature, report = identity(python)
    base = str(report[-1])
    base_signature = _exe_signature(base)
    record = {
        "lock": lock_sha, "python": resolved, "exe": signature[0], "base": [base, base_signature[0]],
        "identity": report, "policy": list(pip_args),
    }  # fmt: skip
    key = hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return key, resolved, signature, base, base_signature


def verify_interpreter(resolved: str, signature: Signature) -> None:
    if _exe_signature(resolved) != signature:
        raise Refused("the interpreter changed after its identity was read")


def verify_base(venv: Path, base: str, base_signature: Signature) -> None:
    """The venv's python must still resolve to the recorded base interpreter, and that file must be unchanged."""
    real = os.path.realpath(interpreter(venv))
    if real != base:
        raise Refused("the venv python no longer resolves to the recorded base interpreter")
    if _exe_signature(base) != base_signature:
        raise Refused("the base interpreter changed after its identity was read")


def interpreter(venv: Path) -> Path:
    return venv / "bin" / "python"


def _trusted(path: Path, what: str, *, kind: str = "file") -> os.stat_result:
    """lstat a venv member and refuse a symbolic link (unless allowed), a foreign owner or group/world write."""
    info = path.lstat()
    is_link = stat.S_ISLNK(info.st_mode)
    if kind == "dir" and not stat.S_ISDIR(info.st_mode):
        raise Refused(f"{what} is not a plain directory (a symbolic link?)")
    if kind == "file" and not stat.S_ISREG(info.st_mode):
        raise Refused(f"{what} is not a plain file (a symbolic link?)")
    if info.st_uid != os.geteuid():
        raise Refused(f"{what} is not owned by this user")
    if not is_link and info.st_mode & 0o222:
        raise Refused(f"{what} is writable")
    return info


def manifest(venv: Path, skip: frozenset[str] = frozenset({MARKER})) -> str:
    """sha256 over the sorted (relative path, size, mode) list of the venv, refusing foreign or writable members.

    Detects accidental or cross-account damage; a same-user attacker can rewrite the marker as well.
    """
    rows: list[str] = []
    for here, dirs, files in os.walk(venv, followlinks=False):
        for name in [*dirs, *files]:
            path = Path(here) / name
            rel = str(path.relative_to(venv))
            if rel in skip:
                continue
            info = path.lstat()
            if info.st_uid != os.geteuid():
                raise Refused("a member is not owned by this user")
            if not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o222:
                raise Refused("a member is writable")
            size = 0 if stat.S_ISDIR(info.st_mode) else info.st_size
            rows.append(f"{rel}\0{size}\0{info.st_mode:o}")
    return hashlib.sha256("\n".join(sorted(rows)).encode()).hexdigest()


@_boundary
def valid(venv: Path, key: str) -> None:
    """Refuse a venv entry that is not exactly what a finished build leaves (layout, owner, modes, marker, manifest)."""
    if not venv.is_symlink() and not venv.exists():
        raise Refused("the venv entry does not exist")
    _trusted(venv, "the venv entry", kind="dir")
    marker = venv / MARKER
    _trusted(marker, "the lock marker")
    if marker.stat().st_size > 200:
        raise Refused("the venv has no matching lock marker")
    parsed = parse_marker(marker.read_bytes())
    if parsed is None or parsed[0] != key:
        raise Refused("the venv has no matching lock marker")
    cfg = venv / "pyvenv.cfg"
    _trusted(cfg, "pyvenv.cfg")
    if re.search(r"(?im)^include-system-site-packages\s*=\s*true", cfg.read_text()):
        raise Refused("the venv includes system site-packages")
    python = interpreter(venv)
    if not python.exists():
        raise Refused("the venv has no interpreter")
    if python.lstat().st_uid != os.geteuid():
        raise Refused("the venv interpreter link is not owned by this user")
    if manifest(venv) != parsed[1]:
        raise Refused("the venv does not match its build manifest")


def _seal(venv: Path) -> None:
    """Remove every write bit below the top directory (the top is renamed first, then sealed)."""
    for here, dirs, files in os.walk(venv, topdown=False, followlinks=False):
        for name in [*dirs, *files]:
            target = Path(here) / name
            if not target.is_symlink():
                target.chmod(target.stat().st_mode & ~0o222)


def _fd_bytes(fd: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks = []
    while chunk := os.read(fd, 1 << 20):
        chunks.append(chunk)
    return b"".join(chunks)


def _pip_failure(root: Path, key: str, status: int, output: bytes, keep: bool) -> str:
    """The fixed failure text; pip's full output goes to a private 0600 file in the root only when asked for."""
    text = f"the install step failed: pip exited with status {status}"
    if not keep:
        return text + " (its output was discarded; --keep-pip-log keeps it in a private file)"
    log = root / f"pip-{key[:12]}-{secrets.token_hex(4)}.log"
    fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(output)
    return (
        text
        + f"; its full output, which may contain credentials, is in the venv root as {log.name}"
        + " (delete it after reading)"
    )


def _describe(exc: BaseException) -> str:
    """A failure text without a command line, so no argument (a URL with a token) can leak through it."""
    if isinstance(exc, subprocess.CalledProcessError):
        return f"a child process exited with status {exc.returncode}"
    if isinstance(exc, subprocess.SubprocessError):
        return type(exc).__name__
    return f"{type(exc).__name__} (errno {getattr(exc, 'errno', None)})"


def build(
    root: Path,
    key: str,
    data: bytes,
    python: str,
    pip_args: Sequence[str],
    expected_sha: str | None = None,
    handle: RootHandle | None = None,
    keep_pip_log: bool = False,
) -> None:
    """Build from the checked bytes `data`: pip reads a private copy through an open descriptor, not the caller's file.

    The venv is staged as a sibling of its final name (`root/.stage-RANDOM`), fully sealed including its top directory,
    and only then renamed into place, so an interruption leaves an unpublished stage or an already sealed entry, never
    a writable published one. Child output is never relayed and never chained into an exception.
    """
    expected = expected_sha or hashlib.sha256(data).hexdigest()
    final = root / key
    if handle:
        handle.check()
    work = Path(tempfile.mkdtemp(prefix=".build-", dir=root))  # mode 0700, random name
    stage = root / (STAGE_PREFIX + work.name[len(".build-") :])
    fd = -1
    published = False
    failure: str | None = None
    try:
        try:
            mark_fd = os.open(
                work / BUILD_MARK, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
            )
            os.write(mark_fd, BUILD_MARK_TEXT.encode())
            os.close(mark_fd)
            home = work / "home"
            home.mkdir(mode=0o700)
            fd = os.open(work / "req.txt", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.write(fd, data)
            if hashlib.sha256(_fd_bytes(fd)).hexdigest() != expected:
                raise Refused("the private lockfile copy does not match the checked hash")
            req = f"/proc/self/fd/{fd}" if Path("/proc/self/fd").is_dir() else str(work / "req.txt")
            env = _clean_env(home)
            code, _, _ = _run_child([python, "-m", "venv", "--clear", str(stage)], env=env, timeout=VENV_TIMEOUT)
            if code is None:
                raise Failed("the venv step timed out")
            if code != 0:
                raise Failed(f"the venv step failed: the interpreter exited with status {code}")
            stage_mark = os.open(
                stage / BUILD_MARK, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
            )
            os.write(stage_mark, BUILD_MARK_TEXT.encode())
            os.close(stage_mark)
            install = [
                str(interpreter(stage)), "-I", "-m", "pip", "--isolated", "install", "--no-input",
                "--disable-pip-version-check", "--require-hashes", "--no-deps",
                "--only-binary=:all:", *pip_args, "-r", req,
            ]  # fmt: skip
            code, out, err = _run_child(install, env=env, timeout=PIP_TIMEOUT, pass_fds=(fd,))
            if code is None:
                raise Failed("the install step failed: pip timed out (its output was discarded)")
            if code != 0:
                # pip's raw output is never relayed: it can carry credentials in any shape. Only its status is reported.
                raise Failed(_pip_failure(root, key, code, out + err, keep_pip_log))
            if hashlib.sha256(_fd_bytes(fd)).hexdigest() != expected:
                raise Refused("the private lockfile copy changed during the install")
            if re.search(r"(?im)^include-system-site-packages\s*=\s*true", (stage / "pyvenv.cfg").read_text()):
                raise Refused("the new venv includes system site-packages")
            _seal(stage)
            marker_path = stage / MARKER
            marker_path.write_text(f"{key}\n{manifest(stage, frozenset({MARKER, BUILD_MARK}))}\n")
            marker_path.chmod(0o444)
            (stage / BUILD_MARK).unlink()
            stage.chmod(stage.stat().st_mode & ~0o222)  # the top is sealed BEFORE it is published
            if handle:
                handle.check()
                os.rename(stage.name, key, src_dir_fd=handle.fd, dst_dir_fd=handle.fd)
            else:
                os.rename(stage, final)
            published = True
        except OSError as exc:
            failure = f"the build failed: {_describe(exc)}"
    finally:
        if fd >= 0:
            with contextlib.suppress(OSError):
                os.close(fd)
        for leftover in (work, stage):  # each cleanup is independent: one failing never skips the next
            with contextlib.suppress(OSError):
                if leftover.exists() or leftover.is_symlink():
                    _remove_tree(leftover)
        if published and not _sealed(final):  # defense in depth: never leave a writable published entry
            with contextlib.suppress(OSError):
                _remove_tree(final)
    if failure is not None:
        raise Failed(failure)


def _sealed(entry: Path) -> bool:
    try:
        return not entry.lstat().st_mode & 0o222
    except OSError:
        return False


def _rm_at(parent_fd: int, name: str) -> None:
    """Remove a directory tree relative to an open parent descriptor: nothing is followed, so nothing can escape."""
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    try:
        os.fchmod(fd, 0o700)  # fails for a directory that is not ours
        for entry in os.listdir(fd):
            if stat.S_ISDIR(os.lstat(entry, dir_fd=fd).st_mode):
                _rm_at(fd, entry)
            else:
                os.unlink(entry, dir_fd=fd)  # a symbolic link is unlinked, never followed
    finally:
        os.close(fd)
    os.rmdir(name, dir_fd=parent_fd)


def _read_at(dir_fd: int, name: str, limit: int = 200) -> bytes | None:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=dir_fd)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_size > limit:
            return None
        return os.read(fd, limit + 1)
    finally:
        os.close(fd)


def _links_expected(dir_fd: int, rel: str, stage: bool) -> bool:
    """No symbolic link inside except a venv's own (`bin/*` and a top-level `lib64`) in a stage; nothing but plain
    files and directories otherwise."""
    for name in os.listdir(dir_fd):
        info = os.lstat(name, dir_fd=dir_fd)
        if stat.S_ISLNK(info.st_mode):
            if not (stage and (rel == "bin" or (rel == "" and name == "lib64"))):
                return False
        elif stat.S_ISDIR(info.st_mode):
            sub = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
            try:
                if not _links_expected(sub, f"{rel}/{name}" if rel else name, stage):
                    return False
            finally:
                os.close(sub)
        elif not stat.S_ISREG(info.st_mode):
            return False
    return True


def _authenticated(root_fd: int, name: str, stage: bool) -> bool:
    """Owned by us, carrying one of this tool's exactly formed markers, and no unexpected link or special file."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
    except OSError:
        return False
    try:
        if os.fstat(fd).st_uid != os.geteuid():
            return False
        build_mark = _read_at(fd, BUILD_MARK)
        done_mark = _read_at(fd, MARKER) if stage else None
        if build_mark != BUILD_MARK_TEXT.encode() and (done_mark is None or parse_marker(done_mark) is None):
            return False
        return _links_expected(fd, "", stage)
    except OSError:
        return False
    finally:
        os.close(fd)


def _own_stale_builds(root: Path, root_fd: int) -> int:
    """Remove leftovers that match this tool's random name AND authenticate; return how many were left alone."""
    left = 0
    for name in sorted(os.listdir(root_fd)):
        stage = bool(STAGE_NAME.fullmatch(name))
        if not stage and not BUILD_NAME.fullmatch(name):
            continue
        if not _authenticated(root_fd, name, stage):
            left += 1
            continue
        try:
            _rm_at(root_fd, name)
        except OSError:
            left += 1
    return left


def _poisoned(entry: Path, key: str) -> bool:
    """An unsealed top directory (owner write bit only) with this tool's complete marker for this key, owned by us."""
    try:
        info = entry.lstat()
        marker = entry / MARKER
        minfo = marker.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            return False
        if stat.S_ISLNK(minfo.st_mode) or not stat.S_ISREG(minfo.st_mode) or minfo.st_uid != os.geteuid():
            return False
        if minfo.st_size > 200:
            return False
        parsed = parse_marker(marker.read_bytes())
        # only the owner write bit (an unsealed entry of ours); group or world write is tampering, never rebuilt over
        return info.st_mode & 0o222 == 0o200 and parsed is not None and parsed[0] == key
    except OSError:
        return False


def _touch_stamp(root: Path, key: str) -> None:
    stamp = root / f"{key}.used"
    try:
        fd = os.open(stamp, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError as exc:
        raise Refused("the use stamp cannot be opened (a symbolic link?)") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
            raise Refused("the use stamp is not a plain single-link file of this user")
        os.utime(fd)
    finally:
        os.close(fd)


@_boundary
def ensure(
    root: Path,
    lockfile: Path,
    python: str,
    pip_args: Sequence[str],
    timeout: float,
    keep_pip_log: bool = False,
) -> Path:
    check_timeout(timeout)
    for value in (root, lockfile, python):
        check_plain(value)
    parse_pip_args(pip_args)
    data = read_lockfile(lockfile)
    check_hashes(data)
    key, resolved, signature, base, base_signature = cache_key(hashlib.sha256(data).hexdigest(), python, pip_args)
    handle = open_root(root)
    try:
        with Lock(root, timeout):
            handle.check()
            left = _own_stale_builds(root, handle.fd)
            if left:
                sys.stderr.write(f"safo-shared-venv: left {left} unrecognized leftover entries alone\n")
            final = root / key
            present = final.exists() or final.is_symlink()
            if present:
                try:
                    valid(final, key)
                except Refused:
                    if not _poisoned(final, key):
                        raise
                    _rm_at(handle.fd, key)  # an unsealed entry of ours (an interrupted older publish): rebuild over it
                    present = False
            if not present:
                verify_interpreter(resolved, signature)  # the file we are about to run is the one we identified
                build(root, key, data, resolved, pip_args, handle=handle, keep_pip_log=keep_pip_log)
                try:
                    valid(final, key)
                except Refused:
                    _rm_at(handle.fd, key)
                    raise
            verify_interpreter(resolved, signature)
            verify_base(final, base, base_signature)
            _touch_stamp(root, key)
    finally:
        handle.close()
    verify_interpreter(resolved, signature)  # immediately before the path is handed back
    return interpreter(final)


def check_age(value: float) -> float:
    if not (math.isfinite(value) and 0 <= value <= MAX_AGE_DAYS):
        raise Refused(f"the age must be a finite number of days from 0 to {MAX_AGE_DAYS:g}")
    return value


@_boundary
def gc(root: Path, max_age_days: float, delete: bool, timeout: float, now: float | None = None) -> list[str]:
    check_age(max_age_days)
    check_timeout(timeout)
    check_plain(root)
    if now is not None and not math.isfinite(now):
        raise Refused("the reference time must be finite")
    now = time.time() if now is None else now
    lines: list[str] = []
    handle = open_root(root)
    try:
        lines = _gc_locked(root, handle, max_age_days, delete, timeout, now)
    finally:
        handle.close()
    return lines


def _gc_locked(
    root: Path, handle: RootHandle, max_age_days: float, delete: bool, timeout: float, now: float
) -> list[str]:
    lines: list[str] = []
    with Lock(root, timeout):
        handle.check()
        for entry in sorted(root.iterdir()):
            if not KEY.fullmatch(entry.name):
                continue
            try:
                valid(entry, entry.name)  # only what this tool built, intact; anything else is reported and left
            except (Refused, Failed):
                lines.append(f"skipped (not a valid shared venv): {entry.name}")
                continue
            stamp = root / f"{entry.name}.used"
            times = [entry.stat().st_mtime]
            if stamp.is_file() and not stamp.is_symlink():
                times.append(stamp.stat().st_mtime)
            age = (now - max(times)) / 86400
            if not age >= max_age_days:  # also false for a NaN age: never select on doubt
                continue
            if delete:
                handle.check()
                _rm_at(handle.fd, entry.name)
                if stamp.is_file() and not stamp.is_symlink():
                    stamp.unlink()
                lines.append(f"deleted {entry.name} (unused {age:.1f} days)")
            else:
                lines.append(f"would delete {entry.name} (unused {age:.1f} days)")
    return lines


def _number(text: str, low: float, high: float, what: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{what} must be a number") from None
    if not (math.isfinite(value) and low <= value <= high):
        raise argparse.ArgumentTypeError(f"{what} must be finite and between {low:g} and {high:g}")
    return value


def _age(text: str) -> float:
    return _number(text, 0, MAX_AGE_DAYS, "the age in days")


def _timeout(text: str) -> float:
    return _number(text, 0, MAX_TIMEOUT, "the lock timeout")


class _QuietParser(argparse.ArgumentParser):
    """argparse echoes the offending arguments in its errors; those can be credential-shaped, so none is shown."""

    def error(self, message: str) -> NoReturn:
        self.exit(EXIT_REFUSED, "safo-shared-venv: invalid arguments (none of them is shown); see --help\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _QuietParser(prog="safo-shared-venv", description=(__doc__ or "").split("\n\n")[0], allow_abbrev=False)
    parser.add_argument("lockfile", nargs="?", type=Path, help="hash-locked requirements file")
    parser.add_argument(
        "--root", type=Path, default=None, help=f"venv root (default ${ROOT_ENV} or ~/.local/share/safo-venvs)"
    )
    parser.add_argument("--python", default=sys.executable, help="interpreter that creates the venv")
    parser.add_argument("--index-url", help="the one package index to use")
    parser.add_argument("--find-links", help="a local directory or URL of wheels")
    parser.add_argument("--no-index", action="store_true", help="never contact an index (use with --find-links)")
    parser.add_argument(
        "--lock-timeout", type=_timeout, default=LOCK_TIMEOUT, help="seconds to wait for the build lock"
    )
    parser.add_argument(
        "--keep-pip-log", action="store_true", help="on a pip failure, keep its output in a private 0600 file"
    )
    parser.add_argument("--gc", action="store_true", help="list venvs unused for --max-age-days (no lockfile needed)")
    parser.add_argument("--max-age-days", type=_age, help="age threshold for --gc, required with it")
    parser.add_argument("--delete", action="store_true", help="with --gc: delete what the listing names")
    args = parser.parse_args(argv)
    try:
        root = args.root or default_root()
        if args.gc:
            if args.max_age_days is None or args.max_age_days < 0 or args.lockfile is not None:
                raise Refused("--gc takes --max-age-days N (N >= 0) and no lockfile")
            for line in gc(root, args.max_age_days, args.delete, args.lock_timeout):
                print(line)
            return EXIT_OK
        if args.lockfile is None or args.delete or args.max_age_days is not None:
            raise Refused("usage: safo-shared-venv LOCKFILE, or --gc --max-age-days N [--delete]")
        pip_args: list[str] = []
        if args.no_index:
            pip_args.append("--no-index")
        if args.index_url:
            pip_args += ["--index-url", args.index_url]
        if args.find_links:
            pip_args += ["--find-links", args.find_links]
        print(ensure(root, args.lockfile, args.python, pip_args, args.lock_timeout, args.keep_pip_log))
        return EXIT_OK
    except Refused as exc:
        print(f"safo-shared-venv: refused: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    except Failed as exc:
        print(f"safo-shared-venv: failed: {exc}", file=sys.stderr)
        return EXIT_FAIL
    except KeyboardInterrupt:
        print("safo-shared-venv: interrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # the last boundary: no traceback, no str(exc), at most the class name and an errno
        print(
            f"safo-shared-venv: unexpected error ({type(exc).__name__}, errno {getattr(exc, 'errno', None)}); "
            "nothing from the input is shown",
            file=sys.stderr,
        )
        return EXIT_FAIL


def run() -> None:
    sys.exit(main())


if __name__ == "__main__":
    run()
