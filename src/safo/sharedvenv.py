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
import fcntl
import hashlib
import json
import math
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path

ROOT_ENV = "SAFO_SHARED_VENV_ROOT"
EXIT_OK, EXIT_FAIL, EXIT_REFUSED = 0, 1, 2
MARKER = ".safo-lock-sha256"
BUILD_MARK = ".safo-build"
BUILD_NAME = re.compile(r"\.build-[A-Za-z0-9_]{8}")
KEY = re.compile(r"[0-9a-f]{64}")
MAX_LOCKFILE = 4 * 1024 * 1024
LOCK_TIMEOUT = 900.0
MAX_AGE_DAYS = 36500.0
MAX_TIMEOUT = 7 * 86400.0
_USERINFO = re.compile(r"(?i)([a-z][a-z0-9+.-]*://)[^/\s@]*@")
_QUERY = re.compile(r"([?&][^=&\s#]+)=[^&\s#]*")
IDENTITY_CODE = (
    "import json,sys,sysconfig\n"
    "try:\n    import ensurepip; pip = ensurepip.version()\nexcept Exception:\n    pip = 'none'\n"
    "print(json.dumps([sys.implementation.name, list(sys.version_info[:2]), sys.implementation.cache_tag,"
    " sysconfig.get_platform(), getattr(sys, 'abiflags', ''), pip]))\n"
)


class Refused(Exception):
    """A lockfile, location or venv this command will not use."""


class Failed(Exception):
    """A build or lock step failed."""


def default_root(env: dict[str, str] | os._Environ[str] = os.environ) -> Path:
    if env.get(ROOT_ENV):
        return Path(env[ROOT_ENV])
    return Path(env.get("HOME", str(Path.home()))) / ".local" / "share" / "safo-venvs"


def read_lockfile(path: Path) -> bytes:
    """Read the lockfile once, through one descriptor, refusing a symbolic link or a special file."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as exc:
        raise Refused(f"the lockfile cannot be opened (a symbolic link or missing?): {path}") from exc
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise Refused(f"the lockfile is not a regular file: {path}")
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
            raise Refused(f"line {number}: not `name==version` with sha256 hashes: {joined[:60]!r}")
        count += 1
    if pending:
        raise Refused("the lockfile ends inside a continued line")
    if count == 0:
        raise Refused("the lockfile holds no requirements")
    return count


def redact(text: str) -> str:
    """Remove URL userinfo and query values from any text that may be shown."""
    return _QUERY.sub(r"\1=***", _USERINFO.sub(r"\1***@", text))


def has_url_secret(value: str) -> bool:
    return bool(_USERINFO.search(value) or _QUERY.search(value))


def _check_ancestors(root: Path) -> None:
    """Every existing ancestor: a plain directory, owned by this user or root, not writable by others (a sticky
    directory such as /tmp is allowed), and no symbolic link anywhere on the path."""
    for ancestor in reversed(Path(os.path.abspath(root)).parents):
        try:
            info = ancestor.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise Refused(f"a symbolic link on the path to the venv root: {ancestor}")
        if not stat.S_ISDIR(info.st_mode):
            raise Refused(f"a non-directory on the path to the venv root: {ancestor}")
        if info.st_uid not in (os.geteuid(), 0):
            raise Refused(f"an ancestor of the venv root is owned by another user: {ancestor}")
        if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
            raise Refused(f"an ancestor of the venv root is writable by group or others: {ancestor}")


class RootHandle:
    """The validated root held by descriptor; `check()` refuses if the path now names a different directory."""

    def __init__(self, path: Path, fd: int, ident: tuple[int, int]) -> None:
        self.path, self.fd, self.ident = path, fd, ident

    def check(self) -> None:
        try:
            info = self.path.lstat()
        except OSError as exc:
            raise Refused(f"the venv root was replaced or removed: {self.path}") from exc
        if stat.S_ISLNK(info.st_mode) or (info.st_dev, info.st_ino) != self.ident:
            raise Refused(f"the venv root was replaced after it was validated: {self.path}")

    def close(self) -> None:
        os.close(self.fd)


def open_root(root: Path) -> RootHandle:
    _check_ancestors(root)
    if root.is_symlink():
        raise Refused(f"the venv root is a symbolic link: {root}")
    if not root.exists():
        root.parent.mkdir(parents=True, exist_ok=True)
        root.mkdir(mode=0o700)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise Refused(f"the venv root is not a directory: {root}")
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise Refused(f"the venv root must be owned by this user and not writable by others: {root}")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    held = os.fstat(fd)
    if (held.st_dev, held.st_ino) != (info.st_dev, info.st_ino):
        os.close(fd)
        raise Refused(f"the venv root changed while it was opened: {root}")
    return RootHandle(root, fd, (held.st_dev, held.st_ino))


def _after_flock(path: Path) -> None:
    """A seam between taking the flock and checking which file it is on (replaced by a test)."""


class Lock:
    """An exclusive flock on `root/.lock`, waited for in bounded polls.

    After the flock is taken, the descriptor is compared with the path; if the file was replaced meanwhile, the lock is
    dropped and taken again on the new file. This narrows the race for a same-user writer, it does not remove it.
    """

    def __init__(self, root: Path, timeout: float) -> None:
        self.path, self.timeout, self.fd = root / ".lock", timeout, -1

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
    """sha256, inode, device and mtime of the interpreter file."""
    with open(resolved, "rb") as handle:
        info = os.fstat(handle.fileno())
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    return digest, info.st_ino, info.st_dev, info.st_mtime_ns


def identity(python: str) -> tuple[str, str, list[object]]:
    """The interpreter as found, its resolved path and what it reports about itself; a missing one is refused."""
    found = shutil.which(python)
    if found is None or not os.access(found, os.X_OK):
        raise Refused(f"the interpreter does not exist or is not executable: {python}")
    resolved = os.path.realpath(found)
    try:
        done = subprocess.run(  # noqa: S603 - the resolved interpreter and a fixed argument list, no shell
            [found, "-I", "-c", IDENTITY_CODE],
            capture_output=True,
            text=True,
            env=_clean_env(Path("/nonexistent")),
            timeout=60,
            check=True,
        )
        report = json.loads(done.stdout.strip().splitlines()[-1])
    except (subprocess.SubprocessError, OSError, ValueError, IndexError) as exc:
        raise Refused(f"the interpreter did not report its identity: {python}") from exc
    return found, resolved, report


def cache_key(lock_sha: str, python: str, pip_args: Sequence[str]) -> tuple[str, str, str, tuple[str, int, int, int]]:
    """The key, the interpreter as found, its resolved path and its file signature.

    The key covers the lockfile hash, the interpreter identity (and the sha256 of its file) and the acquisition policy.
    """
    found, resolved, report = identity(python)
    signature = _exe_signature(resolved)
    record = {"lock": lock_sha, "python": resolved, "exe": signature[0], "identity": report, "policy": list(pip_args)}
    key = hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return key, found, resolved, signature


def verify_interpreter(resolved: str, signature: tuple[str, int, int, int]) -> None:
    try:
        now = _exe_signature(resolved)
    except OSError as exc:
        raise Refused("the interpreter changed after its identity was read (unreadable now)") from exc
    if now != signature:
        raise Refused("the interpreter changed after its identity was read")


def interpreter(venv: Path) -> Path:
    return venv / "bin" / "python"


def _trusted(path: Path, what: str, *, kind: str = "file") -> os.stat_result:
    """lstat a venv member and refuse a symbolic link (unless allowed), a foreign owner or group/world write."""
    info = path.lstat()
    is_link = stat.S_ISLNK(info.st_mode)
    if kind == "dir" and not stat.S_ISDIR(info.st_mode):
        raise Refused(f"{what} is not a plain directory (a symbolic link?): {path}")
    if kind == "file" and not stat.S_ISREG(info.st_mode):
        raise Refused(f"{what} is not a plain file (a symbolic link?): {path}")
    if info.st_uid != os.geteuid():
        raise Refused(f"{what} is not owned by this user: {path}")
    if not is_link and info.st_mode & 0o222:
        raise Refused(f"{what} is writable: {path}")
    return info


def manifest(venv: Path) -> str:
    """sha256 over the sorted (relative path, size, mode) list of the venv, refusing foreign or writable members.

    Detects accidental or cross-account damage; a same-user attacker can rewrite the marker as well.
    """
    rows: list[str] = []
    for here, dirs, files in os.walk(venv, followlinks=False):
        for name in [*dirs, *files]:
            path = Path(here) / name
            rel = str(path.relative_to(venv))
            if rel == MARKER:
                continue
            info = path.lstat()
            if info.st_uid != os.geteuid():
                raise Refused(f"a member is not owned by this user: {path}")
            if not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o222:
                raise Refused(f"a member is writable: {path}")
            size = 0 if stat.S_ISDIR(info.st_mode) else info.st_size
            rows.append(f"{rel}\0{size}\0{info.st_mode:o}")
    return hashlib.sha256("\n".join(sorted(rows)).encode()).hexdigest()


def valid(venv: Path, key: str) -> None:
    """Refuse a venv entry that is not exactly what a finished build leaves (layout, owner, modes, marker, manifest)."""
    if not venv.is_symlink() and not venv.exists():
        raise Refused(f"the venv entry does not exist: {venv}")
    _trusted(venv, "the venv entry", kind="dir")
    marker = venv / MARKER
    _trusted(marker, "the lock marker")
    lines = marker.read_text().split("\n")
    if len(lines) < 2 or lines[0] != key:
        raise Refused(f"the venv has no matching lock marker: {venv}")
    cfg = venv / "pyvenv.cfg"
    _trusted(cfg, "pyvenv.cfg")
    if re.search(r"(?im)^include-system-site-packages\s*=\s*true", cfg.read_text()):
        raise Refused(f"the venv includes system site-packages: {venv}")
    python = interpreter(venv)
    if not python.exists():
        raise Refused(f"the venv has no interpreter: {venv}")
    if python.lstat().st_uid != os.geteuid():
        raise Refused(f"the venv interpreter link is not owned by this user: {python}")
    if manifest(venv) != lines[1]:
        raise Refused(f"the venv does not match its build manifest: {venv}")


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


def _describe(exc: BaseException) -> str:
    """A failure text without a command line, so no argument (a URL with a token) can leak through it."""
    if isinstance(exc, subprocess.CalledProcessError):
        return f"a child process exited with status {exc.returncode}"
    if isinstance(exc, subprocess.SubprocessError):
        return type(exc).__name__
    return f"{type(exc).__name__}: {redact(str(exc))[:200]}"


def build(
    root: Path,
    key: str,
    data: bytes,
    python: str,
    pip_args: Sequence[str],
    expected_sha: str | None = None,
    handle: RootHandle | None = None,
) -> None:
    """Build from the checked bytes `data`: pip reads a private copy through an open descriptor, not the caller's file.

    The copy lives in a fresh random-named 0700 directory; its bytes are re-hashed from the descriptor pip read.
    """
    expected = expected_sha or hashlib.sha256(data).hexdigest()
    final = root / key
    if handle:
        handle.check()
    work = Path(tempfile.mkdtemp(prefix=".build-", dir=root))  # mode 0700, random name
    fd = -1
    published = False
    try:
        marker = os.open(work / BUILD_MARK, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        os.close(marker)
        home, venv = work / "home", work / "venv"
        home.mkdir(mode=0o700)
        fd = os.open(work / "req.txt", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.write(fd, data)
        if hashlib.sha256(_fd_bytes(fd)).hexdigest() != expected:
            raise Refused("the private lockfile copy does not match the checked hash")
        req = f"/proc/self/fd/{fd}" if Path("/proc/self/fd").is_dir() else str(work / "req.txt")
        env = _clean_env(home)
        subprocess.run(  # noqa: S603 - fixed argument list built here, no shell
            [python, "-m", "venv", "--clear", str(venv)], check=True, env=env, timeout=600, stdout=sys.stderr
        )
        install = [
            str(interpreter(venv)), "-I", "-m", "pip", "--isolated", "install", "--no-input",
            "--disable-pip-version-check", "--require-hashes", "--no-deps",
            "--only-binary=:all:", *pip_args, "-r", req,
        ]  # fmt: skip
        done = subprocess.run(  # noqa: S603 - fixed argument list built here, no shell
            install, env=env, timeout=1800, capture_output=True, text=True, pass_fds=(fd,), check=False
        )
        sys.stderr.write(redact(done.stdout + done.stderr))  # pip may echo an index URL: never show userinfo or tokens
        if done.returncode != 0:
            raise Failed(f"pip exited with status {done.returncode}")
        if hashlib.sha256(_fd_bytes(fd)).hexdigest() != expected:
            raise Refused("the private lockfile copy changed during the install")
        if re.search(r"(?im)^include-system-site-packages\s*=\s*true", (venv / "pyvenv.cfg").read_text()):
            raise Refused("the new venv includes system site-packages")
        _seal(venv)
        marker_path = venv / MARKER
        marker_path.write_text(f"{key}\n{manifest(venv)}\n")
        marker_path.chmod(0o444)
        if handle:
            handle.check()
            os.rename(f"{work.name}/venv", key, src_dir_fd=handle.fd, dst_dir_fd=handle.fd)
        else:
            os.rename(venv, final)
        published = True
        final.chmod(final.stat().st_mode & ~0o222)
    except (subprocess.SubprocessError, OSError) as exc:
        raise Failed(f"the build failed: {_describe(exc)}") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        _remove_tree(work)
        if published and not _sealed(final):  # a failure after publication must not leave a writable entry behind
            _remove_tree(final)


def _sealed(entry: Path) -> bool:
    try:
        return not entry.lstat().st_mode & 0o222
    except OSError:
        return False


def _own_stale_builds(root: Path) -> None:
    """Remove only leftovers that match this tool's random build-name pattern and carry its build marker."""
    for entry in sorted(root.iterdir()):
        if not BUILD_NAME.fullmatch(entry.name):
            continue
        info = entry.lstat()
        mark = entry / BUILD_MARK
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or mark.is_symlink() or not mark.is_file():
            continue
        _remove_tree(entry)


def _touch_stamp(root: Path, key: str) -> None:
    stamp = root / f"{key}.used"
    try:
        fd = os.open(stamp, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError as exc:
        raise Refused(f"the use stamp cannot be opened (a symbolic link?): {stamp}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
            raise Refused(f"the use stamp is not a plain single-link file of this user: {stamp}")
        os.utime(fd)
    finally:
        os.close(fd)


def ensure(root: Path, lockfile: Path, python: str, pip_args: Sequence[str], timeout: float) -> Path:
    data = read_lockfile(lockfile)
    check_hashes(data)
    key, found, resolved, signature = cache_key(hashlib.sha256(data).hexdigest(), python, pip_args)
    handle = open_root(root)
    try:
        with Lock(root, timeout):
            handle.check()
            _own_stale_builds(root)
            final = root / key
            if final.exists() or final.is_symlink():
                valid(final, key)
            else:
                verify_interpreter(resolved, signature)  # the file we are about to run is the one we identified
                build(root, key, data, found, pip_args, handle=handle)
                try:
                    valid(final, key)
                except Refused:
                    _remove_tree(final)
                    raise
            _touch_stamp(root, key)
    finally:
        handle.close()
    return interpreter(final)


def check_age(value: float) -> float:
    if not (math.isfinite(value) and 0 <= value <= MAX_AGE_DAYS):
        raise Refused(f"the age must be a finite number of days from 0 to {MAX_AGE_DAYS:g}")
    return value


def gc(root: Path, max_age_days: float, delete: bool, timeout: float, now: float | None = None) -> list[str]:
    check_age(max_age_days)
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
            except (Refused, OSError) as exc:
                lines.append(f"skipped (not a valid shared venv: {str(exc)[:80]}): {entry}")
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
                _remove_tree(entry)
                if stamp.is_file() and not stamp.is_symlink():
                    stamp.unlink()
                lines.append(f"deleted {entry} (unused {age:.1f} days)")
            else:
                lines.append(f"would delete {entry} (unused {age:.1f} days)")
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="safo-shared-venv", description=(__doc__ or "").split("\n\n")[0])
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
        "--allow-url-credentials",
        action="store_true",
        help="accept userinfo or query tokens in --index-url/--find-links",
    )
    parser.add_argument("--gc", action="store_true", help="list venvs unused for --max-age-days (no lockfile needed)")
    parser.add_argument("--max-age-days", type=_age, help="age threshold for --gc, required with it")
    parser.add_argument("--delete", action="store_true", help="with --gc: delete what the listing names")
    args = parser.parse_args(argv)
    root = args.root or default_root()
    try:
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
        if not args.allow_url_credentials and any(has_url_secret(v) for v in (args.index_url, args.find_links) if v):
            raise Refused("an index or links URL carries credentials or a query token (--allow-url-credentials)")
        print(ensure(root, args.lockfile, args.python, pip_args, args.lock_timeout))
        return EXIT_OK
    except Refused as exc:
        print(f"safo-shared-venv: refused: {redact(str(exc))}", file=sys.stderr)
        return EXIT_REFUSED
    except Failed as exc:
        print(f"safo-shared-venv: failed: {redact(str(exc))}", file=sys.stderr)
        return EXIT_FAIL


def run() -> None:
    sys.exit(main())


if __name__ == "__main__":
    run()
