# SPDX-License-Identifier: Apache-2.0
"""safo-shared-venv: one read-only, hash-locked venv per lockfile, shared by every agent (#534, epic #518).

`safo-shared-venv LOCKFILE` prints the interpreter of a venv keyed by the lockfile's sha256. A missing venv is built
under a file lock (two callers never build the same one), from `pip install --require-hashes --no-deps -r LOCKFILE`
only, never with system site-packages, then made read-only and renamed into place in one step. A changed lockfile is
a new key, so a new venv; the old one stays until `--gc --max-age-days N` lists it (and `--delete` removes it).

Refused: a lockfile with a requirement that has no sha256 hash, an option line (an index, `-r`, `-e`) in the
lockfile, a symbolic link as the lockfile, the root or a venv entry, a root that is not private to this user.
Exit codes: 0 done, 1 a build or lock failure, 2 a refusal or bad usage.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path

ROOT_ENV = "SAFO_SHARED_VENV_ROOT"
EXIT_OK, EXIT_FAIL, EXIT_REFUSED = 0, 1, 2
MARKER = ".safo-lock-sha256"
KEY = re.compile(r"[0-9a-f]{64}")
MAX_LOCKFILE = 4 * 1024 * 1024
LOCK_TIMEOUT = 900.0


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


def prepare_root(root: Path) -> Path:
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
    return root


class Lock:
    """An exclusive flock on `root/.lock`, waited for in bounded polls."""

    def __init__(self, root: Path, timeout: float) -> None:
        self.root, self.timeout, self.fd = root, timeout, -1

    def __enter__(self) -> Lock:
        self.fd = os.open(self.root / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    os.close(self.fd)
                    raise Failed("timed out waiting for the venv lock") from None
                time.sleep(0.05)

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
    env["PIP_REQUIRE_VIRTUALENV"] = "0"
    env["PIP_NO_INPUT"] = "1"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    return env


def _private_copy(directory: Path, name: str, data: bytes) -> Path:
    """Write bytes to a new private file (exclusive create, mode 0600, no symbolic link followed)."""
    path = directory / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    return path


def interpreter(venv: Path) -> Path:
    return venv / "bin" / "python"


def valid(venv: Path, key: str) -> None:
    """Refuse a venv entry that is not exactly what a finished build leaves."""
    if venv.is_symlink() or not venv.is_dir():
        raise Refused(f"the venv entry is a symbolic link or not a directory: {venv}")
    marker = venv / MARKER
    if marker.is_symlink() or not marker.is_file() or marker.read_text().strip() != key:
        raise Refused(f"the venv has no matching lock marker: {venv}")
    if not interpreter(venv).exists():
        raise Refused(f"the venv has no interpreter: {venv}")
    cfg = venv / "pyvenv.cfg"
    if cfg.is_file() and re.search(r"(?im)^include-system-site-packages\s*=\s*true", cfg.read_text()):
        raise Refused(f"the venv includes system site-packages: {venv}")


def build(root: Path, key: str, data: bytes, python: str, pip_args: Sequence[str]) -> None:
    """Build from the checked bytes `data`: pip reads a private copy, never the caller's file."""
    tmp = root / f".tmp-{key[:12]}-{os.getpid()}"
    home = root / f".home-{key[:12]}-{os.getpid()}"
    req = root / f".req-{key[:12]}-{os.getpid()}.txt"
    final = root / key
    try:
        home.mkdir(mode=0o700)
        copy = _private_copy(root, req.name, data)
        if hashlib.sha256(copy.read_bytes()).hexdigest() != key:
            raise Refused("the private lockfile copy does not match the key")
        env = _clean_env(home)
        subprocess.run(  # noqa: S603 - fixed argument list built here, no shell
            [python, "-m", "venv", "--clear", str(tmp)], check=True, env=env, timeout=600, stdout=sys.stderr
        )
        install = [
            str(interpreter(tmp)), "-I", "-m", "pip", "install", "--require-hashes", "--no-deps",
            "--only-binary=:all:", *pip_args, "-r", str(copy),
        ]  # fmt: skip
        subprocess.run(install, check=True, env=env, timeout=1800, stdout=sys.stderr)  # noqa: S603 - fixed argument list built here, no shell
        if hashlib.sha256(copy.read_bytes()).hexdigest() != key:
            raise Refused("the private lockfile copy changed during the install")
        (tmp / MARKER).write_text(key + "\n")
        cfg = tmp / "pyvenv.cfg"
        if re.search(r"(?im)^include-system-site-packages\s*=\s*true", cfg.read_text()):
            raise Refused("the new venv includes system site-packages")
        _walk_chmod(tmp, False)
        os.rename(tmp, final)
    except (subprocess.SubprocessError, OSError) as exc:
        raise Failed(f"the build failed: {type(exc).__name__}: {str(exc)[:200]}") from exc
    finally:
        for leftover in (tmp, home):
            if leftover.exists() or leftover.is_symlink():
                _remove_tree(leftover)
        if req.exists() or req.is_symlink():
            req.unlink()


def ensure(root: Path, lockfile: Path, python: str, pip_args: Sequence[str], timeout: float) -> Path:
    data = read_lockfile(lockfile)
    check_hashes(data)
    key = hashlib.sha256(data).hexdigest()
    prepare_root(root)
    with Lock(root, timeout):
        for pattern in (".tmp-*", ".home-*", ".req-*"):  # a crashed build; safe to clear, we hold the lock
            for leftover in root.glob(pattern):
                if leftover.is_dir() and not leftover.is_symlink():
                    _remove_tree(leftover)
                else:
                    leftover.unlink()
        final = root / key
        if final.exists() or final.is_symlink():
            valid(final, key)
        else:
            build(root, key, data, python, pip_args)
            valid(final, key)
        stamp = root / f"{key}.used"
        if stamp.is_symlink():
            raise Refused(f"the use stamp is a symbolic link: {stamp}")
        stamp.touch()
        os.utime(stamp)
    return interpreter(final)


def gc(root: Path, max_age_days: float, delete: bool, timeout: float, now: float | None = None) -> list[str]:
    prepare_root(root)
    now = time.time() if now is None else now
    lines: list[str] = []
    with Lock(root, timeout):
        for entry in sorted(root.iterdir()):
            if not KEY.fullmatch(entry.name):
                continue
            if entry.is_symlink() or not entry.is_dir():
                lines.append(f"skipped (not a plain directory): {entry}")
                continue
            stamp = root / f"{entry.name}.used"
            times = [entry.stat().st_mtime]
            if stamp.is_file() and not stamp.is_symlink():
                times.append(stamp.stat().st_mtime)
            age = (now - max(times)) / 86400
            if age < max_age_days:
                continue
            if delete:
                _remove_tree(entry)
                if stamp.is_file() and not stamp.is_symlink():
                    stamp.unlink()
                lines.append(f"deleted {entry} (unused {age:.1f} days)")
            else:
                lines.append(f"would delete {entry} (unused {age:.1f} days)")
    return lines


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="safo-shared-venv", description=__doc__.split("\n\n")[0])
    parser.add_argument("lockfile", nargs="?", type=Path, help="hash-locked requirements file")
    parser.add_argument(
        "--root", type=Path, default=None, help=f"venv root (default ${ROOT_ENV} or ~/.local/share/safo-venvs)"
    )
    parser.add_argument("--python", default=sys.executable, help="interpreter that creates the venv")
    parser.add_argument("--index-url", help="the one package index to use")
    parser.add_argument("--find-links", help="a local directory or URL of wheels")
    parser.add_argument("--no-index", action="store_true", help="never contact an index (use with --find-links)")
    parser.add_argument("--lock-timeout", type=float, default=LOCK_TIMEOUT, help="seconds to wait for the build lock")
    parser.add_argument("--gc", action="store_true", help="list venvs unused for --max-age-days (no lockfile needed)")
    parser.add_argument("--max-age-days", type=float, help="age threshold for --gc, required with it")
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
        print(ensure(root, args.lockfile, args.python, pip_args, args.lock_timeout))
        return EXIT_OK
    except Refused as exc:
        print(f"safo-shared-venv: refused: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    except Failed as exc:
        print(f"safo-shared-venv: failed: {exc}", file=sys.stderr)
        return EXIT_FAIL


def run() -> None:
    sys.exit(main())


if __name__ == "__main__":
    run()
