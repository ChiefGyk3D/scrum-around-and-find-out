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
HASH = re.compile(r"--hash=sha256:[0-9a-f]{64}(?=\s|$)")
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
    if path.is_symlink():
        raise Refused(f"the lockfile is a symbolic link: {path}")
    if not path.is_file():
        raise Refused(f"the lockfile is not a regular file: {path}")
    if path.stat().st_size > MAX_LOCKFILE:
        raise Refused("the lockfile is larger than 4 MiB")
    return path.read_bytes()


def check_hashes(data: bytes) -> int:
    """Return the requirement count; refuse an option line, a requirement without a sha256 hash, or none at all."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Refused("the lockfile is not UTF-8") from exc
    logical = re.sub(r"\\\r?\n", " ", text)
    count = 0
    for raw in logical.splitlines():
        line = re.sub(r"(^|\s)#.*", "", raw).strip()
        if not line:
            continue
        if line.startswith("-"):
            raise Refused(f"the lockfile holds an option line, not a pinned requirement: {line[:60]!r}")
        if not HASH.search(line):
            raise Refused(f"a requirement has no sha256 hash: {line[:60]!r}")
        count += 1
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


def _clean_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in {"PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP"}}
    env["PIP_REQUIRE_VIRTUALENV"] = "0"
    env["PIP_NO_INPUT"] = "1"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    return env


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


def build(root: Path, key: str, lockfile: Path, python: str, pip_args: Sequence[str]) -> None:
    tmp = root / f".tmp-{key[:12]}-{os.getpid()}"
    final = root / key
    try:
        subprocess.run(  # noqa: S603 - fixed argument list built here, no shell
            [python, "-m", "venv", "--clear", str(tmp)], check=True, env=_clean_env(), timeout=600, stdout=sys.stderr
        )
        install = [
            str(interpreter(tmp)), "-I", "-m", "pip", "install", "--require-hashes", "--no-deps",
            "--only-binary=:all:", *pip_args, "-r", str(lockfile),
        ]  # fmt: skip
        subprocess.run(install, check=True, env=_clean_env(), timeout=1800, stdout=sys.stderr)  # noqa: S603 - fixed argument list built here, no shell
        (tmp / MARKER).write_text(key + "\n")
        cfg = tmp / "pyvenv.cfg"
        if re.search(r"(?im)^include-system-site-packages\s*=\s*true", cfg.read_text()):
            raise Refused("the new venv includes system site-packages")
        _walk_chmod(tmp, False)
        os.rename(tmp, final)
    except (subprocess.SubprocessError, OSError) as exc:
        raise Failed(f"the build failed: {type(exc).__name__}: {str(exc)[:200]}") from exc
    finally:
        if tmp.exists() or tmp.is_symlink():
            _remove_tree(tmp)


def ensure(root: Path, lockfile: Path, python: str, pip_args: Sequence[str], timeout: float) -> Path:
    data = read_lockfile(lockfile)
    check_hashes(data)
    key = hashlib.sha256(data).hexdigest()
    prepare_root(root)
    with Lock(root, timeout):
        for leftover in root.glob(".tmp-*"):  # a crashed build; safe to clear, we hold the lock
            _remove_tree(leftover)
        final = root / key
        if final.exists() or final.is_symlink():
            valid(final, key)
        else:
            build(root, key, lockfile, python, pip_args)
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
