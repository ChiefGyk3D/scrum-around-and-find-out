# SPDX-License-Identifier: Apache-2.0
"""safo-digest: run one allow-listed command, save its full output privately, print only a small digest.

`safo-digest [--config F] [--timeout S] [--max-lines N] [--max-bytes N] -- CMD ARG...` runs CMD with an argv list (no
shell, stdin closed, its own process group), streams stdout and stderr into a new 0600 file inside a private 0700
directory, and prints a capped digest: one header line (command name, exit code, line and byte counts, saved path), the
first failure lines when the command failed, then the head and the tail of the output. The digest is cut to the byte
cap last, so it never exceeds it. See docs/digest.md.

Exit code: the command's own (a signal death is 128 plus the signal), except 124 for a timeout, 125 for a refusal or a
usage or config error (nothing was run), 127 when the executable cannot be found or started.

Safety: the config file and the output directory are opened without following symlinks (every directory component is
walked with O_NOFOLLOW), the directory must be owned by you and closed to group and others, the output file is created
exclusively, and a command runs only when its argv starts with one of the `allow` prefixes in the config.
"""

from __future__ import annotations

import collections
import contextlib
import dataclasses
import errno
import getpass
import os
import pwd
import re
import secrets
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import tomllib
import unicodedata
from dataclasses import dataclass, field

from safo.errors import ConfigError, SafoError

EXIT_TIMEOUT = 124
EXIT_REFUSED = 125
EXIT_NOT_FOUND = 127

_KEYS = {"out_dir", "allow", "max_lines", "max_bytes", "timeout", "max_file_bytes", "redact_words"}
_CONFIG_MAX = 64 * 1024
_STORE_LINE = 512  # bytes kept of one line for the digest; the file keeps all of it
_SHOW_LINE = 200  # characters shown of one line
_FAIL = re.compile(rb"(?i)\b(fail(?:ed|ure|ures|s)?|error|errors|traceback|panic|fatal|exception|assert\w*)\b")
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]|\x1b")
_CALLSIGN = re.compile(r"(?<![A-Za-z0-9])(?:[A-Z]{1,2}|[0-9][A-Z])[0-9][A-Z]{2,3}(?![A-Za-z0-9])")
_GRID = re.compile(r"(?<![A-Za-z0-9])[A-R]{2}[0-9]{2}[a-x]{2}(?![A-Za-z0-9])")
_KEEP = {"N0CALL", "N0TST"}


class DigestError(SafoError):
    """A refusal or a usage error: nothing was run (exit 125)."""


@dataclass(frozen=True)
class Config:
    out_dir: str
    allow: tuple[tuple[str, ...], ...]
    max_lines: int = 40
    max_bytes: int = 4000
    timeout: float = 300.0
    max_file_bytes: int = 256 * 1024 * 1024
    redact_words: tuple[str, ...] = field(default_factory=tuple)


def _home() -> str:
    return os.path.expanduser("~")


def default_config_path() -> str:
    return os.path.join(_home(), ".config", "safo", "digest.toml")


def _int(d: dict[str, object], key: str, lo: int, hi: int, default: int) -> int:
    v = d.get(key, default)
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        raise ConfigError(f"{key} must be an integer from {lo} to {hi}")
    return v


def _read_config_file(path: str) -> str:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as e:
        raise ConfigError(f"config {path}: cannot open without following symlinks ({e.strerror})") from e
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o022 or st.st_size > _CONFIG_MAX:
            raise ConfigError(
                f"config {path}: must be a regular file of yours, not group or world writable, under 64 KiB"
            )
        return f.read(_CONFIG_MAX + 1).decode("utf-8", "strict")


def load_config(path: str | None) -> Config:
    p = path or os.environ.get("SAFO_DIGEST_CONFIG") or default_config_path()
    try:
        d = tomllib.loads(_read_config_file(p))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise ConfigError(f"config {p}: not valid TOML ({type(e).__name__})") from e
    unknown = sorted(set(d) - _KEYS)
    if unknown:
        raise ConfigError(f"config: unknown key {unknown[0]!r}")
    allow = d.get("allow")
    if not isinstance(allow, list) or not allow:
        raise ConfigError("allow must be a non-empty list of command prefixes, each a list of strings")
    prefixes = []
    for item in allow:
        if not isinstance(item, list) or not item or not all(isinstance(s, str) and s for s in item):
            raise ConfigError("allow: each prefix must be a non-empty list of non-empty strings")
        prefixes.append(tuple(item))
    out_dir = d.get("out_dir", os.path.join(_home(), ".local", "state", "safo-digest"))
    if not isinstance(out_dir, str) or not os.path.isabs(out_dir) or "\x00" in out_dir:
        raise ConfigError("out_dir must be an absolute path")
    timeout = d.get("timeout", 300)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 86400:
        raise ConfigError("timeout must be a number of seconds above 0 and up to 86400")
    words = d.get("redact_words", [])
    if not isinstance(words, list) or not all(isinstance(w, str) and w for w in words):
        raise ConfigError("redact_words must be a list of non-empty strings")
    return Config(
        out_dir=os.path.normpath(out_dir),
        allow=tuple(prefixes),
        max_lines=_int(d, "max_lines", 3, 1000, 40),
        max_bytes=_int(d, "max_bytes", 256, 65536, 4000),
        timeout=float(timeout),
        max_file_bytes=_int(d, "max_file_bytes", 1024, 4 * 1024**3, 256 * 1024 * 1024),
        redact_words=tuple(words),
    )


def is_allowed(argv: list[str], allow: tuple[tuple[str, ...], ...]) -> bool:
    return any(len(argv) >= len(p) and tuple(argv[: len(p)]) == p for p in allow)


def resolve_executable(name: str) -> str | None:
    """An absolute path to run. A bare name is looked up on the absolute entries of PATH only (never the cwd)."""
    if "/" in name:
        cands = [name] if os.path.isabs(name) else []
    else:
        cands = [os.path.join(d, name) for d in os.environ.get("PATH", "").split(os.pathsep) if d and os.path.isabs(d)]
    for c in cands:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def open_private_dir(path: str) -> int:
    """Open (creating at 0700 where missing) every component without following a symlink; check the leaf."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    parts = [c for c in path.split("/") if c]
    try:
        for comp in parts:
            try:
                nfd = os.open(comp, flags, dir_fd=fd)
            except FileNotFoundError:
                os.mkdir(comp, 0o700, dir_fd=fd)
                nfd = os.open(comp, flags, dir_fd=fd)
                os.fchmod(nfd, 0o700)
            except OSError as e:
                if e.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise DigestError(f"out_dir: {comp!r} is a symlink or not a directory") from e
                raise
            os.close(fd)
            fd = nfd
        st = os.fstat(fd)
        if st.st_uid != os.getuid() or st.st_mode & 0o077:
            raise DigestError("out_dir must be owned by you with mode 0700 (no group or other access)")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _safe_name(argv0: str) -> str:
    base = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(argv0))[:40] or "cmd"
    return f"{time.strftime('%Y%m%dT%H%M%S', time.gmtime())}-{os.getpid()}-{secrets.token_hex(4)}-{base}.log"


def create_output(dirfd: int, argv0: str) -> tuple[int, str]:
    name = _safe_name(argv0)
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dirfd)
    os.fchmod(fd, 0o600)
    return fd, name


class Collector:
    """Counts every byte and line; keeps only the head, the tail and the first failure lines (bounded)."""

    def __init__(self, cap: int) -> None:
        self.cap = cap
        self.lines = 0
        self.bytes = 0
        self.head: list[bytes] = []
        self.tail: collections.deque[bytes] = collections.deque(maxlen=cap)
        self.fails: list[bytes] = []
        self._cur = bytearray()
        self._cur_has = False

    def _done(self, line: bytes) -> None:
        self.lines += 1
        if len(self.head) < self.cap:
            self.head.append(line)
        self.tail.append(line)
        if len(self.fails) < self.cap and _FAIL.search(line):
            self.fails.append(line)

    def feed(self, chunk: bytes) -> None:
        self.bytes += len(chunk)
        pieces = chunk.split(b"\n")
        for i, piece in enumerate(pieces):
            if i:
                self._done(bytes(self._cur))
                self._cur = bytearray()
                self._cur_has = False
            if piece:
                self._cur_has = True
                room = _STORE_LINE - len(self._cur)
                if room > 0:
                    self._cur += piece[:room]

    def finish(self) -> None:
        if self._cur_has:
            self._done(bytes(self._cur))
            self._cur = bytearray()
            self._cur_has = False


class Redactor:
    """Best effort: the current user name, this host name, the home directory, callsigns, 6-character grid squares
    and any configured words become placeholders. It cannot know what it has not been told; the saved file is raw."""

    def __init__(self, words: tuple[str, ...]) -> None:
        users = {os.environ.get("USER", ""), os.environ.get("LOGNAME", "")}
        try:
            users.add(getpass.getuser())
            users.add(pwd.getpwuid(os.getuid()).pw_name)
        except (KeyError, OSError):
            pass
        host = socket.gethostname()
        hosts = {host, host.split(".")[0]}
        self.home = _home().rstrip("/")
        self._subs: list[tuple[re.Pattern[str], str]] = []
        for group, ph in ((users, "<user>"), (hosts, "<host>"), (set(words), "<redacted>")):
            for w in sorted((w for w in group if len(w) >= 3), key=len, reverse=True):
                self._subs.append((re.compile(r"(?<![A-Za-z0-9_])" + re.escape(w) + r"(?![A-Za-z0-9_])", re.I), ph))

    def __call__(self, text: str) -> str:
        if len(self.home) > 1:
            text = text.replace(self.home, "~")
        for pat, ph in self._subs:
            text = pat.sub(ph, text)
        text = _CALLSIGN.sub(lambda m: m.group(0) if m.group(0) in _KEEP else "<callsign>", text)
        return _GRID.sub("<grid>", text)


def sanitize(raw: bytes) -> str:
    text = raw.decode("utf-8", "replace")
    text = _ANSI.sub("", text)
    if "\r" in text:
        text = text.rsplit("\r", 1)[-1] or text.rstrip("\r").rsplit("\r", 1)[-1]
    text = "".join(" " if c == "\t" else c for c in text if c == "\t" or unicodedata.category(c) not in ("Cc", "Cf"))
    return text[:_SHOW_LINE]


def render(c: Collector, cfg: Config, red: Redactor, name: str, code: int, saved: str, extra: str) -> bytes:
    header = f"safo-digest: cmd={name} exit={code} lines={c.lines} bytes={c.bytes} saved={saved}{extra}"
    body: list[str] = []
    budget = cfg.max_lines - 1
    if c.lines <= budget and c.lines == len(c.head):
        body = [sanitize(x) for x in c.head]
    else:
        if code != 0 and c.fails:
            n = min(len(c.fails), max(1, budget // 4))
            body += ["-- first failures --"] + [sanitize(x) for x in c.fails[:n]] + ["-- output --"]
        rest = max(2, budget - len(body) - 1)
        nhead = max(1, rest // 3)
        ntail = max(1, rest - nhead)
        head = [sanitize(x) for x in c.head[:nhead]]
        tail = [sanitize(x) for x in list(c.tail)[-ntail:]]
        omitted = c.lines - len(head) - len(tail)
        body += head
        if omitted > 0:
            body.append(f"... {omitted} lines omitted, see the saved file ...")
        body += tail
    text = "\n".join([header, *body]) + "\n"
    text = red(text)
    data = text.encode("utf-8")
    if len(data) > cfg.max_bytes:
        cut = b"\n[cut]\n"
        data = data[: cfg.max_bytes - len(cut)].decode("utf-8", "ignore").encode("utf-8") + cut
    return data


def _pump(src: int, dst: int, col: Collector, cap: int, state: dict[str, bool], lock: threading.Lock) -> None:
    written = 0
    while True:
        try:
            chunk = os.read(src, 65536)
        except OSError:
            break
        if not chunk:
            break
        with lock:
            col.feed(chunk)
        if state["truncated"]:
            continue  # keep draining so the command never blocks on a full pipe
        piece = chunk[: cap - written]
        try:
            _write_all(dst, piece)
        except OSError:
            state["truncated"] = True
        written += len(piece)
        if len(piece) < len(chunk):
            state["truncated"] = True


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view) :]


def _kill_group(pid: int) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pid, signal.SIGKILL)


def execute(argv: list[str], cfg: Config) -> tuple[int, bytes]:
    if not argv:
        raise DigestError("no command given; usage: safo-digest [options] -- CMD ARG...")
    if not is_allowed(argv, cfg.allow):
        raise DigestError(f"{os.path.basename(argv[0])!r} with these arguments is not on the allow list in the config")
    exe = resolve_executable(argv[0])
    if exe is None:
        return (
            EXIT_NOT_FOUND,
            f"safo-digest: cmd={os.path.basename(argv[0])} not found on an absolute PATH entry\n".encode(),
        )
    dirfd = open_private_dir(cfg.out_dir)
    try:
        ofd, fname = create_output(dirfd, argv[0])
    finally:
        os.close(dirfd)
    col = Collector(cfg.max_lines)
    state: dict[str, bool] = {"truncated": False}
    lock = threading.Lock()
    timed_out = False
    try:
        try:
            proc = subprocess.Popen(  # noqa: S603 - argv list, shell never used, allow-listed and path-resolved above
                [exe, *argv[1:]],
                executable=exe,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                close_fds=True,
                shell=False,
            )
        except OSError as e:
            return (
                EXIT_NOT_FOUND,
                f"safo-digest: cmd={os.path.basename(argv[0])} could not start ({e.strerror})\n".encode(),
            )
        stdout = proc.stdout
        if stdout is None:  # pragma: no cover - PIPE always gives a stream
            raise DigestError("no output pipe")
        t = threading.Thread(
            target=_pump, args=(stdout.fileno(), ofd, col, cfg.max_file_bytes, state, lock), daemon=True
        )
        t.start()
        try:
            proc.wait(timeout=cfg.timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        _kill_group(proc.pid)  # the command is done or hung: nothing of its group may outlive this run
        proc.wait()
        t.join(5)
        if not t.is_alive():
            stdout.close()
    finally:
        os.close(ofd)
    with lock:
        col.finish()
    rc = proc.returncode
    code = EXIT_TIMEOUT if timed_out else (128 - rc if rc < 0 else rc)
    extra = (f" timeout={cfg.timeout:g}s" if timed_out else "") + (" file-truncated" if state["truncated"] else "")
    shown = os.path.join(cfg.out_dir, fname)
    return code, render(col, cfg, Redactor(cfg.redact_words), os.path.basename(argv[0]), code, shown, extra)


@dataclass
class Options:
    config: str | None = None
    timeout: float | None = None
    max_lines: int | None = None
    max_bytes: int | None = None


def parse(argv: list[str]) -> tuple[Options, list[str]]:
    if "--" not in argv:
        raise DigestError("usage: safo-digest [--config F] [--timeout S] [--max-lines N] [--max-bytes N] -- CMD ARG...")
    i = argv.index("--")
    opts, cmd = argv[:i], argv[i + 1 :]
    out = Options()
    it = iter(opts)
    for o in it:
        if o not in ("--config", "--timeout", "--max-lines", "--max-bytes"):
            raise DigestError(f"unknown option {o!r}")
        try:
            v = next(it)
        except StopIteration:
            raise DigestError(f"{o} needs a value") from None
        try:
            if o == "--config":
                out.config = v
            elif o == "--timeout":
                out.timeout = float(v)
            elif o == "--max-lines":
                out.max_lines = int(v)
            else:
                out.max_bytes = int(v)
        except ValueError:
            raise DigestError(f"{o} needs a number") from None
    return out, cmd


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        opts, cmd = parse(args)
        cfg = load_config(opts.config)
        cfg = dataclasses.replace(
            cfg,
            timeout=cfg.timeout if opts.timeout is None else opts.timeout,
            max_lines=cfg.max_lines if opts.max_lines is None else opts.max_lines,
            max_bytes=cfg.max_bytes if opts.max_bytes is None else opts.max_bytes,
        )
        if not (3 <= cfg.max_lines <= 1000 and 256 <= cfg.max_bytes <= 65536 and 0 < cfg.timeout <= 86400):
            raise DigestError("--max-lines 3..1000, --max-bytes 256..65536, --timeout above 0 and up to 86400")
        code, data = execute(cmd, cfg)
    except SafoError as e:
        sys.stderr.write(f"safo-digest: refused: {e}\n")
        return EXIT_REFUSED
    except OSError as e:
        sys.stderr.write(f"safo-digest: refused: {e.strerror or type(e).__name__}\n")
        return EXIT_REFUSED
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()
    return code


def run() -> None:  # console-script entry
    sys.exit(main())


if __name__ == "__main__":
    run()
