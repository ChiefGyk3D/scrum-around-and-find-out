# SPDX-License-Identifier: Apache-2.0
"""One shared view of the GitHub API budget for every session and agent on this machine (#356).

`ghw` is a pass-through for `gh`. It checks the budget before a call, spaces writes, and reads the rate-limit headers
of the answer; the ledger under `~/.local/state/safo/ratebudget` records every call by bucket,
endpoint class and caller.

Rules (docs/ratebudget.md):

* The truth for a bucket is the WORST of every counter seen for it (response headers, the free `rate_limit` endpoint):
  the endpoint alone said "fine" while GraphQL was refusing calls on 2026-11-07.
* 70% used warns, 90% used refuses until that counter resets. A counter past its reset time no longer counts.
* `Retry-After` (and a secondary-limit answer without one) blocks the bucket until it passes.
* Writes are spaced at least one second apart across every process: each writer reserves a slot under a file lock.
* A call that went out is never replayed here; an unknown outcome is reported, not retried.

The budget is advice. A ledger that cannot be read or written (a hostile or full state directory) is said once and the
call goes through; nothing here may make `gh` unusable.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import email.utils
import fcntl
import hashlib
import json
import math
import os
import re
import signal
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, TextIO

from safo import bounded
from safo.credentials import find_gh
from safo.errors import ConfigError

WARN = 0.70
THROTTLE = 0.90
WRITE_SPACING = 1.0
MAX_WAIT = 3600.0  # no Retry-After or reset is believed past an hour
MAX_SPACING_WAIT = 60.0  # a writer queued longer than this is refused, not parked
SECONDARY_WAIT = 60.0  # GitHub: wait at least a minute after a secondary limit with no Retry-After
MAX_STATE_BYTES = 262_144
MAX_HORIZON = 7200.0  # a counter whose reset is further off than this is corrupt, not a throttle
MAX_COUNTERS = 256
GATE_TRIES = 20  # an iteration bound for the launch gate (each try sleeps at most one spacing); not a time bound
GATE_LOCK_WAIT_SECONDS = 30.0  # how long a writer waits for its account's gate while another is spawning
SIGNAL_GRACE_SECONDS = 5.0  # a forwarded signal gets this long to end the child before SIGKILL
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
WRITES = "*"  # the one write queue of a scope, across buckets
AUTH_TIMEOUT_SECONDS = 20.0
IDENTITY_TTL = 3600.0  # how long a credential's account is remembered
NEGATIVE_TTL = 300.0  # how long a failed lookup is remembered (and reported once)
MAX_IDENTITIES = 64
UNKNOWN_WARN = 0.50  # an account that could not be told is throttled earlier
UNKNOWN_THROTTLE = 0.70
MAX_LEDGER_BYTES = 4 * 1024 * 1024
MAX_HEADER_BYTES = 65_536
MAX_PRELUDE = 2  # leading 100-continue or CONNECT blocks allowed before the final header block
GH_TIMEOUT_SECONDS = 120.0
EXIT_THROTTLED = 75  # EX_TEMPFAIL
EXIT_NO_GH = 127
EXIT_UNKNOWN_OUTCOME = 124

LEDGER = "ledger.jsonl"
STATE = "state.json"
LOCK = "lock"
STATUSLINE = "statusline.txt"
IDENTITY = "identity.json"

_NAME = re.compile(r"[a-z_]{1,32}")
_NUMBER = re.compile(r"[0-9]{1,12}")
_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_BAD_CALLER = re.compile(r"[^A-Za-z0-9._-]+")

Clock = Callable[[], float]
Run = Callable[..., "subprocess.CompletedProcess[str]"]


@dataclass(frozen=True)
class Counter:
    key: str  # "<bucket>/<source>": header and endpoint readings of one bucket are two counters
    bucket: str
    limit: int
    remaining: int
    reset: float  # epoch seconds

    @property
    def used_fraction(self) -> float:
        return (self.limit - self.remaining) / self.limit


@dataclass(frozen=True)
class Headroom:
    level: str  # ok, warn, throttle
    used_fraction: float
    min_remaining: int | None
    retry_after: float
    counter: str


@dataclass(frozen=True)
class Decision:
    action: str  # go, refuse
    wait: float  # seconds to sleep before going, or how long a refusal lasts
    level: str
    message: str


@dataclass(frozen=True)
class Classified:
    bucket: str
    klass: str
    write: bool
    free: bool


def state_dir(env: Mapping[str, str]) -> Path:
    chosen = env.get("XDG_STATE_HOME", "")
    if chosen and Path(chosen).is_absolute():
        base = Path(chosen)
    elif env.get("HOME"):
        base = Path(env["HOME"]) / ".local" / "state"
    else:
        raise ConfigError("no state directory: set HOME or XDG_STATE_HOME")
    return base / "safo" / "ratebudget"


def read_boot_id(path: Path = BOOT_ID_PATH) -> str | None:
    """The kernel's boot id (a UUID), which says the monotonic clock is still the same one; None if unavailable."""
    try:
        text = path.read_text().strip()
    except (OSError, UnicodeError):
        return None
    return text if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", text) else None


UNKNOWN_OUTCOME_EXITS = frozenset(
    {EXIT_UNKNOWN_OUTCOME, 128 + signal.SIGHUP, 128 + signal.SIGINT, 128 + signal.SIGTERM}
)
UNKNOWN_OUTCOME_MARKER = "outcome unknown"


def is_unknown_outcome_exit(code: int, stderr: str | None = None) -> bool:
    """True for the exit codes `main` uses when a call may have been sent and its result is not known: 124 (timeout,
    bad output) and 128 plus SIGHUP, SIGINT or SIGTERM (a signal). No other code above 128 is assumed: `gh` itself
    can exit with any code. If `stderr` is given it must also carry the wrapper's own report, so a `gh` that merely
    exited 130 is not mistaken for one."""
    if code not in UNKNOWN_OUTCOME_EXITS:
        return False
    return stderr is None or any(
        line.startswith("ghw: ") and UNKNOWN_OUTCOME_MARKER in line for line in stderr.splitlines()
    )


def clean_caller(value: str) -> str:
    cleaned = _BAD_CALLER.sub("_", value.strip())[:40].replace("::", "_")
    return cleaned or "unknown"


# parsing what GitHub sends: every value is untrusted


def _whole(value: Any, high: int) -> int | None:
    if not isinstance(value, str) or not _NUMBER.fullmatch(value.strip()):
        return None
    number = int(value.strip())
    return number if number <= high else None


def parse_retry_after(value: str, now: float) -> float | None:
    """Seconds to wait from a Retry-After value (seconds or an HTTP date), capped at MAX_WAIT; None when unusable."""
    text = value.strip()
    if not text:
        return None
    if _NUMBER.fullmatch(text):
        return min(float(int(text)), MAX_WAIT)
    try:
        when = email.utils.parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.UTC)
    seconds = when.timestamp() - now
    if not math.isfinite(seconds):
        return None
    return min(max(seconds, 0.0), MAX_WAIT)


def counters_from_headers(headers: Mapping[str, str], default_bucket: str) -> list[Counter]:
    """The x-ratelimit-* headers of one answer as at most one counter; anything off-shape is no counter."""
    limit = _whole(headers.get("x-ratelimit-limit"), 10_000_000)
    remaining = _whole(headers.get("x-ratelimit-remaining"), 10_000_000)
    reset = _whole(headers.get("x-ratelimit-reset"), 4_000_000_000)
    resource = headers.get("x-ratelimit-resource", default_bucket).strip()
    if limit is None or remaining is None or reset is None or limit < 1 or remaining > limit:
        return []
    if not _NAME.fullmatch(resource):
        return []
    return [Counter(f"{resource}/header", resource, limit, remaining, float(reset))]


def counters_from_rate_limit(body: bytes) -> list[Counter]:
    """The free `rate_limit` endpoint as counters, one per resource; a body that is not that shape gives none."""
    try:
        data = bounded.loads(body)
    except (ValueError, RecursionError):  # includes UnicodeError and duplicate keys
        return []
    resources = data.get("resources") if isinstance(data, dict) else None
    if not isinstance(resources, dict):
        return []
    found: list[Counter] = []
    for name, entry in resources.items():
        if not isinstance(name, str) or not _NAME.fullmatch(name) or not isinstance(entry, dict):
            continue
        numbers = [entry.get(k) for k in ("limit", "remaining", "reset")]
        if not all(isinstance(n, int) and not isinstance(n, bool) and n >= 0 for n in numbers):
            continue
        limit, remaining, reset = (int(n) for n in numbers if n is not None)
        if limit < 1 or remaining > limit or limit > 10_000_000 or reset > 4_000_000_000:
            continue
        found.append(Counter(f"{name}/endpoint", name, limit, remaining, float(reset)))
    return found


# what a gh command line will cost, guessed from its words


_VALUE_FLAGS = frozenset(
    {"-X", "--method", "-H", "--header", "-f", "--raw-field", "-F", "--field", "-q", "--jq", "-t", "--template"}
    | {"--input", "--hostname", "--cache", "-p", "--preview"}
)
_FIELD_FLAGS = frozenset({"-f", "--raw-field", "-F", "--field", "--input"})
_BOOL_FLAGS = frozenset({"--include", "-i", "--paginate", "--slurp", "--silent", "--verbose", "--help", "-h"})
_NO_INCLUDE = frozenset({"--include", "-i", "--jq", "-q", "--template", "-t", "--paginate", "--slurp", "--silent"})
_GRAPHQL_GROUPS = frozenset({"project", "issue", "pr", "repo", "release", "label", "milestone", "discussion"})
_FREE_GROUPS = frozenset({"auth", "config", "alias", "completion", "version", "help", "extension", "--version", "-h"})
_WRITE_WORDS = frozenset(
    {"create", "edit", "close", "reopen", "comment", "merge", "delete", "item-edit", "item-add", "item-create"}
    | {"item-delete", "item-archive", "review", "ready", "lock", "unlock", "transfer", "pin", "unpin", "archive"}
    | {"rename", "fork", "sync", "set", "add", "remove", "link", "unlink"}
)


def _flag_name(word: str) -> str:
    return word.split("=", 1)[0] if word.startswith("--") else word


def _endpoint_class(endpoint: str) -> str:
    segments = [s for s in endpoint.split("?", 1)[0].strip("/").split("/") if s]
    if segments and segments[0] == "repos" and len(segments) >= 3:
        segments[1] = segments[2] = "*"
    elif segments and segments[0] in ("users", "orgs") and len(segments) >= 2:
        segments[1] = "*"
    return "/".join("#" if s.isdigit() else s for s in segments) or "api"


def classify(argv: Sequence[str]) -> Classified:
    if not argv:
        return Classified("core", "", False, True)
    if argv[0] != "api":
        group = argv[0]
        klass = " ".join(argv[:2]) if len(argv) > 1 and not argv[1].startswith("-") else group
        if group in _FREE_GROUPS:
            return Classified("core", klass, False, True)
        bucket = "graphql" if group in _GRAPHQL_GROUPS else "search" if group == "search" else "core"
        return Classified(bucket, klass, any(w in _WRITE_WORDS for w in argv[1:3]), False)
    endpoint = ""
    method = ""
    has_fields = False
    mutation = False
    unknown = (
        False  # an option spelling not in gh's documented grammar: its meaning is unknown, so it counts as a write
    )
    skip = False
    for word in argv[1:]:
        if skip:
            skip = False
            if method == "?":
                method = word.upper()
            mutation = mutation or "mutation" in word
            continue
        name = _flag_name(word)
        if word.startswith("-"):
            inline_ok = word.startswith("--") and "=" in word and name in _VALUE_FLAGS
            if word not in _VALUE_FLAGS and word not in _BOOL_FLAGS and not inline_ok:
                unknown = True  # compact (-XPATCH, -X=PATCH), unknown, or a boolean given a value
            has_fields = has_fields or name in _FIELD_FLAGS
            inline = "=" in word and word.startswith("--")
            if name in ("-X", "--method"):
                if inline:
                    method = word.split("=", 1)[1].upper()
                else:
                    method, skip = "?", True
            elif name in _VALUE_FLAGS and not inline:
                skip = True
            elif inline:
                mutation = mutation or "mutation" in word
        elif not endpoint:
            endpoint = word
        else:
            mutation = mutation or "mutation" in word
    bare = endpoint.split("?", 1)[0].strip("/")
    if bare == "rate_limit":
        return Classified("core", "rate_limit", False, True)
    if bare == "graphql":
        return Classified("graphql", "graphql", mutation or unknown, False)
    bucket = "search" if bare.startswith("search/") else "core"
    verb = method if method and method != "?" else ("POST" if has_fields else "GET")
    return Classified(bucket, _endpoint_class(endpoint), verb not in ("GET", "HEAD") or unknown, False)


class GateUnavailable(Exception):
    """The launch gate could not be taken (the ledger directory is unusable); nothing was started."""


class Interrupted(Exception):
    """SIGINT, SIGTERM or SIGHUP arrived while the child ran: the outcome of the call is unknown."""

    def __init__(self, signum: int) -> None:
        super().__init__(f"signal {signum}")
        self.signum = signum


class GateBusy(Exception):
    """The launch gate did not open within its bounded tries; nothing was started."""


class Launched(Protocol):
    def wait(self) -> subprocess.CompletedProcess[str]: ...

    def stop(self, signum: int) -> None: ...


Launcher = Callable[[list[str], str | None], Launched]


class _Finished:
    def __init__(self, result: subprocess.CompletedProcess[str]) -> None:
        self.result = result

    def wait(self) -> subprocess.CompletedProcess[str]:
        return self.result

    def stop(self, signum: int) -> None:
        return None


_FORWARDED = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
_ACTIVE: _SignalGuard | None = None


class _SignalGuard:
    """SIGINT, SIGTERM and SIGHUP, caught from before the launch gate until the call is over.

    The child is detached (its own session), so a signal sent to us never reaches it by itself, and a signal that
    killed us between the spawn and the wait would leave a possibly-applied call with no report. So the three handlers
    are installed first, with the signals blocked while it is done (all three or none), and restored last. While no
    child can exist (`raising`), a signal raises `Interrupted` at once; across the spawn and the launch record it is
    only noted (`pending`), and the caller acts on it as soon as it holds the child. Off the main thread nothing can be
    installed and the guard does nothing.
    """

    def __init__(self) -> None:
        self.pending: int | None = None
        self.raising = False  # set by the caller once it can handle an Interrupted
        self._previous: dict[signal.Signals, Any] = {}

    def _handle(self, signum: int, _frame: object) -> None:
        if self.pending is None:
            self.pending = signum
        if self.raising:
            raise Interrupted(signum)

    def _restore(self) -> None:
        for number, handler in self._previous.items():
            signal.signal(number, signal.SIG_DFL if handler is None else handler)
        self._previous.clear()

    def __enter__(self) -> _SignalGuard:
        if threading.current_thread() is not threading.main_thread():
            return self
        before = signal.pthread_sigmask(signal.SIG_BLOCK, _FORWARDED)
        try:
            for number in _FORWARDED:
                self._previous[number] = signal.signal(number, self._handle)
        except BaseException:
            self._restore()
            raise
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, before)  # a signal that came meanwhile is delivered now
        return self

    def __exit__(self, *_exc: object) -> None:
        if not self._previous:
            return
        before = signal.pthread_sigmask(signal.SIG_BLOCK, _FORWARDED)
        try:
            self._restore()
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, before)


class _Child:
    """A started `gh`. The start is what the launch gate covers; waiting for it to exit is not."""

    def __init__(self, command: list[str], stdin: str | None) -> None:
        self.stdin = stdin
        guard = _ACTIVE
        if guard is not None:
            if guard.pending is not None:
                raise Interrupted(guard.pending)  # a signal came before anything was started: nothing is sent
            guard.raising = False  # from here a child may exist: signals are noted, not raised
        self.process = subprocess.Popen(  # noqa: S603 - argv list, absolute gh found on a trusted PATH, no shell
            command,
            stdin=None if stdin is None else subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,  # its own process group, so a timeout can end the child and its children
        )

    def stop(self, signum: int) -> None:
        """Forward the signal to the child's group, give it a grace period, then SIGKILL the group and reap."""
        group = self.process.pid
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(group, signum)
        with contextlib.suppress(subprocess.TimeoutExpired):
            self.process.wait(timeout=SIGNAL_GRACE_SECONDS)
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(group, signal.SIGKILL)  # also ends anything left in the group, as the leader may have exited
        with contextlib.suppress(subprocess.TimeoutExpired):
            self.process.wait(timeout=5)
        for pipe in (self.process.stdin, self.process.stdout, self.process.stderr):
            if pipe is not None:
                with contextlib.suppress(OSError, ValueError):
                    pipe.close()

    def wait(self) -> subprocess.CompletedProcess[str]:
        """Wait for the child. A signal raises Interrupted here (the guard's handler); the caller stops the child."""
        try:
            out, err = self.process.communicate(input=self.stdin, timeout=GH_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(self.process.pid, signal.SIGKILL)
            with contextlib.suppress(subprocess.TimeoutExpired):
                self.process.communicate(timeout=5)
            raise
        return subprocess.CompletedProcess(self.process.args, self.process.returncode, out, err)


def _launcher(run: Run) -> Launcher:
    """The real launcher is Popen. A stand-in `run` (tests) is called at once, inside the gate."""
    if run is subprocess.run:
        return _Child

    def launch(command: list[str], stdin: str | None) -> Launched:
        extra = {} if stdin is None else {"input": stdin}  # the request body of `--input -`
        return _Finished(run(command, capture_output=True, text=True, check=False, timeout=GH_TIMEOUT_SECONDS, **extra))

    return launch


# private directories: every file operation is relative to one directory descriptor


def open_private_dir(directory: Path, *, create: bool) -> int:
    """A descriptor for `directory`, which must be ours and is repaired to 0700 when it is looser.

    The directory is opened without following a symlink, and every later operation is relative to the descriptor, so
    a name inside cannot be swapped for another directory's entry after this check.
    """
    if create:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.geteuid():
            raise OSError("the ratebudget directory is not owned by this user")
        if info.st_mode & 0o077:
            os.fchmod(fd, 0o700)
    except BaseException:
        os.close(fd)
        raise
    return fd


def check_regular(fd: int) -> None:
    """The descriptor is a regular file of this user with one link; a mode looser than 0600 is repaired."""
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
        raise OSError("not a private regular file of this user")
    if info.st_mode & 0o077:
        os.fchmod(fd, 0o600)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view) :]


def _replace_private(dfd: int, name: str, data: bytes) -> None:
    tmp = f"{name}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
    try:
        check_regular(fd)
        _write_all(fd, data)
    finally:
        os.close(fd)
    os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)


def write_private(path: Path, data: bytes) -> None:
    """Atomically write `data` to `path` inside a private directory (created or repaired)."""
    dfd = open_private_dir(path.parent, create=True)
    try:
        _replace_private(dfd, path.name, data)
    finally:
        os.close(dfd)


def read_private(dfd: int, name: str, limit: int) -> bytes:
    """At most limit+1 bytes of a private regular file of this user.

    Raises FileNotFoundError when it is absent, and OSError when it is not safe to read: a symlink, a FIFO or other
    special file, a file of another user, or one with more than one link. A mode looser than 0600 is repaired.
    """
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
    try:
        check_regular(fd)
        chunks: list[bytes] = []
        total = 0
        while total <= limit:
            chunk = os.read(fd, min(65_536, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _read_private(dfd: int, name: str, limit: int) -> bytes | None:
    """`read_private`, with None for every failure (absent or unsafe)."""
    try:
        return read_private(dfd, name, limit)
    except OSError:
        return None


# who is calling: a host and credential scope for every counter


def _option_value(argv: Sequence[str], name: str) -> str:
    for i, word in enumerate(argv):
        if word == name and i + 1 < len(argv):
            return argv[i + 1]
        if word.startswith(name + "="):
            return word.split("=", 1)[1]
    return ""


@dataclass(frozen=True)
class Scope:
    name: str
    unknown: bool  # the account could not be told: a conservative, uncoordinated scope
    note: str  # a line to say once (empty when there is nothing new to say)


UNKNOWN_NOTE = (
    "ghw: could not tell which account this credential belongs to; using an unknown-account budget, "
    "throttled early, that is not shared with other credentials"
)
_LOGIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,38}")


def _hash(*parts: str) -> str:
    return hashlib.sha256(b"safo-ratebudget-scope\0" + b"\0".join(p.encode() for p in parts)).hexdigest()[:20]


def _identity_get(directory: Path, key: str, now: float) -> tuple[bool, str | None] | None:
    """(found, scope-or-None) from the identity cache, or None when there is no live entry."""
    try:
        dfd = open_private_dir(directory, create=False)
    except OSError:
        return None
    try:
        raw = _read_private(dfd, IDENTITY, MAX_STATE_BYTES)
    finally:
        os.close(dfd)
    try:
        entry = bounded.loads(raw).get("ids", {}).get(key) if raw else None
    except (ValueError, RecursionError, AttributeError):
        return None
    if not isinstance(entry, dict):
        return None
    if not _valid_identity(key, entry):
        return None
    at, scope = entry["at"], entry.get("scope")
    ttl = IDENTITY_TTL if scope else NEGATIVE_TTL
    if not at - 60 <= now <= at + ttl:
        return None
    return True, scope


def _valid_identity(key: object, entry: object) -> bool:
    """A cache record is kept only if it is exactly the shape this code writes."""
    if not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{20}", key) or not isinstance(entry, dict):
        return False
    at, scope = entry.get("at"), entry.get("scope")
    if isinstance(at, bool) or not isinstance(at, int | float) or not -1e15 < at < 1e15:
        return False
    return scope is None or (isinstance(scope, str) and re.fullmatch(r"[0-9a-f]{20}", scope) is not None)


def _identity_put(directory: Path, clock: Clock, key: str, scope: str | None) -> None:
    now = clock()
    with Budget(directory, clock)._locked() as dfd:
        raw = _read_private(dfd, IDENTITY, MAX_STATE_BYTES)
        try:
            data = bounded.loads(raw) if raw else {}
        except (ValueError, RecursionError):
            data = {}
        loaded = data.get("ids") if isinstance(data, dict) else None
        ids = {k: v for k, v in loaded.items() if _valid_identity(k, v)} if isinstance(loaded, dict) else {}
        ids[key] = {"at": now, "scope": scope}
        newest = sorted(ids.items(), key=lambda kv: -float(kv[1]["at"]))
        _replace_private(dfd, IDENTITY, bounded_dumps({"ids": dict(newest[:MAX_IDENTITIES])}).encode())


def scope_for(
    env: Mapping[str, str],
    argv: Sequence[str],
    run: Run,
    gh: str | None,
    directory: Path | None = None,
    clock: Clock = time.time,
) -> Scope:
    """The budget scope of a call: GitHub host plus the authenticated ACCOUNT, because GitHub limits the account.

    Several tokens of one account share one limit, so the credential is not the scope. It is only the key of a small
    cache (under `directory`, hour-long) that remembers which account `gh api user` said it belongs to; the token
    itself is hashed in memory and never stored, and nor is the login (only a hash of host and login).
    When the account cannot be told (no credential, `gh` failing) the scope is `unknown-<credential hash>`: it is not
    merged with any other credential's, it is throttled earlier, and the condition is reported once per cache period.
    """
    host = (_option_value(argv, "--hostname") or env.get("GH_HOST", "") or "github.com").strip().lower()[:253]
    names = ("GH_TOKEN", "GITHUB_TOKEN") if host == "github.com" else ("GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")
    secret = next((env[n] for n in names if env.get(n)), "")
    if not secret and gh is not None:
        try:
            done = run(
                [gh, "auth", "token", "--hostname", host],
                capture_output=True,
                text=True,
                check=False,
                timeout=AUTH_TIMEOUT_SECONDS,
                stdin=subprocess.DEVNULL,
            )
            secret = (done.stdout or "").strip() if done.returncode == 0 else ""
        except (OSError, subprocess.TimeoutExpired, UnicodeError):
            secret = ""
    key = _hash("credential", host, secret)  # the cache key; reveals nothing about the credential
    unknown = Scope("unknown-" + key[:12], True, "")
    now = clock()
    if directory is not None:
        cached = _identity_get(directory, key, now)
        if cached is not None:
            return Scope(cached[1], False, "") if cached[1] else unknown
    login = ""
    if secret and gh is not None:
        command = [gh, "api", "user"] + ([] if host == "github.com" else ["--hostname", host]) + ["--jq", ".login"]
        try:
            done = run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=AUTH_TIMEOUT_SECONDS,
                stdin=subprocess.DEVNULL,
            )
            text = (done.stdout or "").strip() if done.returncode == 0 else ""
            login = text if _LOGIN.fullmatch(text) else ""
        except (OSError, subprocess.TimeoutExpired, UnicodeError):
            login = ""
    account = _hash("account", host, login.lower()) if login else None
    if directory is not None:
        with contextlib.suppress(OSError, TypeError, ValueError, OverflowError):
            _identity_put(directory, clock, key, account)
    if account:
        return Scope(account, False, "")
    return Scope(unknown.name, True, UNKNOWN_NOTE)


# the ledger


class Budget:
    """The shared state under one directory, for one scope (host and account). Every change holds the file lock."""

    def __init__(
        self,
        directory: Path,
        clock: Clock = time.time,
        scope: str = "local",
        *,
        unknown: bool = False,
        mono: Clock | None = None,
        boot_id: str | None = None,
    ) -> None:
        self.directory = directory
        self.clock = clock
        self.scope = scope
        self.warn = UNKNOWN_WARN if unknown else WARN
        self.throttle = UNKNOWN_THROTTLE if unknown else THROTTLE
        if mono is None and clock is time.time:  # production: spacing is read from this boot's monotonic clock
            mono, boot_id = time.monotonic, boot_id or read_boot_id()
        self.mono = mono if boot_id else None
        self.boot_id = boot_id

    def _k(self, name: str) -> str:
        return f"{self.scope}|{name}"

    @property
    def gate_lock_name(self) -> str:
        """The lock file of this scope's launch gate: a hash, so no scope text reaches the file system."""
        return f"gate-{hashlib.sha256(self.scope.encode()).hexdigest()[:20]}.lock"

    # locking and files

    @contextlib.contextmanager
    def _locked(self) -> Iterator[int]:
        dfd = open_private_dir(self.directory, create=True)
        try:
            lock = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
            try:
                check_regular(lock)
                fcntl.flock(lock, fcntl.LOCK_EX)
                yield dfd
            finally:
                os.close(lock)  # closing releases the lock
        finally:
            os.close(dfd)

    def _read(self, name: str, limit: int) -> bytes | None:
        try:
            dfd = open_private_dir(self.directory, create=False)
        except OSError:
            return None
        try:
            return _read_private(dfd, name, limit)
        finally:
            os.close(dfd)

    def _load(self, dfd: int | None = None) -> dict[str, Any]:
        raw = _read_private(dfd, STATE, MAX_STATE_BYTES) if dfd is not None else self._read(STATE, MAX_STATE_BYTES)
        if raw is None or len(raw) > MAX_STATE_BYTES:
            return {}
        try:
            data = bounded.loads(raw)
        except (ValueError, RecursionError):
            return {}
        return data if isinstance(data, dict) else {}

    def _counters(self, state: Mapping[str, Any]) -> list[Counter]:
        """Every scope's counters; one whose reset is past the horizon is corrupt and is not returned."""
        now = self.clock()
        found: list[Counter] = []
        raw = state.get("counters")
        for key, entry in raw.items() if isinstance(raw, dict) else []:
            try:
                found.append(
                    Counter(
                        str(key),
                        str(entry["bucket"]),
                        int(entry["limit"]),
                        int(entry["remaining"]),
                        float(entry["reset"]),
                    )
                )
            except (KeyError, TypeError, ValueError, OverflowError):
                continue
        return [
            c
            for c in found
            if c.limit >= 1 and 0 <= c.remaining <= c.limit and math.isfinite(c.reset) and c.reset <= now + MAX_HORIZON
        ]

    def _map(self, state: Mapping[str, Any], name: str, ahead: float) -> dict[str, float]:
        """A name -> epoch map from state; a time more than `ahead` seconds from now is corrupt and is dropped."""
        raw = state.get(name)
        now = self.clock()
        out: dict[str, float] = {}
        for key, value in raw.items() if isinstance(raw, dict) else []:
            numeric = isinstance(value, int | float) and not isinstance(value, bool)
            if numeric and math.isfinite(value) and value <= now + ahead:
                out[str(key)] = float(value)
        return out

    def _blocked(self, state: Mapping[str, Any]) -> dict[str, float]:
        return self._map(state, "blocked", MAX_WAIT)

    def _written(self, state: Mapping[str, Any]) -> dict[str, float]:
        return self._map(state, "last_write", MAX_SPACING_WAIT)

    def _launched(self, state: Mapping[str, Any]) -> dict[str, float]:
        return self._map(state, "last_launch", math.inf)

    def _save(self, dfd: int, state: dict[str, Any]) -> None:
        state["updated"] = self.clock()
        _replace_private(dfd, STATE, bounded_dumps(state).encode())
        _replace_private(dfd, STATUSLINE, (self._line(state) + "\n").encode())

    # reading the truth

    def _headroom(self, state: Mapping[str, Any], bucket: str) -> Headroom:
        now = self.clock()
        key = self._k(bucket)
        live = [c for c in self._counters(state) if c.bucket == key and c.reset > now]
        blocked = self._blocked(state).get(key, 0.0) - now
        if not live and blocked <= 0:
            return Headroom("ok", 0.0, None, 0.0, "")
        worst = max(live, key=lambda c: (c.used_fraction, -c.remaining), default=None)
        used = worst.used_fraction if worst else 0.0
        retry = 0.0
        level = "ok"
        if worst and used >= self.throttle:
            level, retry = "throttle", min(worst.reset - now, MAX_WAIT)
        elif worst and used >= self.warn:
            level = "warn"
        if blocked > 0:
            level, retry = "throttle", max(retry, min(blocked, MAX_WAIT))
        counter = worst.key.removeprefix(self.scope + "|") if worst else "blocked"
        return Headroom(level, used, min((c.remaining for c in live), default=None), retry, counter)

    def headroom(self, bucket: str) -> Headroom:
        return self._headroom(self._load(), bucket)

    def observe(self, counters: Sequence[Counter]) -> None:
        with self._locked() as dfd:
            state = self._load(dfd)
            self._apply(state, counters, None, None)
            self._save(dfd, state)

    def block(self, bucket: str, seconds: float) -> None:
        with self._locked() as dfd:
            state = self._load(dfd)
            self._apply(state, (), (bucket, seconds), None)
            self._save(dfd, state)

    def _apply(
        self,
        state: dict[str, Any],
        counters: Sequence[Counter],
        block: tuple[str, float] | None,
        slot: float | None,
        launched: float | None = None,
    ) -> None:
        now = self.clock()
        kept = {c.key: c for c in self._counters(state)}
        for c in counters:
            if c.reset > now + MAX_HORIZON:
                continue  # an implausible reset is no observation
            key = self._k(c.key)
            kept[key] = Counter(key, self._k(c.bucket), c.limit, c.remaining, c.reset)
        live = sorted((c for c in kept.values() if c.reset > now), key=lambda c: c.reset)[-MAX_COUNTERS:]
        state["counters"] = {
            c.key: {"bucket": c.bucket, "limit": c.limit, "remaining": c.remaining, "reset": c.reset} for c in live
        }
        blocked = {k: v for k, v in self._blocked(state).items() if v > now}
        if block:
            key = self._k(block[0])
            blocked[key] = max(blocked.get(key, 0.0), now + min(max(block[1], 0.0), MAX_WAIT))
        state["blocked"] = blocked
        written = self._written(state)
        if slot is not None:
            written[self._k(WRITES)] = slot
        state["last_write"] = {k: v for k, v in written.items() if v > now - 3600}
        launches = self._launched(state)
        monos = state.get("launch_mono")
        monos = dict(monos) if isinstance(monos, dict) else {}
        if launched is not None:
            launches[self._k(WRITES)] = launched
            if self.mono is not None and self.boot_id is not None:
                monos[self._k(WRITES)] = {"boot": self.boot_id, "t": self.mono()}
            else:
                monos.pop(self._k(WRITES), None)
        state["last_launch"] = {k: v for k, v in launches.items() if v > now - 3600}
        state["launch_mono"] = {k: v for k, v in monos.items() if k in state["last_launch"]}

    def _judge(self, state: Mapping[str, Any], bucket: str) -> Decision | None:
        """A refusal when the bucket is throttled or blocked now; None otherwise."""
        head = self._headroom(state, bucket)
        if head.level != "throttle":
            return None
        message = (
            f"{bucket} budget {head.used_fraction:.0%} used or blocked; retry after {math.ceil(head.retry_after)}s"
        )
        return Decision("refuse", head.retry_after, "throttle", message)

    def reserve(self, bucket: str, *, write: bool) -> Decision:
        """Decide, and for a write claim the next free one-second slot so concurrent writers queue instead of racing.

        The queue is one per scope across every bucket: GitHub asks for a second between mutating requests, not a
        second per rate-limit resource.
        """
        with self._locked() as dfd:
            state = self._load(dfd)
            now = self.clock()
            refusal = self._judge(state, bucket)
            if refusal:
                return refusal
            head = self._headroom(state, bucket)
            wait = 0.0
            if write:
                slot = max(now, self._written(state).get(self._k(WRITES), 0.0) + WRITE_SPACING)
                wait = slot - now
                if wait > MAX_SPACING_WAIT:
                    return Decision(
                        "refuse", wait, "throttle", f"{bucket} writes are queued; retry after {math.ceil(wait)}s"
                    )
                self._apply(state, (), None, slot)
                self._save(dfd, state)
            message = ""
            if head.level == "warn":
                left = head.min_remaining if head.min_remaining is not None else 0
                message = f"WARNING {bucket} budget {head.used_fraction:.0%} used ({left} left): slow down"
            return Decision("go", wait, head.level, message)

    def _launch_wait(self, state: dict[str, Any], dfd: int) -> float:
        """Seconds to wait before the next launch of this account (0: go). Under the state lock.

        Same boot: elapsed time since the last launch is read from the monotonic clock, which a wall-clock step cannot
        move. Otherwise the wall clock is used, and a recorded launch that lies in the future (the clock stepped back,
        or the record is corrupt) fails closed: it is clamped to now and costs one spacing, once; it is never dropped.
        """
        key = self._k(WRITES)
        record = state.get("launch_mono")
        entry = record.get(key) if isinstance(record, dict) else None
        if self.mono is not None and isinstance(entry, dict) and entry.get("boot") == self.boot_id:
            seen = entry.get("t")
            if isinstance(seen, int | float) and not isinstance(seen, bool) and math.isfinite(seen):
                elapsed = self.mono() - float(seen)
                if elapsed >= 0:
                    return max(0.0, WRITE_SPACING - elapsed)
                self._apply(state, (), None, None, self.clock())  # a record from the future: repaired, as below
                self._save(dfd, state)
                return WRITE_SPACING
        last = self._launched(state).get(key)
        if last is None:
            return 0.0
        now = self.clock()
        if last > now:
            self._apply(state, (), None, None, now)
            self._save(dfd, state)
            return WRITE_SPACING
        return max(0.0, last + WRITE_SPACING - now)

    def _take_gate(self, dfd: int) -> int:
        """The descriptor of this account's gate lock, once it is ours; waits up to GATE_LOCK_WAIT_SECONDS."""
        fd = os.open(self.gate_lock_name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
        try:
            check_regular(fd)
            give_up = time.monotonic() + GATE_LOCK_WAIT_SECONDS
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return fd
                except BlockingIOError:
                    if time.monotonic() >= give_up:
                        raise GateBusy("another launch of this account is still starting") from None
                    time.sleep(0.01)
        except BaseException:
            os.close(fd)
            raise

    def launch_gate(self, start: Callable[[], Any], sleep: Callable[[float], None]) -> Any:
        """Start a write's child no sooner than WRITE_SPACING after the last ACTUAL launch of this account.

        A reservation is only a place in the queue: a process can be descheduled between reserving and launching and
        then run after a later ticket. So the wait is measured here, from the recorded launch time, under this
        account's gate lock (a file of its own: another account is never held up by it). `start()` (the spawn, not the
        child's whole life) runs while the gate lock is held; the shared state lock is taken only briefly, to read the
        record and to write the real launch time afterwards, never across the spawn. A spawn that fails still counts as
        a launch. At most GATE_TRIES checks are made, each followed by a sleep of at most one spacing, outside the
        state lock.
        """
        try:
            dfd = open_private_dir(self.directory, create=True)
        except OSError as problem:
            raise GateUnavailable(type(problem).__name__) from problem
        try:
            try:
                gate = self._take_gate(dfd)
            except OSError as problem:
                raise GateUnavailable(type(problem).__name__) from problem
            try:
                return self._gated(start, sleep)
            finally:
                os.close(gate)
        finally:
            os.close(dfd)

    def _gated(self, start: Callable[[], Any], sleep: Callable[[float], None]) -> Any:
        for _ in range(GATE_TRIES):
            try:
                with self._locked() as sdfd:
                    wait = self._launch_wait(self._load(sdfd), sdfd)
            except OSError as problem:
                raise GateUnavailable(type(problem).__name__) from problem
            if wait > 0:
                sleep(wait)
                continue
            value: Any = None
            error: Exception | None = None
            try:
                value = start()
            except Exception as problem:  # kept until the launch is recorded, then re-raised
                error = problem
            # the child is already out; a save failure is reported later
            with contextlib.suppress(OSError), self._locked() as sdfd:
                state = self._load(sdfd)
                self._apply(state, (), None, None, self.clock())
                self._save(sdfd, state)
            if error is not None:
                raise error
            return value
        raise GateBusy("the launch gate did not open")

    def confirm(self, bucket: str) -> Decision:
        """Re-check a bucket just before launching a call that waited for its slot. Takes no new slot."""
        with self._locked() as dfd:
            return self._judge(self._load(dfd), bucket) or Decision("go", 0.0, "ok", "")

    def record(
        self,
        *,
        caller: str,
        bucket: str,
        klass: str,
        write: bool,
        status: int,
        counters: Sequence[Counter] = (),
        block_for: float | None = None,
    ) -> None:
        """Save the counters and the block first, then append the audit row; the row may fail alone (OSError)."""
        row = {"t": round(self.clock(), 3), "caller": clean_caller(caller), "bucket": bucket, "class": klass}
        row |= {"write": write, "status": status}
        with self._locked() as dfd:
            state = self._load(dfd)
            self._apply(state, counters, (bucket, block_for) if block_for else None, None)
            self._save(dfd, state)
            self._append(dfd, bounded_dumps(row) + "\n")

    @staticmethod
    def _append(dfd: int, line: str) -> None:
        try:
            if os.stat(LEDGER, dir_fd=dfd, follow_symlinks=False).st_size > MAX_LEDGER_BYTES:
                os.replace(LEDGER, f"{LEDGER}.1", src_dir_fd=dfd, dst_dir_fd=dfd)
        except FileNotFoundError:
            pass
        fd = os.open(LEDGER, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
        try:
            check_regular(fd)
            _write_all(fd, line.encode())
        finally:
            os.close(fd)

    # reports

    def rows(self) -> list[dict[str, Any]]:
        raw = self._read(LEDGER, 2 * MAX_LEDGER_BYTES)
        rows: list[dict[str, Any]] = []
        for line in (raw or b"").splitlines():
            try:
                row = bounded.loads(line)
            except (ValueError, RecursionError):
                continue
            if isinstance(row, dict):
                rows.append(row)
        return rows

    def by_caller(self) -> dict[str, dict[str, dict[str, int]]]:
        report: dict[str, dict[str, dict[str, int]]] = {}
        for row in self.rows():
            caller, bucket = str(row.get("caller", "unknown")), str(row.get("bucket", "core"))
            cell = report.setdefault(caller, {}).setdefault(bucket, {"calls": 0, "writes": 0})
            cell["calls"] += 1
            cell["writes"] += 1 if row.get("write") is True else 0
        return report

    def _line(self, state: Mapping[str, Any]) -> str:
        now = self.clock()
        prefix = self.scope + "|"
        names = {c.bucket for c in self._counters(state) if c.reset > now} | set(self._blocked(state))
        buckets = sorted(n.removeprefix(prefix) for n in names if n.startswith(prefix))
        parts = []
        for bucket in buckets:
            head = self._headroom(state, bucket)
            if head.counter == "":
                continue
            tag = {"warn": " WARN", "throttle": " THROTTLE"}.get(head.level, "")
            left = f"{head.min_remaining} left" if head.min_remaining is not None else "blocked"
            parts.append(f"{bucket} {head.used_fraction:.0%} ({left}){tag}")
        if parts:
            return "ratebudget: " + ", ".join(parts)
        return "ratebudget: ok (no live counters)" if state.get("updated") else "ratebudget: no calls recorded"

    def status_line(self) -> str:
        return self._line(self._load())


def bounded_dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


# the gh wrapper


def _sensitive(name: str) -> bool:
    return name.startswith("x-ratelimit-") or name == "retry-after"


def _parse_block(text: str) -> tuple[int, str, dict[str, str], str] | None:
    """(status, reason, lower-cased headers, rest) of the header block at the start of `text`, or None."""
    if not text.startswith("HTTP/"):
        return None
    match = re.search(r"\r?\n\r?\n", text[:MAX_HEADER_BYTES])
    if match is None:
        return None
    lines = text[: match.start()].splitlines()
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[1].isdigit() or len(parts[1]) != 3:
        return None
    headers: dict[str, str] = {}
    seen: set[str] = set()
    tainted = len(lines) > 200
    for line in lines[1:200]:
        name, sep, value = line.partition(":")
        if line[:1] in (" ", "\t") or not sep or not _TOKEN.fullmatch(name):
            tainted = True  # obs-fold, no colon, or a name that is not an HTTP token: this block cannot be trusted
            continue
        key = name.lower()
        if key in seen and _sensitive(key):
            tainted = True  # a repeated rate-limit header: first-value and last-value readers would disagree
        seen.add(key)
        headers[key] = value.strip()
    if tainted:
        headers = {k: v for k, v in headers.items() if not _sensitive(k)}
    return int(parts[1]), parts[2].strip().lower() if len(parts) > 2 else "", headers, text[match.end() :]


def _is_prelude(status: int, reason: str, headers: Mapping[str, str]) -> bool:
    """A block that is followed by the real one: any 1xx, or a proxy's bare `200 Connection established`."""
    return 100 <= status < 200 or (status == 200 and reason.startswith("connection established") and not headers)


def _split_response(text: str) -> tuple[int, dict[str, str], str]:
    """(status, lower-cased headers, body) of `gh api --include` output; (0, {}, text) when it is not that shape.

    Only a 1xx block or a proxy's CONNECT answer may come before the final block, at most MAX_PRELUDE of them. The first
    final status (200-599) ends the headers: everything after it is body, even if it starts with `HTTP/`, so a body
    cannot pose as headers and feed fake rate-limit values to the ledger.
    """
    rest = text
    for _ in range(MAX_PRELUDE + 1):
        block = _parse_block(rest)
        if block is None:
            return 0, {}, text
        status, reason, headers, rest = block
        if _is_prelude(status, reason, headers):
            continue
        if not 200 <= status <= 599:
            return 0, {}, text
        return status, headers, rest
    return 0, {}, text  # more leading blocks than allowed: nothing here is trusted


def _graphql_secondary(body: str) -> bool:
    """A GraphQL answer (HTTP 200 is possible) whose `errors` list has a secondary-rate-limit message.

    Only the message of an entry in the top-level `errors` list is read: the same words in `data` (user-controlled
    text) or in another member do not count, and a body that is not bounded JSON counts for nothing.
    """
    try:
        data = bounded.loads(body)
    except (ValueError, RecursionError):
        return False
    errors = data.get("errors") if isinstance(data, dict) else None
    if not isinstance(errors, list):
        return False
    return any(
        isinstance(e, dict) and isinstance(e.get("message"), str) and "secondary rate limit" in e["message"].lower()
        for e in errors
    )


def _injectable(argv: Sequence[str]) -> bool:
    return bool(argv) and argv[0] == "api" and not any(_flag_name(w) in _NO_INCLUDE for w in argv[1:])


def main(
    argv: Sequence[str],
    *,
    env: Mapping[str, str],
    out: TextIO,
    err: TextIO,
    run: Run = subprocess.run,
    sleep: Callable[[float], None] = time.sleep,
    clock: Clock = time.time,
    gh: str | None = None,
    stdin: str | None = None,
    launch: Launcher | None = None,
) -> int:
    if not argv:
        err.write("usage: ghw <gh arguments>   (gh, with the shared API budget applied; caller: $SAFO_CALLER)\n")
        return 2
    exe = gh or find_gh(env)
    if exe is None:
        err.write("ghw: gh was not found on PATH\n")
        return EXIT_NO_GH
    what = classify(argv)
    command = [exe, *argv]
    ledger: Budget | None = None
    if not what.free:
        try:
            directory = state_dir(env)
            scope = scope_for(env, argv, run, exe, directory, clock)
            if scope.note:
                err.write(scope.note + "\n")
            ledger = Budget(directory, clock, scope.name, unknown=scope.unknown)
            decision = ledger.reserve(what.bucket, write=what.write)
        except (OSError, ConfigError, TypeError, ValueError, OverflowError) as problem:
            err.write(f"ghw: the budget ledger is unavailable ({type(problem).__name__}); going ahead without it\n")
            ledger = None
        else:
            if decision.action == "refuse":
                err.write(f"ghw: {decision.message}\n")
                return EXIT_THROTTLED
            if decision.message:
                err.write(decision.message + "\n")
            if decision.wait > 0:
                sleep(decision.wait)
                try:
                    again = ledger.confirm(what.bucket)  # another writer may have hit a limit while this one queued
                except OSError:
                    again = None
                if again is not None and again.action == "refuse":
                    err.write(f"ghw: {again.message}\n")
                    return EXIT_THROTTLED
    inject = ledger is not None and _injectable(argv)
    if inject:
        command = [exe, "api", "--include", *argv[1:]]
    starter = launch or _launcher(run)
    child: Launched | None = None
    guard = _SignalGuard()
    global _ACTIVE
    with guard:
        _ACTIVE = guard
        try:
            guard.raising = True  # nothing is started yet: a signal now simply stops us
            if guard.pending is not None:  # one that came while the handlers were being installed
                err.write(f"ghw: interrupted by signal {guard.pending} before the call was sent; nothing was sent\n")
                return 128 + guard.pending
            try:
                if ledger is not None and what.write:
                    try:
                        child = ledger.launch_gate(lambda: starter(command, stdin), sleep)
                    except GateUnavailable as problem:
                        err.write(f"ghw: the launch gate is unavailable ({problem}); going ahead without it\n")
                        child = starter(command, stdin)
                    except GateBusy:
                        err.write("ghw: the launch gate stayed busy; nothing was sent, retry shortly\n")
                        return EXIT_THROTTLED
                else:
                    child = starter(command, stdin)
                guard.raising = True  # the child exists: from here a signal interrupts the wait
                if guard.pending is not None:
                    raise Interrupted(guard.pending)
                done = child.wait()
            except Interrupted as stop:
                guard.raising = False  # clean-up must not be interrupted
                if child is None:
                    err.write(f"ghw: interrupted by signal {stop.signum} before the call was sent; nothing was sent\n")
                    return 128 + stop.signum
                child.stop(stop.signum)
                err.write(
                    f"ghw: interrupted by signal {stop.signum}; {UNKNOWN_OUTCOME_MARKER} "
                    "(the call may or may not have been applied); not retried\n"
                )
                _record(ledger, env, what, 0, [], None, err)
                return 128 + stop.signum
            except (OSError, subprocess.TimeoutExpired, UnicodeError) as problem:  # bad UTF-8 is unknown too
                # sent or not, we cannot tell: record it, never replay it
                err.write(f"ghw: {UNKNOWN_OUTCOME_MARKER} ({type(problem).__name__}); not retried\n")
                _record(ledger, env, what, 0, [], None, err)
                return EXIT_UNKNOWN_OUTCOME
            guard.raising = False  # the call is over; a later signal is noted and honoured below
            return _finish(done, inject, what, ledger, env, clock, out, err, guard)
        finally:
            _ACTIVE = None


def _finish(
    done: subprocess.CompletedProcess[str],
    inject: bool,
    what: Classified,
    ledger: Budget | None,
    env: Mapping[str, str],
    clock: Clock,
    out: TextIO,
    err: TextIO,
    guard: _SignalGuard,
) -> int:
    stdout = done.stdout or ""
    status, headers, body = _split_response(stdout) if inject else (0, {}, stdout)
    out.write(body)
    if done.stderr:
        err.write(done.stderr)
    block: float | None = None
    if status in (403, 429):
        block = parse_retry_after(headers.get("retry-after", ""), clock())
        if block is None and (status == 429 or "secondary rate limit" in body.lower()):
            block = SECONDARY_WAIT
    elif what.bucket == "graphql" and 200 <= status < 300 and _graphql_secondary(body):
        block = parse_retry_after(headers.get("retry-after", ""), clock())
        if block is None:
            block = SECONDARY_WAIT
    counters = counters_from_headers(headers, what.bucket) if headers else []
    _record(ledger, env, what, status, counters, block, err)
    if guard.pending is not None:  # told to stop while finishing: the call is reported above, then honour it
        return 128 + guard.pending
    return done.returncode


def _record(
    ledger: Budget | None,
    env: Mapping[str, str],
    what: Classified,
    status: int,
    counters: Sequence[Counter],
    block: float | None,
    err: TextIO,
) -> None:
    if ledger is None:
        return
    try:
        ledger.record(
            caller=env.get("SAFO_CALLER", "unknown"),
            bucket=what.bucket,
            klass=what.klass,
            write=what.write,
            status=status,
            counters=counters,
            block_for=block,
        )
    except OSError as problem:  # counters and blocks are saved before the audit row; say so once
        err.write(f"ghw: the budget ledger could not be written ({type(problem).__name__}); the call is not repeated\n")


def refresh(ledger: Budget, env: Mapping[str, str], run: Run = subprocess.run, gh: str | None = None) -> int:
    """Read the free `rate_limit` endpoint into the ledger; returns how many counters it gave."""
    exe = gh or find_gh(env)
    if exe is None:
        raise ConfigError("gh was not found on PATH")
    try:
        done = run([exe, "api", "rate_limit"], capture_output=True, text=True, check=False, timeout=GH_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as problem:
        raise ConfigError(f"could not read rate_limit ({type(problem).__name__})") from problem
    counters = counters_from_rate_limit((done.stdout or "").encode()) if done.returncode == 0 else []
    if counters:
        ledger.observe(counters)
    return len(counters)


def run() -> None:
    raise SystemExit(main(sys.argv[1:], env=os.environ, out=sys.stdout, err=sys.stderr))
