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
import json
import math
import os
import re
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

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
MAX_LEDGER_BYTES = 4 * 1024 * 1024
MAX_HEADER_BYTES = 65_536
GH_TIMEOUT_SECONDS = 120.0
EXIT_THROTTLED = 75  # EX_TEMPFAIL
EXIT_NO_GH = 127
EXIT_UNKNOWN_OUTCOME = 124

LEDGER = "ledger.jsonl"
STATE = "state.json"
LOCK = "lock"
STATUSLINE = "statusline.txt"

_NAME = re.compile(r"[a-z_]{1,32}")
_NUMBER = re.compile(r"[0-9]{1,12}")
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
        return Classified("graphql", "graphql", mutation, False)
    bucket = "search" if bare.startswith("search/") else "core"
    verb = method if method and method != "?" else ("POST" if has_fields else "GET")
    return Classified(bucket, _endpoint_class(endpoint), verb not in ("GET", "HEAD"), False)


# the ledger


class Budget:
    """The shared state under one directory. Every method that changes it holds the file lock for the whole step."""

    def __init__(self, directory: Path, clock: Clock = time.time) -> None:
        self.directory = directory
        self.clock = clock

    # locking and files

    def _ensure(self) -> None:
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            raise OSError("the ratebudget directory is not a directory of this user")

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        self._ensure()
        fd = os.open(self.directory / LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)  # closing releases the lock

    def _write_atomic(self, name: str, text: str) -> None:
        tmp = self.directory / f"{name}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, text.encode())
        finally:
            os.close(fd)
        os.replace(tmp, self.directory / name)

    def _load(self) -> dict[str, Any]:
        try:
            raw = bounded.read_bounded(self.directory / STATE, MAX_STATE_BYTES + 1)
            if len(raw) > MAX_STATE_BYTES:
                return {}
            data = bounded.loads(raw)
        except (OSError, ValueError, RecursionError):
            return {}
        return data if isinstance(data, dict) else {}

    def _counters(self, state: Mapping[str, Any]) -> list[Counter]:
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
        return [c for c in found if c.limit >= 1 and 0 <= c.remaining <= c.limit and math.isfinite(c.reset)]

    @staticmethod
    def _map(state: Mapping[str, Any], name: str) -> dict[str, float]:
        raw = state.get(name)
        out: dict[str, float] = {}
        for key, value in raw.items() if isinstance(raw, dict) else []:
            if isinstance(value, int | float) and not isinstance(value, bool) and math.isfinite(value):
                out[str(key)] = float(value)
        return out

    def _save(self, state: dict[str, Any]) -> None:
        state["updated"] = self.clock()
        self._write_atomic(STATE, bounded_dumps(state))
        self._write_atomic(STATUSLINE, self._line(state) + "\n")

    # reading the truth

    def _headroom(self, state: Mapping[str, Any], bucket: str) -> Headroom:
        now = self.clock()
        live = [c for c in self._counters(state) if c.bucket == bucket and c.reset > now]
        blocked = self._map(state, "blocked").get(bucket, 0.0) - now
        if not live and blocked <= 0:
            return Headroom("ok", 0.0, None, 0.0, "")
        worst = max(live, key=lambda c: (c.used_fraction, -c.remaining), default=None)
        used = worst.used_fraction if worst else 0.0
        retry = 0.0
        level = "ok"
        if worst and used >= THROTTLE:
            level, retry = "throttle", min(worst.reset - now, MAX_WAIT)
        elif worst and used >= WARN:
            level = "warn"
        if blocked > 0:
            level, retry = "throttle", max(retry, min(blocked, MAX_WAIT))
        return Headroom(
            level, used, min((c.remaining for c in live), default=None), retry, worst.key if worst else "blocked"
        )

    def headroom(self, bucket: str) -> Headroom:
        return self._headroom(self._load(), bucket)

    def observe(self, counters: Sequence[Counter]) -> None:
        with self._locked():
            state = self._load()
            self._apply(state, counters, None, None)
            self._save(state)

    def block(self, bucket: str, seconds: float) -> None:
        with self._locked():
            state = self._load()
            self._apply(state, (), (bucket, seconds), None)
            self._save(state)

    def _apply(
        self,
        state: dict[str, Any],
        counters: Sequence[Counter],
        block: tuple[str, float] | None,
        last_write: tuple[str, float] | None,
    ) -> None:
        kept = {c.key: c for c in self._counters(state)}
        for c in counters:
            kept[c.key] = c
        state["counters"] = {
            k: {"bucket": c.bucket, "limit": c.limit, "remaining": c.remaining, "reset": c.reset}
            for k, c in kept.items()
            if c.reset > self.clock()
        }
        blocked = {k: v for k, v in self._map(state, "blocked").items() if v > self.clock()}
        if block:
            blocked[block[0]] = max(blocked.get(block[0], 0.0), self.clock() + min(max(block[1], 0.0), MAX_WAIT))
        state["blocked"] = blocked
        written = self._map(state, "last_write")
        if last_write:
            written[last_write[0]] = last_write[1]
        state["last_write"] = {k: v for k, v in written.items() if v > self.clock() - 3600}

    def reserve(self, bucket: str, *, write: bool) -> Decision:
        """Decide, and for a write claim the next free one-second slot so concurrent writers queue instead of racing."""
        with self._locked():
            state = self._load()
            now = self.clock()
            head = self._headroom(state, bucket)
            if head.level == "throttle":
                seconds = math.ceil(head.retry_after)
                message = f"{bucket} budget {head.used_fraction:.0%} used or blocked; retry after {seconds}s"
                return Decision("refuse", head.retry_after, "throttle", message)
            wait = 0.0
            if write:
                slot = max(now, self._map(state, "last_write").get(bucket, 0.0) + WRITE_SPACING)
                wait = slot - now
                if wait > MAX_SPACING_WAIT:
                    return Decision(
                        "refuse", wait, "throttle", f"{bucket} writes are queued; retry after {math.ceil(wait)}s"
                    )
                self._apply(state, (), None, (bucket, slot))
                self._save(state)
            message = ""
            if head.level == "warn":
                left = head.min_remaining if head.min_remaining is not None else 0
                message = f"WARNING {bucket} budget {head.used_fraction:.0%} used ({left} left): slow down"
            return Decision("go", wait, head.level, message)

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
        row = {"t": round(self.clock(), 3), "caller": clean_caller(caller), "bucket": bucket, "class": klass}
        row |= {"write": write, "status": status}
        with self._locked():
            path = self.directory / LEDGER
            with contextlib.suppress(FileNotFoundError):
                if path.stat().st_size > MAX_LEDGER_BYTES:
                    os.replace(path, self.directory / f"{LEDGER}.1")
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                os.write(fd, (bounded_dumps(row) + "\n").encode())
            finally:
                os.close(fd)
            state = self._load()
            self._apply(state, counters, (bucket, block_for) if block_for else None, None)
            self._save(state)

    # reports

    def rows(self) -> list[dict[str, Any]]:
        try:
            lines = bounded.json_lines(self.directory / LEDGER)
        except (OSError, ValueError):
            return []
        return [row for _, row in lines if isinstance(row, dict)]

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
        buckets = sorted({c.bucket for c in self._counters(state) if c.reset > now} | set(self._map(state, "blocked")))
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


def _split_response(text: str) -> tuple[int, dict[str, str], str]:
    """(status, lower-cased headers, body) of `gh api --include` output; (0, {}, text) when it is not that shape."""
    status = 0
    headers: dict[str, str] = {}
    body = text
    for _ in range(3):  # a 100-continue or a proxy can put more than one header block first
        if not body.startswith("HTTP/"):
            break
        match = re.search(r"\r?\n\r?\n", body[:MAX_HEADER_BYTES])
        if match is None:
            return 0, {}, text
        head, body = body[: match.start()], body[match.end() :]
        lines = head.splitlines()
        parts = lines[0].split(" ", 2)
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        headers = {}
        for line in lines[1:200]:
            name, sep, value = line.partition(":")
            if sep:
                headers[name.strip().lower()] = value.strip()
    return status, headers, body


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
            ledger = Budget(state_dir(env), clock)
            decision = ledger.reserve(what.bucket, write=what.write)
        except (OSError, ConfigError) as problem:
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
    inject = ledger is not None and _injectable(argv)
    if inject:
        command = [exe, "api", "--include", *argv[1:]]
    try:
        extra = {} if stdin is None else {"input": stdin}  # the request body of `--input -`; else gh inherits stdin
        done = run(command, capture_output=True, text=True, check=False, timeout=GH_TIMEOUT_SECONDS, **extra)
    except (OSError, subprocess.TimeoutExpired) as problem:
        # sent or not, we cannot tell: record it, never replay it
        err.write(f"ghw: outcome unknown ({type(problem).__name__}); not retried\n")
        _record(ledger, env, what, 0, [], None)
        return EXIT_UNKNOWN_OUTCOME
    stdout = done.stdout or ""
    status, headers, body = _split_response(stdout) if inject else (0, {}, stdout)
    out.write(body)
    if done.stderr:
        err.write(done.stderr)
    block: float | None = None
    if status in (403, 429):
        block = parse_retry_after(headers.get("retry-after", ""), clock())
        if block is None and "secondary rate limit" in body.lower():
            block = SECONDARY_WAIT
    counters = counters_from_headers(headers, what.bucket) if headers else []
    _record(ledger, env, what, status, counters, block)
    return done.returncode


def _record(
    ledger: Budget | None,
    env: Mapping[str, str],
    what: Classified,
    status: int,
    counters: Sequence[Counter],
    block: float | None,
) -> None:
    if ledger is None:
        return
    with contextlib.suppress(OSError):
        ledger.record(
            caller=env.get("SAFO_CALLER", "unknown"),
            bucket=what.bucket,
            klass=what.klass,
            write=what.write,
            status=status,
            counters=counters,
            block_for=block,
        )


def refresh(ledger: Budget, env: Mapping[str, str], run: Run = subprocess.run, gh: str | None = None) -> int:
    """Read the free `rate_limit` endpoint into the ledger; returns how many counters it gave."""
    exe = gh or find_gh(env)
    if exe is None:
        raise ConfigError("gh was not found on PATH")
    try:
        done = run([exe, "api", "rate_limit"], capture_output=True, text=True, check=False, timeout=GH_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired) as problem:
        raise ConfigError(f"could not read rate_limit ({type(problem).__name__})") from problem
    counters = counters_from_rate_limit((done.stdout or "").encode()) if done.returncode == 0 else []
    if counters:
        ledger.observe(counters)
    return len(counters)


def run() -> None:
    raise SystemExit(main(sys.argv[1:], env=os.environ, out=sys.stdout, err=sys.stderr))
