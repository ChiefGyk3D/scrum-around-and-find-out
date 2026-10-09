# SPDX-License-Identifier: MIT
"""Where the routing guard keeps its files, and what its log says. Read here by `agents-status`; written by `hooks`.

One JSON object per line in `log.jsonl`, appended by the dispatch guard on every decision. A record holds
`ts`, `decision` (allow, warn or deny), `mode`, `model`, `local_reachable`, `local_step`, `na` and `rules`, the names of
the routing rules the brief broke. It never holds the brief, the description or any other prompt text.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import fcntl
import math
import os
import stat
import tempfile
import time
from collections import Counter
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from safo.bounded import MAX_BYTES, loads, read_bounded

MODES = ("warn", "block")
DEFAULT_MODE = "warn"
LOG_NAME = "log.jsonl"
PROBE_NAME = "probe.json"
MODE_NAME = "mode"


def _base(env: Mapping[str, str], xdg: str, fallback: tuple[str, ...]) -> Path | None:
    chosen = env.get(xdg, "")
    if chosen and Path(chosen).is_absolute():
        return Path(chosen)
    home = env.get("HOME", "")
    return Path(home).joinpath(*fallback) if home else None


def state_dir(env: Mapping[str, str]) -> Path | None:
    """`$XDG_STATE_HOME/safo/hooks`, else `~/.local/state/safo/hooks`; None when neither is known."""
    base = _base(env, "XDG_STATE_HOME", (".local", "state"))
    return base / "safo" / "hooks" if base else None


def config_dir(env: Mapping[str, str]) -> Path | None:
    """`$XDG_CONFIG_HOME/safo`, else `~/.config/safo`; None when neither is known."""
    base = _base(env, "XDG_CONFIG_HOME", (".config",))
    return base / "safo" if base else None


WARNING = "SAFO routing guard degraded: enforcement may be incomplete; inspect safo hooks status."
MODEL_IDS = ("sonnet", "haiku", "opus", "unknown")
RULE_IDS = ("no-model", "unknown-model", "approval", "no-local-step")
DIAGNOSTICS = ("mode", "config", "input", "timeout", "probe", "state-write", "log-write", "unexpected")
HEALTH = ("healthy", "degraded", "stale", "unknown")
RECORD_CAP = 2048
FILE_CAP = 4 * 1024 * 1024


def bounded_read(path: Path, limit: int = MAX_BYTES) -> bytes:
    """The whole regular file, or ValueError when it is larger than `limit`.

    Opened without following a symlink and without waiting on a FIFO; the type is judged on the descriptor.
    """
    raw = read_bounded(path, limit + 1)
    if len(raw) > limit:
        raise ValueError("file exceeds size limit")
    return raw


def trusted_dir(folder: Path) -> bool:
    """True when `folder` is a directory owned by the effective user that no other user can write to.

    A lock is a pathname's current inode, and the mode, probe and log files are found by pathname, so whoever can write
    to the directory can unlink and replace them. Judged on the directory itself (a link to it is followed); the
    directories above it are the user's own business.
    """
    try:
        info = os.stat(folder)
    except OSError:
        return False
    return stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022


def ensure_dir(folder: Path, check_dir: bool = True) -> None:
    """Make `folder` and any missing parents mode 0700 (whatever the umask); PermissionError for an untrusted one.

    Only directories created here are changed; one that already exists keeps its mode and is judged as it is.
    """
    missing: list[Path] = []
    here = folder
    while not here.exists() and here != here.parent:
        missing.append(here)
        here = here.parent
    for created in reversed(missing):
        try:
            os.mkdir(created, 0o700)
        except FileExistsError:
            continue
        os.chmod(created, 0o700)
    if check_dir and not trusted_dir(folder):
        raise PermissionError(f"{folder.name}: not owned by this user, or writable by others")


@contextlib.contextmanager
def file_lock(path: Path, check_dir: bool = True) -> Iterator[None]:
    ensure_dir(path.parent, check_dir)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("expected regular lock file")
        deadline = time.monotonic() + 0.5
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("lock busy") from None
                time.sleep(0.01)
        yield
    finally:
        os.close(fd)


def write_text(
    path: Path,
    text: str,
    mode: int = 0o600,
    before_replace: Callable[[], None] | None = None,
    check_dir: bool = True,
) -> None:
    """Exclusive random temp, cleanup, file and directory fsync; callers lock read/modify/write sequences."""
    ensure_dir(path.parent, check_dir)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), mode)
            handle.write(text.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        if before_replace is not None:
            before_replace()
        os.replace(temp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temp.unlink(missing_ok=True)


def mode_health(env: Mapping[str, str]) -> tuple[str, str]:
    folder = config_dir(env)
    if folder is None:
        return DEFAULT_MODE, "unknown"
    if os.path.lexists(folder) and not trusted_dir(folder):
        return DEFAULT_MODE, "degraded"  # a mode file another user could have written is not a block setting
    try:
        text = bounded_read(folder / MODE_NAME, 16).decode("utf-8").strip()
    except FileNotFoundError:
        return DEFAULT_MODE, "healthy"  # never configured: explicit default, not a corrupt block setting
    except (OSError, ValueError, UnicodeError):
        return DEFAULT_MODE, "degraded"
    return (text, "healthy") if text in MODES else (DEFAULT_MODE, "degraded")


def read_mode(env: Mapping[str, str]) -> str:
    return mode_health(env)[0]


def finite_time(value: Any) -> bool:
    return type(value) in (int, float) and 0 <= value <= 253402300799 and math.isfinite(value)


def valid_record(row: Any) -> bool:
    keys = {"ts", "decision", "mode", "model", "local_reachable", "local_step", "na", "rules", "health", "diagnostic"}
    if not isinstance(row, dict) or set(row) != keys:
        return False
    ts = row["ts"]
    try:
        if not isinstance(ts, str) or len(ts) != 19 or dt.datetime.fromisoformat(ts).isoformat() != ts:
            return False
    except ValueError:
        return False
    return (
        row["decision"] in ("allow", "warn", "deny", "error")
        and row["mode"] in MODES
        and row["model"] in (*MODEL_IDS, None)
        and row["health"] in HEALTH
        and row["diagnostic"] in ("", *DIAGNOSTICS)
        and all(type(row[k]) is bool for k in ("local_reachable", "local_step", "na"))
        and isinstance(row["rules"], list)
        and len(row["rules"]) <= len(RULE_IDS)
        and all(type(r) is str and r in RULE_IDS for r in row["rules"])
        and len(set(row["rules"])) == len(row["rules"])
    )


def read_log(path: Path | None) -> list[dict[str, Any]]:
    if path is None:
        return []
    try:
        os.lstat(path)  # read-only: a missing log is "nothing yet", never a reason to create its folder or a lock
    except OSError:
        return []
    if not trusted_dir(path.parent):
        return []
    try:
        with file_lock(path.with_name(path.name + ".lock")):
            raw = bounded_read(path, FILE_CAP)
    except (OSError, ValueError, TimeoutError):
        return []
    rows = []
    for line in raw.splitlines(keepends=True):
        if not line.endswith(b"\n") or len(line) > RECORD_CAP:
            continue
        try:
            row = loads(line)
        except (ValueError, UnicodeError):
            continue
        if valid_record(row):
            rows.append(row)
    return rows


@dataclass(frozen=True)
class GuardCounts:
    total: int
    since: str
    decisions: tuple[tuple[str, int], ...]
    models: tuple[tuple[str, int], ...]
    rules: tuple[tuple[str, int], ...]
    local_steps: int
    marked_na: int
    last_flagged: str


def summarise(rows: list[dict[str, Any]]) -> GuardCounts:
    decisions = Counter(str(r.get("decision", "?")) for r in rows)
    models = Counter(str(r.get("model") or "none") for r in rows)
    rules = Counter(str(rule) for r in rows for rule in r["rules"])
    flagged = [r for r in rows if r["rules"]]
    last = (
        f"{str(flagged[-1].get('ts', ''))[11:16]} {', '.join(str(x) for x in flagged[-1]['rules'])}" if flagged else ""
    )
    return GuardCounts(
        len(rows),
        str(rows[0].get("ts", ""))[:10] if rows else "",
        tuple(decisions.most_common()),
        tuple(models.most_common()),
        tuple(sorted(rules.items())),
        sum(1 for r in rows if r.get("local_step") is True),
        sum(1 for r in rows if r.get("na") is True),
        last.strip(),
    )


def guard_lines(env: Mapping[str, str]) -> list[str]:
    """The `Routing guard` section of agents-status."""
    folder = state_dir(env)
    rows = read_log(folder / LOG_NAME if folder else None)
    counts = summarise(rows)
    mode, health = mode_health(env)
    last_health = rows[-1]["health"] if rows else "unknown"
    if folder is not None and os.path.lexists(folder) and not trusted_dir(folder):
        last_health = "degraded"
    elif folder is not None:
        try:
            raw = bounded_read(folder / LOG_NAME, FILE_CAP)
            complete_lines = [line for line in raw.splitlines(keepends=True) if line.strip()]
            if len(complete_lines) != len(rows):
                last_health = "degraded"
        except FileNotFoundError:
            pass
        except (OSError, ValueError):
            last_health = "degraded"
    lines = [
        f"Routing guard (mode: {mode})",
        f"  health: {'degraded' if health == 'degraded' else last_health}; counts cover retained history",
    ]
    if not counts.total:
        return [*lines, "  no dispatches logged yet"]
    lines.append(
        f"  {counts.total} dispatches since {counts.since}: " + ", ".join(f"{k} {v}" for k, v in counts.decisions)
    )
    lines.append(
        "  models: "
        + ", ".join(f"{k} {v}" for k, v in counts.models)
        + f"; briefs with a local step {counts.local_steps}, marked n/a {counts.marked_na}"
    )
    if counts.rules:
        lines.append("  rules flagged: " + ", ".join(f"{k} {v}" for k, v in counts.rules))
    if counts.last_flagged:
        lines.append(f"  last flagged: {counts.last_flagged}")
    return lines
