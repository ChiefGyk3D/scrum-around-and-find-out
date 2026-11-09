# SPDX-License-Identifier: Apache-2.0
"""safo-activity: what the AI helpers are doing right now, read only, for a status line, a table or an event monitor.

    safo-activity                  one line for a status line (cached 10 s); empty when nothing is going on
    safo-activity --table          the detail table, never cached
    safo-activity --json           the same facts as JSON
    safo-activity --watch          the table, redrawn every 2 s until interrupted
    safo-activity --events NAME    one short line per state change of one provider (codex, ollama, ledger, copilot)
    safo-activity --version

Providers (all read only; a provider that is absent or fails leaves its segment out and never raises):
  codex    running jobs from the Codex plugin job files under ~/.claude/plugins/data/codex-openai-codex/state
  quota    plan windows (5 hour, weekly) of Codex from ~/.codex/sessions and of Claude from a small cache file; local
           files only, on by default
  ledger   the local spend ledger kept by the SAFO wrapper: counts, the action name and ages, never entry content
  ollama   loaded models, from `GET /api/ps` of an endpoint in the agents config or $LLM_LOCAL_URL; opt in
  copilot  GitHub Copilot code review state of the owner's open pull requests, REST through `gh`; opt in

With no configuration only codex, quota and ledger are read (local files only). `SAFO_ACTIVITY_PROVIDERS` (comma
list) or `providers:` in `~/.config/safo/activity.yaml` choose the set. See docs/activity.md.

Every string that came from a file or the network is cut to printable ASCII (a plain character class, no decoding of
escapes) and to a short length before it is printed. Nothing here writes outside its own cache files.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import glob
import json
import os
import re
import signal
import stat
import sys
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO, TypeVar
from urllib.parse import quote, urlsplit

import safo
from safo.bounded import read_bounded
from safo.guardlog import config_dir

T = TypeVar("T")

PROVIDERS = ("codex", "quota", "ollama", "ledger", "copilot")
EVENT_PROVIDERS = ("codex", "ollama", "ledger", "copilot")
ALIASES = {"gemini": "ledger"}
DEFAULT_PROVIDERS = ("codex", "quota", "ledger")
LINE_TTL = 10  # seconds a status line is served from its cache
COPILOT_TTL = 60  # seconds the Copilot answer is cached
COPILOT_PR_CAP = 15
COPILOT_CALL_TIMEOUT = 5.0
COPILOT_DEADLINE = 20.0
COPILOT_RUN_NAME = "Running Copilot Code Review"
COPILOT_REVIEWER = "copilot-pull-request-reviewer"
OLLAMA_TIMEOUT = 1.0
OLLAMA_ENDPOINT_CAP = 3
CODEX_JOBS_REL = (".claude", "plugins", "data", "codex-openai-codex", "state", "*", "jobs", "*.json")
CODEX_FILE_CAP = 40
JOB_BYTES = 65_536
LEDGER_TAIL_BYTES = 262_144
LEDGER_TAIL_LINES = 2000
LEDGER_LINE_BYTES = 16_384
CONFIG_BYTES = 65_536
DONE_WINDOW = 3600
WATCH_INTERVAL = 2.0
EVENTS_INTERVAL = 2.0
EVENTS_WINDOW = 60.0
EVENTS_CAP = 6
EVENTS_LIMIT = 29 * 60.0
OWNER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}")
REPO_RE = re.compile(r"[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}")
SHA_RE = re.compile(r"[0-9a-f]{7,64}")
USAGE = (
    "usage: safo-activity [--table | --json | --watch | --events codex|ollama|ledger|copilot | --version]\n"
    "  no option: one line for a status line (empty when nothing is going on)\n"
)


def clean(text: object, limit: int = 200) -> str:
    """Printable ASCII only (control characters, newlines, tabs and non-ASCII become spaces), runs squeezed, cut."""
    return re.sub(" +", " ", re.sub("[^ -~]", " ", str(text)))[:limit]


def human_age(seconds: float) -> str:
    s = max(0, int(seconds))
    if s < 120:
        return f"{s}s"
    if s < 7200:
        return f"{s // 60}m"
    if s < 172800:
        return f"{s // 3600}h"
    return f"{s // 86400}d"


def parse_time(text: object) -> float | None:
    """Seconds since the epoch for an ISO 8601 stamp; a stamp with no zone is local time."""
    if not isinstance(text, str) or not text:
        return None
    try:
        when = dt.datetime.fromisoformat(text)
        return when.astimezone().timestamp() if when.tzinfo is None else when.timestamp()
    except (ValueError, OverflowError, OSError):
        return None


# -- configuration ------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Config:
    providers: tuple[str, ...]
    owner: str = ""  # whose pull requests the copilot provider reads; empty: the login `gh` has
    notes: tuple[str, ...] = ()


def _names(raw: object) -> tuple[tuple[str, ...], tuple[str, ...]]:
    items = raw.split(",") if isinstance(raw, str) else raw if isinstance(raw, list) else []
    chosen: list[str] = []
    notes: list[str] = []
    for item in items:
        name = ALIASES.get(str(item).strip().lower(), str(item).strip().lower())
        if name in PROVIDERS:
            if name not in chosen:
                chosen.append(name)
        elif name:
            notes.append(f"unknown provider {clean(name, 30)!r} ignored")
    return tuple(p for p in PROVIDERS if p in chosen), tuple(notes)


def _read_yaml_config(env: Mapping[str, str]) -> dict[str, Any]:
    base = config_dir(env)
    if base is None or not (base / "activity.yaml").exists():
        return {}
    try:
        text = read_bounded(base / "activity.yaml", CONFIG_BYTES + 1)
        if len(text) > CONFIG_BYTES:
            return {}
        import yaml  # only a machine that has the file pays for the import

        data = yaml.safe_load(text)
    except Exception:  # a bad config file must not stop a status line
        return {}
    return data if isinstance(data, dict) else {}


def load_config(env: Mapping[str, str]) -> Config:
    """SAFO_ACTIVITY_PROVIDERS wins over `providers:` in activity.yaml; with neither only codex and ledger are read."""
    given = env.get("SAFO_ACTIVITY_PROVIDERS")
    owner = env.get("SAFO_ACTIVITY_COPILOT_OWNER", "")
    data: dict[str, Any] = {}
    if given is None or not owner:
        data = _read_yaml_config(env)
    raw = given if given is not None else data.get("providers")
    providers, notes = _names(raw)
    if not isinstance(raw, (str, list)):
        providers = DEFAULT_PROVIDERS
    if not owner:
        section = data.get("copilot")
        raw = section.get("owner") if isinstance(section, dict) else None
        owner = raw if isinstance(raw, str) else ""
    return Config(providers, owner if OWNER_RE.fullmatch(owner) else "", notes)


# -- codex ----------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Job:
    key: str  # the file path: how a finished job is matched to a started one
    title: str
    phase: str
    kind: str
    running: bool
    age: float  # seconds since it started (running) or finished (done)


@dataclass(frozen=True)
class CodexSnap:
    running: tuple[Job, ...] = ()
    done: tuple[Job, ...] = ()


def _field(value: object) -> str:
    return clean(value, 120) if value not in (None, "") else "-"


def read_job(path: str, now: float) -> Job | None:
    """One job file as a Job when it is a running job with a live process or a job completed in the last hour."""
    try:
        data = json.loads(read_bounded(Path(path), JOB_BYTES))
    except (OSError, ValueError, RecursionError):
        return None
    if not isinstance(data, dict):
        return None
    status = data.get("status")
    title, phase, kind = (_field(data.get(k)) for k in ("title", "phase", "kindLabel"))
    if status == "completed":
        finished = parse_time(data.get("completedAt"))
        if finished is None or not 0 <= now - finished <= DONE_WINDOW:
            return None
        return Job(path, title, phase, kind, False, now - finished)
    if not status or status in ("failed", "cancelled") or not isinstance(status, str):
        return None
    pid = data.get("pid")
    if isinstance(pid, bool) or not (isinstance(pid, int) or (isinstance(pid, str) and pid.isdigit())):
        return None
    number = int(pid)
    if number < 2:  # 0 would signal our own process group
        return None
    try:
        os.kill(number, 0)
    except (OSError, OverflowError):
        return None
    started = parse_time(data.get("startedAt"))
    return Job(path, title, phase, kind, True, now - started if started is not None else 0.0)


def collect_codex(home: str, now: float) -> CodexSnap:
    if not home:
        return CodexSnap()
    found: list[tuple[float, str]] = []
    for name in glob.glob(str(Path(home, *CODEX_JOBS_REL))):
        with contextlib.suppress(OSError):
            info = os.lstat(name)
            if stat.S_ISREG(info.st_mode):
                found.append((info.st_mtime, name))
    running: list[Job] = []
    done: list[Job] = []
    for _, name in sorted(found, reverse=True)[:CODEX_FILE_CAP]:
        job = read_job(name, now)
        if job is not None:
            (running if job.running else done).append(job)
    return CodexSnap(tuple(running), tuple(done))


# -- ledger ---------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class LedgerSnap:
    ok: bool = False
    today: int = 0  # rows stamped today (local date)
    newest_age: float | None = None
    typed: int = 0  # call_start and call_end rows seen: 0 means starts and ends cannot be told apart
    inflight: tuple[tuple[str, str, float], ...] = ()  # (call id, action name, age)


def ledger_path(env: Mapping[str, str], home: str) -> Path | None:
    """`ledger:` from gemini.yaml when it names an absolute path, else the wrapper's default place under home."""
    base = config_dir(env)
    if base is not None:
        with contextlib.suppress(OSError):
            for line in read_bounded(base / "gemini.yaml", CONFIG_BYTES).decode("utf-8", "replace").splitlines():
                found = re.fullmatch(r"ledger:\s*(\S.*?)\s*", line)
                if found:
                    named = found.group(1).strip("'\"")
                    if named.startswith("/"):
                        return Path(named)
                    break
    return Path(home, ".local", "share", "safo", "gemini-spend-ledger.jsonl") if home else None


def tail_rows(path: Path) -> list[dict[str, Any]] | None:
    """The parsable object rows among the last 2000 lines; None when the file is not a readable regular file.

    Not the chain-verifying reader: a status line must not raise on a broken chain. It opens without following a
    symlink and without waiting on a FIFO, takes no lock and writes nothing."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None
        start = max(0, info.st_size - LEDGER_TAIL_BYTES)
        os.lseek(fd, start, os.SEEK_SET)
        raw = b""
        while len(raw) < LEDGER_TAIL_BYTES + 1:
            chunk = os.read(fd, LEDGER_TAIL_BYTES + 1 - len(raw))
            if not chunk:
                break
            raw += chunk
    except OSError:
        return None
    finally:
        os.close(fd)
    lines = raw.split(b"\n")
    if start > 0:
        lines = lines[1:]  # the first line of a tail window is usually cut
    rows: list[dict[str, Any]] = []
    for line in lines[-LEDGER_TAIL_LINES:]:
        if not line.strip() or len(line) > LEDGER_LINE_BYTES:
            continue
        try:
            row = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def collect_ledger(env: Mapping[str, str], home: str, now: float) -> LedgerSnap:
    path = ledger_path(env, home)
    rows = tail_rows(path) if path is not None else None
    if rows is None:
        return LedgerSnap()
    today = time.strftime("%Y-%m-%d", time.localtime(now))
    count, newest, typed = 0, 0.0, 0
    starts: dict[str, tuple[str, float]] = {}
    ended: set[str] = set()
    for row in rows:
        when = parse_time(row.get("ts"))
        if when is not None:
            newest = max(newest, when)
            if time.strftime("%Y-%m-%d", time.localtime(when)) == today:
                count += 1
        kind, call = row.get("type"), row.get("call_id")
        if kind not in ("call_start", "call_end") or not isinstance(call, str) or not call:
            continue
        typed += 1
        if kind == "call_end":
            ended.add(call)
        elif when is not None and time.strftime("%Y-%m-%d", time.localtime(when)) == today:
            starts[call] = (clean(row.get("job") or "-", 40) or "-", when)
    inflight = tuple((c, job, now - w) for c, (job, w) in starts.items() if c not in ended)
    return LedgerSnap(True, count, now - newest if newest else None, typed, inflight)


# -- ollama ---------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class OllamaSnap:
    configured: bool = False  # an endpoint is named
    ok: bool = False  # at least one answered
    models: tuple[tuple[str, str], ...] = ()  # (short name, expiry note)
    busy: int | None = None  # established connections to the port; None when `ss` is not there


def _endpoint_urls(env: Mapping[str, str], home: str) -> list[str]:
    """Only $LLM_LOCAL_URL or an endpoint of the agents config; nothing is ever assumed."""
    from safo import netguard

    def sound(url: str) -> bool:
        parts = urlsplit(url)
        try:
            port = parts.port
        except ValueError:
            return False
        return (
            parts.scheme in ("http", "https")
            and bool(parts.hostname)
            and port != 0
            and not (parts.username or parts.password or parts.query or parts.fragment)
            and not netguard.literal_blocked(parts.hostname or "")
        )

    given = env.get("LLM_LOCAL_URL", "").strip().rstrip("/")
    if given:
        return [given] if sound(given) else []
    if not home:
        return []
    from safo.agentsfile import load_agents_merged
    from safo.localfiles import refuse_workspace

    base = Path(home, ".config", "safo")
    chosen = env.get("SAFO_AGENTS", "")
    chosen_local = env.get("SAFO_AGENTS_LOCAL", "")
    path = refuse_workspace(
        Path(chosen) if chosen else base / "agents.yaml", env, "the agents file", explicit=bool(chosen)
    )
    local = refuse_workspace(
        Path(chosen_local) if chosen_local else base / "agents.local.yaml",
        env,
        "the local agents file",
        explicit=bool(chosen_local),
    )
    if not path.exists():
        return []
    doc = load_agents_merged(path, local if local.exists() else None)
    urls = [e.url.rstrip("/") for a in doc.agents if a.kind == "ollama" for e in a.endpoints]
    return [u for u in dict.fromkeys(urls) if sound(u)]


def _short_model(name: object) -> str:
    text = clean(name, 80).strip().rsplit("/", 1)[-1]
    return text.removesuffix(":latest")[:40]


def _expiry_note(raw: object, now: float) -> str:
    when = parse_time(raw)
    if when is None:
        return "expiry unknown"
    if when - now > 31_536_000:
        return "stays loaded (no expiry)"
    return f"expires in {human_age(when - now)}"


def _established(env: Mapping[str, str], port: int) -> int | None:
    from safo.credentials import find_executable

    ss = find_executable("ss", env)
    if ss is None:
        return None
    import subprocess

    try:
        done = subprocess.run(  # noqa: S603 - a fixed argument list; the port is an int
            [ss, "-Htn", "state", "established", f"( dport = :{port} )"],
            capture_output=True,
            timeout=2,
            check=False,
            env={"PATH": env.get("PATH", ""), "LC_ALL": "C"},
            cwd="/",
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return len([ln for ln in done.stdout.splitlines() if ln.strip()]) if done.returncode == 0 else None


def collect_ollama(env: Mapping[str, str], home: str, now: float) -> OllamaSnap:
    try:
        urls = _endpoint_urls(env, home)
    except Exception:  # a broken agents file means no endpoint, never an error here
        return OllamaSnap()
    if not urls:
        return OllamaSnap()
    from safo.ollama import _request  # the guarded client: pinned address, no redirect, no proxy

    models: dict[str, str] = {}
    answered, busy = False, None
    for url in urls[:OLLAMA_ENDPOINT_CAP]:
        try:
            body = _request(f"{url}/api/ps", data=None, timeout=OLLAMA_TIMEOUT)  # the loaded-model listing only
        except Exception:  # noqa: S112 - any failure at all means "not answering"; the endpoint is skipped
            continue
        rows = body.get("models") if isinstance(body, dict) else None
        if not isinstance(rows, list):
            continue
        answered = True
        for row in rows:
            if isinstance(row, dict) and _short_model(row.get("name")):
                models.setdefault(_short_model(row["name"]), _expiry_note(row.get("expires_at"), now))
        port = urlsplit(url).port or (443 if url.startswith("https") else 80)
        count = _established(env, port)
        if count is not None:
            busy = (busy or 0) + count
    return OllamaSnap(True, answered, tuple(models.items()), busy)


# -- copilot --------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class CopilotSnap:
    ok: bool = False
    checked: int = 0
    running: tuple[str, ...] = ()  # owner/repo#number with a review run queued or in progress
    unread: tuple[tuple[str, int, int], ...] = ()  # (ref, reviews with a body, inline comments) on the current head
    age: float = 0.0


def cache_dir(env: Mapping[str, str]) -> Path | None:
    for var, rest in (("XDG_RUNTIME_DIR", ()), ("HOME", (".cache",))):
        base = env.get(var, "")
        if base and os.path.isabs(base):
            return Path(base, *rest)
    return None


GH_ENV = ("PATH", "HOME", "GH_TOKEN", "GITHUB_TOKEN", "GH_HOST", "GH_CONFIG_DIR", "XDG_CONFIG_HOME")


def _gh_env(env: Mapping[str, str]) -> dict[str, str]:
    """What gh needs to find its own login, and nothing else from the caller's environment."""
    return {**{k: env[k] for k in GH_ENV if k in env}, "GH_PROMPT_DISABLED": "1", "NO_COLOR": "1"}


def _gh_json(gh: str, env: Mapping[str, str], path: str, timeout: float) -> Any:
    """One REST GET through gh. The only arguments are `api` and a path: no method, no field, no input, no GraphQL."""
    import subprocess

    done = subprocess.run(  # noqa: S603 - fixed argument list; the path is built from validated parts
        [gh, "api", path],
        capture_output=True,
        timeout=timeout,
        check=False,
        env=_gh_env(env),
        cwd="/",
        stdin=subprocess.DEVNULL,
    )
    if done.returncode != 0 or len(done.stdout) > 2_000_000:
        raise OSError("gh api failed")
    return json.loads(done.stdout)


def _login(user: object) -> str:
    name = user.get("login") if isinstance(user, dict) else None
    return name.removesuffix("[bot]") if isinstance(name, str) else ""


def _check_pr(gh: str, env: Mapping[str, str], ref: str, deadline: float) -> tuple[bool, int, int] | None:
    """(review running, reviews with a body on the head, inline comments on the head), counts only."""
    repo, number = ref.split("#")

    def get(path: str) -> Any:
        left = deadline - time.monotonic()
        if left <= 0:
            raise OSError("deadline")
        return _gh_json(gh, env, f"repos/{repo}/{path}", min(COPILOT_CALL_TIMEOUT, left))

    try:
        sha = (get(f"pulls/{number}").get("head") or {}).get("sha")
        if not isinstance(sha, str) or not SHA_RE.fullmatch(sha):
            return None
        runs = get(f"actions/runs?event=dynamic&head_sha={sha}&per_page=30").get("workflow_runs") or []
        running = any(
            isinstance(r, dict)
            and r.get("name") == COPILOT_RUN_NAME
            and r.get("event") == "dynamic"
            and r.get("status") in ("queued", "in_progress")
            for r in runs
        )
        reviews = get(f"pulls/{number}/reviews?per_page=100")
        comments = get(f"pulls/{number}/comments?per_page=100")
    except (OSError, ValueError, AttributeError, TypeError, RecursionError):
        return None
    except Exception:  # a timeout or a gh that vanished: this pull request is skipped
        return None
    bodied = sum(
        1
        for r in reviews
        if isinstance(r, dict)
        and _login(r.get("user")) == COPILOT_REVIEWER
        and r.get("commit_id") == sha
        and isinstance(r.get("body"), str)
        and r["body"].strip()
    )
    inline = sum(
        1
        for c in comments
        if isinstance(c, dict) and _login(c.get("user")) == COPILOT_REVIEWER and c.get("commit_id") == sha
    )
    return running, bodied, inline


def fetch_copilot(env: Mapping[str, str], owner: str, now: float) -> CopilotSnap:
    from concurrent.futures import ThreadPoolExecutor

    from safo.credentials import find_gh

    gh = find_gh(env)
    if gh is None:
        return CopilotSnap()
    deadline = time.monotonic() + COPILOT_DEADLINE
    try:
        if not owner:
            owner = _login(_gh_json(gh, env, "user", COPILOT_CALL_TIMEOUT))
        if not OWNER_RE.fullmatch(owner):
            return CopilotSnap()
        query = quote(f"is:pr is:open user:{owner}")
        found = _gh_json(gh, env, f"search/issues?q={query}&per_page={COPILOT_PR_CAP}", COPILOT_CALL_TIMEOUT)
        items = found.get("items") if isinstance(found, dict) else None
        if not isinstance(items, list):
            return CopilotSnap()
    except Exception:  # not logged in, offline, rate limited: the segment is left out
        return CopilotSnap()
    refs: list[str] = []
    for item in items[:COPILOT_PR_CAP]:
        number = item.get("number") if isinstance(item, dict) else None
        url = item.get("repository_url") if isinstance(item, dict) else None
        repo = "/".join(str(url).rstrip("/").split("/")[-2:]) if isinstance(url, str) else ""
        if isinstance(number, int) and not isinstance(number, bool) and REPO_RE.fullmatch(repo) and ".." not in repo:
            refs.append(f"{repo}#{number}")
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(lambda r: _check_pr(gh, env, r, deadline), refs))
    running = tuple(r for r, out in zip(refs, results, strict=True) if out and out[0])
    unread = tuple((r, out[1], out[2]) for r, out in zip(refs, results, strict=True) if out and (out[1] or out[2]))
    return CopilotSnap(True, sum(1 for out in results if out is not None), running, unread, 0.0)


def _copilot_files(env: Mapping[str, str]) -> tuple[Path, Path] | None:
    base = cache_dir(env)
    return (base / "safo-activity-copilot.json", base / "safo-activity-copilot.lock") if base else None


def read_copilot_cache(env: Mapping[str, str], now: float) -> CopilotSnap | None:
    files = _copilot_files(env)
    if files is None:
        return None
    try:
        data = json.loads(read_bounded(files[0], 100_000))
        stamp = float(data["ts"])
        if not isinstance(data["ok"], bool) or now - stamp < 0:
            return None
        return CopilotSnap(
            data["ok"],
            int(data["checked"]),
            tuple(str(r) for r in data["running"]),
            tuple((str(r), int(b), int(i)) for r, b, i in data["unread"]),
            now - stamp,
        )
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return None


def write_private(path: Path, text: str) -> bool:
    """Atomic, mode 600, never through a symlink at the target; False on failure (a cache is only a speed-up)."""
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = path.with_name(f"{path.name}.{os.getpid()}")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(text)
        os.replace(tmp, path)
    except OSError:
        return False
    return True


def copilot_snapshot(env: Mapping[str, str], cfg: Config, now: float, *, fetch: bool) -> CopilotSnap | None:
    """The cached answer when it is under 60 s old, else a fresh one (`fetch`) or the stale one (not `fetch`)."""
    cached = read_copilot_cache(env, now)
    if cached is not None and cached.age < COPILOT_TTL:
        return cached
    if not fetch:
        return cached
    fresh = fetch_copilot(env, cfg.owner, now)
    files = _copilot_files(env)
    if files is not None:
        body = {
            "ts": now,
            "ok": fresh.ok,
            "checked": fresh.checked,
            "running": list(fresh.running),
            "unread": [list(u) for u in fresh.unread],
        }
        write_private(files[0], json.dumps(body))
    return fresh


CHILD_ENV_NAMES = ("HOME", "PATH", "LANG")
CHILD_ENV_PREFIXES = ("GH_", "GITHUB_", "XDG_", "SAFO_ACTIVITY_")


def child_env(env: Mapping[str, str]) -> dict[str, str]:
    """What a child process may see: the login gh needs, the XDG folders, the locale and our own settings. Nothing
    else from the caller's environment is passed on."""
    return {k: v for k, v in env.items() if k in CHILD_ENV_NAMES or k.startswith(CHILD_ENV_PREFIXES)}


def background_command(env: Mapping[str, str]) -> tuple[list[str], str]:
    """The refresh child: the interpreter in isolated mode (-I: no current directory and no PYTHON* variables on the
    module path), and a trusted working directory, the cache folder."""
    files = _copilot_files(env)
    return [sys.executable, "-I", "-m", "safo.activity", "--refresh-copilot"], str(files[0].parent if files else "/")


def refresh_in_background(env: Mapping[str, str], now: float) -> None:
    """A status line never waits on the network: a stale Copilot answer starts one detached refresh (at most one per
    30 s) and the next line shows what it found."""
    files = _copilot_files(env)
    if files is None:
        return
    try:
        if now - os.lstat(files[1]).st_mtime < 30:
            return
    except OSError:
        pass
    if not write_private(files[1], ""):
        return
    import subprocess

    argv, cwd = background_command(env)
    with contextlib.suppress(OSError):
        subprocess.Popen(  # noqa: S603 - our own interpreter, isolated mode, fixed module and flag
            argv,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
            env=child_env(env),
        )


# -- quota ----------------------------------------------------------------------------------------------------------

QUOTA_STALE = 1800  # seconds after which a reading is marked stale
CODEX_ROLLOUT_FILES = 3
CODEX_TAIL_BYTES = 262_144
CLAUDE_USAGE_REL = (".cache", "safo", "claude-usage.json")
CLAUDE_USAGE_BYTES = 16_384
CLAUDE_WINDOW_CAP = 8
PLAN_RE = re.compile(r"[A-Za-z0-9]{1,16}")


@dataclass(frozen=True)
class Window:
    label: str
    percent: float
    reset_in: float | None  # seconds until the window resets, when the source says


PACE_MIN_ELAPSED = 0.02  # an early reading must not blow the ratio up
HOLD_CLAUDE_5H = 80.0  # percent of the Claude 5 hour window above which new Claude agents are held


def window_minutes(label: str) -> int | None:
    """The length of a window from its label: wk is 10080 minutes, 5h is 300, Nh is N times sixty."""
    if label == "wk":
        return 10080
    found = re.fullmatch(r"([0-9]{1,4})h", label)
    return int(found.group(1)) * 60 if found and int(found.group(1)) > 0 else None


@dataclass(frozen=True)
class Pace:
    elapsed_percent: float
    ratio: float
    band: str  # under_pace, on_pace, caution or over_pace


def pace_band(ratio: float) -> str:
    if ratio < 0.9:
        return "under_pace"
    if ratio <= 1.0:
        return "on_pace"
    return "caution" if ratio <= 1.3 else "over_pace"


def pace_of(window: Window) -> Pace | None:
    """Used percent against the share of the window already gone. None when the window has no reset time or length."""
    minutes = window_minutes(window.label)
    if minutes is None or window.reset_in is None:
        return None
    elapsed = min(1.0, max(PACE_MIN_ELAPSED, 1.0 - window.reset_in / (minutes * 60)))
    ratio = window.percent / (elapsed * 100)
    return Pace(elapsed * 100, ratio, pace_band(ratio))


@dataclass(frozen=True)
class Quota:
    """One source's plan windows and when they were read. Percentages and labels only."""

    windows: tuple[Window, ...] = ()
    age: float = 0.0
    plan: str = ""

    @property
    def stale(self) -> bool:
        return self.age > QUOTA_STALE


def _window(quota: Quota, label: str) -> Window | None:
    return next((w for w in quota.windows if w.label == label), None)


def recommendation(quota: QuotaSnap) -> str | None:
    """One advisory line for a dispatch: which side has room. It changes no routing and says nothing about review
    routing for security. None unless both weekly windows are fresh and have a reset time."""
    claude, codex = quota.claude, quota.codex
    if claude.stale or codex.stale:
        return None
    cl_wk, cx_wk = _window(claude, "wk"), _window(codex, "wk")
    cl_pace = pace_of(cl_wk) if cl_wk else None
    cx_pace = pace_of(cx_wk) if cx_wk else None
    if cl_wk is None or cx_wk is None or cl_pace is None or cx_pace is None:
        return None
    parts = []
    if cl_pace.band in ("caution", "over_pace") and cx_pace.band in ("under_pace", "on_pace"):
        parts.append("prefer Codex for specified implementer tasks")
    cl_5h = _window(claude, "5h")
    if cl_5h is not None and cl_5h.percent > HOLD_CLAUDE_5H:
        parts.append("hold new Claude agents")
    head = (
        f"Budget: Claude wk {cl_wk.percent:.0f}% ({cl_pace.ratio:.1f}x pace), "
        f"Codex wk {cx_wk.percent:.0f}% ({cx_pace.ratio:.1f}x pace)"
    )
    return f"{head} - {'; '.join(parts) or 'normal'}"


@dataclass(frozen=True)
class QuotaSnap:
    codex: Quota = field(default_factory=Quota)
    claude: Quota = field(default_factory=Quota)


def _num(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value or abs(value) == float("inf"):
        return None
    return float(value)


def window_label(minutes: float) -> str:
    return "5h" if minutes == 300 else "wk" if minutes == 10080 else f"{int(minutes // 60)}h"


def _when(value: object) -> float | None:
    """An ISO stamp or a number of seconds since the epoch."""
    number = _num(value)
    return number if number is not None and 0 < number < 253_402_300_799 else parse_time(value)


def _codex_window(raw: object, now: float) -> Window | None:
    """A window whose fields are null (or missing or odd) is left out."""
    if not isinstance(raw, dict):
        return None
    percent, minutes = _num(raw.get("used_percent")), _num(raw.get("window_minutes"))
    if percent is None or minutes is None or not 0 <= percent <= 100 or not 0 < minutes < 525_600:
        return None
    left = _num(raw.get("resets_in_seconds"))
    if left is None:
        at = _when(raw.get("resets_at"))
        left = at - now if at is not None else None
    return Window(window_label(minutes), percent, left if left is not None and left >= 0 else None)


def _last_rate_limits(path: str) -> tuple[dict[str, Any], float | None] | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None
        os.lseek(fd, max(0, info.st_size - CODEX_TAIL_BYTES), os.SEEK_SET)
        raw = b""
        while len(raw) < CODEX_TAIL_BYTES + 1:
            chunk = os.read(fd, CODEX_TAIL_BYTES + 1 - len(raw))
            if not chunk:
                break
            raw += chunk
    except OSError:
        return None
    finally:
        os.close(fd)
    for line in reversed(raw.split(b"\n")):  # the first line of a cut window fails to parse and is skipped
        if b"rate_limits" not in line or len(line) > LEDGER_LINE_BYTES:
            continue
        try:
            row = json.loads(line)
        except (ValueError, RecursionError):
            continue
        payload = row.get("payload") if isinstance(row, dict) else None
        limits = payload.get("rate_limits") if isinstance(payload, dict) else None
        if isinstance(limits, dict):
            return limits, parse_time(row.get("timestamp"))
    return None


def collect_codex_quota(home: str, now: float) -> Quota:
    """The last `rate_limits` of the newest of the three most recent Codex session files."""
    if not home:
        return Quota()
    found: list[tuple[float, str]] = []
    for name in glob.glob(str(Path(home, ".codex", "sessions", "*", "*", "*", "*.jsonl"))):
        with contextlib.suppress(OSError):
            info = os.lstat(name)
            if stat.S_ISREG(info.st_mode):
                found.append((info.st_mtime, name))
    for _, name in sorted(found, reverse=True)[:CODEX_ROLLOUT_FILES]:
        hit = _last_rate_limits(name)
        if hit is None:
            continue
        limits, stamp = hit
        windows = tuple(w for w in (_codex_window(limits.get(k), now) for k in ("primary", "secondary")) if w)
        plan = limits.get("plan_type")
        return Quota(
            windows,
            max(0.0, now - stamp) if stamp is not None else 0.0,
            plan if isinstance(plan, str) and PLAN_RE.fullmatch(plan) else "",
        )
    return Quota()


def claude_usage_path(env: Mapping[str, str], home: str) -> Path | None:
    given = env.get("SAFO_ACTIVITY_CLAUDE_USAGE", "")
    if given:
        return Path(given) if os.path.isabs(given) else None
    return Path(home, *CLAUDE_USAGE_REL) if home else None


def parse_claude_usage(data: object, now: float) -> Quota:
    """Windows `[{label, used_percent, resets_at?}]` and `captured_at`; a malformed document yields nothing."""
    if not isinstance(data, dict) or not isinstance(data.get("windows"), list):
        return Quota()
    captured = _when(data.get("captured_at"))
    if captured is None:
        return Quota()
    windows: list[Window] = []
    for raw in data["windows"][:CLAUDE_WINDOW_CAP]:
        percent = _num(raw.get("used_percent")) if isinstance(raw, dict) else None
        label = clean(raw.get("label"), 12).strip() if isinstance(raw, dict) else ""
        if percent is None or not 0 <= percent <= 100 or not label:
            continue
        at = _when(raw.get("resets_at"))
        windows.append(Window(label, percent, at - now if at is not None and at >= now else None))
    return Quota(tuple(windows), max(0.0, now - captured))


def collect_claude_quota(env: Mapping[str, str], home: str, now: float) -> Quota:
    path = claude_usage_path(env, home)
    if path is None:
        return Quota()
    try:
        info = os.lstat(path)  # lstat: a symlink is refused, not followed
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            return Quota()
        return parse_claude_usage(json.loads(read_bounded(path, CLAUDE_USAGE_BYTES)), now)
    except (OSError, ValueError, RecursionError):
        return Quota()


def write_claude_usage(doc: object, env: Mapping[str, str] | None = None) -> bool:
    """For a status line script: store the JSON object it was given (windows and captured_at) atomically, mode 600.

    Only a document that parses to at least one valid window is written, and only the fields of the schema are kept.
    Returns False, writing nothing, otherwise. Wired to nothing by default."""
    env = os.environ if env is None else env
    path = claude_usage_path(env, env.get("HOME", ""))
    now = time.time()
    if path is None or not isinstance(doc, dict) or not parse_claude_usage(doc, now).windows:
        return False
    keep: dict[str, Any] = {"captured_at": doc["captured_at"], "windows": []}
    for raw in doc["windows"][:CLAUDE_WINDOW_CAP]:
        row = {k: raw[k] for k in ("label", "used_percent", "resets_at") if isinstance(raw, dict) and k in raw}
        keep["windows"].append(row)
    return write_private(path, json.dumps(keep))


# -- one reading of everything ---------------------------------------------------------------------------------------


@dataclass
class Reading:
    now: float
    cfg: Config
    codex: CodexSnap | None = None
    ollama: OllamaSnap | None = None
    ledger: LedgerSnap | None = None
    copilot: CopilotSnap | None = None
    quota: QuotaSnap | None = None
    extra: dict[str, Any] = field(default_factory=dict)


def read_all(env: Mapping[str, str], now: float, cfg: Config, *, network: bool, only: str = "") -> Reading:
    """Collect the enabled providers (or just `only`). `network` lets Copilot fetch now instead of using its cache."""
    home = env.get("HOME", "")
    out = Reading(now, cfg)
    want = [only] if only else list(cfg.providers)
    if "codex" in want:
        out.codex = _safe(lambda: collect_codex(home, now), CodexSnap())
    if "quota" in want:
        out.quota = _safe(
            lambda: QuotaSnap(collect_codex_quota(home, now), collect_claude_quota(env, home, now)), QuotaSnap()
        )
    if "ollama" in want:
        out.ollama = _safe(lambda: collect_ollama(env, home, now), OllamaSnap())
    if "ledger" in want:
        out.ledger = _safe(lambda: collect_ledger(env, home, now), LedgerSnap())
    if "copilot" in want:
        out.copilot = _safe(lambda: copilot_snapshot(env, cfg, now, fetch=network), None)
        if not network and (out.copilot is None or out.copilot.age >= COPILOT_TTL):
            refresh_in_background(env, now)
    return out


def _safe(call: Callable[[], T], fallback: T) -> T:
    try:
        return call()
    except Exception:  # a provider never takes the status line down with it
        return fallback


# -- rendering --------------------------------------------------------------------------------------------------------


def _row(job: Job) -> str:
    when = f"run  {human_age(job.age)}" if job.running else f"done {human_age(job.age)} ago"
    return f"{job.title:<50.50}  {job.phase:<10.10} {job.kind:<10.10} {when}"


def _first(refs: tuple[str, ...]) -> str:
    return f" {refs[0]}" if refs else ""


def render_line(rd: Reading) -> str:
    parts: list[str] = []
    cx = rd.codex
    if cx is not None and (cx.running or cx.done):
        if cx.running:
            seg = f"cx {len(cx.running)} run"
            room = 39 - len(seg) - 1
            if room > 0:
                seg += f" {cx.running[0].title[:room]}"
            if cx.done and len(seg) + 3 < 40:
                seg += f" {len(cx.done)}✓"
        else:
            seg = f"cx {len(cx.done)}✓"
        parts.append(seg)
    if rd.quota is not None:
        for tag, quota in (("cx", rd.quota.codex), ("cl", rd.quota.claude)):
            if quota.windows:
                shown = " ".join(f"{w.percent:.0f}% {w.label}" for w in quota.windows)
                parts.append(f"{tag} {shown}, age {human_age(quota.age)}" + (" stale" if quota.stale else ""))
    ol = rd.ollama
    if ol is not None and ol.ok:
        seg = ":" + ",".join(name for name, _ in ol.models) if ol.models else ""
        if ol.busy:
            seg += " busy"
        if seg:
            parts.append(f"ol{seg}")
    lg = rd.ledger
    if lg is not None and lg.ok and lg.today > 0:
        parts.append(f"gm {lg.today} {human_age(lg.newest_age or 0)}")
    cp = rd.copilot
    if cp is not None and cp.ok:
        if cp.running:
            parts.append(f"cp {len(cp.running)} run{_first(cp.running)}")
        elif cp.unread:
            parts.append(f"cp {len(cp.unread)} unread {cp.unread[0][0]}")
    return " ".join(parts)


def render_table(rd: Reading) -> list[str]:
    out: list[str] = list(rd.cfg.notes)
    cx = rd.codex
    if cx is not None:
        out.append(f"Codex: {len(cx.running)} running, {len(cx.done)} done (last 60m)")
        out.extend(_row(j) for j in (*cx.running, *cx.done))
    if rd.quota is not None:
        for title, quota in (("Codex", rd.quota.codex), ("Claude", rd.quota.claude)):
            if not quota.windows:
                continue
            plan = f" ({quota.plan})" if quota.plan else ""
            stale = " STALE" if quota.stale else ""
            out.append(f"Quota {title}{plan}: read {human_age(quota.age)} ago{stale}")
            for w in quota.windows:
                reset = f", resets in {human_age(w.reset_in)}" if w.reset_in is not None else ""
                pace = pace_of(w)
                note = f", {pace.elapsed_percent:.0f}% elapsed, {pace.ratio:.1f}x pace ({pace.band})" if pace else ""
                out.append(f"  {w.percent:.0f}% used  {w.label}{reset}{note}")
        advice = recommendation(rd.quota)
        if advice:
            out.append(advice)
            out.append("  note: advisory only; it changes no routing and does not apply to security review")
    ol = rd.ollama
    if ol is not None:
        if not ol.configured:
            out.append("Ollama: no endpoint configured (agents config or LLM_LOCAL_URL)")
        elif not ol.ok:
            out.append("Ollama: not answering (segment omitted)")
        else:
            conns = (
                f"{ol.busy} established connection(s)"
                if ol.busy is not None
                else "connection count unavailable (ss missing)"
            )
            out.append(f"Ollama: {len(ol.models)} loaded, {conns}")
            out.extend(f"{name:<40.40}  {note}" for name, note in ol.models)
            out.append("  note: per-request detail is not available from the server's listing")
    lg = rd.ledger
    if lg is not None:
        if not lg.ok:
            out.append("Ledger: not found or unreadable (segment omitted)")
        else:
            if lg.newest_age is None:
                out.append("Ledger: readable, no timestamped entries")
            else:
                out.append(f"Ledger: {lg.today} entries today, newest {human_age(lg.newest_age)} ago")
            out.extend(f"{job:<30.30}  {'free-tier':<10} in flight {human_age(age)}" for _, job, age in lg.inflight)
            if lg.typed == 0:
                out.append("  note: no call_start/call_end rows found, in-flight calls cannot be told apart")
            else:
                out.append("  note: in flight = call_start today with no call_end (a crashed call looks the same)")
    cp = rd.copilot
    if cp is not None:
        if not cp.ok:
            out.append("Copilot: not available (gh missing, not logged in or offline; segment omitted)")
        else:
            out.append(
                f"Copilot: {len(cp.running)} review running, {len(cp.unread)} unread ({cp.checked} open PRs checked)"
            )
            out.extend(f"  {ref}  review running" for ref in cp.running)
            out.extend(f"  {ref}  unread: {b} review(s) with text, {i} inline comment(s)" for ref, b, i in cp.unread)
            out.append("  note: counts only; open the pull request to read the review")
    return out


def _json_window(w: Window) -> dict[str, Any]:
    pace = pace_of(w)
    return {
        "label": w.label,
        "used_percent": w.percent,
        "resets_in_s": None if w.reset_in is None else int(w.reset_in),
        "elapsed_percent": None if pace is None else round(pace.elapsed_percent, 1),
        "pace_ratio": None if pace is None else round(pace.ratio, 1),
        "band": None if pace is None else pace.band,
    }


def render_json(rd: Reading) -> dict[str, Any]:
    doc: dict[str, Any] = {"providers": list(rd.cfg.providers)}
    if rd.codex is not None:
        doc["codex"] = {
            "running": [
                {"title": j.title, "phase": j.phase, "kind": j.kind, "age_s": int(j.age)} for j in rd.codex.running
            ],
            "done_last_hour": len(rd.codex.done),
        }
    if rd.quota is not None:
        doc["quota"] = {
            name: {
                "plan": q.plan,
                "age_s": int(q.age),
                "stale": q.stale,
                "windows": [_json_window(w) for w in q.windows],
            }
            for name, q in (("codex", rd.quota.codex), ("claude", rd.quota.claude))
        }
        doc["quota"]["recommendation"] = recommendation(rd.quota)
    if rd.ollama is not None:
        doc["ollama"] = {
            "configured": rd.ollama.configured,
            "reachable": rd.ollama.ok,
            "loaded": [name for name, _ in rd.ollama.models],
            "connections": rd.ollama.busy,
        }
    if rd.ledger is not None:
        doc["ledger"] = {
            "readable": rd.ledger.ok,
            "entries_today": rd.ledger.today,
            "newest_age_s": None if rd.ledger.newest_age is None else int(rd.ledger.newest_age),
            "call_rows": rd.ledger.typed,
            "in_flight": [{"action": job, "age_s": int(age)} for _, job, age in rd.ledger.inflight],
        }
    if rd.copilot is not None:
        doc["copilot"] = {
            "available": rd.copilot.ok,
            "checked": rd.copilot.checked,
            "running": list(rd.copilot.running),
            "unread": [{"pr": ref, "reviews_with_text": b, "inline_comments": i} for ref, b, i in rd.copilot.unread],
        }
    return doc


# -- modes ------------------------------------------------------------------------------------------------------------


def read_line_cache(path: Path, now: float) -> str | None:
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or not 0 <= now - info.st_mtime < LINE_TTL:
            return None
        return read_bounded(path, 4096).decode("utf-8", "replace")
    except OSError:
        return None


def mode_line(env: Mapping[str, str], out: TextIO, now: float) -> int:
    base = cache_dir(env)
    cache = base / "safo-activity.cache" if base else None
    if cache is not None:
        hit = read_line_cache(cache, now)
        if hit is not None:
            out.write(hit)
            return 0
    text = render_line(read_all(env, now, load_config(env), network=False))
    if cache is not None:
        write_private(cache, text)
    out.write(text)
    return 0


def mode_table(env: Mapping[str, str], out: TextIO, now: float) -> int:
    out.write("\n".join(render_table(read_all(env, now, load_config(env), network=True))) + "\n")
    return 0


def mode_json(env: Mapping[str, str], out: TextIO, now: float) -> int:
    out.write(json.dumps(render_json(read_all(env, now, load_config(env), network=True)), indent=2) + "\n")
    return 0


def mode_watch(
    env: Mapping[str, str],
    out: TextIO,
    *,
    interval: float = WATCH_INTERVAL,
    max_frames: int = 0,
    wait: Callable[[float], bool] | None = None,
    clock: Callable[[], float] = time.time,
) -> int:
    """Redraw the table until interrupted. `wait` returns True when asked to stop (a signal)."""
    stop = threading.Event()
    wait = wait or stop.wait
    previous = [signal.signal(s, lambda *_: stop.set()) for s in (signal.SIGINT, signal.SIGTERM)]
    try:
        frames = 0
        while True:
            now = clock()
            if out.isatty():
                out.write("\x1b[H\x1b[2J")
            clock_text = time.strftime("%H:%M:%S", time.localtime(now))
            out.write(f"safo-activity watch  {clock_text}  (every {interval:g}s, Ctrl-C quits)\n")
            mode_table(env, out, now)
            out.flush()
            frames += 1
            if (max_frames and frames >= max_frames) or wait(interval):
                return 0
    finally:
        for sig, old in zip((signal.SIGINT, signal.SIGTERM), previous, strict=True):
            signal.signal(sig, old)


# -- events -----------------------------------------------------------------------------------------------------------


@dataclass
class Observed:
    """One provider read as a flat state: key -> value. `down` is a provider that did not answer."""

    state: dict[str, str]
    startup: str
    down: bool = False


def observe(name: str, env: Mapping[str, str], cfg: Config, now: float) -> Observed:
    rd = read_all(env, now, cfg, network=True, only=name)
    if name == "codex":
        cx = rd.codex or CodexSnap()
        return Observed(
            {j.key: f"{j.title[:40]}\t{j.phase}" for j in cx.running},
            f"codex: {len(cx.running)} running, {len(cx.done)} done (last 60m)",
        )
    if name == "ollama":
        ol = rd.ollama or OllamaSnap()
        if not ol.configured:
            return Observed({}, "ollama: no endpoint configured", down=True)
        if not ol.ok:
            return Observed({}, "ollama: unreachable", down=True)
        state = {f"M:{n}": "1" for n, _ in ol.models}
        if ol.busy is not None:
            state["B"] = "1" if ol.busy else "0"
        if ol.busy is None:
            hint = f"{len(ol.models)} loaded (ss missing, busy/idle unavailable)"
        else:
            hint = f"{len(ol.models)} loaded, " + (f"busy ({ol.busy} conn)" if ol.busy else "idle")
        state["_conn"] = str(ol.busy or 0)
        return Observed(state, f"ollama: {hint}")
    if name == "ledger":
        lg = rd.ledger or LedgerSnap()
        if not lg.ok:
            return Observed({}, "ledger: not found or unreadable", down=True)
        if lg.typed == 0:
            note = "ledger: readable, call start and end rows cannot be told apart (no call events)"
        else:
            note = f"ledger: {len(lg.inflight)} call(s) in flight today"
        return Observed({c: job for c, job, _ in lg.inflight}, note)
    cp = rd.copilot
    if cp is None or not cp.ok:
        return Observed({}, "copilot: not available", down=True)
    state = {f"R:{r}": "1" for r in cp.running}
    state.update({f"U:{r}": f"{b}\t{i}" for r, b, i in cp.unread})
    return Observed(state, f"copilot: {len(cp.running)} review running, {len(cp.unread)} unread")


def changes(name: str, prev: Observed, cur: Observed) -> list[str]:
    """One short line per change. A down provider reports only its own transition."""
    if cur.down or prev.down:
        if cur.down and not prev.down:
            return [f"{name}: unreachable" if name != "ledger" else "ledger: became unreadable"]
        if prev.down and not cur.down:
            return [f"{name}: reachable again" if name != "ledger" else "ledger: readable again"]
        return []
    lines: list[str] = []
    for key in sorted(cur.state):
        value = cur.state[key]
        if key not in prev.state:
            if name == "codex":
                title, _, phase = value.partition("\t")
                lines.append(f"codex started: {title} ({phase})")
            elif name == "ollama" and key.startswith("M:"):
                lines.append(f"ollama: loaded {key[2:]}")
            elif name == "ledger":
                lines.append(f"ledger: call started: {value}")
            elif name == "copilot" and key.startswith("R:"):
                lines.append(f"copilot: review running {key[2:]}")
            elif name == "copilot":
                reviews, _, inline = value.partition("\t")
                lines.append(f"copilot: unread {key[2:]} ({reviews} review(s) with text, {inline} inline)")
        elif name == "ollama" and key == "B" and value != prev.state[key]:
            lines.append(f"ollama: busy ({cur.state.get('_conn', '0')} conn)" if value == "1" else "ollama: idle")
    for key in sorted(prev.state):
        if key in cur.state:
            continue
        old = prev.state[key]
        if name == "codex":
            lines.append(f"codex finished: {old.partition(chr(9))[0]}")
        elif name == "ollama" and key.startswith("M:"):
            lines.append(f"ollama: unloaded {key[2:]}")
        elif name == "ledger":
            lines.append(f"ledger: call ended: {old}")
        elif name == "copilot" and key.startswith("R:"):
            lines.append(f"copilot: review finished {key[2:]}")
    return lines


def mode_events(
    name: str,
    env: Mapping[str, str],
    out: TextIO,
    *,
    interval: float = EVENTS_INTERVAL,
    window: float = EVENTS_WINDOW,
    limit: float = EVENTS_LIMIT,
    cap: int = EVENTS_CAP,
    max_polls: int = 0,
    wait: Callable[[float], bool] | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> int:
    """Poll one provider; print a line only on a state change, at most `cap` per `window`, then one dropped-count
    line per window. Ends after `limit` seconds (29 minutes) so the monitor can be re-armed, and on SIGINT/SIGTERM,
    always with exit 0."""
    stop = threading.Event()
    wait = wait or stop.wait
    previous = [signal.signal(s, lambda *_: stop.set()) for s in (signal.SIGINT, signal.SIGTERM)]
    cfg = load_config(env)
    state = {"start": clock(), "sent": 0, "dropped": 0}

    def tick() -> None:
        if clock() - state["start"] >= window:
            if state["dropped"]:
                out.write(
                    f"{name}: {state['dropped']} events dropped in the last {window:g}s (cap {cap} per {window:g}s)\n"
                )
                out.flush()
            state.update(start=clock(), sent=0, dropped=0)

    def emit(line: str) -> None:
        tick()
        if state["sent"] >= cap:
            state["dropped"] += 1
            return
        state["sent"] += 1
        out.write(line + "\n")
        out.flush()

    try:
        last = observe(name, env, cfg, time.time())
        out.write(last.startup + "\n")
        out.flush()
        deadline = clock() + limit
        polls = 0
        while True:
            if wait(interval):
                return 0
            if clock() >= deadline:
                out.write(f"{name}: 29 minute limit reached, re-arm the monitor\n")
                out.flush()
                return 0
            cur = observe(name, env, cfg, time.time())
            tick()
            for line in changes(name, last, cur):
                emit(line)
            last = cur
            polls += 1
            if max_polls and polls >= max_polls:
                return 0
    finally:
        for sig, old in zip((signal.SIGINT, signal.SIGTERM), previous, strict=True):
            signal.signal(sig, old)


# -- entry points -----------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Options:
    mode: str = "line"  # line, table, json, watch, events, refresh
    events: str = ""


def parse_args(argv: list[str]) -> Options | str:
    """Options, or a message to print with exit status 2."""
    if not argv:
        return Options()
    flag = argv[0]
    if flag == "--events":
        name = ALIASES.get(argv[1], argv[1]) if len(argv) == 2 else ""
        return (
            Options("events", name)
            if name in EVENT_PROVIDERS
            else "--events needs one of: " + ", ".join(EVENT_PROVIDERS)
        )
    simple = {
        "--table": "table",
        "--json": "json",
        "--watch": "watch",
        "--version": "version",
        "--refresh-copilot": "refresh",
    }
    if len(argv) == 1 and flag in simple:
        return Options(simple[flag])
    return "unknown or extra argument"


def run_options(opts: Options, env: Mapping[str, str], out: TextIO) -> int:
    now = time.time()
    if opts.mode == "version":
        out.write(f"safo-activity {safo.__version__}\n")
        return 0
    if opts.mode == "table":
        return mode_table(env, out, now)
    if opts.mode == "json":
        return mode_json(env, out, now)
    if opts.mode == "watch":
        return mode_watch(env, out)
    if opts.mode == "events":
        return mode_events(opts.events, env, out)
    if opts.mode == "refresh":
        copilot_snapshot(env, load_config(env), now, fetch=True)
        return 0
    return mode_line(env, out, now)


def main(argv: list[str] | None = None, env: Mapping[str, str] | None = None, out: TextIO | None = None) -> int:
    parsed = parse_args(list(sys.argv[1:] if argv is None else argv))
    if isinstance(parsed, str):
        sys.stderr.write(f"safo-activity: {parsed}\n{USAGE}")
        return 2
    try:
        return run_options(parsed, os.environ if env is None else env, out or sys.stdout)
    except BrokenPipeError:
        return 0


def run() -> None:  # the console entry point
    sys.exit(main())


if __name__ == "__main__":
    run()
