# SPDX-License-Identifier: Apache-2.0
"""`safo-idle-check`: the never-idle Stop hook (#578). Blocks the end of a turn when fewer than `floor` workers run
(default 6) and ready, unstarted work exists; the reason lists that work. A separate entry point, like `safo-guard`: it
adds no top-level command and touches no frozen guard code. Design and limits: docs/idle-check.md.

Counting is done in code from the host (the subagent registry beside the session transcript and the process table),
never by a model. Every source fails open and loudly: an unreadable source is a `DEGRADED:` line in the message and the
log, never a silent allow and never a block on a guess.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import os
import re
import select
import stat
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, TextIO

from safo import output
from safo.bounded import loads

DEFAULT_FLOOR = 6
DEFAULT_WINDOW = 300.0
GH_TIMEOUT = 10.0
GH_TOTAL = 30.0
GH_WORKERS = 8
DEFAULT_CACHE = 60.0
CACHE_CAP = 16_777_216
INPUT_CAP = 1_048_576
INPUT_WAIT = 10.0
QUEUE_CAP = 1_048_576
HEAD_BYTES = 4096
TAIL_BYTES = 8192
LIST_CAP = 10
LOG_CAP = 5_000_000
PR_FIELDS = "number,title,headRefName,isDraft,mergeable,reviewDecision,statusCheckRollup,author,isCrossRepository"
DEFAULT_QUEUE = ".local/share/agent-box-dev/QUEUE.md"
DEFAULT_LOG = ".local/share/safo-dev/idle-check.log"
JOB = re.compile(r"(?:^|[\s/])codex(?:\.js)?\sexec\b|daybreak-run")
NEGATED = re.compile(r"\b(?:not|never|isn't|no)\b[^;,.]{0,20}\bready\b")
SELF = re.compile(r"idlecheck|safo-idle-check")
NOT_READY = ("running", "blocked", "held", "hold", "done", "merged", "waits", "owner", "closed")
Runner = Callable[..., "subprocess.CompletedProcess[str]"]


class Degraded(Exception):
    """One source could not be read; the text names the source and carries no payload."""


# -- configuration --------------------------------------------------------------------------------


def load_config(env: Mapping[str, str]) -> dict[str, Any]:
    cfg: dict[str, Any] = {}
    path = Path(env.get("HOME", "")) / ".config" / "safo" / "idle-check.json"
    try:
        raw = path.read_bytes()[:INPUT_CAP] if path.exists() else b""
        data = loads(raw) if raw else {}
    except (OSError, ValueError) as err:
        raise Degraded("config: idle-check.json unreadable") from err
    if isinstance(data, dict):
        cfg.update(data)
    if "SAFO_IDLE_FLOOR" in env:
        cfg["floor"] = env["SAFO_IDLE_FLOOR"]
    if "SAFO_IDLE_WINDOW" in env:
        cfg["window_seconds"] = env["SAFO_IDLE_WINDOW"]
    if "SAFO_IDLE_UNREVIEWED" in env:
        cfg["include_unreviewed"] = env["SAFO_IDLE_UNREVIEWED"] == "1"
    if "SAFO_IDLE_CACHE" in env:
        cfg["cache_seconds"] = env["SAFO_IDLE_CACHE"]
    if "SAFO_IDLE_MODE" in env:
        cfg["mode"] = env["SAFO_IDLE_MODE"]
    if "SAFO_IDLE_QUEUE" in env:
        cfg["queue_paths"] = [p for p in env["SAFO_IDLE_QUEUE"].split(":") if p]
    if "SAFO_IDLE_TRUSTED" in env:
        cfg["trusted_authors"] = [a.strip() for a in env["SAFO_IDLE_TRUSTED"].split(",") if a.strip()]
    if "SAFO_IDLE_FORKS" in env:
        cfg["allow_forks"] = env["SAFO_IDLE_FORKS"] == "1"
    if "SAFO_IDLE_REPOS" in env:
        cfg["repos"] = [r.strip() for r in env["SAFO_IDLE_REPOS"].split(",") if r.strip()]
    return cfg


def as_int(value: Any, default: int) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def as_float(value: Any, default: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if number > 0 else default


def tracked_repos(env: Mapping[str, str]) -> list[str]:
    """`hooks.tracking_repos` of ~/.config/safo/agents.yaml, the default repo list."""
    import yaml

    path = Path(env.get("HOME", "")) / ".config" / "safo" / "agents.yaml"
    try:
        data = yaml.safe_load(path.read_bytes()[:INPUT_CAP])
        repos = data["hooks"]["tracking_repos"]
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as err:
        raise Degraded("repos: none configured and agents.yaml tracking_repos unreadable") from err
    if not isinstance(repos, list):
        raise Degraded("repos: tracking_repos is not a list")
    return [r for r in repos if isinstance(r, str)]


# -- running workers ------------------------------------------------------------------------------


def last_line(path: Path) -> bytes:
    with path.open("rb") as fh:
        size = fh.seek(0, os.SEEK_END)
        fh.seek(max(0, size - TAIL_BYTES))
        lines = [x for x in fh.read().splitlines() if x.strip()]
    return lines[-1] if lines else b""


def finished(path: Path) -> bool:
    try:
        entry = loads(last_line(path))
    except (OSError, ValueError):
        return False
    message = entry.get("message") if isinstance(entry, dict) else None
    return isinstance(message, dict) and entry.get("type") == "assistant" and message.get("stop_reason") == "end_turn"


def count_subagents(transcript: str, now: float, window: float) -> list[str]:
    """The opening text of each subagent of this session that is still running: transcript touched within `window`
    seconds and not ended. Returns that text (the first bytes), used to tell which PRs an agent is on."""
    if not transcript:
        raise Degraded("agents: no transcript_path in the event")
    base = Path(os.path.expanduser(transcript))
    if not base.is_file():
        raise Degraded("agents: transcript not readable")
    folder = base.with_suffix("") / "subagents"
    if not folder.is_dir():
        return []
    texts: list[str] = []
    try:
        for path in sorted(folder.glob("agent-*.jsonl")):
            if now - path.stat().st_mtime > window or finished(path):
                continue
            with path.open("rb") as fh:
                texts.append(fh.read(HEAD_BYTES).decode("utf-8", "replace"))
    except OSError as err:
        raise Degraded("agents: subagent registry unreadable") from err
    return texts


def parent_of(root: Path, pid: str) -> str:
    text = (root / pid / "stat").read_text(errors="replace")
    return text[text.rindex(")") + 1 :].split()[1]


def count_processes(root: Path, me: int | None = None) -> list[str]:
    """Command lines of detached jobs (`codex exec`, `daybreak-run`) from the process table, one per job: the top-most
    process of each chain (a timeout, bash or node wrapper of the same job is not counted again)."""
    me = os.getpid() if me is None else me
    cands: dict[str, tuple[str, str]] = {}
    try:
        for entry in root.iterdir():
            if not entry.name.isdigit() or int(entry.name) == me:
                continue
            try:
                cmd = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace").strip()
                if JOB.search(cmd) and not SELF.search(cmd):
                    cands[entry.name] = (cmd, parent_of(root, entry.name))
            except (OSError, ValueError, IndexError):
                continue  # a process that exited while the table was read
    except OSError as err:
        raise Degraded("processes: process table unreadable") from err
    return [cmd for pid, (cmd, ppid) in cands.items() if ppid not in cands or ppid == pid]


# -- ready work -----------------------------------------------------------------------------------


def parse_queue(text: str) -> list[str]:
    """The names of the unstarted items (see queue_refs). The names are for tests; the block reason never shows them."""
    return [name for _, _, name in queue_refs(text)]


def queue_refs(text: str) -> list[tuple[int, int, str]]:
    """Unstarted items as (line number, item number on that line, name): `READY:` lines (split on `;`) and
    dependency-table rows (| item | depends on | state |) whose dependencies are met and that are not running,
    blocked, held or done. Prose lines are ignored."""
    items: list[tuple[int, int, str]] = []
    in_table = False
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line.upper().startswith("READY:"):
            names = [p.strip() for p in line[6:].split(";") if p.strip()]
            items.extend((number, k, name) for k, name in enumerate(names, 1))
            continue
        if not line.startswith("|"):
            in_table = False
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if cells and cells[0].lower() == "item":
            in_table = True
            continue
        if not in_table or len(cells) < 3 or set(cells[0]) <= set("-: "):
            continue
        name, dep, state = cells[0], cells[1].lower(), cells[2].lower()
        if not name or state.startswith(NOT_READY):
            continue
        says_ready = re.search(r"\bready\b", state) is not None and NEGATED.search(state) is None
        deps_met = dep in ("", "none", "-")
        if says_ready or (deps_met and state in ("", "todo", "queued", "unstarted")):
            items.append((number, 1, name))
    return items


def read_regular(path: str, limit: int) -> bytes:
    """At most `limit` bytes of a regular file, opened without blocking and without following a link (a FIFO or a
    swapped-in symlink must not hang or redirect the hook)."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("not a regular file")
        with os.fdopen(fd, "rb", closefd=False) as fh:
            return fh.read(limit)
    finally:
        os.close(fd)


def read_queues(paths: list[str]) -> list[str]:
    items: list[str] = []
    for name in paths:
        try:
            raw = read_regular(os.path.expanduser(name), QUEUE_CAP + 1)
        except OSError as err:
            raise Degraded("queue: a queue file is unreadable (missing, not a regular file or a link)") from err
        if len(raw) > QUEUE_CAP:
            raise Degraded(f"queue: a queue file is over {QUEUE_CAP} bytes, so its tail would be missed")
        label = Path(name).name[:40]
        # only where the item is, never its text: queue lines are free text and reach the model as instructions
        items.extend(
            f"queue file {label} line {n}" + (f", item {k}" if k > 1 else "")
            for n, k, _ in queue_refs(raw.decode("utf-8", "replace"))
        )
    return items


def names_pr(text: str, number: int, branch: str) -> bool:
    pattern = rf"(?<![\w/])#{number}(?!\d)|pull/{number}(?!\d)|\bPR #?{number}(?!\d)"
    if re.search(pattern, text) is not None:
        return True
    return bool(branch) and re.search(rf"(?<![\w-]){re.escape(branch)}(?![\w-])", text) is not None


BAD_CHECKS = {"FAILURE", "ERROR", "TIMED_OUT", "STARTUP_FAILURE"}


def is_bad_check(check: Any) -> bool:
    return isinstance(check, dict) and (check.get("conclusion") in BAD_CHECKS or check.get("state") in BAD_CHECKS)


def pr_reasons(pr: dict[str, Any], unreviewed: bool = False) -> list[str]:
    reasons: list[str] = []
    rollup = pr.get("statusCheckRollup")
    if isinstance(rollup, list) and any(is_bad_check(c) for c in rollup):
        reasons.append("failing")
    if pr.get("mergeable") == "CONFLICTING":
        reasons.append("conflicting")
    if unreviewed and not pr.get("isDraft") and pr.get("reviewDecision") in ("REVIEW_REQUIRED", "", None):
        reasons.append("unreviewed")
    return reasons


def fetch_one(repo: str, runner: Runner, cwd: str, began: float) -> list[dict[str, Any]] | None:
    """The open PRs of one repo, or None when gh failed, timed out, or the total time was spent."""
    left = GH_TOTAL - (time.monotonic() - began)
    if left <= 0:
        return None
    argv = ["gh", "pr", "list", "--repo", repo, "--state", "open", "--limit", "50", "--json", PR_FIELDS]
    try:
        done = runner(argv, capture_output=True, text=True, timeout=min(GH_TIMEOUT, left), cwd=cwd, check=False)
        data = loads(done.stdout, CACHE_CAP) if done.returncode == 0 else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    return (
        [p for p in data if isinstance(p, dict) and isinstance(p.get("number"), int)]
        if isinstance(data, list)
        else None
    )


def fetch_prs(repos: list[str], runner: Runner, cwd: str) -> tuple[list[tuple[str, dict[str, Any]]], list[str]]:
    """Open PRs of every repo, a few gh calls at a time, bounded by GH_TOTAL. One note names the repos that failed."""
    began = time.monotonic()
    with ThreadPoolExecutor(max_workers=GH_WORKERS) as pool:
        results = list(pool.map(lambda r: fetch_one(r, runner, cwd, began), repos))
    prs = [(repo, p) for repo, got in zip(repos, results, strict=True) for p in got or []]
    failed = [repo for repo, got in zip(repos, results, strict=True) if got is None]
    if not failed:
        return prs, []
    shown = ", ".join(failed[:5]) + (f" and {len(failed) - 5} more" if len(failed) > 5 else "")
    return prs, [f"prs: gh pr list failed or timed out for {len(failed)} of {len(repos)} repos ({shown})"]


def cache_path(env: Mapping[str, str]) -> Path:
    return log_path(env).with_name("idle-check-prs.json")


def cached_prs(
    env: Mapping[str, str], repos: list[str], ttl: float, now: float
) -> list[tuple[str, dict[str, Any]]] | None:
    """The PR list of the last complete scan of exactly these repos, if it is younger than ttl; else None."""
    try:
        data = loads(cache_path(env).read_bytes()[:CACHE_CAP], CACHE_CAP)
        fresh = 0 <= now - float(data["ts"]) <= ttl and data["repos"] == repos
        return [(r, p) for r, p in data["prs"]] if fresh else None
    except (OSError, ValueError, KeyError, TypeError):
        return None  # a missing or damaged cache is a miss, never an error


def slim(pr: dict[str, Any]) -> dict[str, Any]:
    """Only the fields the ready rule reads; the check rollups of a busy PR run to hundreds of KB."""
    keep = {k: pr.get(k) for k in ("number", "title", "headRefName", "isDraft", "mergeable", "reviewDecision")}
    author = pr.get("author")
    keep["author"] = {"login": author.get("login")} if isinstance(author, dict) else None
    keep["isCrossRepository"] = pr.get("isCrossRepository")
    rollup = pr.get("statusCheckRollup")
    keep["statusCheckRollup"] = (
        [{"conclusion": c.get("conclusion"), "state": c.get("state")} for c in rollup if is_bad_check(c)]
        if isinstance(rollup, list)
        else None
    )
    return keep


def store_prs(env: Mapping[str, str], repos: list[str], prs: list[tuple[str, dict[str, Any]]], now: float) -> None:
    with contextlib.suppress(OSError, TypeError, ValueError):
        path = cache_path(env)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps({"ts": now, "repos": repos, "prs": [(r, slim(p)) for r, p in prs]}))
        tmp.replace(path)


def login_key(login: Any) -> str:
    """A login in comparison form: lower case. A GitHub App keeps its `app/` prefix, so `app/x` is never user `x`."""
    return login.strip().lower() if isinstance(login, str) else ""


def trusted_author(repo: str, pr: dict[str, Any], allow: set[str], forks: bool) -> bool:
    """True only for the repo owner or an allowlisted login, and (unless forks are allowed) a PR from the same repo.
    Fails closed: a missing or odd author or fork flag is not trusted. gh pr list has no authorAssociation field."""
    author = pr.get("author")
    login = login_key(author.get("login")) if isinstance(author, dict) else ""
    if not login:
        return False
    fork = pr.get("isCrossRepository")
    if not isinstance(fork, bool) or (fork and not forks):  # a malformed flag is untrusted even when forks are allowed
        return False
    return login == login_key(repo.split("/")[0]) or login in allow


def ready_prs(
    prs: list[tuple[str, dict[str, Any]]],
    busy: str,
    exempt: set[str],
    unreviewed: bool = False,
    allow: set[str] | None = None,
    forks: bool = False,
) -> tuple[list[str], int]:
    """(ready items, count of PRs skipped for an untrusted author). A skipped PR is only counted, never listed."""
    out: list[str] = []
    skipped = 0
    for repo, pr in prs:
        ref = f"{repo}#{pr['number']}"
        why = pr_reasons(pr, unreviewed)
        if not why or ref in exempt or names_pr(busy, pr["number"], str(pr.get("headRefName") or "")):
            continue
        if not trusted_author(repo, pr, allow or set(), forks):
            skipped += 1
            continue
        out.append(f"{ref} ({', '.join(why)})")  # no title, branch or author: they are third-party text
    return out, skipped


# -- the decision ---------------------------------------------------------------------------------


def log_path(env: Mapping[str, str]) -> Path:
    return Path(env.get("SAFO_IDLE_LOG") or Path(env.get("HOME", "")) / DEFAULT_LOG)


def log_row(env: Mapping[str, str], row: dict[str, Any]) -> bool:
    path = log_path(env)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.stat().st_size > LOG_CAP:
            path.replace(path.with_suffix(".log.1"))
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    except OSError:
        return False
    return True


def reason_text(running: int, floor: int, ready: list[str], notes: list[str]) -> str:
    lines = [
        f"idle-check: {running} of {floor} workers running and ready work exists. Dispatch it before ending the turn:"
    ]
    lines += [f"- {output.line(x)}" for x in ready[:LIST_CAP]]
    if len(ready) > LIST_CAP:
        lines.append(f"- ...and {len(ready) - LIST_CAP} more")
    lines += [f"DEGRADED: {output.line(n)}" for n in notes]
    return "\n".join(lines)


def decide(
    payload: dict[str, Any], env: Mapping[str, str], runner: Runner, now: float
) -> tuple[dict[str, Any], str, dict[str, Any]]:
    """(output, decision, row fields). Every source failure is reported in the notes, never raised."""
    cfg = load_config(env)
    floor = as_int(cfg.get("floor"), DEFAULT_FLOOR)
    window = as_float(cfg.get("window_seconds"), DEFAULT_WINDOW)
    notes: list[str] = []
    busy: list[str] = []
    sources: tuple[tuple[str, Callable[[], list[str]]], ...] = (
        ("agents", lambda: count_subagents(str(payload.get("transcript_path") or ""), now, window)),
        ("processes", lambda: count_processes(Path(env.get("SAFO_IDLE_PROC") or "/proc"))),
    )
    for name, source in sources:  # each source on its own: one failing never hides the other
        try:
            busy.extend(source())
        except Degraded as err:
            notes.append(str(err))
        except Exception:
            notes.append(f"{name}: unexpected failure reading the running workers")
    ready: list[str] = []
    try:
        default_queue = [str(Path(env.get("HOME", "")) / DEFAULT_QUEUE)]
        ready.extend(read_queues(list(cfg.get("queue_paths", default_queue))))
    except Degraded as err:
        notes.append(str(err))
    repos = cfg.get("repos")
    try:
        repos = repos if isinstance(repos, list) else tracked_repos(env)
    except Degraded as err:
        notes.append(str(err))
        repos = []
    where = log_path(env).parent
    ttl = as_float(cfg.get("cache_seconds"), DEFAULT_CACHE) if str(cfg.get("cache_seconds")) != "0" else 0.0
    prs = cached_prs(env, repos, ttl, now) if ttl else None
    if prs is None:
        prs, pr_notes = fetch_prs(repos, runner, str(where) if where.is_dir() else env.get("HOME", "/"))
        notes += pr_notes
        if ttl and not pr_notes:
            store_prs(env, repos, prs, now)  # only a complete scan is cached, so a failure is never served again
    exempt = {x for x in cfg.get("exempt", []) if isinstance(x, str)}
    trusted = cfg.get("trusted_authors")
    allow = {login_key(a) for a in trusted if isinstance(a, str)} if isinstance(trusted, list) else set()
    found, skipped = ready_prs(
        prs, "\n".join(busy), exempt, cfg.get("include_unreviewed") is True, allow, cfg.get("allow_forks") is True
    )
    ready.extend(found)
    unknown = any(n.startswith(("agents:", "processes:")) for n in notes)
    running = len(busy)
    fields: dict[str, Any] = {"running": None if unknown else running, "ready": len(ready), "floor": floor}
    fields["skipped_untrusted"] = skipped
    fields["degraded"] = [n.split(":")[0] for n in notes]
    if not unknown and running < floor and ready:
        text = reason_text(running, floor, ready, notes)
        if str(cfg.get("mode", "block")) == "warn":
            return {"systemMessage": text}, "warn", fields
        return {"decision": "block", "reason": text}, "block", fields
    if notes:
        return (
            {"systemMessage": "idle-check " + "; ".join(f"DEGRADED: {output.line(n)}" for n in notes)},
            "degraded",
            fields,
        )
    return {}, "allow", fields


def main_with(stdin: TextIO, stdout: TextIO, env: Mapping[str, str], runner: Runner = subprocess.run) -> int:
    now = time.time()
    stamp = dt.datetime.fromtimestamp(now).strftime("%Y-%m-%dT%H:%M:%S")
    row: dict[str, Any] = {
        "ts": stamp,
        "session": "",
        "running": None,
        "ready": None,
        "floor": None,
        "skipped_untrusted": 0,  # on every log path, including the stop_hook_active and error paths
        "degraded": [],
    }
    try:
        payload = loads(stdin.read(INPUT_CAP))
        if not isinstance(payload, dict):
            raise ValueError("event is not an object")
        row["session"] = str(payload.get("session_id", ""))[:64]
        if payload.get("stop_hook_active") is True:
            row["decision"] = "active"
            log_row(env, row)
            return 0
        out, decision, fields = decide(payload, env, runner, now)
        row.update(fields)
    except Exception as err:  # fail open, loudly: a fixed notice with the exception class only
        out = {"systemMessage": f"idle-check DEGRADED: {type(err).__name__}; the idle rule was not checked"}
        decision = "degraded"
        row["degraded"] = ["input" if isinstance(err, (ValueError, Degraded)) else "unexpected"]
    row["decision"] = decision
    if not log_row(env, row) and out.get("systemMessage"):
        out["systemMessage"] += " (idle-check log not writable)"
    if out:
        stdout.write(json.dumps(out) + "\n")
        stdout.flush()
    return 0


def stats(env: Mapping[str, str], out: TextIO) -> int:
    try:
        lines = log_path(env).read_text(errors="replace").splitlines()
    except OSError:
        out.write("idle-check: no log yet\n")
        return 0
    days: dict[str, Counter[str]] = {}
    for line in lines:
        with contextlib.suppress(ValueError, AttributeError, KeyError, TypeError):
            row = loads(line)
            days.setdefault(row["ts"][:10], Counter())[row["decision"]] += 1
    for day in sorted(days):
        c = days[day]
        out.write(f"{day} blocks={c['block']} allows={c['allow']} degraded={c['degraded']} warns={c['warn']}\n")
    return 0


def read_event(stream: TextIO, wait: float = INPUT_WAIT) -> TextIO:
    """The event from a pipe, read in chunks against ONE deadline (`wait` seconds in all). It stops at end of input, at
    the size cap, at the deadline, or as soon as what has arrived is a whole JSON document, so a writer that sends the
    event and keeps the pipe open cannot hold the hook. A terminal or a silent pipe is an empty event (degraded)."""
    if stream.isatty():
        return io.StringIO("")
    until = time.monotonic() + wait
    data = b""
    try:
        fd = stream.fileno()
        while len(data) < INPUT_CAP:
            left = until - time.monotonic()
            if left <= 0 or not select.select([fd], [], [], left)[0]:
                break
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            data += chunk
            with contextlib.suppress(ValueError):
                loads(data)
                break  # a complete document: do not wait for the writer to close
    except (OSError, ValueError):
        pass
    return io.StringIO(data.decode("utf-8", "replace"))


def run() -> None:
    if "--stats" in sys.argv[1:]:
        sys.exit(stats(os.environ, sys.stdout))
    sys.exit(main_with(read_event(sys.stdin), sys.stdout, os.environ))


if __name__ == "__main__":
    run()
