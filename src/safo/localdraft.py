# SPDX-License-Identifier: Apache-2.0
"""safo-draft: the local-first path made the easy path (issue #482). A wrapper beside `safo-file` and `safo-card`.

    safo-draft issue   --repo o/r --title T [--epic N] [--facts FILE] [--yes] [PROMPT]
    safo-draft pr      --repo o/r --title T [--head B] [--base B] [--facts FILE] [--yes] [PROMPT]
    safo-draft comment --repo o/r --number N [--facts FILE] [--yes] [PROMPT]
    safo-draft digest ci-log [FILE|-]
    safo-draft digest board-drift [FILE|-]
    safo-draft --report

`issue`, `pr` and `comment` write a draft with `llm-local` (stdin is /dev/null, since llm-local hangs on an open
stdin), print it, run the checks in `check_text`, and file it with `gh` only after a yes (`--yes` for non-interactive
use; the draft is still printed). A draft that fails a check is printed with the reasons and never filed, even with
`--yes`. `digest` groups and counts in code and sends only the grouped lines to the model for a five-line summary.

Every call appends one JSON line (no content) to `$XDG_STATE_HOME/safo/local-share.jsonl` (default
`~/.local/state/safo/`); `--report` prints counts per ISO week. Exit 75 from llm-local (queue busy) is retried with
backoff, then passed on. Any other failure exits non-zero, prints the failure, and says Twingate and the local server
were NOT verified; there is never a silent fallback to a Claude model.

Employer and other private words are not hard-coded (this repository is public): put them, comma separated, in
`SAFO_DRAFT_DENY`, or one per line in the file named by `SAFO_DRAFT_DENY_FILE`. See docs/local-draft.md.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TextIO

SHORT_MODEL = "qwen3.5:4b"
LONG_MODEL = "gemma4:12b"
LONG_INPUT = 600  # characters of prompt plus facts above which the long model is used
MAX_FACTS = 100_000
RETRIES = 4
BACKOFF = (5, 10, 20)
WAIT_SECONDS = "60"
PR_FOOTER = "🤖 Generated with [Claude Code](https://claude.com/claude-code)"
EM_DASH = chr(0x2014)
NOT_VERIFIED = "Twingate and the local server were NOT verified; nothing was sent to a Claude model."

EXIT_OK, EXIT_REFUSED, EXIT_ERROR, EXIT_BUSY = 0, 1, 2, 75

_PLACEHOLDERS = {"N0CALL", "N0TST", "FN31pr"}
_CALLSIGN = re.compile(r"\b[AKNW][A-Z]?[0-9][A-Z]{2,3}\b")
_GRID6 = re.compile(r"\b[A-R]{2}[0-9]{2}[a-x]{2}\b")
_GRID4 = re.compile(r"\bgrid(?:\s+square)?[\s:=]+([A-R]{2}[0-9]{2})\b", re.IGNORECASE)
_IPV4 = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
_HOSTNAME = re.compile(
    r"\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.(?:lan|local|internal|home|corp|intranet|home\.arpa)\b", re.I
)
_SERIAL = re.compile(r"\b(?:serial(?:\s+(?:number|no\.?))?|s/n)[\s:#=]+[A-Z0-9-]{6,}", re.IGNORECASE)
_SESSION_URL = re.compile(r"https?://\S*claude\.ai\S*", re.IGNORECASE)
_SESSION_TRAILER = re.compile(r"^\s*claude-session\s*:", re.IGNORECASE | re.MULTILINE)
_EPIC = re.compile(r"^\s*(?:epic\s*:\s*\S+|part of epic\s+#\d+)", re.IGNORECASE | re.MULTILINE)

_FAILURE = re.compile(r"##\[error\]|\berror\b|\bfailed\b|\bfailure\b|traceback|exit code [1-9]|\bFAIL\b", re.IGNORECASE)
_STAMP = re.compile(r"^(?:[^\t]*\t){0,2}\s*\d{4}-\d\d-\d\dT[\d:.]+Z\s*")
_ISSUE_REF = re.compile(r"(?:[\w.-]+/[\w.-]+)?#\d+")
_NUMBER = re.compile(r"\b\d+\b")

Run = Callable[..., "subprocess.CompletedProcess[str]"]


class Failure(Exception):
    def __init__(self, message: str, code: int) -> None:
        super().__init__(message)
        self.code = code


def deny_words(env: Mapping[str, str]) -> list[str]:
    words = [w.strip() for w in env.get("SAFO_DRAFT_DENY", "").split(",")]
    path = env.get("SAFO_DRAFT_DENY_FILE")
    if path and Path(path).is_file():
        words += [w.strip() for w in Path(path).read_text().splitlines()]
    return [w for w in words if w]


def check_text(kind: str, text: str, deny: Sequence[str] = ()) -> list[str]:
    """The reasons a draft may not be filed. An empty list means it passed."""
    why: list[str] = []
    if EM_DASH in text:
        why.append("em dash found (use a comma, colon or hyphen)")
    if _IPV4.search(text):
        why.append("IP address found")
    if _HOSTNAME.search(text):
        why.append("hostname found")
    if _SERIAL.search(text):
        why.append("serial number found")
    calls = [m for m in _CALLSIGN.findall(text) if m not in _PLACEHOLDERS]
    grids = [m for m in _GRID6.findall(text) if m not in _PLACEHOLDERS]
    grids += [m for m in _GRID4.findall(text) if m not in _PLACEHOLDERS]
    if calls:
        why.append("amateur radio callsign pattern found (use N0CALL)")
    if grids:
        why.append("grid square found (use FN31pr)")
    if _SESSION_URL.search(text):
        why.append("claude.ai session URL found")
    if _SESSION_TRAILER.search(text):
        why.append("Claude-Session trailer found")
    lowered = text.lower()
    for word in deny:
        if word.lower() in lowered:
            why.append("denied word found (SAFO_DRAFT_DENY)")
            break
    if kind == "pr":
        lines = [x for x in text.splitlines() if x.strip()]
        if not lines or lines[-1].strip() != PR_FOOTER:
            why.append(f"pull request body must end with the exact line: {PR_FOOTER}")
    if kind == "issue" and not _EPIC.search(text):
        why.append("issue needs an 'Epic:' or 'Part of epic #N' line (pass --epic N)")
    return why


def _normalize_ci(line: str) -> str:
    line = _STAMP.sub("", line).strip()
    return _NUMBER.sub("N", line)


def _tally(lines: Sequence[str]) -> list[tuple[int, str]]:
    counts = collections.Counter(lines)
    return sorted(((n, text) for text, n in counts.items()), key=lambda x: (-x[0], x[1]))


def group_ci_log(text: str) -> list[tuple[int, str]]:
    """Failure lines of a CI log, normalised and counted in code: [(count, line)], most frequent first."""
    return _tally([_normalize_ci(x) for x in text.splitlines() if _FAILURE.search(x)])


def group_board_drift(text: str) -> list[tuple[int, str]]:
    """`safo audit` lines that name drift, with issue refs folded to #N, counted in code."""
    keep = [
        _ISSUE_REF.sub("#N", x.strip())
        for x in text.splitlines()
        if x.strip() and not x.strip().lower().startswith("ok")
    ]
    return _tally(keep)


def _state_path(env: Mapping[str, str]) -> Path:
    base = env.get("XDG_STATE_HOME") or str(Path(env.get("HOME", str(Path.home()))) / ".local" / "state")
    return Path(base) / "safo" / "local-share.jsonl"


def _log_call(env: Mapping[str, str], now: dt.datetime, sub: str, model: str, code: int, n_in: int, n_out: int) -> None:
    path = _state_path(env)
    row = {"ts": now.isoformat(), "subcommand": sub, "model": model, "exit": code, "chars_in": n_in, "chars_out": n_out}
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a") as handle:
            handle.write(json.dumps(row) + "\n")
    except OSError:
        pass  # metrics must never block the work


def report(env: Mapping[str, str], out: TextIO) -> int:
    path = _state_path(env)
    weeks: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
    if path.is_file():
        for raw in path.read_text().splitlines():
            try:
                row = json.loads(raw)
                year, wk, _ = dt.datetime.fromisoformat(row["ts"]).isocalendar()
                weeks[f"{year}-W{wk:02d}"][str(row["subcommand"])] += 1
                weeks[f"{year}-W{wk:02d}"]["_failed"] += 1 if row.get("exit") != 0 else 0
            except (ValueError, KeyError, TypeError):
                continue
    if not weeks:
        out.write("no local calls recorded\n")
        return EXIT_OK
    for week in sorted(weeks):
        counts = weeks[week]
        failed = counts.pop("_failed", 0)
        detail = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        out.write(f"{week}: {sum(counts.values())} calls, {failed} failed ({detail})\n")
    return EXIT_OK


def _which(env: Mapping[str, str], name: str) -> str:
    found = shutil.which(name, path=env.get("PATH", ""))
    if not found:
        raise Failure(f"{name} not found on PATH. {NOT_VERIFIED}", EXIT_ERROR)
    return found


def call_local(env: Mapping[str, str], sleep: Callable[[float], None], task: str, model: str, prompt: str) -> str:
    exe = _which(env, "llm-local")
    argv = [exe, "--task", task, "--model", model, "--wait", WAIT_SECONDS, prompt]
    last = ""
    for attempt in range(RETRIES):
        done = subprocess.run(  # noqa: S603 - argv list, absolute path from PATH lookup, no shell
            argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, env=dict(env), check=False, timeout=900
        )
        if done.returncode == 0:
            return done.stdout.strip()
        last = (done.stderr or done.stdout).strip()
        if done.returncode != EXIT_BUSY:
            raise Failure(f"llm-local failed (exit {done.returncode}): {last}\n{NOT_VERIFIED}", done.returncode)
        if attempt < RETRIES - 1:
            sleep(BACKOFF[min(attempt, len(BACKOFF) - 1)])
    raise Failure(f"llm-local queue still busy after {RETRIES} tries: {last}", EXIT_BUSY)


def _gh(env: Mapping[str, str], args: list[str], body: str) -> str:
    done = subprocess.run(  # noqa: S603 - argv list, absolute path from PATH lookup, no shell
        [_which(env, "gh"), *args, "--body-file", "-"],
        input=body,
        capture_output=True,
        text=True,
        env=dict(env),
        check=False,
        timeout=120,
    )
    if done.returncode != 0:
        raise Failure(f"gh failed (exit {done.returncode}): {done.stderr.strip()}", done.returncode or EXIT_ERROR)
    return done.stdout.strip()


_INSTRUCTIONS = {
    "issue": "Write the body of a GitHub issue. Plain text, no title line, no em dashes, no hostnames or IPs.",
    "pr": "Write the body of a GitHub pull request. Plain text, no title line, no em dashes, no hostnames or IPs.",
    "comment": "Write a short GitHub comment. Plain text, no em dashes, no hostnames or IPs.",
}


def _read_facts(path: str | None, stdin: TextIO) -> str:
    if not path:
        return ""
    text = stdin.read() if path == "-" else Path(path).read_text()
    return text[:MAX_FACTS]


def _confirm(args: argparse.Namespace, stdin: TextIO, out: TextIO) -> bool:
    if args.yes:
        return True
    out.write("File this? [y/N] ")
    out.flush()
    return stdin.readline().strip().lower() in {"y", "yes"}


def _draft(args: argparse.Namespace, ctx: Ctx) -> int:
    kind = args.cmd
    facts = _read_facts(args.facts, ctx.stdin)
    if not args.prompt and not facts:
        raise Failure("give a short prompt or --facts FILE", EXIT_ERROR)
    prompt = f"{_INSTRUCTIONS[kind]}\n\nRequest: {args.prompt or ''}\n\nFacts:\n{facts}"
    model = args.model or (LONG_MODEL if len(prompt) - len(_INSTRUCTIONS[kind]) > LONG_INPUT else SHORT_MODEL)
    ctx.model, ctx.chars_in = model, len(prompt)
    body = call_local(ctx.env, ctx.sleep, f"draft-{kind}", model, prompt)
    ctx.chars_out = len(body)
    if kind == "pr" and not body.rstrip().endswith(PR_FOOTER):
        body = f"{body.rstrip()}\n\n{PR_FOOTER}"
    if kind == "issue" and args.epic and not _EPIC.search(body):
        body = f"{body.rstrip()}\n\nPart of epic #{args.epic}"
    ctx.out.write(f"--- draft {kind} ---\n{body}\n--- end draft ---\n")
    why = check_text(kind, body, deny_words(ctx.env))
    if why:
        ctx.out.write("NOT FILED. The draft failed these checks:\n" + "".join(f"  - {x}\n" for x in why))
        return EXIT_REFUSED
    if not _confirm(args, ctx.stdin, ctx.out):
        ctx.out.write("not filed\n")
        return EXIT_REFUSED
    if kind == "issue":
        cmd = ["issue", "create", "--repo", args.repo, "--title", args.title]
    elif kind == "pr":
        cmd = ["pr", "create", "--repo", args.repo, "--title", args.title]
        for flag, value in (("--head", args.head), ("--base", args.base)):
            if value:
                cmd += [flag, value]
    else:
        cmd = ["issue", "comment", str(args.number), "--repo", args.repo]
    ctx.out.write(_gh(ctx.env, cmd, body) + "\n")
    return EXIT_OK


def _digest(args: argparse.Namespace, ctx: Ctx) -> int:
    ctx.sub = f"digest-{args.what}"
    path = args.file or "-"
    text = ctx.stdin.read() if path == "-" else Path(path).read_text(errors="replace")
    groups = group_ci_log(text) if args.what == "ci-log" else group_board_drift(text)
    if not groups:
        ctx.out.write("no failure lines found\n" if args.what == "ci-log" else "no drift lines found\n")
        return EXIT_OK
    grouped = "\n".join(f"{n} x {line}" for n, line in groups[:30])
    ctx.out.write(f"--- grouped (counted in code) ---\n{grouped}\n")
    what = "CI failure lines" if args.what == "ci-log" else "board drift lines"
    prompt = (
        f"Summarize these grouped {what} in exactly five short lines. The counts are correct; do not recount, "
        f"regroup or invent items. No em dashes.\n\n{grouped}"
    )
    ctx.model, ctx.chars_in = SHORT_MODEL, len(prompt)
    summary = call_local(ctx.env, ctx.sleep, ctx.sub, SHORT_MODEL, prompt)
    ctx.chars_out = len(summary)
    ctx.out.write(f"--- summary (local model) ---\n{summary}\n")
    return EXIT_OK


class Ctx:
    def __init__(
        self, env: Mapping[str, str], out: TextIO, stdin: TextIO, sleep: Callable[[float], None], sub: str
    ) -> None:
        self.env, self.out, self.stdin, self.sleep, self.sub = env, out, stdin, sleep, sub
        self.model, self.chars_in, self.chars_out = "", 0, 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="safo-draft", description="local-first drafts and digests (llm-local)")
    p.add_argument("--report", action="store_true", help="print local-call counts per ISO week")
    sub = p.add_subparsers(dest="cmd")
    for name in ("issue", "pr", "comment"):
        s = sub.add_parser(name, help=f"draft a {name} locally, check it, file it after a yes")
        s.add_argument("prompt", nargs="?", default="", help="a short prompt")
        s.add_argument("--repo", required=True, help="owner/repo")
        s.add_argument("--facts", help="a fact file (- for stdin)")
        s.add_argument("--model", help=f"override the model ({SHORT_MODEL} short, {LONG_MODEL} long)")
        s.add_argument("--yes", action="store_true", help="file without asking (the draft is still printed)")
        if name != "comment":
            s.add_argument("--title", required=True)
        if name == "issue":
            s.add_argument("--epic", help="epic issue number; adds 'Part of epic #N' when the draft lacks one")
        if name == "pr":
            s.add_argument("--head")
            s.add_argument("--base")
        if name == "comment":
            s.add_argument("--number", required=True, type=int, help="issue or pull request number")
    d = sub.add_parser("digest", help="group and count in code, summarize five lines locally")
    ds = d.add_subparsers(dest="what", required=True)
    for what in ("ci-log", "board-drift"):
        s = ds.add_parser(what)
        s.add_argument("file", nargs="?", help="a file, or - (default) for stdin")
    return p


def main(
    argv: Sequence[str],
    *,
    env: Mapping[str, str],
    out: TextIO,
    err: TextIO,
    stdin: TextIO,
    sleep: Callable[[float], None],
    now: dt.datetime | None = None,
) -> int:
    try:
        args = parser().parse_args(list(argv))
    except SystemExit as stop:
        return int(stop.code) if isinstance(stop.code, int) else EXIT_ERROR
    if args.report:
        return report(env, out)
    if not args.cmd:
        err.write("safo-draft: give a subcommand (issue, pr, comment, digest) or --report\n")
        return EXIT_ERROR
    ctx = Ctx(env, out, stdin, sleep, args.cmd)
    code = EXIT_OK
    try:
        code = _digest(args, ctx) if args.cmd == "digest" else _draft(args, ctx)
    except Failure as problem:
        err.write(f"safo-draft: {problem}\n")
        code = problem.code
    except OSError as problem:
        err.write(f"safo-draft: {problem}\n")
        code = EXIT_ERROR
    if ctx.model:
        _log_call(env, now or dt.datetime.now(dt.UTC), ctx.sub, ctx.model, code, ctx.chars_in, ctx.chars_out)
    return code


def entry() -> None:
    raise SystemExit(
        main(sys.argv[1:], env=os.environ, out=sys.stdout, err=sys.stderr, stdin=sys.stdin, sleep=time.sleep)
    )


if __name__ == "__main__":
    entry()
