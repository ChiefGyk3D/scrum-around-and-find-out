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
import html
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TextIO

SHORT_MODEL = "qwen3.5:4b"
LONG_MODEL = "gemma4:12b"
LONG_INPUT = 600  # characters of prompt plus facts above which the long model is used
MAX_PROMPT_BYTES = 100_000  # encoded bytes of the whole prompt; the kernel limit is 131072 per argument
LLM_TIMEOUT = 900
GH_TIMEOUT = 120
RETRIES = 4
BACKOFF = (5, 10, 20)
WAIT_SECONDS = "60"
PR_FOOTER = "🤖 Generated with [Claude Code](https://claude.com/claude-code)"
# U+2014 em dash and its small, vertical and two/three-em look-alikes. U+2015 (horizontal bar) is not blocked.
EM_DASHES = "".join(chr(c) for c in (0x2014, 0xFE58, 0xFE31, 0x2E3A, 0x2E3B))
MAX_CHECK_CHARS = 20_000  # model output longer than this is refused, not checked
CANON_ROUNDS = 3
NOT_VERIFIED = "Twingate and the local server were NOT verified; nothing was sent to a Claude model."

EXIT_OK, EXIT_REFUSED, EXIT_ERROR, EXIT_DECLINED, EXIT_TIMEOUT, EXIT_INTERNAL, EXIT_GH_FAILED, EXIT_BUSY = (
    0,
    1,
    2,
    10,
    11,
    12,
    13,
    75,
)
EXIT_TABLE = (
    "exit codes: 0 done; 1 refused (the draft or title failed a check); 2 error (usage, missing tool or "
    "input too large); 10 declined (you answered no); 11 timeout (llm-local or gh); 12 unexpected internal "
    "error; 13 gh failed (filing or commenting); 75 local queue still busy; any other code is the llm-local exit code"
)

_PLACEHOLDERS = {"N0CALL", "N0TST", "FN31PR", "FN31", "K1ABC"}
# Common technical tokens that have the shape of a callsign or grid. Extend with SAFO_DRAFT_ALLOW.
_TECH_TOKENS = {
    "K8S",
    "P2P",
    "B2B",
    "E2E",
    "A2A",
    "M2M",
    "H2O",  # the original set
    "K3S",
    "N8N",
    "W3C",
    "C2PA",
    "I2C",
    "I2S",
    "E2EE",
    "L2TP",
    "M3U",  # added in round 3, from docs and common tech terms
}
_CALL_SHAPE = r"[A-Z]{1,2}[0-9][A-Z]{1,3}"
_EDGE_BEFORE = r"(?<![A-Za-z0-9_-])"  # not inside a longer alphanumeric, hyphenated or underscore token
_EDGE_AFTER = r"(?![A-Za-z0-9_-])"
# any case, no cue needed; an optional APRS-style SSID (`-7`, `-15`) is part of the callsign. A hyphen followed by a
# letter or a third digit still makes a longer token (`my-w1aw-x`), left to the allow list for false positives.
_CALLSIGN = re.compile(rf"{_EDGE_BEFORE}{_CALL_SHAPE}(?:-\d{{1,2}})?{_EDGE_AFTER}", re.IGNORECASE)
_CALLSIGN_CTX = re.compile(
    rf"\b(?:call\s*sign|call|de)\b(?:\s+is)?[\s:=]+({_CALL_SHAPE})\b", re.IGNORECASE
)  # any case after a cue, even inside a hyphenated token
_GRID6 = re.compile(r"\b[A-R]{2}[0-9]{2}[A-X]{2}\b", re.IGNORECASE)
_GRID4 = re.compile(rf"{_EDGE_BEFORE}[A-R]{{2}}[0-9]{{2}}{_EDGE_AFTER}", re.IGNORECASE)
_GRID_CTX = re.compile(
    r"\b(?:grid(?:\s*square)?|locator|maidenhead)\b[\s:=]+([A-R]{2}[0-9]{2}(?:[A-X]{2})?)\b", re.IGNORECASE
)
_IPV4 = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
_IPV6_RUN = re.compile(r"[0-9A-Fa-f:.]+(?:%[\w.-]+)?")
_NAME_RUN = re.compile(r"[A-Za-z0-9.-]+")
_PRIVATE_SUFFIXES = {"lan", "local", "internal", "home", "corp", "intranet"}  # plus home.arpa, covered by "home"
_SERIAL = re.compile(
    r"\b(?:serial(?:\s+(?:number|no\.?|num))?|s/n|sn)[\s:#=]+(?=[A-Z0-9-]*\d)[A-Z0-9-]{6,}", re.IGNORECASE
)
_SESSION_TRAILER = re.compile(r"^[ \t]*claude-session[ \t]*:", re.IGNORECASE | re.MULTILINE)
_MD_ESCAPE = re.compile(r"\\([!-/:-@\[-`{-~])")
_TAG = re.compile(r"</?[A-Za-z][^<>]*>")
_EPIC = re.compile(r"^[ \t]*(?:epic\s*:\s*\S+|part of epic\s+#\d+)", re.IGNORECASE | re.MULTILINE)

_FAILURE = re.compile(r"##\[error\]|\berror\b|\bfailed\b|\bfailure\b|traceback|exit code [1-9]|\bFAIL\b", re.IGNORECASE)
_STAMP = re.compile(r"^(?:[^\t]*\t){0,2}\s*\d{4}-\d\d-\d\dT[\d:.]+Z\s*")
_ISSUE_REF = re.compile(r"(?:[\w.-]+/[\w.-]+)?#\d+")
_NUMBER = re.compile(r"\b\d+\b")

Run = Callable[..., "subprocess.CompletedProcess[str]"]


class Failure(Exception):
    def __init__(self, message: str, code: int) -> None:
        super().__init__(message)
        self.code = code


def _words(env: Mapping[str, str], var: str) -> list[str]:
    words = [w.strip() for w in env.get(var, "").split(",")]
    path = env.get(f"{var}_FILE")
    if path and Path(path).is_file():
        words += [w.strip() for w in Path(path).read_text(errors="replace").splitlines()]
    return [w for w in words if w]


def deny_words(env: Mapping[str, str]) -> list[str]:
    return _words(env, "SAFO_DRAFT_DENY")


def allow_words(env: Mapping[str, str]) -> list[str]:
    return _words(env, "SAFO_DRAFT_ALLOW")


def _strip_comments(text: str) -> str:
    """Remove `<!-- ... -->` in one linear pass; an unterminated comment is left as it is."""
    out: list[str] = []
    pos = 0
    while True:
        start = text.find("<!--", pos)
        if start < 0:
            break
        end = text.find("-->", start + 4)
        if end < 0:
            break
        out.append(text[pos:start])
        pos = end + 3
    out.append(text[pos:])
    return "".join(out)


def _canonical_round(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = "".join(c for c in text if unicodedata.category(c) != "Cf")  # zero-width, soft hyphen, BOM, bidi marks
    text = html.unescape(text)
    text = _TAG.sub("", _strip_comments(text))
    return _MD_ESCAPE.sub(r"\1", text)


def canonicalize(text: str) -> str:
    """The render-equivalent form of a text: what a reader sees after Markdown and HTML are rendered.

    NFKC, format and zero-width characters dropped, HTML entities decoded, HTML comments and tags removed, Markdown
    escapes removed; repeated to a fixed point, at most CANON_ROUNDS times (so `&amp;#46;` becomes a dot).
    """
    for _ in range(CANON_ROUNDS):
        new = _canonical_round(text)
        if new == text:
            break
        text = new
    return text


def _has_private_host(text: str) -> bool:
    """A dotted name with a private label (`box.lan`, `a.corp.example.com`, `x.home.arpa`), found by splitting."""
    for run in _NAME_RUN.findall(text):
        labels = run.lower().split(".")
        for i in range(1, len(labels)):
            if labels[i - 1] and labels[i].split("-", 1)[0] in _PRIVATE_SUFFIXES:
                return True
    return False


def _has_session_url(text: str) -> bool:
    for token in text.lower().split():
        at = token.find("claude.ai")
        while at >= 0:
            if token.startswith("claude.ai/", at) or "http://" in token[:at] or "https://" in token[:at]:
                return True
            at = token.find("claude.ai", at + 1)
    return False


_HEXTET = frozenset("0123456789abcdefABCDEF")
_MAX_IPV6_CHARS = 46  # the longest valid IPv6 text (with an embedded IPv4) is 45 characters


def _is_scope(text: str, run_start: int, run: str) -> bool:
    """`std::vector`: a `::` followed by an identifier that cannot be a hextet is a C++ style scope, not an address."""
    at = run.find("::")
    if at < 0:
        return False
    begin = run_start + at + 2
    ident = re.match(r"\w{1,64}", text[begin:])
    if not ident:
        return False
    word = ident.group()
    return (word[0].isalpha() or word[0] == "_") and any(c not in _HEXTET for c in word)


def _hextets_before(cand: str, at: int) -> int:
    parts = cand[:at].split(":")
    return len(parts) if all(parts) else 0


def _has_ipv6(text: str) -> bool:
    """Scan every maximal run of hex, colon and dot characters (and an optional %zone) for an IPv6 address.

    A leading label such as `ipv6:` or `addr:` is shed by also trying each suffix that starts after a colon. Trailing
    word characters do not hide an address (`fe80::1x`), and trailing dots or colons (padding) are stripped before the
    length cap, so they do not either. A prefix that ends in `::` is flagged when it has at least two non-empty hextets
    before the `::` (`2001:db8::`, `fd00:1234::`); one hextet (`e::`, `fe80::`) is not. A C++ style scope
    (`std::vector`, `a::b_c`) is only flagged when the run before it holds two or more hextets before the `::`.
    """
    for match in _IPV6_RUN.finditer(text):
        run = match.group()
        if run.count(":") < 2:
            continue
        run = run.split("%", 1)[0]
        strict = _is_scope(text, match.start(), run)
        lead = len(run) - len(run.lstrip("."))
        end = len(run.rstrip(".:"))
        has_prefix = run.startswith("::", end) and end > 0
        starts = [lead] + [i + 1 for i, ch in enumerate(run) if ch == ":" and i + 1 >= lead]
        for start in starts:
            if end - start > _MAX_IPV6_CHARS:
                continue
            cands = [run[start:end]]
            if has_prefix:
                cands.append(run[start : end + 2])
            for cand in cands:
                if not cand or cand.startswith(".") or cand.strip(":") == "":
                    continue
                at = cand.find("::")
                if at >= 0:
                    after = cand[at + 2 :]
                    if (not after or strict) and _hextets_before(cand, at) < 2:
                        continue
                try:
                    ipaddress.IPv6Address(cand)
                except ValueError:
                    continue
                return True
    return False


def _deny_hit(text: str, deny: Sequence[str]) -> bool:
    lowered = text.lower()
    squeezed = re.sub(r"\s+", "", lowered)  # a denied value split by a line break or space is still found
    for word in deny:
        low = word.lower()
        if low in lowered or re.sub(r"\s+", "", low) in squeezed:
            return True
    return False


def _single_checks(text: str, deny: Sequence[str], allow: Sequence[str]) -> list[str]:
    ok = {w.upper() for w in (*_PLACEHOLDERS, *_TECH_TOKENS, *allow)}
    why: list[str] = []
    if any(c in text for c in EM_DASHES):
        why.append("em dash found (use a comma, colon or hyphen)")
    if _IPV4.search(text) or _has_ipv6(text):
        why.append("IP address found")
    if _has_private_host(text):
        why.append("hostname found")
    if _SERIAL.search(text):
        why.append("serial number found")
    calls = [m for m in _CALLSIGN.findall(text) + _CALLSIGN_CTX.findall(text) if m.upper() not in ok]
    grids = [m for m in _GRID6.findall(text) + _GRID4.findall(text) + _GRID_CTX.findall(text) if m.upper() not in ok]
    if calls:
        why.append("amateur radio callsign pattern found (use N0CALL; SAFO_DRAFT_ALLOW lists exceptions)")
    if grids:
        why.append("grid square found (use FN31pr; SAFO_DRAFT_ALLOW lists exceptions)")
    if _has_session_url(text):
        why.append("claude.ai session URL found")
    if _SESSION_TRAILER.search(text):
        why.append("Claude-Session trailer found")
    if _deny_hit(text, deny):
        why.append("denied word found (SAFO_DRAFT_DENY)")
    return why


def _generic_checks(text: str, deny: Sequence[str], allow: Sequence[str]) -> list[str]:
    """Checks for any text that gets published. Every check runs on the raw text and on its canonical form."""
    why = _single_checks(text, deny, allow)
    canon = canonicalize(text)
    if canon != text:
        why += [x for x in _single_checks(canon, deny, allow) if x not in why]
    return why


def check_title(title: str, deny: Sequence[str] = (), allow: Sequence[str] = ()) -> list[str]:
    return [f"title: {x}" for x in _generic_checks(title, deny, allow)]


def check_text(kind: str, text: str, deny: Sequence[str] = (), allow: Sequence[str] = ()) -> list[str]:
    """The reasons a draft may not be filed. An empty list means it passed."""
    why = _generic_checks(text, deny, allow)
    if kind == "pr":
        lines = [x for x in text.splitlines() if x.strip()]
        if not lines or lines[-1].strip() != PR_FOOTER:
            why.append(f"pull request body must end with the exact line: {PR_FOOTER}")
    if kind == "issue" and not _EPIC.search(text):
        why.append("issue needs an 'Epic:' or 'Part of epic #N' line (pass --epic N)")
    return why


def check_draft(
    kind: str, title: str | None, body: str, deny: Sequence[str] = (), allow: Sequence[str] = ()
) -> list[str]:
    """All reasons a draft may not be filed: the body, the title, and the title and body read together."""
    why = check_text(kind, body, deny, allow)
    if title is None:
        return why
    why += check_title(title, deny, allow)
    seen = {x.removeprefix("title: ") for x in why}
    for joiner in ("\n", ""):
        for x in _generic_checks(f"{title}{joiner}{body}", deny, allow):
            if x not in seen:
                seen.add(x)
                why.append(f"title and body combined: {x}")
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
        info = path.parent.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid():
            return  # a symlinked or foreign state directory is never written or chmodded
        path.parent.chmod(0o700)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a") as handle:
            os.fchmod(handle.fileno(), 0o600)
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
    size = len(prompt.encode())
    if size > MAX_PROMPT_BYTES:
        raise Failure(
            f"input too large: {size} bytes, the limit is {MAX_PROMPT_BYTES} bytes for the whole prompt. "
            "This is a local input error; trim the facts. Nothing was sent.",
            EXIT_ERROR,
        )
    exe = _which(env, "llm-local")
    argv = [exe, "--task", task, "--model", model, "--wait", WAIT_SECONDS, prompt]
    last = ""
    for attempt in range(RETRIES):
        try:
            done = subprocess.run(  # noqa: S603 - argv list, absolute path from PATH lookup, no shell
                argv,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                env=dict(env),
                check=False,
                timeout=LLM_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            raise Failure(f"llm-local timed out after {LLM_TIMEOUT} s. {NOT_VERIFIED}", EXIT_TIMEOUT) from None
        if done.returncode == 0:
            return done.stdout.strip()
        last = (done.stderr or done.stdout).strip()
        if done.returncode != EXIT_BUSY:
            raise Failure(f"llm-local failed (exit {done.returncode}): {last}\n{NOT_VERIFIED}", done.returncode)
        if attempt < RETRIES - 1:
            sleep(BACKOFF[min(attempt, len(BACKOFF) - 1)])
    raise Failure(f"llm-local queue still busy after {RETRIES} tries: {last}", EXIT_BUSY)


def _gh(env: Mapping[str, str], args: list[str], body: str) -> str:
    try:
        done = subprocess.run(  # noqa: S603 - argv list, absolute path from PATH lookup, no shell
            [_which(env, "gh"), *args, "--body-file", "-"],
            input=body,
            capture_output=True,
            text=True,
            env=dict(env),
            check=False,
            timeout=GH_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        raise Failure(
            f"gh timed out after {GH_TIMEOUT} s. Whether the item was filed is unknown: check with gh "
            "(list the issues, pull requests or comments) before retrying.",
            EXIT_TIMEOUT,
        ) from None
    if done.returncode != 0:
        raise Failure(f"gh failed (exit {done.returncode}): {done.stderr.strip()}", EXIT_GH_FAILED)
    return done.stdout.strip()


_INSTRUCTIONS = {
    "issue": "Write the body of a GitHub issue. Plain text, no title line, no em dashes, no hostnames or IPs.",
    "pr": "Write the body of a GitHub pull request. Plain text, no title line, no em dashes, no hostnames or IPs.",
    "comment": "Write a short GitHub comment. Plain text, no em dashes, no hostnames or IPs.",
}


def _read_facts(path: str | None, stdin: TextIO) -> str:
    if not path:
        return ""
    if path == "-":
        return stdin.read(MAX_PROMPT_BYTES + 1)
    with open(path, "rb") as handle:  # one byte past the cap is enough for call_local to refuse
        return handle.read(MAX_PROMPT_BYTES + 1).decode("utf-8", errors="replace")


def _confirm(args: argparse.Namespace, stdin: TextIO, out: TextIO) -> bool:
    if args.yes:
        return True
    out.write("File this? [y/N] ")
    out.flush()
    return stdin.readline().strip().lower() in {"y", "yes"}


def _with_footer(body: str) -> str:
    """End the body with the exact footer; a footer variant the model wrote is replaced, not kept."""
    lines = body.rstrip().splitlines()
    if lines and "generated with" in lines[-1].lower() and "claude code" in lines[-1].lower():
        lines.pop()
    return "\n".join(lines).rstrip() + f"\n\n{PR_FOOTER}"


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
    if len(body) > MAX_CHECK_CHARS:
        raise Failure(
            f"draft too long to check safely: {len(body)} characters, the limit is {MAX_CHECK_CHARS}. "
            "This is a local input error; ask for a shorter draft. Nothing was filed.",
            EXIT_ERROR,
        )
    if kind == "pr":
        body = _with_footer(body)
    if kind == "issue" and args.epic and not _EPIC.search(body):
        body = f"{body.rstrip()}\n\nPart of epic #{args.epic}"
    ctx.out.write(f"--- draft {kind} ---\n{body}\n--- end draft ---\n")
    deny, allow = deny_words(ctx.env), allow_words(ctx.env)
    why = check_draft(kind, None if kind == "comment" else args.title, body, deny, allow)
    if why:
        ctx.out.write("NOT FILED. The draft failed these checks:\n" + "".join(f"  - {x}\n" for x in why))
        return EXIT_REFUSED
    if not _confirm(args, ctx.stdin, ctx.out):
        ctx.out.write("not filed\n")
        return EXIT_DECLINED
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
    p = argparse.ArgumentParser(
        prog="safo-draft", description="local-first drafts and digests (llm-local)", epilog=EXIT_TABLE
    )
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
    except Exception as problem:  # the last line of defense: always a distinct code and a metrics row
        err.write(f"safo-draft: unexpected {type(problem).__name__}: {problem}\n")
        code = EXIT_INTERNAL
    if ctx.model:
        _log_call(env, now or dt.datetime.now(dt.UTC), ctx.sub, ctx.model, code, ctx.chars_in, ctx.chars_out)
    return code


def entry() -> None:
    raise SystemExit(
        main(sys.argv[1:], env=os.environ, out=sys.stdout, err=sys.stderr, stdin=sys.stdin, sleep=time.sleep)
    )


if __name__ == "__main__":
    entry()
