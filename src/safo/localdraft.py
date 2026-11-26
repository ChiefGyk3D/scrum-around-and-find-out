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

Employer and other private words are not hard-coded (this repository is public): put them, one per line, in the
private deny file (`SAFO_DRAFT_DENY_FILE`, default `~/.config/safo/draft-deny`), or comma separated in
`SAFO_DRAFT_DENY`. A deny value is matched exactly after squashing both sides to lowercase ASCII letters and digits,
and a reason names only the entry number, never the value. See docs/local-draft.md.
"""

from __future__ import annotations

import argparse
import bisect
import collections
import dataclasses
import datetime as dt
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
MAX_TITLE_CHARS = 300  # a title from argv is bounded like the body, so no checked field can be unbounded
MAX_CHECK_CHARS = 20_000  # model output longer than this is refused, not checked
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

# The only built-in allowed tokens: the owner-named placeholders, exact and case-sensitive. Everything else with the
# shape of a callsign or grid is blocked; docs/draft-allow.example.txt lists tech tokens to copy into an allow file.
_BUILTIN_ALLOWED = frozenset({"N0CALL", "N0TST", "FN31pr"})
_CALL_SHAPE = r"[A-Z]{1,2}[0-9][A-Z]{1,3}"
_EDGE_BEFORE = r"(?<![A-Za-z0-9])"  # hyphen and underscore are separators, not token characters
_EDGE_AFTER = r"(?![A-Za-z0-9])"
# any case, no cue needed; an optional APRS-style SSID (`-7`, `-15`) is part of the callsign
_CALLSIGN = re.compile(rf"{_EDGE_BEFORE}{_CALL_SHAPE}(?:-\d{{1,2}})?{_EDGE_AFTER}", re.IGNORECASE)
_CALLSIGN_CTX = re.compile(
    rf"\b(?:call\s*sign|call|de)\b(?:\s+is)?[\s:=]+({_CALL_SHAPE}){_EDGE_AFTER}", re.IGNORECASE
)  # any case after a cue, even inside a hyphenated token
_GRID6 = re.compile(rf"{_EDGE_BEFORE}[A-R]{{2}}[0-9]{{2}}[A-X]{{2}}{_EDGE_AFTER}", re.IGNORECASE)
_GRID4 = re.compile(rf"{_EDGE_BEFORE}[A-R]{{2}}[0-9]{{2}}{_EDGE_AFTER}", re.IGNORECASE)
_GRID_CTX = re.compile(
    rf"\b(?:grid(?:\s*square)?|locator|maidenhead)\b[\s:=]+([A-R]{{2}}[0-9]{{2}}(?:[A-X]{{2}})?){_EDGE_AFTER}",
    re.IGNORECASE,
)
# a whole UUID is masked before the callsign and grid scan: its 4-hex groups (`a1bc`, `ab12`) have those shapes
_UUID = re.compile(
    r"(?<![0-9A-Fa-f-])[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}(?![0-9A-Fa-f-])", re.I
)
_IPV4 = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
_IPV6_RUN = re.compile(r"[0-9A-Fa-f:.]+(?:%[\w.-]+)?")
_NAME_RUN = re.compile(r"[A-Za-z0-9.-]+")
_PRIVATE_SUFFIXES = {"lan", "local", "internal", "home", "corp", "intranet"}  # plus home.arpa, covered by "home"
_SERIAL = re.compile(
    r"\b(?:serial(?:\s+(?:number|no\.?|num))?|s/n|sn)[\s:#=]+(?=[A-Z0-9-]*\d)[A-Z0-9-]{6,}", re.IGNORECASE
)
_SESSION_TRAILER = re.compile(r"^[ \t]*claude-session[ \t]*:", re.IGNORECASE | re.MULTILINE)
_MD_PUNCT = re.compile(r"[*`~\\]")  # emphasis, code, strikethrough and escape characters vanish when rendered
_HTML_START = re.compile(r"<[A-Za-z!/?]")  # a tag, a comment, a declaration, a closing tag, a processing instruction
_HTML_REF = re.compile(r"&(?:#[0-9]+|#[xX][0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9]*)(?:;|\b)")
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


MAX_CONFIG_BYTES = 65_536
MIN_DENY_CHARS = 3  # a deny value that squashes to fewer characters would match almost anything
_DENY_MARK = "matched private deny entry"
_BAD_CATEGORIES = frozenset({"Mn", "Me", "Cf", "Cc", "Co", "Cn", "Cs", "Zl", "Zp"})
_NO_REDUCE = "characters that cannot be reduced to ASCII: refused"
_NO_REDUCE_CONFIG = "a deny value holds characters that cannot be reduced to ASCII"
_NO_DENY_NOTE = "safo-draft: no private deny file configured: only heuristics are active"


@dataclasses.dataclass(frozen=True)
class DenyEntry:
    """A private value, squashed. `label` names it in a reason (`#4` is line 4 of the file); the value is not kept."""

    label: str
    squashed: str


_TYPOGRAPHY = frozenset(chr(c) for c in (*range(0x2018, 0x201E), 0x2013, 0x2022, 0x2026, 0xD7, *range(0x2190, 0x2194)))


def _allowed_symbol(c: str) -> bool:
    """Typographic punctuation and emoji that stay in a draft but add nothing to the skeleton. Variation selectors
    (U+FE0F) and the dingbat digit forms (U+2776 to U+2793, which read as numbers) are not on the list."""
    n = ord(c)
    if c in _TYPOGRAPHY:
        return True
    if 0x1F300 <= n <= 0x1FAFF or n in (0x2B50, 0x2B55):
        return True
    return 0x2600 <= n <= 0x27BF and not 0x2776 <= n <= 0x2793


def _skeleton(text: str) -> tuple[str, bool]:
    """(ASCII skeleton, reducible). NFKC, then NFKD with combining marks removed. Every non-ASCII character must
    either reduce to printable ASCII (a precomposed accent: U+00E9 becomes `e`) or be on the typography and emoji
    allowlist (`_allowed_symbol`, left out of the skeleton). Anything else (Cyrillic, Greek, dotless i, small
    capitals, letterlike or operator lookalikes, currency signs, modifier letters) makes the text not reducible; it is
    left out of the skeleton and the caller must refuse."""
    out: list[str] = []
    reducible = True
    for c in unicodedata.normalize("NFKC", text):
        if c.isascii():
            out.append(c)
            continue
        base = "".join(x for x in unicodedata.normalize("NFKD", c) if not unicodedata.combining(x))
        if base and base.isascii() and base.isprintable():
            out.append(base)
        elif not _allowed_symbol(c):
            reducible = False
    return "".join(out), reducible


def _squash(text: str) -> str:
    """The ASCII skeleton, lowercase, only letters and digits kept: `Ac**me** Corp` and `A-c-m-e corp` squash alike."""
    return re.sub(r"[^a-z0-9]", "", _skeleton(text)[0].lower())


def _read_private_file(path: str, what: str) -> str | None:
    """Read a config file only if it is a regular, non-symlink file of this user that nobody else can write.

    Returns None when the file does not exist. The checks run on the opened descriptor, so a swap after the check
    cannot change what is read, and O_NONBLOCK keeps a FIFO from hanging the open.
    """
    try:
        if stat.S_ISLNK(os.lstat(path).st_mode):
            raise Failure(f"{what} is a symlink; refusing to read it", EXIT_ERROR)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as problem:
        raise Failure(f"{what} cannot be opened: {problem.strerror}", EXIT_ERROR) from None
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise Failure(f"{what} is not a regular file; refusing to read it", EXIT_ERROR)
        if info.st_uid != os.geteuid():
            raise Failure(f"{what} is not owned by you; refusing to read it", EXIT_ERROR)
        if info.st_mode & 0o022:
            raise Failure(f"{what} is group or world writable; run chmod go-w on it", EXIT_ERROR)
        data = handle.read(MAX_CONFIG_BYTES + 1)
    if len(data) > MAX_CONFIG_BYTES:
        raise Failure(f"{what} is larger than {MAX_CONFIG_BYTES} bytes", EXIT_ERROR)
    return data.decode("utf-8", errors="replace")


def _config_lines(text: str) -> list[tuple[int, str]]:
    """(line number, value) for each line that is not blank and does not start with `#`."""
    rows = [(n, line.strip()) for n, line in enumerate(text.splitlines(), 1)]
    return [(n, line) for n, line in rows if line and not line.startswith("#")]


def load_deny(env: Mapping[str, str], err: TextIO) -> list[DenyEntry]:
    """The private deny entries: the file (default ~/.config/safo/draft-deny) and the comma separated SAFO_DRAFT_DENY.

    A value that squashes to fewer than MIN_DENY_CHARS characters is a config error naming the line, not the value.
    A missing default file is noted once on `err`; a file named by SAFO_DRAFT_DENY_FILE that is missing is an error.
    """
    entries: list[DenyEntry] = []
    explicit = env.get("SAFO_DRAFT_DENY_FILE")
    path = explicit or str(Path(env.get("HOME", str(Path.home()))) / ".config" / "safo" / "draft-deny")
    text = _read_private_file(path, "SAFO_DRAFT_DENY_FILE")
    if text is None:
        if explicit:
            raise Failure("SAFO_DRAFT_DENY_FILE names a file that was not found", EXIT_ERROR)
        err.write(_NO_DENY_NOTE + "\n")
    else:
        for n, value in _config_lines(text):
            squashed = _squash(value)
            if not _skeleton(value)[1]:
                raise Failure(f"SAFO_DRAFT_DENY_FILE line {n}: {_NO_REDUCE_CONFIG}", EXIT_ERROR)
            if len(squashed) < MIN_DENY_CHARS:
                raise Failure(
                    f"SAFO_DRAFT_DENY_FILE line {n}: a deny value needs at least {MIN_DENY_CHARS} letters or digits",
                    EXIT_ERROR,
                )
            entries.append(DenyEntry(f"#{n}", squashed))
    for i, value in enumerate((w.strip() for w in env.get("SAFO_DRAFT_DENY", "").split(",")), 1):
        if not value:
            continue
        squashed = _squash(value)
        if not _skeleton(value)[1]:
            raise Failure(f"SAFO_DRAFT_DENY entry {i}: {_NO_REDUCE_CONFIG}", EXIT_ERROR)
        if len(squashed) < MIN_DENY_CHARS:
            raise Failure(
                f"SAFO_DRAFT_DENY entry {i}: a deny value needs at least {MIN_DENY_CHARS} letters or digits",
                EXIT_ERROR,
            )
        entries.append(DenyEntry(f"SAFO_DRAFT_DENY#{i}", squashed))
    return entries


def allow_words(env: Mapping[str, str]) -> list[str]:
    """Extra allowed tokens: SAFO_DRAFT_ALLOW and SAFO_DRAFT_ALLOW_FILE, split on commas and whitespace.

    In the file, lines starting with `#` and blank lines are skipped.
    """
    words = re.split(r"[,\s]+", env.get("SAFO_DRAFT_ALLOW", ""))
    path = env.get("SAFO_DRAFT_ALLOW_FILE")
    if path:
        text = _read_private_file(path, "SAFO_DRAFT_ALLOW_FILE")
        if text is None:
            raise Failure("SAFO_DRAFT_ALLOW_FILE names a file that was not found", EXIT_ERROR)
        for _, line in _config_lines(text):
            words += re.split(r"[,\s]+", line)
    return [w for w in words if w]


def canonicalize(text: str) -> str:
    """The render-equivalent form of a text for the token checks: NFKC, then the Markdown punctuation removed.

    `*`, backtick, `~` and backslash disappear when Markdown renders (`W1**AW**` reads `W1AW`); `_` and `-` stay.
    HTML is not decoded or stripped: a draft that holds any is refused by `_has_html`.
    """
    return _MD_PUNCT.sub("", unicodedata.normalize("NFKC", text))


def _has_unusual_characters(text: str) -> bool:
    """Combining marks, format (zero-width, bidi, tag), control, private-use, unassigned and surrogate characters, and
    any space other than U+0020, in the NFKC form or (for spaces, which NFKC folds to U+0020) in the raw text."""
    for c in text:
        if c.isascii():
            if (c < " " and c not in "\n\r\t") or c == "\x7f":
                return True
        elif unicodedata.category(c) in ("Zs", "Zl", "Zp"):
            return True
    for c in unicodedata.normalize("NFKC", text):
        if not c.isascii():
            kind = unicodedata.category(c)
            if kind in _BAD_CATEGORIES or kind == "Zs":
                return True
    return False


def _has_html(text: str) -> bool:
    return bool(_HTML_START.search(text) or _HTML_REF.search(text))


def _strip_block_markers(line: str) -> str:
    """Remove any run of leading block markers: spaces and tabs, `>`, `-`/`*`/`+` and `1.`/`1)` followed by a space or
    tab (or the end of the line). Linear: each step consumes at least one character."""
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if c in " \t>" or (c in "-*+" and (i + 1 == n or line[i + 1] in " \t")):
            i += 1
        elif c.isdigit():
            j = i
            while j < n and line[j].isdigit() and j - i < 10:
                j += 1
            if j < n and line[j] in ".)" and (j + 1 == n or line[j + 1] in " \t") and j > i:
                i = j + 1
            else:
                break
        else:
            break
    return line[i:]


def _has_md_link(text: str) -> bool:
    """Inline links and images (`](`, `![`), reference uses (`][`) and reference definitions. A definition is refused
    after any run of block markers (block quote, bullet, numbered item) is stripped: a line that starts with `[` and
    holds `]:` anywhere, or a label that spans lines (a line that starts with `[` and has no `]`, then a later line of
    the same paragraph that holds `]:`; a blank line ends the paragraph). Prose with `]:` mid-line after text that
    does not start with `[` (`note about a[0]: the first`) is allowed, as are `- [x] done` and `see [1]`. Linear: only
    `str.find` and `in` scans, no backtracking. The exact PR footer is exempt."""
    text = text.replace(PR_FOOTER, "")
    if "](" in text or "![" in text or "][" in text:
        return True
    open_label = False
    for line in text.splitlines():
        rest = _strip_block_markers(line)
        if not rest.strip():
            open_label = False
            continue
        if open_label or rest.startswith("["):
            if "]:" in rest:
                return True
            open_label = "]" not in rest
    return False


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


def _is_scope(text: str, begin: int, head: str) -> bool:
    """`std::vector`: is the identifier at `begin` (right after one `::`) a C++ style scope name, not an address?

    `head` is the text before that `::` in the candidate. Scope-like only when the character right after the `::` is a
    letter that is not a hex digit (`std::vector`, `note::x`), or when the word there holds an underscore and both
    sides are single or double hex characters (`a::b_c`). Anything else (`fe80::abcdxyz`, `fe80::1_x`,
    `Config::default`) is tried as an address, so over-blocking of `Config::default` style names is accepted. Each
    candidate asks about its own `::`, so a scope-like `::` elsewhere in the run does not hide a real address.
    """
    word = re.match(r"\w{1,64}", text[begin : begin + 64])
    if not word:
        return False
    first = word.group()[0]
    if first.isalpha() and first not in _HEXTET:
        return True
    lead = len(word.group()) - len(word.group().lstrip("0123456789abcdefABCDEF"))
    before = head.rsplit(":", 1)[-1]
    return "_" in word.group() and lead <= 2 and len(before) <= 2


def _hextets_before(cand: str, at: int) -> int:
    parts = cand[:at].split(":")
    return len(parts) if all(parts) else 0


def _has_ipv6(text: str) -> bool:
    """Scan every maximal run of hex, colon and dot characters (and an optional %zone) for an IPv6 address.

    A leading label such as `ipv6:` or `addr:` is shed by also trying each suffix that starts after a colon. Trailing
    word characters do not hide an address (`fe80::1x`), and trailing dots or colons (padding) are stripped before the
    length cap, so they do not either. For each `::` in a run, the prefix up to and including it, and the prefix plus
    the hextets directly after it, are also tried, so an address whose tail is not valid hex
    (`2001:db8::deadbeefSECRET`) is still flagged. A prefix that ends in `::` is flagged when it has at least two
    non-empty hextets before the `::` (`2001:db8::`, `fd00:1234::`); one hextet (`e::`, `fe80::`) is not. A candidate
    whose own `::` is followed by a scope-like identifier (see `_is_scope`) is only flagged with two or more hextets
    before that `::`; other `::` in the run are judged on their own.
    """
    for match in _IPV6_RUN.finditer(text):
        run = match.group()
        if run.count(":") < 2:
            continue
        run = run.split("%", 1)[0]
        lead = len(run) - len(run.lstrip("."))
        end = len(run.rstrip(".:"))
        doubles = [i for i in range(len(run) - 1) if run[i] == ":" and run[i + 1] == ":"]
        starts = [lead] + [i + 1 for i, ch in enumerate(run) if ch == ":" and i + 1 >= lead]
        for start in starts:
            cands = []
            if end - start <= _MAX_IPV6_CHARS:
                cands.append(run[start:end])
                if run.startswith("::", end) and end > 0:
                    cands.append(run[start : end + 2])
            first = bisect.bisect_left(doubles, start)
            for k in range(first, len(doubles)):
                p = doubles[k]
                if p + 2 - start > _MAX_IPV6_CHARS:
                    break
                cands.append(run[start : p + 2])  # the prefix up to and including this `::`
                nxt = doubles[k + 1] if k + 1 < len(doubles) else len(run)
                if nxt - start <= _MAX_IPV6_CHARS:
                    cands.append(run[start:nxt].rstrip(".:"))  # and the hextets directly after it
            for cand in dict.fromkeys(cands):
                if not cand or cand.startswith(".") or cand.strip(":") == "":
                    continue
                at = cand.find("::")
                if at >= 0:
                    after = cand[at + 2 :]
                    strict = _is_scope(text, match.start() + start + at + 2, cand[:at])
                    if (not after or strict) and _hextets_before(cand, at) < 2:
                        continue
                try:
                    ipaddress.IPv6Address(cand)
                except ValueError:
                    continue
                return True
    return False


def _entries(deny: Sequence[str | DenyEntry]) -> list[DenyEntry]:
    """Plain strings (the API used by tests) become entries numbered by position; empty squashed values are skipped."""
    rows = [x if isinstance(x, DenyEntry) else DenyEntry(f"#{i}", _squash(x)) for i, x in enumerate(deny, 1)]
    return [x for x in rows if x.squashed]


def _deny_reasons(parts: Sequence[str], deny: Sequence[str | DenyEntry]) -> list[str]:
    """Reasons for each deny entry found in the squashed form of the parts joined with nothing between them.

    The squashed form drops every character that is not an ASCII letter or digit, so a value split by spacing,
    punctuation, Markdown, zero-width characters or a line break is still found. A reason holds the entry label only.
    """
    squashed = "".join(_squash(p) for p in parts)
    return [f"{_DENY_MARK} {e.label}" for e in _entries(deny) if e.squashed in squashed]


def _is_allowed(token: str, allow: set[str]) -> bool:
    base = token.split("-", 1)[0]  # an SSID suffix does not change the callsign
    return base in _BUILTIN_ALLOWED or base.upper() in allow


def _single_checks(text: str, allow: Sequence[str], charset: bool) -> list[str]:
    ok = {w.upper() for w in allow}
    why: list[str] = []
    if charset and _has_unusual_characters(text):
        why.append("unusual characters found (combining, invisible, bidi, tag, private-use or a non-ASCII space)")
    if charset and not _skeleton(text)[1]:
        why.append(_NO_REDUCE)
    if _has_md_link(text):
        why.append("markdown links are not allowed in drafts; write the URL plainly")
    if _has_html(text):
        why.append("HTML is not allowed in drafts; use plain markdown")
    if any(c in text for c in EM_DASHES):
        why.append("em dash found (use a comma, colon or hyphen)")
    if _IPV4.search(text) or _has_ipv6(text):
        why.append("IP address found")
    if _has_private_host(text):
        why.append("hostname found")
    if _SERIAL.search(text):
        why.append("serial number found")
    shaped = _UUID.sub(" ", text)
    calls = [m for m in _CALLSIGN.findall(shaped) + _CALLSIGN_CTX.findall(shaped) if not _is_allowed(m, ok)]
    grids = [
        m for m in _GRID6.findall(shaped) + _GRID4.findall(shaped) + _GRID_CTX.findall(shaped) if not _is_allowed(m, ok)
    ]
    if calls:
        why.append("amateur radio callsign pattern found (use N0CALL; SAFO_DRAFT_ALLOW lists exceptions)")
    if grids:
        why.append("grid square found (use FN31pr; SAFO_DRAFT_ALLOW lists exceptions)")
    if _has_session_url(text):
        why.append("claude.ai session URL found")
    if _SESSION_TRAILER.search(text):
        why.append("Claude-Session trailer found")
    return why


def _generic_checks(text: str, allow: Sequence[str]) -> list[str]:
    """Checks for any text that gets published. Every check runs on the raw text and on its canonical form."""
    why = _single_checks(text, allow, True)
    canon = canonicalize(text)
    if canon != text:
        why += [x for x in _single_checks(canon, allow, False) if x not in why]
    return why


def check_title(title: str, deny: Sequence[str | DenyEntry] = (), allow: Sequence[str] = ()) -> list[str]:
    if len(title) > MAX_TITLE_CHARS:
        return [f"title: title too long to check safely (limit {MAX_TITLE_CHARS} characters)"]
    return [f"title: {x}" for x in _generic_checks(title, allow) + _deny_reasons([title], deny)]


def check_text(kind: str, text: str, deny: Sequence[str | DenyEntry] = (), allow: Sequence[str] = ()) -> list[str]:
    """The reasons a draft may not be filed. An empty list means it passed."""
    if len(text) > MAX_CHECK_CHARS:
        return [f"text too long to check safely (limit {MAX_CHECK_CHARS} characters)"]
    why = _generic_checks(text, allow) + _deny_reasons([text], deny)
    if kind == "pr":
        lines = [x for x in text.splitlines() if x.strip()]
        if not lines or lines[-1].strip() != PR_FOOTER:
            why.append(f"pull request body must end with the exact line: {PR_FOOTER}")
    if kind == "issue" and not _EPIC.search(text):
        why.append("issue needs an 'Epic:' or 'Part of epic #N' line (pass --epic N)")
    return why


def check_draft(
    kind: str,
    title: str | None,
    body: str,
    deny: Sequence[str | DenyEntry] = (),
    allow: Sequence[str] = (),
) -> list[str]:
    """All reasons a draft may not be filed: the body, the title, and the title and body read together."""
    why = check_text(kind, body, deny, allow)
    if title is None:
        return why
    why += check_title(title, deny, allow)
    if len(title) > MAX_TITLE_CHARS or len(body) > MAX_CHECK_CHARS:
        return why  # the combined checks would run on an unbounded text
    seen = {x.removeprefix("title: ") for x in why}
    combined = [x for joiner in ("\n", "") for x in _generic_checks(f"{title}{joiner}{body}", allow)]
    for x in combined + _deny_reasons([title, body], deny):
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
    deny, allow = load_deny(ctx.env, ctx.err), allow_words(ctx.env)  # a config error stops the run before any call
    facts = _read_facts(args.facts, ctx.stdin)
    if not args.prompt and not facts:
        raise Failure("give a short prompt or --facts FILE", EXIT_ERROR)
    prompt = f"{_INSTRUCTIONS[kind]}\n\nRequest: {args.prompt or ''}\n\nFacts:\n{facts}"
    model = args.model or (LONG_MODEL if len(prompt) - len(_INSTRUCTIONS[kind]) > LONG_INPUT else SHORT_MODEL)
    ctx.model, ctx.chars_in = model, len(prompt)
    if kind != "comment" and len(args.title) > MAX_TITLE_CHARS:  # refused before any model call; never echo the title
        raise Failure(
            f"title too long: {len(args.title)} characters, the limit is {MAX_TITLE_CHARS}. "
            "This is a local input error; use a shorter title. Nothing was filed.",
            EXIT_ERROR,
        )
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
    why = check_draft(kind, None if kind == "comment" else args.title, body, deny, allow)
    if any(_DENY_MARK in x for x in why):
        ctx.out.write(f"--- draft {kind} withheld: it matched a private deny entry ---\n")  # never echo the value
    else:
        ctx.out.write(f"--- draft {kind} ---\n{body}\n--- end draft ---\n")
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
        self, env: Mapping[str, str], out: TextIO, err: TextIO, stdin: TextIO, sleep: Callable[[float], None], sub: str
    ) -> None:
        self.env, self.out, self.err, self.stdin, self.sleep, self.sub = env, out, err, stdin, sleep, sub
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
    ctx = Ctx(env, out, err, stdin, sleep, args.cmd)
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
