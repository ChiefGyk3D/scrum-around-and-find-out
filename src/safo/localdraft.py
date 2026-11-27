# SPDX-License-Identifier: Apache-2.0
"""safo-draft: the local-first path made the easy path (issue #482). A wrapper beside `safo-file` and `safo-card`.

    safo-draft issue   --repo o/r --title T [--epic N] [--facts FILE] [--yes] [PROMPT]
    safo-draft pr      --repo o/r --title T [--head B] [--base B] [--facts FILE] [--yes] [PROMPT]
    safo-draft comment --repo o/r --number N [--facts FILE] [--yes] [PROMPT]
    safo-draft digest ci-log [FILE|-]
    safo-draft digest board-drift [FILE|-]
    safo-draft --report
    safo-draft --outcome ID fact-error

`issue`, `pr` and `comment` write a draft with `llm-local` (stdin is /dev/null, since llm-local hangs on an open
stdin), print it, run the checks in `check_text`, and file it with `gh` only after a yes (`--yes` for non-interactive
use; the draft is still printed). A draft that fails a check is printed with the reasons and never filed, even with
`--yes`. `digest` groups and counts in code and sends only the grouped lines to the model for a five-line summary.

Every call appends one JSON line (no content) to `$XDG_STATE_HOME/safo/local-share.jsonl` (default
`~/.local/state/safo/`) with the llm-local call id, the project and, for drafts, the outcome (accepted, rewritten,
discarded; best effort via `llm-local --outcome`, issue #505); `--report` prints counts and outcome rates per ISO week.
Exit 75 from llm-local (queue busy) is retried with
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
import contextlib
import dataclasses
import datetime as dt
import ipaddress
import itertools
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TextIO

from safo import bounded

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
NO_ID = "none"
OUTCOMES = ("accepted", "rewritten", "discarded", "fact-error")
DRAFT_SUBS = ("issue", "pr", "comment")
OUTCOME_TIMEOUT = 30
_CALL_ID = re.compile(r"^llm-local: call id ([A-Za-z0-9][A-Za-z0-9_.-]{0,63})[ \t]*$", re.MULTILINE)
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9_.-]{1,100}")
_REMOTE = re.compile(r"[:/]([A-Za-z0-9][A-Za-z0-9_.-]{0,99})/([A-Za-z0-9_.-]{1,100}?)(?:\.git)?/?$")
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
# shape of a callsign or grid is blocked; contrib/draft-allow.example.txt lists tech tokens to copy into an allow file.
_BUILTIN_ALLOWED = frozenset({"N0CALL", "N0TST", "FN31pr"})
_CALL_SHAPE = r"[A-Z]{1,2}[0-9][A-Z]{1,3}"
_EDGE_BEFORE = r"(?<![A-Za-z0-9])"  # hyphen and underscore are separators, not token characters
_EDGE_AFTER = r"(?![A-Za-z0-9])"
# any case, no cue needed; a hyphen is a separator, so `W1AW-7` (an SSID) is found as `W1AW` and `N0TST-7` as `N0TST`
_CALLSIGN = re.compile(rf"{_EDGE_BEFORE}{_CALL_SHAPE}{_EDGE_AFTER}", re.IGNORECASE)
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
_NO_REDUCE = (
    "characters that cannot be reduced to ASCII (line {n}): remove emoji and other symbols, or use only the "
    "allowed pictographs listed in docs/local-draft.md"
)
_UNUSUAL = (
    "unusual or invisible characters (line {n}): remove them (a stray variation selector, zero-width or "
    "combining character)"
)
_VARIATION_SELECTOR = chr(0xFE0F)
_TOUCH = "a look-alike symbol touches a letter or digit (line {n}): write the letter or leave a space"
MAX_EXPANDED_CHARS = 4 * MAX_CHECK_CHARS  # NFKC can expand one character into 18; a longer form is refused unchecked
_TOO_LONG = f"draft too long to check safely (limit {MAX_CHECK_CHARS} characters, or {MAX_EXPANDED_CHARS} after NFKC)"
_UNCHECKED = "too long to check safely"
_NO_REDUCE_CONFIG = "a deny value holds characters that cannot be reduced to ASCII"
_NO_DENY_NOTE = "safo-draft: no private deny file configured: only heuristics are active"
_EMPTY_DENY_NOTE = "safo-draft: deny file has no entries: only heuristics are active"
_INLINE_COMMENT = re.compile(r"\s+#.*$")  # a hash preceded by whitespace starts a comment; `a#b` keeps its hash
# a deny entry that squashes to one of these would block ordinary text; load_deny warns (line number only)
_COMMON_WORDS = frozenset(
    [
        "about",
        "admin",
        "after",
        "all",
        "and",
        "any",
        "are",
        "area",
        "base",
        "because",
        "been",
        "before",
        "being",
        "boy",
        "but",
        "can",
        "case",
        "city",
        "client",
        "club",
        "code",
        "come",
        "company",
        "could",
        "data",
        "day",
        "default",
        "demo",
        "did",
        "door",
        "east",
        "example",
        "face",
        "fact",
        "file",
        "first",
        "for",
        "from",
        "game",
        "get",
        "girl",
        "good",
        "great",
        "group",
        "had",
        "hand",
        "has",
        "have",
        "head",
        "help",
        "her",
        "here",
        "high",
        "him",
        "his",
        "hold",
        "home",
        "host",
        "house",
        "how",
        "idea",
        "info",
        "item",
        "its",
        "just",
        "kind",
        "know",
        "large",
        "last",
        "left",
        "let",
        "life",
        "like",
        "line",
        "list",
        "little",
        "local",
        "long",
        "look",
        "love",
        "main",
        "make",
        "man",
        "many",
        "mind",
        "money",
        "more",
        "move",
        "much",
        "name",
        "never",
        "new",
        "next",
        "not",
        "note",
        "now",
        "number",
        "office",
        "old",
        "one",
        "only",
        "open",
        "other",
        "our",
        "out",
        "over",
        "page",
        "part",
        "past",
        "place",
        "plan",
        "play",
        "point",
        "power",
        "private",
        "project",
        "public",
        "put",
        "real",
        "rest",
        "right",
        "road",
        "room",
        "root",
        "rule",
        "sample",
        "say",
        "school",
        "see",
        "server",
        "service",
        "she",
        "should",
        "side",
        "site",
        "small",
        "some",
        "state",
        "stay",
        "stop",
        "such",
        "system",
        "take",
        "team",
        "tell",
        "temp",
        "term",
        "test",
        "text",
        "than",
        "that",
        "the",
        "their",
        "them",
        "there",
        "these",
        "they",
        "this",
        "those",
        "time",
        "too",
        "town",
        "tree",
        "turn",
        "two",
        "type",
        "under",
        "use",
        "user",
        "value",
        "very",
        "view",
        "walk",
        "wall",
        "want",
        "was",
        "water",
        "way",
        "week",
        "well",
        "were",
        "west",
        "what",
        "when",
        "where",
        "which",
        "while",
        "who",
        "wife",
        "will",
        "wind",
        "wish",
        "with",
        "word",
        "work",
        "world",
        "would",
        "year",
        "you",
        "your",
        "zone",
    ]
)


@dataclasses.dataclass(frozen=True)
class DenyEntry:
    """A private value, squashed. `label` names it in a reason (`#4` is line 4 of the file); the value is not kept."""

    label: str
    squashed: str
    dropped: str = ""  # the squashed value with look-alike symbols removed, when that differs from `squashed`


_TYPOGRAPHY = frozenset(chr(c) for c in (*range(0x2018, 0x201E), 0x2013, 0x2022, 0x2026, 0xD7, *range(0x2190, 0x2194)))


# The pictographs a draft may hold, and nothing else outside typography. Each is named; none may show a letter or a
# digit in its picture or its Unicode name. Add one only with a test that its name has no letter or digit.
_PICTOGRAPHS = frozenset(
    chr(c)
    for c in (
        0x2714,  # heavy check mark
        0x2705,  # white heavy check mark
        0x274C,  # cross mark (an x in the skeleton)
        0x26A0,  # warning sign
        0x1F680,  # rocket
        0x1F916,  # robot face (the pull request footer)
        0x1F440,  # eyes
        0x1F44D,  # thumbs up
        0x1F44E,  # thumbs down
        0x1F389,  # party popper
        0x1F527,  # wrench
        0x1F528,  # hammer
        0x1F41B,  # bug
        0x1F512,  # locked
        0x1F511,  # key
        0x1F525,  # fire
        0x2728,  # sparkles
        0x2757,  # heavy exclamation mark symbol
        0x1F4A1,  # electric light bulb
        0x1F4DD,  # memo
        0x1F4E6,  # package
        0x1F4DA,  # books
        0x231B,  # hourglass
        0x23F1,  # stopwatch
        0x27A1,  # black rightwards arrow
        0x2B06,  # upwards black arrow
        0x2B07,  # downwards black arrow
        0x1F4CB,  # clipboard
        0x1F4CC,  # pushpin
        0x1F50D,  # left-pointing magnifying glass
        0x2699,  # gear
        0x1F6E1,  # shield
        0x1F914,  # thinking face
        0x1F44B,  # waving hand
        0x1F64F,  # folded hands
        0x1F44F,  # clapping hands
        0x1F534,  # large red circle (an o in the skeleton)
        0x1F7E2,  # large green circle (an o in the skeleton)
        0x1F7E1,  # large yellow circle (an o in the skeleton)
        0x2B50,  # white medium star
        0x2795,  # heavy plus sign
        0x1F3AF,  # direct hit (target)
        0x1F4CA,  # bar chart
        0x1F6A8,  # police car light
        0x1F9EA,  # test tube
    )
)
# Left out on purpose: the link symbol U+1F517 (not on the owner list) and hundred points U+1F4AF (it shows digits).
# Characters that read as a letter in the skeleton: the multiplication sign and the cross mark look like `x`, the
# colored circles like `o`.
_LOOKS_LIKE = {chr(0xD7): "x", chr(0x274C): "x", chr(0x1F534): "o", chr(0x1F7E2): "o", chr(0x1F7E1): "o"}


def _allowed_symbol(c: str) -> bool:
    """Typographic punctuation and the explicit pictograph list: kept in a draft, nothing else. A variation selector
    is not on the list; `_strip_selector` removes the one that follows a pictograph."""
    return c in _TYPOGRAPHY or c in _PICTOGRAPHS


def _strip_selector(text: str) -> str:
    """Remove each U+FE0F that directly follows an allowed pictograph (the rendering form of the emoji). One after
    anything else, a second in a row, or at the start stays, so the checks refuse it as an unusual character."""
    out: list[str] = []
    prev = ""
    for c in text:
        if not (c == _VARIATION_SELECTOR and prev in _PICTOGRAPHS):
            out.append(c)
        prev = c
    return "".join(out)


def _skeleton(text: str, letters: bool = True) -> tuple[str, bool]:
    """(ASCII skeleton, reducible). NFKC, then NFKD with combining marks removed. Every non-ASCII character must
    either reduce to printable ASCII (a precomposed accent: U+00E9 becomes `e`) or be on the typography and emoji
    allowlist (`_allowed_symbol`; a few read as a letter, see `_LOOKS_LIKE`). Anything else (Cyrillic, Greek, dotless
    i, small capitals, letterlike or operator lookalikes, currency signs, modifier letters) makes the text not
    reducible; it is left out of the skeleton and the caller must refuse. With `letters` false the look-alike
    symbols are dropped instead of read as a letter (the other reading a person may take)."""
    out: list[str] = []
    reducible = True
    for c in unicodedata.normalize("NFKC", _strip_selector(text)):
        if c in _LOOKS_LIKE:
            if letters:
                out.append(_LOOKS_LIKE[c])
            continue
        if c.isascii():
            out.append(c)
            continue
        base = "".join(x for x in unicodedata.normalize("NFKD", c) if not unicodedata.combining(x))
        if base and base.isascii() and base.isprintable():
            out.append(base)
        elif not _allowed_symbol(c):
            reducible = False
    return "".join(out), reducible


def _ascii_alnum(c: str) -> bool:
    """Whether a character is, or reduces to, an ASCII letter or digit (so `é` counts as an `e`)."""
    if c.isascii():
        return c.isalnum()
    return any(x.isascii() and x.isalnum() for x in unicodedata.normalize("NFKD", c))


def _touch_line(text: str) -> int:
    """Line of the first look-alike symbol that touches a letter or digit on either side, or 0 for none. A symbol
    that touches one is read two ways (`x` or nothing) and so cannot be told from a letter in a token."""
    plain = _strip_selector(text)
    for i, c in enumerate(plain):
        if c in _LOOKS_LIKE and (
            (i > 0 and _ascii_alnum(plain[i - 1])) or (i + 1 < len(plain) and _ascii_alnum(plain[i + 1]))
        ):
            return _line_at(plain, i)
    return 0


def _expands(text: str) -> bool:
    """Whether the NFKC form of a text is longer than the checks may scan."""
    return len(unicodedata.normalize("NFKC", text)) > MAX_EXPANDED_CHARS


def _squash(text: str, letters: bool = True) -> str:
    """The ASCII skeleton, lowercase, only letters and digits kept: `Ac**me** Corp` and `A-c-m-e corp` squash alike."""
    return re.sub(r"[^a-z0-9]", "", _skeleton(text, letters)[0].lower())


def _deny_entry(label: str, value: str) -> DenyEntry:
    """A deny entry in both readings of the look-alike symbols; the second form is kept only when it differs and is
    long enough to be safe."""
    squashed, dropped = _squash(value), _squash(value, False)
    return DenyEntry(label, squashed, dropped if dropped != squashed and len(dropped) >= MIN_DENY_CHARS else "")


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
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise Failure(f"{what} is group or world writable; run chmod go-w on it", EXIT_ERROR)
        data = handle.read(MAX_CONFIG_BYTES + 1)
    if len(data) > MAX_CONFIG_BYTES:
        raise Failure(f"{what} is larger than {MAX_CONFIG_BYTES} bytes", EXIT_ERROR)
    return data.decode("utf-8", errors="replace")


def _config_lines(text: str) -> list[tuple[int, str]]:
    """(line number, value) for each line that is not blank and does not start with `#`.

    A hash preceded by whitespace starts an inline comment, removed with the whitespace before it.
    """
    rows = [(n, line.strip()) for n, line in enumerate(text.splitlines(), 1)]
    rows = [(n, line) for n, line in rows if line and not line.startswith("#")]
    return [(n, stripped) for n, line in rows if (stripped := _INLINE_COMMENT.sub("", line).strip())]


def load_deny(env: Mapping[str, str], err: TextIO) -> list[DenyEntry]:
    """The private deny entries: the file (default ~/.config/safo/draft-deny) and the comma separated SAFO_DRAFT_DENY.

    A value that squashes to fewer than MIN_DENY_CHARS characters is a config error naming the line, not the value.
    A missing default file is noted once on `err` unless SAFO_DRAFT_DENY supplies an entry; a file named by
    SAFO_DRAFT_DENY_FILE that is missing is an error.
    """
    entries: list[DenyEntry] = []
    file_missing = False
    explicit = env.get("SAFO_DRAFT_DENY_FILE")
    path = explicit or str(Path(env.get("HOME", str(Path.home()))) / ".config" / "safo" / "draft-deny")
    text = _read_private_file(path, "SAFO_DRAFT_DENY_FILE")
    if text is None:
        if explicit:
            raise Failure("SAFO_DRAFT_DENY_FILE names a file that was not found", EXIT_ERROR)
        file_missing = True
    else:
        rows = _config_lines(text)
        if not rows:
            if explicit:
                raise Failure("SAFO_DRAFT_DENY_FILE has no entries", EXIT_ERROR)
            err.write(_EMPTY_DENY_NOTE + "\n")
        common: list[int] = []
        for n, value in rows:
            squashed = _squash(value)
            if squashed in _COMMON_WORDS:
                common.append(n)
            if not _skeleton(value)[1]:
                raise Failure(f"SAFO_DRAFT_DENY_FILE line {n}: {_NO_REDUCE_CONFIG}", EXIT_ERROR)
            if len(squashed) < MIN_DENY_CHARS:
                raise Failure(
                    f"SAFO_DRAFT_DENY_FILE line {n}: a deny value needs at least {MIN_DENY_CHARS} letters or digits",
                    EXIT_ERROR,
                )
            entries.append(_deny_entry(f"#{n}", value))
        if common:
            lines = ", ".join(str(n) for n in common)
            err.write(
                f"safo-draft: deny file {'line' if len(common) == 1 else 'lines'} {lines}: "
                "a very common English word that will block ordinary text\n"
            )
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
        entries.append(_deny_entry(f"SAFO_DRAFT_DENY#{i}", value))
    if file_missing and not entries:
        err.write(_NO_DENY_NOTE + "\n")  # only when neither the file nor the env list supplies an entry
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
    HTML is not decoded or stripped: a draft that holds any is refused by `_html_line`.
    """
    return _MD_PUNCT.sub("", unicodedata.normalize("NFKC", text))


def _line_at(text: str, pos: int) -> int:
    """The 1-based line number of offset `pos`, counted the way `str.splitlines` splits."""
    return len((text[:pos] + "x").splitlines())


def _first_line(text: str, bad: Callable[[str], bool]) -> int:
    """The first line for which `bad` holds, or 0 when none does."""
    return next((n for n, line in enumerate(text.splitlines(), 1) if bad(line)), 0)


def _unusual_line(text: str) -> int:
    """Line of the first unusual character, or 0 for none. A character that only shows on the whole text is line 1."""
    return _first_line(text, _is_unusual) or (1 if _is_unusual(text) else 0)


def _unreducible_line(text: str) -> int:
    """Line of the first character that cannot be reduced to ASCII, or 0 for none."""
    if _skeleton(text)[1]:
        return 0
    return _first_line(text, lambda line: not _skeleton(line)[1]) or 1


def _is_unusual(text: str) -> bool:
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


def _html_line(text: str) -> int:
    """Line of the first HTML tag, comment, declaration or character reference, or 0 for none."""
    hits = [m.start() for m in (_HTML_START.search(text), _HTML_REF.search(text)) if m]
    return _line_at(text, min(hits)) if hits else 0


def _md_link_line(text: str) -> int:
    """Line of the first inline link, image (`](`, `![`) or reference use (`][`), or 0. The PR footer is exempt."""
    text = text.replace(PR_FOOTER, "")  # the footer is one line, so line numbers do not move
    hits = [at for mark in ("](", "![", "][") if (at := text.find(mark)) >= 0]
    return _line_at(text, min(hits)) if hits else 0


def _para_refdef_at(para: str) -> int:
    """Broad on purpose, no parsing: the offset of the `]:` when a `[` is followed anywhere later by `]:`, or when an
    escaped bracket (backslash then `[` or `]`) is followed by a later `]:` (an escaped `]` can sit before the first
    `[`); -1 for none. Only `str.find`, so linear."""
    first = para.find("[")
    if first >= 0 and (at := para.find("]:", first + 1)) >= 0:
        return at
    for esc in ("\\[", "\\]"):
        start = para.find(esc)
        if start >= 0 and (at := para.find("]:", start)) >= 0:
            return at
    return -1


def _md_refdef_line(text: str) -> int:
    """Line of the `]:` in the first paragraph (blank lines separate them) that can hold a reference definition, or 0.
    A paragraph with a `]:` and no earlier `[` or escaped bracket is allowed (`ok]: fine`). Over-blocks prose such as
    `the range is [0, 5]: inclusive` and `arr[0]: the first`; that is the safe side. The exact PR footer is exempt."""
    text = text.replace(PR_FOOTER, "")
    para: list[str] = []
    start = 0
    for n, line in enumerate([*text.splitlines(), ""], 1):
        if line.strip():
            if not para:
                start = n
            para.append(line)
        else:
            if para:
                joined = "\n".join(para)
                at = _para_refdef_at(joined)
                if at >= 0:
                    return start + joined.count("\n", 0, at)
            para = []
    return 0


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
_MAX_IPV6_COLONS = 8  # `1:2:3:4:5:6:7::` and `::2:3:4:5:6:7:8` hold 8, the most any valid address has


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
        colons = [0, *itertools.accumulate(ch == ":" for ch in run)]  # colons[i]: colons in run[:i]
        for start in starts:
            if run.startswith(":::", start):
                continue  # no address starts with three colons, and a long colon run would repeat this work per colon
            cands = []
            if end - start <= _MAX_IPV6_CHARS:
                cands.append(run[start:end])
                if run.startswith("::", end) and end > 0:
                    cands.append(run[start : end + 2])
            first = bisect.bisect_left(doubles, start)
            for k in range(first, len(doubles)):
                p = doubles[k]
                if p + 2 - start > _MAX_IPV6_CHARS or colons[p + 2] - colons[start] > _MAX_IPV6_COLONS:
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
    rows = [x if isinstance(x, DenyEntry) else _deny_entry(f"#{i}", x) for i, x in enumerate(deny, 1)]
    return [x for x in rows if x.squashed]


def _bounded_squash(text: str) -> tuple[str, str]:
    """Two squashes that never expand: the ASCII letters and digits of the raw source, and the skeleton squash only
    when the source is within the cap and its NFKC form stays within the expansion cap (else the raw one again)."""
    raw = re.sub(r"[^a-z0-9]", "", "".join(c for c in text if c.isascii()).lower())
    if len(text) > MAX_CHECK_CHARS or _expands(text):
        return raw, raw
    return raw, _squash(text)


def _bounded_deny_reasons(parts: Sequence[str], deny: Sequence[str | DenyEntry]) -> list[str]:
    """Deny matching for a text that is too long to check fully: only the bounded source forms are searched, so a
    private value written in plain ASCII is still named (the draft is withheld either way)."""
    pairs = [_bounded_squash(p) for p in parts]
    forms = ["".join(x[0] for x in pairs), "".join(x[1] for x in pairs)]
    return [
        f"{_DENY_MARK} {e.label}"
        for e in _entries(deny)
        if any(v and v in f for v in (e.squashed, e.dropped) for f in forms)
    ]


def _deny_reasons(parts: Sequence[str], deny: Sequence[str | DenyEntry]) -> list[str]:
    """Reasons for each deny entry found in the squashed form of the parts joined with nothing between them.

    The squashed form drops every character that is not an ASCII letter or digit, so a value split by spacing,
    punctuation, Markdown, zero-width characters or a line break is still found. A reason holds the entry label only.
    """
    forms = ["".join(_squash(p, letters) for p in parts) for letters in (True, False)]
    return [
        f"{_DENY_MARK} {e.label}"
        for e in _entries(deny)
        if any(v and v in f for v in (e.squashed, e.dropped) for f in forms)
    ]


def _is_allowed(token: str, allow: set[str]) -> bool:
    return token in _BUILTIN_ALLOWED or token.upper() in allow


def _single_checks(text: str, allow: Sequence[str], charset: bool) -> list[str]:
    ok = {w.upper() for w in allow}
    why: list[str] = []
    text = _strip_selector(text)
    if charset and (n := _unusual_line(text)):
        why.append(_UNUSUAL.format(n=n))
    if charset and (n := _unreducible_line(text)):
        why.append(_NO_REDUCE.format(n=n))
    if n := _md_link_line(text):
        why.append(f"markdown links are not allowed in drafts (line {n}): write the URL plainly.")
    if n := _md_refdef_line(text):
        why.append(
            "markdown reference definitions are not allowed in drafts: a `[` followed later by `]:` in the same "
            f"paragraph (line {n}). Reword it, put the text in a code span without brackets, or split the "
            "paragraph; write URLs plainly."
        )
    if n := _html_line(text):
        why.append(
            f"HTML is not allowed in drafts (line {n}): remove the angle-bracket text; write `{{name}}` instead of "
            "`<name>`; a pasted traceback with `<module>` must be rewritten without the angle brackets."
        )
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
    """Checks for any text that gets published. Every heuristic runs on four texts: the raw text, its canonical form,
    and the ASCII skeleton of the canonical form read two ways (a look-alike symbol as a letter, and dropped). A reason
    is reported once by class."""
    why = _single_checks(text, allow, True)
    canon = canonicalize(text)
    if n := _touch_line(canon):
        why.append(_TOUCH.format(n=n))
    seen = {_reason_class(x) for x in why}
    others = [canon] if canon != text else []
    bare = canon.replace(PR_FOOTER, "")  # the exact footer is exempt; its emoji would not survive the skeleton
    for letters in (True, False):
        form = _skeleton(bare, letters)[0]
        if form not in (text, *others):  # a text already scanned is not scanned again
            others.append(form)
    for other in others:
        for x in _single_checks(other, allow, False):
            if (cls := _reason_class(x)) not in seen:
                seen.add(cls)
                why.append(x)
    return why


def check_title(title: str, deny: Sequence[str | DenyEntry] = (), allow: Sequence[str] = ()) -> list[str]:
    if len(title) > MAX_TITLE_CHARS:
        return [f"title: title too long to check safely (limit {MAX_TITLE_CHARS} characters)"] + [
            f"title: {x}" for x in _bounded_deny_reasons([title], deny)
        ]
    return [f"title: {x}" for x in _generic_checks(title, allow) + _deny_reasons([title], deny)]


def check_text(kind: str, text: str, deny: Sequence[str | DenyEntry] = (), allow: Sequence[str] = ()) -> list[str]:
    """The reasons a draft may not be filed. An empty list means it passed."""
    if len(text) > MAX_CHECK_CHARS:
        return [
            f"text too long to check safely (limit {MAX_CHECK_CHARS} characters)",
            *_bounded_deny_reasons([text], deny),
        ]
    if _expands(text):
        return [_TOO_LONG, *_bounded_deny_reasons([text], deny)]
    why = _generic_checks(text, allow) + _deny_reasons([text], deny)
    if kind == "pr":
        lines = [x for x in text.splitlines() if x.strip()]
        if not lines or lines[-1].strip() != PR_FOOTER:
            why.append(f"pull request body must end with the exact line: {PR_FOOTER}")
    if kind == "issue" and not _EPIC.search(text):
        why.append("issue needs an 'Epic:' or 'Part of epic #N' line (pass --epic N)")
    return why


def _reason_class(reason: str) -> str:
    """A reason without its line number: the same refusal found in the body, the title or the join is one reason."""
    return re.sub(r"\s*\(line \d+\)", "", reason)


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
    if len(title) > MAX_TITLE_CHARS or len(body) > MAX_CHECK_CHARS or _expands(body):
        # the combined checks would run on an unbounded text; only the bounded deny match runs
        seen = {_reason_class(x.removeprefix("title: ")) for x in why}
        return why + [
            f"title and body combined: {x}" for x in _bounded_deny_reasons([title, body], deny) if x not in seen
        ]
    seen = {_reason_class(x.removeprefix("title: ")) for x in why}
    combined = [x for joiner in ("\n", "") for x in _generic_checks(f"{title}{joiner}{body}", allow)]
    for x in combined + _deny_reasons([title, body], deny):
        if (cls := _reason_class(x)) not in seen:
            seen.add(cls)
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


def _log_call(
    env: Mapping[str, str],
    now: dt.datetime,
    sub: str,
    model: str,
    code: int,
    n_in: int,
    n_out: int,
    extra: Mapping[str, object] | None = None,
) -> None:
    path = _state_path(env)
    row: dict[str, object] = {
        "ts": now.isoformat(),
        "subcommand": sub,
        "model": model,
        "exit": code,
        "chars_in": n_in,
        "chars_out": n_out,
    }
    row.update(extra or {})
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=stat.S_IRWXU)
        info = path.parent.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid():
            return  # a symlinked or foreign state directory is never written or chmodded
        path.parent.chmod(stat.S_IRWXU)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "a") as handle:
            os.fchmod(handle.fileno(), stat.S_IRUSR | stat.S_IWUSR)
            handle.write(json.dumps(row) + "\n")
    except OSError:
        pass  # metrics must never block the work


def _pct(n: int, total: int) -> str:
    return f"{round(100 * n / total)}%" if total else "0%"


def _rates(counts: collections.Counter[str]) -> str:
    total = sum(counts[k] for k in (*OUTCOMES, NO_ID))
    return ", ".join(f"{k}={counts[k]} ({_pct(counts[k], total)})" for k in (*OUTCOMES, NO_ID))


def report(env: Mapping[str, str], out: TextIO) -> int:
    path = _state_path(env)
    rows: list[dict[str, object]] = []
    if path.is_file():
        for raw in path.read_text().splitlines():
            try:
                row = bounded.loads(raw)
                dt.datetime.fromisoformat(row["ts"]).isocalendar()
                str(row["subcommand"])
            except (ValueError, KeyError, TypeError):
                continue
            rows.append(row)
    marked = {str(r["call_id"]): str(r["outcome"]) for r in rows if r["subcommand"] == "outcome" and "call_id" in r}
    weeks: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
    results: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
    projects: dict[str, dict[str, collections.Counter[str]]] = collections.defaultdict(
        lambda: collections.defaultdict(collections.Counter)
    )
    unrecorded: collections.Counter[str] = collections.Counter()
    for row in rows:
        if row["subcommand"] == "outcome":
            continue  # a later human mark, applied to its draft below; not a model call
        year, wk, _ = dt.datetime.fromisoformat(str(row["ts"])).isocalendar()
        key = f"{year}-W{wk:02d}"
        weeks[key][str(row["subcommand"])] += 1
        weeks[key]["_failed"] += 1 if row.get("exit") != 0 else 0
        if "outcome" not in row:
            continue
        outcome = marked.get(str(row.get("call_id")), str(row["outcome"]))
        outcome = outcome if outcome in OUTCOMES else NO_ID
        results[key][outcome] += 1
        projects[key][str(row.get("project", NO_ID))][outcome] += 1
        unrecorded[key] += 1 if row.get("outcome_recorded") is False else 0
    if not weeks:
        out.write("no local calls recorded\n")
        return EXIT_OK
    for week in sorted(weeks):
        counts = weeks[week]
        failed = counts.pop("_failed", 0)
        detail = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        out.write(f"{week}: {sum(counts.values())} calls, {failed} failed ({detail})\n")
        if results[week]:
            drafts = sum(results[week].values())
            out.write(f"  outcomes of {drafts} drafts: {_rates(results[week])}\n")
            out.write(f"  outcome not recorded: {unrecorded[week]} of {drafts} ({_pct(unrecorded[week], drafts)})\n")
            for name in sorted(projects[week]):
                out.write(f"  project {name}: {_rates(projects[week][name])}\n")
    return EXIT_OK


def _which(env: Mapping[str, str], name: str) -> str:
    found = shutil.which(name, path=env.get("PATH", ""))
    if not found:
        raise Failure(f"{name} not found on PATH. {NOT_VERIFIED}", EXIT_ERROR)
    return found


def _spawn(
    argv: list[str], env: Mapping[str, str], timeout: float | None, body: str | None = None, *, tty: bool = False
) -> subprocess.CompletedProcess[str]:
    """The one place a child process is started: an argv list, no shell; stdin closed, a body, or the terminal."""
    return subprocess.run(  # noqa: S603 - argv list, absolute path from PATH lookup, no shell
        argv,
        input=body,
        stdin=None if body is not None or tty else subprocess.DEVNULL,
        capture_output=not tty,
        text=True,
        env=dict(env),
        check=False,
        timeout=timeout,
    )


def record_outcome(env: Mapping[str, str], call_id: str, outcome: str) -> bool:
    """Best effort `llm-local --outcome ID VALUE`. True only when llm-local exits 0; never raises."""
    if call_id == NO_ID or not _ID.fullmatch(call_id) or outcome not in OUTCOMES:
        return False
    try:
        return _spawn([_which(env, "llm-local"), "--outcome", call_id, outcome], env, OUTCOME_TIMEOUT).returncode == 0
    except (Failure, OSError, subprocess.SubprocessError):
        return False


def project_of(env: Mapping[str, str], repo: str | None) -> str:
    """owner/name from --repo, else from the cwd git remote; `none` when neither resolves. Never a path or URL."""
    if repo is not None:
        return repo if _REPO.fullmatch(repo) else NO_ID
    try:
        done = _spawn([_which(env, "git"), "-C", env.get("PWD") or os.getcwd(), "remote", "get-url", "origin"], env, 10)
    except (Failure, OSError, subprocess.SubprocessError):
        return NO_ID
    found = _REMOTE.search(done.stdout.strip()) if done.returncode == 0 else None
    return f"{found.group(1)}/{found.group(2)}" if found else NO_ID


def call_local(
    env: Mapping[str, str],
    sleep: Callable[[float], None],
    task: str,
    model: str,
    prompt: str,
    ids: list[str] | None = None,
) -> str:
    """Run llm-local. `ids` receives the call id of the attempt that produced the returned text (retries replace it)."""
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
            done = _spawn(argv, env, LLM_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise Failure(f"llm-local timed out after {LLM_TIMEOUT} s. {NOT_VERIFIED}", EXIT_TIMEOUT) from None
        if done.returncode == 0:
            found = _CALL_ID.findall(done.stderr or "")
            if ids is not None:
                ids[:] = [found[-1]] if found else []
            return done.stdout.strip()
        last = (done.stderr or done.stdout).strip()
        if done.returncode != EXIT_BUSY:
            raise Failure(f"llm-local failed (exit {done.returncode}): {last}\n{NOT_VERIFIED}", done.returncode)
        if attempt < RETRIES - 1:
            sleep(BACKOFF[min(attempt, len(BACKOFF) - 1)])
    raise Failure(f"llm-local queue still busy after {RETRIES} tries: {last}", EXIT_BUSY)


def _gh(env: Mapping[str, str], args: list[str], body: str) -> str:
    try:
        done = _spawn([_which(env, "gh"), *args, "--body-file", "-"], env, GH_TIMEOUT, body)
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


def _answer(args: argparse.Namespace, stdin: TextIO, out: TextIO) -> str:
    """`y` to file, `e` to edit first, anything else declines. `--yes` files without asking."""
    if args.yes:
        return "y"
    out.write("File this? [y/N/e to edit] ")
    out.flush()
    said = stdin.readline().strip().lower()
    return "y" if said in {"y", "yes"} else "e" if said in {"e", "edit"} else "n"


def _edit(body: str, ctx: Ctx) -> str:
    """Edit the draft in $VISUAL or $EDITOR; the temp copy is removed with its directory. Unchanged on failure."""
    editor = shlex.split(ctx.env.get("VISUAL") or ctx.env.get("EDITOR") or "")
    if not editor:
        ctx.err.write("safo-draft: note: no VISUAL or EDITOR set; nothing was edited\n")
        return body
    with tempfile.TemporaryDirectory(prefix="safo-draft-") as scratch:
        path = Path(scratch) / "draft.txt"
        path.write_text(body)
        try:
            done = _spawn([*editor, str(path)], ctx.env, None, tty=True)
        except OSError:
            ctx.err.write("safo-draft: note: the editor could not start; nothing was edited\n")
            return body
        if done.returncode != 0:
            ctx.err.write("safo-draft: note: the editor failed; nothing was edited\n")
            return body
        with open(path, "rb") as handle:  # bounded: check_draft refuses anything past its cap
            return handle.read(MAX_CHECK_CHARS * 4 + 1).decode("utf-8", errors="replace")


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
    ctx.project = project_of(ctx.env, args.repo)
    body = call_local(ctx.env, ctx.sleep, f"draft-{kind}", model, prompt, ctx.ids)
    ctx.drafted, ctx.chars_out = True, len(body)
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
    baseline = body  # the model output after the wrapper's own mechanical edits (footer, epic line)
    while True:
        why = check_draft(kind, None if kind == "comment" else args.title, body, deny, allow)
        unchecked = any(_UNCHECKED in x for x in why)
        if unchecked:  # fail closed: a draft that could not be fully checked is never echoed, nor any line number
            ctx.out.write(f"--- draft {kind} withheld: it could not be fully checked ---\n")
            why = [_reason_class(x) for x in why if _UNCHECKED in x or _DENY_MARK in x]
        elif any(_DENY_MARK in x for x in why):
            ctx.out.write(f"--- draft {kind} withheld: it matched a private deny entry ---\n")  # never echo the value
        else:
            ctx.out.write(f"--- draft {kind} ---\n{body}\n--- end draft ---\n")
        if why:
            ctx.out.write("NOT FILED. The draft failed these checks:\n" + "".join(f"  - {x}\n" for x in why))
            ctx.settle("discarded")
            return EXIT_REFUSED
        answer = _answer(args, ctx.stdin, ctx.out)
        if answer == "e":
            body = _edit(body, ctx)
            continue
        if answer != "y":
            ctx.out.write("not filed\n")
            ctx.settle("discarded")
            return EXIT_DECLINED
        break
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
    ctx.settle("accepted" if body == baseline else "rewritten")  # only after gh succeeded; never changes the exit code
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
    ctx.project = project_of(ctx.env, None)
    summary = call_local(ctx.env, ctx.sleep, ctx.sub, SHORT_MODEL, prompt, ctx.ids)
    ctx.chars_out = len(summary)
    ctx.out.write(f"--- summary (local model) ---\n{summary}\n")
    return EXIT_OK


class Ctx:
    def __init__(
        self, env: Mapping[str, str], out: TextIO, err: TextIO, stdin: TextIO, sleep: Callable[[float], None], sub: str
    ) -> None:
        self.env, self.out, self.err, self.stdin, self.sleep, self.sub = env, out, err, stdin, sleep, sub
        self.model, self.chars_in, self.chars_out = "", 0, 0
        self.ids: list[str] = []
        self.project = NO_ID
        self.drafted = False
        self.outcome, self.recorded = NO_ID, False

    @property
    def call_id(self) -> str:
        return self.ids[0] if self.ids else NO_ID

    def settle(self, outcome: str) -> None:
        """Record what happened to the draft. Best effort: a failure adds a counts-only note and nothing else."""
        self.outcome = outcome
        self.recorded = record_outcome(self.env, self.call_id, outcome)
        if not self.recorded:
            self.err.write("safo-draft: note: outcome not recorded (1 draft); the filing is unaffected\n")

    def row(self) -> dict[str, object]:
        extra: dict[str, object] = {"call_id": self.call_id, "project": self.project}
        if self.drafted:
            extra |= {"outcome": self.outcome, "outcome_recorded": self.recorded}
        return extra


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="safo-draft", description="local-first drafts and digests (llm-local)", epilog=EXIT_TABLE
    )
    p.add_argument("--report", action="store_true", help="print local-call counts per ISO week")
    p.add_argument(
        "--outcome", nargs=2, metavar=("ID", "fact-error"), help="mark a filed draft as having a fact error, later"
    )
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


def _mark(call_id: str, outcome: str, env: Mapping[str, str], err: TextIO, now: dt.datetime) -> int:
    """`safo-draft --outcome ID fact-error`: the one outcome only a human can set, after reading the filed text."""
    if outcome != "fact-error" or not _ID.fullmatch(call_id):
        err.write("safo-draft: --outcome takes a call id and the word fact-error (the others are set automatically)\n")
        return EXIT_ERROR
    ok = record_outcome(env, call_id, outcome)
    _log_call(
        env,
        now,
        "outcome",
        NO_ID,
        EXIT_OK if ok else EXIT_ERROR,
        0,
        0,
        {"call_id": call_id, "outcome": outcome, "outcome_recorded": ok},
    )
    if not ok:
        err.write("safo-draft: outcome not recorded by llm-local; the mark is kept in the local metrics file\n")
    return EXIT_OK if ok else EXIT_ERROR


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
        # argparse prints its usage and errors to the process streams; route them to the caller's streams.
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            args = parser().parse_args(list(argv))
    except SystemExit as stop:
        return int(stop.code) if isinstance(stop.code, int) else EXIT_ERROR
    if args.report:
        return report(env, out)
    if args.outcome:
        return _mark(args.outcome[0], args.outcome[1], env, err, now or dt.datetime.now(dt.UTC))
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
        _log_call(env, now or dt.datetime.now(dt.UTC), ctx.sub, ctx.model, code, ctx.chars_in, ctx.chars_out, ctx.row())
    return code


def entry() -> None:
    raise SystemExit(
        main(sys.argv[1:], env=os.environ, out=sys.stdout, err=sys.stderr, stdin=sys.stdin, sleep=time.sleep)
    )


if __name__ == "__main__":
    entry()
