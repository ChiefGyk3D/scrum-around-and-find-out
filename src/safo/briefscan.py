# SPDX-License-Identifier: Apache-2.0
"""safo-brief-scan: a secret and private-data scan for agent briefs and reports (#537).

    safo-brief-scan [FILE ...]     scan files, or stdin when no file (or `-`) is given
    safo-brief-scan --hook         read a Claude Code hook JSON document on stdin and scan its `tool_input`

Exit 0: nothing found. Exit 1: findings. Exit 2: the input could not be read or checked (fail closed). In `--hook`
mode a finding is exit 2 too, the code a hook uses to block a call. Findings go to stderr as `SOURCE:LINE: TYPE [hash]`;
the matched text is never printed. Design and limits: docs/brief-scan.md.

A separate entry point, not a `safo` subcommand: a subcommand would have to be added to the frozen guard's
`TOP_LEVEL_COMMANDS`. No network, no subprocess, nothing written.
"""

from __future__ import annotations

import hashlib
import os
import re
import sys
import unicodedata
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import BinaryIO, TextIO

from safo import bounded, localdraft
from safo.gemini import SECRET_SHAPES

MAX_BYTES = 1_048_576
MAX_PRINTED = 200
MIN_REASON = 8
EXIT_OK, EXIT_FOUND, EXIT_UNCHECKED = 0, 1, 2

_MARKER = re.compile(r"safo-scan-allow:(.*)$")
_TOKCLASS = r"[A-Za-z0-9._~+/=-]"
_BEARER = (
    re.compile(rf"(?i)\bauthorization\s*[:=]\s*(?:bearer|basic|token)\s+{_TOKCLASS}{{16,}}"),
    re.compile(rf"(?i)\bbearer\s+(?={_TOKCLASS}*\d){_TOKCLASS}{{24,}}"),
)
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
_ASSIGN = re.compile(
    r"(?i)(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)[\w-]{0,20}\s*[:=]\s*['\"]?"
    r"([A-Za-z0-9/+_.~=-]{16,})"
)

Finding = tuple[str, str]  # (type, hash tag or "-")


def _tag(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:6]


def _is_value(text: str) -> bool:
    """A real-looking value: letters and digits both present and more than a few distinct characters."""
    return len(set(text)) >= 6 and any(c.isdigit() for c in text) and any(c.isalpha() for c in text)


def _credentials(text: str) -> set[Finding]:
    found: set[Finding] = set()
    for shape in SECRET_SHAPES:
        found |= {("credential", _tag(m.group())) for m in shape.finditer(text)}
    for shape in _BEARER:
        found |= {("bearer", _tag(m.group())) for m in shape.finditer(text)}
    found |= {("jwt", _tag(m.group())) for m in _JWT.finditer(text)}
    found |= {("assignment", _tag(m.group(1))) for m in _ASSIGN.finditer(text) if _is_value(m.group(1))}
    return found


def _private(text: str, allow: set[str]) -> set[Finding]:
    """The private-data classes of safo-draft, by the same detectors. No hash: these values are easy to guess."""
    kinds: set[str] = set()
    if localdraft._IPV4.search(text) or localdraft._has_ipv6(text):
        kinds.add("ip-address")
    if localdraft._has_private_host(text):
        kinds.add("hostname")
    if localdraft._SERIAL.search(text):
        kinds.add("serial-number")
    shaped = localdraft._UUID.sub(" ", text)
    calls = localdraft._CALLSIGN.findall(shaped) + localdraft._CALLSIGN_CTX.findall(shaped)
    if any(not localdraft._is_allowed(m, allow) for m in calls):
        kinds.add("callsign")
    grids = localdraft._GRID6.findall(shaped) + localdraft._GRID4.findall(shaped) + localdraft._GRID_CTX.findall(shaped)
    if any(not localdraft._is_allowed(m, allow) for m in grids):
        kinds.add("grid-square")
    if localdraft._has_session_url(text):
        kinds.add("session-url")
    return {(k, "-") for k in kinds}


def _line_findings(text: str, allow: set[str], deny: Sequence[localdraft.DenyEntry]) -> set[Finding]:
    forms = [text]
    folded = unicodedata.normalize("NFKC", text)
    if folded != text:
        forms.append(folded)
    found: set[Finding] = set()
    for form in forms:
        found |= _credentials(form) | _private(form, allow)
        found |= {("deny-list " + r.rsplit(" ", 1)[1], "-") for r in localdraft._deny_reasons([form], deny)}
    return found


def scan_text(
    text: str, allow: set[str], deny: Sequence[localdraft.DenyEntry]
) -> tuple[list[tuple[int, str, str]], list[int]]:
    """Findings as (line, type, tag) in line order, and the lines on which a valid allow marker suppressed something."""
    rows: list[tuple[int, str, str]] = []
    allowed: list[int] = []
    for n, line in enumerate(text.splitlines(), 1):
        marker = _MARKER.search(line)
        if marker and len(marker.group(1).strip()) >= MIN_REASON:
            # the reason is text too: a credential in it is never suppressed
            found = _line_findings(line[: marker.start()], allow, deny)
            reason = marker.group(1)
            reason_found = _credentials(reason) | _credentials(unicodedata.normalize("NFKC", reason))
            rows += [(n, k, t) for k, t in sorted(reason_found)]
            allowed += [n] * len(found)
            continue
        found = _line_findings(line, allow, deny)
        if marker:
            found.add(("allow-marker-without-reason", "-"))
        rows += [(n, k, t) for k, t in sorted(found)]
    # a deny value split across lines is found only in the joined text
    seen = {k for _, k, _ in rows}
    rows += [
        (0, "deny-list " + r.rsplit(" ", 1)[1], "-")
        for r in localdraft._deny_reasons(text.splitlines(), deny)
        if "deny-list " + r.rsplit(" ", 1)[1] not in seen
    ]
    return rows, allowed


def _safe(label: str) -> str:
    """A label for the output: control, format and line-separator characters escaped, so untrusted JSON keys or file
    names cannot start a line or move the cursor in the diagnostic."""
    return "".join(c if unicodedata.category(c) not in ("Cc", "Cf", "Zl", "Zp") else f"\\u{ord(c):04x}" for c in label)


def _walk(node: object, label: str) -> Iterator[tuple[str, str]]:
    if isinstance(node, str):
        yield label, node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield from _walk(value, f"{label}.{_safe(str(key))}")
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from _walk(value, f"{label}[{i}]")


def _read_stdin(stdin: BinaryIO) -> bytes:
    return stdin.read(MAX_BYTES + 1)


def _sources(argv: Sequence[str], hook: bool, stdin: BinaryIO, err: TextIO) -> tuple[list[tuple[str, str]], bool]:
    """The (label, text) pairs to scan, and whether any input could not be read."""
    unreadable = False
    pairs: list[tuple[str, str]] = []
    if hook:
        raw = _read_stdin(stdin)
        if len(raw) > MAX_BYTES:
            err.write(f"safo-brief-scan: hook input over the {MAX_BYTES} byte limit\n")
            return [], True
        try:
            doc = bounded.loads(raw, MAX_BYTES)
        except ValueError:
            err.write("safo-brief-scan: hook input is not bounded, valid JSON\n")
            return [], True
        if not isinstance(doc, dict) or not isinstance(doc.get("tool_input"), dict):
            err.write("safo-brief-scan: hook input has no tool_input object\n")
            return [], True
        return list(_walk(doc["tool_input"], "tool_input")), False
    for name in argv or ["-"]:
        label = "<stdin>" if name == "-" else _safe(name)
        try:
            raw = _read_stdin(stdin) if name == "-" else bounded.read_bounded(Path(name), MAX_BYTES + 1)
        except OSError as exc:
            err.write(f"safo-brief-scan: {label}: cannot read ({type(exc).__name__})\n")
            unreadable = True
            continue
        if len(raw) > MAX_BYTES:
            err.write(f"safo-brief-scan: {label}: over the {MAX_BYTES} byte limit, not scanned\n")
            unreadable = True
            continue
        try:
            pairs.append((label, raw.decode("utf-8")))
        except UnicodeDecodeError:
            err.write(f"safo-brief-scan: {label}: not valid UTF-8, not scanned\n")
            unreadable = True
    return pairs, unreadable


def main(argv: Sequence[str], stdin: BinaryIO, out: TextIO, err: TextIO, env: Mapping[str, str] | None = None) -> int:
    env = os.environ if env is None else env
    args = list(argv)
    hook = "--hook" in args
    if hook:
        args.remove("--hook")
    if any(a.startswith("-") and a != "-" for a in args) or (hook and args):
        err.write("usage: safo-brief-scan [FILE ...] | --hook\n")
        return EXIT_UNCHECKED
    try:
        deny = localdraft.load_deny(env, err)
        allow = {w.upper() for w in localdraft.allow_words(env)}
    except localdraft.Failure as exc:
        err.write(f"safo-brief-scan: {exc}\n")
        return EXIT_UNCHECKED
    pairs, unreadable = _sources(args, hook, stdin, err)
    printed = total = 0
    for label, text in pairs:
        rows, allowed = scan_text(text, allow, deny)
        total += len(rows)
        for n, kind, tag in rows:
            if printed < MAX_PRINTED:
                err.write(f"{label}:{n}: {kind} [{tag}]\n")
                printed += 1
        if allowed:
            lines = ", ".join(str(n) for n in dict.fromkeys(allowed))
            err.write(f"{label}: allowed: {len(allowed)} (line {lines})\n")
    if total > printed:
        err.write(f"safo-brief-scan: {total - printed} more finding(s) not printed\n")
    if total:
        err.write(f"safo-brief-scan: {total} finding(s); remove the value, do not reword it around the check\n")
    if unreadable or (hook and total):
        return EXIT_UNCHECKED
    return EXIT_FOUND if total else EXIT_OK


def entry(argv: Sequence[str] | None = None) -> int:
    return main(sys.argv[1:] if argv is None else argv, sys.stdin.buffer, sys.stdout, sys.stderr)


def run() -> None:
    sys.exit(entry())


if __name__ == "__main__":
    run()
