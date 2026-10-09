# SPDX-License-Identifier: MIT
"""What must never appear in anything public: docs/, examples/ and README.md.

Generic patterns only. Terms that cannot be written into a public repository (an employer's name, a callsign, a
grid square, region names, real hostnames and serials) live in a file OUTSIDE the repository: set
SAFO_PRIVACY_EXTRA_FILE to its path, one regular expression per line, and `make check` applies them too.
CI runs the generic patterns.
"""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).parent.parent
SCANNED = ("docs", "examples", "README.md", "agents.yaml")
# Plans embed this test's own fixtures (strings that look private on purpose), so they cannot pass it;
# the specs and every other page do.
EXCLUDED = ("docs/superpowers/plans", "docs/superpowers/specs")
TEXT_SUFFIXES = {".md", ".yaml", ".yml", ".txt", ".json", ".jsonl"}

# A callsign-shaped token: one or two prefix letters, a digit, one to three letters. The placeholders are allowed.
CALLSIGN = r"\b(?:[AKNW][A-Z]?|[A-Z][0-9])[0-9][A-Z]{1,3}\b"
ALLOWED_CALLSIGNS = {"N0CALL", "N0TST", "W3C"}
ALLOWED_GRIDS = {"FN31pr"}

PATTERNS: dict[str, str] = {
    "private IPv4 address": r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01])|169\.254)\.\d{1,3}\.\d{1,3}\b",
    "carrier-grade NAT address (a VPN's)": r"\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b",
    "tailnet name": r"(?i)\b[a-z0-9-]+\.ts\.net\b|\btwingate\b|\btailscale\b",
    "MAC address": r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
    "machine identifier": r"(?i)\b(?:serial(?: number)?|service tag|asset tag)\s*[:#=]\s*[A-Z0-9]{6,}\b",
    "Maidenhead grid square": r"\b[A-R]{2}[0-9]{2}(?:[a-x]{2})?\b",
    "callsign-shaped token": CALLSIGN,
    "home-directory path": r"/home/[a-z][a-z0-9_-]*/",
}

# A domain-like token must be one of these; anything else is a hostname that does not belong in a public document.
HOST = re.compile(r"(?i)\b(?:[a-z0-9][a-z0-9-]*\.)+[a-z]{2,63}\b")
# File-like dotted names are not hosts. Single-label private names come from the external supplement.
DOCUMENT_KEYS = {
    "project.number",
    "agents.waiting",
    "agents.working",
    "status.closed",
    "status.merged",
    "status.opened",
    "status.reopened",
    "rules.status.opened",
    "items.totalcount",
    "statusupdate.project.id",
}
FILE_SUFFIXES = {"md", "yaml", "yml", "py", "json", "jsonl", "txt", "sh", "toml", "lock"}

ALLOWED_HOSTS = {
    "github.com",
    "api.github.com",
    "docs.github.com",
    "users.noreply.github.com",
    "pypi.org",
    "files.pythonhosted.org",
    "anthropic.com",
    "claude.com",
    "shellcheck.net",
    "ollama.lan",  # the placeholder endpoint host in agents.yaml; real ones live in a git-ignored local file
}


def extra_patterns() -> dict[str, str]:
    path = os.environ.get("SAFO_PRIVACY_EXTRA_FILE", "")
    if not path:
        return {}
    lines = [x for x in Path(path).read_text().splitlines() if x.strip() and not x.startswith("#")]
    return {f"private term {i + 1}": line for i, line in enumerate(lines)}


def scanned_files() -> list[Path]:
    files: list[Path] = []
    for name in SCANNED:
        base = ROOT / name
        if base.is_file():
            files.append(base)
        elif base.is_dir():
            files += [
                p
                for p in sorted(base.rglob("*"))
                if p.is_file() and p.suffix in TEXT_SUFFIXES and not str(p.relative_to(ROOT)).startswith(EXCLUDED)
            ]
    return files


def findings(text: str) -> list[str]:
    """Category and line only: assertion output and repository logs must never repeat private matches."""
    out: list[str] = []

    def record(kind: str, start: int) -> None:
        out.append(f"{kind}: line {text.count(chr(10), 0, start) + 1}")

    for kind, pattern in {**PATTERNS, **extra_patterns()}.items():
        for m in re.finditer(pattern, text):
            token = m.group(0)
            if kind == "callsign-shaped token" and token in ALLOWED_CALLSIGNS:
                continue
            if kind == "Maidenhead grid square" and token in ALLOWED_GRIDS:
                continue
            record(kind, m.start())
    for m in HOST.finditer(text):
        host = m.group(0).lower()
        if host not in ALLOWED_HOSTS and host not in DOCUMENT_KEYS and host.rsplit(".", 1)[-1] not in FILE_SUFFIXES:
            record("hostname", m.start())
    for m in re.finditer(r"https?://[^\s<>\"']+", text, re.I):
        url_host = urlsplit(m.group(0)).hostname
        if url_host and "." not in url_host and ":" not in url_host and url_host.lower() not in ALLOWED_HOSTS:
            record("hostname", m.start())
    for m in re.finditer(r"(?<![\w:])(?:[0-9a-fA-F]*:){2,}[0-9a-fA-F:.]+(?:%[\w-]+)?", text):
        try:
            address = ipaddress.ip_address(m.group(0).split("%", 1)[0])
        except ValueError:
            continue
        if address.is_private or address.is_link_local or address.is_loopback or address.is_unspecified:
            record("private IPv6 address", m.start())
    return out
