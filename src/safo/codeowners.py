# SPDX-License-Identifier: MIT
"""Does CODEOWNERS cover the files an agent's instructions are made from? (spec 7.2, rule 1)

The profile text, the evidence it cites, the personas and templates it renders and the source that holds the profile
constants all end up in files agents obey, so a change to any of them must reach a code owner. `safo profiles verify`
reads the repository's CODEOWNERS and fails when one of those paths has no owner. The check is offline and answers only
whether a rule names an owner; whether branch protection requires the owner's review cannot be seen from the checkout
(docs/adoption.md).

Matching follows the gitignore rules CODEOWNERS uses: the last matching line wins, and a line with no valid owner
clears ownership of what it matches. Patterns are translated to regular expressions with a cap on pattern length and on
wildcards, so a hostile CODEOWNERS cannot make the match expensive.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from safo.errors import ConfigError
from safo.profile import read_confined

REQUIRED = (
    "agents.yaml",
    "examples/harness/",
    ".claude/agents/",
    "agents/",
    "src/safo/agentsfile.py",
    "src/safo/profile_render.py",
)
LOCATIONS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")  # GitHub's order of precedence
MAX_BYTES = 3 * 1024 * 1024
MAX_RULES = 10_000
MAX_PATTERN = 200
MAX_WILDCARDS = 6
MAX_OWNER = 256
OWNER = re.compile(r"@[A-Za-z0-9][A-Za-z0-9-]*(?:/[A-Za-z0-9._-]+)?|[^@\s]+@[^@\s]+\.[^@\s]+")


class CodeownersError(ConfigError):
    """CODEOWNERS is missing, unreadable or not a plain file."""


@dataclass(frozen=True)
class Rule:
    matcher: re.Pattern[str]
    owned: bool


def find_codeowners(root: Path) -> str:
    """The text of the first CODEOWNERS GitHub would read under `root`; a link or a huge file is refused."""
    for place in LOCATIONS:
        try:
            raw = read_confined(root, place, MAX_BYTES)
        except FileNotFoundError:
            continue
        except NotADirectoryError:
            continue
        except OSError:
            raise CodeownersError(f"{place} is a symbolic link or not a regular file") from None
        if len(raw) > MAX_BYTES:
            raise CodeownersError(f"{place} is larger than {MAX_BYTES} bytes")
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            raise CodeownersError(f"{place} is not valid UTF-8") from None
    raise CodeownersError(f"no CODEOWNERS file (looked in {', '.join(LOCATIONS)})")


def _translate(pattern: str) -> re.Pattern[str] | None:
    """The gitignore-style pattern as a regular expression, or None when it is too long or too wild to trust."""
    if len(pattern) > MAX_PATTERN or pattern.count("*") + pattern.count("?") > MAX_WILDCARDS:
        return None
    directory = pattern.endswith("/")
    body = pattern.strip("/")
    if not body:
        return None
    anchored = pattern.startswith("/") or "/" in body
    out: list[str] = []
    i = 0
    while i < len(body):
        if body.startswith("**/", i) and (i == 0 or body[i - 1] == "/"):
            out.append("(?:.*/)?")
            i += 3
        elif body.startswith("/**", i) and i + 3 == len(body):
            out.append("/.*")
            i += 3
        elif body.startswith("**", i):
            out.append(".*")
            i += 2
        elif body[i] == "*":
            out.append("[^/]*")
            i += 1
        elif body[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(body[i]))
            i += 1
    tail = "/.*" if directory else "(?:/.*)?"
    return re.compile(("" if anchored else "(?:.*/)?") + "".join(out) + tail)


def parse_rules(text: str) -> list[Rule]:
    rules: list[Rule] = []
    for line in text.splitlines()[:MAX_RULES]:
        tokens = line.split("#", 1)[0].split()
        if not tokens:
            continue
        matcher = _translate(tokens[0])
        if matcher is not None:
            rules.append(Rule(matcher, any(len(t) <= MAX_OWNER and OWNER.fullmatch(t) for t in tokens[1:])))
    return rules


def covered(rules: Sequence[Rule], path: str) -> bool:
    """True when the last rule matching the file `path` names an owner."""
    result = False
    for rule in rules:
        if rule.matcher.fullmatch(path):
            result = rule.owned
    return result


def required_paths(lessons: str, templates: Iterable[str]) -> tuple[str, ...]:
    """Every path that must be owned: the fixed list, the configured lessons file and each template's directory."""
    extra = [lessons]
    for template in sorted(set(templates)):
        head, sep, _ = template.rpartition("/")
        extra.append(head + sep if sep else template)
    return REQUIRED + tuple(dict.fromkeys(extra))


def uncovered(rules: Sequence[Rule], paths: Iterable[str]) -> list[str]:
    """The paths with no owner. A directory (trailing slash) is probed with a file inside it."""
    return [p for p in paths if not covered(rules, p + "probe" if p.endswith("/") else p)]
