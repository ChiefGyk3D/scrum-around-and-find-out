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


class _Unsupported(Exception):
    """A pattern this module will not evaluate; the caller turns it into a CodeownersError naming the line."""


def _tokens(line: str) -> list[str]:
    """The whitespace-separated tokens of a line, backslash escapes kept as written; an unescaped # starts a comment."""
    out: list[str] = []
    cur: list[str] = []
    i = 0
    while i < len(line):
        c = line[i]
        if c == "\\":
            cur.append(line[i : i + 2])
            i += 2
            continue
        if c == "#":
            break
        if c.isspace():
            if cur:
                out.append("".join(cur))
                cur = []
        else:
            cur.append(c)
        i += 1
    if cur:
        out.append("".join(cur))
    return out


def _translate(pattern: str) -> re.Pattern[str]:
    """The gitignore-style pattern as a regular expression; _Unsupported for anything not understood with confidence.

    Understood: literal characters, `\\` + a punctuation character or space (that character, literally), `*` and `?`
    (never a slash), and `**` as a whole path segment: leading `**/`, middle `/**/`, trailing `/**`. Any other run of
    stars acts as one `*`. Not understood, so refused: `[...]` classes and section headers, a leading `!`, other
    backslash escapes, and patterns that are long or have many wildcards (the match cost is bounded).
    """
    if len(pattern) > MAX_PATTERN or sum(pattern.count(c) for c in "*?") > MAX_WILDCARDS:
        raise _Unsupported("the pattern is too long or has too many wildcards")
    if pattern.startswith("!") or "[" in pattern or "]" in pattern:
        raise _Unsupported("negation and [...] classes are not evaluated")
    directory = pattern.endswith("/") and not pattern.endswith("\\/")
    raw = pattern[:-1] if directory else pattern
    anchored = raw.startswith("/") or "/" in raw.rstrip("/")
    raw = raw.lstrip("/")
    if not raw:
        raise _Unsupported("the pattern names no path")
    out: list[str] = []
    i = 0
    while i < len(raw):
        c = raw[i]
        if c == "\\":
            if i + 1 >= len(raw) or raw[i + 1].isalnum():
                raise _Unsupported("a backslash must escape a punctuation character or a space")
            out.append(re.escape(raw[i + 1]))
            i += 2
        elif c == "*":
            j = i
            while j < len(raw) and raw[j] == "*":
                j += 1
            run = j - i
            before = i == 0 or raw[i - 1] == "/"
            if run >= 2 and before and j == len(raw) and i > 0:
                out[-1] = ""  # the slash before a trailing /** : the segment is the rest of the path
                out.append("/.*")
            elif run >= 2 and before and raw.startswith("/", j):
                out.append("(?:.*/)?")
                j += 1
            else:
                out.append("[^/]*")
            i = j
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    body = "".join(out)
    tail = "/.*" if directory else "(?:/.*)?"
    if body.endswith("/.*"):
        tail = ""
    return re.compile(("" if anchored else "(?:.*/)?") + body + tail)


def parse_rules(text: str) -> list[Rule]:
    """The rules in file order. A line that cannot be evaluated is an error naming it, never a rule left out."""
    lines = text.splitlines()
    if len(lines) > MAX_RULES:
        raise CodeownersError(f"cannot evaluate CODEOWNERS rule at line {MAX_RULES + 1}: too many lines")
    rules: list[Rule] = []
    for number, line in enumerate(lines, 1):
        tokens = _tokens(line)
        if not tokens:
            continue
        try:
            matcher = _translate(tokens[0])
        except _Unsupported as err:
            raise CodeownersError(f"cannot evaluate CODEOWNERS rule at line {number}: {err}") from None
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


PROBES = ("probe.md", "probe.yaml", "probe", "sub/probe.md", "sub/probe.yaml")


def uncovered(rules: Sequence[Rule], paths: Iterable[str]) -> list[str]:
    """The paths with no owner. A directory (trailing slash) is probed with files of several extensions at two depths,
    so a rule that removes ownership of just `*.md` or `*.yaml` under it is seen."""
    return [
        p
        for p in paths
        if (any(not covered(rules, p + probe) for probe in PROBES) if p.endswith("/") else not covered(rules, p))
    ]
