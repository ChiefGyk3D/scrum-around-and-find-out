# SPDX-License-Identifier: Apache-2.0
"""No hidden work: a brief names the tracking item it serves, and the reference is checked before it is believed.

A reference is one line of its own, `issue: owner/repo#123` (GitHub) or `issue: KEY-123` (a Jira-style key). The
tracker sits behind one seam, `Resolver`, which answers whether a reference is usable. GitHub is looked up read-only
with `gh issue view`; a Jira key is validated by its shape alone, because no Jira instance exists today. A tracker
that is added later only needs a resolver and a pattern here.

Nothing in a brief reaches a shell: a reference must fullmatch a strict pattern first, and `gh` runs from an argument
list with no shell. A rejected reference is never echoed back.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

from safo.bounded import loads

LINE = re.compile(r"^[ \t]*issue:[ \t]*(\S+)[ \t]*\r?$", re.IGNORECASE | re.MULTILINE)
GITHUB_REF = re.compile(r"([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9._-]{1,100})#([1-9][0-9]{0,8})")
JIRA_KEY = re.compile(r"([A-Z][A-Z0-9]{1,9})-([1-9][0-9]{0,8})")
LOOKUP_TIMEOUT_SECONDS = 5

State = Literal["open", "closed", "missing", "error"]

HOW_TO_FILE = (
    "file the work first: `gh issue create --repo OWNER/REPO --title ... --body ...`, put it on the board "
    "(`gh project item-add NUMBER --owner OWNER --url ISSUE_URL`), then give the brief a line of its own, "
    "`issue: OWNER/REPO#N`"
)


@dataclass(frozen=True)
class Ref:
    tracker: Literal["github", "jira"]
    text: str  # the validated reference, safe to print
    repo: str = ""  # owner/name (GitHub only)
    number: int = 0


Resolver = Callable[[Ref], State]


def parse(text: str) -> Ref | None:
    """The first `issue:` line of a brief whose value is a valid reference, else None."""
    for found in LINE.finditer(text):
        value = found.group(1)
        github = GITHUB_REF.fullmatch(value)
        if github:
            return Ref("github", value, f"{github.group(1)}/{github.group(2)}", int(github.group(3)))
        if JIRA_KEY.fullmatch(value):
            return Ref("jira", value)
    return None


def has_issue_line(text: str) -> bool:
    return LINE.search(text) is not None


def exempt(cwd: str, repos: tuple[str, ...]) -> bool:
    """True when a listed repository's name is a component of the session's working directory.

    The opt-out is deliberate and per repository; a brief cannot grant it to itself.
    """
    parts = {p for p in cwd.replace("\\", "/").split("/") if p}
    return any(repo.rpartition("/")[2] in parts for repo in repos)


def gh_resolver(
    run: Callable[..., Any], which: Callable[[str], str | None], env: Mapping[str, str] | None = None
) -> Resolver:
    """Resolve a GitHub reference with `gh issue view`, a read. A Jira key is accepted on its shape alone."""

    def resolve(ref: Ref) -> State:
        if ref.tracker != "github":
            return "open"
        gh = which("gh")
        if gh is None:
            return "error"
        argv = [gh, "issue", "view", str(ref.number), "--repo", ref.repo, "--json", "state"]
        try:
            done = run(  # argument list, no shell; the reference already fullmatched GITHUB_REF
                argv,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=LOOKUP_TIMEOUT_SECONDS,
                **({"env": dict(env)} if env is not None else {}),
            )
        except (OSError, subprocess.TimeoutExpired, UnicodeDecodeError):
            return "error"
        if done.returncode != 0:
            stderr = done.stderr if isinstance(done.stderr, str) else ""
            return "missing" if "could not resolve" in stderr.lower() or "not found" in stderr.lower() else "error"
        try:
            state = loads(done.stdout)["state"]
        except (ValueError, KeyError, TypeError):
            return "error"
        if state == "OPEN":
            return "open"
        return "closed" if state == "CLOSED" else "error"

    return resolve


def check(text: str, resolve: Resolver) -> tuple[str, str] | None:
    """(rule id, reason) for a brief that breaks the rule, or None. Reasons never repeat unvalidated brief text."""
    ref = parse(text)
    if ref is None:
        invalid = has_issue_line(text)
        return (
            "no-issue",
            (
                "the brief's `issue:` line is not owner/repo#N or KEY-N; "
                if invalid
                else "the brief names no tracking item; "
            )
            + HOW_TO_FILE,
        )
    state = resolve(ref)
    if state == "open":
        return None
    if state == "error":
        return (
            "issue-unverified",
            f"could not confirm that {ref.text} exists and is open (is gh installed and logged in?)",
        )
    why = "does not exist" if state == "missing" else "is closed"
    return "issue-unusable", f"{ref.text} {why}; reopen it or file a new one, then name that in the brief"
