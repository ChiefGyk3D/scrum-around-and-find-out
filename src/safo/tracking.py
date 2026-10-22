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

import os
import re
import subprocess
from collections.abc import Callable, Collection, Mapping
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


REMOTE = re.compile(
    r"(?:https?://(?:[^/@\s]+@)?github\.com/|ssh://git@github\.com/|git@github\.com:)"
    r"([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9._-]{1,100}?)(?:\.git)?/?"
)
MIN_LOOKUP_SECONDS = 0.5  # less time than this left, and a lookup is not attempted: it would outlive the hook


def repo_from_remote(url: str) -> str | None:
    """owner/name from a github.com remote URL, else None (another host, a path, anything not recognized)."""
    found = REMOTE.fullmatch(url.strip())
    return f"{found.group(1)}/{found.group(2)}" if found else None


def cwd_repo(
    run: Callable[..., Any],
    env: Mapping[str, str],
    cwd: str,
    remaining: Callable[[], float] = lambda: float(LOOKUP_TIMEOUT_SECONDS),
) -> str | None:
    """The owner/name of the repository a session works in, from its `origin` remote, or None when it cannot be told.

    `git config --get` reads a file and runs nothing from the repository. A relative or missing directory, no git,
    no remote, a remote on another host, a timeout: all None, and the caller treats None as "not this repository".
    """
    if not cwd or not os.path.isabs(cwd) or "\x00" in cwd or not os.path.isdir(cwd):
        return None
    git = next(
        (
            c
            for e in env.get("PATH", "").split(os.pathsep)
            if os.path.isabs(e) and os.path.isfile(c := os.path.join(e, "git")) and os.access(c, os.X_OK)
        ),
        None,
    )
    left = min(float(LOOKUP_TIMEOUT_SECONDS), remaining())
    if git is None or left < MIN_LOOKUP_SECONDS:
        return None
    try:
        done = run(  # argument list, no shell
            [git, "-C", cwd, "config", "--get", "remote.origin.url"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=left,
            env=dict(env),
        )
    except (OSError, subprocess.TimeoutExpired, UnicodeDecodeError):
        return None
    if done.returncode != 0 or not isinstance(done.stdout, str):
        return None
    return repo_from_remote(done.stdout)


def exempt(repo: str | None, repos: tuple[str, ...]) -> bool:
    """True when the session's repository (owner/name, compared without case) is on the opt-out list.

    An undetermined repository (None) is never exempt. The opt-out is deliberate and per repository; a brief cannot
    grant it to itself, and the name of a directory proves nothing.
    """
    return repo is not None and repo.lower() in {r.lower() for r in repos}


def gh_resolver(
    run: Callable[..., Any],
    which: Callable[[str], str | None],
    env: Mapping[str, str] | None = None,
    remaining: Callable[[], float] = lambda: float(LOOKUP_TIMEOUT_SECONDS),
) -> Resolver:
    """Resolve a GitHub reference with `gh issue view`, a read. A Jira key is accepted on its shape alone.

    The lookup gets only the time `remaining()` says is left before the hook's own deadline; with too little left it is
    not attempted and the answer is "error".
    """

    def resolve(ref: Ref) -> State:
        if ref.tracker != "github":
            return "open"
        gh = which("gh")
        left = min(float(LOOKUP_TIMEOUT_SECONDS), remaining())
        if gh is None or left < MIN_LOOKUP_SECONDS:
            return "error"
        argv = [gh, "issue", "view", str(ref.number), "--repo", ref.repo, "--json", "state"]
        try:
            done = run(  # argument list, no shell; the reference already fullmatched GITHUB_REF
                argv,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=left,
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


def check(text: str, resolve: Resolver, accepted: Collection[str] | None = None) -> tuple[str, str] | None:
    """(rule id, reason) for a brief that breaks the rule, or None. Reasons never repeat unvalidated brief text.

    With `accepted` (owner/name values), a GitHub reference outside those repositories is refused before any lookup,
    so an unrelated open issue cannot satisfy the rule. A Jira key is not tied to a repository.
    """
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
    if accepted is not None and ref.tracker == "github" and ref.repo.lower() not in {a.lower() for a in accepted}:
        where = ", ".join(sorted(accepted)) or "none (set hooks.tracking_repos, or run in a repository with an origin)"
        return "issue-unusable", f"{ref.text} is not in an accepted repository; accepted: {where}"
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
