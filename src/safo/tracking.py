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

import contextlib
import json
import os
import re
import stat
import subprocess
import tempfile
import time
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from safo.bounded import loads
from safo.guardlog import trusted_dir

LINE = re.compile(r"^[ \t]*issue:[ \t]*(\S+)[ \t]*\r?$", re.IGNORECASE | re.MULTILINE)
GITHUB_REF = re.compile(r"([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9._-]{1,100})#([1-9][0-9]{0,8})")
JIRA_KEY = re.compile(r"([A-Z][A-Z0-9]{1,9})-([1-9][0-9]{0,8})")
LOOKUP_TIMEOUT_SECONDS = 5
ISSUE_URL = re.compile(r"https://[^/\s]+/[^/\s]+/[^/\s]+/(issues|pull)/[0-9]+")

State = Literal["open", "closed", "missing", "pull_request", "error"]

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


CACHE_NAME = "issue-cache.json"
CACHE_TTL_SECONDS = 300  # a positive answer is believed for five minutes
CACHE_MAX_ENTRIES = 64
CACHE_MAX_BYTES = 65_536
CACHE_MIN_REMAINING_SECONDS = 1.0  # with less of the hook's budget left than this, the cache is not touched at all
REST_FIELDS = '{state: .state, pull_request: has("pull_request")}'


def _cache_key(ref: Ref) -> str:
    return f"{ref.repo.lower()}#{ref.number}"


def _entries(folder: Path) -> dict[str, Any]:
    """The cache file's entries, or {} for anything not trusted: an untrusted directory, a symlink, a FIFO or other
    non-regular file, a file not owned by this user or writable by group or others (judged on the OPENED descriptor),
    one that is too large, or one that does not parse."""
    if not trusted_dir(folder):
        return {}
    try:
        fd = os.open(folder / CACHE_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return {}
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o022
            or info.st_size > CACHE_MAX_BYTES
        ):
            return {}
        data = loads(os.read(fd, CACHE_MAX_BYTES + 1).decode("utf-8"))
        found = data["entries"]
        return found if isinstance(found, dict) else {}
    except (OSError, ValueError, KeyError, TypeError, UnicodeDecodeError):
        return {}
    finally:
        os.close(fd)


def cache_read(folder: Path, ref: Ref, now: float) -> bool:
    """True only when a trusted cache file holds an entry for exactly this repository and issue number, written within
    the last CACHE_TTL_SECONDS (a timestamp in the future is not believed). Every other case is a miss, never a pass."""
    try:
        entry = _entries(folder)[_cache_key(ref)]
        stamp = entry["ts"]
        if entry["repo"] != ref.repo.lower() or entry["number"] != ref.number:
            return False
        return isinstance(stamp, (int, float)) and not isinstance(stamp, bool) and 0 <= now - stamp < CACHE_TTL_SECONDS
    except (KeyError, TypeError):
        return False


def cache_store(folder: Path, ref: Ref, now: float) -> None:
    """Remember a positive answer, best effort: a temporary file in the same directory, owner-only, then os.replace
    (a reader never sees half a file); no fsync, because a lost cache is only a missed optimization. Expired entries
    are dropped and at most CACHE_MAX_ENTRIES kept. Only an open issue is stored, only into a trusted directory."""
    temp = ""
    try:
        if not trusted_dir(folder):
            return
        live = {
            k: v
            for k, v in _entries(folder).items()
            if isinstance(v, dict) and isinstance(v.get("ts"), (int, float)) and 0 <= now - v["ts"] < CACHE_TTL_SECONDS
        }
        live[_cache_key(ref)] = {"repo": ref.repo.lower(), "number": ref.number, "ts": now}
        newest = sorted(live.items(), key=lambda item: item[1]["ts"], reverse=True)[:CACHE_MAX_ENTRIES]
        fd, temp = tempfile.mkstemp(prefix=f".{CACHE_NAME}.", dir=folder)
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(json.dumps({"entries": dict(newest)}, sort_keys=True).encode("utf-8"))
        os.replace(temp, folder / CACHE_NAME)
        temp = ""
    except (OSError, ValueError, TypeError, KeyError):
        return  # a cache that cannot be written is only a missed optimization
    finally:
        if temp:
            with contextlib.suppress(OSError):
                os.unlink(temp)


def gh_resolver(
    run: Callable[..., Any],
    which: Callable[[str], str | None],
    env: Mapping[str, str] | None = None,
    remaining: Callable[[], float] = lambda: float(LOOKUP_TIMEOUT_SECONDS),
    cache_dir: Path | None = None,
    clock: Callable[[], float] = time.time,
    bounded: Callable[[Callable[[], bool]], tuple[bool, bool | None]] | None = None,
    deferred: list[tuple[Ref, float]] | None = None,
) -> Resolver:
    """Resolve a GitHub reference with a read. A Jira key is accepted on its shape alone.

    Order: a positive answer cached in `cache_dir` within the last five minutes; then REST
    (`gh api repos/OWNER/REPO/issues/N`, which has its own rate-limit counter); then, only if REST gave no usable
    answer, GraphQL (`gh issue view`). The function attribute `source` names what answered ("cache", "REST", "GraphQL",
    or "REST and GraphQL" when both failed). Only an open issue is cached; closed, missing and error answers never are.
    The lookups get only the time `remaining()` says is left before the hook's own deadline.
    """

    def ask(argv: list[str]) -> Any | None:
        left = min(float(LOOKUP_TIMEOUT_SECONDS), remaining())
        if left < MIN_LOOKUP_SECONDS:
            return None
        try:
            return run(  # argument list, no shell; the reference already fullmatched GITHUB_REF
                argv,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=left,
                **({"env": dict(env)} if env is not None else {}),
            )
        except (OSError, subprocess.TimeoutExpired, UnicodeDecodeError):
            return None

    def missing(done: Any) -> bool:
        stderr = done.stderr if isinstance(done.stderr, str) else ""
        return "could not resolve" in stderr.lower() or "not found" in stderr.lower()

    def via_rest(gh: str, ref: Ref) -> State:
        done = ask([gh, "api", f"repos/{ref.repo}/issues/{ref.number}", "--jq", REST_FIELDS])
        if done is None:
            return "error"
        if done.returncode != 0:
            return "missing" if missing(done) else "error"
        try:
            answer = loads(done.stdout)
            state, pull = answer["state"], answer["pull_request"]
        except (ValueError, KeyError, TypeError):
            return "error"
        if pull is True:
            return "pull_request"
        if pull is not False:
            return "error"
        if state == "open":
            return "open"
        return "closed" if state == "closed" else "error"

    def via_graphql(gh: str, ref: Ref) -> State:
        done = ask([gh, "issue", "view", str(ref.number), "--repo", ref.repo, "--json", "state,url"])
        if done is None:
            return "error"
        if done.returncode != 0:
            return "missing" if missing(done) else "error"
        try:
            answer = loads(done.stdout)
            state, url = answer["state"], answer["url"]
        except (ValueError, KeyError, TypeError):
            return "error"
        # `gh issue view` also resolves a pull request. Its field list has no type discriminator, but `url` carries
        # one (https://cli.github.com/manual/gh_issue_view): /issues/N for an issue, /pull/N for a pull request.
        kind = ISSUE_URL.fullmatch(url) if isinstance(url, str) else None
        if kind is None:
            return "error"
        if kind.group(1) == "pull":
            return "pull_request"
        if state == "OPEN":
            return "open"
        return "closed" if state == "CLOSED" else "error"

    def resolve(ref: Ref) -> State:
        resolve.source = ""  # type: ignore[attr-defined]
        if ref.tracker != "github":
            return "open"
        cache = cache_dir if cache_dir is not None and remaining() >= CACHE_MIN_REMAINING_SECONDS else None
        if cache is not None:
            stamp, where = clock(), cache
            if bounded is None:
                hit: bool | None = cache_read(where, ref, stamp)
            else:
                done, hit = bounded(lambda: cache_read(where, ref, stamp))
                cache = cache if done else None  # a read that did not finish: no cache work at all this dispatch
            if hit:
                resolve.source = "cache"  # type: ignore[attr-defined]
                return "open"
        gh = which("gh")
        if gh is None:
            return "error"
        state = via_rest(gh, ref)
        source = "REST"
        if state == "error":
            state, source = via_graphql(gh, ref), "GraphQL"
            if state == "error":
                source = "REST and GraphQL"
        resolve.source = source  # type: ignore[attr-defined]
        if state == "open" and cache is not None:
            if deferred is not None:
                deferred.append((ref, clock()))  # written by the caller after the verdict is out
            else:
                cache_store(cache, ref, clock())
        return state

    resolve.source = ""  # type: ignore[attr-defined]
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
    source = getattr(resolve, "source", "")
    if state == "error":
        detail = f"{source} failed; is gh installed and logged in?" if source else "is gh installed and logged in?"
        return "issue-unverified", f"could not confirm that {ref.text} exists and is open ({detail})"
    why = {"missing": "does not exist", "pull_request": "is a pull request, not an issue"}.get(state, "is closed")
    via = f" (answered by {source})" if source else ""
    return "issue-unusable", f"{ref.text} {why}{via}; reopen it or file a new one, then name that in the brief"
