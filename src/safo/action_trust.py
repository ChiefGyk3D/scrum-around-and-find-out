# SPDX-License-Identifier: Apache-2.0
"""What the Action trusts from its caller, decided before a credential is fetched, minted or used.

Two questions, both answered by an allow-list that fails closed:

* `classify`: is this event one the Action can positively identify as trusted? Only the events and refs in `RULES` are;
  any other event, an unknown spelling, or a missing value is refused.
* `Revision`: which commit is trusted, and what do the board file and the status body say *in that commit*? A file is
  read from the git object database at that commit, never from the working tree, and only when it is a regular file
  there (not a link, not a directory, not a submodule, not reached through a link).
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from safo import output
from safo.errors import ConfigError

_SHA = re.compile(r"[0-9a-f]{40}")
_BRANCH = re.compile(r"refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,200}")
_TAG = re.compile(r"refs/tags/[A-Za-z0-9][A-Za-z0-9._/-]{0,200}")
_PULL = re.compile(r"refs/pull/[0-9]{1,9}/merge")
_BRANCH_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,200}")
GIT_TIMEOUT_SECONDS = 30.0
REGULAR = ("100644", "100755")

# events whose run can carry content from outside the repository: the trusted revision must be the one GitHub ran on
FOREIGN_CAPABLE = frozenset({"pull_request", "pull_request_target", "workflow_run", "issues"})


def shown(text: str) -> str:
    return repr(output.line(text[:80]))


@dataclass(frozen=True)
class Trust:
    event: str
    ref: str
    why: str


def _flag(env: Mapping[str, str], name: str, label: str) -> bool:
    value = env.get(name)
    if value not in ("true", "false"):
        raise ConfigError(
            f"{label} is missing or not true or false, so the Action cannot classify this event as trusted"
        )
    return value == "true"


def _default_ref(env: Mapping[str, str]) -> str:
    name = env.get("DEFAULT_BRANCH", "")
    return f"refs/heads/{name}" if _BRANCH_NAME.fullmatch(name) else ""


def classify(env: Mapping[str, str]) -> Trust:
    """The event and ref this run is on, when they are on the allow-list; otherwise ConfigError (fail closed).

    Matching is exact: no case folding, no trimming, no normalization of the event name or the ref.
    """
    event, ref = env.get("EVENT_NAME", ""), env.get("GITHUB_REF", "")
    fork = _flag(env, "IS_FORK", "the fork flag")
    if _flag(env, "REPO_IS_FORK", "the repository fork flag") and env.get("ALLOW_FORK_REPO", "false") != "true":
        raise ConfigError(
            "a repository that is itself a fork receives no credential unless allow-fork-repository is true"
        )
    default = _default_ref(env)
    on_default = bool(default) and ref == default
    refusal = (
        f"event {shown(event)} on ref {shown(ref)} is not one the Action can classify as trusted, so no credential "
        "is fetched or used; trusted events are push (default branch or a tag), schedule, workflow_dispatch, issues "
        "and workflow_run (default branch), pull_request from this repository, and pull_request_target"
    )
    if event == "pull_request":
        if _PULL.fullmatch(ref) and not fork:
            return Trust(event, ref, "pull request from this repository")
        if fork:
            raise ConfigError("a pull request from a fork never receives a credential, a Doppler fetch or a token")
    elif event == "pull_request_target":
        if on_default and not fork:
            return Trust(event, ref, "pull_request_target on the default branch, pull request from this repository")
        if on_default and fork:
            if env.get("ALLOW_FORK_PRT", "false") == "true":
                return Trust(event, ref, "pull_request_target for a fork pull request, allowed by the caller")
            raise ConfigError(
                "a pull request from a fork under pull_request_target receives no credential unless "
                "allow-fork-pull-request-target is true"
            )
    elif event in ("issues", "workflow_run"):
        if on_default and not fork:
            return Trust(event, ref, f"{event} on the default branch")
        if fork:
            raise ConfigError(f"a {event} run that came from a fork never receives a credential")
    elif event == "push":
        if (on_default or _TAG.fullmatch(ref)) and not fork:
            return Trust(event, ref, "push to the default branch or a tag")
    elif event == "schedule":
        if on_default and not fork:
            return Trust(event, ref, "scheduled run on the default branch")
    elif event == "workflow_dispatch":
        if (_BRANCH.fullmatch(ref) or _TAG.fullmatch(ref)) and not fork:
            return Trust(event, ref, "manual run, which GitHub allows only to users with write access")
    raise ConfigError(refusal)


# -- git ------------------------------------------------------------------------------------------------------------


def _git(workspace: str, *args: str) -> subprocess.CompletedProcess[bytes]:
    """git run against the workspace with no user, system or global configuration and no replacement objects."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CEILING_DIRECTORIES": os.path.dirname(workspace) or "/",
    }
    try:
        return subprocess.run(  # noqa: S603 - fixed argv of validated values, no shell, stdin closed, bounded time
            ["git", "-c", f"safe.directory={workspace}", "-C", workspace, *args],  # noqa: S607 - git from the runner PATH
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ConfigError("git could not be run to read the trusted revision") from None


def _commit(workspace: str, name: str) -> str | None:
    done = _git(workspace, "rev-parse", "--verify", "--quiet", "--end-of-options", f"{name}^{{commit}}")
    sha = done.stdout.decode("ascii", "replace").strip()
    return sha if done.returncode == 0 and _SHA.fullmatch(sha) else None


def has_repository(workspace: str) -> bool:
    return _git(workspace, "rev-parse", "--git-dir").returncode == 0


@dataclass(frozen=True)
class Revision:
    workspace: str
    sha: str
    has_repo: bool

    def blob(self, path: str, label: str, limit: int) -> bytes:
        """The bytes of `path` as committed at the trusted revision, which must be a regular file there."""
        parts = path.split("/")
        if (
            not path
            or path[0] in "-~"
            or "\\" in path
            or any(part in ("", ".", "..") for part in parts)
            or any(ord(c) < 32 or ord(c) == 127 for c in path)
        ):
            raise ConfigError(f"{label} {shown(path)} must be a plain relative path inside the trusted revision")
        if not self.has_repo:
            raise ConfigError(
                f"{label} is read from the trusted revision, so the repository must be checked out "
                "(actions/checkout with persist-credentials: false) before this Action"
            )
        if _commit(self.workspace, self.sha) is None:
            raise ConfigError(f"the trusted revision {self.sha[:12]} is not in the checkout; check out that revision")
        listing = _git(self.workspace, "ls-tree", "-z", "--full-tree", self.sha, "--", path)
        entries = [e for e in listing.stdout.split(b"\0") if e]
        if listing.returncode != 0 or len(entries) != 1:
            raise ConfigError(f"{label} {shown(path)} is not a file in the trusted revision (a link or a missing path)")
        meta, _, name = entries[0].partition(b"\t")
        fields = meta.decode("ascii", "replace").split(" ")
        if len(fields) != 3 or name.decode("utf-8", "replace") != path:
            raise ConfigError(f"{label} {shown(path)} is not a file in the trusted revision (a link or a missing path)")
        mode, kind, oid = fields
        if kind != "blob" or mode not in REGULAR or not _SHA.fullmatch(oid):
            raise ConfigError(f"{label} {shown(path)} must be a regular file in the trusted revision, not a link")
        size = _git(self.workspace, "cat-file", "-s", oid)
        try:
            length = int(size.stdout.decode("ascii").strip())
        except ValueError:
            raise ConfigError(f"{label} {shown(path)} could not be read from the trusted revision") from None
        if length > limit:
            raise ConfigError(f"{label} {shown(path)} is longer than {limit} bytes")
        body = _git(self.workspace, "cat-file", "blob", oid)
        if body.returncode != 0:
            raise ConfigError(f"{label} {shown(path)} could not be read from the trusted revision")
        return body.stdout

    def materialize(self, env: Mapping[str, str], path: str, label: str, limit: int, name: str) -> str:
        """Write the committed bytes to a private file under the runner's temp directory; return its path."""
        data = self.blob(path, label, limit)
        directory = Path(tempfile.mkdtemp(prefix="safo-trusted.", dir=env.get("RUNNER_TEMP") or None))
        target = directory / name
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        return str(target)


def trusted_revision(env: Mapping[str, str], trust: Trust) -> Revision:
    """The commit the caller trusts: `trusted-ref` when given, else the commit GitHub ran on (github.sha).

    A given ref is a full commit id or a full branch or tag ref. For events that can carry outside content it must be
    the commit GitHub ran on. It is never the head of the pull request under test unless that is a pull_request event
    from this repository. When the workspace is a git checkout, the checked-out commit must be the trusted one.
    """
    workspace = os.path.realpath(env.get("GITHUB_WORKSPACE") or os.getcwd())
    ran_on = env.get("GITHUB_SHA", "")
    if not _SHA.fullmatch(ran_on):
        raise ConfigError("github.sha is missing or malformed, so the trusted revision cannot be identified")
    given = env.get("TRUSTED_REF", "")
    repo = has_repository(workspace)
    sha = ran_on
    if given:
        if not (_SHA.fullmatch(given) or _BRANCH.fullmatch(given) or _TAG.fullmatch(given)):
            raise ConfigError(
                f"trusted-ref {shown(given)} must be a full commit id or a full refs/heads or refs/tags name"
            )
        if not repo:
            raise ConfigError("trusted-ref needs the repository checked out so the ref can be resolved")
        found = _commit(workspace, given)
        if found is None:
            raise ConfigError(f"trusted-ref {shown(given)} does not resolve to a commit in the checkout")
        sha = found
        if trust.event in FOREIGN_CAPABLE and sha != ran_on:
            raise ConfigError(f"for a {trust.event} run, trusted-ref must be the commit this run is on")
        head = env.get("PR_HEAD_SHA", "").lower()
        if head and sha == head and trust.event != "pull_request":
            raise ConfigError("trusted-ref must not be the head commit of the pull request under test")
    if repo:
        checked_out = _commit(workspace, "HEAD")
        if checked_out != sha:
            raise ConfigError(
                "the checked-out commit is not the trusted revision, so the credential would sit next to other code; "
                "check out the trusted revision only, or run the Action in a job without a checkout"
            )
    return Revision(workspace, sha, repo)
