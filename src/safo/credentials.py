# SPDX-License-Identifier: MIT
"""Where the token comes from. The token itself is only ever held by the Client."""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from safo.errors import ConfigError

APP = "app"  # a GitHub App installation token minted by actions/create-github-app-token
PAT = "token"  # a fine-grained personal access token handed to the Action
GH = "gh"  # the caller's `gh auth token`

GH_TIMEOUT_SECONDS = 20.0
LOGIN = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,38}")  # a GitHub login (EMU logins carry an underscore); never a flag
PLAIN_TOKEN = re.compile(r"[\x21-\x7e]{1,4096}")  # one printable run: it goes into an Authorization header


class NoTokenError(ConfigError):
    """No credential was given: a live run cannot tell anything, even as a dry run."""


@dataclass(frozen=True)
class Credentials:
    token: str
    kind: str

    def __repr__(self) -> str:
        return f"Credentials(kind={self.kind!r})"


def from_env(env: Mapping[str, str]) -> Credentials | None:
    """SAFO_TOKEN (with SAFO_TOKEN_KIND, default `app`), as the Action sets them."""
    token = env.get("SAFO_TOKEN", "").strip()
    if not token:
        return None
    kind = env.get("SAFO_TOKEN_KIND", APP).strip() or APP
    if kind not in (APP, PAT, GH):
        raise ConfigError(f"SAFO_TOKEN_KIND {kind!r} is not one of {APP}, {PAT}, {GH}")
    return Credentials(token, kind)


def flag(env: Mapping[str, str], name: str, label: str) -> bool:
    """A true/false input. Anything else is an error: a loose truthy word must not unlock an exception."""
    value = env.get(name, "").strip().lower()
    if value in ("", "false"):
        return False
    if value == "true":
        return True
    raise ConfigError(f"{label} must be true or false")


def check_for_board(creds: Credentials, owner_type: str, env: Mapping[str, str]) -> None:
    """Refuse a credential that cannot, or should not, write this kind of board. No API call is made first.

    * An App installation token cannot write a user-owned project: GitHub Apps have no user-account Projects
      permission, so the call could only fail, late and confusingly.
    * A personal access token on an organization board is refused unless `allow-token-for-org` is true, because the
      Action's contract is a scoped, short-lived App token; a PAT is the user-board exception.
    """
    allowed = flag(env, "SAFO_ALLOW_TOKEN_FOR_ORG", "allow-token-for-org")
    if creds.kind == APP and owner_type == "user":
        raise ConfigError(
            "a GitHub App installation token cannot write a user-owned project (Apps have no user-account Projects "
            "permission); use the token input with a fine-grained token, or run safo from your own gh login"
        )
    if creds.kind == PAT and owner_type == "organization" and not allowed:
        raise ConfigError(
            "a personal access token is refused for an organization-owned project; mint an App installation token "
            "(client-id and private-key inputs), or set allow-token-for-org to true to accept the risk"
        )


def _inside(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, os.path.realpath(root)]) == os.path.realpath(root)
    except ValueError:
        return False


# Set by an ambient environment, they would replace the stored github.com login `gh auth token` is meant to read.
AMBIENT_GH_VARIABLES = ("GH_HOST", "GH_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_TOKEN", "GITHUB_ENTERPRISE_TOKEN")


def find_gh(env: Mapping[str, str], repo: Path | str | None = None) -> str | None:
    """The first trustworthy `gh` on PATH. A relative or empty entry is the current directory, which a hostile
    checkout controls, so it is never searched; neither is a candidate whose real path (symlinks resolved) is inside
    the current directory, $GITHUB_WORKSPACE or the repository being operated on, because a checkout can add its own
    `bin` to an absolute PATH. The first entry that passes wins."""
    roots = [os.getcwd()]
    if env.get("GITHUB_WORKSPACE"):
        roots.append(env["GITHUB_WORKSPACE"])
    if repo:
        roots.append(str(repo))
    for entry in env.get("PATH", "").split(os.pathsep):
        if not os.path.isabs(entry):
            continue
        candidate = os.path.join(entry, "gh")
        if not (os.path.isfile(candidate) and os.access(candidate, os.X_OK)):
            continue
        real = os.path.realpath(candidate)
        if any(_inside(real, root) for root in roots):
            continue
        return candidate
    return None


def from_gh(env: Mapping[str, str], user: str = "", repo: Path | str | None = None) -> Credentials | None:
    """The caller's stored github.com login from `gh auth token` (the active account, or `--user`). None when gh is
    absent or not logged in, and always None under GitHub Actions, where the credential is the App or token input.

    The command is a fixed argument list, never a shell string, always pinned to github.com; the child gets no
    GH_HOST or token variable; stdin is closed so gh cannot prompt; its stderr is discarded and never repeated; its
    stdout is accepted only as one plain printable token.
    """
    if user and not LOGIN.fullmatch(user):
        raise ConfigError("gh-user is not a GitHub login")
    if env.get("GITHUB_ACTIONS") == "true":
        return None
    gh = find_gh(env, repo)  # an empty PATH finds nothing: tests and the Action never reach a real gh
    if gh is None:
        return None
    child = {k: v for k, v in env.items() if k not in AMBIENT_GH_VARIABLES}
    argv = [gh, "auth", "token", "--hostname", "github.com"] + (["--user", user] if user else [])
    try:
        done = subprocess.run(  # noqa: S603 - fixed argv, absolute executable, validated login, no shell
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=GH_TIMEOUT_SECONDS,
            env=child,
        )
    except (OSError, subprocess.TimeoutExpired, UnicodeDecodeError):
        return None
    token = done.stdout.strip()
    if done.returncode != 0 or not PLAIN_TOKEN.fullmatch(token):
        return None
    return Credentials(token, GH)
