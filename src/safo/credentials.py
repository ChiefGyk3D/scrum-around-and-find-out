# SPDX-License-Identifier: MIT
"""Where the token comes from. The token itself is only ever held by the Client."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from safo.errors import ConfigError

APP = "app"  # a GitHub App installation token minted by actions/create-github-app-token
PAT = "token"  # a fine-grained personal access token handed to the Action
GH = "gh"  # the caller's `gh auth token`


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
