# SPDX-License-Identifier: MIT
"""Where the token comes from. The token itself is only ever held by the Client."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from safo.errors import ConfigError

APP = "app"  # a GitHub App installation token minted by actions/create-github-app-token
PAT = "token"  # a fine-grained personal access token handed to the Action
GH = "gh"  # the caller's `gh auth token`


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
