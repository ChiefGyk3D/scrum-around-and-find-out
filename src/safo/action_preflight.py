# SPDX-License-Identifier: MIT
"""Everything the Action can refuse before it mints a token, fetches a key or sends a request.

Runs as `python -m safo.action_preflight` with the inputs in the environment (never in argv or a template). It is
handed whether a private key and a token were given (HAS_PRIVATE_KEY, HAS_TOKEN), never their values.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Mapping
from pathlib import Path, PurePosixPath

from safo import compat, credentials, output
from safo.credentials import APP, PAT
from safo.errors import ConfigError, MalformedDataError, SafoError
from safo.modes import LocalMode, load_all
from safo.modes.status import STATES
from safo.schema import LOGIN, REPO_NAME, Board, load_board
from safo.values import whole_number

# Local modes (usage, route, outcome, local, hooks, ...) read files on a person's machine; the Action runs none of them.
MODES = frozenset(name for name, mode in load_all().items() if not isinstance(mode, LocalMode)) | {"validate"}
BOARD_LESS_MODES = frozenset({"sync", "reconcile", "status", "validate"})  # a board with no fields cannot be audited
READS = (
    "SAFO_MODE",
    "SAFO_BOARD",
    "SAFO_PROJECT_URL",
    "SAFO_STATUS_FIELD",
    "SAFO_STATUS_OPEN_ISSUE",
    "SAFO_STATUS_OPEN_PR",
    "SAFO_STATUS_DRAFT_PR",
    "SAFO_STATUS_DONE",
    "SAFO_DONE_DATE_FIELD",
    "SAFO_DEFAULT_AREA_FIELD",
    "SAFO_DEFAULT_AREA",
    "SAFO_ALLOW_TOKEN_FOR_ORG",
    "SAFO_STATUS_BODY_FILE",
    "SAFO_STATUS_STATE",
    "SAFO_DRY_RUN",
    "GITHUB_WORKSPACE",
    "GITHUB_REPOSITORY",
    "HAS_PRIVATE_KEY",
    "HAS_TOKEN",
    "CLIENT_ID",
    "APP_ID",
    "APP_OWNER",
    "REPOSITORIES",
    "REPOSITORY_OWNER",
    "REPO_PRIVATE",
    "DOPPLER_IDENTITY_ID",
    "DOPPLER_PROJECT",
    "DOPPLER_CONFIG",
    "EVENT_NAME",
    "IS_FORK",
)
_CLIENT_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")
_SLUG = re.compile(r"[A-Za-z0-9._-]{1,64}")
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def shown(text: str) -> str:
    """Untrusted text as a short, escaped, quoted fragment of a message."""
    return repr(output.line(text[:80]))


def boolean(env: Mapping[str, str], name: str, label: str, *, default: str = "false") -> bool:
    value = env.get(name, default)
    if value not in ("true", "false"):
        raise ConfigError(f"{label} must be true or false, not {shown(value)}")
    return value == "true"


def workspace_path(env: Mapping[str, str], text: str, label: str) -> str:
    """The real path of a file the Action reads, which must stay inside the workspace: relative, no `..`, no control
    characters, and once every symlink is followed still under the real workspace. Returns that real path."""
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or text[0] in "-~" or any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise ConfigError(f"{label} {shown(text)} must be a path inside the workspace")
    workspace = os.path.realpath(env.get("GITHUB_WORKSPACE") or os.getcwd())
    real = os.path.realpath(os.path.join(workspace, text))
    if not Path(real).is_relative_to(workspace):
        raise ConfigError(f"{label} {shown(text)} must be a path inside the workspace")
    return real


def check_board_source(env: Mapping[str, str]) -> Board:
    mode = env.get("SAFO_MODE", "")
    file, url = env.get("SAFO_BOARD", ""), env.get("SAFO_PROJECT_URL", "")
    if file and url:
        raise ConfigError("pass board-file or project-url, not both")
    if not file and not url:
        raise ConfigError("pass board-file, or project-url for the board-less mode")
    if url:
        if mode not in BOARD_LESS_MODES:
            raise ConfigError(f"mode {mode} needs board-file: the board-less inputs describe no fields to check")
        return compat.board_from_env(env)
    return load_board(workspace_path(env, file, "board-file"))


def check_repositories(text: str) -> list[str]:
    """The explicit repository list, as names. Control characters are refused whole, before any splitting."""
    if not text:
        return []
    if any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise ConfigError("repositories must not contain control characters")
    names = [part.strip() for part in text.split(",")]
    for name in names:
        if not REPO_NAME.fullmatch(name) or name in (".", ".."):
            raise ConfigError(f"repositories: {shown(name)} is not a repository name (names only, comma separated)")
    return names


def token_scope(env: Mapping[str, str], board: Board, explicit: list[str]) -> str:
    """The repositories the installation token is limited to, comma separated; never empty.

    Only repositories owned by the account the token is minted for can be named. Default: those board.yaml lists
    (the calling repository in the board-less mode); with none listed, the calling repository when it belongs to
    that account. An explicit list must be a subset of what the board lists, or, when it lists none, the calling
    repository itself. If nothing can be named the token is not minted: it is never installation-wide.
    """
    repo_owner = env.get("REPOSITORY_OWNER", "")
    owner = (env.get("APP_OWNER") or repo_owner).lower()
    listed: dict[str, str] = {}
    for repo in board.repositories:
        if repo.owner.lower() == owner:
            listed.setdefault(repo.name.lower(), repo.name)
    calling = env.get("GITHUB_REPOSITORY", "").partition("/")[2]
    own = owner == repo_owner.lower() and bool(calling)  # the calling repository belongs to the token's owner
    if explicit:
        chosen: dict[str, str] = {}
        for name in explicit:
            if listed:
                if name.lower() not in listed:
                    raise ConfigError(f"repositories: {shown(name)} is not listed in the board")
            elif not (own and name.lower() == calling.lower()):
                if not own:
                    raise ConfigError(no_repository_message(owner))
                raise ConfigError(f"repositories: {shown(name)} is not listed in the board")
            chosen.setdefault(name.lower(), listed[name.lower()] if listed else calling)
        return ",".join(chosen.values())
    if listed:
        return ",".join(listed.values())
    if own:
        return calling
    raise ConfigError(no_repository_message(owner))


def no_repository_message(owner: str) -> str:
    return (
        f"the board lists no repository owned by {shown(owner)}, whose installation the token would be minted for; "
        "an installation-wide token is never minted, so list the repositories in board.yaml"
    )


def check_status_state(env: Mapping[str, str]) -> None:
    if env.get("SAFO_MODE") == "status" and env.get("SAFO_STATUS_STATE", "ON_TRACK") not in STATES:
        raise ConfigError(f"status-state {shown(env.get('SAFO_STATUS_STATE', ''))} is not one of {', '.join(STATES)}")


def check_app_owner(env: Mapping[str, str], *, has_token: bool) -> None:
    owner = env.get("APP_OWNER", "")
    if not owner:
        return
    if not LOGIN.fullmatch(owner):
        raise ConfigError(f"app-owner {shown(owner)} is not a GitHub login")
    if has_token:
        raise ConfigError("app-owner applies to an App installation token, not to the token input")
    if owner.lower() != env.get("REPOSITORY_OWNER", "").lower() and env.get("REPO_PRIVATE") != "false":
        raise ConfigError(
            "app-owner names another account's installation, whose token can read this repository's issues and pull "
            "requests only if the repository is public; this one is private or its visibility is unknown"
        )


def check_doppler(env: Mapping[str, str]) -> bool:
    """Whether the key is to come from Doppler. All three settings, valid, or none."""
    identity, project, config = (env.get(k, "") for k in ("DOPPLER_IDENTITY_ID", "DOPPLER_PROJECT", "DOPPLER_CONFIG"))
    if not (identity or project or config):
        return False
    if not (identity and project and config):
        raise ConfigError("doppler-identity-id, doppler-project and doppler-config go together: set all three or none")
    if not _UUID.fullmatch(identity):
        raise ConfigError("doppler-identity-id is not a UUID")
    if not _SLUG.fullmatch(project) or not _SLUG.fullmatch(config):
        raise ConfigError("doppler-project and doppler-config are slugs of letters, digits, dot, dash and underscore")
    return True


def check_app_identifier(env: Mapping[str, str]) -> None:
    client, app = env.get("CLIENT_ID", ""), env.get("APP_ID", "")
    if client:
        if not _CLIENT_ID.fullmatch(client):
            raise ConfigError("client-id is not a GitHub App Client ID")
        return
    if not app:
        raise ConfigError("a private key needs client-id (or the deprecated app-id)")
    try:
        number = whole_number(app, "app-id")
    except MalformedDataError:
        raise ConfigError("app-id must be a whole number") from None
    if number < 1:
        raise ConfigError("app-id must be a whole number")


def check(env: Mapping[str, str]) -> str:
    """Refuse anything wrong; return the repositories the installation token is to be limited to."""
    mode = env.get("SAFO_MODE", "")
    if mode not in MODES:
        raise ConfigError(f"mode {shown(mode)} is not one of {', '.join(sorted(MODES))}")
    boolean(env, "SAFO_DRY_RUN", "dry-run", default="")
    board = check_board_source(env)
    if env.get("SAFO_STATUS_BODY_FILE"):
        workspace_path(env, env["SAFO_STATUS_BODY_FILE"], "status-body-file")
    check_status_state(env)
    if mode == "validate":
        return ""
    has_key = boolean(env, "HAS_PRIVATE_KEY", "private-key presence")
    has_token = boolean(env, "HAS_TOKEN", "token presence")
    from_doppler = check_doppler(env)
    explicit = check_repositories(env.get("REPOSITORIES", ""))
    check_app_owner(env, has_token=has_token)
    if has_key and has_token:
        raise ConfigError("pass either an App (client-id and private-key) or a token, not both")
    if from_doppler and has_token:
        raise ConfigError("the doppler inputs supply an App key; they cannot be combined with the token input")
    if from_doppler and has_key:
        raise ConfigError("pass the App key as private-key or from Doppler, not both")
    fork_pull_request = boolean(env, "IS_FORK", "fork flag") and env.get("EVENT_NAME") == "pull_request"
    if fork_pull_request and (has_key or has_token):
        raise ConfigError("a pull request from a fork never receives a literal private-key or token input")
    if from_doppler and fork_pull_request:
        raise ConfigError("a pull request from a fork never receives the App key: no Doppler fetch")
    if not (has_key or has_token or from_doppler):
        raise ConfigError(
            "no credential: pass client-id with private-key (or Doppler), or token for a user-owned board"
        )
    if has_token:
        kind = PAT
    else:
        check_app_identifier(env)
        kind = APP
    # Only the kind matters to the rules, never the secret.
    credentials.check_for_board(credentials.Credentials("preflight", kind), board.project.owner_type, env)
    return "" if has_token else token_scope(env, board, explicit)


def main() -> int:
    try:
        scope = check(dict(os.environ))
        if os.environ.get("GITHUB_OUTPUT"):
            output.set_output(os.environ["GITHUB_OUTPUT"], "repositories", scope)
    except SafoError as err:
        output.annotation(sys.stderr, str(err))
        return err.exit_code
    return 0


if __name__ == "__main__":
    sys.exit(main())
