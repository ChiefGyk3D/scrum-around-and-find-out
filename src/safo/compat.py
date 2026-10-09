# SPDX-License-Identifier: MIT
"""A board without a board.yaml: the inputs of GYST's project-sync.yml, so its callers need not change.

`board_from_env` turns SAFO_PROJECT_URL and the status/area inputs into the one-repository Board that GYST's script
worked from (the calling repository, GITHUB_REPOSITORY). `fields` is empty: the names are checked against the live
project at run time instead.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from safo.errors import ConfigError
from safo.output import line
from safo.schema import LOGIN, REPO_NAME, AgentsView, Board, Project, Repository, Rules, StatusRules
from safo.values import whole_number

PROJECT_URL = re.compile(r"https://github\.com/(users|orgs)/([A-Za-z0-9-]+)/projects/([0-9]{1,10})/?")
MAX_NAME = 200
EXPECTED = "https://github.com/orgs/<login>/projects/<n> or https://github.com/users/<login>/projects/<n>"


def parse_project_url(url: str) -> Project:
    match = PROJECT_URL.fullmatch(url.strip())
    if not match or not LOGIN.fullmatch(match[2]):
        # The text is what a caller typed: shown escaped and clipped, never raw.
        raise ConfigError(
            f"project-url {line(url.strip()[:120])!r} is not a GitHub Projects v2 URL; expected {EXPECTED}"
        )
    number = whole_number(match[3], "project-url number")
    if number < 1:
        raise ConfigError(f"project-url {line(url.strip()[:120])!r}: the project number starts at 1")
    return Project(match[2], "user" if match[1] == "users" else "organization", number, "")


def _name(env: Mapping[str, str], variable: str, default: str, *, empty: bool = False) -> str:
    value = env.get(variable, default)
    label = variable.removeprefix("SAFO_").lower().replace("_", "-")
    if value == "" and empty:
        return value
    if not value.strip() or len(value) > MAX_NAME or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ConfigError(f"{label} must be a name of 1 to {MAX_NAME} characters with no control characters")
    return value


def board_from_env(env: Mapping[str, str]) -> Board:
    repo_full = env.get("GITHUB_REPOSITORY", "")
    owner, _, name = repo_full.partition("/")
    if not (LOGIN.fullmatch(owner) and REPO_NAME.fullmatch(name) and name not in (".", "..")):
        raise ConfigError(
            "GITHUB_REPOSITORY is not set to owner/name; the board-less mode works on the calling repository"
        )
    area_field = _name(env, "SAFO_DEFAULT_AREA_FIELD", "", empty=True)
    area = _name(env, "SAFO_DEFAULT_AREA", "", empty=True)
    if bool(area_field) != bool(area):
        raise ConfigError("default-area-field and default-area go together: set both or neither")
    opened = _name(env, "SAFO_STATUS_OPEN_ISSUE", "Backlog")
    done = _name(env, "SAFO_STATUS_DONE", "Done")
    rules = Rules(
        status_field=_name(env, "SAFO_STATUS_FIELD", "Status"),
        area_field=area_field or "Area",
        status=StatusRules(
            opened=opened,
            reopened=opened,
            closed=done,
            merged=done,
            opened_pr=_name(env, "SAFO_STATUS_OPEN_PR", "In progress"),
            draft_pr=_name(env, "SAFO_STATUS_DRAFT_PR", "Backlog"),
        ),
        done_date_field=_name(env, "SAFO_DONE_DATE_FIELD", "Done on", empty=True),
    )
    return Board(
        project=parse_project_url(env.get("SAFO_PROJECT_URL", "")),
        repositories=(Repository(owner, name, area or None),),
        fields=(),
        views=(),
        rules=rules,
        agents=AgentsView(),
    )
