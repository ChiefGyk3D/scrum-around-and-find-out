# SPDX-License-Identifier: MIT
"""Which token may write which board, decided before any request is made."""

from __future__ import annotations

import pytest

from safo import credentials
from safo.credentials import APP, GH, PAT, Credentials, NoTokenError
from safo.errors import ConfigError


def test_no_token_is_none_and_a_blank_one_too() -> None:
    assert credentials.from_env({}) is None
    assert credentials.from_env({"SAFO_TOKEN": "  "}) is None


def test_the_kind_defaults_to_app_and_is_validated() -> None:
    assert credentials.from_env({"SAFO_TOKEN": "t"}) == Credentials("t", APP)
    assert credentials.from_env({"SAFO_TOKEN": "t", "SAFO_TOKEN_KIND": PAT}) == Credentials("t", PAT)
    with pytest.raises(ConfigError, match="SAFO_TOKEN_KIND 'bogus'"):
        credentials.from_env({"SAFO_TOKEN": "t", "SAFO_TOKEN_KIND": "bogus"})


def test_the_token_is_not_in_the_repr() -> None:
    assert "SECRET" not in repr(Credentials("SECRET", APP))
    assert "SECRET" not in str(Credentials("SECRET", APP))


def test_no_token_error_is_a_config_error_so_every_handler_still_catches_it() -> None:
    assert issubclass(NoTokenError, ConfigError)


def test_an_app_token_is_refused_for_a_user_owned_board() -> None:
    with pytest.raises(ConfigError, match="cannot write a user-owned project"):
        credentials.check_for_board(Credentials("t", APP), "user", {})


def test_a_pat_is_refused_for_an_organization_board_unless_allowed() -> None:
    with pytest.raises(ConfigError, match="refused for an organization-owned project"):
        credentials.check_for_board(Credentials("t", PAT), "organization", {})
    credentials.check_for_board(Credentials("t", PAT), "organization", {"SAFO_ALLOW_TOKEN_FOR_ORG": "true"})
    credentials.check_for_board(Credentials("t", PAT), "organization", {"SAFO_ALLOW_TOKEN_FOR_ORG": " TRUE "})
    with pytest.raises(ConfigError):
        credentials.check_for_board(Credentials("t", PAT), "organization", {"SAFO_ALLOW_TOKEN_FOR_ORG": "false"})


@pytest.mark.parametrize("value", ["yes", "1", "on", "tru", "truee"])
def test_the_allow_flag_accepts_only_true_or_false(value: str) -> None:
    """A loose truthy word must not unlock the exception; an unknown word is an error, not a silent refusal."""
    with pytest.raises(ConfigError, match="allow-token-for-org"):
        credentials.check_for_board(Credentials("t", PAT), "organization", {"SAFO_ALLOW_TOKEN_FOR_ORG": value})


def test_the_allow_flag_is_checked_even_when_it_is_not_needed() -> None:
    with pytest.raises(ConfigError, match="allow-token-for-org"):
        credentials.check_for_board(Credentials("t", PAT), "user", {"SAFO_ALLOW_TOKEN_FOR_ORG": "maybe"})


@pytest.mark.parametrize(
    ("kind", "owner_type"),
    [(PAT, "user"), (GH, "user"), (GH, "organization"), (APP, "organization")],
)
def test_the_sensible_pairs_are_accepted(kind: str, owner_type: str) -> None:
    credentials.check_for_board(Credentials("t", kind), owner_type, {})
