# SPDX-License-Identifier: MIT
"""The workspace boundary: lexical and resolved forms, symlinked parents, a missing GITHUB_WORKSPACE under Actions."""

from __future__ import annotations

import argparse
import datetime as dt
import io
from pathlib import Path

import pytest

from safo.context import LocalContext
from safo.errors import ConfigError
from safo.localfiles import agents_path, local_path, outcomes_path, refuse_workspace


def ctx(home: Path, env: dict[str, str]) -> LocalContext:
    return LocalContext(io.StringIO(), {**env, "HOME": str(home)}, dt.datetime.now(dt.UTC))


def args(**kw: str) -> argparse.Namespace:
    return argparse.Namespace(**{"agents": "", "agents_local": "", "log": "", **kw})


@pytest.mark.parametrize("env", [{"GITHUB_ACTIONS": "true"}, {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": ""}])
def test_actions_without_a_workspace_refuses_every_explicit_path(tmp_path: Path, env: dict[str, str]) -> None:
    c = ctx(tmp_path / "home", env)
    for fn, a in (
        (agents_path, args(agents="agents.yaml")),
        (local_path, args(agents_local="a.local.yaml")),
        (outcomes_path, args(log="outcomes.jsonl")),
    ):
        with pytest.raises(ConfigError, match="GITHUB_WORKSPACE"):
            fn(c, a)
    for var, fn in (("SAFO_AGENTS", agents_path), ("SAFO_AGENTS_LOCAL", local_path), ("SAFO_OUTCOMES", outcomes_path)):
        with pytest.raises(ConfigError, match="GITHUB_WORKSPACE"):
            fn(ctx(tmp_path / "home", {**env, var: str(tmp_path / "x")}), args())


def test_actions_without_a_workspace_still_allows_the_home_defaults(tmp_path: Path) -> None:
    c = ctx(tmp_path / "home", {"GITHUB_ACTIONS": "true"})
    assert agents_path(c, args()) == tmp_path / "home/.config/safo/agents.yaml"
    assert local_path(c, args()) == tmp_path / "home/.config/safo/agents.local.yaml"
    assert outcomes_path(c, args()) == tmp_path / "home/.local/state/safo/outcomes.jsonl"


def test_outside_actions_an_explicit_path_in_the_current_directory_is_the_users_choice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert agents_path(ctx(tmp_path / "home", {}), args(agents="agents.yaml")) == Path("agents.yaml")


def test_a_relative_path_into_the_workspace_is_refused_by_its_lexical_form(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.chdir(ws)
    env = {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(ws)}
    for given in ("agents.yaml", "./sub/../agents.yaml", str(ws / "x" / ".." / "agents.yaml")):
        with pytest.raises(ConfigError, match="GITHUB_WORKSPACE"):
            refuse_workspace(Path(given), env, "the agents file")


def test_a_symlink_in_the_workspace_pointing_out_is_refused_by_its_lexical_form(tmp_path: Path) -> None:
    ws, outside = tmp_path / "ws", tmp_path / "outside"
    ws.mkdir()
    outside.mkdir()
    (ws / "escape").symlink_to(outside, target_is_directory=True)
    env = {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(ws)}
    with pytest.raises(ConfigError, match="GITHUB_WORKSPACE"):
        refuse_workspace(ws / "escape" / "outcomes.jsonl", env, "the outcomes log")


def test_a_symlink_outside_pointing_into_the_workspace_is_refused_by_its_resolved_form(tmp_path: Path) -> None:
    ws, elsewhere = tmp_path / "ws", tmp_path / "elsewhere"
    ws.mkdir()
    elsewhere.mkdir()
    (elsewhere / "link").symlink_to(ws, target_is_directory=True)
    env = {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(ws)}
    with pytest.raises(ConfigError, match="GITHUB_WORKSPACE"):
        refuse_workspace(elsewhere / "link" / "agents.yaml", env, "the agents file")


def test_a_symlinked_workspace_root_is_matched_in_both_forms(tmp_path: Path) -> None:
    real_ws = tmp_path / "real"
    real_ws.mkdir()
    link_ws = tmp_path / "ws-link"
    link_ws.symlink_to(real_ws, target_is_directory=True)
    env = {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(link_ws)}
    for p in (link_ws / "a.yaml", real_ws / "a.yaml"):
        with pytest.raises(ConfigError, match="GITHUB_WORKSPACE"):
            refuse_workspace(p, env, "the agents file")


def test_a_path_outside_the_workspace_is_accepted(tmp_path: Path) -> None:
    ws, other = tmp_path / "ws", tmp_path / "ws-sibling"
    ws.mkdir()
    other.mkdir()
    env = {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(ws)}
    assert refuse_workspace(other / "a.yaml", env, "the agents file") == other / "a.yaml"


def test_a_link_out_of_a_symlinked_workspace_is_refused_by_the_lexical_root(tmp_path: Path) -> None:
    real_ws, outside = tmp_path / "real", tmp_path / "outside"
    real_ws.mkdir()
    outside.mkdir()
    link_ws = tmp_path / "ws-link"
    link_ws.symlink_to(real_ws, target_is_directory=True)
    (real_ws / "escape").symlink_to(outside, target_is_directory=True)
    env = {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(link_ws)}
    with pytest.raises(ConfigError, match="GITHUB_WORKSPACE"):
        refuse_workspace(link_ws / "escape" / "o.jsonl", env, "the outcomes log")
