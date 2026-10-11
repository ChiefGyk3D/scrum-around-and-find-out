# SPDX-License-Identifier: MIT
"""Spec test 25: under Actions a profile-bearing agents file inside the workspace is never loaded."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentsdata import write_agents
from localcli import cli
from profiledata import doc, write


@pytest.mark.parametrize("via", ["flag", "env"])
def test_under_actions_a_profile_bearing_file_inside_the_workspace_is_refused(
    _private_home: Path, tmp_path: Path, via: str
) -> None:
    ws = tmp_path / "ws"
    path = write(ws / "sub" / "agents.yaml", doc())
    assert "profile:" in path.read_text()
    env = {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(ws)}
    flags: list[str] = []
    if via == "flag":
        flags = ["--agents", str(path)]
    else:
        env["SAFO_AGENTS"] = str(path)
    code, out, err = cli("route", "research", "--no-usage", *flags, home=_private_home, extra_env=env)
    assert code == 2 and out == "" and "inside GITHUB_WORKSPACE" in err


def test_the_same_file_outside_the_workspace_loads_under_actions(_private_home: Path, tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (tmp_path / "outside").mkdir(mode=0o700)
    outside = write_agents(tmp_path / "outside" / "agents.yaml")
    assert "profile:" in outside.read_text()
    env = {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(ws)}
    code, out, err = cli("route", "research", "--no-usage", "--agents", str(outside), home=_private_home, extra_env=env)
    assert code == 0, err
    assert "recommended:" in out


def test_under_actions_without_a_workspace_an_explicit_profile_bearing_path_is_refused(
    _private_home: Path, tmp_path: Path
) -> None:
    path = write(tmp_path / "agents.yaml", doc())
    code, _, err = cli(
        "route",
        "research",
        "--no-usage",
        "--agents",
        str(path),
        home=_private_home,
        extra_env={"GITHUB_ACTIONS": "true"},
    )
    assert code == 2 and "GITHUB_WORKSPACE is not set" in err


def test_a_symlink_from_outside_into_the_workspace_is_refused_for_a_profile_bearing_file(
    _private_home: Path, tmp_path: Path
) -> None:
    ws = tmp_path / "ws"
    real = write(ws / "agents.yaml", doc())
    link = tmp_path / "link.yaml"
    link.symlink_to(real)
    env = {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(ws)}
    code, _, err = cli("route", "research", "--no-usage", "--agents", str(link), home=_private_home, extra_env=env)
    assert code == 2 and "inside GITHUB_WORKSPACE" in err
