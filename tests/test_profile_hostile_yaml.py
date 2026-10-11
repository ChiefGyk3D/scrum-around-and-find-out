# SPDX-License-Identifier: MIT
"""Spec test 11: the hardened reader covers the profile subtree (aliases, anchors, merge keys, depth, size)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from profiledata import doc, profile, write
from safo.agentsfile import load_agents, load_agents_merged
from safo.errors import ConfigError

MARK = "ZZMARKZZ"


def marked(tmp_path: Path) -> tuple[Path, str]:
    d = doc()
    profile(d, "codex")["dont"][0]["text"] = MARK
    path = write(tmp_path / "agents.yaml", d)
    text = path.read_text()
    assert f"text: {MARK}" in text
    return path, text


def indent(text: str) -> str:
    match = re.search(rf"^( *)text: {MARK}$", text, re.MULTILINE)
    assert match
    return match[1]


def test_an_alias_inside_a_profile_is_refused(tmp_path: Path) -> None:
    path, text = marked(tmp_path)
    ws = indent(text)
    text = text.replace(f"text: {MARK}", "text: &shared Some claim.")
    text = text.replace(f"{ws}evidence:", f"{ws}note: *shared\n{ws}evidence:", 1)
    path.write_text(text)
    with pytest.raises(ConfigError, match=r"anchors are not allowed|aliases are not allowed"):
        load_agents(path)


def test_an_anchor_inside_a_profile_is_refused(tmp_path: Path) -> None:
    path, text = marked(tmp_path)
    path.write_text(text.replace(f"text: {MARK}", "text: &a A claim."))
    with pytest.raises(ConfigError, match=r"anchors are not allowed|aliases are not allowed"):
        load_agents(path)


def test_a_merge_key_inside_a_profile_is_refused(tmp_path: Path) -> None:
    path, text = marked(tmp_path)
    ws = indent(text)
    path.write_text(text.replace(f"text: {MARK}", f"text: A claim.\n{ws}<<: {{x: 1}}"))
    with pytest.raises(ConfigError, match=r"merge keys"):
        load_agents(path)


def test_a_duplicate_key_inside_a_profile_is_refused(tmp_path: Path) -> None:
    path, text = marked(tmp_path)
    ws = indent(text)
    path.write_text(text.replace(f"text: {MARK}", f"text: One.\n{ws}text: Two."))
    with pytest.raises(ConfigError, match="duplicate key 'text'"):
        load_agents(path)
    path, text = marked(tmp_path)
    path.write_text(
        re.sub(r"^(\s+)status: profiled$", r"\1status: profiled\n\1status: unmeasured", text, count=1, flags=re.M)
    )
    with pytest.raises(ConfigError, match="duplicate key 'status'"):
        load_agents(path)


def test_nesting_inside_a_profile_is_bounded(tmp_path: Path) -> None:
    path, text = marked(tmp_path)
    path.write_text(text.replace(f"text: {MARK}", "text: " + "[" * 65 + "0" + "]" * 65))
    with pytest.raises(ConfigError, match="nesting exceeds maximum depth"):
        load_agents(path)


def test_a_file_over_one_mebibyte_is_refused_even_if_the_excess_is_inside_a_profile(tmp_path: Path) -> None:
    path, text = marked(tmp_path)
    path.write_text(text.replace(f"text: {MARK}", "text: " + "x" * 1_100_000))
    with pytest.raises(ConfigError, match="exceeds maximum size"):
        load_agents(path)


def test_a_non_string_key_inside_a_profile_is_refused(tmp_path: Path) -> None:
    path, text = marked(tmp_path)
    ws = indent(text)
    path.write_text(text.replace(f"text: {MARK}", f"text: A claim.\n{ws}1: x"))
    with pytest.raises(ConfigError, match=r"mapping key must be a string"):
        load_agents(path)


def test_a_profile_in_the_local_override_is_hostile_too(tmp_path: Path) -> None:
    base = write(tmp_path / "base.yaml", doc())
    local = tmp_path / "local.yaml"
    local.write_text("agents:\n  codex:\n    profile: &a {status: unmeasured}\n    x: *a\n")
    with pytest.raises(ConfigError, match=r"aliases|anchors"):
        load_agents_merged(base, local)


def test_a_profile_in_the_local_override_is_refused_whole(tmp_path: Path) -> None:
    base = write(tmp_path / "base.yaml", doc())
    for text in (
        "agents:\n  codex:\n    profile: {status: unmeasured, brief: {inline: x}}\n",
        "profile_migration: {agents: []}\n",
        "promotion: {min_outcomes: 3}\n",
    ):
        local = tmp_path / "local.yaml"
        local.write_text(text)
        with pytest.raises(ConfigError, match="local override"):
            load_agents_merged(base, local)


def test_yaml_is_loaded_by_the_safe_loader_only() -> None:
    assert yaml.safe_load("a: 1") == {"a": 1}
    root = Path(__file__).parent.parent / "src" / "safo"
    for name in ("profile.py", "trust.py", "agentsfile.py"):
        text = (root / name).read_text()
        assert not re.search(r"yaml\.(load|full_load|unsafe_load|load_all)\b", text.replace("safe_load", "")), name
