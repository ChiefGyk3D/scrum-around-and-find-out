# SPDX-License-Identifier: MIT
"""safo hooks: the session probe, the dispatch guard, the settings merge and the mode.

Every rule of the guard has a test that fails when the rule is removed, and a hook that meets garbage fails open.
"""

from __future__ import annotations

import datetime as dt
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from agentsdata import A_MODELS, B_MODELS, agents_dict
from fakeollama import FakeOllama
from hooksdata import (
    agents_file,
    block_reprobe,
    dispatch,
    hooks,
    probe_file,
    read_log,
    set_mode,
    set_probe,
    state_folder,
)
from meterdata import NOW
from safo.agentsfile import Endpoint
from safo.cli import main
from safo.errors import ConfigError
from safo.guardlog import read_log as read_guard_log
from safo.guardlog import summarise
from safo.hooks import append_log
from safo.ollama import Probe


@pytest.fixture
def agents(tmp_path: Path) -> Path:
    return agents_file(tmp_path / "agents.yaml")


def guard(home: Path, agents: Path, payload: str, **kwargs: Any) -> tuple[int, str, str]:
    return hooks("guard", "--agents", str(agents), home=home, stdin=payload, **kwargs)


def read_after(home: Path, agents: Path, payload: str) -> dict[str, Any]:
    assert guard(home, agents, payload)[0] == 0
    return read_log(home)[-1]


def reason(output: str) -> str:
    data = json.loads(output)
    return str(data["hookSpecificOutput"].get("permissionDecisionReason") or data["systemMessage"])


# -- install: merge into settings.json without replacing anything --------------------------------------------


def test_install_adds_the_session_probe_and_the_agent_guard_to_a_new_settings_file(_private_home: Path) -> None:
    settings = _private_home / "settings.json"
    code, out, _ = hooks("install", "--settings", str(settings), home=_private_home)
    assert code == 0 and "installed the SessionStart probe and the PreToolUse (Agent) guard" in out
    data = json.loads(settings.read_text())
    assert data["hooks"]["SessionStart"] == [
        {
            "hooks": [
                {
                    "type": "command",
                    "command": "safo hooks probe",
                    "timeout": 15,
                    "statusMessage": "Checking the local LLM...",
                }
            ]
        }
    ]
    assert data["hooks"]["PreToolUse"] == [
        {"matcher": "Agent|Task", "hooks": [{"type": "command", "command": "safo hooks guard", "timeout": 10}]}
    ]
    assert "Start with warn" in out and not (_private_home / ".config" / "safo" / "mode").exists()


def test_install_defaults_to_the_settings_file_in_the_home_directory(_private_home: Path) -> None:
    assert hooks("install", home=_private_home)[0] == 0
    assert "safo hooks guard" in (_private_home / ".claude" / "settings.json").read_text()


def test_install_keeps_every_existing_hook_and_setting(_private_home: Path) -> None:
    settings = _private_home / "settings.json"
    mine: dict[str, Any] = {
        "model": "opus",
        "permissions": {"allow": ["Bash(ls)"]},
        "hooks": {
            "SessionStart": [{"hooks": [{"type": "command", "command": "~/bin/session-start", "timeout": 10}]}],
            "PreToolUse": [
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "~/bin/bash-guard"}]},
                {"matcher": "Agent|Task", "hooks": [{"type": "command", "command": "~/bin/other-agent-hook"}]},
            ],
            "Stop": [{"hooks": [{"type": "command", "command": "~/bin/sync"}]}],
        },
    }
    settings.write_text(json.dumps(mine))
    assert hooks("install", "--settings", str(settings), home=_private_home)[0] == 0
    data = json.loads(settings.read_text())
    assert data["model"] == "opus" and data["permissions"] == mine["permissions"]
    assert data["hooks"]["Stop"] == mine["hooks"]["Stop"]
    assert data["hooks"]["SessionStart"][0] == mine["hooks"]["SessionStart"][0]
    assert data["hooks"]["PreToolUse"][:2] == mine["hooks"]["PreToolUse"]
    assert [g["hooks"][0]["command"] for g in data["hooks"]["SessionStart"]] == [
        "~/bin/session-start",
        "safo hooks probe",
    ]
    assert data["hooks"]["PreToolUse"][2]["hooks"][0]["command"] == "safo hooks guard"
    assert len(data["hooks"]["PreToolUse"]) == 3


def test_install_twice_changes_nothing_the_second_time(_private_home: Path) -> None:
    settings = _private_home / "settings.json"
    hooks("install", "--settings", str(settings), home=_private_home)
    first = settings.read_bytes()
    code, out, _ = hooks("install", "--settings", str(settings), home=_private_home)
    assert code == 0 and "already installed" in out and settings.read_bytes() == first
    data = json.loads(first)
    assert len(data["hooks"]["SessionStart"]) == 1 and len(data["hooks"]["PreToolUse"]) == 1


def test_install_with_another_agents_path_rewrites_its_own_command_and_adds_no_second_copy(
    _private_home: Path, agents: Path
) -> None:
    settings = _private_home / "settings.json"
    hooks("install", "--settings", str(settings), home=_private_home)
    assert hooks("install", "--settings", str(settings), "--agents", str(agents), home=_private_home)[0] == 0
    data = json.loads(settings.read_text())
    assert len(data["hooks"]["SessionStart"]) == 1 and len(data["hooks"]["PreToolUse"]) == 1
    assert data["hooks"]["SessionStart"][0]["hooks"][0]["command"] == f"safo hooks probe --agents {agents.resolve()}"
    assert data["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == f"safo hooks guard --agents {agents.resolve()}"


def test_install_uses_the_command_it_is_given_and_refuses_one_that_is_not_a_plain_program(_private_home: Path) -> None:
    settings = _private_home / "settings.json"
    assert hooks("install", "--settings", str(settings), "--command", "python3 -m safo", home=_private_home)[0] == 0
    assert json.loads(settings.read_text())["hooks"]["SessionStart"][0]["hooks"][0]["command"] == (
        "python3 -m safo hooks probe"
    )
    other = _private_home / "other.json"
    code, _, err = hooks("install", "--settings", str(other), "--command", "safo; rm -rf x", home=_private_home)
    assert code == 2 and "--command" in err and not other.exists()


def _safo_executable(tmp_path: Path) -> Path:
    exe = tmp_path / "venv" / "bin" / "safo"
    exe.parent.mkdir(parents=True)
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    return exe


def test_install_accepts_the_absolute_path_of_a_safo_executable(_private_home: Path, tmp_path: Path) -> None:
    exe = _safo_executable(tmp_path)
    settings = _private_home / "settings.json"
    assert hooks("install", "--settings", str(settings), "--command", str(exe), home=_private_home)[0] == 0
    data = json.loads(settings.read_text())
    assert data["hooks"]["SessionStart"][0]["hooks"][0]["command"] == f"{exe} hooks probe"
    assert data["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == f"{exe} hooks guard"
    before = settings.read_bytes()
    code, out, _ = hooks("install", "--settings", str(settings), "--command", str(exe), home=_private_home)
    assert code == 0 and "already installed" in out and settings.read_bytes() == before, "ownership: a rerun is a no-op"
    moved = tmp_path / "agents.yaml"  # the same launcher with other flags is the same hook: replaced, never duplicated
    flags = ("--command", str(exe), "--agents", str(moved))
    assert hooks("install", "--settings", str(settings), *flags, home=_private_home)[0] == 0
    starts = json.loads(settings.read_text())["hooks"]["SessionStart"]
    assert len(starts) == 1 and starts[0]["hooks"][0]["command"] == f"{exe} hooks probe --agents {moved.resolve()}"
    pipx = tmp_path / "pipx" / "safo"  # pipx exposes a symlink to the venv's script
    pipx.parent.mkdir()
    pipx.symlink_to(exe)
    other = _private_home / "pipx.json"
    assert hooks("install", "--settings", str(other), "--command", str(pipx), home=_private_home)[0] == 0


@pytest.mark.parametrize("case", ["missing", "not-executable", "directory", "other-name", "relative", "dotdot"])
def test_install_refuses_a_launcher_path_that_is_not_an_executable_safo(
    _private_home: Path, tmp_path: Path, case: str
) -> None:
    exe = _safo_executable(tmp_path)
    command = {
        "missing": str(tmp_path / "nowhere" / "safo"),
        "not-executable": str(exe),
        "directory": str(tmp_path / "safo"),
        "other-name": str(exe.with_name("python3")),
        "relative": "venv/bin/safo",
        "dotdot": f"{tmp_path}/venv/bin/../bin/safo",
    }[case]
    if case == "not-executable":
        exe.chmod(0o644)
    if case == "other-name":
        exe.with_name("python3").write_text("#!/bin/sh\n")
        exe.with_name("python3").chmod(0o755)
    if case == "directory":
        (tmp_path / "safo").mkdir()
    settings = _private_home / "settings.json"
    code, _, err = hooks("install", "--settings", str(settings), "--command", command, home=_private_home)
    assert code == 2 and "--command" in err and not settings.exists()


@pytest.mark.parametrize(
    "text,message",
    [
        ("{not json", "invalid JSON"),
        ("[]", "the top level is not a JSON object"),
        ('{"hooks": []}', "hooks is not an object"),
        ('{"hooks": {"SessionStart": {}}}', "invalid hook groups"),
        ('{"hooks": {"PreToolUse": [{"hooks": {}}]}}', "invalid hooks list"),
    ],
    ids=["not-json", "not-object", "hooks-list", "event-dict", "group-hooks-dict"],
)
def test_install_refuses_a_settings_file_it_cannot_merge_into_and_leaves_it_alone(
    _private_home: Path, text: str, message: str
) -> None:
    settings = _private_home / "settings.json"
    settings.write_text(text)
    code, _, err = hooks("install", "--settings", str(settings), home=_private_home)
    assert code == 2 and message in err and settings.read_text() == text


def test_install_writes_through_a_symlinked_settings_file_and_keeps_its_permissions(_private_home: Path) -> None:
    target = _private_home / "dotfiles" / "settings.json"
    target.parent.mkdir()
    target.write_text("{}")
    target.chmod(0o640)
    link = _private_home / "link.json"
    link.symlink_to(target)
    assert hooks("install", "--settings", str(link), home=_private_home)[0] == 0
    assert link.is_symlink() and "safo hooks guard" in target.read_text()
    assert target.stat().st_mode & 0o777 == 0o640


def test_install_sets_the_mode_only_when_asked_and_a_dry_run_writes_nothing(_private_home: Path) -> None:
    settings = _private_home / "settings.json"
    code, out, _ = hooks("install", "--settings", str(settings), "--mode", "block", home=_private_home, dry_run=True)
    assert code == 0 and "dry run" in out and not settings.exists()
    assert not (_private_home / ".config" / "safo" / "mode").exists()
    assert hooks("install", "--settings", str(settings), "--mode", "block", home=_private_home)[0] == 0
    assert (_private_home / ".config" / "safo" / "mode").read_text() == "block\n"


def test_install_with_a_shared_config_directory_stops_with_one_line_and_leaves_settings_alone(
    _private_home: Path,
) -> None:
    config = _private_home / ".config" / "safo"
    config.mkdir(parents=True)
    config.chmod(0o775)
    settings = _private_home / "settings.json"
    code, out, err = hooks("install", "--settings", str(settings), "--mode", "warn", home=_private_home)
    assert code != 0 and "chmod 700" in (out + err) and "Traceback" not in (out + err)
    assert not settings.exists(), "the mode is checked first, so a refusal changes nothing"


# -- probe: SessionStart -------------------------------------------------------------------------------------


def test_probe_reports_a_reachable_local_llm_and_saves_the_state_under_the_xdg_state_home(
    _private_home: Path, tmp_path: Path
) -> None:
    with FakeOllama(A_MODELS, A_MODELS).serve() as a, FakeOllama(B_MODELS, B_MODELS[:1]).serve() as b:
        path = agents_file(tmp_path / "agents.yaml", a.url, b.url)
        xdg = tmp_path / "xdg"
        code, out, _ = hooks("probe", "--agents", str(path), home=_private_home, env={"XDG_STATE_HOME": str(xdg)})
        assert [(m, p) for m, p, _ in a.requests] == [("GET", "/api/tags"), ("GET", "/api/ps")]
        assert a.generates == [] and b.generates == [], "a probe asks what is loaded and never loads anything"
    assert code == 0
    event = json.loads(out)["hookSpecificOutput"]
    assert event["hookEventName"] == "SessionStart"
    assert "Local LLM: REACHABLE." in event["additionalContext"]
    assert "configured local step" in event["additionalContext"]
    assert "not-applicable marker and reason" in event["additionalContext"]
    from safo.agentsfile import load_agents
    from safo.hooks import state_path

    saved = json.loads(state_path(xdg / "safo" / "hooks", "session-a", load_agents(path)).read_text())
    assert saved["reachable"] is True and NOW.timestamp() <= saved["ts"] < NOW.timestamp() + 15
    assert len(saved["endpoints"]) == 2 and all(set(r) == {"general", "reachable"} for r in saved["endpoints"])
    assert "127.0.0.1" not in json.dumps(saved), "the state keeps no addresses"


def test_probe_reports_an_unreachable_local_llm_and_still_succeeds(_private_home: Path, agents: Path) -> None:
    code, out, _ = hooks("probe", "--agents", str(agents), home=_private_home)
    assert code == 0
    message = json.loads(out)["hookSpecificOutput"]["additionalContext"]
    assert message.startswith("Local LLM: UNREACHABLE") and "not required in briefs" in message
    assert json.loads(probe_file(_private_home, agents).read_text())["reachable"] is False


def test_probe_counts_only_a_general_endpoint_as_the_local_llm_being_there(_private_home: Path, tmp_path: Path) -> None:
    with FakeOllama(B_MODELS, B_MODELS[:1]).serve() as guard_only:
        path = agents_file(tmp_path / "agents.yaml", "http://127.0.0.1:9", guard_only.url)
        code, out, _ = hooks("probe", "--agents", str(path), home=_private_home)
    assert code == 0 and "UNREACHABLE" in out
    assert json.loads(probe_file(_private_home, path).read_text())["reachable"] is False


@pytest.mark.parametrize("broken", ["missing", "garbage"])
def test_probe_never_fails_the_session_even_when_agents_yaml_is_broken(
    _private_home: Path, tmp_path: Path, broken: str
) -> None:
    path = tmp_path / "agents.yaml"
    if broken == "garbage":
        path.write_text("a: [unclosed\n")
    code, out, _ = hooks("probe", "--agents", str(path), home=_private_home)
    assert code == 0 and "SAFO routing guard degraded" in out
    assert read_log(_private_home)[-1]["diagnostic"] == "config"


def test_a_later_unreachable_probe_overwrites_an_earlier_reachable_one(_private_home: Path, agents: Path) -> None:
    set_probe(_private_home, reachable=True)
    hooks("probe", "--agents", str(agents), home=_private_home)
    assert json.loads(probe_file(_private_home, agents).read_text())["reachable"] is False


# -- guard rule 1: an explicit model -------------------------------------------------------------------------


def test_a_dispatch_with_no_model_is_flagged_in_warn_mode_but_allowed(_private_home: Path, agents: Path) -> None:
    code, out, _ = guard(_private_home, agents, dispatch(model=None))
    assert code == 0
    data = json.loads(out)
    assert "no explicit `model`" in data["systemMessage"] and "(warn mode: allowed)" in data["systemMessage"]
    assert "permissionDecision" not in data["hookSpecificOutput"]
    assert read_log(_private_home)[0]["decision"] == "warn" and read_log(_private_home)[0]["rules"] == ["no-model"]


def test_a_dispatch_with_no_model_is_denied_in_block_mode(_private_home: Path, agents: Path) -> None:
    set_mode(_private_home, "block")
    code, out, _ = guard(_private_home, agents, dispatch(model=None))
    decision = json.loads(out)["hookSpecificOutput"]
    assert code == 0 and decision["permissionDecision"] == "deny"
    assert decision["hookEventName"] == "PreToolUse" and "no explicit `model`" in decision["permissionDecisionReason"]
    assert read_log(_private_home)[0]["decision"] == "deny"


@pytest.mark.parametrize("model", ["", "   ", None])
def test_an_empty_model_is_no_model(_private_home: Path, agents: Path, model: str | None) -> None:
    assert "no-model" in read_after(_private_home, agents, dispatch(model=model))["rules"]


def test_a_fork_with_no_model_cannot_be_told_from_an_unapproved_parent_model_so_it_needs_the_token(
    _private_home: Path, agents: Path
) -> None:
    set_probe(_private_home)
    set_mode(_private_home, "block")
    code, out, _ = guard(_private_home, agents, dispatch(model=None, subagent_type="fork"))
    assert code == 0 and json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    row = read_log(_private_home)[0]
    assert row["rules"] == ["unknown-model"] and row["model"] == "unknown"
    ok = dispatch(model=None, subagent_type="fork", prompt="safo local run. OPUS-APPROVED: he said so")
    assert guard(_private_home, agents, ok)[1] == ""


@pytest.mark.parametrize("model", ["inherit", "INHERIT", "arbitrary-garbage", "gpt-5", "opus-but-not", "sonnet 4"])
def test_a_model_that_is_not_a_known_agent_id_or_alias_needs_the_token_like_opus_does(
    _private_home: Path, agents: Path, model: str
) -> None:
    set_probe(_private_home)
    set_mode(_private_home, "block")
    code, out, _ = guard(_private_home, agents, dispatch(model=model))
    assert code == 0 and json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "unknown-model" in reason(out) or "unknown model" in reason(out)
    assert model not in out, "the raw value is never echoed"
    row = read_log(_private_home)[0]
    assert row["rules"] == ["unknown-model"] and row["model"] == "unknown"
    ok = dispatch(model=model, prompt="safo local run. OPUS-APPROVED: he said so")
    assert guard(_private_home, agents, ok)[1] == "" and read_log(_private_home)[-1]["decision"] == "allow"


def test_an_unknown_model_only_warns_in_warn_mode_and_a_known_model_is_not_flagged(
    _private_home: Path, agents: Path
) -> None:
    set_probe(_private_home)
    assert read_after(_private_home, agents, dispatch(model="inherit"))["decision"] == "warn"
    assert read_after(_private_home, agents, dispatch(model="sonnet"))["rules"] == []
    assert read_after(_private_home, agents, dispatch(model=None))["rules"] == ["no-model"]


# -- guard rule 2: the approval token for a model that needs the maintainer's OK -----------------------------


@pytest.mark.parametrize("model", ["opus", "Opus", "claude-opus-5-5"])
def test_opus_without_the_approval_token_is_denied_in_block_mode_without_printing_the_token(
    _private_home: Path, agents: Path, model: str
) -> None:
    set_mode(_private_home, "block")
    code, out, _ = guard(_private_home, agents, dispatch(model=model))
    assert code == 0 and json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "OPUS-APPROVED" not in out, "the reason names the setting, not the token"
    assert "hooks.approval_token" in reason(out) and read_log(_private_home)[0]["rules"] == ["approval"]


def test_opus_with_the_approval_token_in_the_brief_is_allowed(_private_home: Path, agents: Path) -> None:
    set_probe(_private_home)
    set_mode(_private_home, "block")
    brief = "Review the branch. safo local run --shape ci-log-summary. OPUS-APPROVED: he said so on the 7th."
    code, out, _ = guard(_private_home, agents, dispatch(model="opus", prompt=brief))
    assert code == 0 and out == "" and read_log(_private_home)[0]["decision"] == "allow"


def test_the_token_and_the_models_that_need_it_come_from_agents_yaml_not_from_the_code(
    _private_home: Path, tmp_path: Path
) -> None:
    data = agents_dict()
    data["agents"]["claude-sonnet"]["approval_required"] = True
    data["agents"]["claude-opus"]["approval_required"] = False
    data["hooks"] = {"approval_token": "MAINTAINER-OK-7"}
    path = tmp_path / "agents.yaml"
    path.write_text(yaml.safe_dump(data))
    set_probe(_private_home, agents=path)
    set_mode(_private_home, "block")
    assert "approval" in read_after(_private_home, path, dispatch(model="sonnet"))["rules"]
    assert "OPUS-APPROVED" not in guard(_private_home, path, dispatch(model="sonnet"))[1]
    ok = dispatch(model="sonnet", prompt="safo local run. MAINTAINER-OK-7")
    assert guard(_private_home, path, ok)[1] == ""
    assert guard(_private_home, path, dispatch(model="opus"))[1] == "", "opus is not marked in this file"


# -- guard rule 3: while the local LLM is reachable, a named local step or a stated reason -------------------

NO_STEP = "Triage these issues and write the summary."


@pytest.mark.parametrize(
    "brief",
    [
        "Run safo local run --shape issue-triage first.",
        "Pipe the log through llm-local for the digest.",
        "SAFO LOCAL RUN does the digest.",
        "Local-LLM: N/A - a one-line rename, nothing to summarise.",
    ],
    ids=["safo-local-run", "llm-local", "case-insensitive", "na-with-reason"],
)
def test_a_brief_with_a_local_step_or_a_reason_for_none_passes_while_the_local_llm_is_reachable(
    _private_home: Path, agents: Path, brief: str
) -> None:
    set_probe(_private_home)
    assert guard(_private_home, agents, dispatch(prompt=brief))[1] == ""
    assert read_log(_private_home)[0]["local_reachable"] is True


def test_a_brief_with_neither_is_flagged_while_the_local_llm_is_reachable(_private_home: Path, agents: Path) -> None:
    set_probe(_private_home)
    code, out, _ = guard(_private_home, agents, dispatch(prompt=NO_STEP))
    assert code == 0 and "names no local step" in reason(out)
    assert "gives no reason for none" in reason(out)
    entry = read_log(_private_home)[0]
    assert entry["rules"] == ["no-local-step"] and entry["local_step"] is False and entry["na"] is False


def test_the_not_applicable_marker_without_a_reason_does_not_count(_private_home: Path, agents: Path) -> None:
    set_probe(_private_home)
    for brief in ("local-llm: n/a -", "local-llm: n/a -    "):
        assert "no-local-step" in read_after(_private_home, agents, dispatch(prompt=brief))["rules"], brief


@pytest.mark.parametrize(
    "case",
    ["unreachable", "stale", "future", "no-state"],
)
def test_the_local_rule_stands_down_unless_the_local_llm_was_reachable_a_moment_ago(
    _private_home: Path, agents: Path, case: str
) -> None:
    if case == "unreachable":
        set_probe(_private_home, reachable=False)
    elif case == "stale":
        set_probe(_private_home, age=301)
        block_reprobe(_private_home)  # a re-probe a moment ago failed or found nothing: the state stays stale
    elif case == "future":
        set_probe(_private_home, age=-5)
    code, out, _ = guard(_private_home, agents, dispatch(prompt=NO_STEP))
    assert code == 0 and read_log(_private_home)[0]["local_reachable"] is False
    assert ("SAFO routing guard degraded" in out) is (case != "unreachable")


def test_a_probe_just_inside_the_age_limit_still_counts(_private_home: Path, agents: Path) -> None:
    set_probe(_private_home, age=300)
    assert "no-local-step" in read_after(_private_home, agents, dispatch(prompt=NO_STEP))["rules"]


def test_the_age_limit_and_the_markers_come_from_agents_yaml(_private_home: Path, tmp_path: Path) -> None:
    path = agents_file(
        tmp_path / "agents.yaml", max_state_age_seconds=120, local_step_markers=["Run-Local"], na_marker="No local: "
    )
    set_probe(_private_home, age=60, agents=path)
    assert "no-local-step" in read_after(_private_home, path, dispatch(prompt="safo local run"))["rules"]
    assert guard(_private_home, path, dispatch(prompt="use run-local here"))[1] == ""
    assert guard(_private_home, path, dispatch(prompt="no local: tiny edit"))[1] == ""
    set_probe(_private_home, age=121, agents=path)
    block_reprobe(_private_home, path)
    assert "SAFO routing guard degraded" in guard(_private_home, path, dispatch(prompt=NO_STEP))[1]


def test_a_stale_state_is_reprobed_once_and_the_fresh_answer_is_used(_private_home: Path, tmp_path: Path) -> None:
    with FakeOllama(A_MODELS, A_MODELS).serve() as a, FakeOllama(B_MODELS, B_MODELS[:1]).serve() as b:
        path = agents_file(tmp_path / "agents.yaml", a.url, b.url)
        set_probe(_private_home, reachable=False, age=900, agents=path)  # old, and it said unreachable
        code, out, _ = guard(_private_home, path, dispatch(prompt=NO_STEP))
        row = read_log(_private_home)[-1]
        assert code == 0 and row["health"] == "healthy" and row["local_reachable"] is True
        assert row["rules"] == ["no-local-step"] and "SAFO routing guard degraded" not in out
        asked = len(a.requests)
        assert asked == 2  # /api/tags and /api/ps, once
        assert json.loads(probe_file(_private_home, path).read_text())["ts"] >= NOW.timestamp()
        guard(_private_home, path, dispatch(prompt=NO_STEP))
        assert len(a.requests) == asked, "the refreshed state is trusted: no second probe"


def test_reprobe_is_rate_limited_and_a_failed_one_is_unknown_with_one_notice(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def down(*args: object, **kwargs: object) -> list[tuple[Endpoint, Probe]]:
        calls.append("probe")
        raise OSError("endpoint down")

    monkeypatch.setattr("safo.hooks.probe_all", down)
    set_probe(_private_home, age=900)
    brief = dispatch(model=None, prompt=NO_STEP)
    first = guard(_private_home, agents, brief)[1]
    second = guard(_private_home, agents, brief)[1]
    assert len(calls) == 1, "the second dispatch inside the interval does not probe again"
    rows = read_log(_private_home)
    assert [r["rules"] for r in rows] == [["no-model"]] * 2, "model rules stand; only the local-step rule is off"
    assert [r["health"] for r in rows] == ["stale", "stale"] and not any(r["local_reachable"] for r in rows)
    assert "SAFO routing guard degraded" in first and "SAFO routing guard degraded" not in second
    later = NOW + dt.timedelta(seconds=61)
    third = guard(_private_home, agents, brief, now=later)[1]
    assert len(calls) == 2, "a minute later it tries again"
    assert "SAFO routing guard degraded" not in third, "one notice per session, however many dispatches"


def test_a_configured_age_above_five_minutes_is_honoured(
    _private_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def probed(*args: object, **kwargs: object) -> list[tuple[Endpoint, Probe]]:
        calls.append("probe")
        return []

    monkeypatch.setattr("safo.hooks.probe_all", probed)
    path = agents_file(tmp_path / "agents.yaml", max_state_age_seconds=900)
    set_probe(_private_home, age=600, agents=path)  # older than five minutes, inside the configured fifteen
    row = read_after(_private_home, path, dispatch(prompt=NO_STEP))
    assert row["health"] == "healthy" and row["rules"] == ["no-local-step"] and calls == []
    set_probe(_private_home, age=901, agents=path)
    read_after(_private_home, path, dispatch(prompt=NO_STEP))
    assert calls == ["probe"], "past the configured age the guard re-probes"


def test_the_probe_and_the_guard_work_together(_private_home: Path, tmp_path: Path) -> None:
    set_mode(_private_home, "block")
    with FakeOllama(A_MODELS, A_MODELS).serve() as a, FakeOllama(B_MODELS, B_MODELS[:1]).serve() as b:
        path = agents_file(tmp_path / "agents.yaml", a.url, b.url)
        assert hooks("probe", "--agents", str(path), home=_private_home)[0] == 0
    later = NOW + dt.timedelta(minutes=2)
    denied = guard(_private_home, path, dispatch(prompt=NO_STEP), now=later)[1]
    assert json.loads(denied)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert guard(_private_home, path, dispatch(), now=later)[1] == ""


# -- the guard's modes, its log, and failing open ------------------------------------------------------------


def test_the_mode_is_warn_unless_the_file_says_block(_private_home: Path, agents: Path) -> None:
    for text in (None, "panic", ""):
        if text is not None:
            set_mode(_private_home, text)
        out = guard(_private_home, agents, dispatch(model=None))[1]
        assert "permissionDecision" not in out and "warn mode" in out


def test_an_unknown_mode_is_shown_as_warn(_private_home: Path) -> None:
    set_mode(_private_home, "panic")
    assert "Routing guard (mode: warn)" in hooks("status", home=_private_home)[1]


@pytest.mark.parametrize(
    "text", ["not json", "[]", '{"reachable": "yes", "ts": 1}', '{"reachable": true, "ts": "now"}']
)
def test_a_probe_state_that_makes_no_sense_counts_as_the_local_llm_not_being_there(
    _private_home: Path, agents: Path, text: str
) -> None:
    set_probe(_private_home)
    probe_file(_private_home).write_text(text)
    entry = read_after(_private_home, agents, dispatch(model=None, prompt=NO_STEP))
    assert entry["rules"] == ["no-model"] and entry["local_reachable"] is False


def test_a_clean_dispatch_prints_nothing_in_either_mode(_private_home: Path, agents: Path) -> None:
    set_probe(_private_home)
    for mode in ("warn", "block"):
        set_mode(_private_home, mode)
        assert guard(_private_home, agents, dispatch()) == (0, "", "")
    assert [e["decision"] for e in read_log(_private_home)] == ["allow", "allow"]


def test_every_decision_is_logged_without_any_prompt_text(_private_home: Path, agents: Path) -> None:
    set_probe(_private_home)
    sentinel = "sentinel-brief-text"
    guard(_private_home, agents, dispatch(prompt=f"{sentinel} safo local run"))
    guard(_private_home, agents, dispatch(model="opus", prompt=f"{sentinel} {NO_STEP}"))
    raw = (state_folder(_private_home) / "log.jsonl").read_text()
    assert sentinel not in raw and "sentinel-description" not in raw and NO_STEP not in raw
    first, second = read_log(_private_home)
    assert first == {
        "ts": "2026-10-07T12:00:00",
        "decision": "allow",
        "mode": "warn",
        "model": "sonnet",
        "local_reachable": True,
        "local_step": True,
        "na": False,
        "rules": [],
        "health": "healthy",
        "diagnostic": "",
    }
    assert second["decision"] == "warn" and second["model"] == "opus"
    assert second["rules"] == ["approval", "no-local-step"]


def test_the_log_is_what_agents_status_reads(_private_home: Path, agents: Path) -> None:
    set_probe(_private_home)
    guard(_private_home, agents, dispatch(model=None, prompt=NO_STEP))
    guard(_private_home, agents, dispatch(prompt="safo local run"))
    counts = summarise(read_guard_log(state_folder(_private_home) / "log.jsonl"))
    assert counts.total == 2 and dict(counts.decisions) == {"warn": 1, "allow": 1}
    assert dict(counts.rules) == {"no-local-step": 1, "no-model": 1} and counts.local_steps == 1


@pytest.mark.parametrize(
    "payload",
    [
        "",
        "not json",
        "[]",
        "null",
        '{"tool_name": "Agent"}',
        '{"tool_name": "Agent", "tool_input": "a string"}',
        "[" * 100 + "]" * 100,
        "x" * 1_100_000,
    ],
    ids=["empty", "not-json", "list", "null", "no-input", "string-input", "deep", "oversized"],
)
def test_a_hook_that_meets_garbage_fails_open_even_in_block_mode(
    _private_home: Path, agents: Path, payload: str
) -> None:
    set_mode(_private_home, "block")
    set_probe(_private_home)
    code, out, err = guard(_private_home, agents, payload)
    assert code == 0 and "deny" not in out and err == ""
    assert "SAFO routing guard degraded" in out
    assert read_log(_private_home)[-1]["diagnostic"] == "input"


def test_wrong_types_in_the_input_are_treated_as_a_missing_model_and_brief(_private_home: Path, agents: Path) -> None:
    payload = json.loads(dispatch())
    payload["tool_input"] = {"prompt": 7, "model": 7}
    payload = json.dumps(payload)
    assert read_after(_private_home, agents, payload)["rules"] == ["no-model"]


@pytest.mark.parametrize("broken", ["missing", "garbage"])
def test_a_broken_agents_file_fails_open_in_block_mode_and_is_logged_as_an_error(
    _private_home: Path, tmp_path: Path, broken: str
) -> None:
    set_mode(_private_home, "block")
    path = tmp_path / "agents.yaml"
    if broken == "garbage":
        path.write_text("a: [unclosed\n")
    code, out, err = guard(_private_home, path, dispatch(model=None))
    assert code == 0 and "SAFO routing guard degraded" in out and err == ""
    assert read_log(_private_home)[0]["decision"] == "error"


def test_a_tool_that_is_not_an_agent_dispatch_is_ignored_and_not_logged(_private_home: Path, agents: Path) -> None:
    set_mode(_private_home, "block")
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}})
    assert guard(_private_home, agents, payload) == (0, "", "") and read_log(_private_home) == []


def test_the_older_task_tool_name_is_guarded_too(_private_home: Path, agents: Path) -> None:
    payload = json.loads(dispatch(model=None))
    payload["tool_name"] = "Task"
    set_mode(_private_home, "block")
    assert "deny" in guard(_private_home, agents, json.dumps(payload))[1]


def test_a_log_that_cannot_be_written_does_not_change_the_decision(
    _private_home: Path, agents: Path, tmp_path: Path
) -> None:
    set_mode(_private_home, "block")
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("x")
    code, out, _ = guard(_private_home, agents, dispatch(model=None), env={"XDG_STATE_HOME": str(blocker)})
    assert code == 0 and json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "SAFO routing guard degraded" in out and "log-write" in out


def test_the_log_moves_aside_when_it_grows_past_its_limit(tmp_path: Path) -> None:
    log = tmp_path / "log.jsonl"
    from safo.hooks import log_record

    record = log_record("2026-10-07T12:00:00", "allow", "warn", None, False)
    limit = len((json.dumps(record, sort_keys=True) + "\n").encode())
    append_log(log, record, limit=limit)
    append_log(log, record, limit=limit)
    append_log(log, {**record, "decision": "warn"}, limit=limit)
    assert json.loads(log.read_text())["decision"] == "warn"
    assert json.loads((tmp_path / "log.jsonl.1").read_text())["decision"] == "allow"


# -- mode and status -----------------------------------------------------------------------------------------


def test_mode_writes_the_mode_the_guard_reads(_private_home: Path, agents: Path) -> None:
    code, out, _ = hooks("mode", "block", home=_private_home)
    assert code == 0 and "guard mode: block (denies a dispatch that breaks a rule)" in out
    assert "deny" in guard(_private_home, agents, dispatch(model=None))[1]
    assert "reports a broken rule" in hooks("mode", "warn", home=_private_home)[1]
    assert "deny" not in guard(_private_home, agents, dispatch(model=None))[1]


def test_mode_rejects_anything_but_warn_or_block_and_a_dry_run_writes_nothing(_private_home: Path) -> None:
    with pytest.raises(SystemExit) as stop:
        hooks("mode", "panic", home=_private_home)
    assert stop.value.code == 2
    assert hooks("mode", "block", home=_private_home, dry_run=True)[0] == 0
    assert not (_private_home / ".config" / "safo" / "mode").exists()


def test_status_shows_the_mode_the_counts_and_the_last_probe(_private_home: Path, agents: Path) -> None:
    code, out, _ = hooks("status", home=_private_home)
    assert code == 0 and "Routing guard (mode: warn)\n" in out and "  no dispatches logged yet" in out
    assert "local LLM probe: unknown" in out
    set_mode(_private_home, "block")
    set_probe(_private_home, age=60)
    guard(_private_home, agents, dispatch(model=None))
    guard(_private_home, agents, dispatch(prompt="safo local run"))
    out = hooks("status", "--session", "session-a", "--agents", str(agents), home=_private_home)[1]
    assert "Routing guard (mode: block)" in out
    assert "  2 dispatches since 2026-10-07: deny 1, allow 1" in out
    assert "  rules flagged: no-model 1" in out
    assert "local LLM probe: reachable, 1 min ago" in out


def test_hooks_needs_a_subcommand(_private_home: Path) -> None:
    with pytest.raises(SystemExit) as stop:
        main(["hooks"], env={"HOME": str(_private_home)})
    assert stop.value.code == 2


# Adversarial review regressions. Each names a contract absent from the old plan.
@pytest.mark.parametrize(
    "command", ["echo safo hooks guard", "/opt/safo-wrapper hooks guard", "safo hooks guard --extra ignored"]
)
def test_false_hook_ownership_is_preserved(command: str) -> None:
    from safo.hooks import merge_settings

    existing = {"matcher": "Bash", "hooks": [{"type": "command", "command": command}]}
    data, _ = merge_settings({"hooks": {"PreToolUse": [existing]}}, "safo hooks probe", "safo hooks guard")
    assert existing in data["hooks"]["PreToolUse"]
    assert data["hooks"]["PreToolUse"][-1]["matcher"] == "Agent|Task"


@pytest.mark.parametrize("matcher,kind", [("Bash", "command"), ("Agent|Task", "prompt"), ("Agent", "command")])
def test_ambiguous_ownership_is_refused_without_writing(_private_home: Path, matcher: str, kind: str) -> None:
    target = _private_home / "settings.json"
    raw = json.dumps(
        {"hooks": {"PreToolUse": [{"matcher": matcher, "hooks": [{"type": kind, "command": "safo hooks guard"}]}]}}
    )
    target.write_text(raw)
    code, _, err = hooks("install", "--settings", str(target), home=_private_home)
    assert code == 2 and "ambiguous" in err and target.read_text() == raw


def test_owned_duplicates_are_collapsed_and_all_required_fields_normalized() -> None:
    from safo.hooks import merge_settings

    group = {
        "matcher": "Agent|Task",
        "hooks": [{"type": "command", "command": "safo hooks guard", "timeout": 999, "async": True}],
    }
    data, _ = merge_settings({"hooks": {"PreToolUse": [group, group]}}, "safo hooks probe", "safo hooks guard")
    assert data["hooks"]["PreToolUse"] == [
        {"matcher": "Agent|Task", "hooks": [{"type": "command", "command": "safo hooks guard", "timeout": 10}]}
    ]


def test_changed_launcher_is_refused(_private_home: Path) -> None:
    target = _private_home / "settings.json"
    assert hooks("install", "--settings", str(target), home=_private_home)[0] == 0
    before = target.read_bytes()
    assert hooks("install", "--settings", str(target), "--command", "python3 -m safo", home=_private_home)[0] == 2
    assert target.read_bytes() == before


def test_settings_backup_and_new_file_permissions_are_private(_private_home: Path) -> None:
    target = _private_home / "settings.json"
    target.write_bytes(b'{"permissions":{"allow":["Read"]}}')
    before = target.read_bytes()
    assert hooks("install", "--settings", str(target), home=_private_home)[0] == 0
    backups = list(target.parent.glob(".settings.json.backup-*"))
    assert len(backups) == 1 and backups[0].read_bytes() == before
    assert backups[0].stat().st_mode & 0o777 == 0o600
    new = _private_home / "new.json"
    assert hooks("install", "--settings", str(new), home=_private_home)[0] == 0
    assert new.stat().st_mode & 0o777 == 0o600


def test_a_concurrent_external_edit_is_not_overwritten(_private_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from safo.hooks import merge_settings as real

    target = _private_home / "settings.json"
    target.write_text("{}")

    def edit(data: dict[str, Any], probe: str, guard: str) -> tuple[dict[str, Any], bool]:
        result = real(data, probe, guard)
        target.write_text('{"external":"keep"}')
        return result

    monkeypatch.setattr("safo.modes.hooks.merge_settings", edit)
    code, _, err = hooks("install", "--settings", str(target), home=_private_home)
    assert code == 2 and "concurrent" in err and target.read_text() == '{"external":"keep"}'
    assert not list(_private_home.glob(".settings.json.backup-*")), "a conflict replaces nothing: no backup is left"


def test_the_final_conflict_check_runs_just_before_replacement(
    _private_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An edit that lands after the early check, while the new file is written, only `before_replace` can see."""
    from safo.hooks import write_text as real

    target = _private_home / "settings.json"
    target.write_text("{}")

    def edit_then_write(
        path: Path,
        text: str,
        mode: int = 0o600,
        before_replace: Callable[[], None] | None = None,
        check_dir: bool = True,
    ) -> None:
        target.write_text('{"external":"keep"}')
        real(path, text, mode, before_replace, check_dir)

    monkeypatch.setattr("safo.modes.hooks.write_text", edit_then_write)
    code, _, err = hooks("install", "--settings", str(target), home=_private_home)
    assert code == 2 and "concurrent" in err and target.read_text() == '{"external":"keep"}'
    assert not list(_private_home.glob(".settings.json.backup-*")), "the aborted replace leaves no backup behind"
    assert not [p for p in _private_home.glob(".settings.json.*") if not p.name.endswith(".safo.lock")]


def test_interrupted_replacement_cleans_temp_and_keeps_backup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    from safo.modes.hooks import install_settings

    target = tmp_path / "settings.json"
    target.write_text("{}")

    def fail(*args: Any, **kwargs: Any) -> Any:
        raise OSError("interrupted")

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(ConfigError):
        install_settings(target, "safo hooks probe", "safo hooks guard")
    assert target.read_text() == "{}"
    assert list(tmp_path.glob(".settings.json.backup-*"))
    assert not [p for p in tmp_path.glob(".settings.json.*") if ".backup-" not in p.name]


def test_predictable_temp_symlink_is_never_followed(tmp_path: Path) -> None:
    import os

    from safo.hooks import write_text

    target, victim = tmp_path / "target", tmp_path / "victim"
    victim.write_text("private")
    link = tmp_path / f".target.{os.getpid()}.tmp"
    link.symlink_to(victim)
    write_text(target, "new")
    assert link.is_symlink() and victim.read_text() == "private" and target.read_text() == "new"


@pytest.mark.parametrize("name,limit", [("settings", 1048576), ("probe", 1048576), ("mode", 16)])
def test_reads_are_bounded_at_the_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, limit: int
) -> None:
    """A file larger than the limit is never read past limit+1 bytes: the bound is on the descriptor, not a slice."""
    import os

    folder = tmp_path / "safo" if name == "mode" else tmp_path
    folder.mkdir(exist_ok=True)
    path = folder / name
    path.write_bytes(b"x" * (limit * 4 + 1))
    real = os.read
    taken: list[int] = []

    def counted(fd: int, count: int) -> bytes:
        assert 0 <= count <= limit + 1
        data = real(fd, count)
        taken.append(len(data))
        return data

    monkeypatch.setattr(os, "read", counted)
    if name == "settings":
        from safo.modes.hooks import read_settings

        with pytest.raises(ConfigError):
            read_settings(path)
    elif name == "probe":
        from safo.hooks import read_state

        assert read_state(path) is None
    else:
        from safo.guardlog import mode_health

        assert mode_health({"XDG_CONFIG_HOME": str(tmp_path)}) == ("warn", "degraded")
    assert taken and sum(taken) == limit + 1


@pytest.mark.parametrize("kind", ["fifo", "device-link", "directory"])
def test_special_files_are_rejected_without_reading(tmp_path: Path, kind: str) -> None:
    import os

    from safo.guardlog import bounded_read

    path = tmp_path / "special"
    if kind == "fifo":
        os.mkfifo(path)
    elif kind == "device-link":
        path.symlink_to("/dev/zero")  # a symlink in the last component is refused outright, and /dev/zero is no file
    else:
        path.mkdir()
    with pytest.raises(OSError):
        bounded_read(path)


@pytest.mark.parametrize("text", ["panic", "x" * 100, "\xff"])
def test_degraded_mode_is_visible_and_recorded(_private_home: Path, agents: Path, text: str) -> None:
    set_mode(_private_home, text)
    set_probe(_private_home)
    code, out, _ = guard(_private_home, agents, dispatch())
    assert code == 0 and "SAFO routing guard degraded" in out
    row = read_log(_private_home)[-1]
    assert row["health"] == "degraded" and row["diagnostic"] == "mode"
    assert "health: degraded" in hooks("status", home=_private_home)[1]


def test_unexpected_guard_exception_is_visible_and_recorded(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import safo.modes.hooks as mod

    def fail(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("sentinel-token")

    monkeypatch.setattr(mod, "check_dispatch", fail)
    code, out, _ = guard(_private_home, agents, dispatch())
    assert code == 0 and "SAFO routing guard degraded" in out and "sentinel-token" not in out
    assert read_log(_private_home)[-1]["diagnostic"] == "unexpected"


def test_state_is_keyed_by_session_and_configuration(tmp_path: Path) -> None:
    from safo.agentsfile import parse_agents
    from safo.hooks import read_state, save_state, state_path

    a = parse_agents(agents_dict())
    data = agents_dict()
    data["hooks"] = {"approval_token": "DIFFERENT-TOKEN"}
    b = parse_agents(data)
    paths = [state_path(tmp_path, "a", a), state_path(tmp_path, "b", a), state_path(tmp_path, "a", b)]
    assert len(set(paths)) == 3
    for i, path in enumerate(paths):
        save_state(path, {"ts": NOW.timestamp(), "reachable": i == 0})
    states = [read_state(path) for path in paths]
    assert [s["reachable"] for s in states if s is not None] == [True, False, False] and None not in states
    assert all("DIFFERENT-TOKEN" not in p.name for p in paths)


def test_out_of_order_completions_keep_the_newest_result(tmp_path: Path) -> None:
    from safo.hooks import read_state, save_state

    path = tmp_path / "probe.json"
    assert save_state(path, {"ts": NOW.timestamp(), "reachable": False})
    assert not save_state(path, {"ts": NOW.timestamp() - 10, "reachable": True})
    state = read_state(path)
    assert state is not None and state["reachable"] is False


def test_failed_state_replacement_invalidates_previous_reachability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import safo.hooks as mod

    path = tmp_path / "probe.json"
    mod.save_state(path, {"ts": NOW.timestamp(), "reachable": True})

    def fail(*args: Any, **kwargs: Any) -> Any:
        raise OSError("failed replace")

    monkeypatch.setattr(mod, "write_text", fail)
    with pytest.raises(OSError):
        mod.save_state(path, {"ts": NOW.timestamp() + 1, "reachable": False})
    assert mod.read_state(path) is None


@pytest.mark.parametrize("stamp", ["1e999", "1" + "0" * 400, "-1", "true", str(NOW.timestamp() + 20)])
def test_hostile_timestamps_do_not_disable_model_checks_or_crash_status(
    _private_home: Path, agents: Path, stamp: str
) -> None:
    set_mode(_private_home, "block")
    set_probe(_private_home)
    probe_file(_private_home).write_text('{"reachable":true,"ts":' + stamp + "}")
    code, out, _ = guard(_private_home, agents, dispatch(model=None, prompt=NO_STEP))
    assert code == 0 and json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert read_log(_private_home)[-1]["rules"] == ["no-model"]
    code, text, _ = hooks("status", "--session", "session-a", "--agents", str(agents), home=_private_home)
    assert code == 0 and "probe: unknown" in text and "0 min ago" not in text


@pytest.mark.parametrize("age,health", [(-5, "unknown"), (301, "stale"), (60, "healthy")])
def test_clock_changes_are_explicit(_private_home: Path, agents: Path, age: float, health: str) -> None:
    set_probe(_private_home, age=age)
    if health == "stale":
        block_reprobe(_private_home)
    guard(_private_home, agents, dispatch())
    assert read_log(_private_home)[-1]["health"] == health
    text = hooks("status", "--session", "session-a", "--agents", str(agents), home=_private_home)[1]
    assert health in text
    if health != "healthy":
        assert "probe: reachable" not in text


def test_truncated_tail_is_recovered_before_append(tmp_path: Path) -> None:
    from safo.hooks import log_record

    path = tmp_path / "log.jsonl"
    row = log_record("2026-10-07T12:00:00", "allow", "warn", None, False)
    append_log(path, row)
    with path.open("ab") as handle:
        handle.write(b'{"half":')
    append_log(path, row)
    assert read_guard_log(path) == [row, row]


def _concurrent_log_writer(path: str, count: int, limit: int) -> None:
    from safo.hooks import log_record

    for _ in range(count):
        append_log(Path(path), log_record("2026-10-07T12:00:00", "allow", "warn", None, False), limit=limit)


def test_concurrent_rotation_and_appends_keep_complete_bounded_records(tmp_path: Path) -> None:
    import multiprocessing

    from safo.hooks import log_record

    path = tmp_path / "log.jsonl"
    row = log_record("2026-10-07T12:00:00", "allow", "warn", None, False)
    size = len((json.dumps(row, sort_keys=True) + "\n").encode())
    ctx = multiprocessing.get_context("fork")
    workers = [ctx.Process(target=_concurrent_log_writer, args=(str(path), 15, size * 10)) for _ in range(4)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(10)
        assert worker.exitcode == 0
    archive = path.with_name(path.name + ".1")
    assert len(read_guard_log(path)) + len(read_guard_log(archive)) == 20
    for item in (path, archive):
        assert item.stat().st_size <= size * 10 and item.stat().st_mode & 0o777 == 0o600
        assert item.read_bytes().endswith(b"\n")


def test_invalid_and_oversized_log_records_are_rejected(tmp_path: Path) -> None:
    from safo.hooks import log_record

    row = log_record("2026-10-07T12:00:00", "allow", "warn", None, False)
    with pytest.raises(ValueError):
        append_log(tmp_path / "log.jsonl", {**row, "model": "sentinel" * 1000})
    assert not (tmp_path / "log.jsonl").exists()


def test_model_label_is_normalized_in_every_output(_private_home: Path, agents: Path) -> None:
    set_probe(_private_home)
    sentinel = "sonnet sentinel-token https://private.invalid\n\x1b[31m"
    _, out, _ = guard(_private_home, agents, dispatch(model=sentinel))
    raw = (state_folder(_private_home) / "log.jsonl").read_text()
    status = hooks("status", home=_private_home)[1]
    assert "sentinel-token" not in out + raw + status and read_log(_private_home)[-1]["model"] == "unknown"


def test_probe_does_not_emit_endpoint_or_loaded_model_labels() -> None:
    from safo.agentsfile import Endpoint, parse_agents
    from safo.hooks import probe_state, session_message
    from safo.ollama import Probe

    endpoint = Endpoint(
        id="sentinel-token", url="http://127.0.0.1:9", roles=("general",), models=(), num_ctx_max=8192, think=False
    )
    result = Probe(
        endpoint_id=endpoint.id,
        url=endpoint.url,
        reachable=True,
        loaded=("sentinel-token https://private.invalid",),
    )
    state = probe_state([(endpoint, result)], NOW.timestamp())
    assert "sentinel-token" not in json.dumps(state) + session_message(parse_agents(agents_dict()), state)


def test_local_step_markers_are_case_insensitive_in_actual_briefs(_private_home: Path, agents: Path) -> None:
    set_probe(_private_home)
    row = read_after(_private_home, agents, dispatch(prompt="Please SAFO LOCAL RUN --shape ci-log-summary"))
    assert row["local_step"] is True and "no-local-step" not in row["rules"]


def test_installed_matcher_covers_every_accepted_tool_name() -> None:
    import re

    from safo.hooks import AGENT_TOOLS, merge_settings

    data, _ = merge_settings({}, "safo hooks probe", "safo hooks guard")
    matcher = data["hooks"]["PreToolUse"][0]["matcher"]
    assert all(re.fullmatch(matcher, tool) for tool in AGENT_TOOLS)


def test_probe_timestamp_is_completion_time(_private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import time

    import safo.modes.hooks as mod

    clock = iter([10.0, 12.0])
    monkeypatch.setattr(time, "monotonic", lambda: next(clock, 12.0))
    monkeypatch.setattr(mod, "probe_all", lambda doc: [])
    assert hooks("probe", "--agents", str(agents), home=_private_home)[0] == 0
    assert json.loads(probe_file(_private_home, agents).read_text())["ts"] == NOW.timestamp() + 2


def test_probe_write_failure_warns_and_records_degradation(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import safo.modes.hooks as mod

    monkeypatch.setattr(mod, "probe_all", lambda doc: [])

    def fail(*args: Any, **kwargs: Any) -> Any:
        raise OSError("sentinel-token")

    monkeypatch.setattr(mod, "save_state", fail)
    code, out, _ = hooks("probe", "--agents", str(agents), home=_private_home)
    assert code == 0 and "SAFO routing guard degraded" in out and "sentinel-token" not in out
    assert read_log(_private_home)[-1]["diagnostic"] == "state-write"


def _concurrent_installer(path: str) -> None:
    from safo.modes.hooks import install_settings

    for _ in range(40):  # a busy lock is a refusal to wait, never a corrupt file; a person would rerun the command
        try:
            install_settings(Path(path), "safo hooks probe", "safo hooks guard")
            return
        except ConfigError as error:
            if "another installer" not in str(error):
                raise
    raise AssertionError("the lock was never free")


def test_cooperating_installers_are_serialized(tmp_path: Path) -> None:
    import multiprocessing

    path = tmp_path / "settings.json"
    path.write_text("{}")
    ctx = multiprocessing.get_context("fork")
    workers = [ctx.Process(target=_concurrent_installer, args=(str(path),)) for _ in range(4)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(10)
        assert worker.exitcode == 0
    data = json.loads(path.read_text())
    assert len(data["hooks"]["SessionStart"]) == len(data["hooks"]["PreToolUse"]) == 1
    assert len(list(tmp_path.glob(".settings.json.backup-*"))) == 1


def test_change_during_temp_write_is_detected_before_replace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    from safo.errors import ConfigError
    from safo.modes.hooks import install_settings

    path = tmp_path / "settings.json"
    path.write_text("{}")
    real = os.fsync

    def edit(fd: int) -> None:
        real(fd)
        path.write_text('{"external":"keep"}')

    monkeypatch.setattr(os, "fsync", edit)
    with pytest.raises(ConfigError, match="concurrent"):
        install_settings(path, "safo hooks probe", "safo hooks guard")
    assert path.read_text() == '{"external":"keep"}'


@pytest.mark.parametrize("operation", ["install", "append"])
def test_mutations_require_the_shared_lock(tmp_path: Path, operation: str) -> None:
    from safo.guardlog import file_lock
    from safo.hooks import log_record
    from safo.modes.hooks import install_settings

    path = tmp_path / ("settings.json" if operation == "install" else "log.jsonl")
    path.write_text("{}" if operation == "install" else "")
    lock = path.with_name(path.name + (".safo.lock" if operation == "install" else ".lock"))
    before = path.read_bytes()
    with file_lock(lock), pytest.raises((ConfigError, TimeoutError)):
        if operation == "install":
            install_settings(path, "safo hooks probe", "safo hooks guard")
        else:
            append_log(path, log_record("2026-10-07T12:00:00", "allow", "warn", None, False))
    assert path.read_bytes() == before


# -- the hostile-input list for T9h, and the host-facing contract of a hook ------------------------------------------


def one_json_line_or_nothing(out: str) -> None:
    """A host parses stdout as one JSON document; a stray byte, a second line or a `::` rewrite breaks that."""
    if out:
        assert out.endswith("\n") and "\n" not in out[:-1] and "::" not in out
        assert isinstance(json.loads(out), dict)


@pytest.mark.parametrize("model", [123, True, 1.5, [], {}, None, "", "   ", "\n", "x" * 100_000, "opus\x00\n\x1b[31m"])
def test_a_model_that_is_not_a_clean_name_is_unknown_or_missing_and_never_echoed(
    _private_home: Path, agents: Path, model: Any
) -> None:
    payload = json.loads(dispatch())
    payload["tool_input"]["model"] = model
    code, out, err = guard(_private_home, agents, json.dumps(payload))
    row = read_log(_private_home)[-1]
    assert code == 0 and err == "" and row["model"] in ("unknown", None)
    assert "no-model" in row["rules"] or row["model"] == "unknown"
    assert "x" * 50 not in out and "\x1b" not in out
    one_json_line_or_nothing(out)


@pytest.mark.parametrize(
    "brief",
    [
        "Review it. [OPUS-APPROVED] he said so",
        "Review it. (OPUS-APPROVED)",
        "Review it. opus-approved: he said so",
        "Review it.\nOpus-Approved",
    ],
)
def test_the_approval_token_is_found_however_it_is_wrapped_or_cased(
    _private_home: Path, agents: Path, brief: str
) -> None:
    set_probe(_private_home)
    set_mode(_private_home, "block")
    assert guard(_private_home, agents, dispatch(model="opus", prompt=brief + " safo local run"))[1] == ""


@pytest.mark.parametrize(
    "brief",
    [
        "local-llm: n/a -  a one-line rename",
        "local-llm:   n/a   -\ta tiny edit",
        "Local-LLM:\nn/a -\nbecause nothing to summarise",
        "x local-llm: n/a - y",
    ],
)
def test_the_not_applicable_marker_tolerates_whitespace_inside_and_after_it(
    _private_home: Path, agents: Path, brief: str
) -> None:
    set_probe(_private_home)
    row = read_after(_private_home, agents, dispatch(prompt=brief))
    assert row["na"] is True and row["rules"] == []


@pytest.mark.parametrize("brief", ["local-llm n/a - nope", "local-llm: n/a", "local-llm: n/a -\n  \t", "n/a - nope"])
def test_a_marker_that_is_not_the_marker_does_not_count(_private_home: Path, agents: Path, brief: str) -> None:
    set_probe(_private_home)
    assert read_after(_private_home, agents, dispatch(prompt=brief))["rules"] == ["no-local-step"]


@pytest.mark.parametrize(
    "payload",
    [
        '{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"Agent","tool_input":[]}',
        '{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"Agent","tool_input":"x"}',
        '{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"Agent","tool_input":null}',
        '{"hook_event_name":"PreToolUse","session_id":"s","tool_name":["Agent"],"tool_input":{}}',
        '{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"Agent"}',
        '{"hook_event_name":"PostToolUse","session_id":"s","tool_name":"Agent","tool_input":{}}',
        '{"hook_event_name":"PreToolUse","session_id":7,"tool_name":"Agent","tool_input":{}}',
        '{"hook_event_name":"PreToolUse","session_id":"","tool_name":"Agent","tool_input":{}}',
        '{"hook_event_name":"PreToolUse","session_id":"' + "s" * 257 + '","tool_name":"Agent","tool_input":{}}',
        '{"hook_event_name":"PreToolUse","session_id":"a\\nb","tool_name":"Agent","tool_input":{}}',
        '{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"Agent","tool_input":{"prompt":"'
        + "x" * 5_000_000,
        '{"a":' * 5000 + "1" + "}" * 5000,
        "\x00\x00\x00",
        '{"n": NaN}',
        '{"n": 1e99999}',
        '{"n": Infinity}',
    ],
    ids=[
        "input-list",
        "input-string",
        "input-null",
        "tool-name-list",
        "no-input",
        "wrong-event",
        "session-int",
        "session-empty",
        "session-long",
        "session-control",
        "5mb-unterminated",
        "deep",
        "nul",
        "nan",
        "huge-exponent",
        "infinity",
    ],
)
def test_hostile_events_fail_open_visibly_in_block_mode_with_clean_output(
    _private_home: Path, agents: Path, payload: str
) -> None:
    set_mode(_private_home, "block")
    set_probe(_private_home)
    code, out, err = guard(_private_home, agents, payload)
    assert code == 0 and err == "" and "deny" not in out
    assert "SAFO routing guard degraded" in out
    assert read_log(_private_home)[-1]["diagnostic"] == "input"
    one_json_line_or_nothing(out)
    leftovers = [
        p.name for p in state_folder(_private_home).iterdir() if not p.name.startswith(("log.jsonl", "probe-"))
    ]
    assert leftovers == []


def test_a_session_id_cannot_steer_the_state_file_anywhere(_private_home: Path, agents: Path, tmp_path: Path) -> None:
    payload = json.loads(dispatch(prompt="safo local run"))
    payload["session_id"] = "../../../../../../tmp/escape"
    assert guard(_private_home, agents, json.dumps(payload))[0] == 0
    assert not (Path("/tmp") / "escape").exists()
    names = {p.name for p in state_folder(_private_home).iterdir()}
    assert all(n.startswith(("log.jsonl", "probe-")) for n in names)


def test_every_output_of_every_hook_path_is_one_json_line(_private_home: Path, agents: Path, tmp_path: Path) -> None:
    set_probe(_private_home)
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("x")
    cases = [
        guard(_private_home, agents, dispatch(model=None, prompt=NO_STEP)),
        guard(_private_home, agents, dispatch(model="opus")),
        guard(_private_home, agents, "garbage"),
        guard(_private_home, tmp_path / "missing.yaml", dispatch()),
        guard(_private_home, agents, dispatch(model=None), env={"XDG_STATE_HOME": str(blocker)}),
        hooks("probe", "--agents", str(agents), home=_private_home),
        hooks("probe", "--agents", str(tmp_path / "missing.yaml"), home=_private_home),
        hooks("probe", "--agents", str(agents), home=_private_home, stdin="garbage"),
    ]
    for code, out, err in cases:
        assert code == 0 and err == ""
        one_json_line_or_nothing(out)


class Blocked:
    """A standard input whose writer never writes and never closes: a host that hangs."""

    def __init__(self) -> None:
        import os

        self.read_end, self.write_end = os.pipe()
        self.stream = os.fdopen(self.read_end, "r")

    def close(self) -> None:
        import os

        self.stream.close()
        os.close(self.write_end)


def test_a_standard_input_that_never_arrives_is_a_visible_timeout_not_a_hang(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import io
    import time

    from safo.cli import main
    from safo.modes import hooks as mode

    monkeypatch.setattr(mode, "STDIN_TIMEOUT_SECONDS", 0.2)
    set_mode(_private_home, "block")
    blocked = Blocked()
    out, err = io.StringIO(), io.StringIO()
    started = time.monotonic()
    try:
        code = main(
            ["hooks", "guard", "--agents", str(agents)],
            env={"HOME": str(_private_home), "PATH": ""},
            out=out,
            err=err,
            now=NOW,
            stdin=blocked.stream,
        )
    finally:
        blocked.close()
    assert time.monotonic() - started < 3 and code == 0 and err.getvalue() == ""
    assert "SAFO routing guard degraded" in out.getvalue() and "deny" not in out.getvalue()
    assert read_log(_private_home)[-1]["diagnostic"] == "timeout"


def test_a_trickling_standard_input_is_cut_off_at_the_size_limit_without_reading_it_all(
    _private_home: Path, agents: Path
) -> None:
    import io
    import os
    import threading

    from safo.cli import main

    read_end, write_end = os.pipe()
    stream = os.fdopen(read_end, "r")
    sent: list[int] = []

    def feed() -> None:
        try:
            with os.fdopen(write_end, "wb", buffering=0) as writer:
                for _ in range(200):
                    sent.append(writer.write(b"x" * 65_536))
        except OSError:  # the guard stopped reading and closed its end
            pass

    feeder = threading.Thread(target=feed, daemon=True)
    feeder.start()
    out = io.StringIO()
    code = main(
        ["hooks", "guard", "--agents", str(agents)],
        env={"HOME": str(_private_home), "PATH": ""},
        out=out,
        err=io.StringIO(),
        now=NOW,
        stdin=stream,
    )
    stream.close()
    feeder.join(5)
    assert code == 0 and "degraded" in out.getvalue()
    assert sum(sent) < 200 * 65_536, "the guard stopped reading at the limit and did not drain the writer"


def test_a_standard_input_that_cannot_be_read_is_a_visible_input_failure(_private_home: Path, agents: Path) -> None:
    import io

    from safo.cli import main

    class Broken(io.StringIO):
        def read(self, size: int | None = -1) -> str:
            raise OSError("sentinel-token")

        def fileno(self) -> int:
            raise OSError("no descriptor")

    out = io.StringIO()
    code = main(
        ["hooks", "guard", "--agents", str(agents)],
        env={"HOME": str(_private_home), "PATH": ""},
        out=out,
        err=io.StringIO(),
        now=NOW,
        stdin=Broken(),
    )
    assert code == 0 and "degraded" in out.getvalue() and "sentinel-token" not in out.getvalue()


@pytest.mark.parametrize("sub", ["guard", "probe"])
def test_a_hook_started_with_arguments_it_does_not_know_still_exits_zero_with_a_warning(
    _private_home: Path, sub: str
) -> None:
    """argparse exits 2 on a bad flag, and a host reads exit 2 from a PreToolUse hook as a denial."""
    import contextlib
    import io

    from safo.cli import main

    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stderr(io.StringIO()):
        code = main(["hooks", sub, "--no-such-flag"], env={"HOME": str(_private_home)}, out=out, err=err, now=NOW)
    assert code == 0 and "SAFO routing guard degraded" in out.getvalue()
    one_json_line_or_nothing(out.getvalue())


def test_a_person_typing_a_bad_command_still_gets_the_usual_usage_error(_private_home: Path) -> None:
    import contextlib
    import io

    for argv in (["hooks", "install", "--no-such-flag"], ["hooks", "mode", "panic"], ["hooks"], ["hooks", "bogus"]):
        with contextlib.redirect_stderr(io.StringIO()), pytest.raises(SystemExit) as stop:
            main(argv, env={"HOME": str(_private_home)}, out=io.StringIO(), err=io.StringIO(), now=NOW)
        assert stop.value.code == 2


def test_a_rejected_mode_leaves_the_mode_that_was_set(_private_home: Path) -> None:
    hooks("mode", "block", home=_private_home)
    with pytest.raises(SystemExit):
        hooks("mode", "123", home=_private_home)
    assert (_private_home / ".config" / "safo" / "mode").read_text() == "block\n"


def test_a_slow_endpoint_costs_the_guard_one_bounded_wait_and_never_a_decision(
    _private_home: Path, tmp_path: Path
) -> None:
    import time

    with FakeOllama(A_MODELS, A_MODELS).serve() as a, FakeOllama(B_MODELS, B_MODELS[:1]).serve() as b:
        a.stall_seconds = b.stall_seconds = 2.5
        path = agents_file(tmp_path / "agents.yaml", a.url, b.url)
        set_probe(_private_home, age=900, agents=path)
        set_mode(_private_home, "block")
        started = time.monotonic()
        code, out, _ = guard(_private_home, path, dispatch(model=None, prompt=NO_STEP))
        elapsed = time.monotonic() - started
    assert code == 0 and elapsed < 2.4, "the re-probe gives up after its own short timeout"
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    row = read_log(_private_home)[-1]
    assert row["rules"] == ["no-model"] and row["local_reachable"] is False, "the answer was 'not reachable'"


def test_reinstalling_keeps_our_hook_where_it_is_and_touches_nothing_else(_private_home: Path) -> None:
    settings = _private_home / "settings.json"
    assert hooks("install", "--settings", str(settings), home=_private_home)[0] == 0
    data = json.loads(settings.read_text())
    data["hooks"]["PreToolUse"].append({"matcher": "Bash", "hooks": [{"type": "command", "command": "~/bin/after"}]})
    data["hooks"]["SessionStart"].insert(0, {"hooks": [{"type": "command", "command": "~/bin/before"}]})
    settings.write_text(json.dumps(data))
    before = settings.read_bytes()
    code, out, _ = hooks("install", "--settings", str(settings), home=_private_home)
    assert code == 0 and "already installed" in out and settings.read_bytes() == before
    assert not list(_private_home.glob(".settings.json.backup-*")), "a no-op writes no backup"


def test_an_installer_that_cannot_get_the_lock_says_so_and_changes_nothing(_private_home: Path) -> None:
    from safo.guardlog import file_lock

    settings = _private_home / "settings.json"
    settings.write_text("{}")
    with file_lock(settings.with_name("settings.json.safo.lock")):
        code, _, err = hooks("install", "--settings", str(settings), home=_private_home)
    assert code == 2 and "another installer" in err and settings.read_text() == "{}"
    assert not list(_private_home.glob(".settings.json.backup-*"))


@pytest.mark.parametrize("permissions", [0o600, 0o640, 0o444])
def test_a_symlinked_settings_target_keeps_whatever_permissions_it_had(_private_home: Path, permissions: int) -> None:
    target = _private_home / "dotfiles" / "settings.json"
    target.parent.mkdir()
    target.write_text("{}")
    target.chmod(permissions)
    link = _private_home / "link.json"
    link.symlink_to(target)
    code, _, _ = hooks("install", "--settings", str(link), home=_private_home)
    assert code == 0 and link.is_symlink() and target.stat().st_mode & 0o777 == permissions


def test_the_guard_never_reads_a_state_file_it_does_not_own_the_name_of(_private_home: Path, agents: Path) -> None:
    """Another session's state, and a file planted under a guessable name, are never trusted."""
    set_probe(_private_home, session="session-other")
    row = read_after(_private_home, agents, dispatch(prompt=NO_STEP))
    assert row["local_reachable"] is False and row["health"] == "unknown"
    (state_folder(_private_home) / "probe.json").write_text(json.dumps({"reachable": True, "ts": NOW.timestamp()}))
    assert read_after(_private_home, agents, dispatch(prompt=NO_STEP))["local_reachable"] is False


def test_the_guard_does_not_open_any_file_in_the_working_directory(
    _private_home: Path, agents: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    planted = tmp_path / "checkout"
    planted.mkdir()
    (planted / "agents.yaml").write_text("this: is: not yaml: [")
    (planted / "agents.local.yaml").write_text("this: is: not yaml: [")
    monkeypatch.chdir(planted)
    set_probe(_private_home)
    assert guard(_private_home, agents, dispatch())[1] == ""


def test_the_guard_refuses_an_agents_file_inside_the_workspace_under_actions(_private_home: Path, agents: Path) -> None:
    code, out, _ = guard(
        _private_home,
        agents,
        dispatch(model=None),
        env={"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(agents.parent)},
    )
    assert code == 0 and "degraded" in out and read_log(_private_home)[-1]["diagnostic"] == "config"


def test_a_session_start_prunes_probe_files_nobody_has_touched_for_a_week_and_nothing_else(
    _private_home: Path, agents: Path
) -> None:
    import os

    folder = state_folder(_private_home)
    folder.mkdir(parents=True)
    name = "probe-" + "a" * 64
    old = [folder / f"{name}.json", folder / f"{name}.json.lock", folder / f"{name}.json.attempt"]
    keep = [
        folder / "log.jsonl",
        folder / "log.jsonl.1",
        folder / "notes.txt",
        folder / ("probe-" + "b" * 64 + ".json"),
    ]
    for path in [*old, *keep]:
        path.write_text("{}")
        age = 8 * 86400 if path in old else 8 * 86400 if path.name == "notes.txt" else 60
        os.utime(path, (NOW.timestamp() - age, NOW.timestamp() - age))
    (folder / "probe-link.json").symlink_to(folder / "notes.txt")
    assert hooks("probe", "--agents", str(agents), home=_private_home)[0] == 0
    assert not any(p.exists() for p in old)
    assert all(p.exists() for p in keep[:3]) and keep[3].exists() and (folder / "probe-link.json").is_symlink()


# -- the approval token is a speed bump, and every place that mentions it says so ------------------------------


@pytest.mark.parametrize("mode", ["warn", "block"])
@pytest.mark.parametrize("model", ["opus", "inherit"])
def test_the_denial_and_the_warning_say_the_token_is_not_proof_of_approval(
    _private_home: Path, agents: Path, mode: str, model: str
) -> None:
    set_mode(_private_home, mode)
    text = reason(guard(_private_home, agents, dispatch(model=model))[1]).lower()
    assert "not proof of approval" in text and "speed bump" in text


def test_the_docs_and_the_readme_state_plainly_that_the_token_is_forgeable_and_name_the_roadmap() -> None:
    root = Path(__file__).resolve().parent.parent
    docs = (root / "docs" / "hooks.md").read_text().lower()
    assert "not proof of" in docs and "forge" in docs and "prompt-injected" in docs
    assert "known limits" in docs and "signed" in docs and "future work" in docs
    readme = (root / "README.md").read_text().lower()
    assert "approval token" in readme and "not proof" in readme


# -- the installer revalidates the identity of settings.json, not only its bytes --------------------------------


def _swap_inode_keeping_the_bytes(target: Path) -> None:
    """What another editor does: write the same bytes to a new file and rename it over the target."""
    twin = target.with_name("twin.json")
    twin.write_bytes(target.read_bytes())
    twin.replace(target)


def _install_with(monkeypatch: pytest.MonkeyPatch, during: Callable[[Path], None]) -> None:
    from safo.hooks import write_text as real

    def racing(
        path: Path,
        text: str,
        mode: int = 0o600,
        before_replace: Callable[[], None] | None = None,
        check_dir: bool = True,
    ) -> None:
        def intercept() -> None:
            during(path)
            assert before_replace is not None
            before_replace()

        real(path, text, mode, intercept, check_dir)

    monkeypatch.setattr("safo.modes.hooks.write_text", racing)


def test_an_inode_swapped_in_with_identical_bytes_before_the_replace_aborts_the_install(
    _private_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from safo.modes.hooks import install_settings

    settings = _private_home / "settings.json"
    settings.write_text('{"model": "sonnet"}\n')
    before = settings.read_bytes()
    _install_with(monkeypatch, _swap_inode_keeping_the_bytes)
    with pytest.raises(ConfigError, match="settings changed while installing"):
        install_settings(settings, "safo hooks probe", "safo hooks guard")
    assert settings.read_bytes() == before, "the file another editor made is not clobbered"
    assert not list(_private_home.glob(".settings.json.*")), "no temp file or backup is left behind"


def test_a_touch_that_changes_only_the_mtime_also_aborts_the_install(
    _private_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from safo.modes.hooks import install_settings

    settings = _private_home / "settings.json"
    settings.write_text('{"model": "sonnet"}\n')
    _install_with(monkeypatch, lambda path: os.utime(path, ns=(1, 1)))
    with pytest.raises(ConfigError, match="settings changed while installing"):
        install_settings(settings, "safo hooks probe", "safo hooks guard")


def test_an_untouched_settings_file_still_installs_with_the_identity_check_in_place(_private_home: Path) -> None:
    from safo.modes.hooks import install_settings

    settings = _private_home / "settings.json"
    settings.write_text('{"model": "sonnet"}\n')
    assert install_settings(settings, "safo hooks probe", "safo hooks guard") is True
    assert "safo hooks guard" in settings.read_text()


# -- two agents sharing a model: approval is required if any of them requires it -----------------------------


@pytest.mark.parametrize("model", ["sonnet", "SONNET", "claude-sonnet-4-5", "safe", "gated"])
@pytest.mark.parametrize("flip", [False, True])
def test_approval_does_not_depend_on_the_order_of_agents_sharing_a_model(model: str, flip: bool) -> None:
    from safo.agentsfile import Agent, AgentsFile, Hooks
    from safo.hooks import check_dispatch, decide

    safe = Agent("safe", "Safe", "claude", "r", model="sonnet", approval_required=False)
    gated = Agent("gated", "Gated", "claude", "r", model="sonnet", approval_required=True)
    agents = (gated, safe) if flip else (safe, gated)
    doc = AgentsFile(agents, (), (), (), hooks=Hooks())
    if model in ("safe", "gated"):
        # an id names exactly one agent: only that agent's own flag counts
        verdict = check_dispatch(doc, {"model": model, "prompt": "ordinary"}, False)
        assert (verdict.rules == ("approval",)) == (model == "gated")
        return
    verdict = check_dispatch(doc, {"model": model, "prompt": "ordinary"}, False)
    assert verdict.rules == ("approval",) and decide(verdict, "block") == "deny"
    # the logged model stays the enum: an alias is logged as itself, a full id never is (it logs as unknown)
    assert verdict.model == ("unknown" if model.startswith("claude-") else "sonnet")
    token = doc.hooks.approval_token
    assert check_dispatch(doc, {"model": model, "prompt": f"ordinary {token}"}, False).rules == ()
