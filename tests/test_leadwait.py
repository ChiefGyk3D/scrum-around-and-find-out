# SPDX-License-Identifier: Apache-2.0
"""The lead-never-waits rule: a lead session's foreground Bash call that waits is flagged or denied.

The cases that matter: the blocking forms, the allowed background form, a sub-agent (which may watch), an exemption
with a reason and one without, lookalike text that is not a command, and the documented sleep threshold.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from hooksdata import agents_file, hooks, probe_file, read_log, set_mode, set_probe
from safo import leadwait
from safo.agentsfile import load_agents
from safo.errors import ConfigError
from safo.hooks import bind_repo

THRESHOLD = leadwait.DEFAULT_SLEEP_THRESHOLD_SECONDS


def bash(command: str, **extra: Any) -> str:
    """The PreToolUse event Claude Code sends for a Bash call (tool_input carries command and run_in_background)."""
    tool_input: dict[str, Any] = {"command": command, "description": "sentinel-description"}
    tool_input.update({k: v for k, v in extra.items() if k != "event"})
    event: dict[str, Any] = {
        "hook_event_name": "PreToolUse",
        "session_id": "session-a",
        "tool_name": "Bash",
        "tool_input": tool_input,
    }
    event.update(extra.get("event", {}))
    return json.dumps(event)


# -- the analysis: what counts as a wait ---------------------------------------------------------------------

BLOCKING = [
    ("gh run watch 123456", "gh-run-watch"),
    ("gh run watch 123456 --exit-status && echo done", "gh-run-watch"),
    ("cd repo && gh run watch", "gh-run-watch"),
    ("gh pr checks 12 --watch", "gh-pr-checks-watch"),
    ("gh pr checks 12 -w", "gh-pr-checks-watch"),
    ("gh pr checks --watch --interval 5", "gh-pr-checks-watch"),
    ("sleep 120", "long-sleep"),
    ("sleep 2m", "long-sleep"),
    ("sleep 5; sleep 6", "long-sleep"),
    ("sleep $DELAY", "long-sleep"),
    ("while true; do gh run view 9 --json status; sleep 5; done", "sleep-loop"),
    ("until gh run view 9 | grep -q completed; do sleep 10; done", "sleep-loop"),
    ("for i in 1 2 3; do curl -s localhost; sleep 1; done", "sleep-loop"),
    ("echo start\nwhile [ -f /tmp/lock ]; do\n  sleep 1\ndone", "sleep-loop"),
    ("x=$(sleep 300)", "long-sleep"),
    ('echo "$(sleep 300)"', "long-sleep"),
]


@pytest.mark.parametrize(("command", "kind"), BLOCKING)
def test_the_blocking_forms_are_found(command: str, kind: str) -> None:
    assert kind in leadwait.find_waits(command, THRESHOLD)


LOOKALIKES = [
    'git commit -m "docs: never run gh run watch in the lead session"',
    "git commit -m 'use gh pr checks --watch only in a monitor agent'",
    "cat <<'EOF'\ngh run watch 1\nsleep 600\nwhile true; do sleep 5; done\nEOF",
    "cat <<EOF > docs/note.md\nthe lead never runs `gh run watch`\nEOF\ngit add docs/note.md",
    "cat <<-EOF\n\tgh pr checks --watch\n\tEOF\necho ok",
    "echo 'sleep 600'",
    "# gh run watch is forbidden here\nls",
    "ls  # sleep 600 would block",
    "grep -rn 'gh run watch' docs",
    "gh run list --limit 5",
    "gh pr checks 12",
    "gh run view 9 --log-failed",
    "sleep 1",
    "sleep 0.5 && echo ok",
    "sleep 9",
    'while read -r line; do echo "$line"; done < file',
    'for f in *.md; do wc -l "$f"; done',
    "cat file | xargs -n1 echo   # asleep",
    "mysleep 600",
]


@pytest.mark.parametrize("command", LOOKALIKES)
def test_lookalike_text_and_short_one_shot_sleeps_are_not_waits(command: str) -> None:
    assert leadwait.find_waits(command, THRESHOLD) == ()


def test_the_sleep_threshold_is_the_documented_one_and_a_setting() -> None:
    assert THRESHOLD == 10  # docs/hooks.md states 10 seconds; change both together
    assert leadwait.find_waits("sleep 9", THRESHOLD) == ()
    assert leadwait.find_waits("sleep 10", THRESHOLD) == ("long-sleep",)
    assert leadwait.find_waits("sleep 3", 2) == ("long-sleep",)
    assert leadwait.find_waits("sleep 60", 120) == ()
    assert leadwait.find_waits("sleep 1m", 120) == ()
    assert leadwait.find_waits("sleep 1m", 30) == ("long-sleep",)


def test_a_short_sleep_inside_a_loop_is_still_a_poll() -> None:
    assert leadwait.find_waits("while true; do sleep 1; done", THRESHOLD) == ("sleep-loop",)


def test_the_exemption_marker_needs_a_real_reason() -> None:
    assert leadwait.marker_reason("sleep 60  # lead-wait: ok - waiting for the DNS TTL, 60 s, no agent needed")
    assert not leadwait.marker_reason("sleep 60")
    assert not leadwait.marker_reason("sleep 60 # lead-wait: ok -")
    assert not leadwait.marker_reason("sleep 60 # lead-wait: ok -   ")
    assert not leadwait.marker_reason("sleep 60 # lead-wait: ok - fine")  # fewer than MIN_REASON_CHARS
    assert not leadwait.marker_reason("sleep 60 # lead-wait: ok")


# -- the hook: lead or sub-agent, background or not, mode, exemption -----------------------------------------


@pytest.fixture
def agents(tmp_path: Path) -> Path:
    return agents_file(tmp_path / "agents.yaml")


def guard(home: Path, agents: Path, payload: str) -> tuple[int, str, str]:
    return hooks("guard", "--agents", str(agents), home=home, stdin=payload)


def test_a_foreground_wait_in_the_lead_is_flagged_in_warn_mode_and_allowed(_private_home: Path, agents: Path) -> None:
    code, out, _ = guard(_private_home, agents, bash("gh run watch 123456"))
    data = json.loads(out)
    assert code == 0 and "(warn mode: allowed)" in data["systemMessage"]
    assert "lead never waits" in data["systemMessage"]
    assert "run_in_background" in data["systemMessage"] and "Sonnet" in data["systemMessage"]
    assert "permissionDecision" not in data["hookSpecificOutput"]
    row = read_log(_private_home)[-1]
    assert row["decision"] == "warn" and row["rules"] == ["lead-waits"] and row["mode"] == "warn"


def test_a_foreground_wait_in_the_lead_is_denied_in_block_mode(_private_home: Path, agents: Path) -> None:
    set_mode(_private_home, "block")
    code, out, _ = guard(_private_home, agents, bash("gh pr checks 12 --watch"))
    decision = json.loads(out)["hookSpecificOutput"]
    assert code == 0 and decision["permissionDecision"] == "deny"
    assert "run_in_background" in decision["permissionDecisionReason"]
    assert read_log(_private_home)[-1]["decision"] == "deny"


def test_the_background_form_is_allowed(_private_home: Path, agents: Path) -> None:
    set_mode(_private_home, "block")
    assert guard(_private_home, agents, bash("gh run watch 123456", run_in_background=True)) == (0, "", "")
    assert read_log(_private_home) == []


@pytest.mark.parametrize("value", [False, None, "true", 1, "yes"])
def test_only_a_real_true_counts_as_background(_private_home: Path, agents: Path, value: object) -> None:
    set_mode(_private_home, "block")
    out = guard(_private_home, agents, bash("gh run watch 1", run_in_background=value))[1]
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_a_sub_agent_may_watch(_private_home: Path, agents: Path) -> None:
    """Inside a sub-agent the host adds `agent_id` to the event; the rule is about the lead's main thread."""
    set_mode(_private_home, "block")
    payload = bash("gh run watch 1", event={"agent_id": "agent-1", "agent_type": "general-purpose"})
    assert guard(_private_home, agents, payload) == (0, "", "")
    assert read_log(_private_home) == []


def test_the_log_and_the_message_never_carry_the_command(_private_home: Path, agents: Path) -> None:
    secret = "sentinel-token-xyz"
    out = guard(_private_home, agents, bash(f"gh run watch 1 # {secret}"))[1]
    assert secret not in out
    assert secret not in (_private_home / ".local/state/safo/hooks/log.jsonl").read_text()
    assert "sentinel-description" not in out


def test_a_clean_bash_call_prints_nothing_and_logs_nothing(_private_home: Path, agents: Path) -> None:
    assert guard(_private_home, agents, bash("ls -la && git status")) == (0, "", "")
    assert read_log(_private_home) == []


def test_lookalike_text_in_a_real_call_does_not_trip_the_hook(_private_home: Path, agents: Path) -> None:
    set_mode(_private_home, "block")
    msg = 'git commit -m "docs: the lead never runs gh run watch"'
    assert guard(_private_home, agents, bash(msg)) == (0, "", "")
    assert guard(_private_home, agents, bash("cat <<'EOF'\ngh run watch 5\nEOF")) == (0, "", "")
    assert guard(_private_home, agents, bash("sleep 1")) == (0, "", "")


def test_an_exemption_with_a_reason_lets_the_call_through_and_is_logged_as_allow(
    _private_home: Path, agents: Path
) -> None:
    set_mode(_private_home, "block")
    cmd = "sleep 45  # lead-wait: ok - waiting out a 45 s DNS TTL before the next check, nothing to delegate"
    assert guard(_private_home, agents, bash(cmd)) == (0, "", "")
    row = read_log(_private_home)[-1]
    assert row["decision"] == "allow" and row["rules"] == ["lead-waits"]


@pytest.mark.parametrize(
    "tail", ["", "  # lead-wait: ok", "  # lead-wait: ok -", "  # lead-wait: ok -    ", "  # lead-wait: ok - short"]
)
def test_an_exemption_without_a_reason_is_refused(_private_home: Path, agents: Path, tail: str) -> None:
    set_mode(_private_home, "block")
    out = guard(_private_home, agents, bash("sleep 45" + tail))[1]
    reason = json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"]
    assert "lead-wait: ok - <reason>" in reason


def test_the_marker_inside_a_heredoc_or_string_is_still_only_a_marker_not_a_bypass_of_the_reason_rule(
    _private_home: Path, agents: Path
) -> None:
    set_mode(_private_home, "block")
    out = guard(_private_home, agents, bash("sleep 45 # lead-wait: ok - x"))[1]
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_the_configured_mode_off_disables_the_rule_and_block_overrides_a_warn_mode(
    _private_home: Path, tmp_path: Path
) -> None:
    off = agents_file(tmp_path / "off.yaml", lead_wait={"mode": "off"})
    set_mode(_private_home, "block")
    assert guard(_private_home, off, bash("gh run watch 1")) == (0, "", "")
    block = agents_file(tmp_path / "block.yaml", lead_wait={"mode": "block"})
    set_mode(_private_home, "warn")
    out = guard(_private_home, block, bash("gh run watch 1"))[1]
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    warn = agents_file(tmp_path / "warn.yaml", lead_wait={"mode": "warn"})
    set_mode(_private_home, "block")
    out = guard(_private_home, warn, bash("gh run watch 1"))[1]
    assert "permissionDecision" not in json.loads(out)["hookSpecificOutput"]


def test_the_configured_threshold_applies(_private_home: Path, tmp_path: Path) -> None:
    strict = agents_file(tmp_path / "s.yaml", lead_wait={"sleep_threshold_seconds": 3})
    assert guard(_private_home, strict, bash("sleep 4"))[1] != ""
    assert guard(_private_home, strict, bash("sleep 2"))[1] == ""


def test_a_repository_exemption_needs_a_reason_and_applies_to_the_bound_repository_only(
    _private_home: Path, tmp_path: Path
) -> None:
    entry = {"repo": "acme/scratch", "reason": "a throwaway repo where nobody is waiting on the lead"}
    exempt = agents_file(tmp_path / "e.yaml", lead_wait={"exempt_repos": [entry]})
    set_mode(_private_home, "block")
    set_probe(_private_home, agents=exempt)
    assert guard(_private_home, exempt, bash("gh run watch 1"))[1] != ""  # not bound: never exempt
    assert bind_repo(probe_file(_private_home, exempt), "Acme/Scratch", "startup") == "bound"
    assert guard(_private_home, exempt, bash("gh run watch 1")) == (0, "", "")
    assert read_log(_private_home)[-1]["decision"] == "allow"


@pytest.mark.parametrize("reason", ["", "   ", "short", None, 5])
def test_a_repository_exemption_without_a_usable_reason_refuses_to_load(tmp_path: Path, reason: object) -> None:
    path = agents_file(tmp_path / "bad.yaml", lead_wait={"exempt_repos": [{"repo": "acme/scratch", "reason": reason}]})
    with pytest.raises(ConfigError, match=r"lead_wait\.exempt_repos\[0\]"):
        load_agents(path)


@pytest.mark.parametrize(
    "bad",
    [
        {"mode": "loud"},
        {"sleep_threshold_seconds": 0},
        {"sleep_threshold_seconds": 99999},
        {"exempt_repos": ["acme/scratch"]},
        {"exempt_repos": [{"repo": "scratch", "reason": "a perfectly good reason here"}]},
        {"unknown_key": 1},
    ],
)
def test_a_malformed_lead_wait_section_is_refused(tmp_path: Path, bad: dict[str, Any]) -> None:
    with pytest.raises(ConfigError):
        load_agents(agents_file(tmp_path / "bad.yaml", lead_wait=bad))


def test_a_broken_agents_file_degrades_visibly_on_a_waiting_call_and_stays_silent_otherwise(
    _private_home: Path, tmp_path: Path
) -> None:
    broken = tmp_path / "broken.yaml"
    broken.write_text("a: [unclosed\n")
    out = guard(_private_home, broken, bash("gh run watch 1"))[1]
    assert "SAFO routing guard degraded" in out
    assert guard(_private_home, broken, bash("ls"))[1] == ""


def test_garbage_in_a_bash_event_fails_open_visibly(_private_home: Path, agents: Path) -> None:
    for payload in (
        json.dumps({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash", "tool_input": []}),
        json.dumps({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash", "tool_input": {}}),
        json.dumps(
            {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash", "tool_input": {"command": 5}}
        ),
    ):
        code, out, _ = guard(_private_home, agents, payload)
        assert code == 0
        assert out == "" or "SAFO routing guard degraded" in out


def test_the_install_matcher_covers_bash_and_an_older_install_is_migrated(_private_home: Path, tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    old = {
        "hooks": {
            "PreToolUse": [
                {"matcher": "Agent|Task", "hooks": [{"type": "command", "command": "safo hooks guard", "timeout": 10}]}
            ]
        }
    }
    settings.write_text(json.dumps(old))
    assert hooks("install", "--settings", str(settings), home=_private_home)[0] == 0
    groups = json.loads(settings.read_text())["hooks"]["PreToolUse"]
    assert [g["matcher"] for g in groups] == ["Agent|Task|Bash"]
    assert len(groups[0]["hooks"]) == 1


# -- the docs keep their promises ----------------------------------------------------------------------------

DOCS = Path(__file__).parent.parent / "docs"


def test_the_docs_state_the_threshold_the_code_uses_and_the_shipped_file_sets_it() -> None:
    hooks_page = (DOCS / "hooks.md").read_text(encoding="utf-8")
    assert f"{leadwait.DEFAULT_SLEEP_THRESHOLD_SECONDS} seconds by default" in hooks_page
    shipped = load_agents(DOCS.parent / "agents.yaml").hooks.lead_wait
    assert shipped.sleep_threshold_seconds == leadwait.DEFAULT_SLEEP_THRESHOLD_SECONDS and shipped.mode == "follow"


def test_the_orchestrator_page_carries_the_rules_the_incident_and_the_monitor_brief() -> None:
    page = " ".join((DOCS / "orchestrator.md").read_text(encoding="utf-8").split())
    for needle in (
        "The lead never waits",
        "Independent steps go in one response",
        "answer in the turn it arrives",
        "A hung step is reported after 5 minutes, not 20",
        "2026-10-25",
        "about **10 minutes**",
        "**2 more minutes**",
        "read-only",
        "quoted verbatim",
        "no progress for 5 minutes",
        'model: "sonnet"',
        "issue: <owner/repo#N>",
    ):
        assert needle in page, needle
