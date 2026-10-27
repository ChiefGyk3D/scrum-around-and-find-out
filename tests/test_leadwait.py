# SPDX-License-Identifier: Apache-2.0
"""The lead-never-waits rule: a lead session's foreground Bash call that waits is flagged or denied.

The cases that matter: the blocking forms, the allowed background form, a sub-agent (which may watch), an exemption
with a reason and one without, lookalike text that is not a command, and the documented sleep threshold.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
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
    # Round 2: this lookalike had an UNQUOTED delimiter, but bash really runs `gh run watch` in backticks there
    # (finding 3), so the old expectation encoded the bug. The delimiter is quoted now; the unquoted form is flagged
    # in BODY_EXPANSION.
    "cat <<'EOF' > docs/note.md\nthe lead never runs `gh run watch`\nEOF\ngit add docs/note.md",
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


# -- PR #77 review: command data is not code, and a marker is a real comment ----------------------------------

REASON = "waiting out a 45 s DNS TTL before the next check, nothing to delegate"


def denied(home: Path, agents: Path, command: str) -> bool:
    """Block mode: True when the hook denies the call, False when it lets it through with no output at all."""
    set_mode(home, "block")
    out = guard(home, agents, bash(command))[1]
    return bool(out) and json.loads(out)["hookSpecificOutput"].get("permissionDecision") == "deny"


@pytest.mark.parametrize(
    "command",
    [
        # thread 1 and 4, verbatim: the marker is data in a quoted argument, not an inline comment
        "sleep 45; echo 'lead-wait: ok - this is a sufficiently long reason'",
        'sleep 45; git commit -m "lead-wait: ok - approved by maintainer for this one"',
        # adversarial: heredoc body, double quotes around $(...), a # inside a quoted string, an argument
        f"sleep 45; cat <<EOF\n# lead-wait: ok - {REASON}\nEOF",
        f"sleep 45; cat <<'EOF'\n# lead-wait: ok - {REASON}\nEOF",
        f'sleep 45; echo "$(date) # lead-wait: ok - {REASON}"',
        f"sleep 45; echo 'x # lead-wait: ok - {REASON}'",
        f'sleep 45; echo "x # lead-wait: ok - {REASON}"',
        f"sleep 45; echo lead-wait: ok - {REASON}",
        f"sleep 45; echo \\# lead-wait: ok - {REASON}",  # an escaped # is a word, not a comment
    ],
)
def test_a_marker_that_is_only_data_does_not_exempt(_private_home: Path, agents: Path, command: str) -> None:
    assert leadwait.marker_reason(command) == ""
    assert denied(_private_home, agents, command)


@pytest.mark.parametrize(
    "command",
    [
        f"sleep 45  # lead-wait: ok - {REASON}",
        f"sleep 45 # lead-wait: ok - {REASON}\necho done",
        f"# lead-wait: ok - {REASON}\nsleep 45",  # the call is one decision: any real comment counts
        f"echo 'a # b'; sleep 45 # lead-wait: ok - {REASON}",
        f'echo "$(date)"; sleep 45 # lead-wait: ok - {REASON}',
        f"cat <<EOF\nbody\nEOF\nsleep 45 # lead-wait: ok - {REASON}",
    ],
)
def test_a_real_comment_marker_with_a_real_reason_exempts(_private_home: Path, agents: Path, command: str) -> None:
    assert leadwait.marker_reason(command) == REASON
    assert not denied(_private_home, agents, command)
    assert read_log(_private_home)[-1]["decision"] == "allow"


def test_a_real_comment_marker_with_a_short_reason_is_refused_and_says_a_reason_is_required(
    _private_home: Path, agents: Path
) -> None:
    set_mode(_private_home, "block")
    out = guard(_private_home, agents, bash("sleep 45 # lead-wait: ok - fine"))[1]
    reason = json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"]
    assert "reason is required" in reason and "lead-wait: ok - <reason>" in reason


@pytest.mark.parametrize(
    "command",
    [
        "echo gh run watch",  # thread 2, verbatim
        "echo sleep 60",  # thread 2, verbatim
        "echo gh pr checks 12 --watch",
        "printf '%s' sleep 600",
        "git log --grep sleep 600",
        "man sleep 600",
        "echo gh run watch && ls",
        "echo start; echo sleep 60 | cat",
    ],
)
def test_plain_text_arguments_are_not_waits(_private_home: Path, agents: Path, command: str) -> None:
    assert leadwait.find_waits(command, THRESHOLD) == ()
    assert not denied(_private_home, agents, command)


def test_a_loop_is_a_poll_only_when_the_sleep_is_in_its_body() -> None:
    thread3 = 'while read line; do echo "$line"; done < file; sleep 1'  # thread 3, verbatim
    assert leadwait.find_waits(thread3, THRESHOLD) == ()  # the sleep is after the loop, and under the threshold
    assert leadwait.find_waits("sleep 1", THRESHOLD) == ()
    assert leadwait.find_waits(thread3.replace("sleep 1", "sleep 12"), THRESHOLD) == ("long-sleep",)
    assert leadwait.find_waits("sleep 1; while true; do echo x; done", THRESHOLD) == ()
    assert leadwait.find_waits("for f in a b; do echo $f; done; sleep 2", THRESHOLD) == ()
    assert leadwait.find_waits("for i in 1 2 3; do echo $i; done", THRESHOLD) == ()
    # a sleep in a later loop is a poll, one after the first loop is not
    assert leadwait.find_waits("for f in a; do echo $f; done; while true; do sleep 1; done", THRESHOLD) == (
        "sleep-loop",
    )
    # a nested loop: the sleep sits inside the inner body, which is inside the outer one
    assert leadwait.find_waits("while a; do for i in 1; do sleep 1; done; done", THRESHOLD) == ("sleep-loop",)
    assert leadwait.find_waits("while a; do for i in 1; do echo; done; done; sleep 1", THRESHOLD) == ()


def test_the_thread_3_command_is_allowed_in_block_mode(_private_home: Path, agents: Path) -> None:
    assert not denied(_private_home, agents, 'while read line; do echo "$line"; done < file; sleep 1')


POSITIONS = [
    ("ls && gh run watch 1", "gh-run-watch"),
    ("ls; gh run watch 1", "gh-run-watch"),
    ("ls || gh run watch 1", "gh-run-watch"),
    ("ls | gh run watch 1", "gh-run-watch"),
    ("ls &\ngh run watch 1", "gh-run-watch"),
    ("(gh run watch 1)", "gh-run-watch"),
    ('echo "$(gh run watch 1)"', "gh-run-watch"),  # code inside double quotes still runs
    ('echo "`gh run watch 1`"', "gh-run-watch"),
    ("x=$(gh run watch 1)", "gh-run-watch"),
    ("diff <(gh run watch 1) file", "gh-run-watch"),
    ("time gh run watch", "gh-run-watch"),
    ("FOO=1 sleep 60", "long-sleep"),
    ("FOO=1 BAR='a b' gh pr checks 3 -w", "gh-pr-checks-watch"),
    ("nohup sleep 60 &", "long-sleep"),  # a shell `&` is not run_in_background: the payload flag is what exempts
    ("sudo -u build nice -n 5 sleep 60", "long-sleep"),
    ("env -u HOME FOO=1 gh run watch 2", "gh-run-watch"),
    ("timeout 600 gh run watch 2", "gh-run-watch"),
    ("command sleep 60", "long-sleep"),
    ("/usr/bin/gh run watch", "gh-run-watch"),
    ("sleep 60 > /dev/null 2>&1", "long-sleep"),
    ("sleep 5 &>/dev/null; sleep 6", "long-sleep"),
    ("while true; do gh pr checks 1 -w; sleep 5; done", "sleep-loop"),
    ("while true; do\n  sleep 1 # poll\ndone", "sleep-loop"),
    ("until gh run view 9; do\\\n  sleep 1; done", "sleep-loop"),
    ("sleep 1; sleep 2; while true; do sleep 1; done &", "sleep-loop"),
]


@pytest.mark.parametrize(("command", "kind"), POSITIONS)
def test_a_wait_at_command_position_is_found_however_it_is_reached(command: str, kind: str) -> None:
    assert kind in leadwait.find_waits(command, THRESHOLD)


def test_the_loop_with_a_poll_and_a_watch_reports_both() -> None:
    kinds = leadwait.find_waits("while true; do gh pr checks 1 -w; sleep 5; done", THRESHOLD)
    assert kinds == ("gh-pr-checks-watch", "sleep-loop")


NOT_AT_POSITION = [
    "echo 'ls; gh run watch 1'",  # single quotes are data
    'echo "ls; gh run watch 1"',
    "echo '$(gh run watch 1)'",
    "cat <<'EOF'\n$(gh run watch 1)\nEOF",
    "for i in a b; do echo gh run watch; done",  # a for loop that only echoes
    "for i in 1 2 3; do echo sleep 5; done",
    "for sleep in a b; do echo $sleep; done",
    "command -v sleep",
    "FOO=sleep echo 60",
    "echo $(( 1 << 2 )) gh run watch",
    "gh pr view 1 --comments 'sleep 600' --json body",
    "echo gh run watch # real comment",
    "ssh host 'sleep 600'",  # runs elsewhere
    # (round 2: `xargs sleep 600` used to be listed here as a limit; xargs is now a wrapper, see the INDIRECTION cases)
]


@pytest.mark.parametrize("command", NOT_AT_POSITION)
def test_text_that_is_not_a_command_is_not_a_wait(command: str) -> None:
    assert leadwait.find_waits(command, THRESHOLD) == ()


def test_shell_string_bodies_and_eval_are_scanned_and_echoing_them_is_not() -> None:
    """Decision: `bash -c '...'`, `sh -c`, `-lc` and `eval` run their string as code, so the string is scanned (to a
    depth of MAX_DEPTH); the same words as arguments to anything else are data."""
    assert leadwait.find_waits("bash -c 'gh run watch 1'", THRESHOLD) == ("gh-run-watch",)
    assert leadwait.find_waits('sh -c "sleep 60"', THRESHOLD) == ("long-sleep",)
    assert leadwait.find_waits("bash -lc 'while true; do sleep 1; done'", THRESHOLD) == ("sleep-loop",)
    assert leadwait.find_waits("eval 'gh pr checks 1 --watch'", THRESHOLD) == ("gh-pr-checks-watch",)
    assert leadwait.find_waits("while true; do bash -c 'sleep 1'; done", THRESHOLD) == ("sleep-loop",)
    assert leadwait.find_waits("echo bash -c 'gh run watch 1'", THRESHOLD) == ()
    assert leadwait.find_waits("bash script.sh", THRESHOLD) == ()  # the script file is not read
    deep = 'bash -c \'bash -c "bash -c \\"bash -c \\\\\\"sleep 600\\\\\\"\\""\''
    # Round 2: this used to assert (), which blessed a fail-open (a depth-four wait was silently allowed). Past
    # MAX_DEPTH the verdict is now explicit: unscannable-depth, which block mode denies.
    assert leadwait.find_waits(deep, THRESHOLD) == ("unscannable-depth",)


def test_deeply_nested_substitutions_do_not_crash_the_scanner() -> None:
    command = "echo " + "$(" * 500 + "sleep 600" + ")" * 500
    assert leadwait.find_waits(command, THRESHOLD) == ("unscannable-depth",)  # round 2: was (), a fail-open
    leadwait.find_waits("echo " + "`" * 5000, THRESHOLD)  # only has to return


# -- thread 5: the install and guard text says Bash as well ----------------------------------------------------


def test_the_install_messages_and_the_guard_help_say_the_guard_covers_bash(
    _private_home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    settings = tmp_path / "settings.json"
    dry = hooks("install", "--settings", str(settings), home=_private_home, dry_run=True)[1]
    assert "PreToolUse (Agent and Bash) guard" in dry
    done = hooks("install", "--settings", str(settings), home=_private_home)[1]
    assert "installed the SessionStart probe and the PreToolUse (Agent and Bash) guard" in done
    for argv in (("guard", "--help"), ("--help",)):  # the guard's own help, and the list of hooks subcommands
        with pytest.raises(SystemExit):
            hooks(*argv, home=_private_home)
        helped = " ".join(capsys.readouterr().out.split())
        assert "Agent and Bash tools" in helped, argv


# -- round 2: an adversarial review of the tokenizer -------------------------------------------------------------

# Every way bash accepts to spell the delimiter EOF. The scanner must read the COMPLETE word and remove its quotes.
DELIMITER_SPELLINGS = ["EOF", "'EOF'", '"EOF"', "\\EOF", "E'OF'", 'E"O"F', "EO\\F", "$'EOF'", '$"EOF"', "E$'O'F"]
QUOTED_SPELLINGS = [d for d in DELIMITER_SPELLINGS if d != "EOF"]

HEREDOC_LATER_WAIT = [f"cat <<{d}\nharmless body\nEOF\nsleep 60" for d in DELIMITER_SPELLINGS] + [
    f"cat <<-{d}\n\tharmless body\n\tEOF\nsleep 60" for d in DELIMITER_SPELLINGS
]
HEREDOC_FORGED_MARKER = [
    f"sleep 45\ncat <<{d}\n# lead-wait: ok - waiting for an intentionally approved operation\nEOF"
    for d in DELIMITER_SPELLINGS
] + [
    f"sleep 45\ncat <<-{d}\n\t# lead-wait: ok - waiting for an intentionally approved operation\n\tEOF"
    for d in DELIMITER_SPELLINGS
]


@pytest.mark.parametrize("command", HEREDOC_LATER_WAIT)
def test_finding_1_a_quoted_or_concatenated_heredoc_delimiter_does_not_hide_a_later_wait(
    _private_home: Path, agents: Path, command: str
) -> None:
    assert leadwait.find_waits(command, THRESHOLD) == ("long-sleep",)
    assert denied(_private_home, agents, command)


def test_finding_1_the_review_repro_is_denied(_private_home: Path, agents: Path) -> None:
    assert denied(_private_home, agents, "cat <<E'OF'\nharmless body\nEOF\nsleep 60")


@pytest.mark.parametrize("command", HEREDOC_FORGED_MARKER)
def test_finding_2_heredoc_data_cannot_forge_the_exemption_marker(
    _private_home: Path, agents: Path, command: str
) -> None:
    assert leadwait.marker_reason(command) == ""
    assert denied(_private_home, agents, command)


def test_finding_2_the_review_repro_is_denied(_private_home: Path, agents: Path) -> None:
    command = "sleep 45\ncat <<\\EOF\n# lead-wait: ok - waiting for an intentionally approved operation\nEOF"
    assert denied(_private_home, agents, command)


def test_the_delimiter_word_must_match_whole_not_by_prefix() -> None:
    # <<EOFX ends at a line that is exactly EOFX; the line EOF and the sleep before it are body
    assert leadwait.find_waits("cat <<EOFX\nEOF\nsleep 60\nEOFX", THRESHOLD) == ()
    assert leadwait.find_waits("cat <<E\nbody\nE\nsleep 60", THRESHOLD) == ("long-sleep",)
    assert (
        leadwait.find_waits("cat <<EOF\nsleep 60\n EOF\nEOF\necho ok", THRESHOLD) == ()
    )  # a space is not a terminator
    assert leadwait.find_waits("cat <<-EOF\n\tsleep 60\n\tEOF\necho ok", THRESHOLD) == ()


BODY_EXPANSION = [
    ("cat <<EOF\n$(sleep 60)\nEOF", "long-sleep"),
    ("cat <<EOF\nnow: `sleep 60`\nEOF", "long-sleep"),
    ("cat <<EOF\nvalue ${x:-$(sleep 60)}\nEOF", "long-sleep"),
    ("cat <<-EOF\n\t$(gh run watch 1)\n\tEOF", "gh-run-watch"),
    ('cat <<EOF\n"$(sleep 60)"\nEOF', "long-sleep"),  # quotes are literal in a body, the substitution still runs
    ("cat <<EOF\n$(sleep 60)\nEOF\necho after", "long-sleep"),
]
BODY_OPAQUE = [
    "cat <<'EOF'\n$(sleep 60)\nEOF",
    'cat <<"EOF"\n$(sleep 60)\nEOF',
    "cat <<\\EOF\n$(sleep 60)\nEOF",
    "cat <<E'OF'\n`sleep 60`\nEOF",
    "cat <<EOF\n\\$(sleep 60)\nEOF",  # an escaped $ is text even in an unquoted body
    "cat <<EOF\n\\`sleep 60\\`\nEOF",
    "cat <<EOF\nsleep 60 is just text\nEOF",
    "cat <<EOF\n$((1 + 2)) and $HOME and ${HOME}\nEOF",
]


@pytest.mark.parametrize(("command", "kind"), BODY_EXPANSION)
def test_finding_3_an_unquoted_heredoc_body_runs_its_substitutions(command: str, kind: str) -> None:
    assert leadwait.find_waits(command, THRESHOLD) == (kind,)


@pytest.mark.parametrize("command", BODY_OPAQUE)
def test_finding_3_a_quoted_heredoc_body_and_escaped_text_stay_data(command: str) -> None:
    assert leadwait.find_waits(command, THRESHOLD) == ()


PARAMETER_EXPANSION = [
    ("echo ${value:-$(sleep 60)}", "long-sleep"),
    ('echo "${value:-$(sleep 60)}"', "long-sleep"),
    ("echo ${value:-`sleep 60`}", "long-sleep"),
    ('echo ${value:-"$(sleep 60)"}', "long-sleep"),
    ("echo ${a:-${b:-$(gh run watch 1)}}", "gh-run-watch"),
    ("echo $(( $(sleep 60) + 1 ))", "long-sleep"),  # arithmetic can run a substitution too
    ("echo $(( a[$(sleep 60)] ))", "long-sleep"),
]
PARAMETER_PLAIN = [
    "echo ${value:-default}",
    "echo ${#value} ${value%%a*} ${value/sleep 60/x}",
    "echo ${value:-'$(sleep 60)'}",  # single quotes inside ${} keep the text literal
    "echo ${value:-\\$(sleep 60)}",
    'echo $(( 1 + 2 )) ${x:-} "${y}"',
]


@pytest.mark.parametrize(("command", "kind"), PARAMETER_EXPANSION)
def test_finding_4_substitutions_inside_parameter_and_arithmetic_expansion_are_scanned(command: str, kind: str) -> None:
    assert leadwait.find_waits(command, THRESHOLD) == (kind,)


@pytest.mark.parametrize("command", PARAMETER_PLAIN)
def test_finding_4_plain_parameter_expansions_are_not_waits(command: str) -> None:
    assert leadwait.find_waits(command, THRESHOLD) == ()


# Executable syntax nested deeper than MAX_DEPTH cannot be checked, so it is its own verdict: never silently allowed.
TOO_DEEP = [
    "echo $(echo $(echo $(echo $(sleep 60))))",  # the review repro: depth four
    "echo $(echo $(echo $(echo $(echo ok))))",  # nothing waits in it, but it cannot be known: still unscannable
    "echo `echo $(echo $(echo $(sleep 60)))`",
    'bash -c "bash -c \'bash -c \\"bash -c \\\\\\"sleep 600\\\\\\"\\"\'"',
    "echo ${a:-${b:-${c:-${d:-$(sleep 60)}}}}",
    "cat <<EOF\n$(echo $(echo $(echo $(sleep 60))))\nEOF",
    "echo " + "$(" * 500 + "sleep 600" + ")" * 500,
]


@pytest.mark.parametrize("command", TOO_DEEP)
def test_finding_5_nesting_beyond_the_limit_is_an_explicit_verdict_not_a_pass(
    _private_home: Path, agents: Path, command: str
) -> None:
    assert leadwait.find_waits(command, THRESHOLD) == ("unscannable-depth",)
    assert denied(_private_home, agents, command)


def test_finding_5_the_deny_text_names_the_rule_and_not_the_command(_private_home: Path, agents: Path) -> None:
    set_mode(_private_home, "block")
    out = guard(_private_home, agents, bash("echo $(echo $(echo $(echo $(sleep 60)))) sentinel-arg-xyz"))[1]
    reason = json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"]
    assert "unscannable-depth" in reason and "sentinel-arg-xyz" not in out
    assert read_log(_private_home)[-1]["rules"] == ["lead-waits"]


def test_finding_5_warn_mode_shows_a_visible_warning(_private_home: Path, agents: Path) -> None:
    out = guard(_private_home, agents, bash("echo $(echo $(echo $(echo $(sleep 60))))"))[1]
    data = json.loads(out)
    assert "unscannable-depth" in data["systemMessage"] and "warn mode: allowed" in data["systemMessage"]


def test_finding_5_nesting_at_the_limit_is_still_scanned() -> None:
    assert leadwait.find_waits("echo $(echo $(echo $(sleep 60)))", THRESHOLD) == ("long-sleep",)
    assert leadwait.find_waits("echo $(echo $(echo $(echo $(echo ok))))", THRESHOLD) == ("unscannable-depth",)
    assert leadwait.find_waits("echo $(echo $(echo $(echo ok)))", THRESHOLD) == ()


INDIRECTION = [
    ("env -S 'sleep 60'", "long-sleep"),
    ("env --split-string='sleep 60'", "long-sleep"),
    ("env --split-string 'gh run watch 1'", "gh-run-watch"),
    ("env -S'gh pr checks 1 --watch'", "gh-pr-checks-watch"),
    ("env -i FOO=1 -S 'sleep 60'", "long-sleep"),
    ("sudo env -S 'sleep 60'", "long-sleep"),
    ("xargs sleep 60", "long-sleep"),
    ("xargs -n1 sleep 60", "long-sleep"),
    ("echo foo | xargs -I{} sleep 600", "long-sleep"),
    ("echo foo | xargs -I {} -P 4 gh run watch {}", "gh-run-watch"),
    ("echo foo | xargs --max-args=1 sleep 60", "long-sleep"),
    ("find . -exec sleep 60 \\;", "long-sleep"),
    ("find . -name x -execdir gh run watch {} +", "gh-run-watch"),
    ("find . -exec sh -c 'sleep 60' \\;", "long-sleep"),
]
INDIRECTION_QUIET = [
    "xargs echo sleep 60",  # xargs runs echo
    "xargs",  # runs echo
    "env -S 'echo sleep 60'",
    "find . -name sleep -print",
    "find . -exec echo sleep 60 \\;",
    "find . -name '*.md' -exec grep -l 'gh run watch' {} +",
]


@pytest.mark.parametrize(("command", "kind"), INDIRECTION)
def test_finding_6_env_split_string_xargs_and_find_exec_are_followed(command: str, kind: str) -> None:
    assert leadwait.find_waits(command, THRESHOLD) == (kind,)


@pytest.mark.parametrize("command", INDIRECTION_QUIET)
def test_finding_6_the_command_that_xargs_env_and_find_run_decides(command: str) -> None:
    assert leadwait.find_waits(command, THRESHOLD) == ()


# What a tokenizer cannot decide. Each of these is documented in docs/hooks.md "Known limits" and ALLOWED today; if
# one starts being detected, update the docs in the same change.
KNOWN_LIMITS = {
    "variable-built command": "cmd='sleep 60'; $cmd",
    "variable passed to a shell": "c='sleep 60'; bash -c \"$c\"",
    "encoded payload piped to a shell": "echo c2xlZXAgNjA= | base64 -d | sh",
    "interpreter": "python3 -c 'import time; time.sleep(60)'",
    "script file": "bash poll.sh",
    "alias": "alias w='sleep 60'; w",
    "remote command": "ssh host 'sleep 60'",
    "variable behind eval": 'x="sleep 60"; eval "$x"',
    "variable behind command": "x=sleep; command $x 60",
    "variable behind exec": "x=sleep; exec $x 60",
}


@pytest.mark.parametrize("name", list(KNOWN_LIMITS))
def test_finding_6_each_documented_limit_is_allowed_and_named_in_the_docs(name: str) -> None:
    assert leadwait.find_waits(KNOWN_LIMITS[name], THRESHOLD) == ()
    page = " ".join((DOCS / "hooks.md").read_text(encoding="utf-8").split())
    assert f"[limit: {name}]" in page


def test_finding_6_the_docs_say_this_is_a_speed_bump_and_not_a_sandbox() -> None:
    page = " ".join((DOCS / "hooks.md").read_text(encoding="utf-8").split())
    assert "speed bump against accidents, not a sandbox" in page
    assert "edit the guard's config, mode file and logs" in page


DORMANT = [
    "poll_later() { sleep 60; }",
    "poll_later() {\n  sleep 60\n}",
    "function poll_later { sleep 60; }",
    "function poll_later() { sleep 60; }",
    "poll_later() { gh run watch 1; }; echo poll_later",  # the name as an argument is not a call
    "poll_later() { gh run watch 1; }; cat poll_later",
    "poll_later() { if true; then { sleep 60; }; fi; }",
    "poll_later() { while true; do sleep 1; done; }",
]
CALLED = [
    ("poll_later() { sleep 60; }; poll_later", "long-sleep"),
    ("poll_later() {\n  sleep 60\n}\npoll_later", "long-sleep"),
    ("function poll_later { sleep 60; }\npoll_later", "long-sleep"),
    ("function poll_later() { gh run watch 1; }; ls && poll_later", "gh-run-watch"),
    ("poll_later() { while true; do sleep 1; done; }; poll_later", "sleep-loop"),
    ("poll_later() { sleep 1; }; while true; do poll_later; done", "sleep-loop"),
    ("inner() { sleep 60; }; outer() { inner; }; outer", "long-sleep"),
    ("poll_later() { sleep 60; }; poll_later() { echo hi; }; echo ok", ""),
]


@pytest.mark.parametrize("command", DORMANT)
def test_finding_7_a_function_that_is_defined_and_never_called_does_not_wait(
    _private_home: Path, agents: Path, command: str
) -> None:
    assert leadwait.find_waits(command, THRESHOLD) == ()
    assert not denied(_private_home, agents, command)


@pytest.mark.parametrize(("command", "kind"), CALLED)
def test_finding_7_a_function_that_is_called_waits(command: str, kind: str) -> None:
    expected = (kind,) if kind else ()
    assert leadwait.find_waits(command, THRESHOLD) == expected


PLACEHOLDER_REASONS = ["!!!!!!!!!!!!", "............", "- - - - - - - -", "a1 !!!!!!!!!", "abc de !!!!!!!!!!!"]


@pytest.mark.parametrize("reason", PLACEHOLDER_REASONS)
def test_finding_8_a_punctuation_padded_inline_reason_is_refused(
    _private_home: Path, agents: Path, reason: str
) -> None:
    command = f"sleep 60 # lead-wait: ok - {reason}"
    assert leadwait.marker_reason(command) == ""
    set_mode(_private_home, "block")
    out = guard(_private_home, agents, bash(command))[1]
    assert "reason is required" in json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"]


def test_finding_8_eight_letters_or_digits_in_twelve_characters_is_enough_and_unicode_counts() -> None:
    assert leadwait.marker_reason("sleep 60 # lead-wait: ok - dns ttl: 60s!!") == "dns ttl: 60s!!"
    assert leadwait.marker_reason("sleep 60 # lead-wait: ok - 12345678 ....")
    assert leadwait.marker_reason("sleep 60 # lead-wait: ok - 待機中のため問題なし確認済み")
    assert not leadwait.marker_reason("sleep 60 # lead-wait: ok - 1234567 ....")  # seven alphanumerics


@pytest.mark.parametrize("reason", PLACEHOLDER_REASONS)
def test_finding_8_a_punctuation_padded_repository_exemption_refuses_to_load(tmp_path: Path, reason: str) -> None:
    path = agents_file(tmp_path / "bad.yaml", lead_wait={"exempt_repos": [{"repo": "acme/scratch", "reason": reason}]})
    with pytest.raises(ConfigError, match=r"lead_wait\.exempt_repos\[0\]\.reason"):
        load_agents(path)


def test_finding_8_a_real_repository_exemption_reason_still_loads(tmp_path: Path) -> None:
    entry = {"repo": "acme/scratch", "reason": "a throwaway repo where nobody is waiting on the lead"}
    path = agents_file(tmp_path / "ok.yaml", lead_wait={"exempt_repos": [entry]})
    assert load_agents(path).hooks.lead_wait.exempt_repos[0].repo == "acme/scratch"


@pytest.mark.parametrize(
    "command", ["sl''eep 60", 's"l"eep 60', "sle\\ep 60", "gh run w''atch 1", "g''h pr checks 1 -w", "$'sleep' 60"]
)
def test_a_word_spelled_with_quotes_is_still_found_and_passes_the_cheap_precheck(
    _private_home: Path, agents: Path, command: str
) -> None:
    """The cheap pre-check used to look for the raw words, so `sl''eep 60` never reached the scanner."""
    assert leadwait.may_wait(command)
    assert denied(_private_home, agents, command)


def test_the_cheap_precheck_still_skips_a_plain_command() -> None:
    assert not leadwait.may_wait("ls -la && git status")
    assert not leadwait.may_wait("echo 'hello' \"world\" $HOME")  # quotes make it tokenize, but nothing waits
    assert not leadwait.may_wait("gh pr checks 12")


# Every fixture above is valid Bash (tests/test_leadwait_bash.py runs `bash -n` over these lists).
SYNTAX_FIXTURES = (
    HEREDOC_LATER_WAIT
    + HEREDOC_FORGED_MARKER
    + [c for c, _ in BODY_EXPANSION]
    + BODY_OPAQUE
    + [c for c, _ in PARAMETER_EXPANSION]
    + PARAMETER_PLAIN
    + TOO_DEEP[:6]  # the 500-deep one is a stress input; bash itself copes, but -n of it is slow to read
    + [c for c, _ in INDIRECTION]
    + INDIRECTION_QUIET
    + list(KNOWN_LIMITS.values())
    + DORMANT
    + [c for c, _ in CALLED]
    + ["sl''eep 60", 's"l"eep 60', "sle\\ep 60", "gh run w''atch 1", "g''h pr checks 1 -w", "$'sleep' 60"]
)


# -- round 3 -----------------------------------------------------------------------------------------------------
# H1: bash removes backslash-newline BEFORE it tokenizes (outside single quotes; also inside double quotes), except
# that a comment ends at its newline, `$'...'` keeps it, and a QUOTED heredoc body keeps it.

ROUND3_FIXTURES: list[str] = []

CONTINUATION_WAITS = [
    "cat <<E\\\nOF\nbody\nEOF\nsleep 60",  # the review repro: the delimiter is EOF
    'cat <<"E\\\nOF"\nbody\nEOF\nsleep 60',  # a continuation inside double quotes is removed too
    "cat <\\\n<EOF\nhi\nEOF\nsleep 60",  # an operator split by a continuation
    "sl\\\neep 60",  # a command name split by a continuation
    "gh run w\\\natch 1",
    "gh \\\nrun watch 1",
    "cat <<EOF\nx\nEO\\\nF\nsleep 60",  # an unquoted body: the terminator can be formed by a continuation
    "cat <<EOF\nEO\\\nF\nsleep 60\nEOF",  # ...so this sleep is code and the last EOF is a command
    "echo a # a comment ends at its newline \\\nsleep 60",  # a comment does not continue
    "cat <<E\\\nOF\nx\nEO\\\nF\nsleep 60",  # a split delimiter is still UNQUOTED: the body joins and EO\\F ends it
    "sleep 60 \\\n  && echo done",
    "echo $'a\\\nb'; sleep 60",  # $'...' keeps the backslash-newline, and the sleep after it is code
]
CONTINUATION_DATA = [
    "cat <<'EOF'\nEO\\\nF\nsleep 60\nEOF",  # a quoted body keeps backslash-newline: no terminator is formed
    "echo 'a\\\nsleep 60'",  # single quotes keep it
    "cat <<EOF\nsleep 60 \\\nis just text\nEOF",  # joined into one line of body
]
ROUND3_FIXTURES += CONTINUATION_WAITS + CONTINUATION_DATA


@pytest.mark.parametrize("command", CONTINUATION_WAITS)
def test_h1_a_wait_is_found_after_bash_removes_line_continuations(
    _private_home: Path, agents: Path, command: str
) -> None:
    assert leadwait.find_waits(command, THRESHOLD) != ()
    assert denied(_private_home, agents, command)


def test_h1_the_review_repro_is_denied(_private_home: Path, agents: Path) -> None:
    assert denied(_private_home, agents, "cat <<E\\\nOF\nbody\nEOF\nsleep 60")


@pytest.mark.parametrize("command", CONTINUATION_DATA)
def test_h1_text_that_bash_keeps_as_data_is_not_a_wait(command: str) -> None:
    assert leadwait.find_waits(command, THRESHOLD) == ()


def test_h1_a_comment_ends_at_its_newline_so_the_next_line_marker_is_real() -> None:
    reason = "waiting out a dns ttl, nothing to delegate"
    assert leadwait.marker_reason(f"sleep 60 # note \\\n# lead-wait: ok - {reason}") == reason
    # the backslash does not pull the next line into the comment: the sleep on it is code, not marker text
    assert leadwait.find_waits(f"echo a # lead-wait: ok - {reason} \\\nsleep 60", THRESHOLD) == ("long-sleep",)


# H2: `<<<` is a here-string, not a heredoc; its word is read with the normal rules and its substitutions run.

HERESTRING_WAITS = [
    'cat <<< "$(sleep 60)"',  # the review repro
    "cat <<< $(sleep 60)",
    "cat <<< `sleep 60`",
    'cat <<<"$(gh run watch 1)"',
    'cat <<<"x" <<< "$(sleep 60)"',
    'cat <<< "x"; sleep 60',
    "cat <<< 'x' <<EOF\n$(sleep 60)\nEOF",  # a here-string next to an unquoted heredoc whose body runs
]
HERESTRING_DATA = [
    "cat <<< '$(sleep 60)'",  # single quotes keep it data
    "cat <<< 'sleep 60'",
    "cat <<< sleep",
    "cat <<<'x' <<'EOF'\n$(sleep 60)\nEOF",  # the quoted heredoc body is data
    "grep -q x <<< 'gh run watch 1'",
]
ROUND3_FIXTURES += HERESTRING_WAITS + HERESTRING_DATA


@pytest.mark.parametrize("command", HERESTRING_WAITS)
def test_h2_a_substitution_in_a_here_string_runs(_private_home: Path, agents: Path, command: str) -> None:
    assert leadwait.find_waits(command, THRESHOLD) != ()
    assert denied(_private_home, agents, command)


@pytest.mark.parametrize("command", HERESTRING_DATA)
def test_h2_quoted_here_string_text_is_data(command: str) -> None:
    assert leadwait.find_waits(command, THRESHOLD) == ()


def test_h2_a_here_string_is_not_a_heredoc() -> None:
    assert leadwait.heredoc_bodies('cat <<< "x"\necho y') == ()
    assert leadwait.find_waits('cat <<< "x"\nsleep 60', THRESHOLD) == ("long-sleep",)
    assert leadwait.find_waits("sleep 5 <<< x", THRESHOLD) == ()  # `<<< x` is a redirection, not an argument


# H3: an unquoted brace expansion in a COMMAND-POSITION word builds the command at run time. Fail closed.

BRACE_COMMANDS = [
    "sl{e..e}ep 60",  # the review forms
    "{sleep,60}",
    "s{l,l}eep 60",
    "{gh,run,watch} 1",
    "FOO=1 {sleep,60}",
    "sudo {sleep,60}",
    "ls && {sleep,60}",
    "x=$(echo hi); sl{e,e}p 1; echo {sleep,60}",
    "{1..3}",
]
BRACE_FINE = [
    "echo {a,b}",
    "ls {a,b}.txt",
    "echo {1..3} && ls",
    "echo ${var} ${var:-x}",
    "{ echo hi; }",
    "{ sleep 1; }",
    "'{a,b}' x",  # quoted: the program is literally named {a,b}
    '"{sleep,60}"',
    "{a}",  # no comma or range: not an expansion
    "{}",
    "git log --format={a,b}",
    "find . -name '*.md' -exec echo {} +",
    "echo \\{sleep,60\\}",
]
ROUND3_FIXTURES += BRACE_COMMANDS + BRACE_FINE


@pytest.mark.parametrize("command", BRACE_COMMANDS)
def test_h3_a_brace_expansion_at_command_position_is_unscannable_brace(
    _private_home: Path, agents: Path, command: str
) -> None:
    assert "unscannable-brace" in leadwait.find_waits(command, THRESHOLD)
    assert leadwait.may_wait(command)  # the cheap pre-check lets it through to the tokenizer
    assert denied(_private_home, agents, command)


@pytest.mark.parametrize("command", BRACE_FINE)
def test_h3_brace_expansion_in_arguments_groups_and_quotes_is_fine(command: str) -> None:
    assert leadwait.find_waits(command, THRESHOLD) == ()


def test_h3_the_deny_text_names_only_the_kind(_private_home: Path, agents: Path) -> None:
    set_mode(_private_home, "block")
    out = guard(_private_home, agents, bash("{sleep,60} sentinel-arg-xyz"))[1]
    reason = json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"]
    assert "unscannable-brace" in reason and "sentinel-arg-xyz" not in out


# M1: more wrappers that run another command, and `watch`, which is itself a wait.

WRAPPER_CASES = [
    ("stdbuf -oL sleep 60", "long-sleep"),
    ("stdbuf -o L -e0 gh run watch 1", "gh-run-watch"),
    ("stdbuf -i0 -o0 -e0 sleep 60", "long-sleep"),
    ("setsid sleep 60", "long-sleep"),
    ("setsid -f sleep 60", "long-sleep"),
    ("setsid --wait gh run watch 1", "gh-run-watch"),
    ("flock /tmp/lock sleep 60", "long-sleep"),
    ("flock -n /tmp/lock gh run watch 1", "gh-run-watch"),
    ("flock -w 5 -x /tmp/lock sleep 60", "long-sleep"),
    ("flock 9 sleep 60", "long-sleep"),
    ("flock /tmp/lock -c 'sleep 60'", "long-sleep"),
    ("flock -x /tmp/lock --command 'gh run watch 1'", "gh-run-watch"),
    ("parallel sleep 60 ::: a b", "long-sleep"),
    ("parallel -j4 gh run watch ::: 1 2", "gh-run-watch"),
    ("parallel -j 2 --halt now,fail=1 sleep 60 ::: a", "long-sleep"),
    ("parallel 'sleep 60' ::: x", "long-sleep"),
    ("parallel -k sleep 60 :::: file", "long-sleep"),
    ("ionice sleep 60", "long-sleep"),
    ("ionice -c3 sleep 60", "long-sleep"),
    ("ionice -c 3 -n 7 gh run watch 1", "gh-run-watch"),
    ("taskset 0x1 sleep 60", "long-sleep"),
    ("taskset -c 0,1 sleep 60", "long-sleep"),
    ("taskset --cpu-list 0 gh run watch 1", "gh-run-watch"),
    ("chrt -r 10 sleep 60", "long-sleep"),
    ("chrt --idle 0 sleep 60", "long-sleep"),
    ("chrt -b 0 gh run watch 1", "gh-run-watch"),
    ("unbuffer sleep 60", "long-sleep"),
    ("unbuffer -p gh run watch 1", "gh-run-watch"),
    ("sudo ionice -c3 nice -n 5 flock /tmp/lock sleep 60", "long-sleep"),
    ("FOO=1 stdbuf -oL setsid taskset -c 0 sleep 60", "long-sleep"),
    ("watch -n 5 gh pr checks 1", "watch"),
    ("watch ls", "watch"),
    ("watch -g -n1 cat /proc/loadavg", "watch"),
    ("sudo watch -n 1 date", "watch"),
    ("ls | watch -n1 cat", "watch"),
]
WRAPPER_QUIET = [
    "stdbuf -oL echo sleep 60",
    "setsid echo sleep 60",
    "flock /tmp/lock echo hi",
    "flock /tmp/lock -c 'echo sleep 60'",
    "parallel echo sleep ::: a b",
    "ionice echo sleep 60",
    "taskset -c 0 echo sleep",
    "chrt -r 10 echo sleep",
    "unbuffer echo sleep 60",
    "echo watch",
    "man watch",
    "ls watch",
    "git log --grep watch",
]
ROUND3_FIXTURES += [c for c, _ in WRAPPER_CASES] + WRAPPER_QUIET


@pytest.mark.parametrize(("command", "kind"), WRAPPER_CASES)
def test_m1_the_command_a_wrapper_runs_decides_and_watch_is_a_wait(command: str, kind: str) -> None:
    assert leadwait.find_waits(command, THRESHOLD) == (kind,)


@pytest.mark.parametrize("command", WRAPPER_QUIET)
def test_m1_a_wrapper_around_a_harmless_command_is_not_a_wait(command: str) -> None:
    assert leadwait.find_waits(command, THRESHOLD) == ()


def test_m1_watch_is_denied_in_block_mode_and_the_background_form_is_allowed(_private_home: Path, agents: Path) -> None:
    assert denied(_private_home, agents, "watch -n 5 gh pr checks 1")
    assert guard(_private_home, agents, bash("watch -n 5 date", run_in_background=True)) == (0, "", "")


# M2: function dormancy. (a) a function nested in another is dormant until ITS OWN name is invoked. (b) a call that
# defines functions and then runs a variable-expanded word cannot be known not to run one: fail closed.

NESTED_DORMANT = [
    "outer() { inner() { sleep 60; }; }; outer",  # calling outer only defines inner
    "outer() { inner() { sleep 60; }; }",
    "outer() {\n  inner() {\n    sleep 60\n  }\n}\nouter",
    "function outer { function inner { sleep 60; }; }; outer",
    "outer() { inner() { sleep 60; }; sleep 1; }; outer",
    "outer() { inner() { gh run watch 1; }; }; echo inner; outer",
]
NESTED_CALLED = [
    ("outer() { inner() { sleep 60; }; inner; }; outer", "long-sleep"),
    ("outer() { inner() { sleep 60; }; }; outer; inner", "long-sleep"),  # inner exists once outer ran
    ("outer() { inner() { sleep 1; }; }; while true; do outer; inner; done", "sleep-loop"),
]
INDIRECT_FAIL_CLOSED = [
    "f() { sleep 60; }; x=f; $x",
    'f() { sleep 60; }; x=f; "$x"',
    "f() { :; }; $(echo f)",
    "function f { sleep 60; }; x=f; ${x}",
    "f() { :; }; x=f; env $x",
    "x=f; $x; f() { sleep 60; }",  # the call defines a function either side of the indirect word
]
INDIRECT_FINE = [
    "x=sleep; $x 60",  # no function is defined: stays a documented limit
    'c=ls; "$c" -la',
    "f() { :; }; echo $x",  # an expansion in an ARGUMENT is data
    "f() { :; }; f",
    "x=1; echo $x",
]
ROUND3_FIXTURES += NESTED_DORMANT + [c for c, _ in NESTED_CALLED] + INDIRECT_FAIL_CLOSED + INDIRECT_FINE


@pytest.mark.parametrize("command", NESTED_DORMANT)
def test_m2a_a_nested_function_is_dormant_until_its_own_name_is_invoked(command: str) -> None:
    assert leadwait.find_waits(command, THRESHOLD) == ()


@pytest.mark.parametrize(("command", "kind"), NESTED_CALLED)
def test_m2a_a_nested_function_waits_once_it_is_invoked(command: str, kind: str) -> None:
    assert leadwait.find_waits(command, THRESHOLD) == (kind,)


@pytest.mark.parametrize("command", INDIRECT_FAIL_CLOSED)
def test_m2b_an_indirect_invocation_in_a_call_that_defines_functions_is_unscannable(
    _private_home: Path, agents: Path, command: str
) -> None:
    assert "unscannable-indirect" in leadwait.find_waits(command, THRESHOLD)
    assert denied(_private_home, agents, command)


@pytest.mark.parametrize("command", INDIRECT_FINE)
def test_m2b_without_a_function_definition_or_without_an_indirect_word_nothing_is_flagged(command: str) -> None:
    assert leadwait.find_waits(command, THRESHOLD) == ()


# L3: a marker counts in top-level code and in a function body that is actually invoked; a dormant body's does not.
L3_REASON = "waiting out a dns ttl, nothing to delegate"
L3_DORMANT_MARKER = [
    f"sleep 60\nf() {{\n  echo hi # lead-wait: ok - {L3_REASON}\n}}",
    f"sleep 60\nf() {{ echo hi; }} ; g() {{ echo # lead-wait: ok - {L3_REASON}\n}}; f",
    f"sleep 60\nouter() {{\n  inner() {{\n    : # lead-wait: ok - {L3_REASON}\n  }}\n}}\nouter",
    f"sleep 60\nfunction f {{\n  : # lead-wait: ok - {L3_REASON}\n}}",
]
L3_LIVE_MARKER = [
    f"sleep 60 # lead-wait: ok - {L3_REASON}",
    f"f() {{ sleep 60 # lead-wait: ok - {L3_REASON}\n}}\nf",  # the body is invoked
    f"f() {{ :; }} # lead-wait: ok - {L3_REASON}\nsleep 60",  # after the closing brace: top level
    f"f() {{ :; }}\nsleep 60 # lead-wait: ok - {L3_REASON}",
    f"outer() {{\n  inner() {{ :; }}\n  : # lead-wait: ok - {L3_REASON}\n}}\nouter\nsleep 60",
]
ROUND3_FIXTURES += L3_DORMANT_MARKER + L3_LIVE_MARKER


@pytest.mark.parametrize("command", L3_DORMANT_MARKER)
def test_l3_a_marker_in_a_dormant_function_body_exempts_nothing(
    _private_home: Path, agents: Path, command: str
) -> None:
    assert leadwait.marker_reason(command) == ""
    assert denied(_private_home, agents, command)


@pytest.mark.parametrize("command", L3_LIVE_MARKER)
def test_l3_a_marker_in_top_level_code_or_an_invoked_body_still_exempts(
    _private_home: Path, agents: Path, command: str
) -> None:
    assert leadwait.marker_reason(command) == L3_REASON
    assert not denied(_private_home, agents, command)


# M3: the body of $((...)) and $[...] is arithmetic, not commands; only substitutions nested in it run.

ARITHMETIC_QUIET = [
    "echo $((sleep 60))",  # a false positive in round 2; bash reports a syntax error and runs nothing
    "echo $(( sleep ))",
    "echo $[sleep 60]",
    "x=$((60 * 5)); echo $x",
    "echo $(( 1 << 2 )) $(( 2 > 1 ? 3 : 4 ))",
    "(( n = 5 * 60 )); echo $n",
]
ARITHMETIC_WAITS = [
    ("echo $(( $(sleep 60) + 1 ))", "long-sleep"),
    ("echo $[ $(sleep 60) + 1 ]", "long-sleep"),
    ("echo $(( `sleep 60` + 1 ))", "long-sleep"),
    ("echo $(( a[$(gh run watch 1)] ))", "gh-run-watch"),
    ("sleep $((5 * 60))", "long-sleep"),  # the argument is not a readable number
    ("sleep $[5 * 60]", "long-sleep"),
    # `$((` that is not arithmetic: the inner parenthesis closes before the outer pair, so it is `$(` + a subshell
    ("echo $((echo a); (sleep 60))", "long-sleep"),
    ("echo $( (sleep 60) )", "long-sleep"),
]
ROUND3_FIXTURES += ARITHMETIC_QUIET + [c for c, _ in ARITHMETIC_WAITS]


@pytest.mark.parametrize("command", ARITHMETIC_QUIET)
def test_m3_arithmetic_words_are_not_commands(command: str) -> None:
    assert leadwait.find_waits(command, THRESHOLD) == ()


@pytest.mark.parametrize(("command", "kind"), ARITHMETIC_WAITS)
def test_m3_substitutions_inside_arithmetic_and_real_subshells_still_run(command: str, kind: str) -> None:
    assert leadwait.find_waits(command, THRESHOLD) == (kind,)


# M4: a sleep in a loop CONDITION (between the keyword and its `do`) is a poll as much as one in the body.

CONDITION_POLLS = [
    "while sleep 1; do :; done",
    "until sleep 1; do :; done",
    "while sleep 1 && true; do :; done",
    "while ! sleep 1; do echo x; done",
    "while\n  sleep 1\ndo\n  :\ndone",
    "while true && sleep 1; do :; done",
]
CONDITION_NOT_POLLS = [
    "while true; do :; done; sleep 1",
    "for i in 1 2; do :; done; sleep 1",
    "if sleep 1; then :; fi",
    "sleep 1 && while true; do :; done",
]
ROUND3_FIXTURES += CONDITION_POLLS + CONDITION_NOT_POLLS + ["while ! gh pr checks 1 -w; do :; done"]


@pytest.mark.parametrize("command", CONDITION_POLLS)
def test_m4_a_sleep_in_a_loop_condition_is_a_sleep_loop(command: str) -> None:
    assert leadwait.find_waits(command, THRESHOLD) == ("sleep-loop",)


@pytest.mark.parametrize("command", CONDITION_NOT_POLLS)
def test_m4_a_sleep_outside_every_loop_is_still_just_a_short_sleep(command: str) -> None:
    assert leadwait.find_waits(command, THRESHOLD) == ()


def test_m4_a_watching_condition_is_flagged(_private_home: Path, agents: Path) -> None:
    command = "while ! gh pr checks 1 -w; do :; done"
    assert "gh-pr-checks-watch" in leadwait.find_waits(command, THRESHOLD)
    assert denied(_private_home, agents, command)


# L1: a reason is real when, with zero-width and combining characters removed, it is 12 characters long and at least 8
# of them are Unicode letters or ASCII digits (full-width and Arabic-Indic digits are not, nor are combining marks).


def _chars(*codes: int) -> str:
    """Built from code points so the source stays readable (and ruff does not flag lookalike characters)."""
    return "".join(chr(c) for c in codes)


FULLWIDTH_DIGITS = _chars(*[0xFF11 + k % 9 for k in range(12)])
ARABIC_INDIC_DIGITS = _chars(*[0x0660 + k % 10 for k in range(12)])
CIRCLED_DIGITS = _chars(*[0x2460 + k for k in range(12)])
ZWJ, ZWSP, ACUTE = _chars(0x200D), _chars(0x200B), _chars(0x0301)
UNREAL_REASONS = [
    FULLWIDTH_DIGITS,
    ARABIC_INDIC_DIGITS,
    CIRCLED_DIGITS,  # not ASCII digits
    "abcd" + ZWJ * 12,  # letters padded with zero-width joiners
    "abcdefgh" + ACUTE * 8,  # eight letters plus eight combining marks: 8 characters once they are removed
    "abc" + ZWSP * 4 + "defgh!!!",  # zero-width spaces do not lengthen it: 11 characters
    "abcdefg!!!!!",  # seven letters
    "!!!!!!!!!!!!",
]
REAL_REASONS = [
    "waiting out a dns ttl, nothing to delegate",
    "abcdefgh!!!!",  # the boundary: twelve characters, eight letters
    "12345678....",
    _chars(0x43E, 0x436, 0x438, 0x434, 0x430, 0x43D, 0x438, 0x435)
    + " dns, "
    + _chars(0x43D, 0x435, 0x447, 0x435, 0x433, 0x43E),
    _chars(0x5F85, 0x6A5F, 0x4E2D, 0x306E, 0x305F, 0x3081, 0x554F, 0x984C, 0x306A, 0x3057, 0x78BA, 0x8A8D),
    # Devanagari: most of the code points are vowel signs (combining), the base letters still make eight
    _chars(0x92F, 0x939, 0x93E, 0x901, 0x20, 0x92A, 0x94D, 0x930, 0x924, 0x940, 0x915, 0x94D, 0x937, 0x93E, 0x20)
    + _chars(0x915, 0x930, 0x928, 0x93E, 0x20, 0x906, 0x935, 0x936, 0x94D, 0x92F, 0x915, 0x20, 0x939, 0x948),
    "caf" + _chars(0xE9) + " renewal wait, 60 s, nothing to delegate",
]


@pytest.mark.parametrize("reason", UNREAL_REASONS)
def test_l1_a_padded_or_lookalike_reason_is_refused_inline_and_in_config(
    _private_home: Path, agents: Path, tmp_path: Path, reason: str
) -> None:
    assert not leadwait.real_reason(reason)
    assert leadwait.marker_reason(f"sleep 60 # lead-wait: ok - {reason}") == ""
    path = agents_file(tmp_path / "bad.yaml", lead_wait={"exempt_repos": [{"repo": "acme/scratch", "reason": reason}]})
    with pytest.raises(ConfigError, match=r"lead_wait\.exempt_repos\[0\]\.reason"):
        load_agents(path)


@pytest.mark.parametrize("reason", REAL_REASONS)
def test_l1_a_real_sentence_in_any_script_is_accepted_inline_and_in_config(tmp_path: Path, reason: str) -> None:
    assert leadwait.real_reason(reason)
    assert leadwait.marker_reason(f"sleep 60 # lead-wait: ok - {reason}") == reason
    path = agents_file(tmp_path / "ok.yaml", lead_wait={"exempt_repos": [{"repo": "acme/scratch", "reason": reason}]})
    assert load_agents(path).hooks.lead_wait.exempt_repos[0].repo == "acme/scratch"


# L2: the scan runs under the guard's deadline and fails closed; the cache holds only small inputs.

BIG = 1 << 20  # 1 MiB


def test_l2_an_expired_deadline_gives_unscannable_timeout_fast() -> None:
    started = time.monotonic()
    command = "echo " + "a " * (BIG // 2)
    assert leadwait.find_waits(command, THRESHOLD, deadline=started - 1) == ("unscannable-timeout",)
    assert time.monotonic() - started < 5
    assert leadwait.find_waits("sleep 1 " + "# x" * 10, THRESHOLD, deadline=started - 1) == ("unscannable-timeout",)


@pytest.mark.parametrize(
    "shape",
    [
        "echo " + "a " * (BIG // 2),
        "$(" * (BIG // 2),
        "\\\n" * (BIG // 2),
        "cat <<A\n" * (BIG // 8),
        "echo '" + "x" * BIG,
        "${a:-" * (BIG // 5),
        "f() { " * (BIG // 6),
        "sleep 1; " * (BIG // 9),
    ],
    ids=[
        "words",
        "open-subst",
        "continuations",
        "heredocs",
        "unterminated-quote",
        "open-brace-expansion",
        "functions",
        "sleeps",
    ],
)
def test_l2_a_pathological_one_mebibyte_input_returns_within_the_deadline(shape: str) -> None:
    started = time.monotonic()
    kinds = leadwait.find_waits(shape, THRESHOLD, deadline=started + 2.0)
    assert time.monotonic() - started < 8, "the scan did not honor its deadline"
    assert isinstance(kinds, tuple)


def test_l2_the_hook_passes_its_deadline_to_the_scan(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from safo.modes import hooks as hooks_mode

    monkeypatch.setattr(
        hooks_mode, "budget_points", lambda begun: (begun - 1.0, begun + 8.0, begun + 9.0)
    )  # lookups are already late; the decision is not

    monkeypatch.setattr(
        hooks_mode, "CONFIG_MIN_WAIT_SECONDS", 10.0
    )  # the subject is the guard deadline, not the load floor on a busy machine
    set_mode(_private_home, "block")
    out = guard(_private_home, agents, bash("sleep 1"))[1]
    reason = json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"]
    assert "unscannable-timeout" in reason


def test_l2_only_small_inputs_are_cached_and_the_cache_is_bounded() -> None:
    assert leadwait.CACHE_MAX_CHARS == 8192
    for n in range(leadwait.CACHE_ENTRIES * 4):
        leadwait.find_waits(f"sleep {n + 1}", THRESHOLD)
    assert len(leadwait._SMALL_CACHE) <= leadwait.CACHE_ENTRIES
    big = "echo " + "a " * (leadwait.CACHE_MAX_CHARS)
    leadwait.find_waits(big, THRESHOLD)
    assert big not in leadwait._SMALL_CACHE


def test_the_docs_name_every_verdict_kind_the_rule_can_emit() -> None:
    page = (DOCS / "hooks.md").read_text(encoding="utf-8")
    for kind in leadwait.KINDS:
        assert f"`{kind}`" in page, kind


# Round 4, HIGH: a brace expansion in a wrapper's option, option value or operand shifts which word is the wrapped
# command (`timeout {1,sleep} 60` runs `timeout 1 60` and `timeout sleep 60`...). Fail closed, whatever the wrapper.

WRAPPER_BRACE_SHIFT = [
    # an operand
    "timeout {1,sleep} 60",
    "flock {file,sleep} 60",
    "taskset {1,sleep} 60",
    "chrt {1,sleep} 60",
    "stdbuf -i 0 timeout {1,sleep} 60",
    "sudo -u {root,sleep} 60",
    # an option value
    "sudo -u {root,build} sleep 60",
    "env -u {A,B} sleep 60",
    "nice -n {1,2} sleep 60",
    "stdbuf -i {0,1} sleep 60",
    "timeout -k {1,2} 5 sleep 60",
    "flock -w {1,2} /tmp/lock sleep 60",
    "taskset -c {0,1} sleep 60",
    "chrt -r {1,2} sleep 60",
    "ionice -c {1,2} sleep 60",
    "xargs -n {1,2} sleep 60",
    "time -f {a,b} sleep 60",
    "exec -a {x,y} sleep 60",
    "parallel -j {1,2} sleep 60 ::: a",
    # an option or the command word itself
    "nohup {-i,sleep} 60",
    "setsid {-f,sleep} 60",
    "unbuffer {-p,sleep} 60",
    "command {-p,sleep} 60",
    "env {-i,sleep} 60",
    "parallel {-j,sleep} 60 ::: 1",
    # nested chains
    "sudo timeout {1,sleep} 60",
    "nice flock {f,sleep} 60",
    "env timeout -k {1,2} 5 sleep 60",
    "nohup nice -n 5 stdbuf -oL setsid timeout {1,sleep} 60",
    # the same through find -exec
    "find . -exec {sleep,60} \\;",
    "find . -exec timeout {1,sleep} 60 \\;",
]
WRAPPER_BRACE_FINE = [
    "timeout 5 ls {a,b}",  # braces in the wrapped command's own arguments
    "sudo -u root ls {a,b}.txt",
    "nice -n 5 echo {a,b}",
    "flock /tmp/lock echo {1..3}",
    "stdbuf -oL echo {a,b}",
    "taskset -c 0 echo {a,b}",
    "env FOO=1 echo {a,b}",
    "env FOO={a,b} sleep 1",  # an assignment is not brace expanded at the command word's position
    "timeout '{1,sleep}' 60",  # a quoted brace is data
    "timeout \\{1,sleep\\} 60",  # an escaped one too
    "sudo -u '{root,build}' echo hi",
    "xargs -I{} echo {a,b}",
    "parallel echo {a,b} ::: x",
]
ROUND3_FIXTURES += WRAPPER_BRACE_SHIFT + WRAPPER_BRACE_FINE


@pytest.mark.parametrize("command", WRAPPER_BRACE_SHIFT)
def test_r4_a_brace_in_a_wrapper_word_is_unscannable_brace(_private_home: Path, agents: Path, command: str) -> None:
    assert "unscannable-brace" in leadwait.find_waits(command, THRESHOLD)
    assert leadwait.may_wait(command)
    assert denied(_private_home, agents, command)


@pytest.mark.parametrize("command", WRAPPER_BRACE_FINE)
def test_r4_braces_after_the_wrapped_command_and_quoted_braces_are_fine(command: str) -> None:
    assert leadwait.find_waits(command, THRESHOLD) == ()


# Round 4, MEDIUM 2: `parallel` takes its commands from the template, or from the `:::` arguments when the template is
# empty or a replacement string. An option this scanner does not know hides the command. Fail closed.

PARALLEL_UNSCANNABLE = [
    "parallel {} ::: 'sleep 60'",  # the commands are the arguments
    "parallel {.} ::: 'sleep 60'",
    "parallel {/} ::: x",
    "parallel ::: 'sleep 60'",  # an empty template
    "parallel -j 4 ::: 'sleep 60'",
    "cat commands | parallel -j4",  # no template and no :::
    "parallel -I @@ sleep 60 ::: 1",  # an option that takes a value and is not in the recognized list
    "parallel -I{} sleep 60 ::: 1",
    "parallel --replace sleep 60 ::: 1",
    "parallel --arg-sep ,, sleep 60 ,, 1",
    "parallel --arg-file-sep // sleep 60 // x",
    "parallel -X sleep 60 ::: 1 2",
    "parallel -S host sleep 60 ::: 1",
    "parallel --sshlogin host sleep 60 ::: 1",
    "parallel --ssh ssh sleep 60 ::: 1",
    "parallel --some-future-option sleep 60 ::: 1",
]
PARALLEL_FINE = [
    ("parallel sleep 60 ::: 1", "long-sleep"),
    ("parallel -j 4 sleep 60 ::: 1 2", "long-sleep"),
    ("parallel -j4 sleep 60 ::: 1 2", "long-sleep"),
    ("parallel --jobs=4 gh run watch ::: 1", "gh-run-watch"),
    ("parallel -k --halt now,fail=1 sleep 60 :::: file", "long-sleep"),
    ("parallel 'sleep 60' ::: x", "long-sleep"),
    ("parallel echo {} ::: a b", ""),  # the replacement string is an ARGUMENT of echo
    ("parallel -j 2 echo sleep ::: a", ""),
]
ROUND3_FIXTURES += PARALLEL_UNSCANNABLE + [c for c, _ in PARALLEL_FINE]


@pytest.mark.parametrize("command", PARALLEL_UNSCANNABLE)
def test_r4_parallel_with_no_template_a_replacement_template_or_an_unknown_option_is_unscannable(
    _private_home: Path, agents: Path, command: str
) -> None:
    assert "unscannable-indirect" in leadwait.find_waits(command, THRESHOLD)
    assert denied(_private_home, agents, command)


@pytest.mark.parametrize(("command", "kind"), PARALLEL_FINE)
def test_r4_the_ordinary_parallel_shapes_still_work(command: str, kind: str) -> None:
    assert leadwait.find_waits(command, THRESHOLD) == ((kind,) if kind else ())


# Round 4, MEDIUM 1: every unbounded loop checks the deadline, and a marker is never honored after a timeout.

SHORT_SHAPES = {
    "very long double-quoted string": 'echo "' + "a" * BIG + '"',
    "long ${ span": "echo ${a:-" + "x" * BIG + "}",
    "long backtick span": "echo `" + "a" * BIG + "`",
    "many continuations in a quoted string": '"' + "\\\n" * (BIG // 2) + '"',
    "huge heredoc body": "cat <<EOF\n" + "x\n" * (BIG // 2) + "EOF",
    "huge unquoted heredoc body with continuations": "cat <<EOF\n" + "x\\\n" * (BIG // 2) + "y\nEOF",
    "long ansi-c string": "echo $'" + "a" * BIG + "'",
    "long arithmetic": "echo $((" + "1+" * (BIG // 2) + "1))",
}


@pytest.mark.parametrize("shape", list(SHORT_SHAPES))
def test_r4_each_pathological_shape_with_an_expired_or_short_deadline_is_unscannable_timeout(shape: str) -> None:
    command = SHORT_SHAPES[shape]
    assert leadwait.find_waits(command, THRESHOLD, deadline=time.monotonic() - 1) == ("unscannable-timeout",)
    assert leadwait.find_waits(command, THRESHOLD, deadline=time.monotonic() + 0.002) == ("unscannable-timeout",)


def test_r4_a_timed_out_scan_is_flagged_by_the_precheck_not_passed() -> None:
    assert leadwait.may_wait("sleep 1 " + "a " * BIG, deadline=time.monotonic() - 1)


def test_r4_a_huge_comment_with_a_marker_never_exempts_after_the_deadline() -> None:
    command = "sleep 60 # lead-wait: ok - " + "a" * BIG
    assert leadwait.marker_reason(command) != ""  # with time to look, it is a real marker
    # The scan is cached by now; only the reason check is left, and it must honor the deadline too: no exemption, so
    # the call is judged as the wait it is (long-sleep here) and is never excused by a marker that was not checked.
    assert leadwait.marker_reason(command, deadline=time.monotonic() - 1) == ""
    fresh = "sleep 60 # lead-wait: ok - waiting out the dns ttl, nothing to delegate " + "b" * 64
    assert leadwait.marker_reason(fresh, deadline=time.monotonic() - 1) == ""  # the scan itself timed out
    assert leadwait.find_waits(fresh, THRESHOLD, deadline=time.monotonic() - 1) == ("unscannable-timeout",)
    assert leadwait.find_waits(fresh, THRESHOLD) == ("long-sleep",)  # and that timeout was not remembered


def test_r4_a_marker_recorded_before_a_timeout_is_never_honored() -> None:
    """The comment is read early, then the scan runs out of time on the filler. Defense in depth: a scan that timed
    out returns no marker (the reason check's own deadline would also refuse it)."""
    # 64 Ki lines of filler is about a second of scanning, 500 times the 2 ms deadline below; the full BIG lines
    # cost the same proof 25 s (three minutes under coverage) and add nothing, as the scan has no size branch
    command = f"sleep 60 # lead-wait: ok - {REASON}\n" + "echo a\n" * (BIG // 16)
    assert leadwait.marker_reason(command) == REASON
    assert leadwait.marker_reason(command + " ", deadline=time.monotonic() + 0.002) == ""


def test_r4_the_hook_does_not_honor_a_marker_after_its_deadline(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from safo.modes import hooks as hooks_mode

    monkeypatch.setattr(
        hooks_mode, "budget_points", lambda begun: (begun - 1.0, begun + 8.0, begun + 9.0)
    )  # lookups are already late; the decision is not

    monkeypatch.setattr(
        hooks_mode, "CONFIG_MIN_WAIT_SECONDS", 10.0
    )  # the subject is the guard deadline, not the load floor on a busy machine
    assert denied(_private_home, agents, f"sleep 60 # lead-wait: ok - {REASON}")


class Ticks:
    """Counts calls to a tick function, standing in for the deadline check."""

    def __init__(self) -> None:
        self.count = 0

    def __call__(self) -> None:
        self.count += 1


LONG = 5000

HELPER_CALLS: dict[str, Callable[[], object]] = {
    "_find_dq": lambda: leadwait._find_dq("a" * LONG + '"', 0),
    "_find_backtick": lambda: leadwait._find_backtick("a" * LONG + "`", 0),
    "_find_close": lambda: leadwait._find_close("a" * LONG + ")", 0, ")"),
    "_drop_continuations": lambda: leadwait._drop_continuations("ab" * LONG),
    "_ansi_c": lambda: leadwait._ansi_c("a" * LONG + "'", 0),
    "_heredoc_word": lambda: leadwait._heredoc_word("A" * LONG, 0),
    "_heredoc_word in double quotes": lambda: leadwait._heredoc_word('"' + "A" * LONG + '"', 0),
    "arithmetic_end": lambda: leadwait._Scan.arithmetic_end("$((" + "1+" * LONG + "1))", 0),
}


@pytest.mark.parametrize("name", list(HELPER_CALLS))
def test_r4_every_helper_loop_ticks_at_least_once_per_two_characters(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    ticks = Ticks()
    monkeypatch.setattr(leadwait, "_tick", ticks)
    HELPER_CALLS[name]()
    assert ticks.count >= LONG // 2, name


PREPASS_INPUTS = {
    "plain words": "a " * LONG,
    "heredoc body lines": "cat <<A\n" + "x\n" * LONG + "A",
    "heredoc continuation joins": "cat <<A\n" + "x\\\n" * LONG + "y\nA",
    "ansi-c span": "$'" + "a" * LONG + "'",
    "blanks after <<": "cat <<" + " " * LONG + "A",
}


@pytest.mark.parametrize("name", list(PREPASS_INPUTS))
def test_r4_every_prepass_loop_ticks(name: str) -> None:
    ticks = Ticks()
    leadwait._join_continuations(PREPASS_INPUTS[name], ticks)
    assert ticks.count >= LONG // 2, name


WALKER_CALLS: dict[str, Callable[[leadwait._Scan], object]] = {
    "main loop": lambda scan: scan.walk("a " * LONG, 0, False, 0, True),
    "double-quoted loop": lambda scan: scan.walk('"' + "a" * LONG + '"', 0, False, 0, True),
    "scan_data": lambda scan: scan.scan_data("a" * LONG, 0, True),
    "heredoc_body": lambda scan: scan.heredoc_body("x\n" * LONG + "EOF\n", 0, "EOF", False, True, 0),
}


@pytest.mark.parametrize("name", list(WALKER_CALLS))
def test_r4_every_walker_loop_ticks(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    ticks = Ticks()
    monkeypatch.setattr(leadwait._Scan, "tick", lambda self: ticks())
    WALKER_CALLS[name](leadwait._Scan())
    assert ticks.count >= LONG // 2, name


def test_r4_real_reason_ticks_over_the_whole_reason() -> None:
    ticks = Ticks()
    assert leadwait.real_reason("a" * LONG, ticks)
    assert ticks.count >= 2 * LONG  # once per character in each of its two passes


# Round 4, test gaps: content-freeness for EVERY verdict kind, and a cache that never changes a verdict.

SENTINEL = "sentinel-arg-xyz"
KIND_COMMANDS = {
    "gh-run-watch": f"gh run watch 1 {SENTINEL}",
    "gh-pr-checks-watch": f"gh pr checks 1 -w {SENTINEL}",
    "watch": f"watch -n 5 echo {SENTINEL}",
    "sleep-loop": f"while true; do sleep 1; echo {SENTINEL}; done",
    "long-sleep": f"sleep 60 {SENTINEL}",
    "unscannable-depth": f"echo $(echo $(echo $(echo $(sleep 60 {SENTINEL}))))",
    "unscannable-brace": f"{{sleep,60}} {SENTINEL}",
    "unscannable-indirect": f"f() {{ :; }}; x=f; $x {SENTINEL}",
    "unscannable-timeout": f"sleep 1 {SENTINEL}",  # the test shrinks the guard's budget to nothing
}
ROUND3_FIXTURES += [c for k, c in KIND_COMMANDS.items() if k != "unscannable-timeout"]


def test_r4_the_content_free_test_covers_every_verdict_kind() -> None:
    assert set(KIND_COMMANDS) == set(leadwait.KINDS)


@pytest.mark.parametrize("mode", ["warn", "block"])
@pytest.mark.parametrize("kind", list(KIND_COMMANDS))
def test_r4_neither_the_hook_output_nor_the_log_carries_the_command_for_any_kind(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch, kind: str, mode: str
) -> None:
    from safo.modes import hooks as hooks_mode

    command = KIND_COMMANDS[kind]
    if kind == "unscannable-timeout":
        monkeypatch.setattr(
            hooks_mode, "budget_points", lambda begun: (begun - 1.0, begun + 8.0, begun - 1.0)
        )  # lookups are already late; the decision is not
        monkeypatch.setattr(
            hooks_mode, "CONFIG_MIN_WAIT_SECONDS", 10.0
        )  # the subject is the guard deadline, not the load floor on a busy machine
    else:
        assert kind in leadwait.find_waits(command, THRESHOLD), kind
    set_mode(_private_home, mode)
    out = guard(_private_home, agents, bash(command))[1]
    assert out, kind
    log_file = _private_home / ".local/state/safo/hooks/log.jsonl"
    skipped = kind == "unscannable-timeout"  # out of time at once: the decision is printed, the append is skipped
    log_text = log_file.read_text() if log_file.exists() else ""
    assert skipped == (not log_file.exists()), kind
    assert SENTINEL not in out and SENTINEL not in log_text, kind
    assert "sentinel-description" not in out and "sentinel-description" not in log_text, kind
    if not skipped:
        assert read_log(_private_home)[-1]["rules"] == ["lead-waits"]
    if kind.startswith("unscannable-"):
        assert kind in out  # the message names the kind, nothing else of the call


CACHE_COMMANDS = [
    "sleep 60",
    "ls -la",
    "{sleep,60}",
    f"sleep 45 # lead-wait: ok - {REASON}",
    "while true; do gh run view 9; sleep 5; done",
    "f() { sleep 60; }; f",
    "echo " + "a " * 6000 + "; sleep 60",  # over CACHE_MAX_CHARS: kept by identity for the call only
    "echo " + "a " * 6000 + f"; sleep 60 # lead-wait: ok - {REASON}",
]


def hook_questions(command: str, deadline: float | None = None) -> tuple[bool, tuple[str, ...], str]:
    """The three questions the hook asks about one input, in its order."""
    return (
        leadwait.may_wait(command, deadline),
        leadwait.find_waits(command, THRESHOLD, deadline),
        leadwait.marker_reason(command, deadline),
    )


@pytest.mark.parametrize("command", CACHE_COMMANDS)
def test_r4_the_cache_never_changes_a_verdict_between_the_hooks_three_calls(command: str) -> None:
    fresh = leadwait._build(command, None)  # no cache involved
    expected_kinds = tuple(k for k in leadwait.KINDS if k in fresh.found)
    first = hook_questions(command)
    assert first == hook_questions(command) == hook_questions(command)
    assert first[1] == leadwait.find_waits(command, THRESHOLD) and set(expected_kinds) <= set(first[1])
    assert first[2] == (REASON if "lead-wait" in command else "")


@pytest.mark.parametrize("size", ["small", "large"])
def test_r4_an_expired_result_is_never_cached(size: str) -> None:
    command = f"sleep 60 # unique {size} {time.monotonic()} " + ("x" * (20000 if size == "large" else 10))
    expired = time.monotonic() - 1
    assert leadwait.find_waits(command, THRESHOLD, expired) == ("unscannable-timeout",)
    assert command not in leadwait._SMALL_CACHE
    assert not leadwait._last_large or leadwait._last_large[0][0] is not command
    # the next call, with time, gets the real verdict (not the remembered timeout)
    assert leadwait.find_waits(command, THRESHOLD) == ("long-sleep",)
    assert leadwait.marker_reason(command) == ""
    # ...and a call that comes back with an expired deadline after a completed scan keeps the completed verdict
    assert leadwait.find_waits(command, THRESHOLD, expired) == ("long-sleep",)


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
        "completion notice arrives without its report",
        "re-dispatches a fresh agent with the same brief within five minutes",
        "not retried by continuing it",
        "(INFERRED, from one session:",
        'model: "sonnet"',
        "issue: <owner/repo#N>",
    ):
        assert needle in page, needle
