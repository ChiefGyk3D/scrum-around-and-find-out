# SPDX-License-Identifier: Apache-2.0
"""The shared-directory deletion guard (#422): the command that did the damage, its cousins, and what stays allowed."""

from __future__ import annotations

import io
import json
from typing import Any

import pytest

from safo import rmguard

HOME = "/home/u"
DEV = f"{HOME}/.local/share/reach-around-dev"
AGENT = f"{DEV}/agents/422-reviewer"
PAD = "/tmp/claude-1000/-home-u-src/abc123/scratchpad"

# The exact command that deleted another session's logs and helper scripts on 2026-11-23.
DAMAGE = f"cd {DEV} && rm -rf build *.py *.log"
DAMAGE_TILDE = "rm -rf ~/.local/share/reach-around-dev/*.py ~/.local/share/reach-around-dev/*.log"

BLOCKED = [
    pytest.param(DAMAGE, "/home/u", id="damage-cd-glob"),
    pytest.param("rm -rf *.py *.log", DEV, id="damage-cwd-glob"),
    pytest.param(DAMAGE_TILDE, "/home/u", id="damage-tilde-glob"),
    pytest.param(f"rm -rf {DEV}/*.py", "/", id="absolute-glob"),
    pytest.param(f"rm -f {DEV}/logs/?.log", "/", id="question-glob"),
    pytest.param(f"rm {DEV}/x[12].log", "/", id="bracket-glob"),
    pytest.param(f"rm -rf {DEV}/{{a,b}}", "/", id="brace-list"),
    pytest.param(f"find {DEV} -name '*.log' -delete", "/", id="find-delete"),
    pytest.param("find . -name '*.pyc' -delete", DEV, id="find-delete-cwd"),
    pytest.param(f"find {DEV} -type f -exec rm {{}} +", "/", id="find-exec-rm"),
    pytest.param(f"find {DEV} -execdir rm -f {{}} \\;", "/", id="find-execdir-rm"),
    pytest.param(f"rm -rf {DEV}", "/", id="parent-shared-root"),
    pytest.param(f"rm -r {DEV}/", "/", id="parent-trailing-slash"),
    pytest.param(f"rm -rf {DEV}/agents", "/", id="parent-agents-folder"),
    pytest.param(f"rm -rf {DEV}/agents/../other", "/", id="dotdot-out-of-agent"),
    pytest.param("rm -rf ~/.local/share", "/", id="ancestor-share"),
    pytest.param("rm -rf $HOME/.local/share/*-dev", "/", id="ancestor-glob-all-dev"),
    pytest.param("rm -rf ~", "/", id="ancestor-home"),
    pytest.param(f"rm -rf {HOME}/.local/share/other-dev/x", "/", id="other-dev-dir"),
    pytest.param(f"rm {DEV}/session.log", "/", id="exact-file-outside-agent"),
    pytest.param("rm -rf ..", f"{DEV}/agents", id="relative-parent"),
    pytest.param("cd agents && rm -rf ../*", DEV, id="cd-then-parent-glob"),
    pytest.param("rm -rf /tmp/claude-1000", "/", id="scratchpad-parent"),
    pytest.param("rm -rf /tmp/claude-1000/*", "/", id="scratchpad-parent-glob"),
    pytest.param(f"rm -rf {PAD}/../other", "/", id="scratchpad-dotdot"),
    pytest.param(f"rm -rf {PAD}", "/", id="scratchpad-itself"),
    pytest.param(f"rm -rf {PAD}/*", "/", id="scratchpad-glob"),
    pytest.param(f"sudo rm -rf {DEV}/*.log", "/", id="sudo-wrapper"),
    pytest.param(f"env FOO=1 nice -n 5 rm -rf {DEV}/*.log", "/", id="env-nice-wrapper"),
    pytest.param(f"/bin/rm -rf {DEV}/*.log", "/", id="absolute-rm"),
    pytest.param(f"\\rm -rf {DEV}/*.log", "/", id="backslash-rm"),
    pytest.param(f"r''m -rf {DEV}/*.log", "/", id="quoted-rm-word"),
    pytest.param(f"echo ok; true && rm -rf {DEV}/*.log", "/", id="after-separator"),
    pytest.param(f"(rm -rf {DEV}/*.log)", "/", id="subshell"),
    pytest.param(f"bash -c 'rm -rf {DEV}/*.log'", "/", id="bash-c"),
    pytest.param(f'sh -c "cd {DEV} && rm -rf *.log"', "/", id="sh-c-cd"),
    pytest.param(f"eval 'rm -rf {DEV}/*.log'", "/", id="eval"),
    pytest.param(f"echo $(rm -rf {DEV}/*.log)", "/", id="substitution"),
    pytest.param(f"echo `rm -rf {DEV}/*.log`", "/", id="backticks"),
    pytest.param(f"cat <<EOF\n$(rm -rf {DEV}/*.log)\nEOF", "/", id="heredoc-substitution"),
    pytest.param(f"ls {DEV}/*.log | xargs rm", "/", id="xargs-rm-mentions-zone"),
    pytest.param("ls | xargs rm -f", DEV, id="xargs-rm-in-zone"),
    pytest.param("unlink ~/.local/share/reach-around-dev/x.log", "/", id="unlink"),
    pytest.param(f"shred -u {DEV}/*.log", "/", id="shred-glob"),
    pytest.param(f"rm -rf {AGENT}/*.log", "/", id="glob-even-in-own-folder"),
    pytest.param(f"sudo -u root rm -rf {DEV}/*.log", "/", id="sudo-option-value"),
    pytest.param(f"timeout 5 rm -rf {DEV}/*.log", "/", id="timeout-duration"),
    pytest.param(f"flock /tmp/l rm -rf {DEV}/*.log", "/", id="flock-operand"),
    pytest.param("find . -print0 | xargs -0 -n1 rm -rf", DEV, id="xargs-options"),
    pytest.param(f"rm -rf {DEV}/*.log >/dev/null 2>&1", "/", id="redirects-dont-hide-targets"),
    # fail closed: it cannot tell where these point
    pytest.param('rm -rf "$SOMEDIR"', "/", id="unknown-expansion-recursive"),
    pytest.param("rm -f $SOMEFILE", "/", id="unknown-expansion-unquoted"),
    pytest.param('cd "$X" && rm -rf *.log', "/", id="cd-unknown-glob"),
    pytest.param(f"rm -rf {DEV}/*.log 'unterminated", "/", id="unterminated-quote"),
    pytest.param(f"$RM -rf {DEV}/*.log", "/", id="command-word-from-expansion"),
    pytest.param(f'bash -c "bash -c \\"bash -c \'bash -c \\\\\\"rm -rf {DEV}/*.log\\\\\\"\'\\""', "/", id="deep"),
]

ALLOWED = [
    pytest.param(f"rm -rf {AGENT}", "/", id="own-folder-exact"),
    pytest.param(f"rm -rf {AGENT}/venv", "/", id="own-subfolder-exact"),
    pytest.param(f"rm {AGENT}/old.log {AGENT}/old.py", "/", id="own-files-exact"),
    pytest.param("rm -rf ~/.local/share/reach-around-dev/agents/422-reviewer", "/", id="tilde-exact"),
    pytest.param("rm -rf $HOME/.local/share/reach-around-dev/agents/422-reviewer", "/", id="home-var-exact"),
    pytest.param("rm -rf venv", AGENT, id="relative-exact-in-own-folder"),
    pytest.param("cd ~/.local/share/reach-around-dev/agents/422-reviewer && rm -rf repo", "/", id="cd-then-exact"),
    pytest.param(f"find {AGENT} -name '*.pyc' -delete", "/", id="find-delete-in-own-folder"),
    pytest.param("find . -name '*.pyc' -delete", AGENT, id="find-delete-cwd-own-folder"),
    pytest.param(f"rm -rf {PAD}/work", "/", id="scratchpad-exact"),
    pytest.param(f"ls {AGENT} | xargs rm", AGENT, id="xargs-in-own-folder"),
    pytest.param("rm -rf build dist *.egg-info", "/work/repo", id="outside-glob"),
    pytest.param("rm -rf ~/src/project/node_modules", "/", id="outside-exact"),
    pytest.param("rm -f /tmp/safo-test.log", "/", id="tmp-file-outside-claude"),
    pytest.param('rm -f "$f"', "/work", id="quoted-nonrecursive-expansion"),
    pytest.param("find /var/log -name '*.old' -print", "/", id="find-without-delete"),
    pytest.param(f"find {DEV} -name '*.log'", "/", id="find-read-only-in-zone"),
    pytest.param(f"ls {DEV}/*.log", "/", id="ls-glob-in-zone"),
    pytest.param(f"echo rm -rf {DEV}/*.log", "/", id="echo-is-data"),
    pytest.param(f"git commit -m 'rm -rf {DEV}/*.log is blocked'", "/", id="commit-message-is-data"),
    pytest.param(f"cat <<'EOF'\nrm -rf {DEV}/*.log\nEOF", "/", id="quoted-heredoc-is-data"),
    pytest.param(f"echo hi # rm -rf {DEV}/*.log", "/", id="comment-is-data"),
    pytest.param('git commit -m "it\'s fine"', "/", id="apostrophe-in-double-quotes"),
    pytest.param("echo 'unterminated", "/", id="unterminated-no-delete-word"),
    pytest.param("ls", "/", id="plain"),
]


@pytest.mark.parametrize(("command", "cwd"), BLOCKED)
def test_blocked(command: str, cwd: str) -> None:
    assert rmguard.check(command, HOME, cwd) is not None, command


@pytest.mark.parametrize(("command", "cwd"), ALLOWED)
def test_allowed(command: str, cwd: str) -> None:
    assert rmguard.check(command, HOME, cwd) is None, command


def test_the_tables_are_not_empty() -> None:
    # collect loosely, assert strictly: a parametrization typo cannot make the guard tests pass by collecting nothing
    assert len(BLOCKED) > 40
    assert len(ALLOWED) > 20


def event(command: str, cwd: str = "/", tool: str = "Bash") -> str:
    return json.dumps({"tool_name": tool, "cwd": cwd, "tool_input": {"command": command}})


def run_hook(raw: str, capsys: pytest.CaptureFixture[str]) -> str:
    """The deny reason the hook printed, or "" when it allowed."""
    assert rmguard.main(io.StringIO(raw), HOME) == 0
    out = capsys.readouterr().out
    if not out:
        return ""
    parsed: dict[str, Any] = json.loads(out)
    assert parsed["hookSpecificOutput"]["permissionDecision"] == "deny"
    return str(parsed["hookSpecificOutput"]["permissionDecisionReason"])


def test_hook_denies_the_damage_command_with_a_message_that_says_what_to_do(capsys: pytest.CaptureFixture[str]) -> None:
    reason = run_hook(event(DAMAGE, "/home/u"), capsys)
    assert "per-agent folder" in reason
    assert "agents/<issue>-<role>" in reason
    assert "EXACT path" in reason
    assert "—" not in reason  # no em dash


def test_hook_allows_the_own_folder_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert run_hook(event(f"rm -rf {AGENT}"), capsys) == ""


def test_hook_ignores_other_tools_and_missing_commands(capsys: pytest.CaptureFixture[str]) -> None:
    assert run_hook(event(DAMAGE, tool="Write"), capsys) == ""
    assert run_hook(json.dumps({"tool_name": "Bash", "tool_input": {}}), capsys) == ""


@pytest.mark.parametrize("raw", ["", "not json", "[1, 2]", "\x00"])
def test_hook_fails_closed_on_an_unreadable_event(raw: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert "could not be read" in run_hook(raw, capsys)


def test_hook_fails_closed_on_an_internal_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(*_: object) -> None:
        raise RuntimeError("bug")

    monkeypatch.setattr(rmguard, "check", boom)
    assert "internal error" in run_hook(event("ls"), capsys)


def test_the_guard_bites_a_negative_control() -> None:
    # the same command moved outside every zone passes, so the rule is about the zone, not about `rm`
    assert rmguard.check("rm -rf *.py *.log", HOME, "/work/repo") is None
    assert rmguard.check("rm -rf *.py *.log", HOME, DEV) is not None
