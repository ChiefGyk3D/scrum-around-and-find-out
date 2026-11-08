# SPDX-License-Identifier: Apache-2.0
"""research-lead (#84), the Stop hook: a final message that relays "not found" about an external fact with no web search
in the turn is flagged. Warn only: it never blocks, never asks Claude to continue. Fails open on every error.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from hooksdata import agents_file, hooks, read_log
from safo import stophook
from safo.agentsfile import Research, load_agents
from safo.errors import ConfigError
from safo.guardlog import RULE_IDS, summarise
from safo.guardlog import read_log as read_guard_log

RELAY = "I searched memory and the docs. No statement found from the vendor, so this needs your decision."


@pytest.fixture
def agents(tmp_path: Path) -> Path:
    return agents_file(tmp_path / "agents.yaml")


def line(kind: str, content: Any, **extra: Any) -> str:
    return json.dumps({"type": kind, "message": {"content": content}, **extra})


def prompt(text: str = "find the vendor statement") -> str:
    return line("user", text)


def tool(name: str) -> str:
    return line("assistant", [{"type": "tool_use", "id": "t", "name": name, "input": {}}])


def result() -> str:
    return line("user", [{"type": "tool_result", "tool_use_id": "t", "content": "ok", "is_error": False}])


def said(text: str) -> str:
    return line("assistant", [{"type": "text", "text": text}])


def transcript(tmp_path: Path, *lines: str) -> Path:
    path = tmp_path / "session.jsonl"
    path.write_text("\n".join(lines) + "\n")
    return path


def stop(home: Path, agents: Path, message: str, path: Path | str | None, **extra: Any) -> tuple[int, str, str]:
    event: dict[str, Any] = {
        "session_id": "s",
        "hook_event_name": "Stop",
        "stop_hook_active": False,
        "last_assistant_message": message,
        **extra,
    }
    if path is not None:
        event["transcript_path"] = str(path)
    return hooks("stop", "--agents", str(agents), home=home, stdin=json.dumps(event))


def test_a_relayed_not_found_with_no_search_warns_visibly_and_logs(
    _private_home: Path, agents: Path, tmp_path: Path
) -> None:
    path = transcript(tmp_path, prompt(), tool("Bash"), result(), tool("Read"), result(), said(RELAY))
    code, out, _ = stop(_private_home, agents, RELAY, path)
    data = json.loads(out)
    assert code == 0 and set(data) == {"systemMessage"}  # no decision, no additionalContext: Claude does not continue
    assert "research-lead" in data["systemMessage"] and "web search" in data["systemMessage"]
    assert '"no statement found"' in data["systemMessage"]
    row = read_log(_private_home)[-1]
    assert row["rules"] == ["research-lead"] and row["decision"] == "warn"
    assert RELAY not in json.dumps(read_log(_private_home))  # the log never holds message text


def test_the_same_message_with_a_web_search_in_the_turn_is_clean(
    _private_home: Path, agents: Path, tmp_path: Path
) -> None:
    for name in ("WebSearch", "WebFetch"):
        path = transcript(tmp_path, prompt(), tool(name), result(), said(RELAY))
        code, out, _ = stop(_private_home, agents, RELAY, path)
        assert (code, out) == (0, ""), name
    assert read_log(_private_home) == []


def test_a_search_in_an_earlier_turn_does_not_count(_private_home: Path, agents: Path, tmp_path: Path) -> None:
    path = transcript(
        tmp_path, prompt("one"), tool("WebSearch"), result(), said("done"), prompt("two"), tool("Bash"), said(RELAY)
    )
    assert "research-lead" in stop(_private_home, agents, RELAY, path)[1]


def test_a_documentation_mcp_call_from_the_configured_list_counts(
    _private_home: Path, agents: Path, tmp_path: Path
) -> None:
    path = transcript(tmp_path, prompt(), tool("mcp__cloudflare-docs__search_cloudflare_documentation"), said(RELAY))
    assert stop(_private_home, agents, RELAY, path)[1] == ""
    custom = agents_file(tmp_path / "c.yaml", research={"search_tools": ["mcp__mine__*"]})
    assert "research-lead" in stop(_private_home, custom, RELAY, path)[1]  # the list is configuration, not code
    path = transcript(tmp_path, prompt(), tool("mcp__mine__lookup"), said(RELAY))
    assert stop(_private_home, custom, RELAY, path)[1] == ""


@pytest.mark.parametrize(
    "message",
    [
        "Ask Tuxedo in writing whether the ME is disabled.",
        "I found no source for that claim.",
        "I could not verify the advisory.",
        "That is unverified.",
        "I'm unable to confirm the release date.",
        "Couldn't find the press release.",
    ],
)
def test_each_default_phrase_family_is_caught(_private_home: Path, agents: Path, tmp_path: Path, message: str) -> None:
    path = transcript(tmp_path, prompt(), tool("Bash"), said(message))
    assert "research-lead" in stop(_private_home, agents, message, path)[1], message


@pytest.mark.parametrize(
    "message",
    [
        "Done. The change is merged and the tests pass.",
        "Nothing was missing; all three sources agree.",
    ],
)
def test_a_clean_turn_is_clean_and_reads_no_transcript(_private_home: Path, agents: Path, message: str) -> None:
    code, out, _ = stop(_private_home, agents, message, "/nonexistent/never-read.jsonl")
    assert (code, out) == (0, "") and read_log(_private_home) == []


@pytest.mark.parametrize(
    "message",
    [
        "The file docs/handoff.md was not found, so I created it.",
        "ls: /home/x/notes.txt: not found",
        "```\ncommand output: not found\n```\nAll good.",
        "The check says `no statement found` when the list is empty.",
        '> the vendor said "not found" earlier\nMoving on.',
        'The error text is "could not find" in our parser.',
        "Our own page returned 404 not found; I fixed the link.",
        "The command not found error came from the PATH.",
    ],
)
def test_the_handled_false_positive_classes_stay_clean(
    _private_home: Path, agents: Path, tmp_path: Path, message: str
) -> None:
    path = transcript(tmp_path, prompt(), tool("Bash"), said(message))
    assert stop(_private_home, agents, message, path)[1] == "", message


def test_stop_hook_active_does_nothing(_private_home: Path, agents: Path, tmp_path: Path) -> None:
    path = transcript(tmp_path, prompt(), tool("Bash"), said(RELAY))
    assert stop(_private_home, agents, RELAY, path, stop_hook_active=True)[1:] == ("", "")
    assert read_log(_private_home) == []


@pytest.mark.parametrize("path", [None, "/nonexistent/x.jsonl", "tmpdir"])
def test_an_unreadable_transcript_fails_open_with_the_degraded_notice(
    _private_home: Path, agents: Path, tmp_path: Path, path: str | None
) -> None:
    given = tmp_path if path == "tmpdir" else path
    code, out, _ = stop(_private_home, agents, RELAY, given)
    data = json.loads(out)
    assert code == 0 and set(data) == {"systemMessage"} and "degraded" in data["systemMessage"]
    row = read_log(_private_home)[-1]
    assert row["decision"] == "error" and row["diagnostic"] == "input" and row["rules"] == []


def test_a_garbage_event_fails_open(_private_home: Path, agents: Path) -> None:
    code, out, _ = hooks("stop", "--agents", str(agents), home=_private_home, stdin="{not json")
    assert code == 0 and "degraded" in json.loads(out)["systemMessage"]


def test_a_broken_config_fails_open(_private_home: Path, tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("not: [valid")
    bad.chmod(0o600)
    code, out, _ = stop(_private_home, bad, RELAY, None)
    assert code == 0 and "degraded" in json.loads(out)["systemMessage"]
    assert read_log(_private_home)[-1]["diagnostic"] == "config"


def test_a_symlinked_or_fifo_transcript_is_refused_not_followed(
    _private_home: Path, agents: Path, tmp_path: Path
) -> None:
    real = transcript(tmp_path, prompt(), tool("WebSearch"), said(RELAY))
    link = tmp_path / "link.jsonl"
    link.symlink_to(real)
    assert "degraded" in stop(_private_home, agents, RELAY, link)[1]
    fifo = tmp_path / "fifo.jsonl"
    os.mkfifo(fifo)
    assert "degraded" in stop(_private_home, agents, RELAY, fifo)[1]


def test_a_huge_transcript_is_read_only_at_its_tail(_private_home: Path, agents: Path, tmp_path: Path) -> None:
    filler = line("user", [{"type": "tool_result", "tool_use_id": "t", "content": "x" * 5_000}])
    head = [prompt("old"), tool("WebSearch")]  # a search long before the window: out of reach, so out of the turn
    body = [filler] * 1_000  # about 5 MB, beyond TAIL_BYTES
    path = transcript(tmp_path, *head, *body, tool("Bash"), said(RELAY))
    assert path.stat().st_size > 4 * stophook.TAIL_BYTES
    reads: list[int] = []
    real = os.read

    def spy(fd: int, n: int) -> bytes:
        got = real(fd, n)
        if os.readlink(f"/proc/self/fd/{fd}") == str(path):
            reads.append(len(got))
        return got

    os.read = spy
    try:
        out = stop(_private_home, agents, RELAY, path)[1]
    finally:
        os.read = real
    assert "research-lead" in out and sum(reads) <= stophook.TAIL_BYTES


def test_one_oversized_line_is_skipped_not_parsed(_private_home: Path, agents: Path, tmp_path: Path) -> None:
    giant = line("user", [{"type": "tool_result", "tool_use_id": "t", "content": "y" * 400_000}])
    path = transcript(tmp_path, prompt(), tool("WebSearch"), giant, said(RELAY))
    assert stop(_private_home, agents, RELAY, path)[1] == ""


def test_the_switch_and_the_phrases_are_configuration(_private_home: Path, tmp_path: Path) -> None:
    path = transcript(tmp_path, prompt(), tool("Bash"), said(RELAY))
    off = agents_file(tmp_path / "off.yaml", research={"lead_check": False})
    assert stop(_private_home, off, RELAY, path)[1] == ""
    custom = agents_file(tmp_path / "p.yaml", research={"lead_phrases": ["nowhere to be seen"]})
    assert stop(_private_home, custom, RELAY, path)[1] == ""
    assert "research-lead" in stop(_private_home, custom, "The page is nowhere to be seen.", path)[1]


def test_bad_lead_config_is_refused(tmp_path: Path) -> None:
    for key, value in (("lead_check", "yes"), ("lead_phrases", []), ("lead_phrases", [" "]), ("search_tools", "x")):
        path = agents_file(tmp_path / "a.yaml", research={key: value})
        with pytest.raises(ConfigError):
            load_agents(path)


def test_defaults_are_on(tmp_path: Path) -> None:
    cfg = load_agents(agents_file(tmp_path / "a.yaml")).hooks.research
    assert cfg.lead_check and cfg.lead_phrases == Research().lead_phrases and "websearch" in cfg.search_tools


def test_the_rule_is_in_the_log_vocabulary_and_the_status_counts(
    _private_home: Path, agents: Path, tmp_path: Path
) -> None:
    assert "research-lead" in RULE_IDS
    path = transcript(tmp_path, prompt(), tool("Bash"), said(RELAY))
    stop(_private_home, agents, RELAY, path)
    rows = read_guard_log(_private_home / ".local" / "state" / "safo" / "hooks" / "log.jsonl")
    assert dict(summarise(rows).rules) == {"research-lead": 1}
    _, out, _ = hooks("status", "--agents", str(agents), home=_private_home)
    assert "rules flagged: research-lead 1" in out


def test_the_hook_never_emits_a_continue_signal(_private_home: Path, agents: Path, tmp_path: Path) -> None:
    path = transcript(tmp_path, prompt(), said(RELAY))
    keys = set(json.loads(stop(_private_home, agents, RELAY, path)[1]))
    assert keys == {"systemMessage"}  # no decision, reason, continue or hookSpecificOutput.additionalContext
