# SPDX-License-Identifier: Apache-2.0
"""Dispatch guard coverage for shell commands (#209).

A Bash call that names the vendor API host, its SDK, the key variable or the secret-store project and config names is
denied unless it is the documented wrapper or a read-only/test command inside this repository. The guard is a speed
bump; the wrapper holds the real gates. Names are built at run time so scanners stay quiet about this file.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

from geminidata import write_config
from hooksdata import agents_file, hooks, read_log
from safo import geminibrief
from safo.gemini import Locations

HOST = "generative" + "language" + ".googleapis" + ".com"
KEY = "GEMINI" + "_API" + "_KEY"
PAID = "prd" + "_paid"
PROJECT = "image" + "-gen"
SDK = "google" + ".generative" + "ai"
REPO = Path(__file__).resolve().parent.parent


def event(command: str, cwd: Path | None = None, **extra: Any) -> str:
    data: dict[str, Any] = {
        "hook_event_name": "PreToolUse",
        "session_id": "session-a",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        **extra,
    }
    if cwd is not None:
        data["cwd"] = str(cwd)
    return json.dumps(data)


@pytest.fixture
def agents(tmp_path: Path, gemini_locations: Locations) -> Path:
    write_config(
        gemini_locations.config, "http://127.0.0.1:9", tmp_path / "data" / "ledger.jsonl", private_terms="none"
    )
    return agents_file(tmp_path / "agents.yaml")


def run(agents: Path, home: Path, payload: str) -> tuple[str, str]:
    code, out, err = hooks("guard", "--agents", str(agents), home=home, stdin=payload)
    assert code == 0 or json.loads(out)["hookSpecificOutput"].get("permissionDecision") == "deny"
    return out, err


def denied(out: str) -> bool:
    return bool(out) and json.loads(out)["hookSpecificOutput"].get("permissionDecision") == "deny"


def reason(out: str) -> str:
    return str(json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"])


# -- the classifier ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        f"curl -s https://{HOST}/v1/models",
        f"curl -s 'https://{HOST}'",
        f"curl https://gen''erative{HOST[len('generative') :]}",
        f'wget "https://{HOST.replace("language", "lan" + chr(92) + "guage")}"',
        f"doppler secrets get {KEY} --plain",
        f"echo ${{{KEY}}}",
        f"doppler run --project {PROJECT} --config x -- env",
        f"doppler secrets --config {PAID}",
        "doppler secrets get X --config prd --plain",
        f"python3 -c 'import {SDK}'",
        'python3 -c "from google import genai; genai.Client()"',
        f"cat /dev/null\ncurl https://{HOST}",
        f"ls \\\n; curl https://{HOST.replace('generative', 'gener' + chr(92) + chr(10) + 'ative')}",
        # look-alike letters and full-width forms fold to the plain name
        "curl https://" + HOST.replace("a", "\u0430", 1),
        f"X={KEY.lower()}; echo $X",
        # words built from escapes beside a network tool, and a secret tool with an expansion
        "curl $'\\x68ttps://example.test/'",
        "printf -v H %s%s gener ativelanguage; curl https://$H.googleapis.com",
        "doppler secrets get $K --plain",
        "doppler secrets get `echo K` --plain",
    ],
)
def test_the_classifier_denies_commands_that_reach_the_vendor_or_its_key(command: str) -> None:
    assert geminibrief.shell_command_class(command) is not None, command


@pytest.mark.parametrize(
    "command",
    [
        "ls -la",
        "git status --short",
        "curl -s https://api.github.com/repos/o/r",
        "doppler --version",
        "echo $HOME && pytest -q tests",
        "python3 -m pytest tests/test_hooks.py",
        "printf '%s\\n' hello",
        "grep -rn prd src",  # the bare config word alone is not the secret tool
        "make check",
        "echo gemini is a constellation",
        "safo gemini quota",
        "safo gemini ask --model m --prompt-file /tmp/p.md --job j",
    ],
)
def test_the_classifier_leaves_ordinary_commands_alone(command: str) -> None:
    assert geminibrief.shell_command_class(command) is None, command


def test_the_wrapper_is_not_exempt_when_it_carries_a_name() -> None:
    assert (
        geminibrief.shell_command_class(f"safo gemini ask --model m --prompt-file docs/{PAID}.md --job j") is not None
    )
    assert geminibrief.shell_command_class(f"python3 -m safo gemini quota # {KEY}") is not None


@pytest.mark.parametrize(
    "command",
    [
        "safo gemini quota",
        "safo gemini ask --model m --prompt-file p",
        "safo gemini keys check",
        "python -m safo gemini quota",
    ],
)
def test_the_documented_wrapper_commands_name_nothing_and_are_not_touched(command: str) -> None:
    assert geminibrief.shell_command_class(command) is None, command


@pytest.mark.parametrize(
    "tail",
    [
        f"; curl https://{HOST}",
        f" && curl https://{HOST}",
        f" | curl -d @- https://{HOST}",
        f" > >(curl https://{HOST})",
        f" $(curl https://{HOST})",
        f" `curl https://{HOST}`",
        f"\ncurl https://{HOST}",
    ],
)
def test_a_name_chained_to_the_wrapper_is_denied(tail: str) -> None:
    assert geminibrief.shell_command_class("safo gemini ask --model m --prompt-file p" + tail) is not None, tail


def test_the_denial_class_is_fixed_text_never_command_text() -> None:
    secret = "tok_SECRETVALUE123"
    found = geminibrief.shell_command_class(f"curl -H 'x: {secret}' https://{HOST}/v1 --data {KEY}")
    assert found is not None and secret not in found and HOST not in found and KEY not in found


def test_a_deadline_that_has_passed_denies_instead_of_allowing() -> None:
    assert geminibrief.shell_command_class("ls", deadline=time.monotonic() - 1) == geminibrief.SHELL_UNVERIFIED


def test_scan_time_grows_in_proportion_to_the_command() -> None:
    # A ratio, never a fixed bound: the suite runs under coverage on shared runners.
    def took(size: int) -> float:
        command = ("echo " + "x" * 60 + "\n") * size
        best = float("inf")
        for _ in range(3):
            start = time.perf_counter()
            geminibrief.shell_command_class(command)
            best = min(best, time.perf_counter() - start)
        return best

    small, large = took(500), took(8000)
    assert large < small * 16 * 6 + 0.05  # 16x the input within 6x slack on linear growth


# -- no exemption for this repository ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        f"grep -rn {HOST} docs tests",
        f"python3 -m pytest tests/test_gemini_guard.py -k {KEY}",
        f"pytest -q tests/test_gemini_bash.py -k {KEY}",
        f"git commit -m 'document {KEY} handling'",
        f"cat docs/gemini-keys.md | grep {PROJECT}",
        f"make check PY=python # {PAID}",
        f"make SHELL='curl https://{HOST}' check",
        f"make --eval='x:; curl https://{HOST}' x",
        f"make -f /dev/stdin <<< 'x:; curl https://{HOST}'",
        f"git grep -O'curl https://{HOST}' x",
        f"git diff --ext-diff --output=/tmp/x {HOST}",
        f"cat ~/.config/safo/gemini.yaml # {PAID}",
        f"head -n5 examples/gemini.example.yaml # {KEY}",
        f"grep -rn . ~/.config/safo # {PROJECT}",
        f"curl https://{HOST}",
        f"grep -rn {HOST} docs | sh",
        f"cat $(curl https://{HOST})",
    ],
)
def test_nothing_is_exempt_by_where_it_runs_or_what_tool_it_is(command: str) -> None:
    assert geminibrief.shell_command_class(command) is not None, command


def test_the_function_takes_no_working_directory() -> None:
    # a spoofed checkout (marker files made anywhere) buys nothing: there is no argument to carry one
    call: Any = geminibrief.shell_command_class
    with pytest.raises(TypeError):
        call(f"grep {HOST} x", cwd=REPO)


def test_the_hook_ignores_the_cwd_even_inside_a_real_checkout(_private_home: Path, agents: Path) -> None:
    assert denied(run(agents, _private_home, event(f"grep -rn {HOST} docs", cwd=REPO))[0])


def test_a_directory_with_spoofed_marker_files_is_denied(_private_home: Path, agents: Path, tmp_path: Path) -> None:
    fake = tmp_path / "fake"
    (fake / "src" / "safo").mkdir(parents=True)
    (fake / "src" / "safo" / "geminibrief.py").write_text("")
    (fake / "pyproject.toml").write_text("")
    assert denied(run(agents, _private_home, event(f"cat {PAID}", cwd=fake))[0])


@pytest.mark.parametrize("command", ["make check", "make lint typecheck test", "pytest -q tests", "git status --short"])
def test_this_repos_normal_commands_are_not_denied_without_an_exemption(command: str) -> None:
    assert geminibrief.shell_command_class(command) is None, command


# -- the hook ----------------------------------------------------------------------------------------------------


def test_the_hook_denies_a_shell_call_to_the_vendor_even_in_warn_mode(_private_home: Path, agents: Path) -> None:
    out, _ = run(agents, _private_home, event(f"curl https://{HOST}/v1/models"))
    assert denied(out)
    text = reason(out)
    assert "gemini-material" in text and "safo gemini" in text and "docs/gemini.md" in text
    assert HOST not in text and "curl" not in text
    assert read_log(_private_home)[-1]["decision"] == "error"


def test_the_hook_denies_for_a_sub_agent_call_too(_private_home: Path, agents: Path) -> None:
    out, _ = run(agents, _private_home, event(f"doppler secrets get {KEY}", agent_id="a1"))
    assert denied(out)


def test_the_hook_allows_the_wrapper_and_an_ordinary_command(_private_home: Path, agents: Path) -> None:
    for command in ("safo gemini quota", "ls -la", "pytest -q"):
        assert run(agents, _private_home, event(command)) == ("", ""), command


def test_a_background_call_is_still_checked(_private_home: Path, agents: Path) -> None:
    payload = json.loads(event(f"curl https://{HOST}"))
    payload["tool_input"]["run_in_background"] = True
    assert denied(run(agents, _private_home, json.dumps(payload))[0])


def test_a_malformed_shell_event_is_still_the_usual_degraded_path(_private_home: Path, agents: Path) -> None:
    payload = json.loads(event("ls"))
    payload["tool_input"] = {"command": 5}
    out, _ = run(agents, _private_home, json.dumps(payload))
    assert not denied(out)


# -- a renamed or hijacked wrapper gains nothing ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        f"alias safo='curl'; safo gemini ask --prompt {HOST}",
        f'safo() {{ curl "$@"; }}; safo https://{HOST}',
        f"PYTHONPATH=/x python3 -m safo gemini quota {KEY}",
    ],
)
def test_a_hijacked_wrapper_name_is_denied_by_the_names_in_the_text(command: str) -> None:
    assert geminibrief.shell_command_class(command) is not None, command


def test_a_command_over_the_size_cap_is_denied_unread() -> None:
    assert geminibrief.shell_command_class("x" * (geminibrief.SHELL_CAP + 1)) == geminibrief.SHELL_UNVERIFIED
    assert geminibrief.shell_command_class("ls " + "x" * 1000) is None


def test_an_eight_megabyte_line_is_denied_fast_relative_to_a_small_command() -> None:
    def took(command: str) -> tuple[float, str | None]:
        start = time.perf_counter()
        for _ in range(3):
            result = geminibrief.shell_command_class(command)
        return (time.perf_counter() - start) / 3, result

    small, _ = took("x" * 60_000)
    big, result = took("x" * 8_000_000)
    assert result == geminibrief.SHELL_UNVERIFIED
    assert big < small * 20 + 0.05  # refused by length: never scales with the 8 MB (a ratio, not a fixed bound)
