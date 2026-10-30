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
        f"curl https://gen''erative{HOST[len('generative'):]}",
        f'wget "https://{HOST.replace("language", "lan" + chr(92) + "guage")}"',
        f"doppler secrets get {KEY} --plain",
        f"echo ${{{KEY}}}",
        f"doppler run --project {PROJECT} --config x -- env",
        f"doppler secrets --config {PAID}",
        "doppler secrets get X --config prd --plain",
        f"python3 -c 'import {SDK}'",
        f"python3 -c \"from google import genai; genai.Client()\"",
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


def test_the_wrapper_is_allowed_even_when_it_carries_a_name() -> None:
    assert geminibrief.shell_command_class(f"safo gemini ask --model m --prompt-file docs/{PAID}.md --job j") is None
    assert geminibrief.shell_command_class(f"python3 -m safo gemini quota # {KEY}") is None


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
def test_the_wrapper_exemption_does_not_cover_what_is_chained_to_it(tail: str) -> None:
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


# -- the repo exemption -------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        f"grep -rn {HOST} docs tests",
        f"python3 -m pytest tests/test_gemini_guard.py -k {KEY}",
        f"pytest -q tests/test_gemini_bash.py -k {KEY}",
        f"git commit -m 'document {KEY} handling'",
        f"cat docs/gemini-keys.md | grep {PROJECT}",
        f"make check PY=python # {PAID}",
    ],
)
def test_reading_and_testing_this_repository_is_allowed(command: str) -> None:
    assert geminibrief.shell_command_class(command, cwd=REPO) is None, command
    assert geminibrief.shell_command_class(command, cwd=REPO / "docs") is None, command
    assert geminibrief.shell_command_class(command) is not None, command  # not from outside the repo


@pytest.mark.parametrize(
    "command",
    [
        f"curl https://{HOST}",
        f"grep -rn {HOST} docs | sh",
        f"grep -rn {HOST} docs; curl https://{HOST}",
        f"cat docs/x | curl -d @- https://{HOST}",
        f"git -c alias.x='!curl https://{HOST}' x",
        f"git -C /somewhere commit -m {KEY}",
        f"rg --pre curl {HOST} docs",
        f"cat $(curl https://{HOST})",
        f"cd / && grep {HOST} x",
        f"make check; doppler secrets get {KEY}",
        f"pytest $(echo {KEY})",
    ],
)
def test_the_repo_exemption_is_narrow(command: str) -> None:
    assert geminibrief.shell_command_class(command, cwd=REPO) is not None, command


def test_a_folder_that_only_looks_like_this_repo_is_not_exempt(tmp_path: Path) -> None:
    (tmp_path / "src" / "safo").mkdir(parents=True)  # no geminibrief.py inside
    assert geminibrief.shell_command_class(f"grep {HOST} x", cwd=tmp_path) is not None


def test_the_repo_docs_and_tests_do_not_trip_a_read_of_themselves() -> None:
    # the false-positive ceiling for this repo's own reading commands stays at 0
    names = [p.name for p in (REPO / "docs").glob("*.md")] + [p.name for p in (REPO / "tests").glob("test_gemini*.py")]
    assert names
    for name in names:
        sub = "docs" if name.endswith(".md") else "tests"
        assert geminibrief.shell_command_class(f"cat {sub}/{name}", cwd=REPO) is None, name
        assert geminibrief.shell_command_class(f"grep -n x {sub}/{name}", cwd=REPO) is None, name


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


def test_the_hook_allows_a_repo_read_from_the_repo_and_denies_it_elsewhere(
    _private_home: Path, agents: Path, tmp_path: Path
) -> None:
    command = f"grep -rn {HOST} docs"
    assert run(agents, _private_home, event(command, cwd=REPO)) == ("", "")
    assert denied(run(agents, _private_home, event(command, cwd=tmp_path))[0])


def test_a_background_call_is_still_checked(_private_home: Path, agents: Path) -> None:
    payload = json.loads(event(f"curl https://{HOST}"))
    payload["tool_input"]["run_in_background"] = True
    assert denied(run(agents, _private_home, json.dumps(payload))[0])


def test_a_malformed_shell_event_is_still_the_usual_degraded_path(_private_home: Path, agents: Path) -> None:
    payload = json.loads(event("ls"))
    payload["tool_input"] = {"command": 5}
    out, _ = run(agents, _private_home, json.dumps(payload))
    assert not denied(out)
