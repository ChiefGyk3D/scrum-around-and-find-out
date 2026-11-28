# SPDX-License-Identifier: Apache-2.0
"""#615 item 3: `safo hooks status` recognises the wrapped guard command; what install writes is unchanged."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from safo import cli
from safo.hooks import guard_form


def cli_main(argv: list[str]) -> tuple[int, str]:
    out = io.StringIO()
    code = cli.main(argv, out=out, err=io.StringIO(), env=None)
    return code, out.getvalue()


WRAPPED = "command -v safo-guard >/dev/null 2>&1 && exec safo-guard || exit 0"


def test_the_wrapped_form_is_recognised_as_the_guard() -> None:
    assert guard_form(WRAPPED) == "new"


@pytest.mark.parametrize(
    "command",
    [
        "command -v safo-guard >/dev/null 2>&1 && exec safo-guard --agents /abs/agents.yaml || exit 0",
    ],
)
def test_the_wrapped_form_with_a_valid_tail_or_launcher_is_recognised(command: str) -> None:
    assert guard_form(command) == "new"


@pytest.mark.parametrize(
    "command",
    [
        "command -v safo-guard >/dev/null 2>&1 && exec evil || exit 0",
        # probes one program and runs another (#397's rule, the stricter one): the probe proves nothing about python3
        "command -v safo-guard >/dev/null 2>&1 && exec python3 -m safo.guard || exit 0",
        "command -v safo-guard >/dev/null 2>&1 && exec safo-guard --agents rel.yaml || exit 0",
        "command -v safo-guard >/dev/null 2>&1 && exec safo-guard; rm -rf x || exit 0",
        "command -v safo-guard >/dev/null 2>&1 && exec safo-guard || exit 1",
        "command -v other >/dev/null 2>&1 && exec safo-guard || exit 0",
        "exec safo-guard || exit 0",
        "command -v safo-guard && exec safo-guard || exit 0",
        "echo hi && command -v safo-guard >/dev/null 2>&1 && exec safo-guard || exit 0",
    ],
)
def test_a_lookalike_wrapper_is_not_the_guard(command: str) -> None:
    assert guard_form(command) is None


def test_the_plain_forms_are_unchanged() -> None:
    assert guard_form("safo-guard") == "new" and guard_form("safo hooks guard") == "legacy"
    assert guard_form("echo hi") is None


def test_status_reports_the_wrapped_form_as_installed(_private_home: Path, tmp_path: Path) -> None:
    target = tmp_path / "settings.json"
    entry = {"type": "command", "command": WRAPPED, "timeout": 10}
    target.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "Agent|Task|Bash", "hooks": [entry]}]}}))
    code, out = cli_main(["hooks", "status", "--settings", str(target)])
    assert code == 0
    [line] = [r for r in out.splitlines() if r.startswith("  guard hook:")]
    assert line.startswith("  guard hook: new ("), line


def test_status_still_calls_a_wrapped_entry_with_the_wrong_matcher_ineffective(
    _private_home: Path, tmp_path: Path
) -> None:
    target = tmp_path / "settings.json"
    entry = {"type": "command", "command": WRAPPED}
    target.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "Read", "hooks": [entry]}]}}))
    _, out = cli_main(["hooks", "status", "--settings", str(target)])
    assert "guard hook: ineffective (wrong matcher" in out


def test_install_does_not_own_the_wrapped_form() -> None:
    from safo.hooks import guard_signature

    assert guard_signature(WRAPPED) is None  # what install replaces or migrates is unchanged


def _install_over(command: str) -> tuple[dict[str, Any], bool]:
    from safo.hooks import merge_settings

    entry = {"type": "command", "command": command, "timeout": 10}
    settings = {"hooks": {"PreToolUse": [{"matcher": "Agent|Task|Bash", "hooks": [entry]}]}}
    return merge_settings(settings, "safo hooks probe", "safo-guard")


def _guard_command(merged: dict[str, Any]) -> str:
    [group] = merged["hooks"]["PreToolUse"]
    [entry] = group["hooks"]
    assert isinstance(entry["command"], str)
    return entry["command"]


def test_install_leaves_a_legacy_wrapper_exactly_as_it_is() -> None:
    from safo.hooks import unwrap_guarded

    legacy = "command -v safo >/dev/null 2>&1 && exec safo hooks guard || exit 0"
    command = _guard_command(_install_over(legacy)[0])
    assert command == legacy  # never a probe of one program and a run of another
    assert unwrap_guarded(command) is not None


def test_install_never_writes_a_wrapper_whose_probe_and_run_differ() -> None:
    from safo.hooks import unwrap_guarded

    for old in (
        "command -v safo >/dev/null 2>&1 && exec safo hooks guard --agents /old/a.yaml || exit 0",
        "command -v safo-guard >/dev/null 2>&1 && exec safo-guard --agents /old/a.yaml || exit 0",
        "command -v safo-guard >/dev/null 2>&1 && exec safo-guard || exit 0",
    ):
        command = _guard_command(_install_over(old)[0])
        assert unwrap_guarded(command) is not None, command


def test_install_updates_the_arguments_inside_a_wrapper_of_the_same_program() -> None:
    old = "command -v safo-guard >/dev/null 2>&1 && exec safo-guard --agents /old/a.yaml || exit 0"
    assert _guard_command(_install_over(old)[0]) == "command -v safo-guard >/dev/null 2>&1 && exec safo-guard || exit 0"


def test_install_leaves_a_normal_wrapper_unchanged() -> None:
    assert _guard_command(_install_over(WRAPPED)[0]) == WRAPPED
