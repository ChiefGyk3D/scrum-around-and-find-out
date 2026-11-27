# SPDX-License-Identifier: Apache-2.0
"""#615 item 3: `safo hooks status` recognises the wrapped guard command; what install writes is unchanged."""

from __future__ import annotations

import io
import json
from pathlib import Path

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
        "command -v safo-guard >/dev/null 2>&1 && exec python3 -m safo.guard || exit 0",
    ],
)
def test_the_wrapped_form_with_a_valid_tail_or_launcher_is_recognised(command: str) -> None:
    assert guard_form(command) == "new"


@pytest.mark.parametrize(
    "command",
    [
        "command -v safo-guard >/dev/null 2>&1 && exec evil || exit 0",
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
