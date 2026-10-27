# SPDX-License-Identifier: Apache-2.0
"""The guard's own entry point (`python -m safo.guard`, console script `safo-guard`, SAFO #189) and the installer form.

The entry reads only `--agents` and `--agents-local`; everything else on its command line is noise. The real-process
tests run it exactly as a host does: standard input a pipe with the event, standard error a FULL pipe nobody reads."""

from __future__ import annotations

import io
import json
import os
import sys
import time
import tomllib
from pathlib import Path
from typing import Any

import pytest

import safo as safo_package
from hooksdata import agents_file, dispatch, set_mode
from safo import guard as entry_module
from safo.guardlog import WARNING
from safo.modes import hooks as mod
from test_guard_emit_first import CHILD_BUDGET, denied, lines, run_entry

GUARD = "safo.guard"
NOISE = [
    pytest.param([], id="empty"),
    pytest.param(["--help"], id="help"),
    pytest.param(["-h"], id="short-help"),
    pytest.param(["--version"], id="version"),
    pytest.param(["hooks", "guard", "--bogus"], id="legacy-words"),
    pytest.param(["\udcff", "", "--agents"], id="garbage"),
    pytest.param(["--board", "hooks", "gua"], id="near-miss"),
]


def go(home: Path, argv: list[str], payload: str, **kw: Any) -> tuple[Any, bool]:
    return run_entry(home, argv, payload=payload, module=GUARD, **kw)


# -- the real process ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("argv", NOISE)
def test_noise_on_the_command_line_still_denies_a_denyable_event_with_a_full_stderr_pipe(
    block_home: Path, argv: list[str]
) -> None:
    result, untouched = go(block_home, argv, dispatch(model=None))
    assert not result.killed and untouched, "nothing was written to the blocked stderr"
    [row] = lines(result.raw.decode())
    assert result.status == 0 and denied(row), "a verdict, never help, never a silent exit 0"
    assert result.elapsed < CHILD_BUDGET


@pytest.mark.parametrize("argv", NOISE)
def test_noise_on_the_command_line_allows_an_allowable_event_with_a_verdict(block_home: Path, argv: list[str]) -> None:
    result, untouched = go(block_home, argv, dispatch())
    assert not result.killed and untouched and result.status == 0
    assert WARNING not in result.raw.decode(), "a verdict, not the cannot-tell notice"
    assert "usage" not in result.raw.decode().lower()


def test_without_a_default_configuration_a_denyable_event_is_the_visible_degraded_allow(
    _private_home: Path,
) -> None:
    assert not (_private_home / ".config" / "safo" / "agents.yaml").exists(), "no default configuration"
    set_mode(_private_home, "block")
    result, untouched = go(_private_home, [], dispatch(model=None))
    assert not result.killed and untouched and result.status == 0
    [row] = lines(result.raw.decode())
    assert not denied(row) and WARNING in row["systemMessage"]


@pytest.mark.parametrize(
    "words",
    [
        pytest.param(["--agents", "{p}"], id="separate"),
        pytest.param(["--agents={p}"], id="equals"),
        pytest.param(["--bogus", "--agents", "{p}", "--version"], id="among-noise"),
        pytest.param(["--agents", "/first/wrong.yaml", "--agents", "{p}"], id="last-wins"),
        pytest.param(["--agents", "", "--agents={p}"], id="empty-then-real"),
    ],
)
def test_the_explicit_agents_path_is_applied_when_there_is_no_default_configuration(
    strict_only: Path, _private_home: Path, words: list[str]
) -> None:
    result, untouched = go(_private_home, [w.replace("{p}", str(strict_only)) for w in words], dispatch(model=None))
    assert not result.killed and untouched
    [row] = lines(result.raw.decode())
    assert denied(row), row


def test_a_policy_path_beginning_with_a_dash_is_kept(strict_only: Path, _private_home: Path, tmp_path: Path) -> None:
    dashed = tmp_path / "-strict.yaml"
    dashed.write_text(strict_only.read_text())
    dashed.chmod(0o600)
    for words in (["--agents=" + str(dashed)], ["--agents", str(dashed)]):
        result, _ = go(_private_home, words, dispatch(model=None))
        assert denied(lines(result.raw.decode())[0]), words
    assert entry_module.scan(["--agents", "-s.yaml"]).agents == "-s.yaml"


def test_agents_local_is_read_too(strict_only: Path, _private_home: Path) -> None:
    result, _ = go(_private_home, ["--agents", str(strict_only), "--agents-local=/nonexistent/x.yaml"], dispatch())
    assert not result.killed and result.status == 0


@pytest.mark.parametrize("payload", ["", "not json", "{"])
def test_an_unreadable_event_takes_the_documented_cannot_tell_path(block_home: Path, payload: str) -> None:
    result, untouched = go(block_home, ["--help"], payload)
    assert not result.killed and untouched and result.status == 0
    [row] = lines(result.raw.decode())
    assert WARNING in row["systemMessage"] and not denied(row)


# -- in process ------------------------------------------------------------------------------------------------------


@pytest.fixture
def run_guard(monkeypatch: pytest.MonkeyPatch, hard_exits: list[int]) -> Any:
    monkeypatch.setattr(mod, "process_started", None)
    monkeypatch.setattr(safo_package, "PROCESS_STARTED", time.monotonic())

    def run(argv: list[str], payload: str) -> int:
        monkeypatch.setattr(sys, "stdin", io.StringIO(payload))
        monkeypatch.setattr(sys, "argv", ["safo-guard", *argv])
        return entry_module.main()

    return run


def test_the_process_ends_exactly_once_and_modes_are_never_loaded(
    block_home: Path, monkeypatch: pytest.MonkeyPatch, hard_exits: list[int], run_guard: Any, capsys: Any
) -> None:
    import safo.modes as modes

    def boom() -> None:
        raise AssertionError("the guard entry must not import or enumerate the modes")

    monkeypatch.setattr(modes, "load_all", boom)
    code = run_guard(["--version", "hooks"], dispatch(model=None))
    assert hard_exits == [code] and len(hard_exits) == 1
    assert denied(lines(capsys.readouterr().out)[0])


def test_importing_the_entry_loads_no_cli_and_no_other_mode() -> None:
    code = (
        "import sys, safo.guard;"
        "other = [m for m in sys.modules if m.startswith('safo.modes.') and m != 'safo.modes.hooks'];"
        "print(sorted([*other, *(m for m in sys.modules if m == 'safo.cli')]))"
    )
    read, write = os.pipe()
    pid = os.posix_spawn(
        sys.executable, [sys.executable, "-c", code], os.environ, file_actions=[(os.POSIX_SPAWN_DUP2, write, 1)]
    )
    os.close(write)
    with os.fdopen(read) as handle:
        printed = handle.read().strip()
    assert os.waitpid(pid, 0)[1] == 0
    assert printed == "[]"


def test_the_scan_rules() -> None:
    def parsed(*words: str) -> tuple[str, str]:
        ns = entry_module.scan(list(words))
        return ns.agents, ns.agents_local

    assert parsed("--agents", "a", "--agents-local", "b") == ("a", "b")
    assert parsed("--agents=a", "--agents-local=b") == ("a", "b")
    assert parsed("--agents", "a", "--agents=c") == ("c", "")
    assert parsed("--agents", "-p") == ("-p", ""), "a single-dash value is kept"
    assert parsed("--agents=-p") == ("-p", "")
    assert parsed("--agents", "--agents-local", "b") == ("", "b"), "a following -- word is not consumed"
    assert parsed("--agents", "--help") == ("", "")
    assert parsed("--agents=") == ("", "") and parsed("--agents", "") == ("", "")
    assert parsed("--agents", "a", "--agents=") == ("a", ""), "an empty value counts as absent"
    assert parsed("--agent", "a", "x", "--help", "--agents-locals", "q") == ("", "")
    assert parsed() == ("", "")


# -- packaging and the installer --------------------------------------------------------------------------------------


def test_the_console_script_is_registered() -> None:
    meta = tomllib.loads((Path(__file__).parent.parent / "pyproject.toml").read_text())
    assert meta["project"]["scripts"]["safo-guard"] == "safo.guard:run"
    assert meta["project"]["scripts"]["safo"] == "safo.cli:run"


def settings_of(home: Path) -> dict[str, Any]:
    return json.loads((home / ".claude" / "settings.json").read_text())  # type: ignore[no-any-return]


def guard_commands(data: dict[str, Any]) -> list[str]:
    return [h["command"] for g in data["hooks"]["PreToolUse"] for h in g["hooks"]]


def cli_main(argv: list[str]) -> tuple[int, str]:
    from safo import cli

    out = io.StringIO()
    code = cli.main(argv, out=out, err=io.StringIO(), env=None)
    return code, out.getvalue()


def test_install_writes_the_direct_guard_line(_private_home: Path) -> None:
    code, _ = cli_main(["hooks", "install"])
    assert code == 0
    assert guard_commands(settings_of(_private_home)) == ["safo-guard"]
    assert settings_of(_private_home)["hooks"]["SessionStart"][0]["hooks"][0]["command"] == "safo hooks probe"


def test_install_with_agents_python_launcher_and_idempotence(_private_home: Path, tmp_path: Path) -> None:
    agents = agents_file(tmp_path / "a.yaml")
    args = ["hooks", "install", "--agents", str(agents), "--command", "python3 -m safo"]
    assert cli_main(args)[0] == 0
    first = (_private_home / ".claude" / "settings.json").read_bytes()
    assert guard_commands(settings_of(_private_home)) == [f"python3 -m safo.guard --agents {agents.resolve()}"]
    code, out = cli_main(args)
    assert code == 0 and "nothing changed" in out
    assert (_private_home / ".claude" / "settings.json").read_bytes() == first


def test_install_with_an_absolute_launcher_uses_the_script_beside_it(_private_home: Path, tmp_path: Path) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name in ("safo", "safo-guard"):
        (bindir / name).write_text("#!/bin/sh\n")
        (bindir / name).chmod(0o755)
    assert cli_main(["hooks", "install", "--command", str(bindir / "safo")])[0] == 0
    assert guard_commands(settings_of(_private_home)) == [str(bindir / "safo-guard")]
    (bindir / "safo-guard").unlink()
    (_private_home / ".claude" / "settings.json").unlink()
    assert cli_main(["hooks", "install", "--command", str(bindir / "safo")])[0] != 0


def legacy_settings(home: Path, command: str, others: bool = True) -> Path:
    path = home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    groups: list[dict[str, Any]] = [{"matcher": "Agent|Task|Bash", "hooks": [{"type": "command", "command": command}]}]
    if others:
        groups.append({"matcher": "Read", "hooks": [{"type": "command", "command": "echo mine"}]})
    path.write_text(json.dumps({"hooks": {"PreToolUse": groups}}))
    return path


def test_install_migrates_a_legacy_line_and_leaves_other_hooks_alone(_private_home: Path) -> None:
    legacy_settings(_private_home, "safo hooks guard")
    assert cli_main(["hooks", "install"])[0] == 0
    data = settings_of(_private_home)
    assert guard_commands(data).count("safo-guard") == 1
    assert "safo hooks guard" not in guard_commands(data)
    assert "echo mine" in guard_commands(data)


def test_install_migrates_a_legacy_line_with_an_agents_path(_private_home: Path, tmp_path: Path) -> None:
    agents = agents_file(tmp_path / "a.yaml")
    legacy_settings(_private_home, f"safo hooks guard --agents {agents.resolve()}", others=False)
    assert cli_main(["hooks", "install", "--agents", str(agents)])[0] == 0
    assert guard_commands(settings_of(_private_home)) == [f"safo-guard --agents {agents.resolve()}"]


def test_install_refuses_to_swap_a_different_launcher_silently(_private_home: Path) -> None:
    legacy_settings(_private_home, "python3 -m safo hooks guard", others=False)
    assert cli_main(["hooks", "install"])[0] != 0
    assert guard_commands(settings_of(_private_home)) == ["python3 -m safo hooks guard"]


def status_line(home: Path) -> str:
    code, out = cli_main(["hooks", "status"])
    assert code == 0
    [row] = [r for r in out.splitlines() if r.startswith("  guard hook:")]
    return row


def test_status_reports_absent_legacy_new_and_mixed(_private_home: Path) -> None:
    assert "absent" in status_line(_private_home)
    legacy_settings(_private_home, "safo hooks guard")
    assert "legacy" in status_line(_private_home) and "mixed" not in status_line(_private_home)
    assert cli_main(["hooks", "install"])[0] == 0
    assert "new" in status_line(_private_home)
    path = _private_home / ".claude" / "settings.json"
    data = json.loads(path.read_text())
    data["hooks"]["PreToolUse"].append(
        {"matcher": "Agent|Task|Bash", "hooks": [{"type": "command", "command": "safo hooks guard"}]}
    )
    path.write_text(json.dumps(data))
    assert "mixed" in status_line(_private_home)
    path.write_text("not json")
    assert "unknown" in status_line(_private_home)


def test_the_status_reads_the_settings_file_it_is_given(_private_home: Path, tmp_path: Path) -> None:
    other = tmp_path / "other.json"
    other.write_text(json.dumps(settings_with([("Agent|Task|Bash", {"type": "command", "command": "safo-guard"})])))
    code, out = cli_main(["hooks", "status", "--settings", str(other)])
    assert code == 0 and "guard hook: new" in out


def test_mode_is_unchanged(_private_home: Path) -> None:
    from safo.guardlog import read_mode

    assert cli_main(["hooks", "mode", "block"])[0] == 0
    assert read_mode({"HOME": str(_private_home)}) == "block"


def test_the_entry_arms_the_process_clock(block_home: Path, run_guard: Any) -> None:
    assert mod.process_started is None
    run_guard([], dispatch())
    assert mod.process_started == safo_package.PROCESS_STARTED, "the budget counts from the start of the process"


def settings_with(groups: list[tuple[Any, Any]]) -> dict[str, Any]:
    return {"hooks": {"PreToolUse": [{"matcher": m, "hooks": [h]} for m, h in groups]}}


def status_of(tmp_path: Path, data: dict[str, Any]) -> str:
    target = tmp_path / "given.json"
    target.write_text(json.dumps(data))
    code, out = cli_main(["hooks", "status", "--settings", str(target)])
    assert code == 0
    [row] = [r for r in out.splitlines() if r.startswith("  guard hook:")]
    return row


FORMS = [pytest.param("safo-guard", id="new"), pytest.param("safo hooks guard", id="legacy")]


@pytest.mark.parametrize("command", FORMS)
@pytest.mark.parametrize(
    ("matcher", "entry_type", "reason"),
    [
        pytest.param("Read", "command", "wrong matcher", id="read"),
        pytest.param("", "command", "wrong matcher", id="empty"),
        pytest.param("Bash", "command", "wrong matcher", id="excludes-agent"),
        pytest.param("^(Read|Write)$", "command", "wrong matcher", id="regex-excludes-agent"),
        pytest.param("Agent|Task|Bash", "prompt", "wrong type", id="prompt"),
        pytest.param("Agent|Task|Bash", "agent", "wrong type", id="agent"),
        pytest.param("Agent|Task|Bash", None, "wrong type", id="missing-type"),
        pytest.param("Read", "prompt", "wrong matcher, wrong type", id="both"),
    ],
)
def test_status_never_calls_an_ineffective_guard_installed(
    tmp_path: Path, command: str, matcher: str, entry_type: Any, reason: str
) -> None:
    entry = {"command": command} if entry_type is None else {"type": entry_type, "command": command}
    row = status_of(tmp_path, settings_with([(matcher, entry)]))
    assert row.startswith("  guard hook: ineffective (" + reason + ":"), row
    assert "new (" not in row and "legacy (" not in row


@pytest.mark.parametrize("command", FORMS)
def test_status_accepts_exactly_what_install_accepts(tmp_path: Path, command: str) -> None:
    word = "new" if command == "safo-guard" else "legacy"
    for matcher in ("Agent|Task|Bash", "Agent|Task"):  # the one install writes and the one it migrates
        row = status_of(tmp_path, settings_with([(matcher, {"type": "command", "command": command})]))
        assert row.startswith(f"  guard hook: {word} ("), row


def test_status_ignores_a_non_string_command(tmp_path: Path) -> None:
    row = status_of(tmp_path, settings_with([("Agent|Task|Bash", {"type": "command", "command": ["safo-guard"]})]))
    assert row.startswith("  guard hook: absent"), row


@pytest.mark.parametrize("command", FORMS)
def test_status_names_an_ineffective_duplicate_beside_an_effective_entry(tmp_path: Path, command: str) -> None:
    word = "new" if command == "safo-guard" else "legacy"
    good = ("Agent|Task|Bash", {"type": "command", "command": command})
    bad = ("Read", {"type": "command", "command": command})
    row = status_of(tmp_path, settings_with([good, bad]))
    assert row.startswith("  guard hook: ineffective (wrong matcher:") and f"effective: {word}" in row, row


def test_install_and_status_share_one_acceptance_rule(_private_home: Path, tmp_path: Path) -> None:
    from safo import hooks as rules

    group = {"matcher": "Read"}
    assert rules.entry_problems(group, {"type": "prompt"}, rules.GUARD_MATCHER, rules.LEGACY_GUARD_MATCHERS) == [
        "wrong matcher",
        "wrong type",
    ]
    bad = settings_with([("Read", {"type": "command", "command": "safo-guard"})])
    with pytest.raises(Exception, match="ambiguous"):  # install refuses what status calls ineffective
        rules.merge_settings(bad, "safo hooks probe", "safo-guard")


def _modules_after_import(code: str) -> list[str]:
    import subprocess

    done = subprocess.run(  # noqa: S603 - fixed argv, no shell; the only variable is a literal import line from this file
        [sys.executable, "-I", "-c", "import sys\n" + code + "\nprint(' '.join(sorted(sys.modules)))"],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    return done.stdout.split()


def test_the_entry_point_imports_neither_argparse_nor_the_cli_nor_other_modes() -> None:
    loaded = _modules_after_import("import safo.guard")
    assert "safo.guard" in loaded, "the guard did not import"  # collect loosely, assert that something was loaded
    assert "argparse" not in loaded
    assert not {m for m in loaded if m == "safo.cli" or m.startswith("safo.modes.")} - {"safo.modes.hooks"}
    assert "safo.cli" not in loaded


def test_the_import_probe_bites() -> None:  # the negative case: the same probe does see argparse when it is imported
    assert "argparse" in _modules_after_import("import safo.guard, argparse")
    assert "safo.cli" in _modules_after_import("import safo.cli")


def test_scan_reads_only_the_two_attributes_the_guard_uses() -> None:
    ns = entry_module.scan(["--agents", "a.yaml", "--agents-local=b.yaml"])
    assert vars(ns) == {"agents": "a.yaml", "agents_local": "b.yaml"}
