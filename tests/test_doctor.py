# SPDX-License-Identifier: Apache-2.0
"""`safo doctor`: each prerequisite is present, missing or too old; exit 0 only when every required one is present.

Hermetic: the tools are fake scripts in a temporary directory that is the whole PATH, HOME is a temporary directory,
and the run is in-process. Nothing real is probed, so a machine that has (or lacks) gh cannot change the result.
"""

from __future__ import annotations

import io
import json
import re
import stat
from collections.abc import Mapping
from pathlib import Path

import pytest

from safo import prereqs
from safo.cli import main

ROOT = Path(__file__).parent.parent
SECRET = "-".join(["planted", "marker", "never", "printed"])  # a fake, built at run time; never printed

GOOD = {
    "git": "git version 2.47.3",
    "gh": "gh version 2.100.0 (2026-09-03)\nhttps://github.com/cli/cli/releases/tag/v2.100.0",
    "jq": "jq-1.7",
    "doppler": "v3.77.1",
    "codex": "codex-cli 0.164.0",
    "claude": "2.1.312 (Claude Code)",
}


def fake(bindir: Path, name: str, text: str, *, code: int = 0, log: Path | None = None) -> None:
    body = "#!/bin/sh\n"
    if log is not None:
        body += f'echo "$@" >> "{log}"\n'
    quoted = "'" + text.replace("'", "'\\''") + "'"
    body += f"printf '%s\\n' {quoted}\nexit {code}\n"  # builtins only: the child's PATH holds nothing else
    path = bindir / name
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


@pytest.fixture
def world(tmp_path: Path) -> tuple[Path, Path]:
    bindir, home = tmp_path / "bin", tmp_path / "home"
    bindir.mkdir()
    home.mkdir()
    return bindir, home


def doctor(bindir: Path, home: Path, *extra: str, env: Mapping[str, str] | None = None) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    environment = {"PATH": str(bindir), "HOME": str(home), **(env or {})}
    code = main(["doctor", *extra], env=environment, out=out, err=err)
    assert err.getvalue() == ""
    return code, out.getvalue()


def stock(bindir: Path, **override: str) -> None:
    for name, text in {**GOOD, **override}.items():
        fake(bindir, name, text)


def line_for(out: str, name: str) -> str:
    return next(
        x for x in out.splitlines() if re.match(rf"(?:present|missing|too old|unreadable)\s+{re.escape(name)}\b", x)
    )


def test_everything_present_and_new_enough_exits_0(world: tuple[Path, Path]) -> None:
    bindir, home = world
    stock(bindir)
    code, out = doctor(bindir, home)
    assert code == 0, out
    assert line_for(out, "gh").startswith("present")
    assert "2.100.0" in line_for(out, "gh")


def test_a_gh_below_the_minimum_is_too_old_and_exits_1(world: tuple[Path, Path]) -> None:
    bindir, home = world
    stock(bindir, gh="gh version 2.56.0 (2024-08-01)")
    code, out = doctor(bindir, home)
    assert code == 1
    assert line_for(out, "gh").startswith("too old")
    assert "2.57.0" in line_for(out, "gh")


def test_the_minimum_itself_passes(world: tuple[Path, Path]) -> None:
    bindir, home = world
    stock(bindir, gh="gh version 2.57.0 (2024-09-16)")
    assert doctor(bindir, home)[0] == 0


def test_a_missing_required_tool_exits_1(world: tuple[Path, Path]) -> None:
    bindir, home = world
    stock(bindir)
    (bindir / "git").unlink()
    code, out = doctor(bindir, home)
    assert code == 1
    assert line_for(out, "git").startswith("missing")


@pytest.mark.parametrize("name", ["jq", "doppler", "codex", "claude"])
def test_a_missing_optional_tool_is_reported_and_exits_0(world: tuple[Path, Path], name: str) -> None:
    bindir, home = world
    stock(bindir)
    (bindir / name).unlink()
    code, out = doctor(bindir, home)
    assert code == 0, out
    assert line_for(out, name).startswith("missing")
    assert "optional" in line_for(out, name)


def test_a_required_tool_whose_version_cannot_be_read_does_not_pass(world: tuple[Path, Path]) -> None:
    bindir, home = world
    stock(bindir, gh="no digits here")
    code, out = doctor(bindir, home)
    assert code == 1
    assert line_for(out, "gh").startswith("unreadable")


def test_a_failing_version_probe_is_unreadable_not_a_crash(world: tuple[Path, Path]) -> None:
    bindir, home = world
    stock(bindir)
    fake(bindir, "git", "boom", code=3)
    code, out = doctor(bindir, home)
    assert code == 1 and line_for(out, "git").startswith("unreadable")


def test_only_a_version_probe_is_ever_run_and_no_secret_is_printed(world: tuple[Path, Path]) -> None:
    bindir, home = world
    log = home / "argv.log"
    for name, text in GOOD.items():
        fake(bindir, name, f"{text}\ntoken: {SECRET}", log=log)
    code, out = doctor(bindir, home, env={"SAFO_TOKEN": SECRET, "GH_TOKEN": SECRET})
    assert code == 0
    assert SECRET not in out
    calls = log.read_text(encoding="utf-8").splitlines()
    assert calls and set(calls) == {"--version"}


def test_a_tool_in_a_relative_path_entry_is_never_run(
    world: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    bindir, home = world
    marker = home / "ran"
    fake(bindir, "git", GOOD["git"])
    hostile = home / "cwd"
    hostile.mkdir()
    (hostile / "gh").write_text(f"#!/bin/sh\ntouch '{marker}'\necho 'gh version 9.9.9'\n", encoding="utf-8")
    (hostile / "gh").chmod(0o755)
    monkeypatch.chdir(hostile)
    code, out = doctor(bindir, home, env={"PATH": f"{bindir}:.:"})
    assert not marker.exists()
    assert code == 1 and line_for(out, "gh").startswith("missing")


def test_python_is_checked_without_running_anything() -> None:
    assert prereqs.check_python((3, 11, 0)).status == "present"
    assert prereqs.check_python((3, 10, 14)).status == "too old"
    assert prereqs.check_python((3, 10, 14)).required


def test_version_parsing_covers_every_tool_format() -> None:
    for text, want in [
        ("git version 2.47.3", (2, 47, 3)),
        ("jq-1.7", (1, 7, 0)),
        ("v3.77.1", (3, 77, 1)),
        ("2.1.312 (Claude Code)", (2, 1, 312)),
        ("gh version 2.100.0 (2026-09-03)", (2, 100, 0)),
    ]:
        assert prereqs.parse_version(text) == want, text
    assert prereqs.parse_version("nothing") is None
    assert prereqs.parse_version("") is None


def test_plugins_and_skills_are_read_from_home_and_never_change_the_exit_code(world: tuple[Path, Path]) -> None:
    bindir, home = world
    stock(bindir)
    plugins = home / ".claude" / "plugins"
    plugins.mkdir(parents=True)
    (plugins / "installed_plugins.json").write_text(
        json.dumps({"plugins": {"superpowers@claude-plugins-official": [{"version": "7.0.0"}]}}), encoding="utf-8"
    )
    skill = home / ".claude" / "skills" / "pack-threat-model"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: pack-threat-model\n---\n", encoding="utf-8")
    code, out = doctor(bindir, home)
    assert code == 0
    assert line_for(out, "superpowers").startswith("present")
    assert line_for(out, "codex-plugin").startswith("missing")
    assert line_for(out, "pack-threat-model").startswith("present")
    assert line_for(out, "pack-rf-emcomm").startswith("missing")


@pytest.mark.parametrize("content", ["{not json", "[]", '{"plugins": 3}', ""])
def test_a_damaged_plugin_file_is_missing_not_a_crash(world: tuple[Path, Path], content: str) -> None:
    bindir, home = world
    stock(bindir)
    plugins = home / ".claude" / "plugins"
    plugins.mkdir(parents=True)
    (plugins / "installed_plugins.json").write_text(content, encoding="utf-8")
    code, out = doctor(bindir, home)
    assert code == 0 and line_for(out, "superpowers").startswith("missing")


def test_no_home_is_not_a_crash(world: tuple[Path, Path]) -> None:
    bindir, _ = world
    stock(bindir)
    out, err = io.StringIO(), io.StringIO()
    assert main(["doctor"], env={"PATH": str(bindir)}, out=out, err=err) == 0
    assert "missing" in line_for(out.getvalue(), "superpowers")


def test_the_summary_line_counts_what_is_wrong(world: tuple[Path, Path]) -> None:
    bindir, home = world
    stock(bindir, gh="gh version 2.1.0")
    _, out = doctor(bindir, home)
    assert out.splitlines()[-1].startswith("FAIL")
    stock(bindir)
    _, out = doctor(bindir, home)
    assert out.splitlines()[-1].startswith("OK")


# the page and the code state the same minimums
PAGE = (ROOT / "docs" / "prerequisites.md").read_text(encoding="utf-8")


def page_minimums(text: str) -> dict[str, str]:
    rows = re.finditer(r"^\| `([a-z-]+)` \| (required|optional) \| ([0-9.]+|none) \|", text, re.MULTILINE)
    return {m[1]: m[3] for m in rows}


def code_minimums() -> dict[str, str]:
    return {t.name: ".".join(map(str, t.minimum)) if t.minimum else "none" for t in prereqs.TOOLS}


def test_the_page_lists_every_tool_with_the_minimum_the_code_enforces() -> None:
    assert code_minimums()
    assert page_minimums(PAGE) == code_minimums()


def test_the_page_guard_bites() -> None:
    changed = PAGE.replace("| `gh` | required | 2.57.0 |", "| `gh` | required | 2.40.0 |")
    assert changed != PAGE and page_minimums(changed) != code_minimums()
    dropped = "\n".join(x for x in PAGE.splitlines() if not x.startswith("| `jq` |"))
    assert page_minimums(dropped) != code_minimums()
    assert page_minimums("no table") == {}


def test_the_probe_child_gets_no_token_or_account_setting(world: tuple[Path, Path]) -> None:
    bindir, home = world
    stock(bindir)
    seen = home / "seen"
    dump = 'printf \'%s|%s|%s\' "$SAFO_TOKEN" "$GH_TOKEN" "$GH_HOST"'
    body = f"#!/bin/sh\n{dump} > '{seen}'\necho 'gh version 2.100.0'\n"
    (bindir / "gh").write_text(body, encoding="utf-8")
    (bindir / "gh").chmod(0o755)
    env = {"SAFO_TOKEN": SECRET, "GH_TOKEN": SECRET, "GH_HOST": "example.invalid"}
    assert doctor(bindir, home, env=env)[0] == 0
    assert seen.read_text(encoding="utf-8") == "||"


def test_a_tool_that_needs_home_to_print_its_version_is_given_it(world: tuple[Path, Path]) -> None:
    bindir, home = world
    stock(bindir)
    body = '#!/bin/sh\n[ -n "$HOME" ] || exit 1\necho "v3.77.1"\n'
    (bindir / "doppler").write_text(body, encoding="utf-8")
    (bindir / "doppler").chmod(0o755)
    _, out = doctor(bindir, home)
    assert line_for(out, "doppler").startswith("present")
