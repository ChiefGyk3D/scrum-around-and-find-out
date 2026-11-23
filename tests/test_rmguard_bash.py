# SPDX-License-Identifier: Apache-2.0
"""rmguard against the real `bash` (#422): what the shell would hand to `rm` versus what the guard decides.

A fake `rm` (and `unlink`) on the PATH records the absolute path of every operand it receives instead of deleting
anything. Each command runs in a throwaway home; if bash hands the fake `rm` a path inside a shared zone that is not an
exact path under a per-agent folder, the guard must deny the same command text. Nothing here deletes a file.

If `bash` is missing the module is skipped, except under CI (the `CI` environment variable is set), where a missing
bash is a FAILURE: a silent skip would turn the differential check off without anyone noticing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from safo import rmguard

BASH = shutil.which("bash")
if BASH is None and not os.environ.get("CI"):
    pytest.skip("bash is not installed", allow_module_level=True)

FAKE = """#!/bin/sh
for a in "$@"; do
  case "$a" in -*) ;; /*) printf '%s\\n' "$a" >> "$OUT" ;; *) printf '%s\\n' "$PWD/$a" >> "$OUT" ;; esac
done
"""

# (command with {H} home, {D} dev dir, {W} work dir; working directory)
DENIED = [
    ("cd {D} && rm -rf *.log", "{H}"),
    ("rm>/dev/null {D}/*.log", "/"),
    ("2>&1 rm -rf {D}/*.log", "/"),
    (">/dev/null rm {D}/a.log", "/"),
    ("$'r\\x6d' -rf {D}/*.log", "/"),
    ("rm -rf $'{D}/a.log'", "/"),
    ("rm -rf //{D}/*.log", "/"),
    ('for f in {D}/*.log; do rm "$f"; done', "{W}"),
    ("cd {D} && (cd {W}); rm *.log", "/"),
    ("cd {D}; cd {W} & wait; rm *.log", "/"),
    ("env -C {D} rm *.log", "/"),
    ("env --chdir={D} rm *.log", "/"),
    ("env -S 'rm -rf *.log'", "{D}"),
    ("find {D} -type f -exec env rm {{}} +", "/"),
    ("find {D} -type f -exec nice rm {{}} \\;", "/"),
    ("pushd {D} >/dev/null; pushd {W} >/dev/null; popd >/dev/null; rm *.log", "/"),
    ("cd {D} || true; rm *.log", "/"),
    ("rm -rf {D}/agents/../b.py", "/"),
    ("rm {D}/a.log", "/"),
]
ALLOWED = [
    ("rm -rf {W}/*.o", "/"),
    ("cd {W} && rm *.o", "/"),
    ("(cd {D}); rm {W}/x.o", "{W}"),
    ("rm {D}/agents/me/ok.log", "/"),
    ("2>/dev/null rm -rf {D}/agents/me", "/"),
    ("env -C {W} rm x.o", "/"),
]


@pytest.fixture
def world(tmp_path: Path) -> dict[str, str]:
    home = tmp_path / "home"
    dev = home / ".local/share/reach-around-dev"
    work = home / "work"
    for path in (dev / "agents/me", work, tmp_path / "bin"):
        path.mkdir(parents=True)
    for path in (dev / "a.log", dev / "b.py", dev / "agents/me/ok.log", work / "x.o"):
        path.write_text("x")
    for name in ("rm", "unlink", "shred", "rmdir"):
        fake = tmp_path / "bin" / name
        fake.write_text(FAKE)
        fake.chmod(0o755)
    return {"H": str(home), "D": str(dev), "W": str(work), "bin": str(tmp_path / "bin"), "out": str(tmp_path / "out")}


def touched(command: str, cwd: str, w: dict[str, str]) -> list[str]:
    env = {"HOME": w["H"], "PATH": f"{w['bin']}:/usr/bin:/bin", "OUT": w["out"], "LC_ALL": "C"}
    Path(w["out"]).write_text("")
    assert BASH is not None
    subprocess.run([BASH, "-c", command], cwd=cwd, env=env, check=False, capture_output=True, timeout=20)  # noqa: S603
    return [line for line in Path(w["out"]).read_text().splitlines() if line]


@pytest.mark.parametrize(("template", "cwd"), DENIED)
def test_when_bash_would_delete_in_a_zone_the_guard_denies(
    template: str, cwd: str, world: dict[str, str], tmp_path: Path
) -> None:
    command = template.format(**world)
    where = cwd.format(**world)
    paths = touched(command, where, world)
    zones = rmguard.Zones(world["H"])
    hit = [p for p in paths if zones.judge(os.path.normpath(p), False) == "shared"]
    assert hit, f"the fixture no longer reaches a zone: {command!r} gave {paths!r}"
    assert rmguard.check(command, world["H"], where) is not None, command


@pytest.mark.parametrize(("template", "cwd"), ALLOWED)
def test_when_bash_stays_outside_or_in_an_agent_folder_the_guard_allows(
    template: str, cwd: str, world: dict[str, str]
) -> None:
    command = template.format(**world)
    where = cwd.format(**world)
    paths = touched(command, where, world)
    assert paths, f"the fixture no longer deletes anything: {command!r}"
    zones = rmguard.Zones(world["H"])
    assert all(zones.judge(os.path.normpath(p), False) != "shared" for p in paths), paths
    assert rmguard.check(command, world["H"], where) is None, command
