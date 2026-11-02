# SPDX-License-Identifier: Apache-2.0
"""Refuse to start below the root-owned version floor (docs/gemini-broker.md, "Install and update chain", step 4).

The service unit runs `python -I -m safo.broker.floor` as ExecStartPre. The installer already refuses to install or roll
back below `/etc/safo/broker-min-version`; this is the second layer: a release that comes back by another route (a
restore from backup, a manual link change, an alternate boot root) still does not run once root has raised the floor.
Standard library plus the single output path only; it reads one root-owned file and compares two versions.
"""

from __future__ import annotations

import os
import re
import stat
import sys
from collections.abc import Sequence
from pathlib import Path

from safo import __version__, output

FLOOR_PATH = Path("/etc/safo/broker-min-version")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")


def _version(text: str) -> tuple[int, int, int] | None:
    if not VERSION.fullmatch(text):
        return None
    a, b, c = (int(x) for x in text.split("."))
    return (a, b, c)


def entry_problem(path: Path, uid: int, *, want_dir: bool) -> str | None:
    try:
        st = os.lstat(path)
    except OSError:
        return f"{path} is missing"
    if stat.S_ISLNK(st.st_mode):
        return f"{path} is a symlink"
    if not (stat.S_ISDIR(st.st_mode) if want_dir else stat.S_ISREG(st.st_mode)):
        return f"{path} is not a regular {'directory' if want_dir else 'file'}"
    if st.st_uid != uid:
        return f"{path} is not owned by the trusted user"
    if st.st_mode & 0o022:
        return f"{path} is writable by its group or others"
    return None


def check(floor_path: Path, version: str, *, uid: int = 0, anchor: Path = Path("/")) -> str | None:
    """Return the reason the broker must not start, or None when it may. Anything unclear refuses."""
    problem = entry_problem(floor_path, uid, want_dir=False)
    parent = floor_path.parent
    while problem is None:
        problem = entry_problem(parent, uid, want_dir=True)
        if parent == anchor or parent == parent.parent:
            break
        parent = parent.parent
    if problem:
        return f"the version floor file is unusable: {problem}"
    floor = _version(floor_path.read_text().strip())
    mine = _version(version)
    if floor is None:
        return "the version floor file does not hold a version"
    if mine is None:
        return f"this release has no usable version ({version!r})"
    if mine < floor:
        return f"this release {version} is below the floor {'.'.join(str(x) for x in floor)}"
    return None


def main(argv: Sequence[str] | None = None) -> int:
    if argv:
        output.write(sys.stderr, "safo.broker.floor takes no arguments")
        return 2
    reason = check(FLOOR_PATH, __version__)
    if reason:
        output.write(sys.stderr, f"refusing to start: {reason}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
