# SPDX-License-Identifier: MIT
"""Check that the venv the Action runs credentials through holds only what it should.

Run by the install step as `python -I src/safo/venv_check.py <phase> <venv>` with the interpreter that made the venv,
before anything inside the venv has run: a startup hook planted in site-packages (a `.pth` line, a `sitecustomize`
or `usercustomize`, a package that shadows `pip` or `safo`) would run the moment the venv's Python starts. Phase
`created`: only what venv and ensurepip put there. Phase `installed`: that plus PyYAML and safo. Anything else, and
any symbolic link, is refused. Standard library only, because nothing is installed yet when it first runs.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_VERSION = r"[0-9][0-9A-Za-z.+!_-]*"
CREATED = (
    r"pip",
    rf"pip-{_VERSION}\.dist-info",
    r"__pycache__",
    r"setuptools",
    rf"setuptools-{_VERSION}\.dist-info",
    r"pkg_resources",
    r"_distutils_hack",
    r"distutils-precedence\.pth",
)
INSTALLED = (*CREATED, r"yaml", r"_yaml", rf"(?i:pyyaml)-{_VERSION}\.dist-info", r"safo")
PHASES = {"created": CREATED, "installed": INSTALLED}


class VenvError(Exception):
    """The venv holds something it should not."""


def _shown(name: str) -> str:
    return repr(name[:80])  # repr writes line breaks and control characters as escapes


def site_packages(venv: Path) -> Path:
    found = sorted({*venv.glob("lib/python*/site-packages"), *venv.glob("Lib/site-packages")})
    if len(found) != 1:
        raise VenvError(f"expected exactly one site-packages in the venv, found {len(found)}")
    return found[0]


def check(venv: Path, phase: str) -> None:
    if phase not in PHASES:
        raise VenvError(f"unknown phase {_shown(phase)}")
    allowed = [re.compile(pattern) for pattern in PHASES[phase]]
    for entry in sorted(site_packages(venv).iterdir()):
        if entry.is_symlink():
            raise VenvError(f"site-packages holds a symbolic link {_shown(entry.name)}")
        if not any(pattern.fullmatch(entry.name) for pattern in allowed):
            raise VenvError(f"site-packages holds an unexpected entry {_shown(entry.name)} ({phase})")


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        raise SystemExit("::error title=safo::usage: venv_check.py <created|installed> <venv>")
    try:
        check(Path(argv[2]), argv[1])
    except VenvError as err:
        raise SystemExit(f"::error title=safo::{err}") from None
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
