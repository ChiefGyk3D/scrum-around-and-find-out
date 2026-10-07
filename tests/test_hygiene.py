# SPDX-License-Identifier: MIT
"""Repository rules that are cheap to check and expensive to rediscover."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import safo

ROOT = Path(__file__).parent.parent
SPDX = "SPDX-License-Identifier: MIT"
CODE_SUFFIXES = {".py", ".sh", ".yml", ".yaml"}
SKIP_DIRS = {
    ".git",
    ".venv",
    "node_modules",
    "wiki-out",
    "build",
    "dist",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
}


def tracked_or_present() -> list[Path]:
    """Files git knows about, or all files when this is not a checkout (an sdist)."""
    try:
        out = subprocess.run(  # noqa: S603
            ["git", "-C", str(ROOT), "ls-files", "--cached", "--others", "--exclude-standard"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
        ).stdout.splitlines()
        return [ROOT / line for line in out if (ROOT / line).is_file()]
    except (OSError, subprocess.CalledProcessError):
        return [p for p in ROOT.rglob("*") if p.is_file() and not SKIP_DIRS & set(p.parts)]


def test_every_source_file_carries_the_spdx_header_in_its_first_three_lines() -> None:
    missing = []
    for path in tracked_or_present():
        if path.suffix in CODE_SUFFIXES or path.name in {"Makefile", "action.yml"}:
            head = "\n".join(path.read_text().splitlines()[:3])
            if SPDX not in head:
                missing.append(str(path.relative_to(ROOT)))
    assert missing == []


def test_nothing_runs_a_shell_from_a_string() -> None:
    needles = ("shell" + "=True", "os." + "system(", "eval" + "(", "exec" + "(")
    offenders = []
    for path in tracked_or_present():
        if path.suffix == ".py" and path.name != "test_hygiene.py" and "docs" not in path.parts:
            text = path.read_text()
            offenders += [f"{path.relative_to(ROOT)}: {n}" for n in needles if n in text]
    assert offenders == []


def test_the_runtime_imports_only_the_standard_library_and_pyyaml() -> None:
    stdlib = set(__import__("sys").stdlib_module_names)
    allowed = stdlib | {"yaml", "safo"}
    bad = []
    for path in (ROOT / "src" / "safo").rglob("*.py"):
        for line in path.read_text().splitlines():
            m = re.match(r"^\s*(?:from|import)\s+([A-Za-z_][A-Za-z0-9_]*)", line)
            if m and m[1] not in allowed:
                bad.append(f"{path.name}: {line.strip()}")
    assert bad == []


def test_the_version_is_one_number() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+", safo.__version__)
    assert 'dynamic = ["version"]' in (ROOT / "pyproject.toml").read_text()


def test_the_licence_is_mit() -> None:
    assert (ROOT / "LICENSE").read_text().startswith("MIT License")
