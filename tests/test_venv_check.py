# SPDX-License-Identifier: MIT
"""The venv the Action runs credentials through holds only what venv, ensurepip and the locked install put in it."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

from safo import venv_check

SRC = Path(venv_check.__file__)


def venv_root(tmp_path: Path, names: list[str]) -> Path:
    site = tmp_path / "v" / "lib" / "python3.13" / "site-packages"
    site.mkdir(parents=True)
    for name in names:
        (site / name).mkdir() if not name.endswith((".pth", ".py")) else (site / name).write_text("x")
    return tmp_path / "v"


FRESH = ["pip", "pip-25.0.dist-info", "__pycache__"]
INSTALLED = [*FRESH, "yaml", "_yaml", "PyYAML-6.0.3.dist-info", "safo"]


def test_a_freshly_created_venv_passes_and_so_does_the_finished_one(tmp_path: Path) -> None:
    venv_check.check(venv_root(tmp_path / "a", FRESH), "created")
    venv_check.check(venv_root(tmp_path / "b", INSTALLED), "installed")


def test_older_pythons_setuptools_files_are_allowed(tmp_path: Path) -> None:
    names = [*FRESH, "setuptools", "setuptools-65.5.0.dist-info", "pkg_resources", "_distutils_hack"]
    venv_check.check(venv_root(tmp_path, [*names, "distutils-precedence.pth"]), "created")


@pytest.mark.parametrize(
    "planted",
    ["evil.pth", "sitecustomize.py", "usercustomize.py", "pip.py", "yaml.py", "safo.py", "other", "x.egg-link"],
)
@pytest.mark.parametrize("phase", ["created", "installed"])
def test_a_planted_entry_is_refused_in_either_phase(tmp_path: Path, planted: str, phase: str) -> None:
    root = venv_root(tmp_path, [*(FRESH if phase == "created" else INSTALLED), planted])
    with pytest.raises(venv_check.VenvError, match="unexpected"):
        venv_check.check(root, phase)


@pytest.mark.parametrize("name", ["yaml", "_yaml", "PyYAML-6.0.3.dist-info", "safo"])
def test_the_installed_packages_are_unexpected_before_the_install(tmp_path: Path, name: str) -> None:
    with pytest.raises(venv_check.VenvError, match="unexpected"):
        venv_check.check(venv_root(tmp_path, [*FRESH, name]), "created")


def test_a_symlink_is_refused_even_under_an_allowed_name(tmp_path: Path) -> None:
    root = venv_root(tmp_path, FRESH)
    site = next(root.glob("lib/python*/site-packages"))
    (site / "safo").symlink_to(tmp_path)
    with pytest.raises(venv_check.VenvError, match="symbolic link"):
        venv_check.check(root, "installed")


def test_there_must_be_exactly_one_site_packages(tmp_path: Path) -> None:
    root = venv_root(tmp_path, FRESH)
    with pytest.raises(venv_check.VenvError, match="site-packages"):
        venv_check.check(tmp_path / "empty", "created")
    (root / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
    with pytest.raises(venv_check.VenvError, match="site-packages"):
        venv_check.check(root, "created")


def test_an_unknown_phase_is_refused(tmp_path: Path) -> None:
    with pytest.raises(venv_check.VenvError, match="phase"):
        venv_check.check(venv_root(tmp_path, FRESH), "later")


def script_run(phase: str, venv: Path) -> subprocess.CompletedProcess[str]:
    env = {"PY": sys.executable, "CHECK": str(SRC), "PHASE": phase, "VENV_DIR": str(venv)}
    return subprocess.run(
        ["/bin/bash", "-c", '"$PY" -I "$CHECK" "$PHASE" "$VENV_DIR"'],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_the_script_exits_non_zero_with_one_annotation_and_zero_when_clean(tmp_path: Path) -> None:
    good = venv_root(tmp_path / "g", FRESH)
    bad = venv_root(tmp_path / "b", [*FRESH, "sitecustomize.py"])
    ok = script_run("created", good)
    assert ok.returncode == 0 and ok.stdout == "" and ok.stderr == ""
    no = script_run("created", bad)
    assert no.returncode != 0 and no.stderr.startswith("::error title=safo::") and no.stderr.count("\n") == 1
    assert "sitecustomize.py" in no.stderr


def test_a_hostile_file_name_cannot_start_a_second_command(tmp_path: Path) -> None:
    root = venv_root(tmp_path, FRESH)
    site = next(root.glob("lib/python*/site-packages"))
    (site / "a\n::set-output name=x::y").write_text("x")
    with pytest.raises(venv_check.VenvError) as caught:
        venv_check.check(root, "created")
    assert "\n" not in str(caught.value)


def test_the_checker_uses_only_the_standard_library_because_it_runs_before_anything_is_installed() -> None:
    tree = ast.parse(SRC.read_text())
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert imported <= {"__future__", "os", "re", "sys", "pathlib"}
