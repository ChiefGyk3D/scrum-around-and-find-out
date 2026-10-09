# SPDX-License-Identifier: MIT
"""The Action never imports code from the caller's workspace.

The workspace is the caller's checkout, so anything in it (a `safo` package, a `yaml.py`, a `sitecustomize.py`) is
untrusted. These tests run the Action's own commands, taken from action.yml, from a workspace laid out to hijack
Python, with a hostile PYTHONPATH as well, and prove none of it is imported. A control run shows the same workspace
does hijack a plain `python -m`, so the proof can fail.
"""

from __future__ import annotations

import subprocess
import sys
import sysconfig
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).parent.parent
STEPS: list[dict[str, Any]] = yaml.safe_load((ROOT / "action.yml").read_text())["runs"]["steps"]
BOARD = (ROOT / "tests" / "data" / "board.yaml").read_text()
HOSTILE = "import pathlib, sys\npathlib.Path(__file__).with_name('MARKER').write_text(__name__)\nsys.exit(99)\n"
PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAabcdefgh\n-----END RSA PRIVATE KEY-----"


def script(name_part: str) -> str:
    found = [s for s in STEPS if name_part in str(s.get("name", ""))]
    assert len(found) == 1, name_part
    return str(found[0]["run"])


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    (ws / "safo").mkdir(parents=True)
    (ws / "safo" / "__init__.py").write_text(HOSTILE)
    for name in ("yaml.py", "venv.py", "sitecustomize.py", "usercustomize.py", "pip.py"):
        (ws / name).write_text(HOSTILE)
    (ws / "board.yaml").write_text(BOARD)
    return ws


def bash(command: str, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Run a fixed command line; everything variable travels in the environment, never in the argument list."""
    return subprocess.run(
        ["/bin/bash", "-c", 'eval "$SAFO_TEST_COMMAND"'],
        cwd=cwd,
        env={**env, "SAFO_TEST_COMMAND": command},
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture
def venv(tmp_path: Path) -> Path:
    """What the install step leaves: a venv holding SAFO and PyYAML. Built without a network (a .pth stands in for
    the copy and the hash-locked install, which action.yml's own tests check)."""
    target = tmp_path / "safo-venv"
    base = {"PY": sys.executable, "TARGET": str(target)}
    assert bash('"$PY" -I -m venv "$TARGET"', tmp_path, base).returncode == 0
    code = "import sysconfig; print(sysconfig.get_path('purelib'))"
    found = bash('"$TARGET/bin/python" -I -c "$CODE"', tmp_path, {**base, "CODE": code})
    purelib = Path(found.stdout.strip())
    (purelib / "safo-test.pth").write_text(f"{ROOT / 'src'}\n{sysconfig.get_path('purelib')}\n")
    return target


def run_step(name_part: str, ws: Path, venv: Path, extra: dict[str, str]) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": f"{venv / 'bin'}:/usr/bin:/bin",
        "PYTHONPATH": str(ws),
        "ACTION_PATH": str(ROOT),
        "VENV": str(venv),
        "GITHUB_WORKSPACE": str(ws),
        "STEP_SCRIPT": script(name_part),
        **extra,
    }
    return bash('eval "$STEP_SCRIPT"', ws, env)


def assert_untouched(ws: Path) -> None:
    assert list(ws.rglob("MARKER")) == [], "a file from the workspace was imported"


def test_the_mask_step_never_imports_the_workspace(workspace: Path, venv: Path) -> None:
    done = run_step("Mask the credentials", workspace, venv, {"PRIVATE_KEY": PEM, "TOKEN": "ghp_example_token"})
    assert done.returncode == 0, done.stderr
    assert "::add-mask::MIIEowIBAAKCAQEAabcdefgh" in done.stdout
    assert_untouched(workspace)


def test_the_preflight_step_never_imports_the_workspace(workspace: Path, venv: Path) -> None:
    extra = {
        "SAFO_MODE": "audit",
        "SAFO_BOARD": "board.yaml",
        "HAS_PRIVATE_KEY": "true",
        "HAS_TOKEN": "false",
        "CLIENT_ID": "Iv23liTEST",
        "GITHUB_REPOSITORY": "acme/widgets",
        "REPOSITORY_OWNER": "acme",
        "REPO_PRIVATE": "true",
        "SAFO_DRY_RUN": "false",
        "GITHUB_OUTPUT": str(workspace.parent / "output"),
    }
    done = run_step("Preflight", workspace, venv, extra)
    assert done.returncode == 0, done.stdout + done.stderr
    assert (workspace.parent / "output").read_text() == "repositories=widgets,manuals\n"
    assert_untouched(workspace)


def test_the_run_step_never_imports_the_workspace(workspace: Path, venv: Path) -> None:
    done = run_step(
        "Run safo", workspace, venv, {"SAFO_MODE": "validate", "SAFO_BOARD": "board.yaml", "SAFO_DRY_RUN": "false"}
    )
    assert done.returncode == 0, done.stdout + done.stderr
    assert "configuration valid" in done.stdout
    assert_untouched(workspace)


def test_the_installed_code_is_the_actions_not_the_workspaces(workspace: Path, venv: Path) -> None:
    code = "import safo, yaml; print(safo.__file__); print(yaml.__file__)"
    probe = bash(
        '"$VENV/bin/python" -I -c "$CODE"', workspace, {"VENV": str(venv), "CODE": code, "PYTHONPATH": str(workspace)}
    )
    assert probe.returncode == 0, probe.stderr
    assert str(workspace) not in probe.stdout and str(ROOT / "src") in probe.stdout


def test_the_control_run_shows_the_same_workspace_does_hijack_a_plain_python(workspace: Path, venv: Path) -> None:
    """Without -I and with the workspace on the path, the hostile package is imported: the guard above can fail."""
    env = {"VENV": str(venv), "PYTHONPATH": str(workspace), "PRIVATE_KEY": PEM}
    plain = bash('"$VENV/bin/python" -m safo.action_mask', workspace, env)
    assert plain.returncode != 0 and list(workspace.rglob("MARKER"))
