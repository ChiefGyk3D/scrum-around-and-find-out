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


# -- the install step: a fresh, unpredictable venv, verified before anything runs in it ---------------------------

FAKE_PIP = (
    'P="$(echo "$VENV"/lib/python*/site-packages)"; cp -R "$FAKE_SRC/yaml" "$P/yaml"; '
    '[ ! -d "$FAKE_SRC/_yaml" ] || cp -R "$FAKE_SRC/_yaml" "$P/_yaml"; mkdir "$P/PyYAML-6.0.3.dist-info"'
)


def install_script() -> str:
    """The install step's script with only the network line replaced: the hash-locked pip install becomes a copy of
    the test environment's PyYAML, so it can run offline. The venv creation, checks and copy are the Action's own."""
    lines = script("Install SAFO").splitlines()
    out = [FAKE_PIP if "-m pip install" in line else line for line in lines]
    assert out != lines
    return "\n".join(out)


def run_install(
    tmp_path: Path, runner_temp: Path, *, path_prefix: str = ""
) -> tuple[subprocess.CompletedProcess[str], Path]:
    import yaml

    out = tmp_path / f"out-{len(list(tmp_path.glob('out-*')))}"
    env = {
        "PATH": f"{path_prefix}{Path(sys.executable).parent}:/usr/bin:/bin",
        "ACTION_PATH": str(ROOT),
        "RUNNER_TEMP": str(runner_temp),
        "GITHUB_OUTPUT": str(out),
        "FAKE_SRC": str(Path(yaml.__file__).parent.parent),
        "STEP_SCRIPT": install_script(),
    }
    runner_temp.mkdir(exist_ok=True)
    return bash('eval "$STEP_SCRIPT"', tmp_path, env), out


def venv_of(out: Path) -> Path:
    line = out.read_text().strip()
    assert line.startswith("venv=") and "\n" not in line
    return Path(line.removeprefix("venv="))


def test_two_runs_get_two_different_unpredictable_directories(tmp_path: Path) -> None:
    rt = tmp_path / "rt"
    first, out1 = run_install(tmp_path, rt)
    second, out2 = run_install(tmp_path, rt)
    assert first.returncode == 0 and second.returncode == 0, first.stderr + second.stderr
    a, b = venv_of(out1), venv_of(out2)
    assert a != b and a.parent.parent == rt == b.parent.parent
    assert a.parent.name.startswith("safo.") and len(a.parent.name) == len("safo.") + 10
    assert (a / "bin" / "python").exists()


def test_a_venv_pre_planted_at_the_old_fixed_path_is_never_executed(tmp_path: Path, workspace: Path) -> None:
    rt = tmp_path / "rt"
    marker = tmp_path / "PLANTED-RAN"
    site = rt / "safo-venv" / "lib" / "python3.13" / "site-packages"
    site.mkdir(parents=True)
    (site / "evil.pth").write_text(f"import pathlib; pathlib.Path({str(marker)!r}).write_text('ran')\n")
    (site / "sitecustomize.py").write_text(f"import pathlib; pathlib.Path({str(marker)!r}).write_text('ran')\n")
    done, out = run_install(tmp_path, rt)
    assert done.returncode == 0, done.stderr
    venv = venv_of(out)
    assert venv.name == "venv" and venv != rt / "safo-venv"
    for step_name, extra in (("Mask the credentials", {"PRIVATE_KEY": PEM}),):
        ran = run_step(step_name, workspace, venv, extra)
        assert ran.returncode == 0, ran.stderr
    assert not marker.exists() and (site / "evil.pth").exists()


def test_a_file_planted_in_the_new_venv_is_detected_and_nothing_is_published(tmp_path: Path) -> None:
    """A `python` that plants a sitecustomize into the venv it just made: the step refuses before running the venv."""
    marker = tmp_path / "PLANTED-RAN"
    wrap = tmp_path / "wrap"
    wrap.mkdir()
    real = sys.executable
    (wrap / "python").write_text(
        "#!/bin/bash\n"
        f'{real!r} "$@"; rc=$?\n'
        'if [ "$3" = "venv" ]; then\n'
        '  for d in "${@: -1}"/lib/python*/site-packages; do\n'
        f"    echo \"import pathlib; pathlib.Path('{marker}').write_text('ran')\" > \"$d/sitecustomize.py\"\n"
        "  done\n"
        "fi\n"
        "exit $rc\n"
    )
    (wrap / "python").chmod(0o755)
    done, out = run_install(tmp_path, tmp_path / "rt", path_prefix=f"{wrap}:")
    assert done.returncode != 0 and "sitecustomize.py" in done.stderr + done.stdout
    assert not marker.exists() and (not out.exists() or out.read_text() == "")
