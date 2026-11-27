# SPDX-License-Identifier: Apache-2.0
"""scripts/impacted-tests.py maps changed files to the tests to run, and falls back to the full suite when unsure."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "scripts" / "impacted-tests.py"
GUARDS = [
    "tests/test_docs.py",
    "tests/test_duplicate_keys.py",
    "tests/test_output.py",
    "tests/test_privacy.py",
    "tests/test_readme_links.py",
]


def run(root: Path, *args: str) -> tuple[int, list[str], str]:
    proc = subprocess.run(  # noqa: S603 - fixed interpreter and script path, fixture tree
        [sys.executable, "-I", str(SCRIPT), "--root", str(root), *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    return proc.returncode, proc.stdout.splitlines(), proc.stderr


def put(root: Path, rel: str, text: str = "") -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    for guard in GUARDS:
        put(tmp_path, guard, "def test_x() -> None: ...\n")
    put(tmp_path, "src/safo/__init__.py")
    put(tmp_path, "src/safo/errors.py", "class SafoError(Exception): ...\n")
    put(tmp_path, "src/safo/alpha.py", "from safo.errors import SafoError\n")
    put(tmp_path, "src/safo/beta.py")
    put(tmp_path, "src/safo/gamma.py", "from . import beta\n")
    put(tmp_path, "src/safo/orphan.py")
    put(tmp_path, "src/safo/pkg/__init__.py")
    put(tmp_path, "src/safo/pkg/deep.py")
    put(tmp_path, "tests/test_alpha.py", "import safo.alpha\n")
    put(tmp_path, "tests/test_alpha_more.py", "x = 1\n")
    put(tmp_path, "tests/test_uses_beta.py", "from safo import beta\n")
    put(tmp_path, "tests/test_uses_deep.py", "from safo.pkg.deep import thing\n")
    put(tmp_path, "tests/helper.py", "y = 1\n")
    put(tmp_path, "tests/test_uses_helper.py", "import helper\n")
    return tmp_path


def test_module_maps_by_name_and_import(tree: Path) -> None:
    code, out, _ = run(tree, "src/safo/alpha.py")
    assert code == 0
    assert "tests/test_alpha.py" in out
    assert "tests/test_alpha_more.py" in out
    assert "tests/test_uses_beta.py" not in out
    assert set(GUARDS) <= set(out)


def test_import_only_mapping(tree: Path) -> None:
    code, out, _ = run(tree, "src/safo/beta.py")
    assert code == 0
    assert "tests/test_uses_beta.py" in out


def test_from_import_of_submodule_member(tree: Path) -> None:
    code, out, _ = run(tree, "src/safo/pkg/deep.py")
    assert code == 0
    assert "tests/test_uses_deep.py" in out


def test_transitive_importers(tree: Path) -> None:
    code, out, _ = run(tree, "src/safo/errors.py")
    assert code == 0
    assert "tests/test_alpha.py" in out  # alpha imports errors, the test imports alpha


def test_changed_test_runs_itself_and_helper_maps_to_importers(tree: Path) -> None:
    code, out, _ = run(tree, "tests/test_alpha_more.py")
    assert code == 0
    assert "tests/test_alpha_more.py" in out
    code, out, _ = run(tree, "tests/helper.py")
    assert code == 0
    assert "tests/test_uses_helper.py" in out


def test_docs_only_runs_the_guards_alone(tree: Path) -> None:
    code, out, _ = run(tree, "docs/new.md", "README.md", "CHANGELOG.md")
    assert code == 0
    assert out == sorted(GUARDS)


@pytest.mark.parametrize(
    "changed",
    ["src/safo/orphan.py", "pyproject.toml", ".github/workflows/ci.yml", "agents.yaml", "src/safo/data.json"],
)
def test_unmapped_or_config_falls_back_to_all(tree: Path, changed: str) -> None:
    put(tree, changed, "x")
    code, out, err = run(tree, changed)
    assert code == 3
    assert out == ["ALL"]
    assert len(err.strip().splitlines()) == 1


def test_one_unmapped_file_makes_the_whole_run_all(tree: Path) -> None:
    code, out, _ = run(tree, "src/safo/alpha.py", "src/safo/orphan.py")
    assert code == 3
    assert out == ["ALL"]


def test_unparseable_test_file_falls_back_to_all(tree: Path) -> None:
    put(tree, "tests/test_broken.py", "def (:\n")
    code, out, _ = run(tree, "src/safo/alpha.py")
    assert code == 3
    assert out == ["ALL"]


def test_missing_guard_falls_back_to_all(tree: Path) -> None:
    (tree / "tests/test_privacy.py").unlink()
    code, out, _ = run(tree, "docs/x.md")
    assert code == 3
    assert out == ["ALL"]


@pytest.mark.parametrize("bad", ["/etc/passwd", "../x.py", "src/safo/a\nb.py", "src/safo/\x1b[31m.py", ""])
def test_hostile_paths_are_usage_errors(tree: Path, bad: str) -> None:
    code, out, err = run(tree, bad)
    assert code == 2
    assert out == []
    assert "\x1b" not in err
    assert err.count("\n") <= 1


def test_no_arguments_is_usage(tree: Path) -> None:
    assert run(tree)[0] == 2
    assert run(tree, "--base", "-evil")[0] == 2


def test_output_is_bounded(tree: Path) -> None:
    for i in range(700):
        put(tree, f"tests/test_many{i}.py", "import safo.beta\n")
    code, out, _ = run(tree, "src/safo/beta.py")
    assert code == 3
    assert out == ["ALL"]


def test_never_executes_repo_code(tree: Path) -> None:
    marker = tree / "ran"
    put(tree, "tests/test_evil.py", f"import safo.beta\nopen({str(marker)!r}, 'w').close()\n")
    put(tree, "src/safo/beta.py", f"open({str(marker)!r}, 'w').close()\n")
    code, out, _ = run(tree, "src/safo/beta.py")
    assert code == 0
    assert "tests/test_evil.py" in out
    assert not marker.exists()


def test_base_uses_git_diff(tree: Path) -> None:
    def git(*a: str) -> None:
        subprocess.run(  # noqa: S603, S607 - fixed git arguments in a fixture repo
            ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-C", str(tree), *a],
            check=True,
            capture_output=True,
        )

    git("init", "-q")
    git("add", ".")
    git("commit", "-q", "-m", "base")
    put(tree, "src/safo/beta.py", "z = 1\n")
    code, out, _ = run(tree, "--base", "HEAD")
    assert code == 0
    assert "tests/test_uses_beta.py" in out


def test_the_guard_list_matches_real_files() -> None:
    root = Path(__file__).parent.parent
    assert GUARDS
    assert all((root / g).is_file() for g in GUARDS)
    text = SCRIPT.read_text(encoding="utf-8")
    assert all(g in text for g in GUARDS)
