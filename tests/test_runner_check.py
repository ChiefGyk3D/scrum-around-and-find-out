# SPDX-License-Identifier: Apache-2.0
"""safo-runner-check: classify full-suite and mutation commands and print the ra-remote form (#485). No network."""

from __future__ import annotations

import io
import json
import subprocess
from pathlib import Path

import pytest

from safo import runner_check as rc

PUBLIC = {"SAFO_PUBLIC_OWNERS": "ChiefGyk3D,Renegade-Penguin"}


def _git(path: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True)  # noqa: S603, S607 - test fixture


def make_repo(tmp_path: Path, remote: str | None, name: str = "repo") -> Path:
    repo = tmp_path / name
    repo.mkdir()
    _git(repo, "init", "-q")
    if remote:
        _git(repo, "remote", "add", "origin", remote)
    return repo


def env_for(tmp_path: Path, **extra: str) -> dict[str, str]:
    return {"HOME": str(tmp_path / "home"), "XDG_STATE_HOME": str(tmp_path / "state"), **extra}


def run(argv: list[str], env: dict[str, str], stdin: str = "") -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = rc.main(argv, env=env, out=out, err=err, stdin=io.StringIO(stdin))
    return code, out.getvalue(), err.getvalue()


@pytest.mark.parametrize(
    ("command", "klass"),
    [
        ("pytest", "full-suite"),
        ("python -m pytest -q", "full-suite"),
        ("pytest tests/", "full-suite"),
        ("uv run pytest .", "full-suite"),
        ("mutmut run", "mutation"),
        ("cosmic-ray exec session.sqlite", "mutation"),
        ("npx stryker run", "mutation"),
        ("vitest run", "full-suite"),
        ("npm test", "full-suite"),
        ("npm run test", "full-suite"),
        ("make check", "full-suite"),
        ("cd x && FOO=1 pytest -q", "full-suite"),
    ],
)
def test_flags_full_runs(command: str, klass: str) -> None:
    found = rc.classify(command)
    assert [f.klass for f in found] == [klass]


@pytest.mark.parametrize(
    "command",
    [
        "pytest tests/test_a.py",
        "pytest tests/test_a.py::test_b",
        "pytest -k parser",
        "pytest --lf",
        "vitest run src/a.test.ts",
        "ruff check src",
        "git status",
        "echo pytest",
    ],
)
def test_targeted_or_unrelated_not_flagged(command: str) -> None:
    assert rc.classify(command) == []


def test_wrapped_is_remote_not_flagged() -> None:
    found = rc.classify("ra-remote --plan /w -- pytest")
    assert [(f.klass, f.wrapped) for f in found] == [("full-suite", True)]


def test_compound_command_splits() -> None:
    found = rc.classify("pytest tests/a.py && mutmut run; npm test")
    assert [f.klass for f in found] == ["mutation", "full-suite"]


def test_owner_parsing() -> None:
    assert rc.remote_owner("git@github.com:ChiefGyk3D/x.git") == "chiefgyk3d"
    assert rc.remote_owner("https://github.com/Renegade-Penguin/x") == "renegade-penguin"
    assert rc.remote_owner("/some/local/path") is None


def test_public_repo_suggests_ra_remote_with_plan(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, "https://github.com/ChiefGyk3D/demo.git")
    code, out, _ = run(["--repo", str(repo), "--command", "pytest -q"], env_for(tmp_path, **PUBLIC))
    assert code == 0
    assert "repo: public" in out
    assert f"ra-remote --plan {repo} -- pytest -q" in out
    assert f"ra-remote {repo} -- pytest -q" in out
    assert "reach-around-dev" in out


def test_strict_exits_nonzero_on_public_local_full(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, "https://github.com/ChiefGyk3D/demo.git")
    code, _, _ = run(["--strict", "--repo", str(repo), "--command", "npm test"], env_for(tmp_path, **PUBLIC))
    assert code == 1


def test_strict_passes_when_wrapped(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, "https://github.com/ChiefGyk3D/demo.git")
    cmd = "ra-remote /w -- pytest"
    code, out, _ = run(["--strict", "--repo", str(repo), "--command", cmd], env_for(tmp_path, **PUBLIC))
    assert code == 0
    assert "already runs through ra-remote" in out


def test_strict_passes_when_targeted(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, "https://github.com/ChiefGyk3D/demo.git")
    code, _, _ = run(["--strict", "--repo", str(repo), "--command", "pytest tests/a.py"], env_for(tmp_path, **PUBLIC))
    assert code == 0


def test_unlisted_owner_looks_private_never_recommended(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, "git@github.com:SomeoneElse/secret.git")
    code, out, _ = run(["--strict", "--repo", str(repo), "--command", "mutmut run"], env_for(tmp_path, **PUBLIC))
    assert code == 0  # a private repo must run local; that is not a violation
    assert "looks private" in out
    assert "keep local" in out
    assert "ra-remote --plan" not in out


def test_no_owner_list_cannot_tell(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, "https://github.com/ChiefGyk3D/demo.git")
    code, out, _ = run(["--strict", "--repo", str(repo), "--command", "pytest"], env_for(tmp_path))
    assert code == 0
    assert "cannot tell: keep local" in out
    assert "ra-remote --plan" not in out


def test_no_remote_cannot_tell(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, None)
    _, out, _ = run(["--repo", str(repo), "--command", "pytest"], env_for(tmp_path, **PUBLIC))
    assert "cannot tell: keep local" in out


def test_owner_list_from_config_file(tmp_path: Path) -> None:
    cfg = tmp_path / "xdgc" / "safo"
    cfg.mkdir(parents=True)
    (cfg / "public-owners").write_text("# owners\nChiefGyk3D\n", encoding="utf-8")
    repo = make_repo(tmp_path, "https://github.com/ChiefGyk3D/demo.git")
    env = env_for(tmp_path, XDG_CONFIG_HOME=str(tmp_path / "xdgc"))
    _, out, _ = run(["--repo", str(repo), "--command", "pytest"], env)
    assert "repo: public" in out


def test_brief_text_commands_extracted(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, "https://github.com/ChiefGyk3D/demo.git")
    brief = "Run `pytest -q` at the end.\n```\nmutmut run\npytest tests/a.py\n```\n$ npm test\nprose pytest is great\n"
    code, out, _ = run(["--strict", "--repo", str(repo), "--brief", "-"], env_for(tmp_path, **PUBLIC), stdin=brief)
    assert code == 1
    assert out.count("-> ra-remote --plan") == 3


def test_metrics_line_has_no_command_content(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, "https://github.com/ChiefGyk3D/demo.git")
    env = env_for(tmp_path, **PUBLIC)
    run(["--repo", str(repo), "--command", "FOO=topsecret pytest"], env)
    run(["--repo", str(repo), "--command", "pytest tests/a.py"], env)
    lines = (tmp_path / "state" / "safo" / "runner-check.jsonl").read_text(encoding="utf-8").splitlines()
    rows = [json.loads(x) for x in lines]
    assert [(r["class"], r["decision"], r["repo_class"]) for r in rows] == [
        ("full-suite", "suggest-remote", "public"),
        ("none", "ok-targeted", "public"),
    ]
    assert all(set(r) == {"ts", "class", "decision", "repo_class"} for r in rows)
    assert "topsecret" not in "".join(lines)


def test_metrics_failure_does_not_break_check(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, None)
    blocker = tmp_path / "state"
    blocker.write_text("not a dir", encoding="utf-8")
    code, _, err = run(["--repo", str(repo), "--command", "pytest"], env_for(tmp_path))
    assert code == 0
    assert "metrics not written" in err


def test_requires_one_input(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        run(["--repo", str(tmp_path)], env_for(tmp_path))
