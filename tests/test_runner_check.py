# SPDX-License-Identifier: Apache-2.0
"""safo-runner-check: classify full-suite and mutation commands and print the ra-remote form (#485). No network."""

from __future__ import annotations

import io
import json
import os
import shlex
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from safo import runner_check as rc

PUBLIC = {"SAFO_PUBLIC_OWNERS": "ChiefGyk3D,Renegade-Penguin"}


def _git(path: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True)  # noqa: S603, S607 - test fixture


def _git_out(path: Path, *args: str, check: bool = True) -> bytes:
    argv = ["git", "-C", str(path), *args]
    done = subprocess.run(argv, check=check, capture_output=True)  # noqa: S603 - test fixture, fixed git argv
    return done.stdout


def make_repo(
    tmp_path: Path,
    remote: str | None,
    name: str = "repo",
    *,
    dev: bool = True,
    extra: tuple[tuple[str, str], ...] = (),
    fetched: bool = True,
) -> Path:
    base = tmp_path / "home" / ".local" / "share" / "reach-around-dev" if dev else tmp_path / "elsewhere"
    base.mkdir(parents=True, exist_ok=True)
    repo = base / name
    repo.mkdir()
    _git(repo, "init", "-q")
    if remote:
        _git(repo, "remote", "add", "origin", remote)
    for rname, url in extra:
        _git(repo, "remote", "add", rname, url)
    if fetched and remote:  # a published (fetched) empty root commit, so HEAD exists and is on a remote ref
        ident = ("-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false")
        _git(repo, *ident, "commit", "-q", "--allow-empty", "-m", "root")
        _git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
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


# ---- fix round (#485): fail closed on repo class, faithful command ----------------------------------------------


def verdict(tmp_path: Path, repo: Path, **extra: str) -> str:
    _, out, _ = run(["--repo", str(repo), "--command", "pytest -q"], env_for(tmp_path, **{**PUBLIC, **extra}))
    return out


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/ChiefGyk3D/reach-around-instance.git",
        "git@github.com:ChiefGyk3D/reach-around-instance.git",
        "ssh://git@github.com/ChiefGyk3D/reach-around-instance.git",
        "https://github.com/ChiefGyk3D/chiefgyk3d-brand",
        "https://github.com/ChiefGyk3D/dotfiles",
        "https://github.com/ChiefGyk3D/AI-Shit.git",
        "https://github.com/ChiefGyk3D/some-instance",
        "https://github.com/ChiefGyk3D/lead-notes",
        "https://github.com/ChiefGyk3D/homelab-identity",
    ],
)
def test_denylisted_name_under_public_owner_is_never_recommended(tmp_path: Path, url: str) -> None:
    out = verdict(tmp_path, make_repo(tmp_path, url))
    assert "looks private" in out
    assert "denylist match" in out
    assert "ra-remote" not in out


def test_denylist_beats_allowlist(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, "https://github.com/ChiefGyk3D/dotfiles")
    out = verdict(tmp_path, repo, SAFO_PUBLIC_REPOS="chiefgyk3d/dotfiles")
    assert "denylist match" in out
    assert "ra-remote" not in out


def test_denylist_file_extends_builtin(tmp_path: Path) -> None:
    cfg = tmp_path / "xdgc" / "safo"
    cfg.mkdir(parents=True)
    (cfg / "runner-never").write_text("# mine\nweird-*\n", encoding="utf-8")
    repo = make_repo(tmp_path, "https://github.com/ChiefGyk3D/weird-thing")
    out = verdict(tmp_path, repo, XDG_CONFIG_HOME=str(tmp_path / "xdgc"))
    assert "denylist match" in out
    assert "ra-remote" not in out


def test_unsafe_denylist_file_fails_closed(tmp_path: Path) -> None:
    cfg = tmp_path / "xdgc" / "safo"
    cfg.mkdir(parents=True)
    bad = cfg / "runner-never"
    bad.write_text("x\n", encoding="utf-8")
    bad.chmod(0o666)
    out = verdict(
        tmp_path, make_repo(tmp_path, "https://github.com/ChiefGyk3D/demo"), XDG_CONFIG_HOME=str(tmp_path / "xdgc")
    )
    assert "cannot tell: keep local" in out
    assert "not owner-only" in out
    assert "ra-remote" not in out


def test_clean_public_repo_names_the_deciding_rule(tmp_path: Path) -> None:
    out = verdict(tmp_path, make_repo(tmp_path, "https://github.com/ChiefGyk3D/demo"))
    assert "public: owner listed, no denylist match" in out
    assert "ra-remote --plan" in out


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.com/ChiefGyk3D/demo",
        "https://evil.com/github.com/ChiefGyk3D/demo",
        "git@evil.com:ChiefGyk3D/demo.git",
        "ssh://git@evil.com/ChiefGyk3D/demo.git",
        "https://github.com.evil.com/ChiefGyk3D/demo",
        "https://github.com@evil.com/ChiefGyk3D/demo",
        "http://github.com/ChiefGyk3D/demo",
        "/some/local/path/ChiefGyk3D/demo",
    ],
)
def test_host_must_be_github(tmp_path: Path, url: str) -> None:
    out = verdict(tmp_path, make_repo(tmp_path, url))
    assert "cannot tell: keep local" in out
    assert "ra-remote" not in out


def test_parse_remote_forms_and_no_credentials() -> None:
    assert rc.parse_remote("https://user:tok3n@github.com/Own/Name.git") == ("own", "name")
    assert rc.parse_remote("ssh://git@github.com:22/Own/Name") == ("own", "name")
    assert rc.parse_remote("git@github.com:Own/Name.git") == ("own", "name")
    assert rc.parse_remote("https://github.com/Own/Name/extra") is None
    assert rc.parse_remote("https://github.com/Own") is None


def test_credentials_in_remote_never_echoed(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, "https://user:tok3n@github.com/ChiefGyk3D/demo.git")
    code, out, err = run(["--repo", str(repo), "--command", "pytest"], env_for(tmp_path, **PUBLIC))
    assert code == 0
    assert "tok3n" not in out + err


def test_second_remote_with_other_owner_blocks(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path, "https://github.com/ChiefGyk3D/demo", extra=(("up", "https://github.com/SomeoneElse/demo"),)
    )
    out = verdict(tmp_path, repo)
    assert "looks private" in out
    assert "ra-remote" not in out


def test_second_remote_unparseable_or_denied_blocks(tmp_path: Path) -> None:
    odd = make_repo(tmp_path, "https://github.com/ChiefGyk3D/demo", "odd", extra=(("x", "https://evil.com/a/b"),))
    assert "cannot tell" in verdict(tmp_path, odd)
    deny = make_repo(
        tmp_path,
        "https://github.com/ChiefGyk3D/demo",
        "deny",
        extra=(("x", "https://github.com/ChiefGyk3D/dotfiles"),),
    )
    out = verdict(tmp_path, deny)
    assert "denylist match" in out
    assert "ra-remote" not in out


def test_allowlist_mode_requires_listing(tmp_path: Path) -> None:
    listed = make_repo(tmp_path, "https://github.com/ChiefGyk3D/demo", "a")
    other = make_repo(tmp_path, "https://github.com/ChiefGyk3D/other", "b")
    out_ok = verdict(tmp_path, listed, SAFO_PUBLIC_REPOS="ChiefGyk3D/demo")
    assert "listed in the repo allowlist, no denylist match" in out_ok
    out_no = verdict(tmp_path, other, SAFO_PUBLIC_REPOS="ChiefGyk3D/demo")
    assert "not in the repo allowlist" in out_no
    assert "ra-remote" not in out_no


def test_allowlist_file_and_all_remotes(tmp_path: Path) -> None:
    cfg = tmp_path / "xdgc" / "safo"
    cfg.mkdir(parents=True)
    (cfg / "public-repos").write_text("chiefgyk3d/demo\n", encoding="utf-8")
    xdg = {"XDG_CONFIG_HOME": str(tmp_path / "xdgc")}
    ok = make_repo(tmp_path, "https://github.com/ChiefGyk3D/demo", "ok")
    assert "listed in the repo allowlist" in verdict(tmp_path, ok, **xdg)
    two = make_repo(
        tmp_path, "https://github.com/ChiefGyk3D/demo", "two", extra=(("x", "https://github.com/ChiefGyk3D/zzz"),)
    )
    assert "ra-remote" not in verdict(tmp_path, two, **xdg)


def test_worktree_outside_dev_folders_gets_no_command(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, "https://github.com/ChiefGyk3D/demo", dev=False)
    code, out, _ = run(["--strict", "--repo", str(repo), "--command", "pytest"], env_for(tmp_path, **PUBLIC))
    assert code == 0
    assert "keep local: the worktree is outside the runner's allowed folders" in out
    assert "reach-around-dev" in out
    assert "ra-remote --plan" not in out


def test_symlinked_worktree_resolving_outside_is_refused(tmp_path: Path) -> None:
    real = make_repo(tmp_path, "https://github.com/ChiefGyk3D/demo", dev=False)
    link = tmp_path / "home" / ".local" / "share" / "reach-around-dev" / "link"
    link.parent.mkdir(parents=True)
    link.symlink_to(real)
    _, out, _ = run(["--repo", str(link), "--command", "pytest"], env_for(tmp_path, **PUBLIC))
    assert "keep local: the worktree is outside" in out
    assert "ra-remote --plan" not in out


def test_worktree_gate_is_a_path_check_not_a_substring(tmp_path: Path) -> None:
    sneaky = tmp_path / "home" / "reach-around-dev-copy" / "repo"
    sneaky.mkdir(parents=True)
    env = {"HOME": str(tmp_path / "home")}
    assert not rc.worktree_allowed(sneaky, env)
    root = tmp_path / "home" / ".local" / "share" / "reach-around-dev"
    (root / "w").mkdir(parents=True)
    assert rc.worktree_allowed(root / "w", env)
    assert not rc.worktree_allowed(root, env)  # strictly below, as ra-remote requires
    for folder in ("safo-dev/agents", "chatty-kathy-dev"):
        sub = tmp_path / "home" / ".local" / "share" / folder / "w"
        sub.mkdir(parents=True)
        assert rc.worktree_allowed(sub, env)
    other = tmp_path / "home" / ".local" / "share" / "safo-dev" / "wt-1"
    other.mkdir(parents=True)
    assert not rc.worktree_allowed(other, env)


@pytest.mark.parametrize(
    "command",
    [
        "pip install pytest",
        "which pytest",
        "pytest --version",
        "pytest --help",
        "pytest --collect-only",
        "ssh host pytest",
        "echo pytest",
        "grep pytest file",
        "pytest --deselect tests/a.py::t tests/a.py",  # an explicit file target stays targeted
        "go test -run TestX ./...",
        "cargo test parser",
        "mvn test -Dtest=FooTest",
        "gradle test --tests Foo",
        "python -m unittest tests.test_a",
        "tox --version",
        "make build",
        "npm run build",
    ],
)
def test_not_full_suite(command: str) -> None:
    assert rc.classify(command) == []


@pytest.mark.parametrize(
    "command",
    [
        "pytest --deselect tests/a.py::t",
        "pytest --ignore tests/a.py",
        "pytest --ignore-glob=x --junitxml out/r.xml",
        "pytest -p plugin.py --rootdir src",
        "pytest --cov src -c cfg.py -o addopts=x",
        "pytest --confcutdir tests/conftest.py",
        "time pytest",
        "timeout 600 pytest -q",
        "nice -n 5 pytest",
        "env FOO=1 pytest",
        "uv run --with x pytest",
        "poetry run pytest",
        "python3 -m pytest",
        "tox",
        "nox -s tests",
        "make test",
        "make check",
        "npm run test",
        "npm run test:unit",
        "pnpm run test:unit",
        "bash -lc 'pytest -q'",
        'sh -c "pytest"',
        "(pytest)",
        "$(pytest)",
        "echo $(pytest)",
        "xargs pytest",
        "find . | xargs pytest",
        "python -m unittest",
        "python -m unittest discover -s tests",
        "go test ./...",
        "cargo test",
        "cargo test -- --nocapture",
        "mvn test",
        "gradle test",
        "./gradlew test",
        "npx vitest run",
    ],
)
def test_full_suite_forms(command: str) -> None:
    assert [f.klass for f in rc.classify(command)] == ["full-suite"]


def test_directory_and_node_id_targets() -> None:
    assert rc.classify("pytest tests/") != []
    assert rc.classify("pytest tests") != []
    assert rc.classify("pytest tests/test_a.py") == []
    assert rc.classify("pytest tests/a.py::T::t") == []
    assert rc.classify("pytest -k parser --deselect tests/x.py::y") == []


def test_simple_line_prints_faithful_env_form(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, "https://github.com/ChiefGyk3D/demo")
    _, out, _ = run(["--repo", str(repo), "--command", "FOO='a b' pytest -q"], env_for(tmp_path, **PUBLIC))
    assert f"-> ra-remote {repo} -- env 'FOO=a b' pytest -q" in out
    assert f"-> ra-remote --plan {repo} -- env 'FOO=a b' pytest -q" in out


@pytest.mark.parametrize(
    "command",
    [
        "cd x && pytest",
        "pytest > out.txt",
        "pytest | tee log",
        "(pytest)",
        "echo $(pytest)",
        "pytest; ruff check",
        "FOO=$HOME pytest",
        "pytest `x`",
    ],
)
def test_complex_line_gets_advice_only(tmp_path: Path, command: str) -> None:
    repo = make_repo(tmp_path, "https://github.com/ChiefGyk3D/demo")
    _, out, _ = run(["--repo", str(repo), "--command", command], env_for(tmp_path, **PUBLIC))
    assert f"run this through ra-remote: ra-remote --plan {repo} -- <the suite command alone>" in out
    assert f"-> ra-remote {repo} --" not in out
    assert f"-> ra-remote --plan {repo} -- pytest" not in out


def test_path_with_space_is_quoted(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, "https://github.com/ChiefGyk3D/demo", "my repo")
    _, out, _ = run(["--repo", str(repo), "--command", "pytest 'a b'"], env_for(tmp_path, **PUBLIC))
    assert f"-> ra-remote {shlex.quote(str(repo))} -- pytest 'a b'" in out


def test_state_dir_and_file_modes(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, None)
    state = tmp_path / "state" / "safo"
    state.mkdir(parents=True)
    state.chmod(0o755)
    log = state / "runner-check.jsonl"
    log.write_text("", encoding="utf-8")
    log.chmod(0o644)
    run(["--repo", str(repo), "--command", "pytest"], env_for(tmp_path))
    assert state.stat().st_mode & 0o777 == 0o700
    assert log.stat().st_mode & 0o777 == 0o600


def test_state_dir_created_private(tmp_path: Path) -> None:
    run(["--repo", str(make_repo(tmp_path, None)), "--command", "pytest"], env_for(tmp_path))
    assert (tmp_path / "state" / "safo").stat().st_mode & 0o777 == 0o700


def test_state_symlink_not_followed(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "safo").symlink_to(target)
    _, _, err = run(["--repo", str(make_repo(tmp_path, None)), "--command", "pytest"], env_for(tmp_path))
    assert "metrics not written" in err
    assert list(target.iterdir()) == []


def test_module_entry_point(tmp_path: Path) -> None:
    src = Path(rc.__file__).resolve().parents[1]
    done = subprocess.run(  # noqa: S603 - test fixture, fixed argv
        [sys.executable, "-m", "safo.runner_check", "--repo", str(tmp_path), "--command", "git status"],
        capture_output=True,
        text=True,
        check=False,
        env={"PYTHONPATH": str(src), "HOME": str(tmp_path / "home"), "XDG_STATE_HOME": str(tmp_path / "st")},
    )
    assert done.returncode == 0
    assert "no local full suite" in done.stdout


# ---- fix round 2 (#485): content gate, transport overrides, wrappers, allowlist, ancestry, names -------------------

REPO_URL = "https://github.com/ChiefGyk3D/demo"
PUBLIC_REPO_ENV = {"SAFO_PUBLIC_REPOS": "ChiefGyk3D/demo"}


def commit_all(repo: Path, *, publish: bool = True) -> None:
    """Commit everything; by default also record it as fetched (refs/remotes/origin/main), i.e. published."""
    _git(repo, "add", "-A")
    _git(
        repo,
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@example.com",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-qm",
        "x",
    )
    if publish:
        _git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")


def clean_repo(tmp_path: Path, name: str = "repo") -> Path:
    repo = make_repo(tmp_path, REPO_URL, name)
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    commit_all(repo)
    return repo


def strict(tmp_path: Path, repo: Path, command: str = "pytest", **extra: str) -> tuple[int, str]:
    code, out, _ = run(
        ["--strict", "--repo", str(repo), "--command", command], env_for(tmp_path, **{**PUBLIC, **extra})
    )
    return code, out


def assert_kept_local(code: int, out: str) -> None:
    assert code == 0  # keep-local is not a violation
    assert "keep local: the worktree holds files the runner would copy" in out
    assert "ra-remote" not in out


def test_clean_public_repo_still_gets_the_command(tmp_path: Path) -> None:
    code, out = strict(tmp_path, clean_repo(tmp_path))
    assert code == 1
    assert "-> ra-remote --plan" in out


def test_gitignored_files_are_not_a_content_problem(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, REPO_URL)
    (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    commit_all(repo)
    (repo / ".env").write_text("TOKEN=x\n", encoding="utf-8")  # ignored: ra-remote never copies it
    code, out = strict(tmp_path, repo)
    assert code == 1
    assert "-> ra-remote --plan" in out


def test_untracked_file_keeps_local_and_prints_counts_only(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    (repo / "private-plan.txt").write_text("x\n", encoding="utf-8")
    code, out = strict(tmp_path, repo)
    assert_kept_local(code, out)
    assert "(1 untracked files; 0 nested git directories; 0 symlinks leaving the tree)" in out
    assert "private-plan" not in out
    assert "clone a clean copy under" in out


def test_untracked_env_file_reviewer_reproduction(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, REPO_URL)
    (repo / ".env").write_text("TOKEN=private\n", encoding="utf-8")
    code, out = strict(tmp_path, repo)
    assert_kept_local(code, out)
    assert ".env" not in out
    assert "TOKEN" not in out


def test_untracked_nested_repo_reviewer_reproduction(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    nested = repo / "vendor"
    nested.mkdir()
    _git(nested, "init", "-q")
    _git(nested, "remote", "add", "origin", "git@github.com:private-owner/secret.git")
    (nested / "secret.txt").write_text("private material\n", encoding="utf-8")
    code, out = strict(tmp_path, repo)
    assert_kept_local(code, out)
    assert "1 nested git directories" in out
    assert "private-owner" not in out
    assert "vendor" not in out


def test_tracked_nested_git_directory_alone_is_refused(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    nested = repo / "vendor"
    nested.mkdir()
    _git(nested, "init", "-q")
    (nested / "m.py").write_text("y = 1\n", encoding="utf-8")
    commit_all(nested)
    commit_all(repo)  # a tracked gitlink: no untracked file, nothing secret-looking
    code, out = strict(tmp_path, repo)
    assert_kept_local(code, out)
    assert "(0 untracked files; 1 nested git directories; 0 symlinks leaving the tree)" in out


def test_tracked_symlink_leaving_the_tree_is_refused(tmp_path: Path) -> None:
    outside = tmp_path / "outside-dir"
    outside.mkdir()
    repo = clean_repo(tmp_path)
    (repo / "link").symlink_to(outside)
    commit_all(repo)
    code, out = strict(tmp_path, repo)
    assert_kept_local(code, out)
    assert "(0 untracked files; 0 nested git directories; 1 symlinks leaving the tree)" in out
    assert "outside-dir" not in out


def test_untracked_symlink_to_outside_is_refused(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    (repo / "notes-link").symlink_to(tmp_path)
    code, out = strict(tmp_path, repo)
    assert_kept_local(code, out)
    assert "1 symlinks leaving the tree" in out


def test_tracked_symlink_inside_the_tree_is_fine(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    (repo / "alias.py").symlink_to("a.py")
    commit_all(repo)
    code, out = strict(tmp_path, repo)
    assert code == 1
    assert "-> ra-remote --plan" in out


@pytest.mark.parametrize(
    "name",
    [
        ".env",
        ".env.production",
        "server.pem",
        "tls.key",
        "id_rsa",
        "id_ed25519.pub",
        "store.p12",
        "store.pfx",
        "vault.kdbx",
        ".netrc",
        "credentials.json",
        "my-secret-notes.txt",
    ],
)
def test_tracked_secret_looking_names_are_refused(tmp_path: Path, name: str) -> None:
    repo = clean_repo(tmp_path)
    (repo / name).write_text("x\n", encoding="utf-8")
    commit_all(repo)
    code, out = strict(tmp_path, repo)
    assert_kept_local(code, out)
    assert "secret-looking file names present" in out
    assert "(0 untracked files; 0 nested git directories; 0 symlinks leaving the tree)" in out
    assert name not in out


def test_secret_looking_directory_name_is_refused(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    (repo / "mysecrets").mkdir()
    (repo / "mysecrets" / "a.txt").write_text("x\n", encoding="utf-8")
    commit_all(repo)
    _, out = strict(tmp_path, repo)
    assert "secret-looking file names present" in out


def test_walk_bound_is_enforced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = clean_repo(tmp_path)
    for i in range(6):
        (repo / f"f{i}.py").write_text("x\n", encoding="utf-8")
    commit_all(repo)
    monkeypatch.setattr(rc, "WALK_LIMIT", 3)
    code, out = strict(tmp_path, repo)
    assert_kept_local(code, out)
    assert "could not be fully checked" in out


def test_content_gate_runs_only_for_suggestions(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    (repo / "x.txt").write_text("x\n", encoding="utf-8")
    code, out = strict(tmp_path, repo, "pytest tests/a.py")
    assert code == 0
    assert "no local full suite" in out


def test_keep_local_content_is_recorded_without_names(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    (repo / "x.txt").write_text("x\n", encoding="utf-8")
    strict(tmp_path, repo)
    rows = (tmp_path / "state" / "safo" / "runner-check.jsonl").read_text(encoding="utf-8")
    assert "keep-local-content" in rows
    assert "x.txt" not in rows


# ---- F2: git transport overrides ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("config", "shown"),
    [
        (("core.sshCommand", "evil-value"), "core.sshcommand"),
        (("core.gitProxy", "evil-value"), "core.gitproxy"),
        (("remote.origin.vcs", "evil-value"), "remote.*.vcs"),
        (("remote.origin.proxy", "evil-value"), "remote.*.proxy"),
        (("remote.origin.pushurl", "https://github.com/ChiefGyk3D/demo"), "remote.*.pushurl"),
        (("url.https://evil-value/.insteadOf", "https://zzz/"), "url.*.insteadof"),
        (("url.https://evil-value/.pushInsteadOf", "https://zzz/"), "url.*.pushinsteadof"),
        (("includeIf.gitdir:/evil-value/.path", "x.cfg"), "includeIf gitdir"),
    ],
)
def test_config_transport_override_is_cannot_tell(tmp_path: Path, config: tuple[str, str], shown: str) -> None:
    repo = clean_repo(tmp_path)
    _git(repo, "config", config[0], config[1])
    code, out = strict(tmp_path, repo)
    assert code == 0
    assert f"cannot tell: keep local (git transport is overridden (setting {shown}))" in out
    assert "evil-value" not in out
    assert "ra-remote" not in out


@pytest.mark.parametrize("var", ["GIT_SSH", "GIT_SSH_COMMAND", "GIT_PROXY_COMMAND", "GIT_CONFIG_COUNT"])
def test_env_transport_override_is_cannot_tell(tmp_path: Path, var: str) -> None:
    repo = clean_repo(tmp_path)
    code, out = strict(tmp_path, repo, **{var: "evil-value"})
    assert code == 0
    assert f"git transport is overridden (setting {var.replace('GIT_CONFIG_COUNT', 'GIT_CONFIG_*')})" in out
    assert "evil-value" not in out
    assert "ra-remote" not in out


# ---- F3: wrappers and the fail-closed rule ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "command -- pytest",
        "nohup -- pytest",
        "exec -a x -- pytest",
        "env -i -- pytest",
        "time -p -- pytest",
        "timeout 60 -- pytest",
        "timeout -s KILL 60 -- pytest",
        "stdbuf -oL -- pytest",
        "taskset -c 0 -- pytest",
        "builtin -- pytest",
        "nice -n 5 -- pytest",
        "ionice -c 3 -- pytest",
        "setsid -- pytest",
        "chrt -f 10 pytest",
        "unbuffer -- pytest",
        "flock -n /tmp/l -- pytest",
        "xvfb-run -a -- pytest",
        "yarn run vitest",
        "pipenv run -- pytest",
        "sudo pytest",  # unknown head: fail closed
        "sudo mutmut run",
        "sudo make test",
        "somewrapper --flag jest",
    ],
)
def test_wrapper_end_of_options_does_not_hide_a_suite(command: str) -> None:
    assert rc.classify(command) != []


def test_strict_fails_for_the_reviewer_reproductions(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    for command in ("command -- pytest", "nohup -- pytest"):
        code, out = strict(tmp_path, repo, command)
        assert code == 1, out


@pytest.mark.parametrize(
    "command",
    [
        "pip install pytest",
        "pip3 install pytest",
        "uv pip install pytest",
        "which pytest",
        "man pytest",
        "type pytest",
        "command -v pytest",
        "printf pytest",
        "cat pytest",
        "less pytest",
        "ls pytest",
        "rg pytest src",
        "scp pytest host:",
        "git log pytest",
        "apt install pytest",
        "apt-get install pytest",
        "brew install pytest",
        "command -- which pytest",
        "pytest tests/a.py",
        "nohup -- pytest tests/a.py",
    ],
)
def test_known_non_runner_heads_stay_unflagged(command: str) -> None:
    assert rc.classify(command) == []


# ---- F4: an empty allowlist means no repo is public ---------------------------------------------------------------


def test_empty_allowlist_file_means_no_repo_is_public(tmp_path: Path) -> None:
    cfg = tmp_path / "xdgc" / "safo"
    cfg.mkdir(parents=True)
    (cfg / "public-repos").write_text("# nothing yet\n", encoding="utf-8")
    out = verdict(tmp_path, clean_repo(tmp_path), XDG_CONFIG_HOME=str(tmp_path / "xdgc"))
    assert "not in the repo allowlist" in out
    assert "ra-remote" not in out


def test_empty_allowlist_env_means_no_repo_is_public(tmp_path: Path) -> None:
    out = verdict(tmp_path, clean_repo(tmp_path), SAFO_PUBLIC_REPOS="")
    assert "not in the repo allowlist" in out
    assert "ra-remote" not in out


def test_unset_allowlist_still_falls_back_to_owner_trust(tmp_path: Path) -> None:
    assert "public: owner listed" in verdict(tmp_path, clean_repo(tmp_path))


# ---- F5: config ancestry and races --------------------------------------------------------------------------------


def _owners_cfg(base: Path) -> Path:
    cfg = base / "safo"
    cfg.mkdir(parents=True)
    cfg.chmod(0o700)
    (cfg / "public-owners").write_text("chiefgyk3d\n", encoding="utf-8")
    (cfg / "public-owners").chmod(0o600)
    return cfg


def _no_env_owners(tmp_path: Path, xdg: Path, repo: Path) -> str:
    env = env_for(tmp_path, XDG_CONFIG_HOME=str(xdg))
    _, out, _ = run(["--repo", str(repo), "--command", "pytest"], env)
    return out


def test_owner_only_config_is_accepted(tmp_path: Path) -> None:
    _owners_cfg(tmp_path / "xdgc")
    out = _no_env_owners(tmp_path, tmp_path / "xdgc", clean_repo(tmp_path))
    assert "public: owner listed" in out


def test_symlinked_xdg_config_home_is_refused(tmp_path: Path) -> None:
    _owners_cfg(tmp_path / "realcfg")
    (tmp_path / "cfg-link").symlink_to(tmp_path / "realcfg")
    out = _no_env_owners(tmp_path, tmp_path / "cfg-link", clean_repo(tmp_path))
    assert "not owner-only" in out
    assert "ra-remote" not in out


def test_symlinked_parent_of_the_xdg_folder_is_refused(tmp_path: Path) -> None:
    _owners_cfg(tmp_path / "real" / "cfg")
    (tmp_path / "link").symlink_to(tmp_path / "real")
    out = _no_env_owners(tmp_path, tmp_path / "link" / "cfg", clean_repo(tmp_path))
    assert "not owner-only" in out
    assert "ra-remote" not in out


def test_symlinked_safo_folder_is_refused(tmp_path: Path) -> None:
    real = _owners_cfg(tmp_path / "elsewhere")
    (tmp_path / "xdgc").mkdir()
    (tmp_path / "xdgc" / "safo").symlink_to(real)
    out = _no_env_owners(tmp_path, tmp_path / "xdgc", clean_repo(tmp_path))
    assert "not owner-only" in out


def test_group_writable_ancestor_below_home_is_refused(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    _owners_cfg(tmp_path / "home" / ".config")
    env = {"HOME": str(tmp_path / "home"), "XDG_STATE_HOME": str(tmp_path / "state")}
    _, ok, _ = run(["--repo", str(repo), "--command", "pytest"], env)
    assert "public: owner listed" in ok
    (tmp_path / "home" / ".config").chmod(0o777)
    _, out, _ = run(["--repo", str(repo), "--command", "pytest"], env)
    assert "not owner-only" in out
    assert "ra-remote" not in out


def test_config_file_swapped_between_check_and_open_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = _owners_cfg(tmp_path / "xdgc")
    target = cfg / "public-owners"
    real_open = os.open

    def swapping_open(path: Any, *args: Any, **kwargs: Any) -> int:
        if str(path) == str(target):
            target.unlink()
            target.write_text("someone-else\n", encoding="utf-8")
            target.chmod(0o600)
        return real_open(path, *args, **kwargs)

    repo = clean_repo(tmp_path)
    monkeypatch.setattr(os, "open", swapping_open)
    out = _no_env_owners(tmp_path, tmp_path / "xdgc", repo)
    assert "not owner-only" in out
    assert "ra-remote" not in out


# ---- F6: repository name normalization ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/ChiefGyk3D/reach-around-instance.git.git",
        "https://github.com/ChiefGyk3D/reach-around-instance.GIT",
        "https://github.com/ChiefGyk3D/reach-around-instance.git.GIT.git",
        "https://github.com/ChiefGyk3D/reach-around-instance.",
        "https://github.com/ChiefGyk3D/reach-around-instance/",
        "https://github.com/ChiefGyk3D/reach-around-instance.git/",
    ],
)
def test_denylisted_name_variants_are_still_denied(tmp_path: Path, url: str) -> None:
    out = verdict(tmp_path, make_repo(tmp_path, url))
    assert "denylist match" in out
    assert "ra-remote" not in out


def test_fullwidth_lookalike_is_cannot_tell(tmp_path: Path) -> None:
    lookalike = chr(0xFF52) + "each-around-instance"  # fullwidth r
    out = verdict(tmp_path, make_repo(tmp_path, f"https://github.com/ChiefGyk3D/{lookalike}"))
    assert "cannot tell: keep local" in out
    assert "ra-remote" not in out
    owner_look = verdict(tmp_path, make_repo(tmp_path, "https://github.com/" + chr(0xFF23) + "hiefGyk3D/demo", "o"))
    assert "cannot tell: keep local" in owner_look


def test_parse_remote_normalizes_names() -> None:
    assert rc.parse_remote("https://github.com/Own/Name.git.GIT/") == ("own", "name")
    assert rc.parse_remote("https://github.com/Own/Name.") == ("own", "name")
    assert rc.parse_remote("https://github.com/Own/N" + chr(0xFF41) + "me") is None


# ---- single worktree resolution point -----------------------------------------------------------------------------


def test_symlinked_worktree_is_resolved_once_in_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real = make_repo(tmp_path, REPO_URL, "real", dev=False)
    (real / "a.py").write_text("x\n", encoding="utf-8")
    commit_all(real)
    link = tmp_path / "home" / ".local" / "share" / "reach-around-dev" / "link"
    link.parent.mkdir(parents=True)
    link.symlink_to(real)
    original = rc._git

    def lying_git(repo: Path, env: Mapping[str, str], *args: str) -> str:
        if args[:2] == ("rev-parse", "--show-toplevel"):
            return str(link)  # as if git reported the symlinked path
        return original(repo, env, *args)

    monkeypatch.setattr(rc, "_git", lying_git)
    code, out, _ = run(["--strict", "--repo", str(link), "--command", "pytest"], env_for(tmp_path, **PUBLIC))
    assert code == 0
    assert "keep local: the worktree is outside" in out
    assert "ra-remote --plan" not in out


# ---- G1: modified tracked files and the content gate ---------------------------------------------------------------


def assert_differs(code: int, out: str) -> None:
    assert code == 0  # keep-local is not a violation
    assert "keep local: " in out
    assert "tracked files differ from the public commit" in out
    assert "commit or discard them first" in out
    assert "ra-remote" not in out
    assert "a.py" not in out  # counts only, never names


def test_modified_tracked_file_reviewer_reproduction(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, REPO_URL)
    (repo / "settings.txt").write_text("public placeholder\n", encoding="utf-8")
    commit_all(repo)
    (repo / "settings.txt").write_text("API_TOKEN=locally-added-private-value\n", encoding="utf-8")
    code, out = strict(tmp_path, repo)
    assert_differs(code, out)
    assert "settings.txt" not in out
    assert "API_TOKEN" not in out


def test_staged_change_is_refused(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    (repo / "a.py").write_text("x = 2\n", encoding="utf-8")
    _git(repo, "add", "a.py")
    _git(repo, "checkout", "-q", "--", "a.py")  # worktree matches HEAD again, only the index differs
    assert_differs(*strict(tmp_path, repo))


def test_intent_to_add_is_refused(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    (repo / "new.py").write_text("TOKEN = 'x'\n", encoding="utf-8")
    _git(repo, "add", "-N", "new.py")
    code, out = strict(tmp_path, repo)
    assert code == 0
    assert "ra-remote" not in out
    assert "tracked files differ" in out
    assert "new.py" not in out


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
def test_hidden_modifications_are_refused(tmp_path: Path, flag: str) -> None:
    repo = clean_repo(tmp_path)
    _git(repo, "update-index", flag, "a.py")
    (repo / "a.py").write_text("SECRET = 1\n", encoding="utf-8")  # git status shows nothing
    assert _git_out(repo, "status", "--porcelain") == b""
    assert_differs(*strict(tmp_path, repo))


def test_unmerged_index_is_refused(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    ident = ["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"]
    _git(repo, "checkout", "-q", "-b", "side")
    (repo / "a.py").write_text("x = 'side'\n", encoding="utf-8")
    _git(repo, *ident, "commit", "-qam", "side")
    _git(repo, "checkout", "-q", "-")
    (repo / "a.py").write_text("x = 'main'\n", encoding="utf-8")
    _git(repo, *ident, "commit", "-qam", "main")
    _git_out(repo, *ident, "merge", "side", check=False)  # the merge must conflict
    assert_differs(*strict(tmp_path, repo))


def test_tracked_files_without_a_head_commit_are_refused(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, REPO_URL)
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(repo, "add", "a.py")  # nothing committed: nothing proves these bytes are public
    code, out = strict(tmp_path, repo)
    assert code == 0
    assert "ra-remote" not in out


def test_clean_repo_is_not_flagged_as_modified(tmp_path: Path) -> None:
    code, out = strict(tmp_path, clean_repo(tmp_path))
    assert code == 1
    assert "differ" not in out
    assert "-> ra-remote --plan" in out


def test_modified_gate_failure_is_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = clean_repo(tmp_path)
    monkeypatch.setattr(rc, "_git_for_selection", lambda *a, **k: None)
    gate = rc.content_gate(repo, env_for(tmp_path))
    assert gate.refusal() is not None


# ---- G2: the checker sees the files ra-remote would copy ------------------------------------------------------------


def test_core_excludes_file_does_not_hide_a_file(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    ignore = tmp_path / "global-ignore"
    ignore.write_text("internal.txt\n", encoding="utf-8")
    _git(repo, "config", "core.excludesFile", str(ignore))
    (repo / "internal.txt").write_text("private\n", encoding="utf-8")
    assert_kept_local(*strict(tmp_path, repo))


def test_global_xdg_excludes_do_not_hide_a_file(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    xdg = tmp_path / "xdg"
    (xdg / "git").mkdir(parents=True)
    (xdg / "git" / "ignore").write_text("internal.txt\n", encoding="utf-8")
    (repo / "internal.txt").write_text("private\n", encoding="utf-8")
    assert_kept_local(*strict(tmp_path, repo, XDG_CONFIG_HOME=str(xdg)))


def test_global_gitconfig_excludes_do_not_hide_a_file(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    ignore = tmp_path / "global-ignore"
    ignore.write_text("internal.txt\n", encoding="utf-8")
    (tmp_path / "home" / ".gitconfig").write_text(f"[core]\n\texcludesFile = {ignore}\n", encoding="utf-8")
    (repo / "internal.txt").write_text("private\n", encoding="utf-8")
    assert_kept_local(*strict(tmp_path, repo))


def test_info_exclude_is_still_honored(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    (repo / ".git" / "info" / "exclude").write_text("internal.txt\n", encoding="utf-8")
    (repo / "internal.txt").write_text("private\n", encoding="utf-8")  # ra-remote skips it too
    code, out = strict(tmp_path, repo)
    assert code == 1
    assert "-> ra-remote --plan" in out


def test_selection_runs_with_the_ra_remote_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = clean_repo(tmp_path)
    calls: list[tuple[list[str], dict[str, str]]] = []
    original = subprocess.run

    def recording(argv: list[str], *a: Any, **kw: Any) -> Any:
        calls.append((list(argv), dict(kw.get("env") or {})))
        return original(argv, *a, **kw)

    monkeypatch.setattr(subprocess, "run", recording)
    env = env_for(tmp_path, GIT_DIR="/nonexistent", GIT_INDEX_FILE="/nonexistent", XDG_CONFIG_HOME="/nonexistent")
    assert rc.content_gate(repo, env).refusal() is None
    assert len(calls) >= 4  # ls-files twice, status, ls-files -v, diff --cached (at least)
    for argv, genv in calls:
        assert genv["GIT_CONFIG_GLOBAL"] == "/dev/null"
        assert genv["GIT_CONFIG_NOSYSTEM"] == "1"
        assert "GIT_DIR" not in genv
        assert "GIT_INDEX_FILE" not in genv
        pairs = [argv[i + 1] for i, word in enumerate(argv) if word == "-c"]
        for want in (
            "core.fsmonitor=false",
            "core.untrackedCache=false",
            "core.excludesFile=/dev/null",
            "core.hooksPath=/dev/null",
        ):
            assert want in pairs


def test_transport_query_still_reads_the_effective_config(tmp_path: Path) -> None:
    # F2 is about where the remote points, not which files are copied: it must see the caller's own config.
    repo = clean_repo(tmp_path)
    (tmp_path / "home" / ".gitconfig").write_text('[url "https://evil-value/"]\n\tinsteadOf = https://zzz/\n', "utf-8")
    code, out = strict(tmp_path, repo)
    assert code == 0
    assert "setting url.*.insteadof" in out


# ---- G3: a bound that is hit is ambiguous, so it is a full suite -----------------------------------------------------


def nest_bash(command: str, levels: int) -> str:
    for _ in range(levels):
        command = "bash -c " + shlex.quote(command)
    return command


@pytest.mark.parametrize("levels", [5, 6, 9])
def test_deep_shell_nesting_is_treated_as_full(levels: int) -> None:
    found = rc.classify(nest_bash("true", levels))
    assert [f.klass for f in found] == ["full-suite"]
    assert found[0].note == "nesting too deep to read: treat as a local full suite"


def test_shallow_shell_nesting_still_reads_through() -> None:
    assert rc.classify(nest_bash("true", 3)) == []
    assert [f.klass for f in rc.classify(nest_bash("pytest", 3))] == ["full-suite"]


def test_deep_nesting_inside_ra_remote_is_treated_as_full() -> None:
    found = rc.classify("ra-remote /w -- " + nest_bash("true", 6))
    assert [f.klass for f in found] == ["full-suite"]
    assert found[0].wrapped is False


def test_too_many_wrappers_is_treated_as_full() -> None:
    found = rc.classify("nohup " * 12 + "true")
    assert [f.klass for f in found] == ["full-suite"]
    assert found[0].note


def test_ten_wrappers_still_read() -> None:
    assert rc.classify("nohup " * 10 + "true") == []
    assert [f.klass for f in rc.classify("nohup " * 10 + "pytest")] == ["full-suite"]


def test_deep_nesting_is_a_strict_violation_with_its_reason(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    code, out = strict(tmp_path, repo, nest_bash("true", 6))
    assert code == 1
    assert "nesting too deep to read: treat as a local full suite" in out


# ---- G4: every transport query key is named ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("config", "shown"),
    [
        (("include.path", "x.cfg"), "include.path"),
        (("protocol.ext.allow", "always"), "protocol.*"),
        (("protocol.allow", "always"), "protocol.*"),
    ],
)
def test_include_and_protocol_are_named(tmp_path: Path, config: tuple[str, str], shown: str) -> None:
    repo = clean_repo(tmp_path)
    _git(repo, "config", config[0], config[1])
    code, out = strict(tmp_path, repo)
    assert code == 0
    assert f"cannot tell: keep local (git transport is overridden (setting {shown}))" in out
    assert "x.cfg" not in out
    assert "ra-remote" not in out


# ---- round 4 (#485): verify the copied bytes against the HEAD tree, never trust git status -------------------------


def assert_unverified(code: int, out: str, text: str = "tracked files differ from the public commit") -> None:
    assert code == 0
    assert text in out
    assert "ra-remote" not in out


def _set_filter(repo: Path) -> None:
    _git(repo, "config", "filter.private.clean", "sed s/PRIVATE_TOKEN/PUBLIC_VALUE/g")
    _git(repo, "config", "filter.private.smudge", "sed s/PUBLIC_VALUE/PRIVATE_TOKEN/g")


def test_clean_smudge_filter_reviewer_reproduction(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, REPO_URL)
    _set_filter(repo)
    (repo / ".gitattributes").write_text("*.txt filter=private\n", encoding="utf-8")
    (repo / "data.txt").write_text("PRIVATE_TOKEN\n", encoding="utf-8")
    commit_all(repo)
    assert _git_out(repo, "status", "--porcelain", "--untracked-files=no") == b""  # git itself says clean
    assert _git_out(repo, "show", "HEAD:data.txt") == b"PUBLIC_VALUE\n"
    code, out = strict(tmp_path, repo)
    assert_unverified(code, out)
    assert "PRIVATE_TOKEN" not in out
    assert "data.txt" not in out


def test_filter_in_info_attributes_is_refused_even_when_bytes_match(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    _set_filter(repo)
    (repo / ".git" / "info" / "attributes").write_text("*.py filter=private\n", encoding="utf-8")
    code, out = strict(tmp_path, repo)
    assert_unverified(code, out, "cannot tell: content filters are configured (filter)")
    assert "private" not in out


def test_filter_attribute_on_an_unchanged_file_is_refused(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, REPO_URL)
    (repo / ".gitattributes").write_text("*.py filter=private\n", encoding="utf-8")
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    commit_all(repo)
    code, out = strict(tmp_path, repo)
    assert_unverified(code, out, "cannot tell: content filters are configured (filter)")


def test_gitattributes_mentioning_filter_is_refused(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, REPO_URL)
    (repo / "sub").mkdir()
    (repo / "sub" / ".gitattributes").write_text("# nothing\n*.zzz filter=unused\n", encoding="utf-8")
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    commit_all(repo)
    code, out = strict(tmp_path, repo)
    assert_unverified(code, out, "cannot tell: content filters are configured (filter)")


def test_core_attributes_file_with_filter_is_refused(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    attrs = tmp_path / "attrs"
    attrs.write_text("*.py filter=private\n", encoding="utf-8")
    _git(repo, "config", "core.attributesFile", str(attrs))
    code, out = strict(tmp_path, repo)
    assert_unverified(code, out, "cannot tell: content filters are configured (filter)")


def test_check_stat_minimal_same_size_replacement_reviewer_reproduction(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, REPO_URL)
    (repo / "data.txt").write_text("PUBLIC1234\n", encoding="utf-8")
    commit_all(repo)
    _git(repo, "config", "core.checkStat", "minimal")
    _git(repo, "config", "core.trustctime", "false")
    old = os.stat(repo / "data.txt").st_mtime_ns - 5_000_000_000
    os.utime(repo / "data.txt", ns=(old, old))
    _git(repo, "update-index", "--refresh")
    (repo / "data.txt").write_text("PRIVATE123\n", encoding="utf-8")
    os.utime(repo / "data.txt", ns=(old, old))
    assert _git_out(repo, "status", "--porcelain", "--untracked-files=no") == b""
    code, out = strict(tmp_path, repo)
    assert_unverified(code, out)
    assert "PRIVATE" not in out


def _stat_hidden_replacement(repo: Path, name: str = "a.py", body: str = "x = 9\n") -> None:
    old = os.stat(repo / name).st_mtime_ns - 5_000_000_000
    os.utime(repo / name, ns=(old, old))
    _git(repo, "update-index", "--refresh")
    (repo / name).write_text(body, encoding="utf-8")  # same size as "x = 1\n"
    os.utime(repo / name, ns=(old, old))


def test_ignore_stat_modified_file_is_refused(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    _git(repo, "config", "core.ignoreStat", "true")
    _git(repo, "add", "--renormalize", "a.py")
    _git(repo, "update-index", "--really-refresh")
    (repo / "a.py").write_text("x = 2\n", encoding="utf-8")
    assert _git_out(repo, "status", "--porcelain", "--untracked-files=no") == b""
    assert_unverified(*strict(tmp_path, repo))


def test_assume_unchanged_modified_file_is_refused(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    _git(repo, "update-index", "--assume-unchanged", "a.py")
    (repo / "a.py").write_text("x = 2\n", encoding="utf-8")
    assert_unverified(*strict(tmp_path, repo))


def test_same_size_modified_file_with_restored_mtime_is_refused(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    _stat_hidden_replacement(repo)
    assert_unverified(*strict(tmp_path, repo))


def test_changed_file_mode_is_refused(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    _git(repo, "config", "core.fileMode", "false")  # git no longer looks at the mode bit
    (repo / "a.py").chmod(0o755)
    assert _git_out(repo, "status", "--porcelain", "--untracked-files=no") == b""
    assert_unverified(*strict(tmp_path, repo))


def test_executable_file_that_is_committed_executable_stays_clean(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    (repo / "run.sh").write_text("echo hi\n", encoding="utf-8")
    (repo / "run.sh").chmod(0o755)
    commit_all(repo)
    code, out = strict(tmp_path, repo)
    assert code == 1
    assert "-> ra-remote --plan" in out


def test_executable_bit_dropped_on_a_committed_executable_is_refused(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    (repo / "run.sh").write_text("echo hi\n", encoding="utf-8")
    (repo / "run.sh").chmod(0o755)
    commit_all(repo)
    _git(repo, "config", "core.fileMode", "false")
    (repo / "run.sh").chmod(0o644)
    assert_unverified(*strict(tmp_path, repo))


def test_retargeted_symlink_is_refused(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    (repo / "alias.py").symlink_to("a.py")
    commit_all(repo)
    _git(repo, "config", "core.ignoreStat", "true")
    (repo / "alias.py").unlink()
    (repo / "alias.py").symlink_to("b.py")
    assert_unverified(*strict(tmp_path, repo))


def test_symlink_replaced_by_a_regular_file_is_refused(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    (repo / "alias.py").symlink_to("a.py")
    commit_all(repo)
    _git(repo, "update-index", "--assume-unchanged", "alias.py")
    (repo / "alias.py").unlink()
    (repo / "alias.py").write_text("a.py", encoding="utf-8")
    assert_unverified(*strict(tmp_path, repo))


def test_file_deleted_from_the_worktree_is_refused(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    (repo / "a.py").unlink()
    assert_unverified(*strict(tmp_path, repo))


def test_deleted_file_hidden_by_skip_worktree_is_refused(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    _git(repo, "update-index", "--skip-worktree", "a.py")
    (repo / "a.py").unlink()
    assert_unverified(*strict(tmp_path, repo))


def test_path_in_the_index_but_not_in_head_is_refused(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    (repo / "extra.py").write_text("y = 1\n", encoding="utf-8")
    _git(repo, "add", "extra.py")
    assert_unverified(*strict(tmp_path, repo))


def test_directory_swapped_for_a_symlink_is_refused(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, REPO_URL)
    (repo / "pkg").mkdir()
    (repo / "pkg" / "m.py").write_text("y = 1\n", encoding="utf-8")
    commit_all(repo)
    _git(repo, "update-index", "--skip-worktree", "pkg/m.py")
    other = tmp_path / "elsewhere-dir"
    other.mkdir()
    (other / "m.py").write_text("y = 1\n", encoding="utf-8")  # identical bytes, but behind a symlink
    (repo / "pkg" / "m.py").unlink()
    (repo / "pkg").rmdir()
    (repo / "pkg").symlink_to(other)
    assert_unverified(*strict(tmp_path, repo))


def test_submodule_gitlink_is_refused(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    nested = repo / "vendor"
    nested.mkdir()
    _git(nested, "init", "-q")
    (nested / "m.py").write_text("y = 1\n", encoding="utf-8")
    commit_all(nested)
    commit_all(repo)
    assert "160000" in _git_out(repo, "ls-tree", "HEAD").decode()
    assert_unverified(*strict(tmp_path, repo))


def test_odd_file_names_in_a_clean_repo_still_get_the_command(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    for name in ("with space.py", "-dash.py", "line\nbreak.py", 'q"uote.py', "café.py", "sub dir/in side.py"):
        target = repo / name
        target.parent.mkdir(exist_ok=True)
        target.write_text("z = 1\n", encoding="utf-8")
    commit_all(repo)
    code, out = strict(tmp_path, repo)
    assert code == 1
    assert "-> ra-remote --plan" in out
    assert "differ" not in out


def test_odd_file_name_modified_is_refused(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    (repo / "line\nbreak.py").write_text("z = 1\n", encoding="utf-8")
    commit_all(repo)
    _git(repo, "update-index", "--assume-unchanged", "line\nbreak.py")
    (repo / "line\nbreak.py").write_text("z = 2\n", encoding="utf-8")
    code, out = strict(tmp_path, repo)
    assert_unverified(code, out)
    assert "break" not in out


def test_file_over_the_size_limit_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = clean_repo(tmp_path)
    (repo / "big.bin").write_bytes(b"0" * 64)
    commit_all(repo)
    monkeypatch.setattr(rc, "FILE_LIMIT", 63)
    assert_unverified(*strict(tmp_path, repo), "cannot verify the copied bytes (size or entry bound)")


def test_total_size_over_the_limit_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = clean_repo(tmp_path)
    for i in range(4):
        (repo / f"f{i}.bin").write_bytes(b"0" * 40)
    commit_all(repo)
    monkeypatch.setattr(rc, "TOTAL_LIMIT", 100)
    assert_unverified(*strict(tmp_path, repo), "cannot verify the copied bytes (size or entry bound)")


def test_entry_count_over_the_limit_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = clean_repo(tmp_path)
    for i in range(5):
        (repo / f"f{i}.py").write_text("x\n", encoding="utf-8")
    commit_all(repo)
    monkeypatch.setattr(rc, "WALK_LIMIT", 3)
    assert_unverified(*strict(tmp_path, repo), "cannot verify the copied bytes (size or entry bound)")


def test_verification_failure_is_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = clean_repo(tmp_path)
    monkeypatch.setattr(rc, "_verify_content", lambda *a, **k: None)
    assert rc.content_gate(repo, env_for(tmp_path)).refusal() is not None


def test_verification_ignores_repository_stat_and_status_settings(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    for key, value in (
        ("core.ignoreStat", "true"),
        ("core.checkStat", "minimal"),
        ("core.trustctime", "false"),
        ("status.showUntrackedFiles", "no"),
        ("diff.ignoreSubmodules", "all"),
        ("core.fsmonitor", "false"),
    ):
        _git(repo, "config", key, value)
    _stat_hidden_replacement(repo)
    assert_unverified(*strict(tmp_path, repo))


# ---- round 4: transport names for http proxies ------------------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    ["http.proxy", "http.https://example.com/.proxy", "http.https://example.com/a/.proxy"],
)
def test_http_proxy_is_named_as_a_transport_override(tmp_path: Path, key: str) -> None:
    repo = clean_repo(tmp_path)
    _git(repo, "config", key, "http://evil-value:3128")
    code, out = strict(tmp_path, repo)
    assert code == 0
    assert "cannot tell: keep local (git transport is overridden (setting http.proxy))" in out
    assert "evil-value" not in out
    assert "example.com" not in out
    assert "ra-remote" not in out


def test_credential_settings_are_not_a_transport_override(tmp_path: Path) -> None:
    # credential.* only changes how a login is supplied, never where a remote points
    repo = clean_repo(tmp_path)
    _git(repo, "config", "credential.helper", "store")
    code, out = strict(tmp_path, repo)
    assert code == 1
    assert "overridden" not in out


# ---- round 4: the verification alone decides (status layers stubbed out), so each rule is proven by itself --------


def _scn_symlink_retarget(repo: Path) -> None:
    (repo / "alias.py").symlink_to("a.py")
    commit_all(repo)
    (repo / "alias.py").unlink()
    (repo / "alias.py").symlink_to("b.py")


def _scn_symlink_to_file(repo: Path) -> None:
    (repo / "alias.py").symlink_to("a.py")
    commit_all(repo)
    (repo / "alias.py").unlink()
    (repo / "alias.py").write_text("a.py", encoding="utf-8")


def _scn_extra_in_index(repo: Path) -> None:
    (repo / "extra.py").write_text("y = 1\n", encoding="utf-8")
    _git(repo, "add", "extra.py")


def _scn_deleted(repo: Path) -> None:
    (repo / "a.py").unlink()


def _scn_mode(repo: Path) -> None:
    (repo / "a.py").chmod(0o755)


def _scn_exec_dropped(repo: Path) -> None:
    (repo / "run.sh").write_text("echo hi\n", encoding="utf-8")
    (repo / "run.sh").chmod(0o755)
    commit_all(repo)
    (repo / "run.sh").chmod(0o644)


def _scn_content(repo: Path) -> None:
    (repo / "a.py").write_text("x = 2\n", encoding="utf-8")


def _scn_dir_symlink(repo: Path) -> None:
    (repo / "pkg").mkdir()
    (repo / "pkg" / "m.py").write_text("y = 1\n", encoding="utf-8")
    commit_all(repo)
    other = repo.parent / "elsewhere-dir"
    other.mkdir()
    (other / "m.py").write_text("y = 1\n", encoding="utf-8")
    (repo / "pkg" / "m.py").unlink()
    (repo / "pkg").rmdir()
    (repo / "pkg").symlink_to(other)


def _scn_gitlink(repo: Path) -> None:
    nested = repo / "vendor"
    nested.mkdir()
    _git(nested, "init", "-q")
    (nested / "m.py").write_text("y = 1\n", encoding="utf-8")
    commit_all(nested)
    commit_all(repo)


@pytest.mark.parametrize(
    "scenario",
    [
        _scn_symlink_retarget,
        _scn_symlink_to_file,
        _scn_extra_in_index,
        _scn_deleted,
        _scn_mode,
        _scn_exec_dropped,
        _scn_content,
        _scn_dir_symlink,
        _scn_gitlink,
    ],
)
def test_verification_alone_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scenario: Any) -> None:
    repo = clean_repo(tmp_path)
    scenario(repo)
    monkeypatch.setattr(rc, "_modified", lambda *a, **k: 0)  # as if git status, ls-files -v and the diff were clean
    gate = rc.content_gate(repo, env_for(tmp_path))
    assert gate.modified >= 1
    assert gate.refusal() is not None


def test_verification_alone_passes_a_clean_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = clean_repo(tmp_path)
    (repo / "alias.py").symlink_to("a.py")
    (repo / "run.sh").write_text("echo hi\n", encoding="utf-8")
    (repo / "run.sh").chmod(0o755)
    commit_all(repo)
    monkeypatch.setattr(rc, "_modified", lambda *a, **k: 0)
    assert rc.content_gate(repo, env_for(tmp_path)).refusal() is None


# ---- round 5: HEAD must be published on a public remote ---------------------------------------------------------

NOT_PUBLISHED = "keep local: HEAD is not published on a public remote"


def assert_unpublished(code: int, out: str) -> None:
    assert code == 0
    assert NOT_PUBLISHED in out
    assert "ra-remote" not in out


def test_local_commit_not_on_any_remote_ref_is_refused(tmp_path: Path) -> None:
    # reviewer reproduction: a clean local commit holding private material, never pushed
    repo = make_repo(tmp_path, REPO_URL, fetched=False)
    (repo / "private-plan.txt").write_text("secret plans\n", encoding="utf-8")
    commit_all(repo, publish=False)
    code, out = strict(tmp_path, repo)
    assert_unpublished(code, out)
    assert "private-plan" not in out
    assert "secret" not in out


def test_head_equal_to_remote_ref_passes(tmp_path: Path) -> None:
    code, out = strict(tmp_path, clean_repo(tmp_path))
    assert code == 1
    assert "-> ra-remote --plan" in out


def test_head_ancestor_of_remote_ref_passes(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    (repo / "b.py").write_text("y = 2\n", encoding="utf-8")
    commit_all(repo)  # remote ref now at the newer commit
    _git(repo, "reset", "-q", "--hard", "HEAD~1")  # HEAD is an ancestor of refs/remotes/origin/main
    code, out = strict(tmp_path, repo)
    assert code == 1
    assert "-> ra-remote --plan" in out


def test_commits_ahead_of_remote_ref_are_counted_not_named(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    for name in ("one-private.txt", "two-private.txt"):
        (repo / name).write_text("x\n", encoding="utf-8")
        commit_all(repo, publish=False)
    code, out = strict(tmp_path, repo)
    assert_unpublished(code, out)
    assert "(2 commits ahead of the remote branches, or never pushed)" in out
    assert "push it first and fetch" in out
    assert "private" not in out


def test_stray_ref_under_a_remote_that_does_not_exist_is_ignored(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, REPO_URL, fetched=False)
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    commit_all(repo, publish=False)
    _git(repo, "update-ref", "refs/remotes/ghost/main", "HEAD")
    code, out = strict(tmp_path, repo)
    assert_unpublished(code, out)


def test_no_remote_tracking_refs_at_all_is_refused(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, REPO_URL, fetched=False)
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    commit_all(repo, publish=False)
    code, out = strict(tmp_path, repo)
    assert_unpublished(code, out)
    assert "never fetched: no remote-tracking refs" in out


def test_unborn_head_is_refused(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, REPO_URL, fetched=False)
    _git(repo, "update-ref", "refs/remotes/origin/main", "4b825dc642cb6eb9a060e54bf8d69288fbee4904")
    code, out = strict(tmp_path, repo)
    assert code == 0
    assert "ra-remote" not in out


def test_detached_head_without_a_containing_remote_ref_is_refused(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    (repo / "b.py").write_text("y = 2\n", encoding="utf-8")
    commit_all(repo, publish=False)
    _git(repo, "checkout", "-q", "--detach", "HEAD")
    assert_unpublished(*strict(tmp_path, repo))


def test_ref_bound_refuses_when_there_are_too_many(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    for n in range(rc.REF_LIMIT + 1):
        _git(repo, "update-ref", f"refs/remotes/origin/b{n}", "HEAD")
    code, out = strict(tmp_path, repo)
    assert code == 0
    assert "keep local: cannot tell whether HEAD is published (more than" in out
    assert "ra-remote" not in out


def test_ref_bound_exactly_at_the_limit_still_works(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)  # one ref already
    for n in range(rc.REF_LIMIT - 1):
        _git(repo, "update-ref", f"refs/remotes/origin/b{n}", "HEAD")
    code, out = strict(tmp_path, repo)
    assert code == 1
    assert "-> ra-remote --plan" in out


def test_publish_check_ignores_repository_config_and_caller_git_env(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    _git(repo, "config", "core.hooksPath", str(tmp_path / "nowhere"))
    _git(repo, "config", "core.fsmonitor", "false")
    code, out = strict(tmp_path, repo, GIT_NAMESPACE="other")  # unisolated git would look under another namespace
    assert code == 1
    assert "-> ra-remote --plan" in out
    # and an unpublished commit stays refused under the same hostile settings
    (repo / "c.py").write_text("z = 3\n", encoding="utf-8")
    commit_all(repo, publish=False)
    assert_unpublished(*strict(tmp_path, repo, GIT_NAMESPACE="other"))


def test_publish_check_is_not_run_for_commands_that_need_no_remote(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, REPO_URL)
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    commit_all(repo, publish=False)
    code, out = strict(tmp_path, repo, command="pytest tests/test_a.py")
    assert code == 0
    assert NOT_PUBLISHED not in out
