# SPDX-License-Identifier: Apache-2.0
"""safo-runner-check: classify full-suite and mutation commands and print the ra-remote form (#485). No network."""

from __future__ import annotations

import io
import json
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from safo import runner_check as rc

PUBLIC = {"SAFO_PUBLIC_OWNERS": "ChiefGyk3D,Renegade-Penguin"}


def _git(path: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True)  # noqa: S603, S607 - test fixture


def make_repo(
    tmp_path: Path,
    remote: str | None,
    name: str = "repo",
    *,
    dev: bool = True,
    extra: tuple[tuple[str, str], ...] = (),
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
