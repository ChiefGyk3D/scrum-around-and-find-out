# SPDX-License-Identifier: Apache-2.0
"""Tests for safo-remerge (#588), on real temporary git repositories (no mocks)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from gitrepo import git, make_repo
from safo import remerge

PY = sys.executable
IDENT = {
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
}  # fmt: skip
PASS = f'["{PY}", "-c", "raise SystemExit(0)"]'
FAIL = f'["{PY}", "-c", "raise SystemExit(7)"]'

CHANGELOG = "# Changelog\n\n## Unreleased\n\n- base entry\n\n## v0.1.0\n\n- old\n"
HOME = "# Home\n\n- [A](a.md): a page.\n- [B](b.md): b page.\n\nTail.\n"


def scene(
    tmp: Path,
    base: dict[str, str],
    ours: dict[str, str] | None = None,
    theirs: dict[str, str] | None = None,
    *,
    delete_ours: tuple[str, ...] = (),
    delete_theirs: tuple[str, ...] = (),
) -> tuple[Path, Path]:
    """An origin with main, a clone on a feature branch with `ours`, and origin's main then moved on with `theirs`."""
    origin = tmp / "origin"
    make_repo(origin, base)
    work = tmp / "work"
    git(tmp, "clone", "-q", str(origin), str(work))
    git(work, "checkout", "-q", "-b", "feat")
    for name in delete_ours:
        git(work, "rm", "-q", name)
    make_repo(work, ours or {}, message="ours")
    for name in delete_theirs:
        git(origin, "rm", "-q", name)
    make_repo(origin, theirs or {}, message="theirs")
    return origin, work


def run(work: Path, test: str = PASS, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv in a test, no shell
        [PY, "-m", "safo.remerge", "--worktree", str(work), "--test-argv", test, *extra],
        capture_output=True,
        text=True,
        env={**os.environ, **IDENT, "PYTHONPATH": str(Path(remerge.__file__).parent.parent)},
        stdin=subprocess.DEVNULL,
        timeout=120,
        check=False,
    )


def clean(work: Path) -> bool:
    return git(work, "status", "--porcelain", "--untracked-files=all") == ""


def test_both_sides_add_to_changelog_and_home_keep_both(tmp_path: Path) -> None:
    base = {"CHANGELOG.md": CHANGELOG, "docs/home.md": HOME, "README.md": HOME}
    ours = {
        "CHANGELOG.md": CHANGELOG.replace("- base entry\n", "- base entry\n- ours entry\n"),
        "docs/home.md": HOME.replace("- [B](b.md): b page.\n", "- [B](b.md): b page.\n- [O](o.md): ours.\n"),
        "README.md": HOME.replace("- [B](b.md): b page.\n", "- [B](b.md): b page.\n- [O](o.md): ours.\n"),
    }
    theirs = {
        "CHANGELOG.md": CHANGELOG.replace("- base entry\n", "- base entry\n- theirs entry\n"),
        "docs/home.md": HOME.replace("- [B](b.md): b page.\n", "- [B](b.md): b page.\n- [T](t.md): theirs.\n"),
        "README.md": HOME.replace("- [B](b.md): b page.\n", "- [B](b.md): b page.\n- [T](t.md): theirs.\n"),
    }
    _, work = scene(tmp_path, base, ours, theirs)
    head_before = git(work, "rev-parse", "HEAD")
    done = run(work)
    assert done.returncode == 0, done.stderr + done.stdout
    for name in base:
        text = (work / name).read_text()
        assert "<<<<<<<" not in text and "=======" not in text and ">>>>>>>" not in text
    log = (work / "CHANGELOG.md").read_text()
    assert log.count("- ours entry\n") == 1 and log.count("- theirs entry\n") == 1
    assert log.index("ours entry") < log.index("theirs entry")  # stable order: this branch's lines first
    assert (work / "README.md").read_text().count("[T](t.md)") == 1
    assert clean(work)
    parents = git(work, "rev-list", "--parents", "-n", "1", "HEAD").split()
    assert len(parents) == 3 and parents[1] == head_before
    assert git(work, "log", "-1", "--format=%s") == remerge.COMMIT_MESSAGE
    assert git(work, "rev-parse", "HEAD") != head_before


def test_identical_line_on_both_sides_is_kept_once(tmp_path: Path) -> None:
    page = "- [B](b.md): b page.\n"
    ours = {"docs/home.md": HOME.replace(page, page + "- [S](s.md): same.\n- [O](o.md): ours.\n")}
    theirs = {"docs/home.md": HOME.replace(page, page + "- [S](s.md): same.\n- [T](t.md): theirs.\n")}
    _, work = scene(tmp_path, {"docs/home.md": HOME}, ours, theirs)
    # the common line is a duplicate of itself across sides: the combined block repeats it, so this must abort
    done = run(work)
    assert done.returncode == remerge.EXIT_NEEDS_AGENT
    assert "docs/home.md" in done.stdout


def test_same_line_edit_aborts_and_restores(tmp_path: Path) -> None:
    base = {"docs/home.md": HOME}
    ours = {"docs/home.md": HOME.replace("a page.", "ours edit.")}
    theirs = {"docs/home.md": HOME.replace("a page.", "theirs edit.")}
    _, work = scene(tmp_path, base, ours, theirs)
    head_before = git(work, "rev-parse", "HEAD")
    done = run(work)
    assert done.returncode == remerge.EXIT_NEEDS_AGENT
    assert "docs/home.md" in done.stdout
    assert git(work, "rev-parse", "HEAD") == head_before
    assert clean(work)
    assert "<<<<<<<" not in (work / "docs/home.md").read_text()
    assert not (work / ".git" / "MERGE_HEAD").exists()


def test_edit_of_a_base_line_in_an_allowed_file_aborts(tmp_path: Path) -> None:
    base = {"CHANGELOG.md": CHANGELOG}
    ours = {"CHANGELOG.md": CHANGELOG.replace("- base entry\n", "- base entry reworded\n- ours entry\n")}
    theirs = {"CHANGELOG.md": CHANGELOG.replace("- base entry\n", "- base entry\n- theirs entry\n")}
    _, work = scene(tmp_path, base, ours, theirs)
    done = run(work)
    assert done.returncode == remerge.EXIT_NEEDS_AGENT
    assert clean(work)


def test_delete_versus_edit_aborts(tmp_path: Path) -> None:
    base = {"docs/home.md": HOME, "README.md": HOME}
    _, work = scene(
        tmp_path,
        base,
        None,
        {"README.md": HOME.replace("Tail.", "- [T](t.md): theirs.\n\nTail.")},
        delete_ours=("README.md",),
    )
    done = run(work)
    assert done.returncode == remerge.EXIT_NEEDS_AGENT
    assert "README.md" in done.stdout
    assert clean(work)
    assert not (work / "README.md").exists()


def test_a_conflict_in_any_other_path_aborts_listing_all_paths(tmp_path: Path) -> None:
    base = {"CHANGELOG.md": CHANGELOG, "src/x.py": "a = 1\n", "src/y.py": "b = 1\n"}
    ours = {
        "CHANGELOG.md": CHANGELOG.replace("- base entry\n", "- base entry\n- ours\n"),
        "src/x.py": "a = 2\n",
        "src/y.py": "b = 2\n",
    }
    theirs = {
        "CHANGELOG.md": CHANGELOG.replace("- base entry\n", "- base entry\n- theirs\n"),
        "src/x.py": "a = 3\n",
        "src/y.py": "b = 3\n",
    }
    _, work = scene(tmp_path, base, ours, theirs)
    head_before = git(work, "rev-parse", "HEAD")
    done = run(work)
    assert done.returncode == remerge.EXIT_NEEDS_AGENT
    assert "src/x.py" in done.stdout and "src/y.py" in done.stdout
    assert git(work, "rev-parse", "HEAD") == head_before and clean(work)


def test_a_non_list_line_added_by_both_sides_aborts(tmp_path: Path) -> None:
    page = "- [B](b.md): b page.\n"
    ours = {"docs/home.md": HOME.replace(page, page + "Ours prose.\n")}
    theirs = {"docs/home.md": HOME.replace(page, page + "Theirs prose.\n")}
    _, work = scene(tmp_path, {"docs/home.md": HOME}, ours, theirs)
    done = run(work)
    assert done.returncode == remerge.EXIT_NEEDS_AGENT
    assert clean(work)


def test_changelog_additions_outside_unreleased_abort(tmp_path: Path) -> None:
    ours = {"CHANGELOG.md": CHANGELOG + "- ours old\n"}
    theirs = {"CHANGELOG.md": CHANGELOG + "- theirs old\n"}
    _, work = scene(tmp_path, {"CHANGELOG.md": CHANGELOG}, ours, theirs)
    done = run(work)
    assert done.returncode == remerge.EXIT_NEEDS_AGENT
    assert clean(work)


def test_dirty_tree_is_refused_untouched(tmp_path: Path) -> None:
    _, work = scene(tmp_path, {"docs/home.md": HOME}, {"docs/home.md": HOME + "x\n"}, {"README.md": "r\n"})
    (work / "scratch.txt").write_text("mine\n")
    head_before = git(work, "rev-parse", "HEAD")
    done = run(work)
    assert done.returncode == remerge.EXIT_REFUSED
    assert (work / "scratch.txt").read_text() == "mine\n"
    assert git(work, "rev-parse", "HEAD") == head_before
    (work / "scratch.txt").unlink()
    (work / "docs/home.md").write_text("edited\n")
    assert run(work).returncode == remerge.EXIT_REFUSED
    assert (work / "docs/home.md").read_text() == "edited\n"


def test_a_live_process_with_the_worktree_as_cwd_is_refused(tmp_path: Path) -> None:
    _, work = scene(tmp_path, {"a.txt": "a\n"}, {"b.txt": "b\n"}, {"c.txt": "c\n"})
    sub = work / "sub"
    sub.mkdir()
    proc = subprocess.Popen(  # noqa: S603 - fixed argv in a test
        [PY, "-c", "import time; time.sleep(60)"], cwd=sub, stdin=subprocess.DEVNULL
    )
    try:
        done = run(work)
        assert done.returncode == remerge.EXIT_REFUSED
        assert "process" in done.stdout + done.stderr
    finally:
        proc.kill()
        proc.wait()
    assert run(work).returncode == 0


def test_failing_tests_do_not_commit_and_restore(tmp_path: Path) -> None:
    ours = {"CHANGELOG.md": CHANGELOG.replace("- base entry\n", "- base entry\n- ours\n")}
    theirs = {"CHANGELOG.md": CHANGELOG.replace("- base entry\n", "- base entry\n- theirs\n")}
    _, work = scene(tmp_path, {"CHANGELOG.md": CHANGELOG}, ours, theirs)
    head_before = git(work, "rev-parse", "HEAD")
    done = run(work, FAIL)
    assert done.returncode == remerge.EXIT_TESTS_FAILED
    assert "7" in done.stdout
    assert git(work, "rev-parse", "HEAD") == head_before and clean(work)


def test_a_clean_merge_runs_the_tests_and_commits(tmp_path: Path) -> None:
    _, work = scene(tmp_path, {"a.txt": "a\n"}, {"b.txt": "b\n"}, {"c.txt": "c\n"})
    done = run(work)
    assert done.returncode == 0, done.stderr
    assert (work / "b.txt").exists() and (work / "c.txt").exists() and clean(work)


def test_already_up_to_date_is_a_no_op(tmp_path: Path) -> None:
    _, work = scene(tmp_path, {"a.txt": "a\n"}, {"b.txt": "b\n"}, {})
    git(work, "fetch", "-q", "origin")
    git(work, "merge", "-q", "origin/main")
    head = git(work, "rev-parse", "HEAD")
    done = run(work)
    assert done.returncode == 0 and git(work, "rev-parse", "HEAD") == head


def test_test_argv_is_required_and_never_a_shell_string(tmp_path: Path) -> None:
    _, work = scene(tmp_path, {"a.txt": "a\n"}, {"b.txt": "b\n"}, {"c.txt": "c\n"})
    for bad in ("", "pytest -q", '"pytest"', "[]", "[1]", '["a", 2]'):
        assert run(work, bad).returncode == remerge.EXIT_USAGE, bad
    marker = tmp_path / "marker"
    assert run(work, f'["{PY}", "-c", "pass", ";touch {marker}"]').returncode == 0
    assert not marker.exists()


def test_a_branch_on_main_or_detached_is_refused(tmp_path: Path) -> None:
    _, work = scene(tmp_path, {"a.txt": "a\n"}, {"b.txt": "b\n"}, {"c.txt": "c\n"})
    git(work, "checkout", "-q", "--detach")
    assert run(work).returncode == remerge.EXIT_REFUSED
    git(work, "checkout", "-q", "main")
    assert run(work).returncode == remerge.EXIT_REFUSED


def test_a_symlinked_changelog_aborts(tmp_path: Path) -> None:
    origin = tmp_path / "origin"
    make_repo(origin, {"a.md": CHANGELOG, "b.md": CHANGELOG, "c.md": CHANGELOG}, {"CHANGELOG.md": "a.md"})
    work = tmp_path / "work"
    git(tmp_path, "clone", "-q", str(origin), str(work))
    git(work, "checkout", "-q", "-b", "feat")
    make_repo(work, {}, {"CHANGELOG.md": "b.md"}, message="o")
    make_repo(origin, {}, {"CHANGELOG.md": "c.md"}, message="t")
    done = run(work)
    assert done.returncode == remerge.EXIT_NEEDS_AGENT
    assert "CHANGELOG.md" in done.stdout and clean(work)


def test_the_tests_timeout_is_bounded(tmp_path: Path) -> None:
    _, work = scene(tmp_path, {"a.txt": "a\n"}, {"b.txt": "b\n"}, {"c.txt": "c\n"})
    sleeper = f'["{PY}", "-c", "import time; time.sleep(30)"]'
    done = run(work, sleeper, "--test-timeout", "1")
    assert done.returncode == remerge.EXIT_TESTS_FAILED and clean(work)


def test_works_in_a_real_linked_worktree(tmp_path: Path) -> None:
    origin = tmp_path / "origin"
    make_repo(origin, {"CHANGELOG.md": CHANGELOG})
    main = tmp_path / "main"
    git(tmp_path, "clone", "-q", str(origin), str(main))
    wt = tmp_path / "wt"
    git(main, "worktree", "add", "-q", "-b", "feat", str(wt), "origin/main")
    make_repo(wt, {"CHANGELOG.md": CHANGELOG.replace("- base entry\n", "- base entry\n- ours\n")}, message="o")
    make_repo(origin, {"CHANGELOG.md": CHANGELOG.replace("- base entry\n", "- base entry\n- theirs\n")}, message="t")
    assert run(wt).returncode == 0
    assert "- theirs" in (wt / "CHANGELOG.md").read_text()


def test_changelog_resolver_is_a_replaceable_interface() -> None:
    assert remerge.RESOLVERS["CHANGELOG.md"] is remerge.resolve_changelog
    out = remerge.resolve_changelog(CHANGELOG, CHANGELOG.replace("- base entry\n", "- base entry\n- o\n"), CHANGELOG)
    assert out is not None and "- o\n" in out
    assert remerge.resolve_changelog(CHANGELOG, "x\n", CHANGELOG) is None


def test_console_script_registered_and_not_a_safo_subcommand() -> None:
    meta = tomllib.loads((Path(__file__).parent.parent / "pyproject.toml").read_text())
    assert meta["project"]["scripts"]["safo-remerge"] == "safo.remerge:entry"
    guard = (Path(__file__).parent.parent / "src" / "safo" / "guard.py").read_text()
    assert "remerge" not in guard


def test_indented_prose_added_by_both_sides_is_not_a_continuation(tmp_path: Path) -> None:
    page = "- [B](b.md): b page.\n"
    ours = {"docs/home.md": HOME.replace(page, page + "  ours indented prose\n")}
    theirs = {"docs/home.md": HOME.replace(page, page + "  theirs indented prose\n")}
    _, work = scene(tmp_path, {"docs/home.md": HOME}, ours, theirs)
    done = run(work)
    assert done.returncode == remerge.EXIT_NEEDS_AGENT
    assert clean(work)


def test_a_list_row_with_its_continuation_still_merges(tmp_path: Path) -> None:
    page = "- [B](b.md): b page.\n"
    ours = {"docs/home.md": HOME.replace(page, page + "- [O](o.md): ours\n  more ours.\n")}
    theirs = {"docs/home.md": HOME.replace(page, page + "- [T](t.md): theirs\n  more theirs.\n")}
    _, work = scene(tmp_path, {"docs/home.md": HOME}, ours, theirs)
    assert run(work).returncode == 0
    assert "  more ours.\n- [T]" in (work / "docs/home.md").read_text()


@pytest.mark.parametrize("tail", ["## v0.1.0\n\n- old\n", ""])
def test_additions_at_the_end_of_unreleased_merge(tmp_path: Path, tail: str) -> None:
    base = "# Changelog\n\n## Unreleased\n- base\n" + tail
    ours = {"CHANGELOG.md": base.replace("- base\n", "- base\n- ours\n")}
    theirs = {"CHANGELOG.md": base.replace("- base\n", "- base\n- theirs\n")}
    _, work = scene(tmp_path, {"CHANGELOG.md": base}, ours, theirs)
    done = run(work)
    assert done.returncode == 0, done.stdout
    assert "- ours\n- theirs\n" in (work / "CHANGELOG.md").read_text()


def test_a_git_timeout_mid_merge_restores_the_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ours = {"CHANGELOG.md": CHANGELOG.replace("- base entry\n", "- base entry\n- ours\n")}
    theirs = {"CHANGELOG.md": CHANGELOG.replace("- base entry\n", "- base entry\n- theirs\n")}
    _, work = scene(tmp_path, {"CHANGELOG.md": CHANGELOG}, ours, theirs)
    for key, value in IDENT.items():
        monkeypatch.setenv(key, value)
    head = git(work, "rev-parse", "HEAD")
    real = remerge.git

    def slow(worktree: Path, *args: str, timeout: int = 120) -> subprocess.CompletedProcess[bytes]:
        if args[:1] == ("ls-files",):
            raise subprocess.TimeoutExpired("git", timeout)
        return real(worktree, *args, timeout=timeout)

    monkeypatch.setattr(remerge, "git", slow)
    code = remerge.remerge(work, [PY, "-c", "pass"], 5)
    monkeypatch.setattr(remerge, "git", real)
    assert code == remerge.EXIT_GIT
    assert git(work, "rev-parse", "HEAD") == head and clean(work)
    assert not (work / ".git" / "MERGE_HEAD").exists()


def test_test_command_output_cannot_write_workflow_commands(tmp_path: Path) -> None:
    _, work = scene(tmp_path, {"a.txt": "a\n"}, {"b.txt": "b\n"}, {"c.txt": "c\n"})
    code = 'import sys; print("::error::boom"); print("::set-output name=x::1", file=sys.stderr)'
    noisy = json.dumps([PY, "-c", code])
    done = run(work, noisy)
    assert done.returncode == 0
    assert "::" not in done.stdout + done.stderr  # the helper breaks every workflow-command marker
    assert "boom" in done.stdout


PYPROJECT = """[project]
name = "x"
dependencies = ["PyYAML==6.0.3"]

[project.scripts]
safo = "safo.cli:run"
safo-card = "safo.card_cli:entry"

[tool.setuptools.dynamic]
version = { attr = "safo.__version__" }
"""
LAST = 'safo-card = "safo.card_cli:entry"\n'


def with_script(*lines: str, text: str = PYPROJECT) -> dict[str, str]:
    return {"pyproject.toml": text.replace(LAST, LAST + "".join(lines))}


def test_pyproject_both_sides_add_a_script_line_merges(tmp_path: Path) -> None:
    ours = with_script('safo-ours = "safo.ours:entry"\n')
    theirs = with_script('safo-theirs = "safo.theirs_2:run"\n')
    _, work = scene(tmp_path, {"pyproject.toml": PYPROJECT}, ours, theirs)
    done = run(work)
    assert done.returncode == 0, done.stdout
    text = (work / "pyproject.toml").read_text()
    assert LAST + 'safo-ours = "safo.ours:entry"\nsafo-theirs = "safo.theirs_2:run"\n\n[tool' in text
    assert clean(work)


def test_pyproject_same_key_with_different_values_is_refused(tmp_path: Path) -> None:
    ours = with_script('safo-x = "safo.one:entry"\n')
    theirs = with_script('safo-x = "safo.two:entry"\n')
    _, work = scene(tmp_path, {"pyproject.toml": PYPROJECT}, ours, theirs)
    done = run(work)
    assert done.returncode == remerge.EXIT_NEEDS_AGENT and "pyproject.toml" in done.stdout
    assert clean(work)


def test_pyproject_same_key_added_with_an_existing_key_is_refused(tmp_path: Path) -> None:
    ours = with_script('safo-card = "safo.other:entry"\n')
    theirs = with_script('safo-theirs = "safo.theirs:entry"\n')
    _, work = scene(tmp_path, {"pyproject.toml": PYPROJECT}, ours, theirs)
    assert run(work).returncode == remerge.EXIT_NEEDS_AGENT
    assert clean(work)


def test_pyproject_edit_of_an_existing_script_line_is_refused(tmp_path: Path) -> None:
    ours = {"pyproject.toml": PYPROJECT.replace("safo.card_cli:entry", "safo.card2:entry")}
    theirs = with_script('safo-theirs = "safo.theirs:entry"\n')
    _, work = scene(tmp_path, {"pyproject.toml": PYPROJECT}, ours, theirs)
    assert run(work).returncode == remerge.EXIT_NEEDS_AGENT
    assert clean(work)


def test_pyproject_dependency_conflict_is_refused(tmp_path: Path) -> None:
    ours = {"pyproject.toml": PYPROJECT.replace("PyYAML==6.0.3", "PyYAML==7.0.0")}
    theirs = {"pyproject.toml": PYPROJECT.replace("PyYAML==6.0.3", "PyYAML==6.1.0")}
    _, work = scene(tmp_path, {"pyproject.toml": PYPROJECT}, ours, theirs)
    assert run(work).returncode == remerge.EXIT_NEEDS_AGENT
    assert clean(work)


def test_pyproject_additions_outside_the_scripts_table_are_refused(tmp_path: Path) -> None:
    dyn = 'version = { attr = "safo.__version__" }\n'
    ours = {"pyproject.toml": PYPROJECT.replace(dyn, dyn + 'a = "safo.a:entry"\n')}
    theirs = {"pyproject.toml": PYPROJECT.replace(dyn, dyn + 'b = "safo.b:entry"\n')}
    _, work = scene(tmp_path, {"pyproject.toml": PYPROJECT}, ours, theirs)
    assert run(work).returncode == remerge.EXIT_NEEDS_AGENT
    assert clean(work)


def test_pyproject_a_hunk_straddling_the_table_boundary_is_refused(tmp_path: Path) -> None:
    # both sides add a script line and also a line after the blank line, just before the next table
    ours = with_script('safo-ours = "safo.ours:entry"\n')
    theirs = with_script('safo-theirs = "safo.theirs:entry"\n')
    ours["pyproject.toml"] = ours["pyproject.toml"].replace("\n[tool", '\nsafo-late = "safo.late:entry"\n[tool')
    _, work = scene(tmp_path, {"pyproject.toml": PYPROJECT}, ours, theirs)
    assert run(work).returncode == remerge.EXIT_NEEDS_AGENT
    assert clean(work)


@pytest.mark.parametrize(
    "line", ['safo-x = "pkg.x:entry"\n', 'safo-x = "safo.x:Entry"\n', "safo-x = 1\n", 'safo-x = "safo.x:entry"  # c\n']
)
def test_pyproject_a_value_outside_the_pattern_is_refused(tmp_path: Path, line: str) -> None:
    ours = with_script(line)
    theirs = with_script('safo-theirs = "safo.theirs:entry"\n')
    _, work = scene(tmp_path, {"pyproject.toml": PYPROJECT}, ours, theirs)
    assert run(work).returncode == remerge.EXIT_NEEDS_AGENT
    assert clean(work)


def test_pyproject_resolver_is_registered() -> None:
    assert remerge.RESOLVERS["pyproject.toml"] is remerge.resolve_pyproject
