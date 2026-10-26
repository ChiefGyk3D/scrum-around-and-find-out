# SPDX-License-Identifier: Apache-2.0
"""scripts/check-claude-gitlinks.sh: an agent worktree staged as an embedded repository must fail the check (#86)."""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).parent.parent
SCRIPT = ROOT / "scripts" / "check-claude-gitlinks.sh"
FAKE_SHA = "1" * 40


def git(repo: Path, *args: str) -> None:
    subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],  # noqa: S607
        check=True,
        capture_output=True,
    )


def make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    (repo / "README.md").write_text("x\n")
    git(repo, "add", "README.md")
    return repo


def gitlink(repo: Path, path: str) -> None:
    """Stage a mode 160000 entry, which is what `git add -A` records for a nested repository."""
    git(repo, "update-index", "--add", "--cacheinfo", f"160000,{FAKE_SHA},{path}")


def check(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["bash", str(SCRIPT), *args],  # noqa: S607
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )


def test_a_gitlink_under_claude_worktrees_fails_and_names_the_path(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    gitlink(repo, ".claude/worktrees/agent-abc")
    done = check(repo)
    assert done.returncode == 1
    assert ".claude/worktrees/agent-abc" in done.stderr


def test_a_gitlink_anywhere_under_claude_fails(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    gitlink(repo, ".claude/other/nested")
    done = check(repo)
    assert done.returncode == 1
    assert ".claude/other/nested" in done.stderr


def test_ignored_untracked_worktrees_pass_even_when_the_ignore_is_required(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    (repo / ".gitignore").write_text(".claude/worktrees/\n")
    nested = repo / ".claude" / "worktrees" / "agent-abc"
    nested.mkdir(parents=True)
    (nested / "f").write_text("x\n")
    git(repo, "add", "-A")  # the command that caused #86: with the ignore in place it stages nothing from there
    assert check(repo, "--require-ignore").returncode == 0


def test_a_submodule_outside_claude_is_not_flagged(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    gitlink(repo, "vendor/lib")
    gitlink(repo, "claude/worktrees/not-hidden")  # similar name, wrong prefix
    done = check(repo)
    assert done.returncode == 0, done.stderr


def test_require_ignore_fails_when_worktrees_are_not_ignored(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    assert check(repo).returncode == 0
    done = check(repo, "--require-ignore")
    assert done.returncode == 1
    assert ".claude/worktrees/" in done.stderr


def test_a_path_with_spaces_is_named_whole(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    gitlink(repo, ".claude/worktrees/my agent")
    done = check(repo)
    assert done.returncode == 1
    assert ".claude/worktrees/my agent" in done.stderr


def test_outside_a_git_checkout_it_is_an_error_not_a_pass(tmp_path: Path) -> None:
    done = check(tmp_path)
    assert done.returncode == 2


def test_this_repository_passes_its_own_check_with_the_ignore_required() -> None:
    done = check(ROOT, "--require-ignore")
    assert done.returncode == 0, done.stderr
