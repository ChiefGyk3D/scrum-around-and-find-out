# SPDX-License-Identifier: Apache-2.0
"""safo spend-post: post the weekly spend summary to a private issue. A fake gh stands in; nothing is sent."""

from __future__ import annotations

import argparse
import io
import subprocess
from pathlib import Path
from typing import Any

import pytest

from meterdata import NOW
from safo.context import LocalContext
from safo.errors import ConfigError
from safo.modes import spend, spend_post
from test_spend import MON, SECRET, World, msg, standard

WEEK = "2026-W41"


class FakeGh:
    """Stands in for subprocess.run: answers `gh api repos/...` with the visibility and records every call."""

    def __init__(self, private: str = "true", fail_comment: bool = False) -> None:
        self.private = private
        self.fail_comment = fail_comment
        self.calls: list[list[str]] = []
        self.bodies: list[str] = []

    def __call__(self, argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        if argv[1:3] == ["api", "repos/me/priv"] or argv[1] == "api":
            return subprocess.CompletedProcess(argv, 0, self.private + "\n", "")
        if argv[1:3] == ["issue", "comment"]:
            if self.fail_comment:
                return subprocess.CompletedProcess(argv, 1, "", "boom")
            self.bodies.append(kw.get("input", ""))
            return subprocess.CompletedProcess(argv, 0, "https://example.invalid/c\n", "")
        raise AssertionError(argv)

    def posted(self) -> list[list[str]]:
        return [c for c in self.calls if c[1:3] == ["issue", "comment"]]


def post(world: World, gh: Any, *argv: str) -> tuple[int, str]:
    parser = argparse.ArgumentParser()
    spend_post.add_arguments(parser)
    args = parser.parse_args(
        [
            "--claude",
            str(world.claude),
            "--codex",
            str(world.codex),
            "--week",
            WEEK,
            "--repo",
            "me/priv",
            "--issue",
            "7",
            *argv,
        ]
    )
    out = io.StringIO()
    ctx = LocalContext(
        out=out, env={"HOME": str(world.home), "PATH": ""}, now=NOW, run=gh, which_override=lambda n: "/fake/gh"
    )
    try:
        code = spend_post.run(ctx, args)
    except ConfigError as exc:
        return exc.exit_code, str(exc)
    return code, out.getvalue()


@pytest.fixture
def world(tmp_path: Path) -> World:
    w = World(tmp_path)
    standard(w)
    return w


def test_posts_one_summary_comment_to_a_private_repo(world: World) -> None:
    gh = FakeGh("true")
    code, _ = post(world, gh)
    assert code == 0
    assert len(gh.posted()) == 1
    argv = gh.posted()[0]
    assert argv[argv.index("--repo") + 1] == "me/priv" and argv[3] == "7"
    body = gh.bodies[0]
    assert "2026-W41" in body and "500" in body  # weighted total
    assert "estimate" in body.lower() and "measured" in body.lower()


def test_the_visibility_is_asked_with_the_documented_call(world: World) -> None:
    gh = FakeGh("true")
    post(world, gh)
    assert gh.calls[0][1:] == ["api", "repos/me/priv", "--jq", ".private"]


@pytest.mark.parametrize("answer", ["false", "", "null", "yes", "true\nfalse"])
def test_a_repo_that_is_not_known_private_is_refused_and_nothing_is_posted(world: World, answer: str) -> None:
    gh = FakeGh(answer)
    code, msg_ = post(world, gh)
    assert code == 2 and "private" in msg_
    assert gh.posted() == []


def test_a_failed_visibility_lookup_refuses(world: World) -> None:
    def broken(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 1, "", "nope")

    code, _ = post(world, broken)
    assert code == 2


@pytest.mark.parametrize("repo", ["me", "me/priv/x", "-x/y", "me/priv; rm", "", "me/pr iv", "../x"])
def test_a_bad_repo_name_is_refused_before_gh_runs(world: World, repo: str) -> None:
    gh = FakeGh()
    code, _ = post(world, gh, f"--repo={repo}")
    assert code == 2 and gh.calls == []


@pytest.mark.parametrize("issue", ["0", "-1", "abc", "1.5", "99999999999"])
def test_a_bad_issue_number_is_refused(world: World, issue: str) -> None:
    gh = FakeGh()
    code, _ = post(world, gh, "--issue", issue)
    assert code == 2 and gh.calls == []


def test_the_body_holds_no_sentinel_path_or_host(world: World) -> None:
    gh = FakeGh()
    world.lead("s9", [msg("zz", MON, inp=1, text=SECRET)])
    code, _ = post(world, gh)
    assert code == 0
    body = gh.bodies[0]
    assert SECRET not in body and str(world.home) not in body and str(world.claude) not in body
    assert "/home/" not in body and "@" not in body


def test_a_body_that_names_the_home_directory_is_refused(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(spend_post, "summary", lambda *a, **k: f"week from {world.home}/x")
    gh = FakeGh()
    code, _ = post(world, gh)
    assert code == 2 and gh.posted() == []


def test_a_failed_comment_is_an_error_and_is_never_retried(world: World) -> None:
    gh = FakeGh(fail_comment=True)
    code, _ = post(world, gh)
    assert code == 2 and len(gh.posted()) == 1


def test_the_change_since_the_baseline_is_in_the_body(world: World, tmp_path: Path) -> None:
    base = tmp_path / "base.json"
    gh = FakeGh()
    code, _ = post(world, gh, "--baseline", str(base))
    assert code == 0 and base.exists() and "no baseline" in gh.bodies[0].lower()
    world.lead("s2", [msg("l2", MON, inp=100)])  # 100 more weighted
    gh2 = FakeGh()
    code, _ = post(world, gh2, "--baseline", str(base))
    assert code == 0
    assert "+100" in gh2.bodies[0] and "baseline 500" in gh2.bodies[0]


def test_dry_run_prints_the_body_and_posts_nothing(world: World) -> None:
    gh = FakeGh()
    code, out = post(world, gh, "--dry-run")
    assert code == 0 and gh.posted() == [] and "2026-W41" in out
    assert gh.calls[0][1] == "api"  # the privacy check still runs


def test_the_mode_is_registered() -> None:
    from safo.modes import load_all

    assert "spend-post" in load_all()
    assert spend.run is not None
