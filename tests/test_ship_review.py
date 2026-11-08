# SPDX-License-Identifier: Apache-2.0
"""safo-ship prints the unresolved threads with their comments and can wait for the automated reviewer (#371)."""

from __future__ import annotations

from typing import Any

import pytest

from safo import ship
from test_ship import GREEN, HEAD, MOVED, REPO, Rig, merges, rig, threads, view  # noqa: F401

BOT = "copilot-pull-request-reviewer[bot]"


def review(login: str = BOT, commit: str = HEAD) -> dict[str, Any]:
    return {"login": login, "commit": commit}


def review_calls(calls: list[list[str]]) -> list[list[str]]:
    return [c for c in calls if len(c) > 2 and c[1] == "api" and "/reviews" in c[2]]


def test_threads_are_printed_with_author_location_and_comment(rig: Rig) -> None:  # noqa: F811
    rig.state["threads"] = [threads("a.py", body="Use a bounded read here.", author="copilot-pull-request-reviewer")]
    code, out, calls = rig.go("5", "--repo", REPO)
    assert code == ship.EXIT_THREADS and merges(calls) == []
    lines = out.splitlines()
    assert "  a.py:3 https://x/a.py" in lines
    assert '    copilot-pull-request-reviewer: "Use a bounded read here."' in lines


def test_a_long_comment_is_cut_at_600_characters(rig: Rig) -> None:  # noqa: F811
    rig.state["threads"] = [threads("a.py", body="y" * 5000)]
    _code, out, _calls = rig.go("5", "--repo", REPO)
    body_line = next(line for line in out.splitlines() if line.startswith("    x:"))
    assert body_line.count("y") == 600 and body_line.endswith('[truncated]"')
    assert "y" * 601 not in out


def test_a_comment_of_exactly_600_characters_is_not_marked_cut(rig: Rig) -> None:  # noqa: F811
    rig.state["threads"] = [threads("a.py", body="z" * 600)]
    _code, out, _calls = rig.go("5", "--repo", REPO)
    assert "z" * 600 in out and "[truncated]" not in out


def test_control_characters_in_a_comment_are_stripped_not_printed(rig: Rig) -> None:  # noqa: F811
    nasty = "bad\x1b[31mred\x07 line1\nline2\r\n\ttab ‮gnp.exe ​hidden \x00nul ::error::fake"
    rig.state["threads"] = [threads("a.py", body=nasty)]
    _code, out, _calls = rig.go("5", "--repo", REPO)
    body_line = next(line for line in out.splitlines() if line.startswith("    x:"))
    assert "\x1b" not in out and "\x07" not in out and "\x00" not in out and "‮" not in out
    assert "::error::" not in out, "a workflow command stays broken up by the output module"
    assert "\\x" not in body_line.replace(":\\x3a", "") and "\\u" not in body_line, "stripped, not written as escapes"
    assert "bad[31mred line1 line2 tab gnp.exe hidden nul" in body_line


def test_the_wait_is_off_by_default_and_asks_for_no_reviews(rig: Rig) -> None:  # noqa: F811
    _code, _out, calls = rig.go("5", "--repo", REPO)
    assert review_calls(calls) == []


def test_a_wait_that_times_out_says_so_and_still_checks_threads(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [view(GREEN)]
    rig.state["reviews"] = [[]]
    rig.state["threads"] = [threads("late.py")]
    code, out, calls = rig.go("5", "--repo", REPO, "--wait-for-review", "60", "--interval", "20")
    assert code == ship.EXIT_THREADS and "NOTICE no review by the automated reviewer" in out
    assert "late.py:3" in out and merges(calls) == []
    assert rig.slept == [20, 20, 20] and len(review_calls(calls)) == 4


def test_a_timed_out_wait_goes_on_to_merge_when_there_are_no_threads(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [view(GREEN), view(GREEN), view(GREEN, state="MERGED")]
    rig.state["reviews"] = [[]]
    code, out, calls = rig.go("5", "--repo", REPO, "--wait-for-review", "20", "--interval", "20")
    assert code == 0 and "NOTICE no review" in out and len(merges(calls)) == 1


def test_a_review_that_arrives_during_the_wait_ends_it_before_the_thread_check(rig: Rig) -> None:  # noqa: F811
    rig.state["reviews"] = [[], [review("someone-else")], [review(commit=MOVED)], [review()]]
    rig.state["threads"] = [threads("fresh.py", body="found by the reviewer")]
    code, out, calls = rig.go("5", "--repo", REPO, "--wait-for-review", "300", "--interval", "20")
    assert code == ship.EXIT_THREADS and "NOTICE" not in out
    assert "fresh.py:3" in out and "found by the reviewer" in out and merges(calls) == []
    assert len(review_calls(calls)) == 4 and rig.slept == [20, 20, 20]


def test_the_wait_never_outlasts_timeout(rig: Rig) -> None:  # noqa: F811
    rig.state["reviews"] = [[]]
    rig.state["threads"] = [threads("t.py")]
    code, out, calls = rig.go("5", "--repo", REPO, "--wait-for-review", "900", "--timeout", "30", "--interval", "20")
    assert code == ship.EXIT_THREADS and "NOTICE" in out and sum(rig.slept) <= 30
    assert merges(calls) == []


def test_the_wait_respects_max_polls(rig: Rig) -> None:  # noqa: F811
    rig.state["reviews"] = [[]]
    rig.state["threads"] = [threads("t.py")]
    _code, _out, calls = rig.go("5", "--repo", REPO, "--wait-for-review", "900", "--max-polls", "2", "--interval", "20")
    assert len(review_calls(calls)) == 2


def test_a_head_that_moves_during_the_wait_stops_without_merging(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [view(GREEN), view(GREEN), view(GREEN, head=MOVED)]
    rig.state["reviews"] = [[]]
    code, out, calls = rig.go("5", "--repo", REPO, "--wait-for-review", "300", "--interval", "20")
    assert code == ship.EXIT_HEAD_MOVED and MOVED in out and merges(calls) == []


def test_a_review_read_that_fails_is_an_error_not_a_pass(rig: Rig) -> None:  # noqa: F811
    rig.state["reviews"] = [[{"login": None}]]  # unreadable item: no "commit" key
    code, _out, calls = rig.go("5", "--repo", REPO, "--wait-for-review", "30")
    assert code == ship.EXIT_ERROR and merges(calls) == []


@pytest.mark.parametrize("value", ["-1", "901", "nan"])
def test_wait_for_review_is_bounded(rig: Rig, value: str, capsys: pytest.CaptureFixture[str]) -> None:  # noqa: F811
    with pytest.raises(SystemExit) as stop:
        rig.go("5", "--repo", REPO, "--wait-for-review", value)
    assert stop.value.code == 2
    assert "--wait-for-review" in capsys.readouterr().err


def test_ship_never_resolves_a_thread(rig: Rig) -> None:  # noqa: F811
    rig.state["threads"] = [threads("a.py")]
    _code, _out, calls = rig.go("5", "--repo", REPO, "--wait-for-review", "20")
    assert not any("resolveReviewThread" in " ".join(c) for c in calls)
