# SPDX-License-Identifier: Apache-2.0
"""The issue check over REST with a short positive cache (#370): REST first, GraphQL as a fallback, fail closed."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from hooksdata import dispatch, set_mode, set_probe, state_folder
from safo import tracking
from safo.modes import hooks as hooks_mod
from safo.tracking import Ref
from test_tracking import GOOD, OPEN_ISSUE, REST_OPEN, agents, run_guard, stand_in_gh  # noqa: F401

REF = Ref("github", GOOD, "acme/widgets", 12)


def rest_run(
    rest: str, graphql: str = OPEN_ISSUE, rest_code: int = 0, graphql_code: int = 0
) -> tuple[Any, list[list[str]]]:
    calls: list[list[str]] = []

    def run(argv: list[str], **kwargs: Any) -> Any:
        calls.append(argv)
        if argv[1] == "api":
            return SimpleNamespace(returncode=rest_code, stdout=rest, stderr="HTTP 403" if rest_code else "")
        return SimpleNamespace(returncode=graphql_code, stdout=graphql, stderr="rate limit" if graphql_code else "")

    return run, calls


def make(run: Any, cache: Path | None, now: list[float]) -> Any:
    return tracking.gh_resolver(run, lambda name: "/usr/bin/gh", None, cache_dir=cache, clock=lambda: now[0])


def test_rest_answers_while_graphql_is_rate_limited(tmp_path: Path) -> None:
    run, calls = rest_run(REST_OPEN, "", graphql_code=1)
    resolve = make(run, tmp_path, [1000.0])
    assert resolve(REF) == "open" and resolve.source == "REST"
    assert [c[1] for c in calls] == ["api"]


def test_a_second_check_within_five_minutes_is_a_cache_hit(tmp_path: Path) -> None:
    run, calls = rest_run(REST_OPEN)
    now = [1000.0]
    resolve = make(run, tmp_path, now)
    assert resolve(REF) == "open"
    now[0] += 299
    assert resolve(REF) == "open" and resolve.source == "cache" and len(calls) == 1
    cache = tmp_path / tracking.CACHE_NAME
    assert stat.S_IMODE(cache.stat().st_mode) == 0o600 and json.loads(cache.read_text()).keys() == {"entries"}


def test_an_expired_cache_entry_is_checked_again(tmp_path: Path) -> None:
    run, calls = rest_run(REST_OPEN)
    now = [1000.0]
    resolve = make(run, tmp_path, now)
    assert resolve(REF) == "open"
    now[0] += tracking.CACHE_TTL_SECONDS
    assert resolve(REF) == "open" and resolve.source == "REST" and len(calls) == 2


def test_a_closed_issue_is_refused_and_never_cached(tmp_path: Path) -> None:
    run, _ = rest_run('{"state":"closed","pull_request":false}')
    resolve = make(run, tmp_path, [1000.0])
    verdict = tracking.check(f"issue: {GOOD}", resolve)
    assert verdict is not None and verdict[0] == "issue-unusable" and "is closed" in verdict[1]
    assert "answered by REST" in verdict[1] and not (tmp_path / tracking.CACHE_NAME).exists()


def test_a_pull_request_number_is_not_an_issue(tmp_path: Path) -> None:
    run, _ = rest_run('{"state":"open","pull_request":true}')
    resolve = make(run, tmp_path, [1000.0])
    assert resolve(REF) == "pull_request" and not (tmp_path / tracking.CACHE_NAME).exists()


def test_when_rest_and_graphql_both_fail_it_fails_closed_and_says_so(tmp_path: Path) -> None:
    run, calls = rest_run("", "", rest_code=1, graphql_code=1)
    resolve = make(run, tmp_path, [1000.0])
    verdict = tracking.check(f"issue: {GOOD}", resolve)
    assert verdict is not None and verdict[0] == "issue-unverified" and "REST and GraphQL failed" in verdict[1]
    assert not (tmp_path / tracking.CACHE_NAME).exists() and len(calls) == 2


def test_graphql_still_answers_when_rest_fails(tmp_path: Path) -> None:
    run, _ = rest_run("", OPEN_ISSUE, rest_code=1)
    resolve = make(run, tmp_path, [1000.0])
    assert resolve(REF) == "open" and resolve.source == "GraphQL"


@pytest.mark.parametrize(
    "junk", ["not json", "[]", '{"entries": 7}', '{"entries": {"acme/widgets#12": 5}}', "\x00" * 9]
)
def test_a_corrupt_cache_file_is_ignored_and_replaced(tmp_path: Path, junk: str) -> None:
    (tmp_path / tracking.CACHE_NAME).write_text(junk)
    run, calls = rest_run(REST_OPEN)
    resolve = make(run, tmp_path, [1000.0])
    assert resolve(REF) == "open" and len(calls) == 1
    assert tracking.cache_read(tmp_path, REF, 1001.0)


def test_a_cache_entry_for_another_repository_is_not_believed(tmp_path: Path) -> None:
    entry = {"repo": "evil/widgets", "number": 12, "ts": 1000.0}
    (tmp_path / tracking.CACHE_NAME).write_text(json.dumps({"entries": {"acme/widgets#12": entry}}))
    assert not tracking.cache_read(tmp_path, REF, 1001.0)


def test_the_cache_stays_bounded(tmp_path: Path) -> None:
    for number in range(1, tracking.CACHE_MAX_ENTRIES + 20):
        ref = Ref("github", f"acme/widgets#{number}", "acme/widgets", number)
        tracking.cache_store(tmp_path, ref, 1000.0 + number)
    entries = json.loads((tmp_path / tracking.CACHE_NAME).read_text())["entries"]
    assert len(entries) == tracking.CACHE_MAX_ENTRIES


def test_an_unwritable_cache_folder_does_not_break_the_check(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x")
    run, _ = rest_run(REST_OPEN)
    assert make(run, blocker / "deeper", [1000.0])(REF) == "open"


def test_a_lookup_that_fails_to_run_falls_back_then_fails_closed() -> None:
    def run(*args: Any, **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired("gh", 5)

    resolve = make(run, None, [1000.0])
    assert resolve(REF) == "error" and resolve.source == "REST and GraphQL"


def test_end_to_end_rest_answers_while_graphql_is_limited(_private_home: Path, agents: Path, tmp_path: Path) -> None:  # noqa: F811
    set_mode(_private_home, "block")
    set_probe(_private_home, reachable=False, agents=agents)
    bin_dir = stand_in_gh(tmp_path, {"12": OPEN_ISSUE}, graphql=False)
    payload = dispatch(prompt=f"issue: {GOOD}\nwork", tracked=False)
    out, log = run_guard(_private_home, agents, payload, bin_dir)
    assert out == "" and log[-1]["decision"] == "allow"
    out2, _ = run_guard(_private_home, agents, payload, bin_dir)
    assert out2 == "" and len((tmp_path / "gh.log").read_text().splitlines()) == 1, "the second dispatch is cached"
    assert (state_folder(_private_home) / tracking.CACHE_NAME).is_file()


def test_end_to_end_both_sources_down_is_denied_and_names_them(
    _private_home: Path,
    agents: Path,  # noqa: F811
    tmp_path: Path,
) -> None:
    set_mode(_private_home, "block")
    set_probe(_private_home, reachable=False, agents=agents)
    bin_dir = stand_in_gh(tmp_path, {"12": OPEN_ISSUE}, rest=False, graphql=False)
    out, log = run_guard(_private_home, agents, dispatch(prompt=f"issue: {GOOD}", tracked=False), bin_dir)
    reason = json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"]
    assert log[-1]["rules"] == ["issue-unverified"] and "REST and GraphQL failed" in reason


# -- the cache is trusted only when it provably is ours (#370 security review) ------------------------------


def seed(folder: Path, ts: float = 1000.0, mode: int = 0o600) -> Path:
    """A well-formed cache entry for REF, written by this user."""
    entry = {"repo": "acme/widgets", "number": 12, "ts": ts}
    path = folder / tracking.CACHE_NAME
    path.write_text(json.dumps({"entries": {"acme/widgets#12": entry}}))
    path.chmod(mode)
    return path


def falls_through(folder: Path, now: float = 1001.0) -> None:
    """The resolver must ask REST (never answer from the cache) and still say open from that answer."""
    run, calls = rest_run(REST_OPEN)
    resolve = make(run, folder, [now])
    assert resolve(REF) == "open" and resolve.source != "cache" and [c[1] for c in calls][:1] == ["api"]


def test_a_trusted_seed_is_a_hit(tmp_path: Path) -> None:
    seed(tmp_path)
    assert tracking.cache_read(tmp_path, REF, 1001.0), "control: the seed is good, so the misses below are the checks"


def test_a_world_or_group_writable_cache_file_is_a_miss(tmp_path: Path) -> None:
    for mode in (0o666, 0o662, 0o620):
        seed(tmp_path, mode=mode)
        assert not tracking.cache_read(tmp_path, REF, 1001.0)
        falls_through(tmp_path)


def test_a_cache_file_owned_by_someone_else_is_a_miss(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seed(tmp_path)
    monkeypatch.setattr(tracking, "trusted_dir", lambda folder: True)  # the folder passes; the file's owner must fail
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(tmp_path).st_uid + 1)
    assert not tracking.cache_read(tmp_path, REF, 1001.0)
    falls_through(tmp_path)


def test_a_symlinked_cache_file_is_a_miss(tmp_path: Path) -> None:
    real = tmp_path / "elsewhere.json"
    real.write_text(seed(tmp_path).read_text())
    (tmp_path / tracking.CACHE_NAME).unlink()
    (tmp_path / tracking.CACHE_NAME).symlink_to(real)
    assert not tracking.cache_read(tmp_path, REF, 1001.0)
    falls_through(tmp_path)


def test_a_fifo_cache_is_a_miss_and_does_not_hang(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / tracking.CACHE_NAME)
    assert not tracking.cache_read(tmp_path, REF, 1001.0)


def test_a_future_timestamp_is_a_miss_with_no_skew_allowance(tmp_path: Path) -> None:
    seed(tmp_path, ts=1001.5)
    assert not tracking.cache_read(tmp_path, REF, 1001.0)
    falls_through(tmp_path)
    seed(tmp_path, ts=1000.0 - tracking.CACHE_TTL_SECONDS)
    assert not tracking.cache_read(tmp_path, REF, 1000.0)


def test_an_untrusted_directory_is_a_miss_and_is_never_written(tmp_path: Path) -> None:
    folder = tmp_path / "shared"
    folder.mkdir()
    seed(folder)
    folder.chmod(0o777)
    assert not tracking.cache_read(folder, REF, 1001.0)
    falls_through(folder)
    assert json.loads((folder / tracking.CACHE_NAME).read_text())["entries"].keys() == {"acme/widgets#12"}


def test_a_store_never_follows_a_planted_symlink(tmp_path: Path) -> None:
    target = tmp_path / "victim"
    target.write_text("keep")
    (tmp_path / tracking.CACHE_NAME).symlink_to(target)
    tracking.cache_store(tmp_path, REF, 1000.0)
    assert target.read_text() == "keep", "os.replace swaps the link itself, it never writes through it"


def test_the_cache_is_not_touched_when_little_time_is_left(tmp_path: Path) -> None:
    seed(tmp_path)
    run, calls = rest_run(REST_OPEN)

    def never(work: Any) -> Any:
        raise AssertionError("the cache must not be read with no time left")

    resolve = tracking.gh_resolver(
        run, lambda n: "/usr/bin/gh", None, lambda: 0.5, cache_dir=tmp_path, clock=lambda: 1001.0, bounded=never
    )
    assert resolve(REF) == "open" and len(calls) == 1
    assert resolve.source == "REST"  # type: ignore[attr-defined]


def test_a_cache_read_that_does_not_finish_is_a_miss_and_nothing_is_stored(tmp_path: Path) -> None:
    run, _calls = rest_run(REST_OPEN)
    later: list[tuple[Ref, float]] = []
    resolve = tracking.gh_resolver(
        run,
        lambda n: "/usr/bin/gh",
        None,
        cache_dir=tmp_path,
        clock=lambda: 1001.0,
        bounded=lambda work: (False, None),
        deferred=later,
    )
    assert resolve(REF) == "open" and later == []
    assert resolve.source == "REST"  # type: ignore[attr-defined]


def test_with_deferral_the_resolver_writes_nothing_itself(tmp_path: Path) -> None:
    run, _ = rest_run(REST_OPEN)
    later: list[tuple[Ref, float]] = []
    resolve = tracking.gh_resolver(
        run, lambda n: "/usr/bin/gh", None, cache_dir=tmp_path, clock=lambda: 1001.0, deferred=later
    )
    assert resolve(REF) == "open" and later == [(REF, 1001.0)] and not (tmp_path / tracking.CACHE_NAME).exists()


def test_a_store_that_raises_is_swallowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise OSError("disk full")

    monkeypatch.setattr(tempfile, "mkstemp", boom)
    tracking.cache_store(tmp_path, REF, 1000.0)  # no exception
    assert list(tmp_path.iterdir()) == []


def test_the_store_leaves_no_temp_file_when_the_replace_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise OSError("nope")

    monkeypatch.setattr(os, "replace", boom)
    tracking.cache_store(tmp_path, REF, 1000.0)
    assert list(tmp_path.iterdir()) == []


def guard_once(home: Path, agents_path: Path, tmp_path: Path) -> tuple[str, list[dict[str, Any]]]:
    set_mode(home, "block")
    set_probe(home, reachable=False, agents=agents_path)
    bin_dir = stand_in_gh(tmp_path, {"12": OPEN_ISSUE})
    return run_guard(home, agents_path, dispatch(prompt=f"issue: {GOOD}\nwork", tracked=False), bin_dir)


def test_the_verdict_is_emitted_before_the_cache_is_written(
    _private_home: Path,
    agents: Path,  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    order: list[str] = []
    real_emit, real_store = hooks_mod.emit, tracking.cache_store

    def emit(*args: Any, **kwargs: Any) -> Any:
        order.append("emit")
        return real_emit(*args, **kwargs)

    def store(*args: Any, **kwargs: Any) -> None:
        order.append("store")
        real_store(*args, **kwargs)

    monkeypatch.setattr(hooks_mod, "emit", emit)
    monkeypatch.setattr(tracking, "cache_store", store)
    # A different rule denies this brief (the local LLM is reachable and the brief names no local step), so a line is
    # written; the issue is open, so a cache write is queued as well.
    set_mode(_private_home, "block")
    set_probe(_private_home, reachable=True, agents=agents)
    bin_dir = stand_in_gh(tmp_path, {"12": OPEN_ISSUE})
    out, _log = run_guard(_private_home, agents, dispatch(prompt=f"issue: {GOOD}\nwork", tracked=False), bin_dir)
    assert "deny" in out and order == ["emit", "store"]


def test_a_store_that_raises_does_not_change_the_verdict(
    _private_home: Path,
    agents: Path,  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("store exploded")

    monkeypatch.setattr(tracking, "cache_store", boom)
    out, log = guard_once(_private_home, agents, tmp_path)
    assert out == "" and log[-1]["decision"] == "allow"


def test_a_store_that_blocks_cannot_hold_the_hook_past_its_limit(
    _private_home: Path,
    agents: Path,  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = threading.Event()
    monkeypatch.setattr(tracking, "cache_store", lambda *a, **k: release.wait(30))
    monkeypatch.setattr(hooks_mod, "GUARD_TIMEOUT_SECONDS", 3)
    began = time.monotonic()
    try:
        out, _log = guard_once(_private_home, agents, tmp_path)
    finally:
        release.set()
    assert out == "", "the allow was delivered"
    assert time.monotonic() - began < 3.5, "the blocked store was cut off at the hook's own limit"
