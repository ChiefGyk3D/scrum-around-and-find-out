# SPDX-License-Identifier: Apache-2.0
"""Round 2 of #356 (review findings 1-9): account scope, queued re-check, global write spacing, ledger failure,
private directories, bounded persisted times, duplicate and malformed headers, option grammar, invalid UTF-8."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from safo import ratebudget as rb
from test_ratebudget import OK, T0, Clock, Harness, budget, counter, done, http

DIR = ".local/state/safo/ratebudget"
GH = "/usr/bin/gh"


# 1. counters are scoped to host and credential


def scope(env: dict[str, str], argv: list[str] | None = None) -> str:
    return rb.scope_for(env, argv or ["api", "x"], subprocess.run, GH)


def test_scope_differs_by_credential_and_host_and_hides_the_credential() -> None:
    a = scope({"GH_TOKEN": "cred-A"})
    b = scope({"GH_TOKEN": "cred-B"})
    c = scope({"GH_TOKEN": "cred-A"}, ["api", "--hostname", "ghe.example", "x"])
    d = scope({"GH_TOKEN": "cred-A", "GH_HOST": "ghe.example"})
    assert len({a, b, c}) == 3
    assert c == d
    assert "cred-A" not in a
    assert len(a) <= 24


def test_scope_falls_back_to_gh_auth_token() -> None:
    seen: list[list[str]] = []

    def run(argv: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        seen.append(argv)
        return done("cred-from-gh\n")

    got = rb.scope_for({}, ["api", "x"], run, GH)
    assert seen == [[GH, "auth", "token", "--hostname", "github.com"]]
    assert got == rb.scope_for({"GH_TOKEN": "cred-from-gh"}, ["api", "x"], run, GH)


def test_scope_survives_a_failing_gh() -> None:
    def run(argv: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        raise OSError("no gh")

    assert rb.scope_for({}, ["api", "x"], run, GH)


def test_one_account_cannot_overwrite_or_poison_another(tmp_path: Path) -> None:
    a = rb.Budget(tmp_path / "rb", Clock(), "acct-a")
    b = rb.Budget(tmp_path / "rb", Clock(), "acct-b")
    a.observe([counter(remaining=0)])
    b.observe([counter(remaining=5000)])
    assert a.reserve("core", write=False).action == "refuse"  # B's healthy answer did not wash A's
    assert b.reserve("core", write=False).action == "go"
    b.observe([counter(remaining=0, reset=T0 + 500)])
    assert rb.Budget(tmp_path / "rb", Clock(), "acct-c").reserve("core", write=False).action == "go"


def test_blocks_and_write_slots_are_per_account(tmp_path: Path) -> None:
    a = rb.Budget(tmp_path / "rb", Clock(), "acct-a")
    b = rb.Budget(tmp_path / "rb", Clock(), "acct-b")
    a.block("core", 30)
    a.reserve("core", write=True)
    assert b.reserve("core", write=True).wait == 0
    assert b.reserve("core", write=False).action == "go"
    assert a.reserve("core", write=False).action == "refuse"


def test_wrapper_keeps_accounts_apart_and_writes_no_credential(tmp_path: Path) -> None:
    h = Harness(tmp_path, http("200 OK", {**OK, "x-ratelimit-remaining": "0"}, "{}"))
    h.go(["api", "repos/o/r"])
    assert h.go(["api", "repos/o/r"]) == rb.EXIT_THROTTLED
    h.cred = "another-account-credential"
    h.reply = http("200 OK", OK, "{}")
    assert h.go(["api", "repos/o/r"]) == 0  # the other account has its own budget
    for f in (tmp_path / DIR).iterdir():
        data = f.read_bytes()
        assert b"t0-credential" not in data
        assert b"another-account-credential" not in data


# 2. a queued writer re-checks before it launches


def test_queued_writer_rechecks_a_block_installed_while_it_slept(tmp_path: Path) -> None:
    h = Harness(tmp_path, http("200 OK", OK, "{}"))
    h.go(["api", "-X", "PATCH", "repos/o/r/issues/1", "-f", "a=b"])  # takes the first slot
    h.on_sleep = lambda _s: h.ledger.block("core", 60)  # another process hits a secondary limit meanwhile
    h.calls.clear()
    assert h.go(["api", "-X", "PATCH", "repos/o/r/issues/2", "-f", "a=b"]) == rb.EXIT_THROTTLED
    assert h.calls == []
    assert "retry after" in h.err.getvalue()


def test_confirm_does_not_take_a_new_slot(tmp_path: Path) -> None:
    b = budget(tmp_path)
    b.reserve("core", write=True)
    assert b.confirm("core").action == "go"
    assert b.reserve("core", write=True).wait == pytest.approx(1)  # confirm() added no queue entry


# 3. write spacing is global


def test_write_spacing_is_global_across_buckets(tmp_path: Path) -> None:
    b = budget(tmp_path)
    assert b.reserve("core", write=True).wait == 0
    assert b.reserve("graphql", write=True).wait == pytest.approx(1)
    assert b.reserve("search", write=True).wait == pytest.approx(2)


# 4. a failing audit append keeps the counters


def test_a_failing_ledger_append_does_not_lose_the_counters(tmp_path: Path) -> None:
    h = Harness(tmp_path, http("200 OK", OK, "{}"))
    h.go(["api", "repos/o/r"])  # creates the directory
    (tmp_path / DIR / "ledger.jsonl").unlink()
    (tmp_path / DIR / "ledger.jsonl").mkdir()  # the audit log can no longer be appended
    h.reply = http("200 OK", {**OK, "x-ratelimit-remaining": "0"}, "{}")
    assert h.go(["api", "repos/o/r"]) == 0
    assert h.err.getvalue().count("could not be written") == 1
    assert h.ledger.headroom("core").level == "throttle"
    assert h.go(["api", "repos/o/r"]) == rb.EXIT_THROTTLED


# 5. the state directory is private, and files in it are not followed


def test_an_existing_group_writable_directory_is_repaired(tmp_path: Path) -> None:
    d = tmp_path / "rb"
    d.mkdir()
    d.chmod(0o777)
    rb.Budget(d, Clock()).observe([counter()])
    assert (d.stat().st_mode & 0o077) == 0


def test_lock_that_is_a_symlink_is_refused(tmp_path: Path) -> None:
    d = tmp_path / "rb"
    b = rb.Budget(d, Clock())
    b.observe([counter()])
    (d / "lock").unlink()
    (d / "lock").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(OSError):
        b.observe([counter()])


def test_state_file_that_is_a_symlink_is_not_followed(tmp_path: Path) -> None:
    d = tmp_path / "rb"
    b = rb.Budget(d, Clock())
    b.observe([counter(remaining=0)])
    (d / "state.json").rename(tmp_path / "moved.json")
    (d / "state.json").symlink_to(tmp_path / "moved.json")
    assert b.headroom("core").level == "ok"  # a symlinked state is no state


def test_ledger_that_is_a_symlink_is_not_appended_to(tmp_path: Path) -> None:
    d = tmp_path / "rb"
    b = rb.Budget(d, Clock())
    b.record(caller="a", bucket="core", klass="x", write=False, status=200)
    (d / "ledger.jsonl").unlink()
    target = tmp_path / "victim.txt"
    target.write_text("keep\n")
    (d / "ledger.jsonl").symlink_to(target)
    with pytest.raises(OSError):
        b.record(caller="a", bucket="core", klass="x", write=False, status=200)
    assert target.read_text() == "keep\n"


def test_write_private_repairs_and_writes(tmp_path: Path) -> None:
    d = tmp_path / "plain"
    d.mkdir()
    d.chmod(0o775)
    rb.write_private(d / "f.json", b"{}")
    assert (d.stat().st_mode & 0o077) == 0
    assert ((d / "f.json").stat().st_mode & 0o077) == 0


# 7. persisted times are bounded


def test_a_far_future_reset_in_state_is_corrupt_not_a_throttle(tmp_path: Path) -> None:
    b = budget(tmp_path)
    b.observe([counter(remaining=0)])
    state = json.loads((b.directory / "state.json").read_text())
    for entry in state["counters"].values():
        entry["reset"] = 4_000_000_000
    state["blocked"] = {"local|core": 4_000_000_000}
    state["last_write"] = {"local|*": 4_000_000_000}
    (b.directory / "state.json").write_text(json.dumps(state))
    assert b.headroom("core").level == "ok"
    for _ in range(3):
        assert b.reserve("core", write=True).action == "go"


def test_a_hostile_observation_with_a_far_reset_is_dropped(tmp_path: Path) -> None:
    b = budget(tmp_path)
    b.observe([counter(remaining=0, reset=4_000_000_000)])
    assert b.reserve("core", write=False).action == "go"
    assert json.loads((b.directory / "state.json").read_text())["counters"] == {}  # not even stored


# 8. duplicate and malformed headers


def parse(text: str) -> dict[str, str]:
    return rb._split_response(text)[1]


def test_duplicate_rate_limit_header_rejects_the_observation() -> None:
    text = "HTTP/2.0 200 OK\r\nx-ratelimit-limit: 5000\r\nx-ratelimit-remaining: 0\r\n"
    text += "x-ratelimit-remaining: 5000\r\nx-ratelimit-reset: 1800000600\r\n\r\n{}"
    assert rb.counters_from_headers(parse(text), "core") == []


@pytest.mark.parametrize(
    "line",
    [" x-folded: 1", "\tcontinued", "x-ratelimit-remaining : 0", "bad name: 1", "no colon here", "x@y: 1"],
)
def test_obs_fold_and_malformed_names_reject_the_rate_limit_headers(line: str) -> None:
    text = "HTTP/2.0 200 OK\r\nx-ratelimit-limit: 5000\r\nx-ratelimit-remaining: 10\r\n"
    text += f"x-ratelimit-reset: 1800000600\r\nretry-after: 5\r\n{line}\r\n\r\n{{}}"
    headers = parse(text)
    assert rb.counters_from_headers(headers, "core") == []
    assert "retry-after" not in headers


def test_a_clean_block_is_still_read() -> None:
    assert rb.counters_from_headers(parse(http("200 OK", OK, "{}")), "core")


def test_duplicate_retry_after_on_429_still_blocks(tmp_path: Path) -> None:
    reply = "HTTP/2.0 429 Too Many Requests\r\nretry-after: 1\r\nretry-after: 2\r\n\r\n{}"
    h = Harness(tmp_path, reply, code=1)
    h.go(["api", "repos/o/r"])
    assert h.ledger.headroom("core").retry_after == pytest.approx(rb.SECONDARY_WAIT)


# 9. option grammar


@pytest.mark.parametrize(
    "argv",
    [
        ["api", "-XPATCH", "repos/o/r/issues/1"],
        ["api", "-X=PATCH", "repos/o/r/issues/1"],
        ["api", "-xPATCH", "repos/o/r/issues/1"],
        ["api", "--no-such-flag", "repos/o/r/issues/1"],
        ["api", "-fa=b", "repos/o/r/issues/1"],
        ["api", "-HAccept:x", "repos/o/r/issues/1"],
    ],
)
def test_compact_or_unknown_option_forms_count_as_writes(argv: list[str]) -> None:
    assert rb.classify(argv).write


@pytest.mark.parametrize(
    "argv",
    [
        ["api", "repos/o/r/issues/1"],
        ["api", "-X", "GET", "repos/o/r/issues/1"],
        ["api", "--method=GET", "repos/o/r/issues/1"],
        ["api", "-H", "Accept: x", "--hostname", "h", "repos/o/r"],
    ],
)
def test_ordinary_reads_stay_reads(argv: list[str]) -> None:
    assert not rb.classify(argv).write


# invalid UTF-8 from gh


def test_invalid_utf8_from_gh_is_an_unknown_outcome(tmp_path: Path) -> None:
    h = Harness(tmp_path, "")
    h.fail = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")
    assert h.go(["api", "-X", "PATCH", "repos/o/r/issues/1", "-f", "a=b"]) == rb.EXIT_UNKNOWN_OUTCOME
    assert "outcome unknown" in h.err.getvalue()
    assert len(h.calls) == 1
    assert h.ledger.rows()[0]["status"] == 0
