# SPDX-License-Identifier: Apache-2.0
"""The rate-budget ledger and the gh wrapper: thresholds, the minimum rule, Retry-After, rollover, concurrency.

Nothing here runs gh or touches the network: the wrapper's `run` and `sleep` are stubs, and the state lives in tmp_path.
"""

from __future__ import annotations

import io
import json
import multiprocessing
import subprocess
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from safo import ratebudget as rb

T0 = 1_800_000_000.0


class Clock:
    def __init__(self, now: float = T0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def budget(tmp_path: Path, clock: Clock | None = None) -> rb.Budget:
    return rb.Budget(tmp_path / "rb", clock or Clock())


def counter(
    bucket: str = "core", source: str = "header", limit: int = 5000, remaining: int = 5000, reset: float = T0 + 600
) -> rb.Counter:
    return rb.Counter(f"{bucket}/{source}", bucket, limit, remaining, reset)


# thresholds


def test_below_warn_is_ok(tmp_path: Path) -> None:
    b = budget(tmp_path)
    b.observe([counter(remaining=2000)])  # 60% used
    assert b.headroom("core").level == "ok"


def test_warn_at_seventy_percent(tmp_path: Path) -> None:
    b = budget(tmp_path)
    b.observe([counter(remaining=1500)])  # exactly 70% used
    assert b.headroom("core").level == "warn"


def test_throttle_at_ninety_percent(tmp_path: Path) -> None:
    b = budget(tmp_path)
    b.observe([counter(remaining=500)])
    head = b.headroom("core")
    assert head.level == "throttle"
    assert head.retry_after == pytest.approx(600)
    decision = b.reserve("core", write=False)
    assert decision.action == "refuse"
    assert "600" in decision.message


def test_just_under_throttle_goes(tmp_path: Path) -> None:
    b = budget(tmp_path)
    b.observe([counter(remaining=501)])
    assert b.reserve("core", write=False).action == "go"


# the minimum rule: two counters for one bucket, the worse one is the truth


def test_minimum_across_counters_is_the_truth(tmp_path: Path) -> None:
    b = budget(tmp_path)
    b.observe([counter("graphql", "endpoint", remaining=4900), counter("graphql", "header", remaining=100)])
    head = b.headroom("graphql")
    assert head.level == "throttle"
    assert head.min_remaining == 100
    assert head.counter == "graphql/header"


def test_endpoint_alone_would_have_said_fine(tmp_path: Path) -> None:
    b = budget(tmp_path)
    b.observe([counter("graphql", "endpoint", remaining=4900)])
    assert b.headroom("graphql").level == "ok"
    b.observe([counter("graphql", "header", remaining=100)])
    assert b.headroom("graphql").level == "throttle"


def test_buckets_are_independent(tmp_path: Path) -> None:
    b = budget(tmp_path)
    b.observe([counter("graphql", remaining=10), counter("core", remaining=4000)])
    assert b.reserve("core", write=False).action == "go"
    assert b.reserve("graphql", write=False).action == "refuse"


# reset rollover


def test_counter_rolls_over_at_reset(tmp_path: Path) -> None:
    clock = Clock()
    b = budget(tmp_path, clock)
    b.observe([counter(remaining=0, reset=T0 + 60)])
    assert b.reserve("core", write=False).action == "refuse"
    clock.now = T0 + 61
    assert b.headroom("core").level == "ok"
    assert b.reserve("core", write=False).action == "go"


def test_newer_observation_replaces_older(tmp_path: Path) -> None:
    b = budget(tmp_path)
    b.observe([counter(remaining=0)])
    b.observe([counter(remaining=4000)])
    assert b.headroom("core").level == "ok"


# Retry-After


@pytest.mark.parametrize(
    ("value", "expected"),
    [("30", 30.0), ("0", 0.0), (" 5 ", 5.0), ("99999999", rb.MAX_WAIT)],
)
def test_retry_after_seconds(value: str, expected: float) -> None:
    assert rb.parse_retry_after(value, T0) == expected


@pytest.mark.parametrize("value", ["nan", "inf", "-inf", "-3", "", "soon", "1e400", "\x00"])
def test_retry_after_rejects_junk(value: str) -> None:
    assert rb.parse_retry_after(value, T0) is None


def test_retry_after_http_date() -> None:
    assert rb.parse_retry_after("Sun, 15 Nov 2026 08:00:00 GMT", 1_794_729_540.0) == pytest.approx(60)


def test_retry_after_blocks_the_bucket_until_it_passes(tmp_path: Path) -> None:
    clock = Clock()
    b = budget(tmp_path, clock)
    b.block("graphql", 45)
    decision = b.reserve("graphql", write=False)
    assert decision.action == "refuse"
    assert decision.wait == pytest.approx(45)
    assert b.reserve("core", write=False).action == "go"
    clock.now = T0 + 46
    assert b.reserve("graphql", write=False).action == "go"


# write spacing


def test_writes_are_spaced_one_second(tmp_path: Path) -> None:
    b = budget(tmp_path)
    first = b.reserve("graphql", write=True)
    second = b.reserve("graphql", write=True)
    third = b.reserve("graphql", write=True)
    assert first.wait == 0
    assert second.wait == pytest.approx(1)
    assert third.wait == pytest.approx(2)


def test_reads_are_not_spaced(tmp_path: Path) -> None:
    b = budget(tmp_path)
    b.reserve("core", write=True)
    assert b.reserve("core", write=False).wait == 0


def test_concurrent_writers_get_distinct_slots(tmp_path: Path) -> None:
    waits: list[float] = []
    lock = threading.Lock()

    def work() -> None:
        # a separate Budget object per thread: separate file descriptors, as separate processes would have
        decision = budget(tmp_path).reserve("core", write=True)
        with lock:
            waits.append(decision.wait)

    threads = [threading.Thread(target=work) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(round(w, 3) for w in waits) == [float(i) for i in range(12)]


def _append(args: tuple[str, int]) -> None:
    directory, who = args
    b = rb.Budget(Path(directory))
    for _ in range(25):
        b.record(caller=f"p{who}", bucket="core", klass="repos/*/*/issues/#", write=False, status=200)


def _frozen() -> float:
    return T0


def _claim(directory: str) -> list[float]:
    b = rb.Budget(Path(directory), _frozen)
    return [b.reserve("core", write=True).wait for _ in range(10)]


def test_concurrent_processes_get_distinct_write_slots(tmp_path: Path) -> None:
    ctx = multiprocessing.get_context("spawn")
    with ctx.Pool(4) as pool:
        got = pool.map(_claim, [str(tmp_path / "rb")] * 4)
    assert sorted(round(w, 3) for waits in got for w in waits) == [float(i) for i in range(40)]


def test_concurrent_processes_lose_no_ledger_line(tmp_path: Path) -> None:
    ctx = multiprocessing.get_context("spawn")
    with ctx.Pool(4) as pool:
        pool.map(_append, [(str(tmp_path / "rb"), n) for n in range(4)])
    rows = rb.Budget(tmp_path / "rb").rows()
    assert len(rows) == 100
    assert {r["caller"] for r in rows} == {"p0", "p1", "p2", "p3"}


# header parsing


def test_headers_to_counters() -> None:
    headers = {
        "x-ratelimit-limit": "5000",
        "x-ratelimit-remaining": "4990",
        "x-ratelimit-reset": "1800000600",
        "x-ratelimit-resource": "graphql",
    }
    got = rb.counters_from_headers(headers, "core")
    assert got == [rb.Counter("graphql/header", "graphql", 5000, 4990, 1_800_000_600.0)]


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"x-ratelimit-limit": "nan", "x-ratelimit-remaining": "1", "x-ratelimit-reset": "5"},
        {"x-ratelimit-limit": "0", "x-ratelimit-remaining": "0", "x-ratelimit-reset": "5"},
        {"x-ratelimit-limit": "5000", "x-ratelimit-remaining": "-1", "x-ratelimit-reset": "5"},
        {"x-ratelimit-limit": "5000", "x-ratelimit-remaining": "9999", "x-ratelimit-reset": "5"},
        {"x-ratelimit-limit": "5000", "x-ratelimit-remaining": "1"},
        {
            "x-ratelimit-limit": "5000",
            "x-ratelimit-remaining": "1",
            "x-ratelimit-reset": "5",
            "x-ratelimit-resource": "a/b",
        },
    ],
)
def test_bad_headers_give_no_counter(headers: dict[str, str]) -> None:
    assert rb.counters_from_headers(headers, "core") == []


def test_rate_limit_endpoint_body() -> None:
    body = json.dumps(
        {"resources": {"core": {"limit": 5000, "remaining": 10, "reset": 1_800_000_100}, "bad": {"limit": "x"}}}
    )
    assert rb.counters_from_rate_limit(body.encode()) == [
        rb.Counter("core/endpoint", "core", 5000, 10, 1_800_000_100.0)
    ]


def test_rate_limit_body_garbage_is_empty() -> None:
    assert rb.counters_from_rate_limit(b"[[[[") == []
    assert rb.counters_from_rate_limit(b"{" * 100 + b"}" * 100) == []
    assert rb.counters_from_rate_limit(b'{"resources": {"core": {"limit": 1}, "core": {"limit": 2}}}') == []


# classification


@pytest.mark.parametrize(
    ("argv", "bucket", "write"),
    [
        (["api", "repos/o/r/issues/5"], "core", False),
        (["api", "-X", "PATCH", "repos/o/r/issues/5", "-f", "state=closed"], "core", True),
        (["api", "repos/o/r/issues", "-f", "title=x"], "core", True),
        (["api", "graphql", "-f", "query=query { viewer { login } }"], "graphql", False),
        (["api", "graphql", "-f", "query=mutation { x }"], "graphql", True),
        (["api", "-H", "Accept: x", "search/issues?q=a"], "search", False),
        (["project", "item-list", "3"], "graphql", False),
        (["issue", "view", "5"], "graphql", False),
        (["issue", "close", "5"], "graphql", True),
    ],
)
def test_classify(argv: list[str], bucket: str, write: bool) -> None:
    got = rb.classify(argv)
    assert (got.bucket, got.write) == (bucket, write)


def test_endpoint_class_drops_ids() -> None:
    assert rb.classify(["api", "repos/ChiefGyk3D/safo/issues/356/comments"]).klass == "repos/*/*/issues/#/comments"


def test_rate_limit_endpoint_is_free() -> None:
    assert rb.classify(["api", "rate_limit"]).free


# the wrapper


def done(stdout: str, code: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], code, stdout, "")


def http(status: str, headers: dict[str, str], body: str) -> str:
    return f"HTTP/2.0 {status}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n" + body


class Harness:
    def __init__(self, tmp_path: Path, reply: str = "", code: int = 0) -> None:
        self.clock = Clock()
        self.calls: list[list[str]] = []
        self.slept: list[float] = []
        self.reply = reply
        self.code = code
        self.out = io.StringIO()
        self.err = io.StringIO()
        self.tmp = tmp_path
        self.cred = "t0-credential"
        self.fail: Exception | None = None
        self.on_sleep: Callable[[float], None] | None = None

    def run(self, argv: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv)
        if self.fail is not None:
            raise self.fail
        return done(self.reply, self.code)

    @property
    def env(self) -> dict[str, str]:
        return {"HOME": str(self.tmp), "SAFO_CALLER": "agent-a", "PATH": "/usr/bin", "GH_TOKEN": self.cred}

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        if self.on_sleep:
            self.on_sleep(seconds)

    def go(self, argv: list[str], caller: str = "agent-a") -> int:
        env = {**self.env, "SAFO_CALLER": caller}
        return rb.main(
            argv,
            env=env,
            out=self.out,
            err=self.err,
            run=self.run,
            sleep=self.sleep,
            clock=self.clock,
            gh="/usr/bin/gh",
        )

    @property
    def ledger(self) -> rb.Budget:
        scope = rb.scope_for(self.env, ["api", "x"], self.run, "/usr/bin/gh")
        return rb.Budget(self.tmp / ".local" / "state" / "safo" / "ratebudget", self.clock, scope)


OK = {
    "x-ratelimit-limit": "5000",
    "x-ratelimit-remaining": "4000",
    "x-ratelimit-reset": str(int(T0) + 600),
    "x-ratelimit-resource": "core",
}


def test_wrapper_injects_include_strips_headers_and_records(tmp_path: Path) -> None:
    h = Harness(tmp_path, http("200 OK", OK, '{"n": 5}'))
    assert h.go(["api", "repos/o/r/issues/5"]) == 0
    assert h.calls == [["/usr/bin/gh", "api", "--include", "repos/o/r/issues/5"]]
    assert h.out.getvalue() == '{"n": 5}'
    rows = h.ledger.rows()
    assert [(r["caller"], r["bucket"], r["status"]) for r in rows] == [("agent-a", "core", 200)]
    assert h.ledger.headroom("core").min_remaining == 4000


def test_wrapper_refuses_when_throttled_without_calling_gh(tmp_path: Path) -> None:
    h = Harness(tmp_path, http("200 OK", {**OK, "x-ratelimit-remaining": "100"}, "{}"))
    h.go(["api", "repos/o/r"])
    h.calls.clear()
    assert h.go(["api", "repos/o/r"]) == rb.EXIT_THROTTLED
    assert h.calls == []
    assert "retry after" in h.err.getvalue()


def test_wrapper_warns_at_seventy_percent_but_goes(tmp_path: Path) -> None:
    h = Harness(tmp_path, http("200 OK", {**OK, "x-ratelimit-remaining": "1400"}, "{}"))
    h.go(["api", "repos/o/r"])
    h.err.truncate(0)
    h.err.seek(0)
    assert h.go(["api", "repos/o/r"]) == 0
    assert "WARNING" in h.err.getvalue()
    assert "core" in h.err.getvalue()


def test_wrapper_spaces_writes(tmp_path: Path) -> None:
    h = Harness(tmp_path, http("200 OK", OK, "{}"))
    h.go(["api", "-X", "PATCH", "repos/o/r/issues/5", "-f", "state=open"])
    h.go(["api", "-X", "PATCH", "repos/o/r/issues/6", "-f", "state=open"])
    assert h.slept == [pytest.approx(1)]


def test_wrapper_honors_retry_after_on_429(tmp_path: Path) -> None:
    h = Harness(tmp_path, http("429 Too Many Requests", {"retry-after": "30"}, '{"message":"x"}'), code=1)
    assert h.go(["api", "repos/o/r"]) == 1
    h.calls.clear()
    h.clock.now += 10
    assert h.go(["api", "repos/o/r"]) == rb.EXIT_THROTTLED
    assert "20" in h.err.getvalue()
    assert h.calls == []
    h.clock.now += 25
    h.reply = http("200 OK", OK, "{}")
    h.code = 0
    assert h.go(["api", "repos/o/r"]) == 0


def test_wrapper_secondary_limit_without_header_waits_a_minute(tmp_path: Path) -> None:
    body = '{"message":"You have exceeded a secondary rate limit. Please wait a few minutes"}'
    h = Harness(tmp_path, http("403 Forbidden", {}, body), code=1)
    h.go(["api", "repos/o/r"])
    assert h.ledger.headroom("core").retry_after == pytest.approx(60)


def test_wrapper_does_not_replay_a_failed_call(tmp_path: Path) -> None:
    h = Harness(tmp_path, http("502 Bad Gateway", {}, ""), code=1)
    h.go(["api", "-X", "POST", "repos/o/r/issues", "-f", "title=x"])
    assert len(h.calls) == 1


def test_wrapper_rate_limit_endpoint_is_not_counted_or_blocked(tmp_path: Path) -> None:
    h = Harness(tmp_path, "{}")
    h.ledger.observe([counter(remaining=0)])
    assert h.go(["api", "rate_limit"]) == 0
    assert h.ledger.rows() == []
    assert h.calls == [["/usr/bin/gh", "api", "rate_limit"]]


def test_wrapper_leaves_jq_calls_alone(tmp_path: Path) -> None:
    h = Harness(tmp_path, "5\n")
    assert h.go(["api", "repos/o/r/issues/5", "--jq", ".number"]) == 0
    assert h.calls == [["/usr/bin/gh", "api", "repos/o/r/issues/5", "--jq", ".number"]]
    assert h.out.getvalue() == "5\n"
    assert h.ledger.rows()[0]["bucket"] == "core"


def test_wrapper_non_api_command_is_recorded(tmp_path: Path) -> None:
    h = Harness(tmp_path, "ok\n")
    assert h.go(["project", "item-list", "3"]) == 0
    assert h.ledger.rows()[0]["bucket"] == "graphql"


def test_wrapper_unreadable_headers_do_not_crash(tmp_path: Path) -> None:
    h = Harness(tmp_path, "HTTP/2.0 200 OK\r\nx-ratelimit-limit: nan\r\n\r\n{}")
    assert h.go(["api", "repos/o/r"]) == 0
    assert h.ledger.headroom("core").level == "ok"


# reports


def test_report_by_caller_and_status_line(tmp_path: Path) -> None:
    h = Harness(tmp_path, http("200 OK", {**OK, "x-ratelimit-remaining": "1000"}, "{}"))
    h.go(["api", "repos/o/r"], caller="agent-a")
    h.go(["api", "repos/o/r"], caller="agent-a")
    h.go(["api", "-X", "PATCH", "repos/o/r/issues/1", "-f", "a=b"], caller="agent-b")
    report = h.ledger.by_caller()
    assert report["agent-a"]["core"] == {"calls": 2, "writes": 0}
    assert report["agent-b"]["core"] == {"calls": 1, "writes": 1}
    line = h.ledger.status_line()
    assert line.startswith("ratebudget:")
    assert "core 80%" in line
    assert "WARN" in line
    cache = h.ledger.directory / "statusline.txt"
    assert cache.read_text().strip() == line


def test_status_line_with_nothing_known(tmp_path: Path) -> None:
    assert budget(tmp_path).status_line() == "ratebudget: no calls recorded"


def test_caller_name_is_sanitised(tmp_path: Path) -> None:
    h = Harness(tmp_path, http("200 OK", OK, "{}"))
    h.go(["api", "repos/o/r"], caller="evil\n::set-output x\x1b[31m")
    caller = h.ledger.rows()[0]["caller"]
    assert "\n" not in caller
    assert "\x1b" not in caller
    assert "::" not in caller


def test_corrupt_state_is_survivable(tmp_path: Path) -> None:
    b = budget(tmp_path)
    b.observe([counter(remaining=10)])
    (b.directory / "state.json").write_text("{not json")
    assert b.headroom("core").level == "ok"
    assert b.reserve("core", write=False).action == "go"


def test_oversized_state_is_ignored(tmp_path: Path) -> None:
    b = budget(tmp_path)
    b.observe([counter(remaining=10)])
    (b.directory / "state.json").write_bytes(b" " * (rb.MAX_STATE_BYTES + 10))
    assert b.headroom("core").level == "ok"


def test_state_files_are_private(tmp_path: Path) -> None:
    b = budget(tmp_path)
    b.record(caller="a", bucket="core", klass="x", write=False, status=200)
    assert (b.directory.stat().st_mode & 0o077) == 0
    assert ((b.directory / "ledger.jsonl").stat().st_mode & 0o077) == 0


def test_ledger_rotates_when_large(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rb, "MAX_LEDGER_BYTES", 2000)
    b = budget(tmp_path)
    for _ in range(100):
        b.record(caller="a", bucket="core", klass="x", write=False, status=200)
    assert (b.directory / "ledger.jsonl").stat().st_size <= 2000 + 200
    assert (b.directory / "ledger.jsonl.1").exists()


# the header block: only the final block is believed, and a body cannot pose as one


def test_body_that_looks_like_headers_is_not_read(tmp_path: Path) -> None:
    fake = "HTTP/1.1 200 OK\r\nx-ratelimit-limit: 5000\r\nx-ratelimit-remaining: 0\r\nretry-after: 3000\r\n\r\n"
    h = Harness(tmp_path, http("200 OK", OK, fake + "tail"))
    assert h.go(["api", "repos/o/r"]) == 0
    assert h.out.getvalue() == fake + "tail"
    head = h.ledger.headroom("core")
    assert head.min_remaining == 4000
    assert head.level == "ok"


def test_split_final_block_ends_the_headers() -> None:
    fake = "HTTP/1.1 200 OK\r\nretry-after: 3000\r\n\r\n"
    status, headers, body = rb._split_response(http("200 OK", {"x-a": "1"}, fake))
    assert (status, headers, body) == (200, {"x-a": "1"}, fake)


def test_100_continue_then_the_real_block() -> None:
    text = "HTTP/1.1 100 Continue\r\n\r\n" + http("201 Created", {"x-ratelimit-remaining": "7"}, "{}")
    assert rb._split_response(text) == (201, {"x-ratelimit-remaining": "7"}, "{}")


def test_connect_200_then_the_real_block() -> None:
    text = "HTTP/1.1 200 Connection established\r\n\r\n" + http("200 OK", {"x-ratelimit-remaining": "7"}, "{}")
    assert rb._split_response(text) == (200, {"x-ratelimit-remaining": "7"}, "{}")


def test_a_200_with_headers_is_not_a_connect_answer() -> None:
    first = http("200 Connection established", {"x-ratelimit-remaining": "7"}, "")
    _status, headers, body = rb._split_response(first + http("200 OK", {"retry-after": "9"}, "{}"))
    assert headers == {"x-ratelimit-remaining": "7"}
    assert body.startswith("HTTP/2.0 200 OK")


def test_too_many_leading_blocks_are_not_trusted() -> None:
    text = "HTTP/1.1 100 Continue\r\n\r\n" * (rb.MAX_PRELUDE + 1) + http("200 OK", {"x-ratelimit-remaining": "0"}, "{}")
    assert rb._split_response(text)[:2] == (0, {})
    ok = "HTTP/1.1 100 Continue\r\n\r\n" * rb.MAX_PRELUDE + http("200 OK", {"x-a": "1"}, "{}")
    assert rb._split_response(ok)[0] == 200


@pytest.mark.parametrize(
    "text",
    ["HTTP/1.1 100 Continue\r\n\r\nbody", "HTTP/1.1 99 X\r\n\r\nb", "HTTP/1.1 600 X\r\n\r\nb", "HTTP/1.1 abc\r\n\r\nb"],
)
def test_odd_status_gives_no_headers(text: str) -> None:
    assert rb._split_response(text) == (0, {}, text)
