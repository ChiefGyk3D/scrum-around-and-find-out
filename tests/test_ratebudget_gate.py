# SPDX-License-Identifier: Apache-2.0
"""#367 (the launch gate) and #368 (a hostile identity cache must fail open)."""

from __future__ import annotations

import fcntl
import json
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from safo import ratebudget as rb
from test_ratebudget import OK, T0, Clock, Harness, budget, done, http

DIR = ".local/state/safo/ratebudget"
WRITE = ["api", "-X", "PATCH", "repos/o/r/issues/1", "-f", "a=b"]


def lock_is_held(directory: Path) -> bool:
    """True when another descriptor cannot take the per-account lock right now."""
    fd = (directory / "lock").open("a")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        fd.close()


# 367: the gate


def test_a_paused_first_ticket_cannot_launch_right_behind_the_second(tmp_path: Path) -> None:
    clock = Clock()
    b = budget(tmp_path, clock)
    first = b.reserve("core", write=True)  # slot T0
    second = b.reserve("core", write=True)  # slot T0 + 1
    assert first.wait == 0
    assert second.wait == pytest.approx(1)
    launched: list[float] = []

    def start() -> str:
        launched.append(clock.now)
        return "child"

    def sleep(seconds: float) -> None:
        clock.now += seconds

    clock.now = T0 + 1.0  # the second ticket wakes on time and goes
    b.launch_gate(start, sleep)
    clock.now = T0 + 1.2  # the first ticket was descheduled past the second's slot
    b.launch_gate(start, sleep)
    assert launched == [pytest.approx(T0 + 1.0), pytest.approx(T0 + 2.0)]
    assert launched[1] - launched[0] >= rb.WRITE_SPACING


def test_the_gate_waits_from_the_last_actual_launch(tmp_path: Path) -> None:
    clock = Clock()
    b = budget(tmp_path, clock)
    b.launch_gate(lambda: None, lambda s: None)  # a launch at T0
    clock.now = T0 + 0.4
    slept: list[float] = []

    def sleep(seconds: float) -> None:
        slept.append(seconds)
        clock.now += seconds

    b.launch_gate(lambda: None, sleep)
    assert slept == [pytest.approx(0.6)]


def test_the_gate_records_the_real_launch_time(tmp_path: Path) -> None:
    clock = Clock()
    b = budget(tmp_path, clock)

    def start() -> None:
        clock.now += 0.3  # spawning took a while

    b.launch_gate(start, lambda s: None)
    state = json.loads((b.directory / "state.json").read_text())
    assert state["last_launch"] == {"local|*": pytest.approx(T0 + 0.3, rel=0, abs=1e-6)}


def test_the_child_is_started_while_the_gate_is_held(tmp_path: Path) -> None:
    b = budget(tmp_path)
    seen: list[bool] = []
    b.launch_gate(lambda: seen.append(lock_is_held(b.directory)), lambda s: None)
    assert seen == [True]
    assert not lock_is_held(b.directory)  # and it is released as soon as the start returns


def test_a_failed_spawn_still_counts_as_a_launch(tmp_path: Path) -> None:
    clock = Clock()
    b = budget(tmp_path, clock)

    def boom() -> None:
        raise OSError("exec failed")

    with pytest.raises(OSError, match="exec failed"):
        b.launch_gate(boom, lambda s: None)
    slept: list[float] = []

    def sleep(seconds: float) -> None:
        slept.append(seconds)
        clock.now += seconds

    b.launch_gate(lambda: None, sleep)
    assert slept  # the next one waited: an ambiguous spawn is not free


def test_a_launch_time_in_the_future_is_corrupt_and_does_not_stall(tmp_path: Path) -> None:
    b = budget(tmp_path)
    b.launch_gate(lambda: None, lambda s: None)
    state = json.loads((b.directory / "state.json").read_text())
    state["last_launch"] = {"local|*": T0 + 4_000_000_000}
    (b.directory / "state.json").write_text(json.dumps(state))
    slept: list[float] = []
    b.launch_gate(lambda: None, slept.append)
    assert slept == []


def test_the_gate_gives_up_after_bounded_tries(tmp_path: Path) -> None:
    b = budget(tmp_path)
    b.launch_gate(lambda: None, lambda s: None)
    with pytest.raises(rb.GateBusy):
        b.launch_gate(lambda: None, lambda s: None)  # the clock never moves, so it never becomes ready


def test_a_broken_lock_is_gate_unavailable_and_nothing_started(tmp_path: Path) -> None:
    b = budget(tmp_path)
    b.observe([])
    (b.directory / "lock").unlink()
    (b.directory / "lock").symlink_to(tmp_path / "elsewhere")
    started: list[int] = []
    with pytest.raises(rb.GateUnavailable):
        b.launch_gate(lambda: started.append(1), lambda s: None)
    assert started == []


# 367: the wrapper uses it


def test_wrapper_writes_launch_at_least_a_second_apart(tmp_path: Path) -> None:
    h = Harness(tmp_path, http("200 OK", OK, "{}"))
    h.advance = True
    for _ in range(3):
        assert h.go(WRITE) == 0
    gaps = [b - a for a, b in zip(h.launches, h.launches[1:], strict=False)]
    assert len(h.launches) == 3
    assert all(g >= rb.WRITE_SPACING - 1e-9 for g in gaps)


def test_wrapper_reads_do_not_use_the_gate(tmp_path: Path) -> None:
    h = Harness(tmp_path, http("200 OK", OK, "{}"))
    for _ in range(3):
        h.go(["api", "repos/o/r"])
    assert h.slept == []
    assert json.loads((tmp_path / DIR / "state.json").read_text())["last_launch"] == {}


class Handle:
    def __init__(self, directory: Path, log: list[str]) -> None:
        self.directory, self.log = directory, log

    def wait(self) -> subprocess.CompletedProcess[str]:
        self.log.append("held-while-running" if lock_is_held(self.directory) else "free-while-running")
        return done(http("200 OK", OK, "{}"))


def test_the_gate_is_released_after_the_spawn_not_after_the_child_exits(tmp_path: Path) -> None:
    from io import StringIO

    log: list[str] = []
    directory = tmp_path / DIR

    def launch(command: list[str], stdin: str | None) -> Handle:
        log.append("held-at-spawn" if directory.exists() and lock_is_held(directory) else "free-at-spawn")
        return Handle(directory, log)

    h = Harness(tmp_path)
    h.advance = True
    h.go(WRITE)  # creates the directory and the lock
    log.clear()
    code = rb.main(
        WRITE,
        env=h.env,
        out=StringIO(),
        err=StringIO(),
        run=h.run,
        sleep=h.sleep,
        clock=h.clock,
        gh="/usr/bin/gh",
        launch=launch,
    )
    assert code == 0
    assert log == ["held-at-spawn", "free-while-running"]


def test_wrapper_goes_ahead_when_the_gate_is_unavailable(tmp_path: Path) -> None:
    h = Harness(tmp_path, http("200 OK", OK, "{}"))
    h.go(["api", "repos/o/r"])
    (tmp_path / DIR / "lock").unlink()
    (tmp_path / DIR / "lock").symlink_to(tmp_path / "elsewhere")
    h.err.truncate(0)
    h.err.seek(0)
    assert h.go(WRITE) == 0
    assert len(h.calls) == 2  # launched once, not twice
    assert "unavailable" in h.err.getvalue()


def test_wrapper_refuses_when_the_gate_stays_busy(tmp_path: Path) -> None:
    h = Harness(tmp_path, http("200 OK", OK, "{}"))
    h.go(WRITE)
    h.calls.clear()
    # the sleep stub does not move the clock, so the gate never opens
    code = h.go(WRITE)
    assert code == rb.EXIT_THROTTLED
    assert h.calls == []
    assert "launch gate" in h.err.getvalue()


# 368: a hostile but valid identity cache fails open

SCOPE_ARGS = ["api", "x"]


def put_cache(tmp_path: Path, content: str) -> None:
    d = tmp_path / DIR
    d.mkdir(parents=True, exist_ok=True)
    d.chmod(0o700)
    f = d / "identity.json"
    f.write_text(content)
    f.chmod(0o600)


HOSTILE = [
    '{"ids": {"aaaaaaaaaaaaaaaaaaaa": {"at": "yesterday", "scope": null}}}',
    '{"ids": {"aaaaaaaaaaaaaaaaaaaa": {"at": [1], "scope": null}}}',
    '{"ids": {"aaaaaaaaaaaaaaaaaaaa": {"at": null, "scope": null}}}',
    '{"ids": {"aaaaaaaaaaaaaaaaaaaa": {"at": true, "scope": null}}}',
    '{"ids": {"aaaaaaaaaaaaaaaaaaaa": {"scope": null}}}',
    '{"ids": {"aaaaaaaaaaaaaaaaaaaa": 5}}',
    '{"ids": {"aaaaaaaaaaaaaaaaaaaa": [1, 2]}}',
    '{"ids": {"aaaaaaaaaaaaaaaaaaaa": {"at": 1e999, "scope": null}}}',
    '{"ids": {"aaaaaaaaaaaaaaaaaaaa": {"at": ' + "9" * 400 + ', "scope": null}}}',
    '{"ids": {"aaaaaaaaaaaaaaaaaaaa": {"at": 1, "scope": 7}}}',
    '{"ids": {"aaaaaaaaaaaaaaaaaaaa": {"at": 1, "scope": "not-hex"}}}',
    '{"ids": {"not a key": {"at": 1, "scope": null}}}',
    '{"ids": []}',
    '{"ids": "x"}',
    '{"ids": null}',
    "[]",
    "5",
    "[" * 200 + "]" * 200,
]


@pytest.mark.parametrize("content", HOSTILE)
def test_a_hostile_identity_cache_does_not_crash_the_wrapper(tmp_path: Path, content: str) -> None:
    put_cache(tmp_path, content)
    h = Harness(tmp_path, http("200 OK", OK, "{}"))
    h.cred = "fresh-credential"  # a cache miss, so the cache is maintained, not just read
    assert h.go(["api", "repos/o/r"]) == 0
    assert len(h.calls) == 1
    assert h.ledger.rows()  # and the ledger still works


@pytest.mark.parametrize("content", HOSTILE)
def test_a_hostile_identity_cache_is_cleaned_up_on_the_next_write(tmp_path: Path, content: str) -> None:
    put_cache(tmp_path, content)
    clock = Clock()

    def run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        return done("octocat\n")

    rb.scope_for({"GH_TOKEN": "c1"}, SCOPE_ARGS, run, "/usr/bin/gh", tmp_path / DIR, clock)
    data = json.loads((tmp_path / DIR / "identity.json").read_text())
    assert all(isinstance(v, dict) and isinstance(v.get("at"), int | float) for v in data["ids"].values())
    assert len(data["ids"]) == 1  # the malformed records are gone, the fresh one is in


def test_a_cache_maintenance_error_is_ledger_unavailable_not_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_a: Any, **_k: Any) -> None:
        raise TypeError("hostile")

    monkeypatch.setattr(rb, "_identity_put", boom)
    h = Harness(tmp_path, http("200 OK", OK, "{}"))
    assert h.go(["api", "repos/o/r"]) == 0
    assert len(h.calls) == 1


@pytest.mark.parametrize("error", [TypeError("x"), ValueError("x"), OverflowError("x")])
def test_those_errors_from_the_budget_setup_fail_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise error

    monkeypatch.setattr(rb, "scope_for", boom)
    h = Harness(tmp_path, http("200 OK", OK, "{}"))
    assert h.go(["api", "repos/o/r"]) == 0
    assert "unavailable" in h.err.getvalue()
    assert len(h.calls) == 1


# the real launcher (Popen) against a stand-in gh executable


def fake_gh(tmp_path: Path, body: str) -> str:
    script = tmp_path / "fake-gh"
    script.write_text("#!/bin/sh\n" + body)
    script.chmod(0o755)
    return str(script)


def real_main(tmp_path: Path, gh: str, argv: list[str], stdin: str | None = None) -> tuple[int, str, str]:
    from io import StringIO

    out, err = StringIO(), StringIO()
    env = {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin", "GH_TOKEN": "tok", "SAFO_CALLER": "t"}
    code = rb.main(argv, env=env, out=out, err=err, gh=gh, stdin=stdin)
    return code, out.getvalue(), err.getvalue()


def test_the_real_launcher_passes_the_request_body_and_returns_the_output(tmp_path: Path) -> None:
    gh = fake_gh(tmp_path, "printf 'HTTP/2.0 200 OK\\r\\n\\r\\n'\ncat\n")
    code, out, _ = real_main(tmp_path, gh, ["api", "-X", "PATCH", "x/y", "--input", "-"], stdin="hello")
    assert code == 0
    assert out == "hello"


def test_the_real_launcher_kills_a_child_that_outlives_the_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(rb, "GH_TIMEOUT_SECONDS", 0.5)
    gh = fake_gh(tmp_path, 'case "$2" in user) echo octocat;; *) sleep 30;; esac\n')
    started = time.monotonic()
    code, _, err = real_main(tmp_path, gh, ["api", "-X", "PATCH", "x/y", "-f", "a=b"])
    assert time.monotonic() - started < 3  # the child's own child (sleep 30) was ended too, not waited for
    assert code == rb.EXIT_UNKNOWN_OUTCOME
    assert "outcome unknown" in err


def test_wrapper_waits_again_when_another_process_launched_during_its_sleep(tmp_path: Path) -> None:
    h = Harness(tmp_path, http("200 OK", OK, "{}"))
    h.advance = True
    h.go(WRITE)  # launch at T0
    fired: list[int] = []

    def other_process(_seconds: float) -> None:
        if not fired:  # an earlier ticket, descheduled until now, launches during this writer's sleep
            fired.append(1)
            h.ledger.launch_gate(lambda: h.launches.append(h.clock.now), h.sleep)

    h.on_sleep = other_process
    assert h.go(WRITE) == 0
    gaps = [b - a for a, b in zip(h.launches, h.launches[1:], strict=False)]
    assert len(h.launches) == 3
    assert all(g >= rb.WRITE_SPACING - 1e-9 for g in gaps)


def test_scope_for_itself_survives_a_cache_maintenance_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def boom(*_a: Any, **_k: Any) -> None:
        raise OverflowError("hostile")

    monkeypatch.setattr(rb, "_identity_put", boom)

    def run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        return done("octocat\n")

    assert not rb.scope_for({"GH_TOKEN": "c"}, SCOPE_ARGS, run, "/usr/bin/gh", tmp_path / DIR, Clock()).unknown


@pytest.mark.parametrize(
    "entry",
    [
        '{"at": "yesterday", "scope": null}',
        '{"at": [1], "scope": null}',
        '{"at": null}',
        '{"at": 1, "scope": 7}',
        '{"at": 1, "scope": "zz"}',
        '{"at": ' + "9" * 400 + ', "scope": null}',
        "5",
        "[]",
    ],
)
def test_a_hostile_record_at_the_credentials_own_key_is_a_miss(tmp_path: Path, entry: str) -> None:
    key = rb._hash("credential", "github.com", "c1")
    put_cache(tmp_path, '{"ids": {"' + key + '": ' + entry + "}}")

    def run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        return done("octocat\n")

    got = rb.scope_for({"GH_TOKEN": "c1"}, SCOPE_ARGS, run, "/usr/bin/gh", tmp_path / DIR, Clock())
    assert not got.unknown  # asked again, and the bad record was replaced
    data = json.loads((tmp_path / DIR / "identity.json").read_text())
    assert data["ids"][key]["scope"] == got.name
