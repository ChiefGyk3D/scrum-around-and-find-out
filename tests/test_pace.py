# SPDX-License-Identifier: Apache-2.0
"""The weekly pace reader: thresholds, the early-week cap, step-down, staleness, rollover, and the security route.

Time is injected. RESETS is an arbitrary instant; `at(elapsed_pct)` is the `now` at which that much of the week has
passed, so a case reads as "used X percent when Y percent of the week is gone".
"""

from __future__ import annotations

import json
import random
import time
from pathlib import Path
from typing import Any

import pytest

from safo import pace

RESETS = 1_800_000_000.0
STEP = pace.STEP_DOWN_GAP_SECONDS


def at(elapsed_pct: float) -> float:
    return RESETS - pace.WEEK_SECONDS + pace.WEEK_SECONDS * elapsed_pct / 100.0


def cache(
    used: float, now: float, *, captured_ago: float = 0.0, resets: float = RESETS, **extra: Any
) -> dict[str, Any]:
    row = {"label": "weekly", "used_percent": used, "resets_at": resets, "captured_at": now - captured_ago}
    return {"windows": [row, *extra.get("more", [])]}


def mode_of(used: float, elapsed: float, state: dict[str, Any] | None = None) -> str:
    return pace.decide(cache(used, at(elapsed)), at(elapsed), state)[0].mode


# every threshold edge at 50 percent elapsed: pace = used / 50 (0.90 -> 45, 1.00 -> 50, 1.30 -> 65)
@pytest.mark.parametrize(
    ("used", "elapsed", "expected"),
    [
        (0, 50, "normal"),
        (44.9, 50, "normal"),
        (45, 50, "shift"),
        (49.9, 50, "shift"),
        (50, 50, "lean"),
        (64.9, 50, "lean"),
        (65, 50, "hard"),
        (84.9, 80, "lean"),  # used under 85 and pace 1.06
        (85, 90, "hard"),  # the absolute line, pace 0.94
        (84.9, 90, "shift"),  # pace 0.94
        (99.9, 99, "hard"),
        (100.0, 99, "lockdown"),
        (31.9, 43.2, "normal"),
    ],
)
def test_threshold_edges(used: float, elapsed: float, expected: str) -> None:
    assert mode_of(used, elapsed) == expected


@pytest.mark.parametrize(
    ("used", "elapsed", "expected_mode", "expected_pace"),
    [
        (4, 4, "normal", 0.8),  # floor: 4 percent used at 4 percent elapsed reads 0.8x, not 1.0x
        (4, 5, "normal", 0.8),
        (4, 0, "normal", 0.8),
        (10, 4, "shift", 2.0),  # capped at shift in the first 5 percent
        (14.9, 2, "shift", 2.98),  # still under the absolute line
        (15, 4, "hard", 3.0),  # 15 percent used is an absolute burn: no cap
        (15, 5, "hard", 3.0),
        (10, 5, "hard", 2.0),  # at 5 percent elapsed the cap is over
    ],
)
def test_early_week_floor_and_cap(used: float, elapsed: float, expected_mode: str, expected_pace: float) -> None:
    d = pace.decide(cache(used, at(elapsed)), at(elapsed))[0]
    assert (d.mode, d.pace) == (expected_mode, expected_pace)


def test_any_window_at_100_is_lockdown() -> None:
    now = at(10)
    five = {"label": "5h", "used_percent": 100, "resets_at": now + 100, "captured_at": now}
    d = pace.decide(cache(5, now, more=[five]), now)[0]
    assert d.mode == "lockdown"
    assert d.used == 5  # the numbers are still the weekly ones


@pytest.mark.parametrize("used", [101, 150, -1, -0.01, float("nan"), "50", None, True])
def test_used_out_of_range_or_not_a_number_is_unknown(used: Any) -> None:
    d = pace.decide(cache(used, at(50)), at(50))[0]
    assert d.mode == "unknown"


def test_used_100_point_0_is_valid() -> None:
    assert mode_of(100.0, 50) == "lockdown"


def test_pace_numbers_for_the_documented_reading() -> None:
    d = pace.decide(cache(32, at(43.2), captured_ago=90), at(43.2))[0]
    assert (d.mode, round(d.pace or 0, 2), d.used, round(d.elapsed or 0, 1), d.age) == ("normal", 0.74, 32, 43.2, 90)
    assert pace.format_line(d) == "mode=normal pace=0.74x used=32 elapsed=43.2 age=90"


@pytest.mark.parametrize(
    ("ago", "mode"),
    [(0, "normal"), (1799, "normal"), (1800, "normal"), (1801, "unknown"), (86400, "unknown")],
)
def test_staleness_over_30_minutes_is_unknown(ago: float, mode: str) -> None:
    now = at(50)
    d = pace.decide(cache(10, now, captured_ago=ago), now)[0]
    assert d.mode == mode
    assert d.reason == ("ok" if mode == "normal" else "stale")


@pytest.mark.parametrize(("ahead", "mode"), [(0, "normal"), (-299, "normal"), (-301, "unknown"), (-3600, "unknown")])
def test_future_captured_at(ahead: float, mode: str) -> None:
    now = at(50)
    assert pace.decide(cache(10, now, captured_ago=ahead), now)[0].mode == mode


@pytest.mark.parametrize("delta", [0, 1, 3600])
def test_rollover_is_unknown_and_clears_state(delta: float) -> None:
    now = RESETS + delta
    d, state = pace.decide(cache(90, now), now, {"mode": "hard", "pending_since": 5.0})
    assert (d.mode, d.reason, state) == ("unknown", "rolled-over", {})


def test_resets_more_than_a_week_ahead_is_unknown() -> None:
    now = RESETS - pace.WEEK_SECONDS - 10
    assert pace.decide(cache(1, now), now)[0].reason == "resets-too-far"


@pytest.mark.parametrize(
    "data",
    [None, [], "x", 5, {}, {"windows": None}, {"windows": "w"}, {"windows": []}, {"windows": [5, None]},
     {"windows": [{"label": "5h", "used_percent": 1, "resets_at": RESETS, "captured_at": 1}]},
     {"windows": [{"label": "weekly", "used_percent": 1, "resets_at": RESETS}]},
     {"windows": [{"label": "weekly", "used_percent": 1, "captured_at": at(5)}]}],
)  # fmt: skip
def test_malformed_or_missing_weekly_row_is_unknown(data: object) -> None:
    assert pace.decide(data, at(5))[0].mode == "unknown"


def test_newest_weekly_row_wins() -> None:
    now = at(50)
    old = {"label": "weekly", "used_percent": 90, "resets_at": RESETS, "captured_at": now - 100}
    new = {"label": "weekly", "used_percent": 10, "resets_at": RESETS, "captured_at": now}
    assert pace.decide({"windows": [old, new]}, now)[0].used == 10
    assert pace.decide({"windows": [new, old]}, now)[0].used == 10


# step-down: one level, after two readings 10 minutes apart below the leave line
def test_step_up_is_immediate() -> None:
    _, state = pace.decide(cache(10, at(50)), at(50))
    d, _ = pace.decide(cache(70, at(50) + 60), at(50) + 60, state)
    assert d.mode == "hard"


def test_step_down_needs_two_readings_ten_minutes_apart() -> None:
    state: dict[str, Any] = {"mode": "shift", "pending_since": None}
    t = at(50)
    d, state = pace.decide(cache(30, t), t, state)  # pace 0.6, first reading below 0.80
    assert d.mode == "shift"
    d, state = pace.decide(cache(30, t + STEP - 1), t + STEP - 1, state)  # too soon
    assert d.mode == "shift"
    d, state = pace.decide(cache(30, t + STEP), t + STEP, state)
    assert d.mode == "normal"
    assert state["pending_since"] is None


def test_step_down_is_one_level_at_a_time() -> None:
    t = at(50)
    state: dict[str, Any] = {"mode": "hard", "pending_since": None}
    seen = []
    for i in range(6):
        d, state = pace.decide(cache(5, t + i * STEP), t + i * STEP, state)  # pace 0.1: raw is normal
        seen.append(d.mode)
    assert seen == ["hard", "lean", "lean", "shift", "shift", "normal"]


def test_reading_between_leave_and_enter_holds_the_mode_and_clears_the_wait() -> None:
    t = at(50)
    state: dict[str, Any] = {"mode": "shift", "pending_since": t - 5 * 60}
    d, state = pace.decide(cache(42, t), t, state)  # pace 0.84: under enter 0.90, above leave 0.80
    assert d.mode == "shift"
    assert state["pending_since"] is None
    d, state = pace.decide(cache(30, t + STEP), t + STEP, state)  # the wait restarts
    assert d.mode == "shift"


@pytest.mark.parametrize(
    ("mode", "used", "held"),
    [
        ("shift", 40, True),  # 0.80 is not below 0.80
        ("shift", 39.5, False),
        ("lean", 46, True),  # 0.92
        ("lean", 45.5, False),
        ("hard", 57.5, True),  # 1.15
        ("hard", 57, False),
    ],
)
def test_leave_lines(mode: str, used: float, held: bool) -> None:
    t = at(50)
    state: dict[str, Any] = {"mode": mode, "pending_since": t - STEP}
    d, _ = pace.decide(cache(used, t), t, state)
    stepped_down = d.mode != mode
    assert stepped_down is (not held)


def test_hard_also_needs_used_under_80_to_leave() -> None:
    t = at(90)
    state: dict[str, Any] = {"mode": "hard", "pending_since": t - STEP}
    d, _ = pace.decide(cache(80, t), t, state)  # pace 0.89 but used 80
    assert d.mode == "hard"
    d, _ = pace.decide(cache(79, t), t, state)
    assert d.mode == "lean"


def test_lockdown_leaves_when_no_window_is_full() -> None:
    t = at(50)
    state: dict[str, Any] = {"mode": "lockdown", "pending_since": t - STEP}
    five = {"label": "5h", "used_percent": 100, "resets_at": t + 100, "captured_at": t}
    assert pace.decide(cache(60, t, more=[five]), t, state)[0].mode == "lockdown"
    assert pace.decide(cache(60, t), t, state)[0].mode == "hard"


def test_garbage_state_is_ignored() -> None:
    for state in ({"mode": "banana"}, {"mode": 5}, {"pending_since": "x"}, {}):
        assert pace.decide(cache(10, at(50)), at(50), state)[0].mode == "normal"


def test_unknown_keeps_state_for_the_next_good_reading() -> None:
    state = {"mode": "hard", "pending_since": None}
    _, kept = pace.decide(cache(10, at(50), captured_ago=7200), at(50), state)
    assert kept == state


# the security route: never reads the mode
class Tripwire:
    """A mode that raises if anything looks at it."""

    def __getattribute__(self, name: str) -> Any:
        raise AssertionError(f"mode read: {name}")

    def __eq__(self, other: object) -> bool:
        raise AssertionError("mode compared")

    def __hash__(self) -> int:
        raise AssertionError("mode hashed")

    def __index__(self) -> int:
        raise AssertionError("mode indexed")

    def __str__(self) -> str:
        raise AssertionError("mode stringified")


def test_security_review_is_daybreak_in_every_mode() -> None:
    assert [pace.route("security-review", m) for m in pace.MODES] == ["D"] * 6


def test_security_review_never_reads_the_mode_1000_random_inputs() -> None:
    rng = random.Random(429)  # noqa: S311 - a seeded test generator, not a secret
    pool: list[object] = [*pace.MODES, "", "banana", None, 7, -1, 1e9, b"x", [], {}, Tripwire()]
    for _ in range(1000):
        mode = rng.choice(pool) if rng.random() < 0.5 else "".join(rng.choice("abcxyz") for _ in range(8))
        assert pace.route("security-review", mode) == "D"
    assert pace.route("security-review", Tripwire()) == "D"


def test_other_classes_follow_the_table_and_unknown_routes_as_normal() -> None:
    assert pace.route("implementer-specified", "normal") == "C"
    assert pace.route("implementer-specified", "shift") == "X"
    assert pace.route("implementer-specified", "unknown") == "C"
    assert pace.route("design-judgment", "lockdown") == "C"
    assert pace.route("mechanical", "hard") == "L"
    with pytest.raises(ValueError, match="unknown task class"):
        pace.route("nonsense", "normal")


# CLI
def write_cache(path: Path, used: float, now: float, **kw: Any) -> None:
    path.write_text(json.dumps(cache(used, now, **kw)), encoding="utf-8")


def test_cli_prints_one_line_and_exits_0(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "c.json"
    write_cache(f, 32, at(43.2), captured_ago=60)
    assert pace.run(["--cache", str(f), "--no-state"], now=at(43.2)) == 0
    assert capsys.readouterr().out == "mode=normal pace=0.74x used=32 elapsed=43.2 age=60\n"


@pytest.mark.parametrize("content", [None, "", "{not json", "[]", '{"windows": 3}'])
def test_cli_missing_or_garbage_cache_is_unknown_exit_0(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], content: str | None
) -> None:
    f = tmp_path / "c.json"
    if content is not None:
        f.write_text(content, encoding="utf-8")
    assert pace.run(["--cache", str(f), "--no-state"], now=at(10)) == 0
    out = capsys.readouterr().out
    assert out.startswith("mode=unknown pace=- used=- elapsed=- age=-")
    assert out.count("\n") == 1


def test_cli_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "c.json"
    write_cache(f, 50, at(50))
    pace.run(["--cache", str(f), "--json", "--no-state"], now=at(50))
    out = json.loads(capsys.readouterr().out)
    assert (out["mode"], out["pace"], out["reason"]) == ("lean", 1.0, "ok")


def test_cli_state_makes_step_down_survive_processes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f, s = tmp_path / "c.json", tmp_path / "state" / "s.json"
    t = at(50)
    s.parent.mkdir()
    s.write_text(json.dumps({"mode": "shift", "pending_since": None}), encoding="utf-8")
    modes = []
    for now in (t, t + STEP):
        write_cache(f, 30, now)
        pace.run(["--cache", str(f), "--state", str(s), "--json"], now=now)
        modes.append(json.loads(capsys.readouterr().out)["mode"])
    assert modes == ["shift", "normal"]
    assert oct(s.stat().st_mode & 0o777) == "0o600"
    assert not list(s.parent.glob("*.tmp"))


def test_cli_survives_an_internal_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_: object) -> None:
        raise RuntimeError("x")

    monkeypatch.setattr(pace, "decide", boom)
    assert pace.run(["--cache", str(tmp_path / "none"), "--no-state"], now=1.0) == 0
    assert "mode=unknown" in capsys.readouterr().out


def test_runtime_is_under_100_ms(tmp_path: Path) -> None:
    f = tmp_path / "c.json"
    write_cache(f, 32, at(43.2))
    start = time.perf_counter()
    for _ in range(20):
        pace.run(["--cache", str(f), "--no-state"], now=at(43.2))
    assert (time.perf_counter() - start) / 20 < 0.1
