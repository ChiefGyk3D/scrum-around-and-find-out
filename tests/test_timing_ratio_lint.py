# SPDX-License-Identifier: Apache-2.0
"""No test asserts on a ratio of two measured times (#539).

A bound on elapsed_a / elapsed_b flakes on a loaded runner: both timings move with the machine. Count the work done or
inject a clock instead. The detector lives in tests/timingratio.py; this file holds its fixtures (bad and good code),
the allowlist, and the scan of every tests/test_*.py file.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

import timingratio

TESTS_DIR = Path(__file__).resolve().parent

# "file:test" -> one-line reason. Empty on purpose: a hit is fixed (count work, inject a clock), not silenced.
ALLOWLIST: dict[str, str] = {}

BAD = {
    "ratio_in_assert": """
        import time
        def test_scaling():
            t0 = time.perf_counter()
            work(100)
            a = time.perf_counter() - t0
            t0 = time.perf_counter()
            work(1000)
            b = time.perf_counter() - t0
            assert b / a < 20
    """,
    "ratio_through_name": """
        import time
        def test_scaling():
            a = timed(work, 100).elapsed
            b = timed(work, 1000).elapsed
            ratio = b / a
            assert ratio <= 12
    """,
    "cpu_clock_from_import": """
        from time import process_time
        def test_cpu():
            s = process_time(); f(1); a = process_time() - s
            s = process_time(); f(2); b = process_time() - s
            assert a / b > 0.5
    """,
    "scaling_by_multiplication": """
        import time
        def test_scaling():
            t0 = time.monotonic(); f(1); small = time.monotonic() - t0
            t0 = time.monotonic(); f(9); big = time.monotonic() - t0
            assert big < 15 * small
    """,
    "helper_named_elapsed": """
        def test_helpers():
            fast = measure_elapsed(f, 1)
            slow = measure_duration(f, 2)
            assert slow / fast < 4
    """,
    "timeit_ratio": """
        import timeit
        def test_timeit():
            a = timeit.timeit(f, number=10)
            b = timeit.timeit(g, number=10)
            assert a / b >= 0.9
    """,
    "method_in_class": """
        import time
        class TestX:
            def test_it(self):
                a = time.time(); b = time.time(); c = time.time()
                assert (c - b) / (b - a) < 3
    """,
}

GOOD = {
    "absolute_bound": """
        import time
        def test_fast():
            t0 = time.perf_counter(); f(); took = time.perf_counter() - t0
            assert took < 5.0
    """,
    "counted_work": """
        def test_calls():
            calls = run(1000)
            assert calls / 1000 < 2
    """,
    "injected_clock": """
        def test_clock():
            clock = FakeClock()
            run(clock)
            assert clock.now / clock.ticks == 1
    """,
    "ratio_not_asserted": """
        import time
        def test_log():
            a = time.perf_counter(); b = time.perf_counter(); c = time.perf_counter()
            print((c - b) / (b - a))
    """,
    "time_divided_by_constant": """
        import time
        def test_ms():
            t0 = time.perf_counter(); f(); ms = (time.perf_counter() - t0) / 1000
            assert ms < 50
    """,
    "not_a_test": """
        import time
        def helper():
            a = time.perf_counter(); b = time.perf_counter()
            return b / a < 2
    """,
}


def _hits(src: str) -> list[str]:
    return timingratio.find_timing_ratio_asserts(textwrap.dedent(src), "fixture.py")


@pytest.mark.parametrize("name", sorted(BAD))
def test_bad_fixture_is_flagged(name: str) -> None:
    assert _hits(BAD[name]), name


@pytest.mark.parametrize("name", sorted(GOOD))
def test_good_fixture_is_not_flagged(name: str) -> None:
    assert _hits(GOOD[name]) == [], name


def test_hit_names_the_test() -> None:
    assert _hits(BAD["ratio_in_assert"]) == ["fixture.py:test_scaling"]
    assert _hits(BAD["method_in_class"]) == ["fixture.py:test_it"]


def test_allowlist_entries_carry_a_reason() -> None:
    for key, reason in ALLOWLIST.items():
        assert ":" in key and reason.strip() and "\n" not in reason, key


def test_scan_collects_test_files() -> None:
    # Loose collection, strict assertion: the scan must see the suite, else the guard below proves nothing.
    assert len(sorted(TESTS_DIR.glob("test_*.py"))) > 50


def test_no_test_asserts_on_a_ratio_of_timings() -> None:
    found: set[str] = set()
    for path in sorted(TESTS_DIR.glob("test_*.py")):
        if path.name == Path(__file__).name:
            continue
        found.update(timingratio.find_timing_ratio_asserts(path.read_text(encoding="utf-8"), path.name))
    unlisted = sorted(found - set(ALLOWLIST))
    assert not unlisted, "ratio of measured times asserted (count work or inject a clock): " + ", ".join(unlisted)
    stale = sorted(set(ALLOWLIST) - found)
    assert not stale, "allowlist entries with no hit: " + ", ".join(stale)
