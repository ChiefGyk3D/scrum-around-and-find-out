# SPDX-License-Identifier: Apache-2.0
"""The CPU bound helper: it passes a slow-but-idle body and fails a busy one and a hung one."""

from __future__ import annotations

import itertools
import time

import pytest

from cputime import cpu_bound


def test_an_idle_wait_is_not_charged_as_cpu() -> None:
    with cpu_bound(0.2):  # the wall clock moves, the CPU clock does not
        time.sleep(0.4)


def test_a_busy_body_over_the_cpu_limit_fails() -> None:
    ticks = itertools.count(0.0, 1.0)  # an injected CPU clock: each read is one second later
    with pytest.raises(AssertionError, match="of CPU"), cpu_bound(0.5, cpu_clock=lambda: next(ticks), note="busy"):
        pass


def test_real_cpu_work_over_the_limit_fails() -> None:
    with pytest.raises(AssertionError, match="of CPU"), cpu_bound(0.05):
        end = time.process_time() + 0.2
        while time.process_time() < end:
            pass


def test_a_body_over_the_wall_backstop_fails_even_with_no_cpu() -> None:
    ticks = itertools.count(0.0, 100.0)  # an injected wall clock
    with pytest.raises(AssertionError, match="wall time"), cpu_bound(5.0, wall=30.0, wall_clock=lambda: next(ticks)):
        pass


def test_an_exception_in_the_body_is_not_hidden() -> None:
    with pytest.raises(ZeroDivisionError), cpu_bound(5.0):
        raise ZeroDivisionError
