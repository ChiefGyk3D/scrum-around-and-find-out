# SPDX-License-Identifier: Apache-2.0
"""Bound the work a test does by CPU time, with a generous wall backstop.

A tight wall-clock bound on a short operation measures the load on the runner as much as the code. CPU time of the
process that does the work does not stretch when other processes compete for the cores, so it keeps the bound as
tight as it was while a loaded runner cannot trip it. The wall bound stays only as a backstop that catches a hang.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager

WALL_BACKSTOP = 30.0  # seconds; far above any honest run and below the hard timeout a CI step allows


@contextmanager
def cpu_bound(
    limit: float,
    *,
    wall: float = WALL_BACKSTOP,
    note: object = "",
    cpu_clock: Callable[[], float] = time.process_time,
    wall_clock: Callable[[], float] = time.monotonic,
) -> Iterator[None]:
    """Fail when the body spends `limit` seconds of this process's CPU, or `wall` seconds of the wall clock."""
    cpu_started, wall_started = cpu_clock(), wall_clock()
    yield
    cpu, elapsed = cpu_clock() - cpu_started, wall_clock() - wall_started
    assert cpu < limit, f"{cpu:.3f} s of CPU, limit {limit} s: {note}"
    assert elapsed < wall, f"{elapsed:.1f} s of wall time, backstop {wall} s: {note}"
