# SPDX-License-Identifier: Apache-2.0
"""Scrum Around and Find Out: a GitHub Project defined as code."""

import os
import time

PROCESS_AGE_LIMIT_SECONDS = 60.0  # an age over this is not a fresh short-lived hook process: it is not trusted


def _process_age(stat_text: str, uptime_text: str, ticks_per_second: float) -> float | None:
    """The process's age in seconds from the text of /proc/self/stat and /proc/uptime, or None when it cannot be read or
    does not look like a fresh process (negative, or over PROCESS_AGE_LIMIT_SECONDS). Both numbers count from boot,
    suspend included, so their difference is exact whatever the monotonic clock did during a suspend."""
    try:
        fields = stat_text.rsplit(")", 1)[1].split()
        age = float(uptime_text.split()[0]) - int(fields[19]) / ticks_per_second
    except (IndexError, ValueError, ZeroDivisionError):
        return None
    return age if 0.0 <= age <= PROCESS_AGE_LIMIT_SECONDS else None


def _process_started() -> float:
    """When this process started, on the `time.monotonic()` clock, so a hook's budget counts the interpreter's start-up
    and the package imports, not only the time after they are done. Linux: the age from /proc (reading two kernel files
    cannot block) subtracted from the monotonic NOW. Anywhere else, or if anything looks wrong (see _process_age: this
    includes a long-lived process, and a clock that disagrees after a suspend by more than the limit), it is simply now,
    which is when this package was imported: the earliest point left. The start-up before that import is then not
    counted."""
    now = time.monotonic()
    try:
        with open("/proc/self/stat", encoding="ascii") as handle:
            stat_text = handle.read()
        with open("/proc/uptime", encoding="ascii") as handle:
            uptime_text = handle.read()
        ticks = os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError, AttributeError):
        return now
    age = _process_age(stat_text, uptime_text, float(ticks))
    return now if age is None else now - age


PROCESS_STARTED = _process_started()

__version__ = "0.1.2"
