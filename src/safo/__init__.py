# SPDX-License-Identifier: Apache-2.0
"""Scrum Around and Find Out: a GitHub Project defined as code."""

import os
import time


def _process_started() -> float:
    """When this process started, on the `time.monotonic()` clock, so a hook's budget counts the interpreter's start-up
    and the package imports, not only the time after they are done. Linux: the process age is /proc/uptime minus the
    start time in /proc/self/stat (both count from boot, suspend included, so their difference is exact); reading two
    kernel files cannot block. Anywhere else, or if anything looks wrong (no /proc, an age over a minute: not a fresh
    short-lived process), it is simply now, which is when this package was imported: the earliest point left."""
    now = time.monotonic()
    try:
        with open("/proc/self/stat", encoding="ascii") as handle:
            fields = handle.read().rsplit(")", 1)[1].split()
        with open("/proc/uptime", encoding="ascii") as handle:
            uptime = float(handle.read().split()[0])
        age = uptime - int(fields[19]) / os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError, IndexError, AttributeError):
        return now
    return now - age if 0.0 <= age <= 60.0 else now


PROCESS_STARTED = _process_started()

__version__ = "0.1.2"
