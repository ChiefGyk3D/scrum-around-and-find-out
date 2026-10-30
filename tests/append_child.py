# SPDX-License-Identifier: Apache-2.0
"""Append N valid records to one log as a real process (support file for the quarantine concurrency test).

usage: append_child.py LOG N [BARRIER_DIR ME OTHER]   (with a barrier, neither child appends until both are running)
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

from safo.hooks import append_log, log_record

log, count = Path(sys.argv[1]), int(sys.argv[2])
if len(sys.argv) > 5:  # a real barrier: announce yourself, then wait until the OTHER child has announced itself
    barrier, me, other = Path(sys.argv[3]), sys.argv[4], sys.argv[5]
    (barrier / me).write_text("here")
    while not (barrier / other).exists():
        time.sleep(0.002)
for _ in range(count):
    append_log(log, log_record("2026-01-01T00:00:00", "allow", "warn", None, False, "healthy", ""), lock_timeout=5.0)
