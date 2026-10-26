# SPDX-License-Identifier: Apache-2.0
"""Append N valid records to one log as a real process (support file for the quarantine concurrency test).

usage: append_child.py LOG N
"""

from __future__ import annotations

import sys
from pathlib import Path

from safo.hooks import append_log, log_record

log, count = Path(sys.argv[1]), int(sys.argv[2])
for _ in range(count):
    append_log(log, log_record("2026-01-01T00:00:00", "allow", "warn", None, False, "healthy", ""), lock_timeout=5.0)
