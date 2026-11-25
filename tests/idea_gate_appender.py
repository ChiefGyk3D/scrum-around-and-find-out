# SPDX-License-Identifier: Apache-2.0
"""A child process for the ledger concurrency test: append records over short writes once the start file exists."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from safo import idea_gate_io


def short(fd: int, data: bytes | memoryview) -> int:
    return os.write(fd, bytes(data[:1000]))  # many small writes, so unserialized records would interleave


def main(ledger: str, start: str, tag: str, count: int) -> None:
    fd = idea_gate_io.open_ledger(Path(ledger))
    while not Path(start).exists():
        time.sleep(0.005)
    for i in range(count):
        record = json.dumps({"tag": tag, "i": i, "pad": tag * 70_000}) + "\n"
        idea_gate_io.write_all(fd, record.encode(), short)
    os.close(fd)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]))
