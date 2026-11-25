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
    time.sleep(0.001)  # slow, small writes: two unserialized records are certain to overlap
    return os.write(fd, bytes(data[:1000]))


def main(ledger: str, start: str, tag: str, count: int) -> None:
    fd = idea_gate_io.open_ledger(Path(ledger))
    records = [(json.dumps({"tag": tag, "i": i, "pad": tag * 200_000}) + "\n").encode() for i in range(count)]
    Path(start).with_name(f"ready-{tag}").write_text("")
    while not Path(start).exists():
        time.sleep(0.002)
    for record in records:
        idea_gate_io.write_all(fd, record, short)
    os.close(fd)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]))
