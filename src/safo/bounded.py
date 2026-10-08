# SPDX-License-Identifier: MIT
"""Bound untrusted JSON before parsing; never include input values in errors."""

from __future__ import annotations

import errno
import json
import math
import os
import re
import stat
from pathlib import Path
from typing import Any

MAX_BYTES = 1_048_576
MAX_FILE_BYTES = 16 * MAX_BYTES
MAX_DEPTH = 64


def loads(raw: str | bytes) -> Any:
    if len(raw) > MAX_BYTES:
        raise ValueError("JSON exceeds size limit")
    text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError("JSON exceeds depth limit")
        elif char in "]}":
            depth -= 1

    def bad_constant(value: str) -> None:
        raise ValueError("nonfinite JSON number")

    return json.loads(text, parse_constant=bad_constant)


def read_json(path: Path) -> Any:
    with path.open("rb") as handle:
        return loads(handle.read(MAX_BYTES + 1))


def json_lines(path: Path) -> list[tuple[int, Any]]:
    # One bounded file read, including an incomplete last line; callers decide how to handle it.
    with path.open("rb") as handle:
        raw = handle.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError("JSONL exceeds file limit")
    rows = []
    for number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        try:
            rows.append((number, loads(line)))
        except (ValueError, UnicodeError):
            rows.append((number, None))
    return rows


def number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    try:
        result = float(value)
    except (ValueError, OverflowError):
        return None
    return result if math.isfinite(result) and 0 <= result <= 10**15 else None


def count(value: Any) -> int:
    result = number(value)
    if result is None or not result.is_integer():
        raise ValueError("expected a bounded nonnegative integer")
    return int(result)


def month(value: str) -> str:
    if not re.fullmatch(r"[0-9]{4}-(?:0[1-9]|1[0-2])", value) or value[:4] == "0000":
        raise ValueError("expected YYYY-MM")
    return value


class NotRegularFileError(OSError):
    """The path names a FIFO, a directory, a device or the like."""


def read_bounded(path: Path, limit: int) -> bytes:
    """At most `limit` bytes of a regular file, judged by the descriptor it was opened as.

    The open neither follows a symlink in the last component nor waits for a writer on a FIFO, and the file type is
    asked of the descriptor (not of the path), so the file cannot be swapped for a FIFO between a check and the open.
    """
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise NotRegularFileError(errno.EINVAL, "not a regular file")
        chunks: list[bytes] = []
        total = 0
        while total < limit:
            chunk = os.read(fd, min(65_536, limit - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)
