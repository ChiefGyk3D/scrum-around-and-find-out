# SPDX-License-Identifier: MIT
"""The one place safo writes to a stream.

Everything printed in a run can carry text that GitHub or an event payload sent: a title, a view name, a filter, an
error message. On a GitHub Actions runner a line holding `::name::` anywhere in it is a workflow command, so no text
reaches a stream except through here:

- `line` escapes every control character, every other character of Unicode category C (format marks such as the
  bidirectional controls and zero-width characters, private use, unassigned) and the line and paragraph separators, and
  breaks up every `::`. It is idempotent.
- `block` shows several lines of untrusted text between `::stop-commands::<token>` and `::<token>::`, with a fresh
  random token each time, and always attempts the closing marker once the opening one is out.

`mask` is the one command written unescaped, for the reason in its docstring. A test walks the package and fails
on any `print` or `sys.stdout`/`sys.stderr` write outside this module.
"""

from __future__ import annotations

import secrets
import unicodedata
from collections.abc import Iterable
from typing import TextIO

_SEPARATORS = chr(0x2028) + chr(0x2029)  # line and paragraph separator


def _written(char: str) -> str:
    code = ord(char)
    if unicodedata.category(char).startswith("C") or char in _SEPARATORS:
        if code < 0x100:
            return f"\\x{code:02x}"
        return f"\\u{code:04x}" if code < 0x10000 else f"\\U{code:08x}"
    return char


def inner(text: str) -> str:
    """Control and format characters written out; `::` left as it is. For text inside a stop-commands block."""
    return "".join(_written(char) for char in text)


def line(text: str) -> str:
    """The text as one safe log line: nothing in it can start, end or hide a workflow command."""
    return inner(text).replace("::", ":\\x3a")


def write(stream: TextIO, text: str) -> None:
    print(line(text), file=stream)


def annotation(stream: TextIO, message: str) -> None:
    """The error annotation GitHub shows on the run: the one command safo writes, with its text escaped."""
    print(f"::error title=safo::{line(message)}", file=stream)


def mask(stream: TextIO, value: str) -> None:
    """Tell the runner to hide `value` in every later log line, one command per non-blank line (a PEM key is many).

    The one place a command is written from text that is not ours, so it is the only writer that does not escape:
    the text after `add-mask::` is the value to hide, taken to the end of its own line, and a value holding a line
    break is split here so no line can start a second command.
    """
    for text in value.splitlines():
        if text.strip():
            print(f"::add-mask::{text.strip()}", file=stream)


def set_output(path: str, name: str, value: str) -> None:
    """Append `name=value` to the step output file the runner gave us. The value may not carry a line break, so it
    can never start a second output; the callers hold names that already passed a strict pattern."""
    if "\n" in value or "\r" in value or "=" in name or "\n" in name:
        raise ValueError("a step output is one line")
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(f"{name}={value}\n")


def block(stream: TextIO, lines: Iterable[str]) -> None:
    """Untrusted lines between stop and resume markers. The resume marker is attempted even if a write or the
    iterable fails; if the opening marker cannot be written, nothing was opened and nothing is closed."""
    token = secrets.token_hex(16)
    print(f"::stop-commands::{token}", file=stream)
    try:
        for text in lines:
            print(inner(text), file=stream)
    finally:
        print(f"::{token}::", file=stream)
