# SPDX-License-Identifier: MIT
"""What a mode receives: the validated board, an authenticated client and the streams."""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import TextIO

from safo import output
from safo.graphql import Client
from safo.schema import Board


@dataclass
class Context:
    board: Board
    client: Client
    out: TextIO
    today: dt.date
    env: Mapping[str, str] = field(repr=False)

    def say(self, line: str = "") -> None:
        """One log line, escaped: nothing printed can act as a workflow command."""
        output.write(self.out, line)

    def block(self, lines: Iterable[str]) -> None:
        """Several lines of untrusted text inside `::stop-commands::`, resumed even if writing them fails."""
        output.block(self.out, lines)
