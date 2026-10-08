# SPDX-License-Identifier: MIT
"""What a mode receives: the validated board, an authenticated client and the streams."""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TextIO

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
        print(line, file=self.out)
