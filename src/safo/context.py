# SPDX-License-Identifier: MIT
"""What a mode receives: the validated board, an authenticated client and the streams."""

from __future__ import annotations

import datetime as dt
import subprocess
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from safo import output
from safo.credentials import find_gh
from safo.errors import ConfigError
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


@dataclass
class LocalContext:
    """What a mode that needs no board receives: streams, the environment, the clock and the two things it may run.

    `home` comes from $HOME in `env`, never from the account database, so a test points it at a temporary
    directory and the real home directory is never read.
    """

    out: TextIO
    env: Mapping[str, str] = field(repr=False)
    now: dt.datetime
    run: Callable[..., Any] = subprocess.run
    which_override: Callable[[str], str | None] | None = None
    dry_run: bool = False
    stdin: TextIO | None = None  # what a hook reads its event from; None means the process's own standard input

    @property
    def which(self) -> Callable[[str], str | None]:
        """Find `gh` on the absolute PATH entries of `env`, not the process's: an empty PATH finds nothing."""
        return self.which_override or (lambda name: find_gh(self.env) if name == "gh" else None)

    @property
    def home(self) -> Path:
        value = self.env.get("HOME", "")
        if not value:
            raise ConfigError("HOME is not set, so there is nowhere to look for the agents' session files")
        return Path(value)

    def say(self, line: str = "") -> None:
        """One log line, escaped: nothing printed can act as a workflow command."""
        output.write(self.out, line)
