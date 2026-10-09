# SPDX-License-Identifier: MIT
"""Run the safo command line in-process against a private HOME, with an empty PATH so no real program is reached."""

from __future__ import annotations

import io
from pathlib import Path

from meterdata import NOW
from safo.cli import main


def cli(*argv: str, home: Path, extra_env: dict[str, str] | None = None) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    env = {"HOME": str(home), "PATH": "", **(extra_env or {})}
    code = main(list(argv), env=env, out=out, err=err, now=NOW)
    return code, out.getvalue(), err.getvalue()


def local_run(shape: str, prompt: Path, agents: Path, log: Path, home: Path, *extra: str) -> tuple[int, str, str]:
    argv = ["local", "run", "--shape", shape, "--prompt-file", str(prompt), "--agents", str(agents), "--log", str(log)]
    return cli(*argv, *extra, home=home)
