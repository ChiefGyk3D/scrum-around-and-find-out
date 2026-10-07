# SPDX-License-Identifier: MIT
"""The `safo` command line. The modes arrive task by task; the entry point and --version come first."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from safo import __version__


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="safo", description="Scrum Around and Find Out: a GitHub Project defined as code."
    )
    parser.add_argument("--version", action="version", version=f"safo {__version__}")
    parser.parse_args(argv)
    parser.print_help()
    return 0


def run() -> None:
    raise SystemExit(main())
