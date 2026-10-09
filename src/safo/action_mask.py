# SPDX-License-Identifier: MIT
"""Mask the credentials the Action was handed, before anything else in the job can print them.

Runs as `python -m safo.action_mask` with the secret in the environment (never in argv): PRIVATE_KEY (the App's PEM),
TOKEN (a personal token) and MINTED_TOKEN (the installation token). It imports nothing but `output`, so it runs
before the dependencies are installed.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from typing import TextIO

from safo import output

NAMES = ("PRIVATE_KEY", "TOKEN", "MINTED_TOKEN")


def mask_env(env: Mapping[str, str], stream: TextIO) -> None:
    for name in NAMES:
        output.mask(stream, env.get(name, ""))


def main() -> int:
    mask_env(os.environ, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
