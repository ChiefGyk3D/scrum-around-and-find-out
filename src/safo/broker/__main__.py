# SPDX-License-Identifier: Apache-2.0
"""Entry point of the broker service (`python -I -m safo.broker`).

The socket server is phase 3. Until it lands this refuses to run with a clear status, so a unit that starts it fails
loudly instead of silently doing nothing. `--self-test` is what the installer runs in the staged release before it is
activated: it imports every module of the broker package and exits 0 only if all of them import. Phase 3 keeps
that mode.
"""

from __future__ import annotations

import importlib
import pkgutil
import sys
from collections.abc import Sequence

from safo import output

NOT_IMPLEMENTED = 78  # EX_CONFIG: the service cannot run in this build


def self_test() -> int:
    package = importlib.import_module("safo.broker")
    for info in pkgutil.iter_modules(package.__path__):
        if info.name == "__main__":
            continue
        try:
            importlib.import_module(f"safo.broker.{info.name}")
        except Exception as exc:
            output.write(sys.stderr, f"self-test failed: safo.broker.{info.name}: {type(exc).__name__}")
            return 1
    return 0


def main(argv: Sequence[str]) -> int:
    if list(argv) == ["--self-test"]:
        return self_test()
    if argv:
        output.write(sys.stderr, "safo.broker takes no arguments except --self-test")
        return 2
    output.write(sys.stderr, "the broker server is not implemented yet (phase 3); refusing to start")
    return NOT_IMPLEMENTED


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
