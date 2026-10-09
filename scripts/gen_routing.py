#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Write or check docs/routing.md, which is generated from agents.yaml.

scripts/gen_routing.py --write     regenerate docs/routing.md
scripts/gen_routing.py --check     exit 1 if docs/routing.md is not what agents.yaml renders
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from safo.agentsfile import load_agents  # noqa: E402
from safo.errors import SafoError  # noqa: E402
from safo.routing_doc import render_routing  # noqa: E402

AGENTS = ROOT / "agents.yaml"
PAGE = ROOT / "docs" / "routing.md"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", action="store_true")
    group.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    try:
        text = render_routing(load_agents(AGENTS))
    except SafoError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    if args.write:
        PAGE.write_text(text, encoding="utf-8")
        print(f"wrote {PAGE.relative_to(ROOT)}")
        return 0
    if not PAGE.exists() or PAGE.read_text(encoding="utf-8") != text:
        print("error: docs/routing.md is stale: run python scripts/gen_routing.py --write", file=sys.stderr)
        return 1
    print("ok: docs/routing.md matches agents.yaml")
    return 0


if __name__ == "__main__":
    sys.exit(main())
