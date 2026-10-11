#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Write or check examples/harness/, the instruction files generated from the profiles in agents.yaml.

scripts/gen_profiles.py --write     make examples/harness/ exactly what agents.yaml renders
scripts/gen_profiles.py --check     exit 1 if it is not (a missing, unexpected, stale or hand-edited file)

Only the repository's agents.yaml is read, never a local override or anything under ~/.config/safo. Unresolved evidence
fails the build. The tree is read and written without following a link (src/safo/harness_tree.py, spec 2.6).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from safo.errors import SafoError  # noqa: E402
from safo.evidence import load_verified_agents  # noqa: E402
from safo.harness_tree import check_tree, write_tree  # noqa: E402
from safo.profile_render import render_harness  # noqa: E402

AGENTS = ROOT / "agents.yaml"
OUT = ROOT / "examples" / "harness"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", action="store_true")
    group.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    shown = OUT.relative_to(ROOT) if OUT.is_relative_to(ROOT) else OUT
    try:
        # a repository checkout: review is the control (spec 7.2), and no local override is ever read
        verified = load_verified_agents(AGENTS, None, trusted=False)
        verified.require_clean()
        for warning in verified.agents.warnings:
            print(f"warning: {warning}", file=sys.stderr)
        files = render_harness(verified)
    except SafoError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    if args.write:
        problems, changes = write_tree(OUT, files)
        if problems:
            for problem in problems:
                print(f"error: {problem}", file=sys.stderr)
            return 1
        for change in changes:
            print(change)
        print(f"ok: {shown} is {len(files)} generated files")
        return 0
    problems = check_tree(OUT, files)
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        print(f"error: {shown} is stale: run python scripts/gen_profiles.py --write", file=sys.stderr)
        return 1
    print(f"ok: {shown} matches agents.yaml")
    return 0


if __name__ == "__main__":
    sys.exit(main())
