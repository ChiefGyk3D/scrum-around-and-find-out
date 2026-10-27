# SPDX-License-Identifier: Apache-2.0
"""Every test id is the same on every run, whatever the hash seed.

pytest-xdist makes each worker collect the whole suite on its own and refuses to run when two workers
collected different ids. A parametrize id built from `hash()` of a string changes with PYTHONHASHSEED, so
the suite would run only serially. This collects the suite under two seeds and compares the ids.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent


def collected_ids(seed: str) -> list[str]:
    done = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-p", "no:cacheprovider", "-p", "no:xdist"],
        cwd=ROOT,
        env={**os.environ, "PYTHONHASHSEED": seed},
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    return [line for line in done.stdout.splitlines() if "::" in line]


def differing(first: list[str], second: list[str]) -> list[str]:
    return sorted(set(first) ^ set(second))


def test_the_ids_do_not_depend_on_the_hash_seed() -> None:
    first, second = collected_ids("1"), collected_ids("2")
    assert len(first) > 1000, "the collection looks empty, so the comparison would prove nothing"
    assert differing(first, second) == []


def test_the_comparison_sees_an_id_that_changes() -> None:
    """The guard bites: ids that differ between two collections are reported."""
    assert differing(["t.py::a[x|1]", "t.py::b"], ["t.py::a[x|2]", "t.py::b"]) == ["t.py::a[x|1]", "t.py::a[x|2]"]
    assert differing(["t.py::a"], ["t.py::a"]) == []
