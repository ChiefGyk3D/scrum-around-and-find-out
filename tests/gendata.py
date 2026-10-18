# SPDX-License-Identifier: Apache-2.0
"""Loading scripts/gen_profiles.py as a module with its paths pointed at a scratch repository."""

from __future__ import annotations

import importlib.util
import os
import stat
import sys
from pathlib import Path
from types import ModuleType

import pytest

from renderdata import render_repo

ROOT = Path(__file__).parent.parent


def load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("gen_profiles", ROOT / "scripts" / "gen_profiles.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["gen_profiles"] = module
    spec.loader.exec_module(module)
    return module


def scratch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[ModuleType, Path]:
    """The script aimed at tmp_path/repo (agents.yaml, lessons, persona, template), output in repo/examples/harness."""
    repo = tmp_path / "repo"
    agents = render_repo(repo)
    script = load_script()
    monkeypatch.setattr(script, "ROOT", repo)
    monkeypatch.setattr(script, "AGENTS", agents)
    monkeypatch.setattr(script, "OUT", repo / "examples" / "harness")
    return script, repo / "examples" / "harness"


def snapshot(root: Path) -> dict[str, tuple[int, bytes | str]]:
    """Every entry under root without following links: its type bits and its content (or link target)."""
    out: dict[str, tuple[int, bytes | str]] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in [*dirnames, *filenames]:
            p = Path(dirpath) / name
            mode = os.lstat(p).st_mode
            rel = str(p.relative_to(root))
            if stat.S_ISLNK(mode):
                out[rel] = (mode, os.readlink(p))
            elif stat.S_ISREG(mode):
                out[rel] = (mode, p.read_bytes())
            else:
                out[rel] = (mode, "")
    return out
