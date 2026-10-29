# SPDX-License-Identifier: Apache-2.0
"""What SAFO leans on outside this package, and the read-only checks that say whether each is there.

The table is the single source for `safo doctor` and for the minimums in docs/prerequisites.md (a test holds the two
together). A probe is `<tool> --version` and nothing else, run with a closed stdin, a clean environment (so no token
reaches the child) and a short timeout; only the digits of the version are ever kept or printed.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from safo.bounded import loads, read_bounded

Status = Literal["present", "missing", "too old", "unreadable"]
Version = tuple[int, int, int]
PROBE_TIMEOUT_SECONDS = 5
MAX_PLUGIN_FILE = 1_048_576
PYTHON_MINIMUM: Version = (3, 11, 0)  # pyproject.toml: requires-python = ">=3.11"
_VERSION = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


@dataclass(frozen=True)
class Tool:
    name: str
    required: bool
    minimum: Version | None
    probe: bool = True  # False: presence only, because the program has no version flag we may call


# gh 2.57.0 added `gh auth status --active` (release notes, checked 2026-10-29); SAFO's own calls need less, the
# helpers that read the active account need that. codex 0.164.0 is the maintainer's rule for the cyber-program flag.
TOOLS: tuple[Tool, ...] = (
    Tool("git", True, (2, 5, 0)),
    Tool("gh", True, (2, 57, 0)),
    Tool("jq", False, None),
    Tool("doppler", False, None),
    Tool("ollama", False, None),
    Tool("codex", False, (0, 164, 0)),
    Tool("claude", False, None),
    Tool("llm-local", False, None, probe=False),
)

PLUGINS = (
    ("superpowers", "superpowers@"),
    ("codex-plugin", "codex@"),
    ("ollama-plugin", "ollama@"),
)
PACKS = (
    "pack-python-untrusted-input",
    "pack-gha-security-dast",
    "pack-threat-model",
    "pack-rf-emcomm",
    "pack-linux-platform",
    "pack-local-llm-routing",
)


@dataclass(frozen=True)
class Result:
    name: str
    status: Status
    required: bool
    version: Version | None = None
    minimum: Version | None = None
    note: str = ""

    @property
    def failing(self) -> bool:
        return self.required and self.status != "present"


def dotted(version: Version | None) -> str:
    return ".".join(map(str, version)) if version else ""


def parse_version(text: str) -> Version | None:
    found = _VERSION.search(text)
    if found is None:
        return None
    return (int(found[1]), int(found[2]), int(found[3] or 0))


def find_tool(name: str, env: Mapping[str, str]) -> str | None:
    """The first executable file called `name` on the absolute PATH entries of `env`. A relative or empty entry is the
    current directory, which a hostile checkout controls, so it is never searched; neither is a candidate whose real
    path is inside the current directory."""
    cwd = os.getcwd()
    for entry in env.get("PATH", "").split(os.pathsep):
        if not os.path.isabs(entry):
            continue
        candidate = os.path.join(entry, name)
        if not (os.path.isfile(candidate) and os.access(candidate, os.X_OK)):
            continue
        real = os.path.realpath(candidate)
        if real == cwd or real.startswith(cwd + os.sep):
            continue
        return candidate
    return None


def check_tool(tool: Tool, env: Mapping[str, str], run: Callable[..., Any] = subprocess.run) -> Result:
    path = find_tool(tool.name, env)
    if path is None:
        return Result(tool.name, "missing", tool.required, minimum=tool.minimum)
    if not tool.probe:
        return Result(tool.name, "present", tool.required, note="presence only; not run")
    clean = {"PATH": env.get("PATH", ""), "LC_ALL": "C"}  # no token, no GH_HOST: the child gets nothing to leak
    try:
        done = run(  # argument list, an absolute executable found above, no shell
            [path, "--version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=PROBE_TIMEOUT_SECONDS,
            env=clean,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return Result(tool.name, "unreadable", tool.required, minimum=tool.minimum)
    version = parse_version(done.stdout) if done.returncode == 0 and isinstance(done.stdout, str) else None
    if version is None:
        return Result(tool.name, "unreadable", tool.required, minimum=tool.minimum)
    if tool.minimum is not None and version < tool.minimum:
        return Result(tool.name, "too old", tool.required, version, tool.minimum)
    return Result(tool.name, "present", tool.required, version, tool.minimum)


def check_python(version: Sequence[int] = tuple(sys.version_info[:3])) -> Result:
    have: Version = (version[0], version[1], version[2] if len(version) > 2 else 0)
    status: Status = "present" if have >= PYTHON_MINIMUM else "too old"
    return Result("python", status, True, have, PYTHON_MINIMUM)


def _installed_plugins(home: Path | None) -> list[str]:
    """The keys of ~/.claude/plugins/installed_plugins.json. Anything unreadable or oddly shaped is no plugins."""
    if home is None:
        return []
    try:
        raw = read_bounded(home / ".claude" / "plugins" / "installed_plugins.json", MAX_PLUGIN_FILE)
        document = loads(raw)
    except (OSError, ValueError):
        return []
    plugins = document.get("plugins") if isinstance(document, dict) else None
    return [k for k in plugins if isinstance(k, str)] if isinstance(plugins, dict) else []


def check_extras(home: Path | None) -> list[Result]:
    """Plugins and skill packs, all optional: SAFO works without them and they never change the exit code."""
    keys = _installed_plugins(home)
    results = [
        Result(label, "present" if any(k.startswith(prefix) for k in keys) else "missing", False)
        for label, prefix in PLUGINS
    ]
    for pack in PACKS:
        skill = home / ".claude" / "skills" / pack / "SKILL.md" if home is not None else None
        results.append(Result(pack, "present" if skill is not None and skill.is_file() else "missing", False))
    return results
