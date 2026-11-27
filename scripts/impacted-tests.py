#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Print the test files worth running for a set of changed files, or ALL when that cannot be said safely.

scripts/impacted-tests.py FILE [FILE ...]      changed files, relative to the repository root
scripts/impacted-tests.py --base BASE          changed files from `git diff --name-only BASE`
scripts/impacted-tests.py --root DIR ...       analyse another tree (the tests use this)

Output is test paths, one per line, sorted. Exit 0: run those. Exit 3: run the full suite (stdout is the single
line ALL, stderr is a one-line reason). Exit 2: usage error. The tool only reads files and parses them with `ast`;
it never imports or runs code from the tree it analyses. CI stays the judge: this is for targeted local runs.
"""

from __future__ import annotations

import argparse
import ast
import os
import re
import subprocess
import sys
from pathlib import Path

# Tests that always run, so a cheap run can never skip them.
GUARDS = (
    "tests/test_docs.py",
    "tests/test_duplicate_keys.py",
    "tests/test_output.py",
    "tests/test_privacy.py",
    "tests/test_readme_links.py",
)
MODULE_ROOTS = ("src", "tests", "packaging")  # the pytest pythonpath
MAX_CHANGED = 5000
MAX_FILES = 5000
MAX_BYTES = 1_000_000
MAX_OUT = 400
SAFE_PATH = re.compile(r"[A-Za-z0-9._/+@-]+")
SAFE_REF = re.compile(r"[A-Za-z0-9._/~^@{}-]+")
DOC_NAMES = frozenset({"LICENSE", "NOTICE"})


class Usage(Exception):
    pass


class RunAll(Exception):
    pass


def clean(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._/-]", "?", text)[:120]


def normalize(raw: str) -> str:
    path = raw[2:] if raw.startswith("./") else raw
    if not path or not SAFE_PATH.fullmatch(path) or path.startswith("/") or ".." in path.split("/"):
        raise Usage("unsafe or empty changed path")
    return path


def changed_from_git(root: Path, base: str) -> list[str]:
    if not SAFE_REF.fullmatch(base) or base.startswith("-"):
        raise Usage("unsafe base ref")
    cmd = ["git", "-C", str(root), "diff", "--name-only", "-z", "--no-ext-diff", "--no-textconv", base, "--"]
    try:
        proc = subprocess.run(cmd, capture_output=True, check=False, timeout=30)  # noqa: S603 - fixed argv
    except (OSError, subprocess.SubprocessError):
        raise RunAll("git diff could not run") from None
    if proc.returncode != 0:
        raise RunAll("git diff failed")
    return [p for p in proc.stdout.decode("utf-8", "replace").split("\0") if p]


def module_name(root_dir: str, rel: str) -> tuple[str, bool]:
    parts = rel[len(root_dir) + 1 :].removesuffix(".py").split("/")
    if parts[-1] == "__init__":
        return ".".join(parts[:-1]), True
    return ".".join(parts), False


def scan(root: Path) -> dict[str, tuple[str, bool]]:
    """Map every module file under the module roots to (dotted name, is package)."""
    found: dict[str, tuple[str, bool]] = {}
    for top in MODULE_ROOTS:
        base = root / top
        if not base.is_dir() or base.is_symlink():
            continue
        for here, dirs, files in os.walk(base, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d != "__pycache__" and not d.startswith("."))
            for name in sorted(files):
                if not name.endswith(".py"):
                    continue
                path = Path(here) / name
                if path.is_symlink():
                    raise RunAll("a python file is a symlink")
                rel = path.relative_to(root).as_posix()
                found[rel] = module_name(top, rel)
                if len(found) > MAX_FILES:
                    raise RunAll("too many python files to analyse")
    return found


def imports_of(root: Path, rel: str, name: str, is_pkg: bool, known: set[str]) -> set[str]:
    path = root / rel
    try:
        if path.stat().st_size > MAX_BYTES:
            raise RunAll("a python file is too large to analyse")
        tree = ast.parse(path.read_bytes())
    except (SyntaxError, ValueError, RecursionError, MemoryError, OSError):
        raise RunAll(f"cannot parse {clean(rel)}") from None
    package = name if is_pkg else name.rpartition(".")[0]
    wanted: set[str] = set()

    def add(dotted: str) -> None:
        parts = dotted.split(".")
        for i in range(1, len(parts) + 1):  # importing a.b.c also loads a and a.b
            prefix = ".".join(parts[:i])
            if prefix in known:
                wanted.add(prefix)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                up = package.split(".") if package else []
                if node.level - 1 > len(up):
                    continue
                up = up[: len(up) - (node.level - 1)]
                module = ".".join([*up, *([node.module] if node.module else [])])
            else:
                module = node.module or ""
            if module:
                add(module)
            for alias in node.names:
                add(f"{module}.{alias.name}" if module else alias.name)
    wanted.discard(name)
    return wanted


def is_doc(path: str) -> bool:
    return path.startswith("docs/") or path.endswith(".md") or path in DOC_NAMES


def named_tests(root: Path, stem: str) -> set[str]:
    stem = stem.replace("-", "_")
    tests = root / "tests"
    if not tests.is_dir():
        return set()
    return {
        f"tests/{p.name}"
        for p in tests.iterdir()
        if p.is_file() and p.suffix == ".py" and (p.stem == f"test_{stem}" or p.stem.startswith(f"test_{stem}_"))
    }


def impacted(root: Path, changed: list[str]) -> list[str]:
    files = scan(root)
    names = {name for name, _ in files.values()}
    by_name = {name: rel for rel, (name, _) in files.items()}
    deps = {rel: imports_of(root, rel, name, pkg, names) for rel, (name, pkg) in files.items()}
    importers: dict[str, set[str]] = {}
    for rel, wanted in deps.items():
        for dep in wanted:
            importers.setdefault(dep, set()).add(files[rel][0])

    chosen: set[str] = set()
    for path in changed:
        if is_doc(path):
            continue
        got: set[str] = set()
        stem = Path(path).stem
        if path.startswith("tests/") and re.fullmatch(r"tests/(?:.+/)?test_[^/]+\.py", path):
            got.add(path)  # a changed test runs itself, even if it was deleted (nothing to run then)
            chosen.update(p for p in got if (root / p).is_file())
            continue
        if path.startswith("scripts/"):
            got |= named_tests(root, stem)
        elif path.endswith(".py") and path in files:
            name = files[path][0]
            if path.startswith("src/"):
                got |= named_tests(root, name.rpartition(".")[2])
            reach, todo = {name}, [name]
            while todo:
                for up in importers.get(todo.pop(), ()):
                    if up not in reach:
                        reach.add(up)
                        todo.append(up)
            got |= {by_name[m] for m in reach if re.fullmatch(r"tests/(?:.+/)?test_[^/]+\.py", by_name[m])}
        elif path.endswith(".py") and path.startswith("src/"):
            got |= named_tests(root, stem)  # a deleted module: only the naming convention is left
        if not got:
            raise RunAll(f"no test maps to {clean(path)}")
        chosen.update(got)

    for guard in GUARDS:
        if not (root / guard).is_file() or (root / guard).is_symlink():
            raise RunAll("an always-run guard test is missing")
        chosen.add(guard)
    out = sorted(chosen)
    if len(out) > MAX_OUT:
        raise RunAll("too many tests selected")
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("files", nargs="*")
    parser.add_argument("--base")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 2
    try:
        root = Path(args.root).resolve()
        if args.base is None and not args.files:
            raise Usage("give changed files or --base BASE")
        if len(args.files) > MAX_CHANGED:
            raise Usage("too many changed files")
        try:
            raw = [*args.files, *(changed_from_git(root, args.base) if args.base is not None else [])]
            changed = sorted({normalize(p) for p in raw})
            if len(changed) > MAX_CHANGED:
                raise RunAll("too many changed files")
            if not changed:
                raise RunAll("no changed files reported")
            out = impacted(root, changed)
        except RunAll as why:
            print("ALL")
            print(f"run the full suite: {why}", file=sys.stderr)
            return 3
    except Usage as err:
        print(f"usage: {err}", file=sys.stderr)
        return 2
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
