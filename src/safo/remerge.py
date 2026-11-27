# SPDX-License-Identifier: Apache-2.0
"""safo-remerge: merge origin/main into a branch and settle only the pure-table conflicts (#588).

    safo-remerge --worktree PATH --test-argv '["python", "-m", "pytest", "-q", "tests/test_x.py"]' [--test-timeout 900]

In one worktree: refuse unless it is a clean branch checkout that no other live process uses as a working directory;
`git fetch origin`; `git merge --no-ff --no-commit origin/main`. A conflict is settled by code only when the path is
CHANGELOG.md (inside its Unreleased section), docs/home.md or README.md and BOTH sides only added list or table lines
(the lines are kept, this branch's first, no marker left, no line twice). Any other conflicted path, or any change
that is not a pure addition on both sides, aborts the merge, restores the tree and exits 11 with the paths. After a
clean result the caller's test command runs (an argv list, never a shell); only if it exits 0 is the merge
committed with a fixed message. Nothing is pushed.

Exit codes: 0 merged and committed (or already up to date); 2 usage; 10 refused (dirty, busy, wrong branch);
11 needs an agent (paths printed); 12 the tests failed or timed out (merge aborted); 13 a git step failed
(merge aborted); 14 the tree could not be restored (look at it by hand).

The CHANGELOG rule sits behind `RESOLVERS` so a fragments-aware version (#581) can replace one function. Because the
rule reads the whole file, a branch that also edited an old line of one of these files goes to an agent.
"""

from __future__ import annotations

import argparse
import difflib
import os
import re
import stat
import subprocess
import sys
import tempfile
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from safo import bounded, output

EXIT_OK, EXIT_USAGE, EXIT_REFUSED, EXIT_NEEDS_AGENT = 0, 2, 10, 11
EXIT_TESTS_FAILED, EXIT_GIT, EXIT_NOT_RESTORED = 12, 13, 14
COMMIT_MESSAGE = "Merge origin/main (safo-remerge: table conflicts kept both sides)"
MAX_FILE_BYTES = 1_048_576
GIT_TIMEOUT = 120
MAX_TEST_TIMEOUT = 3600
DEFAULT_TEST_TIMEOUT = 900

Resolver = Callable[[str, str, str], str | None]  # (base, ours, theirs) -> merged text, or None for "needs an agent"

_LIST_OR_TABLE = re.compile(r"^(?:\s*(?:[-*+]|\d+\.)\s+\S|\s*\|)")
_CONTINUATION = re.compile(r"^\s{2,}\S")
_MARKER = re.compile(r"^(?:<{7}|={7}|>{7})(?: |$)", re.MULTILINE)


class NotAdditive(ValueError):
    """One side changed or removed a line of the base."""


_REDIRECTS = (  # variables that point git at another repository, index, config or program
    "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR", "GIT_NAMESPACE", "GIT_EXEC_PATH", "GIT_EXTERNAL_DIFF", "GIT_SSH_COMMAND", "GIT_ASKPASS",
    "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_CEILING_DIRECTORIES", "GIT_PREFIX",
)  # fmt: skip


def _git_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in _REDIRECTS and not k.startswith("GIT_CONFIG_KEY_")}
    env = {k: v for k, v in env.items() if not k.startswith("GIT_CONFIG_VALUE_")}
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_MERGE_AUTOEDIT": "no", "LC_ALL": "C", "GIT_EDITOR": "true"})
    return env


def git(worktree: Path, *args: str, timeout: int = GIT_TIMEOUT) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603 - argv list, no shell; `git` is looked up on PATH like every tool here
        ["git", "-c", "rerere.enabled=false", "-c", "core.fsmonitor=false", "-C", str(worktree), *args],  # noqa: S607
        env=_git_env(),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def _text(done: subprocess.CompletedProcess[bytes]) -> str:
    return done.stdout.decode("utf-8", "replace").strip()


# -- the pure-addition merge of one file ------------------------------------------------------------------------------


def _insertions(base: list[str], other: list[str]) -> dict[int, list[str]]:
    """Lines `other` added before base line i; raises NotAdditive on any replace or delete."""
    found: dict[int, list[str]] = {}
    for tag, i1, _i2, j1, j2 in difflib.SequenceMatcher(None, base, other, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        if tag != "insert":
            raise NotAdditive
        found[i1] = other[j1:j2]
    return found


def _addable(block: list[str]) -> bool:
    """A block of added lines starts with a list item or table row; only then may indented lines follow it."""
    if not block or not _LIST_OR_TABLE.match(block[0]):
        return False
    return all(_LIST_OR_TABLE.match(line) or _CONTINUATION.match(line) for line in block)


def merge_additions(
    base: str, ours: str, theirs: str, *, allowed_at: Callable[[int], bool] | None = None
) -> str | None:
    """Keep both sides' added list/table lines; None when anything else changed, repeats or sits where it may not."""
    texts = (base, ours, theirs)
    if any(not t.endswith("\n") or "\r" in t or "\x00" in t for t in texts):
        return None
    if any(len(t.encode()) > MAX_FILE_BYTES for t in texts):
        return None
    b, o, t = (x.splitlines(keepends=True) for x in texts)
    try:
        ins_o, ins_t = _insertions(b, o), _insertions(b, t)
    except NotAdditive:
        return None
    out: list[str] = []
    added: list[str] = []
    for i in range(len(b) + 1):
        mine, other = ins_o.get(i, []), ins_t.get(i, [])
        block = mine if mine == other else mine + other
        if block and allowed_at is not None and not allowed_at(i):
            return None
        if any(side and not _addable(side) for side in (mine, other)):
            return None
        out.extend(block)
        added.extend(block)
        if i < len(b):
            out.append(b[i])
    counts = Counter(out)
    if any(counts[line] != 1 for line in added):  # a line twice (same on both sides, or already in the base)
        return None
    merged = "".join(out)
    if _MARKER.search(merged):
        return None
    return merged


def resolve_changelog(base: str, ours: str, theirs: str) -> str | None:
    """CHANGELOG.md: additions only, and only inside the Unreleased section. Replace this for fragments (#581)."""
    lines = base.splitlines(keepends=True)
    starts = [n for n, line in enumerate(lines) if line.rstrip() == "## Unreleased"]
    if len(starts) != 1:
        return None
    first = starts[0] + 1
    last = next((n for n in range(first, len(lines)) if lines[n].startswith("## ")), len(lines))
    return merge_additions(base, ours, theirs, allowed_at=lambda i: first <= i <= last)


def resolve_table_page(base: str, ours: str, theirs: str) -> str | None:
    """docs/home.md and README.md: list and table lines added by both sides."""
    return merge_additions(base, ours, theirs)


RESOLVERS: Mapping[str, Resolver] = {
    "CHANGELOG.md": resolve_changelog,
    "docs/home.md": resolve_table_page,
    "README.md": resolve_table_page,
}


# -- the merge --------------------------------------------------------------------------------------------------


def _live_users(worktree: Path) -> list[int]:
    """Other processes whose working directory is the worktree or below it; no /proc fails closed."""
    proc = Path("/proc")
    if not proc.is_dir():
        raise OSError("no /proc")
    root = worktree.resolve()
    mine = os.getpid()
    users: list[int] = []
    for entry in proc.iterdir():
        if not entry.name.isdigit() or int(entry.name) == mine:
            continue
        try:
            cwd = Path(os.readlink(entry / "cwd"))
        except OSError:
            continue  # gone, or another user's process: nothing to learn
        if cwd == root or root in cwd.parents:
            users.append(int(entry.name))
    return users


def _refusal(worktree: Path) -> str | None:
    top = git(worktree, "rev-parse", "--show-toplevel")
    if top.returncode != 0 or Path(_text(top)).resolve() != worktree.resolve():
        return "not the top of a git worktree"
    branch = _text(git(worktree, "symbolic-ref", "--quiet", "--short", "HEAD"))
    if not branch or branch in {"main", "master"}:
        return "needs a feature branch (detached HEAD, main and master are refused)"
    if git(worktree, "rev-parse", "-q", "--verify", "MERGE_HEAD").returncode == 0:
        return "a merge is already in progress"
    state = git(worktree, "status", "--porcelain", "--untracked-files=all")
    if state.returncode != 0 or state.stdout.strip():
        return "the tree is not clean"
    try:
        users = _live_users(worktree)
    except OSError:
        return "cannot list the live processes"
    if users:
        return "a live process has this worktree as its working directory (pid " + ", ".join(map(str, users[:5])) + ")"
    return None


def _stage_paths(worktree: Path) -> dict[str, dict[int, str]]:
    """Unmerged paths -> {stage: mode}."""
    out = git(worktree, "ls-files", "-u", "-z").stdout.decode("utf-8", "replace")
    paths: dict[str, dict[int, str]] = {}
    for record in filter(None, out.split(chr(0))):
        meta, _, path = record.partition("\t")
        mode, _sha, stage = meta.split()
        paths.setdefault(path, {})[int(stage)] = mode
    return paths


def _blob(worktree: Path, stage: int, path: str) -> str | None:
    done = git(worktree, "show", f":{stage}:{path}")
    if done.returncode != 0 or len(done.stdout) > MAX_FILE_BYTES:
        return None
    try:
        return done.stdout.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _settle(worktree: Path, paths: dict[str, dict[int, str]], resolvers: Mapping[str, Resolver]) -> list[str]:
    """Resolve what code may; return the paths that need an agent (empty when all settled)."""
    if any(p not in resolvers for p in paths):
        return sorted(paths)
    results: dict[str, str] = {}
    for path, stages in paths.items():
        if set(stages) != {1, 2, 3} or any(m != "100644" for m in stages.values()):
            return sorted(paths)  # a delete, an add on one side, a mode change or a link
        target = worktree / path
        if target.is_symlink() or not target.is_file():
            return sorted(paths)
        base, ours, theirs = (_blob(worktree, n, path) for n in (1, 2, 3))
        if base is None or ours is None or theirs is None:
            return sorted(paths)
        merged = resolvers[path](base, ours, theirs)
        if merged is None:
            return sorted(paths)
        results[path] = merged
    for path, merged in results.items():
        (worktree / path).write_text(merged, encoding="utf-8")
        if git(worktree, "add", "--", path).returncode != 0:
            return sorted(paths)
    return []


def _restore(worktree: Path, head: str) -> bool:
    git(worktree, "merge", "--abort")
    if git(worktree, "rev-parse", "-q", "--verify", "MERGE_HEAD").returncode == 0:
        return False
    same = _text(git(worktree, "rev-parse", "HEAD")) == head
    return same and git(worktree, "status", "--porcelain", "--untracked-files=all").stdout.strip() == b""


OUTPUT_TAIL_BYTES = 65536
OUTPUT_TAIL_LINES = 40


def _run_tests(worktree: Path, argv: list[str], timeout: int) -> int | None:
    """Run the caller's command; its output is captured and shown through safo.output, never passed through raw."""
    with tempfile.TemporaryFile() as sink:
        try:
            code: int | None = subprocess.run(  # noqa: S603 - the caller's argv list, no shell
                argv, cwd=worktree, stdin=subprocess.DEVNULL, stdout=sink, stderr=subprocess.STDOUT, timeout=timeout,
                check=False,
            ).returncode  # fmt: skip
        except subprocess.TimeoutExpired:
            code = None
        except OSError:
            code = 127
        size = sink.seek(0, os.SEEK_END)
        sink.seek(max(0, size - OUTPUT_TAIL_BYTES))
        tail = sink.read().decode("utf-8", "replace").splitlines()[-OUTPUT_TAIL_LINES:]
    for text in tail:
        output.write(sys.stdout, "test> " + text[:300])
    return code


def _parse_argv(text: str) -> list[str] | None:
    try:
        data = bounded.loads(text, 65536)
    except ValueError:
        return None
    if isinstance(data, list) and data and all(isinstance(x, str) and x and chr(0) not in x for x in data):
        return data
    return None


def remerge(
    worktree: Path, test_argv: list[str], test_timeout: int, *, resolvers: Mapping[str, Resolver] = RESOLVERS
) -> int:
    out, err = sys.stdout, sys.stderr
    reason = _refusal(worktree)
    if reason:
        output.write(err, f"safo-remerge: refused: {reason}")
        output.write(out, f"refused: {reason}")
        return EXIT_REFUSED
    head = _text(git(worktree, "rev-parse", "HEAD"))
    try:
        return _transaction(worktree, head, test_argv, test_timeout, resolvers)
    except subprocess.TimeoutExpired:
        output.write(out, "a git step timed out; merge aborted")
        try:
            return EXIT_GIT if _restore(worktree, head) else EXIT_NOT_RESTORED
        except subprocess.TimeoutExpired:
            return EXIT_NOT_RESTORED


def _transaction(
    worktree: Path, head: str, test_argv: list[str], test_timeout: int, resolvers: Mapping[str, Resolver]
) -> int:
    out = sys.stdout
    if git(worktree, "fetch", "origin", "--quiet").returncode != 0:
        output.write(out, "git fetch origin failed; nothing changed")
        return EXIT_GIT
    merge = git(worktree, "merge", "--no-ff", "--no-commit", "origin/main")
    in_merge = git(worktree, "rev-parse", "-q", "--verify", "MERGE_HEAD").returncode == 0
    if not in_merge:
        if merge.returncode == 0:
            output.write(out, "already up to date; nothing to do")
            return EXIT_OK
        output.write(out, "git merge failed before it started; nothing changed")
        for note in merge.stderr.decode("utf-8", "replace").splitlines()[:3]:
            output.write(out, "git: " + note[:200])
        return EXIT_GIT if _restore(worktree, head) else EXIT_NOT_RESTORED
    conflicts = _stage_paths(worktree)
    needs_agent = _settle(worktree, conflicts, resolvers) if conflicts else []
    if needs_agent or (merge.returncode != 0 and not conflicts):
        ok = _restore(worktree, head)
        if needs_agent:
            output.write(
                out, "needs an agent: merge aborted, tree restored" if ok else "needs an agent: RESTORE FAILED"
            )
            for path in needs_agent:
                output.write(out, f"needs-agent: {path}")
        else:
            output.write(out, "git merge failed; aborted")
        if not ok:
            return EXIT_NOT_RESTORED
        return EXIT_NEEDS_AGENT if needs_agent else EXIT_GIT
    code = _run_tests(worktree, test_argv, test_timeout)
    output.write(out, "tests: timed out" if code is None else f"tests: exit {code}")
    if code != 0:
        return EXIT_TESTS_FAILED if _restore(worktree, head) else EXIT_NOT_RESTORED
    done = git(worktree, "commit", "-q", "-m", COMMIT_MESSAGE)
    if done.returncode != 0:
        output.write(out, "git commit failed; merge aborted")
        return EXIT_GIT if _restore(worktree, head) else EXIT_NOT_RESTORED
    output.write(out, "merged and committed (not pushed): " + _text(git(worktree, "rev-parse", "--short", "HEAD")))
    return EXIT_OK


def entry(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="safo-remerge", description="Merge origin/main, settle only pure-table conflicts."
    )
    ap.add_argument("--worktree", type=Path, default=Path.cwd(), help="the worktree to merge in (default: here)")
    ap.add_argument("--test-argv", required=True, help='the test command as a JSON list, e.g. \'["pytest", "-q"]\'')
    ap.add_argument(
        "--test-timeout", type=int, default=DEFAULT_TEST_TIMEOUT, help="seconds before the tests are killed"
    )
    try:
        args = ap.parse_args(argv)
    except SystemExit as stop:
        return EXIT_USAGE if stop.code else EXIT_OK
    test_argv = _parse_argv(args.test_argv)
    if test_argv is None:
        output.write(sys.stderr, "safo-remerge: --test-argv must be a non-empty JSON list of strings (no shell string)")
        return EXIT_USAGE
    if not 1 <= args.test_timeout <= MAX_TEST_TIMEOUT:
        output.write(sys.stderr, f"safo-remerge: --test-timeout must be 1 to {MAX_TEST_TIMEOUT}")
        return EXIT_USAGE
    try:
        info = args.worktree.stat()
    except OSError:
        output.write(sys.stderr, "safo-remerge: the worktree does not exist")
        return EXIT_USAGE
    if not stat.S_ISDIR(info.st_mode):
        output.write(sys.stderr, "safo-remerge: the worktree is not a directory")
        return EXIT_USAGE
    try:
        return remerge(args.worktree, test_argv, args.test_timeout)
    except subprocess.TimeoutExpired:
        output.write(sys.stderr, "safo-remerge: a git step timed out")
        return EXIT_GIT


if __name__ == "__main__":
    sys.exit(entry())
