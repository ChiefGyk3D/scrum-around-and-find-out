# SPDX-License-Identifier: Apache-2.0
"""`safo-codex-run`: one safe way to run one Codex command per task class (#431, epic #428, design phase 2).

The lead hands over a prompt FILE (never an argument string), a class and, for two classes, a worktree. Everything
else is fixed here, in code, so it is not remembered per call:

| class       | model              | tier flag                  | sandbox         | working root       |
|-------------|--------------------|----------------------------|-----------------|--------------------|
| implementer | the general model  | none                       | workspace-write | the named worktree |
| review      | the general model  | none                       | read-only       | the named worktree |
| copy        | the general model  | none                       | read-only       | an EMPTY temp dir  |
| security    | daybreak-blue-latest | daybreak_blue (cyber tier) | read-only     | an EMPTY temp dir  |

`security` always carries the cyber tier flags and runs from an empty temporary folder (the owner's Daybreak rule of
2026-10-24); the material to review goes in the prompt file. No flag chooses a model or a sandbox: `--model` and
`--sandbox` are not accepted, and any unknown option is a refusal that runs nothing. `implementer` gets `-s
workspace-write` with the named worktree as its only root and the sandbox's network switch pinned off.

What it does, in order, and stops at the first refusal with NO codex call (exit 2):

1. Reads the prompt file through one descriptor opened without following a link: a regular file, ours, not writable
   by group or other, 1 byte to MAX_PROMPT_BYTES, inside an allowed folder (`~/.local/share/<name>-dev/...` or the
   harness scratchpad `/tmp/claude-<uid>/...`). A symlink, a FIFO, an oversize file and any path outside those
   folders is refused. The text is scanned for secret shapes (the shapes `safo gemini` already uses) and for the
   entries of the private deny list `~/.config/safo/codex-deny.txt` (one literal per line, never in a repository; a
   hit names the line number only). What codex receives is a private copy of exactly the bytes that were hashed.
2. For `implementer` and `review`, checks the worktree: a linked git worktree (its `.git` is a file, its top level is
   the folder named) under `~/.local/share/<name>-dev/` or a `.claude/worktrees/` folder below the account home. An
   `implementer` run also needs a clean tree, except for paths named with `--allow-dirty` (repeatable).
3. Starts codex by an absolute path, no shell, with an allow-list environment (a fixed PATH plus the directories of
   codex and node, HOME from the account database, CODEX_HOME, locale, a private TMPDIR; no `GH_*`, no tokens, no
   `*_API_KEY`, no secret-manager variables), `--ignore-user-config` and `--ignore-rules` (so `config.toml` cannot
   add a tool server or change the sandbox), `--ephemeral`, stdin from the prompt copy, its own process group, and a
   hard timeout (default 1800 s, at most 3600 s). On a timeout the whole process group is killed (exit 124).
4. Looks for the cybersecurity-risk cutoff (the phrase "flagged for possible cybersecurity risk" in codex's error
   stream or in a short final message). If found: exit 40, say which tier was set, and tell the lead to fix the tier.
   It never rewords the prompt, never retries, never falls back to another model (the Daybreak fallback is not
   active; only the owner decides one).
5. Appends ONE row to `~/.local/state/safo/codex-runs.jsonl`: ts, class, model, sandbox, tier, exit, codex_exit,
   seconds, prompt_bytes, prompt_sha256. Never the prompt, never the output text. The ledger is opened BEFORE the run,
   so a run that could not be recorded does not start.
6. Prints one summary line on standard output with the result path (the final message, under
   `~/.local/state/safo/codex-runs/`, mode 0600).

Exit codes: 0 done; 2 refused or could not start (nothing ran); 30 codex failed (its own code is in the ledger);
40 tier filtered; 124 timed out.

What it does NOT do (and the Daybreak review should weigh): the read-only sandbox lets codex READ any file the account
can read, so "empty folder" fixes the starting point, not a read fence; a same-user process can change a file between
the checks and the run (the prompt is copied, the worktree is not); the sandbox network switch for `implementer` is the
`sandbox_workspace_write.network_access` setting, and is only as strong as codex's own sandbox. It does not edit any
guard or settings file; the permission rule that lets the lead run it without a prompt is phase 3, by the owner.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import os
import pwd
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import NoReturn

from safo import output
from safo.bounded import loads
from safo.errors import EXIT_OK, EXIT_UNKNOWN, SafoError

SAFE_PATH = "/usr/local/bin:/usr/bin:/bin"
LOCALE = "C.UTF-8"

EXIT_REFUSED = EXIT_UNKNOWN  # 2: nothing ran
EXIT_CODEX_FAILED = 30
EXIT_FILTERED = 40
EXIT_TIMEOUT = 124  # the code coreutils `timeout` uses

# The general model for implementer, review and copy: the default Codex lists first in its model cache
# (`~/.codex/models_cache.json`, priority 1, read 2026-11-24). Pinned here on purpose (design Q6); re-verify monthly.
GENERAL_MODEL = "gpt-6.1-terra"
DAYBREAK_MODEL = "gpt-daybreak-blue-latest"
DAYBREAK_TIER = "daybreak_blue"

DEFAULT_TIMEOUT = 1800
MAX_TIMEOUT = 3600
MAX_PROMPT_BYTES = 512 * 1024
MAX_TAIL = 1024 * 1024  # how much of codex's error stream is read for the cutoff phrase
SHORT_MESSAGE = 8 * 1024  # a final message this small may be the cutoff notice itself; a long review is not
FILTER_PHRASE = "flagged for possible cybersecurity risk"

STATE_PARTS = (".local", "state", "safo")
LEDGER_NAME = "codex-runs.jsonl"
RESULTS_NAME = "codex-runs"
SCRATCH_NAME = "codex-run-scratch"
DENY_LIST = (".config", "safo", "codex-deny.txt")


class CodexRunError(SafoError):
    """A refusal or a failure to start; nothing was sent to codex."""

    exit_code = EXIT_REFUSED


@dataclass(frozen=True)
class ClassSpec:
    model: str
    sandbox: str
    tier: str  # "" when the class has no cyber tier flag
    root: str  # "worktree" or "empty"
    network_off: bool  # pin the workspace-write network switch off


SPECS: Mapping[str, ClassSpec] = {
    "implementer": ClassSpec(GENERAL_MODEL, "workspace-write", "", "worktree", True),
    "review": ClassSpec(GENERAL_MODEL, "read-only", "", "worktree", False),
    "copy": ClassSpec(GENERAL_MODEL, "read-only", "", "empty", False),
    "security": ClassSpec(DAYBREAK_MODEL, "read-only", DAYBREAK_TIER, "empty", False),
}
NEEDS_WORKTREE = ("implementer", "review")


def account_home() -> str:
    try:
        return pwd.getpwuid(os.geteuid()).pw_dir  # the account database: $HOME is the caller's to set
    except KeyError:
        raise CodexRunError("this account has no home directory in the account database; nothing was run") from None


# -- the command line ------------------------------------------------------------------------------------------------


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:  # never print the offending text; usage errors are refusals
        raise CodexRunError(f"bad command line: {message.split(':')[0]}; nothing was run")


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="safo-codex-run", allow_abbrev=False, add_help=True)
    parser.add_argument("--class", dest="cls", required=True, choices=sorted(SPECS))
    parser.add_argument("--prompt-file", required=True)
    parser.add_argument("--worktree", default=None)
    parser.add_argument("--allow-dirty", action="append", default=[], metavar="PATH")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    return parser


def parse(argv: Sequence[str]) -> argparse.Namespace:
    args, extra = build_parser().parse_known_args(list(argv))
    if extra:
        # names only, and only the option part: a stray value could be anything
        names = sorted({word.split("=", 1)[0][:40] for word in extra if word.startswith("-")})
        shown = ", ".join(names) if names else "a stray argument"
        raise CodexRunError(
            f"not accepted: {shown}; the model, tier, sandbox and prompt are fixed by --class and --prompt-file; "
            "nothing was run"
        )
    if not 1 <= args.timeout <= MAX_TIMEOUT:
        raise CodexRunError(f"--timeout must be 1 to {MAX_TIMEOUT} seconds; nothing was run")
    if args.cls in NEEDS_WORKTREE and not args.worktree:
        raise CodexRunError(f"class {args.cls} needs --worktree; nothing was run")
    if args.cls not in NEEDS_WORKTREE and args.worktree:
        raise CodexRunError(
            f"class {args.cls} runs from an empty temporary folder and takes no --worktree; put the material "
            "in the prompt file; nothing was run"
        )
    if args.allow_dirty and args.cls != "implementer":
        raise CodexRunError("--allow-dirty applies to the implementer class only; nothing was run")
    return args


# -- paths ---------------------------------------------------------------------------------------------------------


def _under(real: str, root: str) -> bool:
    return real == root or real.startswith(root.rstrip("/") + "/")


def in_dev_folder(real: str, home: str) -> bool:
    """`~/.local/share/<name>-dev/<something>`: strictly below a dev folder, never the folder itself."""
    share = os.path.realpath(os.path.join(home, ".local", "share"))
    if not _under(real, share) or real == share:
        return False
    parts = real[len(share) :].strip("/").split("/")
    return len(parts) >= 2 and len(parts[0]) > len("-dev") and parts[0].endswith("-dev")


def allowed_prompt_folder(real: str, home: str) -> bool:
    """A dev folder, or the harness scratchpad `/tmp/claude-<uid>/<something>`."""
    if in_dev_folder(real, home):
        return True
    scratch = os.path.realpath(f"/tmp/claude-{os.geteuid()}")  # noqa: S108 - the harness scratchpad parent, read only
    return _under(real, scratch) and real != scratch


def allowed_worktree_folder(real: str, home: str) -> bool:
    """A dev folder, or a `.claude/worktrees/<dir>` folder below the account home."""
    if in_dev_folder(real, home):
        return True
    root = os.path.realpath(home)
    if not _under(real, root):
        return False
    parts = real[len(root) :].strip("/").split("/")
    return any(parts[i] == ".claude" and parts[i + 1] == "worktrees" for i in range(len(parts) - 2))


@dataclass(frozen=True)
class Prompt:
    data: bytes
    sha256: str


def read_prompt(path: str, home: str) -> Prompt:
    """The prompt file's bytes, after every check, from the one descriptor that was checked."""
    if not path or "\0" in path:
        raise CodexRunError("the prompt file path is empty or not a path; nothing was run")
    real = os.path.realpath(path)
    if not allowed_prompt_folder(real, home):
        raise CodexRunError(
            "the prompt file is outside the allowed folders (a folder named *-dev under ~/.local/share, or the "
            "harness scratchpad); nothing was run"
        )
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as err:
        raise CodexRunError(
            f"the prompt file cannot be opened without following a link ({err.strerror}); nothing was run"
        ) from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise CodexRunError("the prompt file is not a regular file (a FIFO, a device or a folder); nothing was run")
        if st.st_uid != os.geteuid() or st.st_mode & 0o022:
            raise CodexRunError("the prompt file is not ours or is writable by others; nothing was run")
        if st.st_size < 1 or st.st_size > MAX_PROMPT_BYTES:
            raise CodexRunError(f"the prompt file must be 1 to {MAX_PROMPT_BYTES} bytes; nothing was run")
        with os.fdopen(os.dup(fd), "rb") as handle:
            data = handle.read(MAX_PROMPT_BYTES + 1)
    finally:
        os.close(fd)
    if not data or len(data) > MAX_PROMPT_BYTES:
        raise CodexRunError(f"the prompt file must be 1 to {MAX_PROMPT_BYTES} bytes; nothing was run")
    return Prompt(data, hashlib.sha256(data).hexdigest())


def deny_entries(home: str) -> list[str]:
    path = os.path.join(home, *DENY_LIST)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return []
    except OSError:
        raise CodexRunError("the private deny list exists but cannot be opened; nothing was run") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o022 or st.st_size > 65536:
            raise CodexRunError("the private deny list is not a plain private file; nothing was run")
        with os.fdopen(os.dup(fd), "rb") as handle:
            text = handle.read(65537).decode("utf-8", "replace")
    finally:
        os.close(fd)
    return [line.strip().lower() for line in text.splitlines() if line.strip() and not line.startswith("#")]


def scan_prompt(prompt: Prompt, home: str) -> None:
    from safo.gemini import has_secret_shape  # lazily: the shapes live with the Gemini wrapper

    text = prompt.data.decode("utf-8", "replace")
    if has_secret_shape(text):
        raise CodexRunError("the prompt holds a secret-shaped string; it is not sent; nothing was run")
    lowered = text.lower()
    for number, entry in enumerate(deny_entries(home), start=1):
        if entry in lowered:
            raise CodexRunError(
                f"the prompt holds an entry of the private deny list (entry {number}); it is not sent; nothing was run"
            )


def git_env(home: str) -> dict[str, str]:
    return {
        "PATH": SAFE_PATH,
        "HOME": home,
        "LANG": LOCALE,
        "LC_ALL": LOCALE,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }


def _git(git: str, home: str, root: str, *args: str) -> str:
    try:
        done = subprocess.run(  # noqa: S603 - absolute git, fixed argv, no shell, stdin closed, bounded time
            [git, "-c", "core.fsmonitor=false", "-C", root, *args],
            env=git_env(home),
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise CodexRunError("git could not be run on the worktree; nothing was run") from None
    if done.returncode != 0:
        raise CodexRunError("the worktree is not a usable git work tree; nothing was run")
    return done.stdout.decode("utf-8", "replace")


def check_worktree(path: str, home: str, cls: str, allow_dirty: Sequence[str]) -> str:
    """The worktree's real path, after the checks; for the implementer the tree must be clean."""
    if not path or "\0" in path:
        raise CodexRunError("the worktree path is empty or not a path; nothing was run")
    real = os.path.realpath(path)
    if not os.path.isdir(real) or not allowed_worktree_folder(real, home):
        raise CodexRunError(
            "the worktree is not a folder under ~/.local/share/<name>-dev or a .claude/worktrees folder; "
            "nothing was run"
        )
    marker = os.path.join(real, ".git")
    if os.path.islink(marker) or not os.path.isfile(marker):
        raise CodexRunError("the folder is not a linked git worktree (its .git is not a plain file); nothing was run")
    git = shutil.which("git", path=SAFE_PATH)
    if not git:
        raise CodexRunError("git was not found; nothing was run")
    top = os.path.realpath(_git(git, home, real, "rev-parse", "--show-toplevel").strip())
    if top != real:
        raise CodexRunError("the folder named is not the top of its git worktree; nothing was run")
    if cls == "implementer":
        raw = _git(git, home, real, "status", "--porcelain=v1", "-z", "--untracked-files=all")
        dirty = _dirty_paths(raw)
        named = {os.path.normpath(p) for p in allow_dirty}
        loose = [p for p in dirty if os.path.normpath(p) not in named]
        if loose:
            raise CodexRunError(
                f"the worktree has {len(loose)} uncommitted path(s) not named with --allow-dirty "
                f"(first: {output.line(loose[0][:80])}); commit, stash or name them; nothing was run"
            )
    return real


def _dirty_paths(raw: str) -> list[str]:
    parts = raw.split("\0")
    out: list[str] = []
    skip = False
    for item in parts:
        if skip:  # the origin half of a rename or copy
            skip = False
            continue
        if len(item) < 4:
            continue
        out.append(item[3:])
        if item[0] in "RC" or item[1] in "RC":
            skip = True
    return out


# -- codex, its environment, and its argument list ------------------------------------------------------------------


def find_binary(name: str, env: Mapping[str, str]) -> str | None:
    found = shutil.which(name, path=env.get("PATH", ""))
    return os.path.abspath(found) if found else None


def check_codex(binary: str) -> None:
    st = os.stat(binary)
    if not stat.S_ISREG(st.st_mode) or not os.access(binary, os.X_OK) or st.st_mode & 0o022:
        raise CodexRunError("the codex binary is not a plain executable that only its owner can write; nothing was run")


def child_path(codex: str, node: str | None) -> str:
    dirs: list[str] = []
    for item in (codex, os.path.realpath(codex), node):
        if item:
            folder = os.path.dirname(item)
            if folder not in dirs and folder not in SAFE_PATH.split(":"):
                dirs.append(folder)
    return ":".join([*dirs, SAFE_PATH])


def child_env(home: str, codex: str, node: str | None, caller: Mapping[str, str], scratch: str) -> dict[str, str]:
    """The whole environment of codex: this allow-list, built here, never a copy of the caller's."""
    codex_home = caller.get("CODEX_HOME", "")
    if not (codex_home and os.path.isabs(codex_home) and os.path.isdir(codex_home)):
        codex_home = os.path.join(home, ".codex")
    return {
        "PATH": child_path(codex, node),
        "HOME": home,
        "CODEX_HOME": codex_home,
        "LANG": LOCALE,
        "LC_ALL": LOCALE,
        "TMPDIR": scratch,
    }


def build_argv(codex: str, cls: str, root: str, out: str) -> list[str]:
    spec = SPECS[cls]
    argv = [
        codex,
        "exec",
        "--skip-git-repo-check",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--color",
        "never",
        "--json",
        "-s",
        spec.sandbox,
        "-m",
        spec.model,
    ]
    if spec.tier:
        argv += ["--cyber-access-program", spec.tier]
    if spec.network_off:
        argv += ["-c", "sandbox_workspace_write.network_access=false"]
    argv += ["-C", root, "-o", out, "-"]
    return argv


# -- private folders and the ledger --------------------------------------------------------------------------------


def private_chain(home: str, parts: Sequence[str]) -> str:
    """`home/parts...`, each folder made if missing, opened without following a link, ours; the last is mode 0700."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for name in parts:
                with contextlib.suppress(FileExistsError):
                    os.mkdir(name, stat.S_IRWXU, dir_fd=fd)
                nxt = os.open(name, flags, dir_fd=fd)
                os.close(fd)
                fd = nxt
                st = os.fstat(fd)
                if st.st_uid != os.geteuid() or st.st_mode & 0o022:
                    raise CodexRunError("a state folder is not private to this user; nothing was run")
            os.fchmod(fd, stat.S_IRWXU)
        finally:
            os.close(fd)
    except OSError as err:
        raise CodexRunError(f"a state folder cannot be used ({err.strerror}); nothing was run") from None
    return os.path.join(home, *parts)


def open_ledger(home: str) -> int:
    folder = private_chain(home, STATE_PARTS)
    try:
        fd = os.open(
            os.path.join(folder, LEDGER_NAME),
            os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            stat.S_IRUSR | stat.S_IWUSR,
        )
    except OSError as err:
        raise CodexRunError(f"the ledger cannot be opened ({err.strerror}); nothing was run") from None
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o022:
        os.close(fd)
        raise CodexRunError("the ledger is not a plain private file; nothing was run")
    return fd


def ledger_row(
    cls: str, prompt: Prompt, exit_code: int, codex_exit: int | None, seconds: float, now: dt.datetime
) -> dict[str, object]:
    """Counts, names and a hash. Never the prompt, never the output."""
    spec = SPECS[cls]
    return {
        "ts": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "class": cls,
        "model": spec.model,
        "sandbox": spec.sandbox,
        "tier": spec.tier or "none",
        "exit": exit_code,
        "codex_exit": codex_exit,
        "seconds": round(seconds, 1),
        "prompt_bytes": len(prompt.data),
        "prompt_sha256": prompt.sha256,
    }


def append_row(fd: int, row: Mapping[str, object]) -> None:
    import json

    line = (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        os.write(fd, line)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)


# -- the run ----------------------------------------------------------------------------------------------------


def _tail(path: str, limit: int) -> str:
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - limit))
            return handle.read(limit).decode("utf-8", "replace")
    except OSError:
        return ""


def _squash(text: str) -> str:
    return " ".join(text.lower().split())


def tier_filtered(stderr_path: str, events_path: str, out_path: str) -> bool:
    """True when codex was cut off by the cybersecurity-risk filter. The phrase counts in the error stream, in an
    error event, and in a SHORT final message; a long review that merely quotes it does not."""
    if FILTER_PHRASE in _squash(_tail(stderr_path, MAX_TAIL)):
        return True
    for raw in _tail(events_path, MAX_TAIL).splitlines():
        if FILTER_PHRASE not in _squash(raw):
            continue
        try:
            event = loads(raw)
        except ValueError:
            continue
        kind = str(event.get("type", "")) if isinstance(event, dict) else ""
        if "error" in kind or "fail" in kind:
            return True
    try:
        small = os.path.getsize(out_path) <= SHORT_MESSAGE
    except OSError:
        return False
    return small and FILTER_PHRASE in _squash(_tail(out_path, SHORT_MESSAGE))


def _kill_group(pgid: int) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pgid, signal.SIGKILL)


def run_codex(
    argv: Sequence[str], env: Mapping[str, str], cwd: str, stdin_path: str, meta: str, timeout: int
) -> tuple[int, bool]:
    """(codex exit code, timed out). Its own process group; the group is killed on a timeout and when it ends."""
    with (
        open(stdin_path, "rb") as stdin,
        open(os.path.join(meta, "events"), "wb") as events,
        open(os.path.join(meta, "stderr"), "wb") as errors,
    ):
        proc = subprocess.Popen(  # noqa: S603 - absolute codex, fixed argv, no shell, allow-list env, own group
            list(argv),
            stdin=stdin,
            stdout=events,
            stderr=errors,
            cwd=cwd,
            env=dict(env),
            close_fds=True,
            start_new_session=True,
        )
        try:
            code = proc.wait(timeout=timeout)
            _kill_group(proc.pid)
            return code, False
        except subprocess.TimeoutExpired:
            _kill_group(proc.pid)
            proc.wait()
            return -signal.SIGKILL, True


def _new_result(home: str, cls: str, now: dt.datetime) -> str:
    folder = private_chain(home, (*STATE_PARTS, RESULTS_NAME))
    path = os.path.join(folder, f"{now.strftime('%Y%m%dT%H%M%SZ')}-{cls}-{secrets.token_hex(4)}.out")
    try:
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, stat.S_IRUSR | stat.S_IWUSR))
    except OSError as err:
        raise CodexRunError(f"the result file cannot be created ({err.strerror}); nothing was run") from None
    return path


def _lines(path: str) -> int:
    try:
        with open(path, "rb") as handle:
            return sum(1 for _ in handle)
    except OSError:
        return 0


def execute(args: argparse.Namespace, caller_env: Mapping[str, str], home: str) -> int:
    cls: str = args.cls
    spec = SPECS[cls]
    prompt = read_prompt(args.prompt_file, home)
    scan_prompt(prompt, home)
    worktree = check_worktree(args.worktree, home, cls, args.allow_dirty) if cls in NEEDS_WORKTREE else ""
    codex = find_binary("codex", caller_env)
    if not codex:
        raise CodexRunError("codex was not found on PATH; nothing was run")
    check_codex(codex)
    node = find_binary("node", caller_env)
    ledger = open_ledger(home)
    meta = empty = ""
    now = dt.datetime.now(dt.UTC)
    started = time.monotonic()
    try:
        scratch_parent = private_chain(home, (*STATE_PARTS, SCRATCH_NAME))
        meta = tempfile.mkdtemp(prefix="run-", dir=scratch_parent)
        empty = tempfile.mkdtemp(prefix="empty-", dir=scratch_parent) if spec.root == "empty" else ""
        result = _new_result(home, cls, now)
        copy_path = os.path.join(meta, "prompt")
        fd = os.open(copy_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "wb") as handle:
            handle.write(prompt.data)
        root = empty or worktree
        if empty and os.listdir(empty):
            raise CodexRunError("the empty working folder is not empty; nothing was run")
        argv = build_argv(codex, cls, root, result)
        env = child_env(home, codex, node, caller_env, meta)
        code, timed_out = run_codex(argv, env, root, copy_path, meta, args.timeout)
        seconds = time.monotonic() - started
        filtered = tier_filtered(os.path.join(meta, "stderr"), os.path.join(meta, "events"), result)
        if filtered:
            final = EXIT_FILTERED
        elif timed_out:
            final = EXIT_TIMEOUT
        elif code != 0:
            final = EXIT_CODEX_FAILED
        else:
            final = EXIT_OK
        if empty and os.listdir(empty):
            output.write(sys.stderr, "safo-codex-run: warning: the empty working folder was written to during the run")
        row = ledger_row(cls, prompt, final, None if timed_out else code, seconds, now)
        try:
            append_row(ledger, row)
        except OSError:
            output.write(sys.stderr, "safo-codex-run: warning: the ledger row could not be written")
        if filtered:
            tier = f"--cyber-access-program {spec.tier}, model {spec.model}" if spec.tier else "no cyber tier flag"
            output.write(
                sys.stderr, f"TIER FILTERED: a cybersecurity-risk filter cut off the {cls} run. Tier set: {tier}."
            )
            output.write(
                sys.stderr,
                "Fix the tier (security work must use the security class) and rerun. Do not reword the prompt and do "
                "not use another model: only the owner decides that.",
            )
        elif timed_out:
            output.write(sys.stderr, f"safo-codex-run: timed out after {args.timeout} s; the process group was killed")
        output.write(
            sys.stdout,
            f"safo-codex-run: class={cls} exit={final} seconds={seconds:.0f} out={result} lines={_lines(result)}",
        )
        return final
    finally:
        os.close(ledger)
        for folder in (meta, empty):
            if folder:
                shutil.rmtree(folder, ignore_errors=True)


def main(argv: Sequence[str] | None = None, env: Mapping[str, str] | None = None, home: str | None = None) -> int:
    words = sys.argv[1:] if argv is None else list(argv)
    try:
        args = parse(words)
        return execute(args, os.environ if env is None else env, home or account_home())
    except CodexRunError as err:
        output.write(sys.stderr, f"safo-codex-run: {err}")
        return err.exit_code
    except SystemExit as err:  # --help
        return int(err.code) if isinstance(err.code, int) else EXIT_OK


def run() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    run()
