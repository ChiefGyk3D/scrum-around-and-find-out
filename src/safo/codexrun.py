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
3. Finds codex (and node) ONLY through the private config `~/.config/safo/codex-run.json`, a JSON object with the key
   "codex" (an absolute, normalized path) and optionally "node"; the caller's PATH is never searched, and an unset
   or unusable config is exit 2 naming the expected key. The binary, its real path and EVERY folder above both must be
   owned by this user or root and not writable by group or other (a sticky folder such as /tmp passes when root or
   we own it). The config file itself must be ours and not group or world writable.
   Git runs (worktree checks) with the global and system config and attributes switched off, `core.hooksPath` at
   /dev/null, `core.fsmonitor` off, `protocol.allow` never (a default; the repository's own `protocol.*` keys are refused) and no optional locks. The worktree's `.git` file must name
   a `<main>/.git/worktrees/<name>` folder outside the worktree, below the home, ours, that names the worktree back.
   A repository whose own config sets a filter, textconv, include, alias, URL rewrite or similar program key is
   refused. Then it starts codex by an absolute path, no shell, with an allow-list environment (a fixed PATH plus the
   directories of codex and node, HOME from the account database, CODEX_HOME, locale, a private TMPDIR; no `GH_*`,
   no tokens, no `*_API_KEY`, no secret-manager variables), `--ignore-user-config` and `--ignore-rules` (so
   `config.toml` cannot
   add a tool server or change the sandbox), `--ephemeral`, stdin from the prompt copy, its own process group, and a
   hard timeout (default 1800 s, at most 3600 s). On a timeout the whole process group is killed (exit 124).
4. Looks for the cybersecurity-risk cutoff: a NONZERO codex exit AND the phrase "flagged for possible cybersecurity
   risk" in codex's error stream or in a structured `error` / `turn.failed` event of the JSONL stream (both files
   scanned whole). The final message is model text and is never read, so a prompt cannot fake a cutoff. If found:
   exit 40, say which tier was set, and tell the lead to fix the tier. It never rewords the prompt, never retries,
   never falls back to another model (the Daybreak fallback is not active; only the owner decides one).
5. Writes a `started` row to `~/.local/state/safo/codex-runs.jsonl` BEFORE codex starts (no row, no run), then a
   `finished` row with the same `run` id: ts, class, model, sandbox, tier, confined, exit, codex_exit, seconds,
   prompt_bytes, prompt_sha256. Never the prompt, never the output text. If the closing row cannot be written the exit
   is 50, never 0.
6. Prints one summary line on standard output with the result path (the final message, under
   `~/.local/state/safo/codex-runs/`, mode 0600).

Exit codes: 0 done; 2 refused or could not start (nothing ran); 30 codex failed (its own code is in the ledger);
40 tier filtered; 50 ran but the closing ledger row failed; 124 timed out.

Read confinement (security and copy classes). Codex's `read-only` sandbox restricts WRITES, not reads (its docs list
`read-only`, `workspace-write`, `danger-full-access` and permission profiles `[permissions.<name>]`; they document no
readable-roots key; read 2026-11-24, profile details unverified). So an empty working folder is a starting point, not
a fence. These two classes therefore run inside bubblewrap (`bwrap`, configured path, default /usr/bin/bwrap): a fresh
mount namespace with NO account home, no ~/.ssh, no ~/.config; every namespace but the network unshared; the child
dies with the wrapper. If bwrap cannot make the namespace the run is refused (exit 2): no confinement, no run. What a
prompt CAN still read in there: /usr and a few /etc network files (read only); the codex and node binary files (not
their folders: a codex that needs a package folder, such as a node script, needs it named in `ro_paths`) and the
config's `ro_paths` (read only); no exposed path may be or contain the account home (exit 2); the config's
`rw_paths`; the whole codex home, auth.json included (it is mounted read-write because codex must authenticate and
keep state); the empty folder, the private run folder and the result file. It can reach the network (codex needs its
service), so anything in that list can leave. Residual risks:
the codex home's auth token is exposed to the prompt; the prompt text itself and `ro_paths` are the owner's choice;
bwrap needs unprivileged user namespaces; and codex's own sandbox nested inside this one was NOT run or verified.
Setting `"confinement": "none"` in the config turns this off (a warning on every run, `confined: false` in the
ledger); it exists for hosts without namespaces and for the unit tests. The `implementer` and `review` classes need
the worktree and git and are NOT read-confined: they can read what the account can.

What it does NOT do (and the Daybreak review should weigh): a same-user process can still race the worktree between
the checks and the run (the prompt is copied; the worktree and its git directory are re-checked by device and inode
just before the start, which narrows the window and does not close it); the sandbox network switch for `implementer`
is the `sandbox_workspace_write.network_access` setting, and is only as strong as codex's own sandbox. CODEX_HOME is
never inherited: it is the config's "codex_home" (default ~/.codex), a real private folder of ours. It does not edit
any guard or settings file; the permission rule that lets the lead run it without a prompt is phase 3, by the owner.
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
MAX_EVENT_LINE = 4 * 1024 * 1024  # longest event line read whole; a longer one is read in pieces and not parsed
FILTER_PHRASE = "flagged for possible cybersecurity risk"
FILTER_EVENT_TYPES = ("error", "turn.failed")
DEFAULT_BWRAP = "/usr/bin/bwrap"
EXIT_UNRECORDED = 50  # codex ran but the closing ledger row could not be written

STATE_PARTS = (".local", "state", "safo")
LEDGER_NAME = "codex-runs.jsonl"
RESULTS_NAME = "codex-runs"
SCRATCH_NAME = "codex-run-scratch"
DENY_LIST = (".config", "safo", "codex-deny.txt")
CONFIG_FILE = (".config", "safo", "codex-run.json")


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
        if st.st_nlink != 1:
            # a hard link is a second name of an inode that may live outside the allowed folders; realpath cannot tell
            raise CodexRunError("the prompt file has more than one hard link; nothing was run")
        try:
            opened = os.readlink(f"/proc/self/fd/{fd}")  # where the descriptor we hold really is, not the path given
        except OSError:
            raise CodexRunError("the prompt file's location cannot be verified; nothing was run") from None
        if not allowed_prompt_folder(os.path.realpath(opened), home):
            raise CodexRunError("the opened prompt file is outside the allowed folders; nothing was run")
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
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }


# Options on every git call: repository-controlled settings that start programs are overridden on the command line
# (which beats the repository's own config), and the repository is never locked or written to.
GIT_HARDENING = (
    "--no-optional-locks",
    "-c",
    f"core.hooksPath={os.devnull}",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "protocol.allow=never",
    "-c",
    f"core.attributesFile={os.devnull}",
    "-c",
    "submodule.recurse=false",
)
# Keys of the repository's own config that can start a program or redirect git in ways the options above do not cover
# (a content filter named by an attributes file, a textconv, an include of another file, a URL rewrite, an alias).
DANGEROUS_CONFIG_PREFIXES = ("filter.", "include.", "includeif.", "alias.", "url.", "credential.", "protocol.")
DANGEROUS_CONFIG_SUFFIXES = (".textconv", ".clean", ".smudge", ".process", ".command", ".external")
DANGEROUS_CONFIG_KEYS = ("core.sshcommand", "core.pager", "core.editor", "core.askpass", "core.gitproxy")


def _git(git: str, home: str, root: str, *args: str, errors: str = "replace") -> str:
    try:
        done = subprocess.run(  # noqa: S603 - absolute git, fixed argv, no shell, stdin closed, bounded time
            [git, *GIT_HARDENING, "-C", root, *args],
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
    return done.stdout.decode("utf-8", errors)


def _read_small(path: str, limit: int = 4096) -> str:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return ""
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return ""
        with os.fdopen(os.dup(fd), "rb") as handle:
            return handle.read(limit).decode("utf-8", "replace")
    finally:
        os.close(fd)


def check_gitfile(marker: str, worktree: str, home: str) -> str:
    """The worktree's `.git` file must name a git directory `<main>/.git/worktrees/<name>` that lies OUTSIDE the
    worktree, below the account home, owned by us, and that names this worktree back. A gitfile aimed anywhere else
    (inside the worktree, at another repository, at a folder someone else controls) is refused before git runs."""
    text = _read_small(marker).strip()
    if not text.startswith("gitdir:") or "\n" in text:
        raise CodexRunError("the worktree's .git file does not name a git directory; nothing was run")
    target = text[len("gitdir:") :].strip()
    gitdir = os.path.realpath(target if os.path.isabs(target) else os.path.join(worktree, target))
    parent = os.path.dirname(gitdir)
    shape = os.path.basename(parent) == "worktrees" and os.path.basename(os.path.dirname(parent)) == ".git"
    st = os.stat(gitdir) if os.path.isdir(gitdir) else None
    if (
        not shape
        or st is None
        or _under(gitdir, worktree)
        or not _under(gitdir, os.path.realpath(home))
        or st.st_uid != os.geteuid()
        or st.st_mode & 0o022
    ):
        raise CodexRunError(
            "the worktree's .git file does not point into a main repository's .git/worktrees folder that we own "
            "outside the worktree; nothing was run"
        )
    _trusted_chain(gitdir, "git directory")  # every parent up to the root: ours or root's, not group/other writable
    _trusted_chain(os.path.dirname(os.path.dirname(parent)), "main repository")
    back = _read_small(os.path.join(gitdir, "gitdir")).strip()
    if not back or os.path.realpath(back) != os.path.join(worktree, ".git"):
        raise CodexRunError("the git directory does not name this worktree back; nothing was run")
    return gitdir


def worktree_identity(worktree: str, home: str) -> tuple[tuple[int, int], ...]:
    """(device, inode) of the worktree, its `.git` file and its git directory, to compare just before codex starts."""
    gitdir = check_gitfile(os.path.join(worktree, ".git"), worktree, home)
    try:
        stats = (os.lstat(worktree), os.lstat(os.path.join(worktree, ".git")), os.lstat(gitdir))
        return tuple((s.st_dev, s.st_ino) for s in stats)
    except OSError:
        raise CodexRunError("the worktree changed while it was being checked; nothing was run") from None


MAX_SUBMODULE_DEPTH = 4


def _check_config_keys(git: str, home: str, folder: str) -> None:
    listing = _git(git, home, folder, "config", "--list", "-z")
    for entry in listing.split("\0"):
        key = entry.split("\n", 1)[0].lower()
        if (
            key.startswith(DANGEROUS_CONFIG_PREFIXES)
            or key.endswith(DANGEROUS_CONFIG_SUFFIXES)
            or key in DANGEROUS_CONFIG_KEYS
        ):
            raise CodexRunError(
                f"the repository config sets {output.line(key[:60])}, which can start a program; nothing was run"
            )


def _submodule_folders(git: str, home: str, folder: str) -> list[str]:
    """The folders of the gitlinks (mode 160000) in the index of `folder`. Listing the index runs nothing."""
    raw = _git(git, home, folder, "ls-files", "--stage", "-z", errors="surrogateescape")
    found: list[str] = []
    for entry in raw.split("\0"):
        meta, _, name = entry.partition("\t")
        if meta.startswith("160000 ") and name:
            found.append(os.path.join(folder, name))
    return found


def check_repo_config(git: str, home: str, root: str, depth: int = 0) -> None:
    """Refuse a repository whose own config can start a program through a setting the command-line options do not
    override (a content filter, a textconv, an include, an alias). The same check runs on every submodule, nested ones
    too, because a submodule keeps its own config. Listing config runs nothing."""
    _check_config_keys(git, home, root)
    if depth >= MAX_SUBMODULE_DEPTH:
        if _submodule_folders(git, home, root):
            raise CodexRunError("the repository nests submodules too deeply to check; nothing was run")
        return
    for folder in _submodule_folders(git, home, root):
        if os.path.islink(folder):
            raise CodexRunError("a submodule path is a symbolic link; nothing was run")
        if not os.path.lexists(folder):
            continue  # not checked out: git has no repository of its own there
        if not os.path.isdir(folder):
            raise CodexRunError("a submodule path is not a folder; nothing was run")
        if os.path.realpath(folder) != os.path.join(os.path.realpath(root), os.path.relpath(folder, root)):
            raise CodexRunError("a submodule folder resolves outside its place in the worktree; nothing was run")
        check_repo_config(git, home, folder, depth + 1)


def _sealed_status(git: str, home: str, root: str, gitdir: str) -> str:
    """`git status` against a private git directory that holds only what we wrote: HEAD as a bare id, a copy of the
    index, the real object store through `alternates`, and a fixed config. Nothing the repository can change after the
    config check (its config, its info/attributes, a submodule's config) is read by this call, so no content filter,
    textconv or other program it names can run; a later edit of those files has nothing to act on. The working tree's
    own .gitattributes can still name a filter, but with no `filter.*` setting in the config git has no program to
    start."""
    head = _git(git, home, root, "rev-parse", "--verify", "HEAD").strip()
    common = _git(git, home, root, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    scratch = tempfile.mkdtemp(prefix="safo-status-")
    try:
        for name in ("objects/info", "refs"):
            os.makedirs(os.path.join(scratch, name))
        with open(os.path.join(scratch, "objects", "info", "alternates"), "w", encoding="utf-8") as handle:
            handle.write(os.path.join(common, "objects") + "\n")
        with open(os.path.join(scratch, "HEAD"), "w", encoding="utf-8") as handle:
            handle.write(head + "\n")
        with open(os.path.join(scratch, "config"), "w", encoding="utf-8") as handle:
            handle.write("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n")
        try:
            shutil.copyfile(os.path.join(gitdir, "index"), os.path.join(scratch, "index"))
        except OSError:
            raise CodexRunError("the worktree's index could not be read; nothing was run") from None
        sealed = (f"--git-dir={scratch}", f"--work-tree={root}")
        # assume-unchanged ("h", any lower-case tag) and skip-worktree ("S") entries are never compared with the
        # files, so a modified file behind one of them would read as clean: refuse such an index.
        for entry in _git(git, home, root, *sealed, "ls-files", "-v", "-z", errors="surrogateescape").split("\0"):
            if entry and (entry[0].islower() or entry[0] == "S"):
                raise CodexRunError(
                    "the index marks a file assume-unchanged or skip-worktree, so the tree cannot be checked; "
                    "nothing was run"
                )
        return _git(
            git,
            home,
            root,
            *sealed,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=all",
        )
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


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
    _trusted_chain(real, "worktree")  # every folder from the root down: ours or root's, not group/other writable
    marker = os.path.join(real, ".git")
    if os.path.islink(marker) or not os.path.isfile(marker):
        raise CodexRunError("the folder is not a linked git worktree (its .git is not a plain file); nothing was run")
    gitdir = check_gitfile(marker, real, home)
    git = shutil.which("git", path=SAFE_PATH)
    if not git:
        raise CodexRunError("git was not found; nothing was run")
    top = os.path.realpath(_git(git, home, real, "rev-parse", "--show-toplevel").strip())
    if top != real:
        raise CodexRunError("the folder named is not the top of its git worktree; nothing was run")
    check_repo_config(git, home, real)
    if cls == "implementer":
        raw = _sealed_status(git, home, real, gitdir)
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


def _trusted_chain(path: str, what: str) -> None:
    """Every component of `path`, from the root down, is owned by this user or root and is not writable by group or
    other. A sticky folder (such as /tmp) passes when root or we own it: others cannot replace entries in it. A symlink
    is judged by its owner, its target by the walk over the real path."""
    parts = [p for p in path.split("/") if p]
    current = "/"
    for part in ["", *parts]:
        current = os.path.join(current, part) if part else "/"
        try:
            st = os.lstat(current)
        except OSError:
            raise CodexRunError(f"the {what} path cannot be examined; nothing was run") from None
        if st.st_uid not in (0, os.geteuid()):
            raise CodexRunError(f"the {what} path has a component owned by someone else; nothing was run")
        if stat.S_ISLNK(st.st_mode):
            continue
        sticky_ok = stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX
        if st.st_mode & 0o022 and not sticky_ok:
            raise CodexRunError(f"the {what} path has a component that group or others can write; nothing was run")


def trusted_binary(path: str, what: str) -> str:
    """The absolute path, after checking the file, its real path and every folder above both."""
    if not path or "\0" in path or not os.path.isabs(path) or os.path.normpath(path) != path:
        raise CodexRunError(f"the {what} path in the config is not a normalized absolute path; nothing was run")
    real = os.path.realpath(path)
    for item in dict.fromkeys((path, real)):
        _trusted_chain(item, what)
    st = os.stat(real)
    if not stat.S_ISREG(st.st_mode) or not os.access(real, os.X_OK):
        raise CodexRunError(f"the {what} binary is not a plain executable file; nothing was run")
    return path


@dataclass(frozen=True)
class RunConfig:
    codex: str
    node: str | None
    codex_home: str
    bwrap: str
    confine: bool
    ro_paths: tuple[str, ...]
    rw_paths: tuple[str, ...]


def _path_list(config: Mapping[str, object], key: str, home: str) -> tuple[str, ...]:
    raw = config.get(key, [])
    if not isinstance(raw, list) or len(raw) > 32:
        raise CodexRunError(f'the codex-run config key "{key}" must be a list of at most 32 paths; nothing was run')
    out: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not os.path.isabs(item) or os.path.normpath(item) != item or "\0" in item:
            raise CodexRunError(f'the codex-run config key "{key}" holds a path that is not normalized absolute')
        if item == "/" or _under(os.path.realpath(home), os.path.realpath(item)):
            raise CodexRunError(f'the codex-run config key "{key}" would expose the account home; nothing was run')
        out.append(item)
    return tuple(out)


def _checked_codex_home(path: str) -> str:
    """CODEX_HOME is chosen here, from the owner's config, never taken from the caller's environment: an absolute,
    normalized real folder (no link anywhere in it), ours, private, every parent trusted."""
    if not path or "\0" in path or not os.path.isabs(path) or os.path.normpath(path) != path:
        raise CodexRunError("the codex home is not a normalized absolute path; nothing was run")
    try:
        st = os.lstat(path)
    except OSError:
        raise CodexRunError("the codex home folder does not exist; nothing was run") from None
    if (
        not stat.S_ISDIR(st.st_mode)
        or os.path.realpath(path) != path
        or st.st_uid != os.geteuid()
        or st.st_mode & 0o022
    ):
        raise CodexRunError("the codex home is not a real private folder of ours; nothing was run")
    _trusted_chain(path, "codex home")
    return path


def configured_binaries(home: str, *, need_confinement: bool = False) -> RunConfig:
    """The owner's `~/.config/safo/codex-run.json`: codex and node (never looked up on the caller's PATH), the
    codex home, and the confinement settings."""
    path = os.path.join(home, *CONFIG_FILE)
    expected = f'expected {path} holding a JSON object with the key "codex" (an absolute path) and optionally "node"'
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise CodexRunError(f"codex is not configured: {expected}; nothing was run") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o022 or st.st_size > 4096:
            raise CodexRunError("the codex-run config is not a plain private file; nothing was run")
        with os.fdopen(os.dup(fd), "rb") as handle:
            raw = handle.read(4097)
    finally:
        os.close(fd)
    try:
        config = loads(raw)
    except ValueError:
        raise CodexRunError(f"the codex-run config is not valid JSON: {expected}; nothing was run") from None
    codex = config.get("codex") if isinstance(config, dict) else None
    node = config.get("node") if isinstance(config, dict) else None
    if not isinstance(codex, str) or not (node is None or isinstance(node, str)):
        raise CodexRunError(f"the codex-run config lacks a usable key: {expected}; nothing was run")
    mode = config.get("confinement", "bwrap") if isinstance(config, dict) else "bwrap"
    if mode not in ("bwrap", "none"):
        raise CodexRunError('the codex-run config key "confinement" must be "bwrap" or "none"; nothing was run')
    bwrap_path = config.get("bwrap", DEFAULT_BWRAP) if isinstance(config, dict) else DEFAULT_BWRAP
    if not isinstance(bwrap_path, str):
        raise CodexRunError('the codex-run config key "bwrap" must be a path; nothing was run')
    confine = mode == "bwrap"
    assert isinstance(config, dict)  # noqa: S101 - narrowed above; a non-dict config has no usable "codex"
    codex_home = config.get("codex_home", os.path.join(home, ".codex"))
    if not isinstance(codex_home, str):
        raise CodexRunError('the codex-run config key "codex_home" must be a path; nothing was run')
    _refuse_home_exposure([codex_home], home)
    return RunConfig(
        codex=trusted_binary(codex, "codex"),
        node=trusted_binary(node, "node") if node else None,
        codex_home=_checked_codex_home(codex_home),
        bwrap=trusted_binary(bwrap_path, "bwrap") if confine and need_confinement else bwrap_path,
        confine=confine,
        ro_paths=_path_list(config, "ro_paths", home),
        rw_paths=_path_list(config, "rw_paths", home),
    )


def child_path(codex: str, node: str | None) -> str:
    dirs: list[str] = []
    for item in (codex, os.path.realpath(codex), node):
        if item:
            folder = os.path.dirname(item)
            if folder not in dirs and folder not in SAFE_PATH.split(":"):
                dirs.append(folder)
    return ":".join([*dirs, SAFE_PATH])


def child_env(home: str, codex: str, node: str | None, codex_home: str, scratch: str) -> dict[str, str]:
    """The whole environment of codex: this allow-list, built here, never a copy of the caller's. `codex_home` is
    read from the owner's config (checked), never from the caller's CODEX_HOME.

    The git settings here close what the wrapper can close for the git that codex starts itself: no system or global
    config, and command-scope settings (they beat the repository's config) that turn off fsmonitor and hooks and forbid
    network and `ext::` transports. A per-transport `protocol.<name>.allow` key in the repository config would beat
    the general `protocol.allow` setting, so the pre-run check refuses every repository `protocol.*` key; this is not
    absolute for a config written after that check. RESIDUAL, not closed: the repository config is read by that git at run time, and a
    `filter.*` / `diff.*.textconv` program cannot be forbidden by name in advance. A process that can write the
    repository config WHILE codex runs can therefore still get a program started. The checks before the run cover the
    config as it was then (see docs/codex-run.md)."""
    env = {
        "PATH": child_path(codex, node),
        "HOME": home,
        "CODEX_HOME": codex_home,
        "LANG": LOCALE,
        "LC_ALL": LOCALE,
        "TMPDIR": scratch,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    forced = (
        ("core.fsmonitor", "false"),
        ("core.hooksPath", os.devnull),
        ("protocol.allow", "never"),
        ("protocol.ext.allow", "never"),
        ("core.attributesFile", os.devnull),
    )
    env["GIT_CONFIG_COUNT"] = str(len(forced))
    for number, (key, value) in enumerate(forced):
        env[f"GIT_CONFIG_KEY_{number}"] = key
        env[f"GIT_CONFIG_VALUE_{number}"] = value
    return env


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


# -- read confinement (the empty-folder classes) -------------------------------------------------------------------
# Codex's own read-only sandbox does not restrict READS: a prompt can make it read any file the account can. So the
# security and copy classes run inside a bubblewrap mount namespace in which the account home does not exist at all.

ETC_FILES = (
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/ssl",
    "/etc/ca-certificates",
    "/etc/localtime",
)


def _exposed_binary_files(cfg: RunConfig) -> list[str]:
    """The binaries THEMSELVES (and their link targets), never the folders they sit in: a binary under the home must
    not expose its siblings. Runtime files a binary needs beyond itself are named in the config's `ro_paths`."""
    files: list[str] = []
    for item in (cfg.codex, os.path.realpath(cfg.codex), cfg.node, os.path.realpath(cfg.node) if cfg.node else None):
        if item and item not in files:
            files.append(item)
    return files


def _refuse_home_exposure(paths: Sequence[str], home: str) -> None:
    real_home = os.path.realpath(home)
    for item in paths:
        real = os.path.realpath(item)
        if real == "/" or _under(real_home, real):
            raise CodexRunError(
                "a path to be exposed in the namespace is or contains the account home; nothing was run"
            )


def confine_argv(cfg: RunConfig, argv: Sequence[str], root: str, meta: str, result: str, home: str) -> list[str]:
    """`argv` wrapped in bwrap. Visible inside: /usr (read only, with the /lib /bin links), a few /etc network files,
    a fresh /proc /dev /tmp, the codex and node binary FILES (read only; not their folders), the config's
    `ro_paths` (read only) and
    `rw_paths`, the codex home (read-write: auth and state), the empty working folder, the private run folder and the
    result file. Nothing else: not the home, not ~/.ssh, not ~/.config. The network stays shared (codex must reach
    its service); every other namespace is unshared and the child dies with this process."""
    out = [
        cfg.bwrap, "--unshare-all", "--share-net", "--die-with-parent", "--new-session",
        "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
        "--symlink", "usr/bin", "/bin", "--symlink", "usr/sbin", "/sbin",
        "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",  # noqa: S108 - a fresh empty /tmp inside the namespace
    ]  # fmt: skip
    for etc in ETC_FILES:
        out += ["--ro-bind-try", etc, etc]
    read_only = (*_exposed_binary_files(cfg), *cfg.ro_paths)
    writable = (*cfg.rw_paths, cfg.codex_home, root, meta, result)
    _refuse_home_exposure([*read_only, *writable], home)  # every exposed path, whatever put it on the list
    for item in read_only:
        out += ["--ro-bind-try", item, item]
    for item in writable:
        out += ["--bind", item, item]
    return [*out, "--chdir", root, "--", *argv]


def confinement_works(cfg: RunConfig) -> bool:
    """A real, trivial bwrap run with the same namespace options: when this machine cannot make the namespace, the
    confined classes refuse instead of running unconfined."""
    probe = [
        cfg.bwrap, "--unshare-all", "--share-net", "--die-with-parent", "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
        "--", "/usr/bin/true",
    ]  # fmt: skip
    try:
        done = subprocess.run(  # noqa: S603 - the trusted bwrap, fixed argv, no shell, stdin closed, bounded time
            probe, env={"PATH": SAFE_PATH}, capture_output=True, stdin=subprocess.DEVNULL, timeout=20, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return done.returncode == 0


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
    cls: str,
    prompt: Prompt,
    exit_code: int | None,
    codex_exit: int | None,
    seconds: float,
    now: dt.datetime,
    *,
    run: str,
    status: str,
    confined: bool,
) -> dict[str, object]:
    """Counts, names and a hash. Never the prompt, never the output. Two rows per run share `run`: `started` (written
    before codex starts; no row, no run) and `finished`. A `started` row with no `finished` row is a run that did not
    end cleanly or could not be recorded."""
    spec = SPECS[cls]
    return {
        "run": run,
        "status": status,
        "confined": confined,
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


def _squash(text: str) -> str:
    return " ".join(text.lower().split())


def _stream_has_phrase(path: str) -> bool:
    """The phrase anywhere in the whole file, read in chunks (a carry joins the chunk edges): padding after a real
    notice cannot push it out of view."""
    carry = ""
    try:
        with open(path, "rb") as handle:
            while chunk := handle.read(65536):
                text = _squash(carry + chunk.decode("utf-8", "replace"))
                if FILTER_PHRASE in text:
                    return True
                carry = text[-(len(FILTER_PHRASE) + 8) :]
    except OSError:
        return False
    return False


def _strings(value: object, depth: int = 0) -> list[str]:
    if isinstance(value, str):
        return [value]
    if depth > 6:
        return []
    if isinstance(value, dict):
        return [s for item in value.values() for s in _strings(item, depth + 1)]
    if isinstance(value, list):
        return [s for item in value for s in _strings(item, depth + 1)]
    return []


def _events_have_phrase(path: str) -> bool:
    """A structured error event (`type` is one of FILTER_EVENT_TYPES) whose text holds the phrase. Model output arrives
    in other event types (messages, items), so it cannot make one of these."""
    try:
        with open(path, "rb") as handle:
            for raw in iter(lambda: handle.readline(MAX_EVENT_LINE), b""):
                if FILTER_PHRASE not in _squash(raw.decode("utf-8", "replace")):
                    continue
                try:
                    event = loads(raw)
                except ValueError:
                    continue
                is_error = isinstance(event, dict) and event.get("type") in FILTER_EVENT_TYPES
                if is_error and any(FILTER_PHRASE in _squash(text) for text in _strings(event)):
                    return True
    except OSError:
        return False
    return False


def tier_filtered(code: int, timed_out: bool, stderr_path: str, events_path: str) -> bool:
    """True when codex was cut off by the cybersecurity-risk filter. Needs BOTH a failed codex exit (a run that exits
    0 was not cut off, whatever its final message says) AND the phrase in codex's own error stream or in a structured
    error event of the JSONL stream. The final message is never read: it is model text. The files are scanned whole.
    The event type names in FILTER_EVENT_TYPES and the stderr wording are ASSUMED from codex's `--json` mode, not
    verified against a live cutoff (no real codex run was made); if a real cutoff takes another shape the run is
    reported as exit 30 (codex failed), never as success."""
    if timed_out or code == 0:
        return False
    return _stream_has_phrase(stderr_path) or _events_have_phrase(events_path)


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
    del caller_env  # nothing is inherited from the caller: not PATH, not CODEX_HOME
    worktree = check_worktree(args.worktree, home, cls, args.allow_dirty) if cls in NEEDS_WORKTREE else ""
    identity = worktree_identity(worktree, home) if worktree else ()
    confined_class = spec.root == "empty"
    cfg = configured_binaries(home, need_confinement=confined_class)
    confined = confined_class and cfg.confine
    if confined and not confinement_works(cfg):
        raise CodexRunError(
            f"the {cls} class must run in a read-confined namespace and bubblewrap cannot make one here; "
            "no confinement, no run; nothing was run"
        )
    if confined_class and not confined:
        output.write(
            sys.stderr, "safo-codex-run: warning: confinement is switched off in the config; codex can read the account"
        )
    ledger = open_ledger(home)
    meta = empty = ""
    now = dt.datetime.now(dt.UTC)
    run_id = secrets.token_hex(8)
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
        argv = build_argv(cfg.codex, cls, root, result)
        if confined:
            argv = confine_argv(cfg, argv, root, meta, result, home)
        env = child_env(home, cfg.codex, cfg.node, cfg.codex_home, meta)
        if worktree and worktree_identity(worktree, home) != identity:
            raise CodexRunError("the worktree was replaced after it was checked; nothing was run")
        try:  # no row, no run: the audit trail is written BEFORE codex starts
            append_row(
                ledger, ledger_row(cls, prompt, None, None, 0.0, now, run=run_id, status="started", confined=confined)
            )
        except OSError:
            raise CodexRunError("the ledger row could not be written; nothing was run") from None
        code, timed_out = run_codex(argv, env, root, copy_path, meta, args.timeout)
        seconds = time.monotonic() - started
        filtered = tier_filtered(code, timed_out, os.path.join(meta, "stderr"), os.path.join(meta, "events"))
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
        row = ledger_row(
            cls,
            prompt,
            final,
            None if timed_out else code,
            seconds,
            now,
            run=run_id,
            status="finished",
            confined=confined,
        )
        try:
            append_row(ledger, row)
        except OSError:
            final = EXIT_UNRECORDED
            output.write(
                sys.stderr,
                f"safo-codex-run: codex ran (run {run_id}) but the closing ledger row could not be written; "
                "the started row is the only record",
            )
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
