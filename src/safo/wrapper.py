# SPDX-License-Identifier: Apache-2.0
"""The research wrapper's own process: an isolated interpreter, a sanitized environment, a confined directory (#221).

`safo gemini ...` is where the gates are (docs/gemini.md), and it holds the key for one call. The installed `safo`
script starts a plain interpreter, so a caller's environment has already acted by the time any of this code runs. So the
wrapper does two things at the entry, before it reads a config, a prompt or a key:

* REFUSES to run when an interpreter startup variable (any `PYTHON*`) or a shell startup variable (`BASH_ENV`, `ENV`) is
  set. It names the variables, never their values, and runs nothing.
* RE-STARTS itself as `<absolute interpreter> -I -c <boot> ...`: no user site, no `PYTHON*` variables, no current
  directory on the import path. The child gets an argument vector of fixed words (no shell), only the variables on an
  allow-list (a fixed PATH, locale and temporary directory, the account's home from the account database, and per
  action the few variables that action needs), a fresh private directory as its working directory, and no inherited
  descriptor.

This is not a sandbox: the child runs as the same user. It closes the ways an environment, a working directory or a
descriptor handed down by the caller could change what the wrapper imports, executes or reads.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence

from safo import output
from safo.errors import EXIT_UNKNOWN, SafoError

SAFE_PATH = "/usr/local/bin:/usr/bin:/bin"
LOCALE = "C.UTF-8"
SCRATCH_PARENT = (".local", "state", "safo", "wrapper")  # under the account home; no $TMPDIR is consulted
# The child imports THIS installation: the folder holding the `safo` package goes first on the import path, so no other
# `safo` on a path wins. `-I` has already removed the current directory, the user site and every PYTHON* variable.
BOOT = "import sys; sys.path.insert(0, sys.argv.pop(1)); from safo.cli import run; run()"

# Variables that act on an interpreter or a shell before any code of ours runs. A prefix for the interpreter's, since
# the list grows (PYTHONPATH, PYTHONSTARTUP, PYTHONHOME, PYTHONUSERBASE, PYTHONINSPECT, ...).
STARTUP_PREFIX = "PYTHON"
STARTUP_NAMES = frozenset({"BASH_ENV", "ENV"})

# What each action may receive beyond the fixed variables. `ask` reads the key through the secret tool, which takes
# its own token from here; `approve` runs ssh-keygen to sign with the security key. Nothing else carries over.
_SIGNING = ("SSH_AUTH_SOCK", "DISPLAY", "WAYLAND_DISPLAY", "TERM")
EXTRA_NAMES: Mapping[str, tuple[str, ...]] = {"ask": ("DOPPLER_TOKEN",), "approve": _SIGNING}


class WrapperError(SafoError):
    """The wrapper could not start its isolated child; nothing was run."""

    exit_code = EXIT_UNKNOWN


def isolated() -> bool:
    return bool(sys.flags.isolated)


def startup_variables(env: Mapping[str, str]) -> list[str]:
    """The names (sorted) of the startup variables set in this environment."""
    return sorted(k for k in env if k.startswith(STARTUP_PREFIX) or k in STARTUP_NAMES)


def default_entry() -> tuple[str, ...]:
    """The child's entry point: the code above, and the folder this running copy of the package was imported from."""
    package = os.path.dirname(os.path.abspath(__file__))
    return ("-c", BOOT, os.path.dirname(package))


def parsed(words: Sequence[str]) -> argparse.Namespace | None:
    """What the REAL top-level parser makes of the command line (abbreviations, `=` forms, a value that looks like a
    mode, all as argparse reads them), or None when it exits (an error, help, version): then no mode runs. There is
    no hand-written scanner to disagree with it."""
    from safo import cli  # lazily: cli imports this module

    parser, _ = cli.build_parser()
    sink = io.StringIO()
    try:
        with contextlib.redirect_stderr(sink), contextlib.redirect_stdout(sink):
            return parser.parse_args(list(words))
    except SystemExit:
        return None


def account_home() -> str:
    try:
        return pwd.getpwuid(os.geteuid()).pw_dir  # the account database: $HOME is the caller's to set
    except KeyError:
        raise WrapperError("this account has no home directory in the account database; nothing was run") from None


def scratch_root(home: str) -> str:
    """The private parent of the child's working directories. Each component below the home is made if missing, opened
    without following a symlink and checked (ours, not writable by others); the last one must be mode 0700."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for name in SCRATCH_PARENT:
                with contextlib.suppress(FileExistsError):
                    os.mkdir(name, 0o700, dir_fd=fd)
                nxt = os.open(name, flags, dir_fd=fd)
                os.close(fd)
                fd = nxt
                st = os.fstat(fd)
                if st.st_uid != os.geteuid() or st.st_mode & 0o022:
                    raise WrapperError("the wrapper's scratch folder is not private to this user; nothing was run")
            os.fchmod(fd, 0o700)
        finally:
            os.close(fd)
    except OSError as err:
        raise WrapperError(f"the wrapper's scratch folder cannot be used ({err.strerror}); nothing was run") from None
    return os.path.join(home, *SCRATCH_PARENT)


def child_env(action: str, env: Mapping[str, str], scratch: str) -> dict[str, str]:
    """The whole environment of the child: the allow-list, built here, never a copy of the caller's."""
    out = {"PATH": SAFE_PATH, "HOME": account_home(), "LANG": LOCALE, "LC_ALL": LOCALE, "TMPDIR": scratch}
    for name in EXTRA_NAMES.get(action, ()):
        if name in env:
            out[name] = env[name]
    return out


def is_the_child(action: str, env: Mapping[str, str]) -> bool:
    """True only when this process looks like what `launch` makes: exactly the allow-list for this action, and a
    working directory that is a fresh private folder of ours under the scratch root, named by TMPDIR. The interpreter
    flag alone proves nothing (anyone can run `python -I -m safo` in a dirty place)."""
    try:
        home = account_home()
        root = os.path.realpath(scratch_root(home))
        cwd = os.path.realpath(os.getcwd())
        st = os.stat(cwd)
    except (OSError, WrapperError):
        return False
    allowed = {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", *EXTRA_NAMES.get(action, ())}
    return (
        set(env) <= allowed
        and {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR"} <= set(env)
        and env["PATH"] == SAFE_PATH
        and env["HOME"] == home
        and env["LANG"] == LOCALE
        and env["LC_ALL"] == LOCALE
        and os.path.realpath(env["TMPDIR"]) == cwd
        and os.path.dirname(cwd) == root
        and os.path.basename(cwd).startswith("run-")
        and st.st_uid == os.geteuid()
        and not st.st_mode & 0o077
    )


def _inherit(fd: int) -> int | None:
    """None keeps the caller's descriptor; a descriptor that is closed here becomes /dev/null, so that nothing the
    child opens later can land on 0, 1 or 2."""
    try:
        os.fstat(fd)
    except OSError:
        return subprocess.DEVNULL
    return None


def launch(
    words: Sequence[str],
    env: Mapping[str, str],
    *,
    action: str,
    entry: Sequence[str] | None = None,
    python: str | None = None,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run the entry point in a child: `-I`, an allow-list environment, a fresh private working directory, no shell,
    no inherited descriptor above 2, and standard input only for `approve` (which asks the person a question).
    `entry` is a seam for a test's fake child."""
    exe = python or sys.executable
    if not exe or not os.path.isabs(exe) or not os.path.isfile(exe) or not os.access(exe, os.X_OK):
        raise WrapperError("the interpreter cannot be found by an absolute path; nothing was run")
    scratch = tempfile.mkdtemp(prefix="run-", dir=scratch_root(account_home()))  # mode 0700, owned by this user
    stdin = _inherit(0) if action == "approve" else subprocess.DEVNULL
    try:
        return subprocess.run(  # noqa: S603 - absolute interpreter, fixed words and the caller's own arguments, no shell
            [exe, "-I", *(default_entry() if entry is None else entry), *words],
            env=child_env(action, env, scratch),
            cwd=scratch,
            close_fds=True,
            shell=False,
            check=False,
            text=True,
            stdin=stdin,
            stdout=subprocess.PIPE if capture else _inherit(1),
            stderr=subprocess.PIPE if capture else _inherit(2),
        )
    except OSError as err:
        raise WrapperError(f"the isolated child could not start ({err.strerror}); nothing was run") from None
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _absolute(path: str) -> str:
    return path if not path or os.path.isabs(path) else os.path.join(os.getcwd(), path)


def absolutize(words: Sequence[str]) -> list[str]:
    """The same arguments with the two file paths made absolute, because the child starts in another directory."""
    out = list(words)
    ns = parsed(out)
    if ns is None or ns.mode != "gemini":
        return out  # the child reports a usage error itself
    after_propose = False
    i = 0
    while i < len(out):
        word = out[i]
        if word == "--prompt-file" and i + 1 < len(out):
            out[i + 1] = _absolute(out[i + 1])
            i += 2
            continue
        if word.startswith("--prompt-file="):
            out[i] = "--prompt-file=" + _absolute(word[len("--prompt-file=") :])
        elif after_propose and ns.keys_file and word == ns.keys_file:
            out[i] = _absolute(word)
            after_propose = False
        elif word == "propose" and ns.keys_action == "propose":
            after_propose = True
        i += 1
    return out


def _refuse(text: str) -> int:
    output.write(sys.stderr, f"error: refused: {text}")
    return EXIT_UNKNOWN


def enter(words: Sequence[str], env: Mapping[str, str]) -> int | None:
    """None when this process should carry on with the command itself (it is not the research wrapper, or it is the
    isolated child and looks like one). Otherwise the exit code: a refusal, or the isolated child's."""
    ns = parsed(words)
    if ns is None or ns.mode != "gemini":
        return None
    bad = startup_variables(env)
    if bad:
        return _refuse(f"startup variable(s) set: {', '.join(bad)}. Unset them and run again; nothing was run.")
    if isolated():
        if is_the_child(ns.action, env):
            return None
        return _refuse(
            "this is not the isolated child the wrapper starts (its environment or working directory differs). "
            "Run `safo gemini ...` instead; nothing was run."
        )
    try:
        done = launch(absolutize(words), env, action=ns.action)
    except WrapperError as err:
        return _refuse(f"{err}")
    code = done.returncode
    return 128 - code if code < 0 else code
