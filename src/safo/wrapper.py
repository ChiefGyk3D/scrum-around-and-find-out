# SPDX-License-Identifier: Apache-2.0
"""The research wrapper's own process: an isolated interpreter, a sanitized environment, a confined directory (#221).

`safo gemini ...` is where the gates are (docs/gemini.md), and it holds the key for one call. The installed `safo`
script starts a plain interpreter, so a caller's environment has already acted by the time any of this code runs. So the
wrapper does two things at the entry, before it reads a config, a prompt or a key:

* REFUSES to run when an interpreter startup variable (any `PYTHON*`) or a shell startup variable (`BASH_ENV`, `ENV`) is
  set. It names the variables, never their values, and runs nothing.
* RE-STARTS itself as `<absolute interpreter> -I -m safo ...`: no user site, no `PYTHON*` variables, no current
  directory on the import path. The child gets an argument vector of fixed words (no shell), only the variables on an
  allow-list (a fixed PATH, locale and temporary directory, the account's home from the account database, and per
  action the few variables that action needs), a fresh private directory as its working directory, and no inherited
  descriptor.

This is not a sandbox: the child runs as the same user. It closes the ways an environment, a working directory or a
descriptor handed down by the caller could change what the wrapper imports, executes or reads.
"""

from __future__ import annotations

import argparse
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
ENTRY = ("-m", "safo")

# Variables that act on an interpreter or a shell before any code of ours runs. A prefix for the interpreter's, since
# the list grows (PYTHONPATH, PYTHONSTARTUP, PYTHONHOME, PYTHONUSERBASE, PYTHONINSPECT, ...).
STARTUP_PREFIX = "PYTHON"
STARTUP_NAMES = frozenset({"BASH_ENV", "ENV"})

# What each action may receive beyond the fixed variables. `ask` reads the key through the secret tool, which takes
# its own token from here; `approve` runs ssh-keygen to sign with the security key. Nothing else carries over.
_SIGNING = (
    "SSH_AUTH_SOCK",
    "SSH_SK_PROVIDER",
    "SSH_ASKPASS",
    "SSH_ASKPASS_REQUIRE",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "TERM",
)
EXTRA_NAMES: Mapping[str, tuple[str, ...]] = {"ask": ("DOPPLER_TOKEN",), "approve": _SIGNING}

_VALUE_FLAGS = frozenset({"--board", "--gh-user"})  # the global options that take a value


class WrapperError(SafoError):
    """The wrapper could not start its isolated child; nothing was run."""

    exit_code = EXIT_UNKNOWN


def isolated() -> bool:
    return bool(sys.flags.isolated)


def startup_variables(env: Mapping[str, str]) -> list[str]:
    """The names (sorted) of the startup variables set in this environment."""
    return sorted(k for k in env if k.startswith(STARTUP_PREFIX) or k in STARTUP_NAMES)


def mode_index(words: Sequence[str]) -> int | None:
    """Where the mode word is: the first word that is not a global option or its value."""
    i = 0
    while i < len(words):
        word = words[i]
        if word in _VALUE_FLAGS:
            i += 2
        elif word.startswith("-"):
            i += 1
        else:
            return i
    return None


def account_home() -> str:
    try:
        return pwd.getpwuid(os.geteuid()).pw_dir  # the account database: $HOME is the caller's to set
    except KeyError:
        raise WrapperError("this account has no home directory in the account database; nothing was run") from None


def scratch_root(home: str) -> str:
    """The private parent of the child's working directories, made if it is missing."""
    root = os.path.join(home, *SCRATCH_PARENT)
    try:
        os.makedirs(root, mode=0o700, exist_ok=True)
        if os.stat(root).st_uid != os.geteuid() or os.stat(root).st_mode & 0o022:
            raise WrapperError("the wrapper's scratch folder is not private to this user; nothing was run")
    except OSError as err:
        raise WrapperError(f"the wrapper's scratch folder cannot be made ({err.strerror}); nothing was run") from None
    return root


def child_env(action: str, env: Mapping[str, str], scratch: str) -> dict[str, str]:
    """The whole environment of the child: the allow-list, built here, never a copy of the caller's."""
    home = account_home()
    out = {"PATH": SAFE_PATH, "HOME": home, "LANG": LOCALE, "LC_ALL": LOCALE, "TMPDIR": scratch}
    for name in EXTRA_NAMES.get(action, ()):
        if name in env:
            out[name] = env[name]
    return out


def launch(
    words: Sequence[str],
    env: Mapping[str, str],
    *,
    action: str,
    entry: Sequence[str] = ENTRY,
    python: str | None = None,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run the entry point in a child: `-I`, an allow-list environment, a fresh private working directory, no shell,
    no inherited descriptor. `entry` is a seam for a test's fake child."""
    exe = python or sys.executable
    if not exe or not os.path.isabs(exe) or not os.path.isfile(exe) or not os.access(exe, os.X_OK):
        raise WrapperError("the interpreter cannot be found by an absolute path; nothing was run")
    scratch = tempfile.mkdtemp(prefix="run-", dir=scratch_root(account_home()))  # mode 0700, owned by this user
    try:
        return subprocess.run(  # noqa: S603 - absolute interpreter, fixed words and the caller's own arguments, no shell
            [exe, "-I", *entry, *words],
            env=child_env(action, env, scratch),
            cwd=scratch,
            close_fds=True,
            shell=False,
            check=False,
            text=True,
            capture_output=capture,
        )
    except OSError as err:
        raise WrapperError(f"the isolated child could not start ({err.strerror}); nothing was run") from None
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _absolute(path: str) -> str:
    return path if not path or os.path.isabs(path) else os.path.join(os.getcwd(), path)


def _namespace(words: Sequence[str], index: int) -> argparse.Namespace | None:
    """What the real parser makes of the gemini arguments, or None for a command line it rejects."""
    from safo.modes.gemini import BriefParseError, brief_namespace  # lazily: the modes import this module's package

    try:
        return brief_namespace(list(words[index + 1 :]))
    except BriefParseError:
        return None


def absolutize(words: Sequence[str]) -> list[str]:
    """The same arguments with the two file paths made absolute, because the child starts in another directory."""
    out = list(words)
    index = mode_index(out)
    if index is None or out[index] != "gemini":
        return out
    ns = _namespace(out, index)
    if ns is None:
        return out  # the child reports the usage error itself
    i = index + 1
    after_propose = False
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


def enter(words: Sequence[str], env: Mapping[str, str]) -> int | None:
    """None when this process should carry on with the command itself (it is not the research wrapper, or it already is
    the isolated child). Otherwise the exit code: the refusal, or the isolated child's."""
    index = mode_index(words)
    if index is None or words[index] != "gemini":
        return None
    bad = startup_variables(env)
    if bad:
        output.write(
            sys.stderr,
            f"error: refused: startup variable(s) set: {', '.join(bad)}. Unset them and run again; nothing was run.",
        )
        return EXIT_UNKNOWN
    if isolated():
        return None
    ns = _namespace(words, index)
    action = ns.action if ns is not None else ""
    try:
        done = launch(absolutize(words), env, action=action)
    except WrapperError as err:
        output.write(sys.stderr, f"error: {err}")
        return EXIT_UNKNOWN
    code = done.returncode
    return 128 - code if code < 0 else code
