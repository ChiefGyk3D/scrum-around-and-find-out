# SPDX-License-Identifier: Apache-2.0
"""Run one command under the real `bash` for the rmguard differential tests, with no output and a time limit.

It starts bash with `os.posix_spawn` (no shell is involved in starting it, standard streams go to /dev/null) and the
working directory is set by a tiny `cd` in front of an inner `bash -c`, because `posix_spawn` has no cwd argument.
"""

from __future__ import annotations

import os
import shutil
import signal
import time

SCRIPT = 'cd -- "$1" && exec bash -c "$2"'


def bash_path(path: str | None = None) -> str | None:
    return shutil.which("bash", path=path)


def run_bash(command: str, cwd: str, env: dict[str, str], timeout: float = 30.0) -> int:
    """Run `command` with bash in `cwd` and the given environment; return its exit status (or -9 on a timeout)."""
    bash = bash_path(env.get("PATH"))
    if bash is None:
        raise FileNotFoundError("bash")
    actions = [
        (os.POSIX_SPAWN_OPEN, 0, os.devnull, os.O_RDONLY, 0),
        (os.POSIX_SPAWN_OPEN, 1, os.devnull, os.O_WRONLY, 0),
        (os.POSIX_SPAWN_OPEN, 2, os.devnull, os.O_WRONLY, 0),
    ]
    pid = os.posix_spawn(bash, [bash, "-c", SCRIPT, "rmguard", cwd, command], env, file_actions=actions)
    deadline = time.monotonic() + timeout
    while True:
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            return os.waitstatus_to_exitcode(status)
        if time.monotonic() > deadline:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            return -9
        time.sleep(0.005)
