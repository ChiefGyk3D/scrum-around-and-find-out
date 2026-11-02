# SPDX-License-Identifier: Apache-2.0
"""The broker client refuses a direct module start unless a person is at a terminal (#299).

`python3 -I -m safo.broker.client` skips the wrapper (its sanitized environment, private directory and closed
descriptors). The guard's text patterns are a denylist and can be got around, so the module also checks where it runs:
the direct entry starts only with a controlling terminal and a terminal on standard input and output (a person), and
with no startup variable the wrapper refuses. The wrapper's own paid commands never reach this entry: they call
`run_paid` and `run_dryrun` in-process, so they are unaffected."""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from safo.broker import client

HERE = Path(__file__).resolve().parent.parent


def tty_yes(_fd: int) -> bool:
    return True


def tty_no(_fd: int) -> bool:
    return False


def open_ok() -> None:
    return None


def open_fail() -> None:
    raise OSError("no controlling terminal")


def problem(
    env: Mapping[str, str] | None = None,
    isatty: Callable[[int], bool] = tty_yes,
    open_tty: Callable[[], None] = open_ok,
) -> str | None:
    return client.direct_start_problem({} if env is None else env, isatty=isatty, open_tty=open_tty)


def test_a_person_at_a_terminal_may_start_it() -> None:
    assert problem() is None


def test_no_terminal_on_standard_input_is_refused() -> None:
    seen: list[int] = []

    def only_output(fd: int) -> bool:
        seen.append(fd)
        return fd == 1

    assert problem(isatty=only_output) is not None
    assert 0 in seen


def test_no_terminal_on_standard_output_is_refused() -> None:
    assert problem(isatty=lambda fd: fd == 0) is not None


def test_no_controlling_terminal_is_refused() -> None:
    assert problem(open_tty=open_fail) is not None


@pytest.mark.parametrize("name", ["PYTHONPATH", "PYTHONSTARTUP", "LD_PRELOAD", "BASH_ENV", "ENV"])
def test_a_startup_variable_is_refused_and_named_without_its_value(name: str) -> None:
    found = problem(env={name: "value-that-must-not-print"})
    assert found is not None and name in found and "value-that-must-not-print" not in found


def test_every_refusal_is_a_fixed_message_with_the_refused_exit_status(capsys: pytest.CaptureFixture[str]) -> None:
    code = client.entry([], env={}, isatty=tty_no, open_tty=open_ok)
    assert code == client.EXIT_REFUSED
    err = capsys.readouterr().err
    assert "terminal" in err and "safo gemini paid" in err


def test_the_wrapper_paid_commands_do_not_pass_through_the_entry() -> None:
    """They call run_paid and run_dryrun in-process, so the check cannot reach them."""
    source = (HERE / "src" / "safo" / "modes" / "gemini.py").read_text()
    assert "client.run_paid(" in source and "client.run_dryrun(" in source
    assert "client.entry(" not in source and "client.main(" not in source


def run_module(
    stdin: int | None, stdout: int | None, env: Mapping[str, str], *, controlling: bool
) -> subprocess.CompletedProcess[bytes]:
    base = [sys.executable, "-I", "-m", "safo.broker.client", "--help"]
    if controlling:  # make fd 0 the controlling terminal of a new session, then start the module
        code = (
            "import fcntl, os, sys, termios; fcntl.ioctl(0, termios.TIOCSCTTY, 0); "
            "os.execve(sys.argv[1], sys.argv[1:], dict(os.environ))"
        )
        base = [sys.executable, "-c", code, *base]
    return subprocess.run(  # noqa: S603 - fixed argv built here, no shell
        base, stdin=stdin, stdout=stdout, stderr=subprocess.PIPE, env=dict(env), check=False, start_new_session=True
    )


def clean_env() -> dict[str, str]:
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "TERM": "dumb"}


def test_started_from_a_pipe_it_refuses_and_exits_with_the_refused_status() -> None:
    done = run_module(subprocess.DEVNULL, subprocess.PIPE, clean_env(), controlling=False)
    assert done.returncode == client.EXIT_REFUSED
    assert b"terminal" in done.stderr


def test_started_with_a_pseudo_terminal_it_gets_past_the_check() -> None:
    master, slave = os.openpty()
    try:
        done = run_module(slave, slave, clean_env(), controlling=True)
        os.close(slave)
        slave = -1
        try:
            shown = os.read(master, 65_536)
        except OSError:
            shown = b""
    finally:
        os.close(master)
        if slave != -1:
            os.close(slave)
    assert done.returncode == 0, done.stderr
    assert b"--model" in shown  # the argument parser ran: --help printed its usage


def test_a_pseudo_terminal_with_a_startup_variable_is_still_refused() -> None:
    master, slave = os.openpty()
    try:
        done = run_module(slave, slave, {**clean_env(), "BASH_ENV": "x"}, controlling=True)
    finally:
        os.close(slave)
        os.close(master)
    assert done.returncode == client.EXIT_REFUSED
    assert b"BASH_ENV" in done.stderr
