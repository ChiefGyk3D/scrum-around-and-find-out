# SPDX-License-Identifier: Apache-2.0
"""safo-digest (#531): real subprocesses, synthetic commands, temporary folders only."""

from __future__ import annotations

import getpass
import importlib
import os
import signal
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

SRC = str(Path(__file__).resolve().parents[1] / "src")
PY = sys.executable


def _toml_list(items: list[list[str]]) -> str:
    return "[" + ", ".join("[" + ", ".join('"' + s.replace("\\", "\\\\") + '"' for s in i) + "]" for i in items) + "]"


class Env:
    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.out = tmp / "digests"
        self.cfg = tmp / "digest.toml"
        self.home = tmp / "home"
        self.home.mkdir()

    def config(self, allow: list[list[str]] | None = None, extra: str = "", out: Path | None = None) -> None:
        allow = [[PY]] if allow is None else allow
        self.cfg.write_text(f'out_dir = "{out or self.out}"\nallow = {_toml_list(allow)}\n{extra}\n')

    def run(
        self, *cmd: str, flags: tuple[str, ...] = (), timeout: float = 60, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[bytes]:
        e = {**os.environ, "PYTHONPATH": SRC, "HOME": str(self.home)}
        e.update(env or {})
        return subprocess.run(  # noqa: S603 - argv list of this interpreter and synthetic arguments
            [PY, "-m", "safo.digest", "--config", str(self.cfg), *flags, "--", *cmd],
            capture_output=True,
            timeout=timeout,
            env=e,
            check=False,
        )

    def saved(self) -> list[Path]:
        return sorted(self.out.glob("*")) if self.out.exists() else []


@pytest.fixture()
def env(tmp_path: Path) -> Env:
    e = Env(tmp_path)
    e.config()
    return e


def test_large_output_is_capped_and_saved_in_full(env: Env) -> None:
    env.config(extra="max_lines = 30\nmax_bytes = 3000")
    r = env.run(PY, "-c", "[print('line', i, 'x' * 50) for i in range(200000)]")
    assert r.returncode == 0
    assert len(r.stdout) <= 3000
    assert len(r.stdout.splitlines()) <= 40
    assert b"line 0 " in r.stdout and b"line 199999 " in r.stdout
    [f] = env.saved()
    assert f.read_text().count("\n") == 200000
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert stat.S_IMODE(env.out.stat().st_mode) == 0o700
    assert b"exit=0" in r.stdout and b"lines=200000" in r.stdout


def test_binary_and_escape_sequences_never_reach_the_digest(env: Env) -> None:
    code = (
        "import sys; sys.stdout.buffer.write(bytes([0x6f,0x6b,0,0xff,0xfe,0x1b])"
        " + b'[31mRED' + bytes([10]) + bytes([0x1b]) + b']0;title' + bytes([7, 0x1b]) + b'[2J' + bytes([13])"
        " + b'zzz' + bytes([10, 0x9b]) + b'31m')"
    )
    r = env.run(PY, "-c", code)
    assert r.returncode == 0
    for bad in (b"\x1b", b"\x00", b"\x07", b"\x9b", b"\r"):
        assert bad not in r.stdout
    assert b"RED" in r.stdout
    for frag in (b"[31m", b"]0;title", b"[2J"):
        assert frag not in r.stdout, frag
    [f] = env.saved()
    raw = f.read_bytes()
    assert b"\x1b[31mRED" in raw and b"\xff\xfe" in raw


def test_nonzero_exit_passes_through_with_failures_first(env: Env) -> None:
    env.config(extra="max_lines = 20")
    code = (
        "import sys\nfor i in range(500): print('ok', i)\n"
        "print('FAILED tests/test_x.py::test_boom - assert 1 == 2')\nprint('ok tail')\nsys.exit(3)"
    )
    r = env.run(PY, "-c", code)
    assert r.returncode == 3
    text = r.stdout.decode()
    assert "exit=3" in text
    assert text.index("FAILED tests/test_x.py::test_boom") < text.index("ok 0")


def test_hung_child_times_out_and_whole_group_dies(env: Env) -> None:
    pidfile = env.tmp / "gc.pid"
    code = (
        "import subprocess, sys, time\n"
        "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(600)'])\n"
        f"open({str(pidfile)!r}, 'w').write(str(p.pid))\n"
        "print('started', flush=True)\n"
        "time.sleep(600)\n"
    )
    t0 = time.monotonic()
    r = env.run(PY, "-c", code, flags=("--timeout", "2"))
    assert time.monotonic() - t0 < 20
    assert r.returncode == 124
    assert b"timeout" in r.stdout and b"started" in r.stdout
    pid = int(pidfile.read_text())
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        os.kill(pid, signal.SIGKILL)
        pytest.fail("grandchild survived the timeout")


def test_command_not_on_allow_list_is_refused_and_not_run(env: Env) -> None:
    marker = env.tmp / "ran"
    env.config(allow=[["gh", "pr", "checks"]])
    r = env.run(PY, "-c", f"open({str(marker)!r}, 'w')")
    assert r.returncode == 125 and not marker.exists() and env.saved() == []
    assert b"allow" in r.stderr
    r = env.run("gh", "pr", "view")  # a different command than the listed prefix
    assert r.returncode == 125


def test_empty_allow_list_refuses_everything(env: Env) -> None:
    env.config(allow=[])
    assert env.run(PY, "-c", "pass").returncode == 125


def test_no_shell_arguments_are_literal(env: Env) -> None:
    marker = env.tmp / "pwned"
    arg = f"; touch {marker} $(touch {marker}) `touch {marker}` | cat"
    r = env.run(PY, "-c", "import sys; print(sys.argv[1])", arg)
    assert r.returncode == 0 and not marker.exists()
    assert b"$(touch" in r.stdout


def test_missing_executable_is_127(env: Env) -> None:
    env.config(allow=[["definitely-not-a-real-binary-531"]])
    assert env.run("definitely-not-a-real-binary-531").returncode == 127


def test_relative_path_entry_cannot_hijack_an_allowed_name(env: Env) -> None:
    evil = env.tmp / "evilbin"
    evil.mkdir()
    marker = env.tmp / "hijacked"
    tool = evil / "mytool531"
    tool.write_text(f"#!/bin/sh\n: > {marker}\n")
    tool.chmod(0o755)
    env.config(allow=[["mytool531"]])
    r = subprocess.run(  # noqa: S603 - argv list of this interpreter and synthetic arguments
        [PY, "-m", "safo.digest", "--config", str(env.cfg), "--", "mytool531"],
        capture_output=True,
        cwd=env.tmp,
        env={"PATH": "evilbin", "PYTHONPATH": SRC, "HOME": str(env.home)},
        check=False,
    )
    assert r.returncode in (125, 127) and not marker.exists()


def test_symlinked_output_dir_is_refused(env: Env, tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(real)
    env.config(out=link)
    r = env.run(PY, "-c", "print(1)")
    assert r.returncode == 125 and list(real.iterdir()) == []


def test_symlinked_parent_component_is_refused(env: Env, tmp_path: Path) -> None:
    real = tmp_path / "realparent"
    real.mkdir()
    (tmp_path / "lnk").symlink_to(real)
    env.config(out=tmp_path / "lnk" / "d")
    r = env.run(PY, "-c", "print(1)")
    assert r.returncode == 125 and list(real.iterdir()) == []


def test_loose_output_dir_is_refused(env: Env) -> None:
    env.out.mkdir(mode=0o755)
    env.out.chmod(0o755)
    assert env.run(PY, "-c", "print(1)").returncode == 125


def test_output_file_is_never_written_through_a_planted_symlink(env: Env) -> None:
    env.out.mkdir(mode=0o700)
    victim = env.tmp / "victim"
    victim.write_text("keep")
    for i in range(3):
        (env.out / f"plant{i}").symlink_to(victim)
    r = env.run(PY, "-c", "print('hello')")
    assert r.returncode == 0 and victim.read_text() == "keep"


def test_digest_redacts_user_host_home_and_callsign_but_file_is_raw(env: Env) -> None:
    user, host = getpass.getuser(), socket.gethostname()
    code = (
        f"print('user {user} host {host} home {env.home}/x call W1AW and K1ABC grid FN31pr keep N0CALL')\n"
        "print('secretword here')"
    )
    env.config(extra='redact_words = ["secretword"]')
    r = env.run(PY, "-c", code)
    out = r.stdout.decode()
    assert r.returncode == 0
    for leak in (host, str(env.home), "W1AW", "K1ABC", "FN31pr", "secretword"):
        assert leak not in out, leak
    if len(user) > 3:
        assert user not in out.replace(str(env.out), "")
    assert "N0CALL" in out
    [f] = env.saved()
    assert "W1AW" in f.read_text()


def test_saved_path_is_printed(env: Env) -> None:
    r = env.run(PY, "-c", "print('hi')")
    line = next(x for x in r.stdout.decode().splitlines() if "saved=" in x)
    assert env.out.name in line.split("saved=", 1)[1]


def test_long_single_line_and_tiny_byte_cap(env: Env) -> None:
    env.config(extra="max_bytes = 300\nmax_lines = 5")
    r = env.run(PY, "-c", "print('A' * 5_000_000); print('B' * 10)")
    assert r.returncode == 0 and len(r.stdout) <= 300
    [f] = env.saved()
    assert f.stat().st_size == 5_000_000 + 1 + 10 + 1


def test_file_size_cap_flags_truncation_and_still_drains(env: Env) -> None:
    env.config(extra="max_file_bytes = 100000")
    r = env.run(PY, "-c", "[print('x' * 99) for _ in range(5000)]")
    assert r.returncode == 0 and b"file-truncated" in r.stdout
    [f] = env.saved()
    assert f.stat().st_size <= 100000


@pytest.mark.parametrize(
    "body",
    [
        'allow = "gh"',
        'allow = ["gh"]',
        "allow = [[1]]",
        "allow = [[]]",
        "max_lines = 0",
        "max_bytes = 10",
        "bogus = 1",
    ],
)
def test_bad_config_fails_closed(env: Env, body: str) -> None:
    base = f'out_dir = "{env.out}"\nallow = [["{PY}"]]\n'
    key = body.split("=")[0].strip()
    base = "".join(ln + "\n" for ln in base.splitlines() if not ln.startswith(key + " "))
    env.cfg.write_text(base + body + "\n")
    assert env.run(PY, "-c", "print(1)").returncode == 125


def test_relative_out_dir_is_refused(env: Env) -> None:
    env.cfg.write_text(f'out_dir = "relative"\nallow = [["{PY}"]]\n')
    assert env.run(PY, "-c", "print(1)").returncode == 125


def test_config_symlink_is_refused(env: Env) -> None:
    real = env.tmp / "real.toml"
    real.write_text(env.cfg.read_text())
    env.cfg.unlink()
    env.cfg.symlink_to(real)
    assert env.run(PY, "-c", "print(1)").returncode == 125


def test_output_create_refuses_a_planted_symlink_at_the_exact_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = importlib.import_module("safo." + "digest")
    d = tmp_path / "d"
    d.mkdir(mode=0o700)
    victim = tmp_path / "victim"
    victim.write_text("keep")
    (d / "fixed.log").symlink_to(victim)
    monkeypatch.setattr(mod, "_safe_name", lambda _argv0: "fixed.log")
    dirfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(FileExistsError):
            mod.create_output(dirfd, "x")
    finally:
        os.close(dirfd)
    assert victim.read_text() == "keep"


def test_no_command_is_a_usage_error(env: Env) -> None:
    r = subprocess.run(  # noqa: S603 - argv list of this interpreter and synthetic arguments
        [PY, "-m", "safo.digest", "--config", str(env.cfg)],
        capture_output=True,
        env={**os.environ, "PYTHONPATH": SRC},
        check=False,
    )
    assert r.returncode == 125
