# SPDX-License-Identifier: Apache-2.0
"""What the service reads at start and per request: the epoch, the root-owned switch, the paid key, the process
hardening and the environment scrub (docs/gemini-broker.md, "How the key reaches the broker", "The root-owned enable
switch", "The unit files and their hardening"). Every path is a parameter; nothing here has a global.
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import re
import resource
import secrets
from collections.abc import Callable, MutableMapping
from pathlib import Path

from safo import geminisign
from safo.bounded import read_bounded
from safo.broker.errors import LedgerError
from safo.errors import ConfigError

EPOCH_FILE = "epoch"
EPOCH = re.compile(r"[0-9a-f]{32}")
KEY_FILE = "paid-key"
KEY_SHAPE = re.compile(r"[A-Za-z0-9_-]{20,256}")
KEEP_ENV = ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "CREDENTIALS_DIRECTORY", "STATE_DIRECTORY")
PR_SET_DUMPABLE = 4


def read_epoch(state_dir: Path) -> str:
    """The broker's epoch: 32 hex characters made once, in the private state directory, and read back after that. A
    file that is not exactly that shape stops the broker (root must look): it is never silently remade."""
    path = state_dir / EPOCH_FILE
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        try:
            text = read_bounded(path, 128).decode("ascii")
        except (OSError, UnicodeError):
            raise LedgerError("the epoch file cannot be read; root must look at it") from None
        if EPOCH.fullmatch(text[:-1]) is None or not text.endswith("\n"):
            raise LedgerError("the epoch file is malformed; root must look at it") from None
        return text[:-1]
    value = secrets.token_hex(16)
    try:
        os.write(fd, (value + "\n").encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    return value


def switch_reader(path: Path, trust_uid: int = 0) -> Callable[[], bool]:
    """A function that answers, on every call and from the file alone, whether the root-owned switch says `enabled`.
    Anything else (absent, wrong owner, writable, a link, other text) is False. Never cached."""

    def enabled() -> bool:
        try:
            data = geminisign.read_trust_file(path, trust_uid, "paid-use switch")
            text = data.decode("utf-8", "replace")
            lines = [x.strip() for x in text.splitlines() if x.strip() and not x.startswith("#")]
        except Exception:  # any failure to read the switch is "disabled", the safe answer
            return False
        return lines == ["enabled"]

    return enabled


def key_reader(credentials_dir: str | None) -> Callable[[], str]:
    """A function that returns the paid key from the systemd credential directory, read fresh each time. The key is
    one token of plain characters, optionally followed by one newline; anything else raises (no text of the file)."""

    def read() -> str:
        if not credentials_dir or not os.path.isabs(credentials_dir):
            raise ConfigError("the credential directory was not passed")
        try:
            raw = read_bounded(Path(credentials_dir) / KEY_FILE, 512).decode("ascii")
        except (OSError, UnicodeError):
            raise ConfigError("the paid key cannot be read") from None
        value = raw[:-1] if raw.endswith("\n") else raw
        if KEY_SHAPE.fullmatch(value) is None:
            raise ConfigError("the paid key does not have the plain shape of a key")
        return value

    return read


def key_present(read: Callable[[], str]) -> Callable[[], bool]:
    """`status`'s `key_loaded`: the credential exists and has the plain shape. The key goes nowhere."""

    def loaded() -> bool:
        try:
            read()
        except Exception:
            return False
        return True

    return loaded


def harden_process(
    prctl: Callable[[int, int, int, int, int], int] | None = None,
    setrlimit: Callable[[int, tuple[int, int]], None] = resource.setrlimit,
) -> None:
    """No core file and not dumpable: a crash or a ptrace by the same user cannot read the key from memory."""
    if prctl is None:
        prctl = ctypes.CDLL(None, use_errno=True).prctl
    if prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise OSError("the process could not be made undumpable")
    setrlimit(resource.RLIMIT_CORE, (0, 0))


def scrub_environment(environ: MutableMapping[str, str]) -> None:
    """Keep only what systemd hands the service; drop everything else, proxy variables included."""
    for name in [n for n in environ if n not in KEEP_ENV]:
        with contextlib.suppress(KeyError):
            del environ[name]
