# SPDX-License-Identifier: Apache-2.0
"""The ExecStart of the sandbox acceptance check (scripts/broker_sandbox_check.py). Not shipped, not a test module.

It runs the broker's real start-up flow (`safo.broker.__main__.run`, after `runtime.harden_process`) as a
socket-activated transient user unit, with the test seams a laptop needs: a fake vendor, a software key standing in
for the hardware key, and trust files owned by the current user. Settings come from the environment the check passes in:

  SAFO_REPO     the repository root (the interpreter runs with -I, so the paths are added here)
  SAFO_RUN_DIR  the scratch directory with etc/ (config, signers, switch)
  SAFO_MUTATE   none, or one deliberate bug the check must catch: socket, socketpair or recvmsg
"""

from __future__ import annotations

import os
import socket
import stat
import sys
import traceback
from pathlib import Path
from typing import Any

REPO = Path(os.environ["SAFO_REPO"])
RUN = Path(os.environ["SAFO_RUN_DIR"])
MUTATE = os.environ.get("SAFO_MUTATE", "none")
sys.path[:0] = [str(REPO / "src"), str(REPO / "tests")]

from fakevendor import FakeClock, FakeVendor, jpeg  # noqa: E402 - the paths are added just above
from pipedata import as_hardware  # noqa: E402
from safo import geminisign  # noqa: E402
from safo.broker import __main__ as entry  # noqa: E402
from safo.broker import runtime  # noqa: E402
from safo.broker import server as server_module  # noqa: E402


class _Os:
    """HARNESS ONLY. In a user-namespace sandbox every root-owned directory shows as uid 65534, and a scratch tree sits
    under directories the trust-file walk would reject, for reasons that do not exist for the real root-owned /etc/safo.
    This reports the ancestors of the scratch `etc` directory as root:root 0755 and changes nothing else."""

    def __getattr__(self, name: str) -> Any:
        return getattr(os, name)

    def stat(self, path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        info = os.stat(path, *args, **kwargs)
        etc = str(RUN / "etc")
        if (etc + "/").startswith(str(path).rstrip("/") + "/") and stat.S_ISDIR(info.st_mode):
            fields = list(info)
            fields[0] = (info.st_mode & ~0o7777) | 0o755
            fields[4] = 0
            return os.stat_result(fields)
        return info


def mutate() -> None:
    """One deliberate bug per mode, for the check's negative cases: the check must go red for each."""
    original_init = server_module.Server.__init__
    original_admit = server_module.Server.admit
    if MUTATE == "socket":

        def init_socket(self: Any, *a: Any, **k: Any) -> None:
            original_init(self, *a, **k)
            socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        server_module.Server.__init__ = init_socket  # type: ignore[method-assign]  # the injected bug
    elif MUTATE == "socketpair":

        def init_pair(self: Any, *a: Any, **k: Any) -> None:
            original_init(self, *a, **k)
            socket.socketpair()

        server_module.Server.__init__ = init_pair  # type: ignore[method-assign]  # the injected bug
    elif MUTATE == "recvmsg":

        def admit_msg(self: Any, conn: socket.socket) -> None:
            conn.recvmsg(1, 0, socket.MSG_PEEK)
            original_admit(self, conn)

        server_module.Server.admit = admit_msg  # type: ignore[method-assign]  # the injected bug
    elif MUTATE != "none":
        raise SystemExit("unknown SAFO_MUTATE")


def go() -> int:
    geminisign.__dict__["os"] = _Os()  # harness only, see _Os
    mutate()
    runtime.harden_process()  # as main() does
    clock = FakeClock()
    vendor = FakeVendor(clock)
    vendor.image = jpeg()
    vendor.mime = "image/jpeg"
    return entry.run(
        os.environ,
        pid=os.getpid(),
        config=RUN / "etc/broker.yaml",
        signers=RUN / "etc/signers",
        revoked=RUN / "etc/revoked",
        switch=RUN / "etc/paid-enabled",
        trust_uid=os.getuid(),
        require_hardware=False,
        verifier=as_hardware,
        transport=vendor,
        wall=clock.wall,
    )


if __name__ == "__main__":
    try:
        code = go()
    except BaseException:
        traceback.print_exc()
        code = 99
    print("serve exit", code, file=sys.stderr, flush=True)
    sys.exit(code)
