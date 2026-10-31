#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Local acceptance check: the broker under the sandbox properties of its systemd unit.

Starts the broker's real start-up flow (tests/sandbox_serve.py) as a socket-activated transient USER unit with the
hardening properties of the shipped unit, then drives it over the socket: status, dryrun, begin and call for text and
for an image, and a SIGTERM stop that must end with exit status 0. In `--kill` mode the filtered system calls end the
process with SIGSYS instead of failing with an error. `--extra-filter` adds one more system-call filter (for example
`~socketpair`) to prove the server does not need a call the unit may take away. `--mutate` injects one deliberate bug
(socket, socketpair or recvmsg) that the check must catch.

Needs a user systemd manager (`systemd-run --user`). Exit status: 0 passed, 1 failed, 3 not available here (with the
reason on standard error). The pytest wrapper, tests/test_broker_sandbox.py, skips with that reason.

User mode differs from the shipped unit in what it cannot reproduce: no `User=`, no encrypted credential, no root-owned
files (a harness shim reports the scratch directory's parents as root-owned), `RestrictAddressFamilies=AF_INET` so any
new AF_UNIX socket the server tried to make is refused. It is a check for what the server asks of the kernel, not a
replacement for the throwaway-machine run of phase 5.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
SERVE = REPO / "tests" / "sandbox_serve.py"

# The properties of the shipped unit that a user manager accepts (docs/gemini-broker.md, "The unit files and their
# hardening"), with ProtectHome=read-only so the scratch tree can be read, and AF_INET only, so a new AF_UNIX socket
# fails.
PROPERTIES = (
    "NoNewPrivileges=yes",
    "CapabilityBoundingSet=",
    "PrivateTmp=yes",
    "PrivateDevices=yes",
    "PrivateMounts=yes",
    "ProtectSystem=strict",
    "ProtectHome=read-only",
    "ProtectProc=invisible",
    "ProcSubset=pid",
    "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes",
    "ProtectKernelLogs=yes",
    "ProtectControlGroups=yes",
    "ProtectClock=yes",
    "ProtectHostname=yes",
    "RestrictAddressFamilies=AF_INET",
    "RestrictNamespaces=yes",
    "RestrictRealtime=yes",
    "RestrictSUIDSGID=yes",
    "LockPersonality=yes",
    "MemoryDenyWriteExecute=yes",
    "SystemCallArchitectures=native",
    "SystemCallFilter=@system-service",
    "SystemCallFilter=~@privileged @resources",
    "SystemCallFilter=~recvmsg recvmmsg",
    "DevicePolicy=closed",
    "KeyringMode=private",
    "RemoveIPC=yes",
    "LimitCORE=0",
    "LimitNOFILE=64",
    "TasksMax=32",
    "UMask=0077",
)
ERRNO_PROPERTY = "SystemCallErrorNumber=EPERM"  # left out in kill mode: a filtered call then ends with SIGSYS

Check = Callable[[dict[str, Any], list[bytes]], bool]


@dataclasses.dataclass
class Outcome:
    ok: bool
    steps: list[str]
    log: str


def unavailable_reason() -> str | None:
    """Why the check cannot run here, or None."""
    if shutil.which("systemd-run") is None or shutil.which("systemctl") is None:
        return "systemd-run is not installed"
    try:
        done = subprocess.run(
            ["systemd-run", "--user", "--pipe", "--wait", "--collect", "-q", "/bin/true"],  # noqa: S607 - from PATH
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "systemd-run --user did not answer"
    if done.returncode != 0:
        return "systemd-run --user is unavailable (no user service manager in this session)"
    return None


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=60, check=False)  # noqa: S603 - fixed vector


def _journal(name: str) -> str:
    """The last lines the user manager logged for a unit that failed (what systemd says, not what the service says)."""
    done = _run("journalctl", "--user", "-u", f"{name}.service", "-u", f"{name}.socket", "-n", "15", "--no-pager")
    return "\n--- journal ---\n" + (done.stdout or done.stderr)[-1500:]


def _exchange(sock_path: str, body: bytes) -> tuple[dict[str, Any], list[bytes]]:
    from safo.broker import protocol

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(60)
        sock.connect(sock_path)
        sock.sendall(protocol.frame(body, protocol.MAX_REQUEST_FRAME))
        sock.shutdown(socket.SHUT_WR)
        reply = protocol.parse_reply(protocol.read_frame(sock.recv, protocol.MAX_REPLY_FRAME))
        frames = [
            protocol.read_frame(sock.recv, protocol.MAX_ATTACHMENT_FRAME)
            for _ in range(protocol.attachment_count(reply))
        ]
    return reply, frames


def run_check(*, kill: bool = False, extra_filter: str = "", mutate: str = "none") -> Outcome:
    sys.path[:0] = [str(REPO / "src"), str(REPO / "tests")]
    import yaml

    from brokerdata import prices_data
    from geminidata import make_key, signers_line
    from pipedata import Rig, image_req, text_req
    from safo import geminisign
    from safo.broker import protocol
    from safo.broker.issue import Offer
    from serverdata import call_fields

    cache = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".cache"  # the real home, not a test-patched $HOME under /tmp
    cache.mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="safo-sandbox-", dir=cache))  # readable under ProtectHome=read-only
    name = f"safo-broker-check-{uuid.uuid4().hex[:10]}"
    run = work / "run"
    sock_path = str(run / "broker.sock")
    log = work / "service.log"
    steps: list[str] = []
    ok = True

    def step(label: str, good: bool, detail: str = "") -> None:
        nonlocal ok
        ok = ok and good
        steps.append(f"{'ok  ' if good else 'FAIL'} {label}{(': ' + detail) if detail else ''}")

    try:
        for sub in ("etc", "state", "cred", "keys"):
            (run / sub).mkdir(parents=True, mode=0o755 if sub == "etc" else 0o700)
        key = make_key(run / "keys" / "a")
        (run / "etc/signers").write_text(signers_line("yubikey-a", key.with_suffix(".pub")) + "\n")
        (run / "etc/revoked").write_text("")
        (run / "etc/paid-enabled").write_text("enabled\n")
        (run / "etc/broker.yaml").write_text(
            yaml.safe_dump({"server": {"allowed_uids": [os.getuid()], "grace_seconds": 10}, "prices": prices_data()})
        )
        (run / "cred/paid-key").write_text("THROWAWAYKEY_abcdefghijklmnopqrstuvwxyz0123\n")
        for path in (run / "etc").iterdir():
            path.chmod(0o644)
        (work / "rig").mkdir(mode=0o700)
        rig = Rig(work / "rig", key)  # only to build and sign approval texts on this side

        props = list(PROPERTIES)
        if not kill:
            props.append(ERRNO_PROPERTY)
        if extra_filter:
            props.append(f"SystemCallFilter={extra_filter}")
        command = [
            "systemd-run",
            "--user",
            "--collect",
            f"--unit={name}",
            f"--socket-property=ListenStream={sock_path}",
            "--socket-property=SocketMode=0600",
            "--socket-property=Accept=no",
            "--socket-property=Backlog=16",
            *[arg for p in props for arg in ("-p", p)],
            *["-p", f"ReadWritePaths={run / 'state'}"],
            *["-p", f"LoadCredential=paid-key:{run / 'cred/paid-key'}"],
            *["-p", f"StandardError=file:{log}"],
            *["-p", "Environment=PYTHONDONTWRITEBYTECODE=1"],
            *["-p", f"Environment=STATE_DIRECTORY={run / 'state'}"],
            *["-p", f"Environment=SAFO_REPO={REPO}"],
            *["-p", f"Environment=SAFO_RUN_DIR={run}"],
            *["-p", f"Environment=SAFO_MUTATE={mutate}"],
            *["-p", "TimeoutStopSec=20s"],
            sys.executable,
            "-I",
            str(SERVE),
        ]
        started = _run(*command)
        step("start the socket unit", started.returncode == 0, started.stderr.strip()[:120])
        if started.returncode != 0:
            return Outcome(False, steps, started.stderr)

        def attempt(label: str, op: str, check: Check | None = None, **fields: Any) -> dict[str, Any]:
            try:
                reply, frames = _exchange(sock_path, protocol.request_body(op, **fields))
            except Exception as exc:  # the service died, was killed, or answered badly
                step(label, False, type(exc).__name__)
                return {}
            good = reply.get("ok") is True and (check is None or check(reply, frames))
            step(label, good, "" if good else str(reply.get("code", "unexpected answer")))
            return reply if good else {}

        attempt("status", "status", lambda r, f: r.get("enabled") is True and r.get("key_loaded") is True)
        throwaway = '{"dry_run":true}'
        attempt(
            "dryrun",
            "dryrun",
            lambda r, f: r.get("principal") == "yubikey-a",
            approval={"payload": throwaway, "signature": rig.sign(throwaway, geminisign.DRYRUN_NAMESPACE)},
        )
        for kind, req in (("text", text_req()), ("image", image_req())):
            shape: dict[str, Any] = {}
            if kind == "image":
                shape = {"count": req.count, "image_size": req.image_size, "aspect_ratio": req.aspect_ratio}
            begin = attempt(
                f"{kind} begin",
                "begin",
                model=req.model,
                job=req.job,
                kind=kind,
                max_output_tokens=req.max_output_tokens,
                prompt_bytes=len(req.prompt.encode()),
                max_usd="2.5",
                **shape,
            )
            if not begin:
                continue
            offer = Offer(
                str(begin["nonce"]),
                str(begin["epoch"]),
                rig.clock.wall(),
                str(begin["ledger_head"]),
                0,
                0,
                str(begin["thinking_level"]),
                bool(begin["beyond_ceiling"]),
                2_500_000,
            )
            approval = rig.text(req, offer)
            want = 1 if kind == "image" else 0
            attempt(
                f"{kind} call",
                "call",
                lambda r, f, want=want, kind=kind: (
                    len(f) == want and (kind == "image" or r.get("text") == "a short answer")
                ),
                **call_fields(req, approval, rig.sign(approval)),
            )
        stopped = _run("systemctl", "--user", "stop", f"{name}.service")
        step("SIGTERM stop", stopped.returncode == 0, stopped.stderr.strip()[:120])
        time.sleep(0.2)
        text_log = log.read_text() if log.exists() else ""
        last = text_log.strip().splitlines()[-1][:120] if text_log.strip() else "no log"
        step("the server exited 0 after the stop", "serve exit 0" in text_log, last)
        step("no traceback in the service log", "Traceback" not in text_log)
        return Outcome(ok, steps, text_log if ok else text_log + _journal(name))
    finally:
        for unit in (f"{name}.socket", f"{name}.service"):
            _run("systemctl", "--user", "stop", unit)
            _run("systemctl", "--user", "reset-failed", unit)
        shutil.rmtree(work, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="The broker under the sandbox properties of its unit (see the module text)."
    )
    parser.add_argument("--kill", action="store_true", help="a filtered system call ends the process with SIGSYS")
    parser.add_argument("--extra-filter", default="", help="one more SystemCallFilter value, such as ~socketpair")
    parser.add_argument("--mutate", default="none", choices=["none", "socket", "socketpair", "recvmsg"])
    args = parser.parse_args(argv)
    why = unavailable_reason()
    if why:
        print(f"not available: {why}", file=sys.stderr)
        return 3
    outcome = run_check(kill=args.kill, extra_filter=args.extra_filter, mutate=args.mutate)
    print("\n".join(outcome.steps))
    print(json.dumps({"ok": outcome.ok}))
    return 0 if outcome.ok else 1


if __name__ == "__main__":
    sys.exit(main())
