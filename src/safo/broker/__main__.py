# SPDX-License-Identifier: Apache-2.0
"""`python -I -m safo.broker`: the unit's ExecStart. Reads the root-owned config, opens the private state directory,
recovers (open calls become ambiguous before anything is served), takes the socket systemd passes and serves until
SIGTERM. Every setup failure exits 4 with the exception class on standard error and nothing else."""

from __future__ import annotations

import datetime as dt
import logging
import os
import signal
import sys
import time
from collections.abc import Callable, MutableMapping
from pathlib import Path

from safo import geminisign, output
from safo.broker import runtime
from safo.broker.approval import Verifier
from safo.broker.issue import Issuer
from safo.broker.ledger import CallLedger
from safo.broker.pipeline import DEFAULT_DEADLINE_SECONDS, Pipeline
from safo.broker.policy import Caps, Policy
from safo.broker.prices import parse_prices
from safo.broker.server import Server, ServerConfig, adopt_listener, install_signal_handlers, read_config
from safo.broker.transport import HttpsTransport
from safo.broker.vendor import Transport
from safo.errors import SafoError

CONFIG = Path("/etc/safo/broker.yaml")
SIGNERS = Path("/etc/safo/gemini-allowed-signers")
REVOKED = Path("/etc/safo/gemini-revoked-signers")
SWITCH = Path("/etc/safo/gemini-paid-enabled")
EXIT_FAILED = 4
_SECTIONS = {"server", "prices", "caps", "deadline_seconds"}


def run(
    environ: MutableMapping[str, str],
    *,
    pid: int,
    config: Path = CONFIG,
    signers: Path = SIGNERS,
    revoked: Path = REVOKED,
    switch: Path = SWITCH,
    trust_uid: int = 0,
    require_hardware: bool = True,  # a test seam: software keys stand in for a hardware key
    first_fd: int = 3,
    verifier: Verifier = geminisign.verify,  # a test seam: the stand-in for the authenticator
    transport: Transport | None = None,
    on_ready: Callable[[Server], None] | None = None,
    handle_signals: bool = True,
    wall: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.UTC),
) -> int:
    """Set up and serve. Raises `SafoError` or `OSError` on a setup failure; `main` turns those into an exit status."""
    state_env = environ.get("STATE_DIRECTORY")
    credentials = environ.get("CREDENTIALS_DIRECTORY")
    runtime.scrub_environment(environ)
    listener = adopt_listener(environ, pid, first_fd=first_fd)
    data = read_config(config, trust_uid)
    if set(data) - _SECTIONS or not {"server", "prices"} <= set(data):
        raise SafoError("the broker config has an unknown or a missing section")
    server_cfg = ServerConfig.from_mapping(data["server"])
    caps_data = data.get("caps", {})
    if type(caps_data) is not dict or set(caps_data) - {"job_usd", "month_usd"}:
        raise SafoError("the broker config caps section is job_usd and month_usd")
    policy = Policy(parse_prices(data["prices"]), Caps.from_usd(caps_data.get("job_usd"), caps_data.get("month_usd")))
    deadline = data.get("deadline_seconds", DEFAULT_DEADLINE_SECONDS)
    if type(deadline) not in (int, float) or not 1 <= deadline <= 600:
        raise SafoError("the broker config deadline_seconds is from 1 to 600")
    if not state_env or not os.path.isabs(state_env):
        raise SafoError("the state directory was not passed")
    ledger = CallLedger(Path(state_env))
    ledger.open()
    epoch = runtime.read_epoch(ledger.dir)
    trust = geminisign.Trust(signers, revoked, trust_uid, require_hardware, True)
    key = runtime.key_reader(credentials)
    pipeline = Pipeline(
        ledger,
        policy,
        Issuer(ledger, policy, epoch),
        trust,
        transport if transport is not None else HttpsTransport(key),
        epoch=epoch,
        wall=wall,
        mono=time.monotonic,
        deadline_seconds=float(deadline),
        verifier=verifier,
    )
    ledger.recover(wall())  # before anything is served: every open call becomes ambiguous
    pipeline.issuer.flush()  # a restart empties the issued table
    server = Server(
        pipeline,
        server_cfg,
        switch=runtime.switch_reader(switch, trust_uid),
        key_loaded=runtime.key_present(key),
    )
    restore = install_signal_handlers(server, (signal.SIGTERM, signal.SIGINT)) if handle_signals else lambda: None
    try:
        if on_ready is not None:
            on_ready(server)
        return 0 if server.serve(listener) == 0 else EXIT_FAILED
    finally:
        restore()


def main() -> int:
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(message)s")
    try:
        runtime.harden_process()
        return run(os.environ, pid=os.getpid())
    except (SafoError, OSError, ValueError) as exc:
        output.write(sys.stderr, f"safo-broker: cannot start ({type(exc).__name__})")  # the class only, never a message
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
