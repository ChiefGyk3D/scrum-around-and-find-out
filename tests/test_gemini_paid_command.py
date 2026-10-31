# SPDX-License-Identifier: Apache-2.0
"""`safo gemini paid` and `safo gemini paid-dryrun` (#287): the only paid entry in the Gemini command group. They run
the broker client against a broker over a real Unix socket in a temporary directory (the real server, a fake vendor, a
software key standing in for the hardware key)."""

from __future__ import annotations

import datetime as dt
import io
import os
import shutil
import socket
import tempfile
import threading
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

import clientdata as d
from geminidata import make_key
from pipedata import LABEL, Rig
from safo import geminisign
from safo.broker import client
from safo.cli import main
from serverdata import CRED, Env

NOW = dt.datetime(2026, 10, 30, 12, 0, 0, tzinfo=dt.UTC)


class FakeBroker:
    """A listener on a Unix socket in a temporary directory; every connection goes to the real server in a thread."""

    def __init__(self, rig: Rig) -> None:
        self.env = Env(rig)
        self.rig = rig
        self.folder = Path(tempfile.mkdtemp(prefix="sb"))
        self.path = str(self.folder / "b.sock")
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(self.path)
        self.listener.listen(4)
        self.listener.settimeout(0.2)
        self.stop = threading.Event()
        self.threads: list[threading.Thread] = []
        self.accepter = threading.Thread(target=self.accept)
        self.accepter.start()

    def accept(self) -> None:
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            thread = threading.Thread(target=self.env.server.handle_connection, args=(conn, CRED))
            thread.start()
            self.threads.append(thread)

    def close(self) -> None:
        self.stop.set()
        self.accepter.join(timeout=10)
        for thread in self.threads:
            thread.join(timeout=30)
        self.listener.close()
        shutil.rmtree(self.folder, ignore_errors=True)


class Wired:
    """What `broker_setup` hands the command: a client config and dependencies aimed at the temporary socket."""

    def __init__(self, broker: FakeBroker, tmp_path: Path) -> None:
        self.broker = broker
        self.events: list[str] = []
        self.phrase: str | None = None  # None: type the right phrase for whatever is asked
        self.interactive = True
        self.connect: Callable[[], socket.socket] = lambda: client.connect_unix(broker.path, owner=os.geteuid())
        self.image_dir = str(tmp_path / "images")

    def answer(self, prompt: str) -> str:
        if self.phrase is not None:
            return self.phrase
        return "dryrun signer-check" if "dryrun" in prompt else "approve job-one"

    def __call__(self, ctx: object) -> tuple[client.ClientConfig, client.Deps]:
        rig = self.broker.rig
        cfg = client.ClientConfig(socket=self.broker.path, signing_key="/x", principal=LABEL, image_dir=self.image_dir)
        deps = client.Deps(
            connect=self.connect,
            sign=d.Signer(rig.key, self.events),
            now=rig.clock.wall,
            mono=rig.clock.mono,
            writer=client.adapter_write_image,
            sidecar=client.adapter_write_sidecar,
            check_dir=client.check_image_dir,
            terms=lambda text: None,
            confirm=self.answer,
            interactive=self.interactive,
            dry_sign=lambda payload: geminisign.sign(str(rig.key), payload, geminisign.DRYRUN_NAMESPACE, {}),
        )
        return cfg, deps


@pytest.fixture
def broker(tmp_path: Path) -> Iterator[FakeBroker]:
    fake = FakeBroker(Rig(tmp_path, make_key(tmp_path / "k")))
    try:
        yield fake
    finally:
        fake.close()


@pytest.fixture
def wired(broker: FakeBroker, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Wired:
    """`broker_setup` is the one seam; everything else is the real command."""
    setup = Wired(broker, tmp_path)
    monkeypatch.setattr("safo.modes.gemini.broker_setup", setup)
    return setup


def run(tmp_path: Path, *argv: str, globals_: tuple[str, ...] = ()) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    env = {"HOME": str(tmp_path), "PATH": "/nonexistent"}
    code = main([*globals_, "gemini", *argv], env=env, out=out, err=err, now=NOW)
    return code, out.getvalue(), err.getvalue()


def paid_args(tmp_path: Path) -> list[str]:
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("say hello to the broker")
    values = {
        "--model": "flat-test",
        "--job": "job-one",
        "--prompt-file": str(prompt),
        "--max-output-tokens": "500",
        "--max-usd": "2.5",
        "--quote": "go ahead",
        "--quoted-at": "2026-10-30T11:59:00Z",
    }
    return [x for pair in values.items() for x in pair]


def test_paid_runs_one_call_through_the_broker(broker: FakeBroker, wired: Wired, tmp_path: Path) -> None:
    code, out, err = run(tmp_path, "paid", *paid_args(tmp_path))
    assert code == 0, err + out
    assert "receipt: call " in out
    assert len(broker.rig.vendor.requests) == 1
    assert wired.events == ["sign"]


def test_paid_stops_when_the_person_does_not_type_the_phrase(broker: FakeBroker, wired: Wired, tmp_path: Path) -> None:
    wired.phrase = "no"
    code, out, err = run(tmp_path, "paid", *paid_args(tmp_path))
    assert code == 2 and "not confirmed" in out + err
    assert broker.rig.vendor.requests == [] and wired.events == []


def test_paid_global_dry_run_sends_nothing_and_opens_no_socket(
    wired: Wired, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom() -> socket.socket:
        raise AssertionError("no socket on a dry run")

    wired.connect = boom
    code, out, _ = run(tmp_path, "paid", *paid_args(tmp_path), globals_=("--dry-run",))
    assert code == 0 and "dry run" in out and wired.events == []


def test_paid_dryrun_tests_the_signer_against_the_broker_and_spends_nothing(
    broker: FakeBroker, wired: Wired, tmp_path: Path
) -> None:
    code, out, err = run(tmp_path, "paid-dryrun")
    assert code == 0, err + out
    assert "principal yubikey-a" in out and "hardware key" in out and "paid use is enabled" in out
    assert broker.rig.vendor.requests == [] and wired.events == []  # the call signer never ran


def test_paid_dryrun_says_when_the_broker_switch_is_off(broker: FakeBroker, wired: Wired, tmp_path: Path) -> None:
    broker.env.enabled = False
    code, out, _ = run(tmp_path, "paid-dryrun")
    assert code == 0 and "paid use is DISABLED" in out


def test_paid_dryrun_needs_a_person_at_a_terminal(broker: FakeBroker, wired: Wired, tmp_path: Path) -> None:
    wired.interactive = False
    code, out, err = run(tmp_path, "paid-dryrun")
    assert code == 2 and "terminal" in out + err


def test_paid_dryrun_reports_an_unreachable_broker(wired: Wired, tmp_path: Path) -> None:
    def nothing() -> socket.socket:
        raise FileNotFoundError

    wired.connect = nothing
    code, out, err = run(tmp_path, "paid-dryrun")
    assert code == 2 and "not reachable" in out + err
