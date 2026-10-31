# SPDX-License-Identifier: Apache-2.0
"""The pieces around the server: the inherited descriptor, the config, the epoch, the switch, the key, the process
hardening, the transport to the vendor, and the entry point end to end (a fake vendor, a temporary unix socket)."""

from __future__ import annotations

import contextlib
import datetime as dt
import http.client
import http.server
import json
import os
import resource
import socket
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any, ClassVar

import pytest
import yaml

from brokerdata import Crash, CrashAt, prices_data
from fakevendor import FakeVendor
from geminidata import make_key, signers_line
from pipedata import LABEL, Rig, as_hardware, text_req
from safo import gemini, geminisign
from safo.broker import __main__ as entry
from safo.broker import protocol, runtime
from safo.broker.errors import LedgerError
from safo.broker.server import (
    ListenError,
    Server,
    ServerConfig,
    adopt_listener,
    load_config,
    read_config,
)
from safo.broker.transport import VENDOR_HOST, VENDOR_PORT, HttpsTransport, default_arm
from safo.broker.vendor import TransportError, TransportTimeout, VendorRequest
from safo.errors import ConfigError, SafoError
from serverdata import call_fields, join_or_fail, split_frames

PID = 31337
UID = os.geteuid()


@pytest.fixture(scope="module")
def key(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return make_key(tmp_path_factory.mktemp("keys") / "a")


# -- the inherited descriptor --------------------------------------------------------------------------------------


@pytest.fixture
def listening(tmp_path: Path) -> Iterator[tuple[int, socket.socket]]:
    """A listening unix socket, and a duplicate of its descriptor at a number other than 3 (what systemd would pass)."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(str(tmp_path / "l.sock"))
    sock.listen(4)
    fd = os.dup(sock.fileno())
    yield fd, sock
    sock.close()


def env_for(**over: str) -> dict[str, str]:
    base = {"LISTEN_PID": str(PID), "LISTEN_FDS": "1", "LISTEN_FDNAMES": "broker"}
    base.update(over)
    return base


def test_the_one_listening_descriptor_is_adopted_and_the_variables_are_removed(
    listening: tuple[int, socket.socket],
) -> None:
    fd, orig = listening
    environ = env_for() | {"OTHER": "kept"}
    os.set_inheritable(fd, True)  # as a descriptor passed by an exec would be
    adopted = adopt_listener(environ, PID, first_fd=fd)
    assert adopted.fileno() == fd and adopted.getsockname() == orig.getsockname()
    assert environ == {"OTHER": "kept"}
    assert os.get_inheritable(fd) is False and adopted.getblocking() is False
    adopted.close()


def refuses(environ: dict[str, str], fd: int, pid: int = PID) -> None:
    with pytest.raises(ListenError):
        adopt_listener(environ, pid, first_fd=fd)
    assert not {"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} & set(environ)  # removed even on refusal


@pytest.mark.parametrize("value", ["0", "2", "01", " 1", "1 ", "+1", "1.0", "-1", "", "one", "1\n", "11"])
def test_any_count_but_exactly_one_is_refused(listening: tuple[int, socket.socket], value: str) -> None:
    refuses(env_for(LISTEN_FDS=value), listening[0])


def test_a_missing_count_is_refused(listening: tuple[int, socket.socket]) -> None:
    environ = env_for()
    del environ["LISTEN_FDS"]
    refuses(environ, listening[0])


@pytest.mark.parametrize("value", [str(PID + 1), str(PID - 1), "0", "", " " + str(PID), "0" + str(PID), "x", "-1"])
def test_a_wrong_pid_is_refused(listening: tuple[int, socket.socket], value: str) -> None:
    refuses(env_for(LISTEN_PID=value), listening[0])


def test_a_missing_pid_is_refused(listening: tuple[int, socket.socket]) -> None:
    environ = env_for()
    del environ["LISTEN_PID"]
    refuses(environ, listening[0])


def test_a_descriptor_that_is_not_a_socket_is_refused() -> None:
    r, w = os.pipe()
    try:
        refuses(env_for(), r)
    finally:
        os.close(w)
        # the pipe's read end stays open if the socket constructor refused it; close what is left
        with contextlib.suppress(OSError):
            os.close(r)


def test_a_descriptor_that_is_not_open_is_refused() -> None:
    fd = os.dup(0)
    os.close(fd)
    refuses(env_for(), fd)


def test_a_connected_or_unbound_socket_is_not_a_listener() -> None:
    a, b = socket.socketpair()
    try:
        refuses(env_for(), os.dup(a.fileno()))
    finally:
        a.close()
        b.close()
    idle = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        refuses(env_for(), os.dup(idle.fileno()))
    finally:
        idle.close()


def test_a_listening_seqpacket_socket_is_not_a_stream_listener(tmp_path: Path) -> None:
    seq = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    seq.bind(str(tmp_path / "q.sock"))
    seq.listen(1)
    try:
        refuses(env_for(), os.dup(seq.fileno()))
    finally:
        seq.close()


def test_a_listening_inet_or_datagram_socket_is_refused() -> None:
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(("127.0.0.1", 0))
    tcp.listen(1)
    dgram = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        refuses(env_for(), os.dup(tcp.fileno()))
        refuses(env_for(), os.dup(dgram.fileno()))
    finally:
        tcp.close()
        dgram.close()


# -- the config ----------------------------------------------------------------------------------------------------


def write_config(path: Path, text: str, mode: int = 0o644) -> Path:
    path.write_text(text)
    path.chmod(mode)
    return path


def test_the_server_section_loads_with_defaults(tmp_path: Path) -> None:
    cfg = load_config(write_config(tmp_path / "b.yaml", "server:\n  allowed_uids: [1000]\n"), UID)
    assert cfg == ServerConfig(allowed_uids=frozenset({1000}))


def test_every_server_key_can_be_set(tmp_path: Path) -> None:
    text = (
        "server:\n  allowed_uids: [5, 6]\n  max_connections: 3\n  max_per_uid: 1\n  read_deadline: 2\n"
        "  max_concurrent_calls: 1\n  begin_per_minute: 4\n  slot_wait: 1.5\n"
    )
    cfg = load_config(write_config(tmp_path / "b.yaml", text), UID)
    assert cfg.allowed_uids == {5, 6} and cfg.max_connections == 3 and cfg.max_per_uid == 1
    assert cfg.read_deadline == 2.0 and cfg.max_concurrent_calls == 1 and cfg.begin_per_minute == 4
    assert cfg.slot_wait == 1.5


@pytest.mark.parametrize(
    "text",
    [
        "server:\n  allowed_uids: []\n",
        "server:\n  allowed_uids: 1000\n",
        "server:\n  allowed_uids: [true]\n",
        "server:\n  allowed_uids: [-1]\n",
        "server:\n  allowed_uids: ['1000']\n",
        "server:\n  allowed_uids: [1.5]\n",
        "server:\n  allowed_uids: [1000]\n  surprise: 1\n",
        "server:\n  max_connections: 8\n",
        "server:\n  allowed_uids: [1]\n  max_connections: 0\n",
        "server:\n  allowed_uids: [1]\n  max_connections: 65\n",
        "server:\n  allowed_uids: [1]\n  max_connections: true\n",
        "server:\n  allowed_uids: [1]\n  max_per_uid: 0\n",
        "server:\n  allowed_uids: [1]\n  read_deadline: 0\n",
        "server:\n  allowed_uids: [1]\n  read_deadline: fast\n",
        "server:\n  allowed_uids: [1]\n  read_deadline: true\n",
        "server:\n  allowed_uids: [1]\n  grace_seconds: -1\n",
        "server:\n  allowed_uids: [1]\n  slot_wait: 61\n",
        "server:\n  allowed_uids: [1]\n  max_calls_per_minute: 0\n",
        "server:\n  allowed_uids: [1]\n  max_concurrent_calls: 9\n",
        "server:\n  allowed_uids: [1]\n  max_concurrent_calls: 3\n",
        "server:\n  allowed_uids: [1]\n  max_concurrent_calls: 2\n",
        "server: []\n",
        "server:\n  allowed_uids: [1]\n  allowed_uids: [2]\n",
        "server: &a\n  allowed_uids: [1]\nother: *a\n",
        "server:\n  <<: {allowed_uids: [1]}\n",
        "other: 1\n",
        "- server\n",
        "",
        "server: {allowed_uids: [1]\n",
        "!!python/object/apply:os.getcwd []\n",
    ],
)
def test_a_bad_config_is_refused(tmp_path: Path, text: str) -> None:
    with pytest.raises(ConfigError):
        load_config(write_config(tmp_path / "b.yaml", text), UID)


def test_a_config_the_wrong_account_owns_or_that_is_writable_is_refused(tmp_path: Path) -> None:
    path = write_config(tmp_path / "b.yaml", "server:\n  allowed_uids: [1]\n")
    with pytest.raises(ConfigError):
        load_config(path, UID + 1)
    path.chmod(0o666)
    with pytest.raises(ConfigError):
        load_config(path, UID)
    with pytest.raises(ConfigError):
        load_config(tmp_path / "absent.yaml", UID)


def test_a_config_that_is_a_link_is_refused(tmp_path: Path) -> None:
    real = write_config(tmp_path / "real.yaml", "server:\n  allowed_uids: [1]\n")
    link = tmp_path / "link.yaml"
    link.symlink_to(real)
    assert read_config(real, UID)
    # read_trust_file resolves the path and then refuses a link at the end: a link to a good file is the same file
    assert read_config(link, UID) == read_config(real, UID)


# -- the epoch -----------------------------------------------------------------------------------------------------


def test_the_epoch_is_made_once_and_read_back(tmp_path: Path) -> None:
    first = runtime.read_epoch(tmp_path)
    assert len(first) == 32 and set(first) <= set("0123456789abcdef")
    assert runtime.read_epoch(tmp_path) == first
    path = tmp_path / "epoch"
    assert path.read_text() == first + "\n" and (path.stat().st_mode & 0o777) == 0o600


@pytest.mark.parametrize(
    "text", ["", "\n", "abc\n", "A" * 32 + "\n", "a" * 32, "a" * 32 + "\n\n", "a" * 33 + "\n", "g" * 32 + "\n"]
)
def test_a_malformed_epoch_file_stops_the_broker_and_is_not_remade(tmp_path: Path, text: str) -> None:
    (tmp_path / "epoch").write_text(text)
    with pytest.raises(LedgerError):
        runtime.read_epoch(tmp_path)
    assert (tmp_path / "epoch").read_text() == text


def test_an_epoch_that_is_a_link_is_not_followed(tmp_path: Path) -> None:
    (tmp_path / "elsewhere").write_text("a" * 32 + "\n")
    (tmp_path / "epoch").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(LedgerError):
        runtime.read_epoch(tmp_path)


# -- the switch ----------------------------------------------------------------------------------------------------


def test_the_switch_is_read_each_time_and_only_the_word_enabled_counts(tmp_path: Path) -> None:
    path = tmp_path / "switch"
    enabled = runtime.switch_reader(path, UID)
    assert enabled() is False  # absent
    write_config(path, "enabled\n")
    assert enabled() is True
    write_config(path, "# note\nenabled\n\n")
    assert enabled() is True
    for text in ["", "disabled\n", "yes\n", "enabled please\n", "ENABLED\n", "enabled\nextra\n", "enabled\ndisabled\n"]:
        write_config(path, text)
        assert enabled() is False, text
    write_config(path, "enabled\n")
    assert enabled() is True
    path.unlink()
    assert enabled() is False


def test_a_switch_the_wrong_account_owns_or_anyone_can_write_is_off(tmp_path: Path) -> None:
    path = write_config(tmp_path / "switch", "enabled\n")
    assert runtime.switch_reader(path, UID + 1)() is False
    path.chmod(0o666)
    assert runtime.switch_reader(path, UID)() is False
    path.chmod(0o664)
    assert runtime.switch_reader(path, UID)() is False


# -- the key -------------------------------------------------------------------------------------------------------

GOOD_KEY = "AIza" + "x" * 30


def test_the_key_is_read_fresh_from_the_credential_directory(tmp_path: Path) -> None:
    read = runtime.key_reader(str(tmp_path))
    (tmp_path / "paid-key").write_text(GOOD_KEY + "\n")
    assert read() == GOOD_KEY
    (tmp_path / "paid-key").write_text("B" * 40)
    assert read() == "B" * 40


@pytest.mark.parametrize(
    "text",
    [
        "",
        "\n",
        "short",
        "has space " + "x" * 30,
        GOOD_KEY + "\n\n",
        GOOD_KEY + " ",
        "x" * 257,
        "café" + "x" * 30,
        "a\nb" + "x" * 30,
    ],
)
def test_a_key_of_the_wrong_shape_is_refused_without_quoting_it(tmp_path: Path, text: str) -> None:
    (tmp_path / "paid-key").write_text(text)
    with pytest.raises(ConfigError) as err:
        runtime.key_reader(str(tmp_path))()
    assert text.strip() not in str(err.value) or not text.strip()


@pytest.mark.parametrize("where", [None, "", "relative/dir"])
def test_a_missing_or_relative_credential_directory_is_refused(where: str | None) -> None:
    with pytest.raises(ConfigError):
        runtime.key_reader(where)()


def test_an_absent_or_linked_key_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        runtime.key_reader(str(tmp_path))()
    (tmp_path / "real").write_text(GOOD_KEY)
    (tmp_path / "paid-key").symlink_to(tmp_path / "real")
    with pytest.raises(ConfigError):
        runtime.key_reader(str(tmp_path))()


def test_key_loaded_is_true_only_for_a_key_of_the_right_shape(tmp_path: Path) -> None:
    loaded = runtime.key_present(runtime.key_reader(str(tmp_path)))
    assert loaded() is False
    (tmp_path / "paid-key").write_text(GOOD_KEY)
    assert loaded() is True
    (tmp_path / "paid-key").write_text("bad key")
    assert loaded() is False


# -- hardening and the environment ---------------------------------------------------------------------------------


def test_the_process_is_made_undumpable_and_core_files_are_off() -> None:
    calls: list[Any] = []
    limits: list[Any] = []

    def prctl(*a: int) -> int:
        calls.append(a)
        return 0

    runtime.harden_process(prctl, lambda which, value: limits.append((which, value)))
    assert calls == [(4, 0, 0, 0, 0)] and limits == [(resource.RLIMIT_CORE, (0, 0))]


def test_a_failed_prctl_stops_the_start() -> None:
    with pytest.raises(OSError):
        runtime.harden_process(lambda *a: -1, lambda *a: None)


def test_harden_really_sets_the_flags_in_a_child_process() -> None:
    import subprocess
    import sys

    code = (
        "import ctypes, resource\n"
        "from safo.broker import runtime\n"
        "runtime.harden_process()\n"
        "print(ctypes.CDLL(None).prctl(3, 0, 0, 0, 0), resource.getrlimit(resource.RLIMIT_CORE))\n"
    )
    done = subprocess.run(  # noqa: S603 - this interpreter with a fixed program, no shell
        [sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True
    )
    assert done.stdout.strip() == "0 (0, 0)"


def test_the_environment_keeps_only_what_systemd_hands_the_service() -> None:
    environ = {
        "LISTEN_PID": "1",
        "LISTEN_FDS": "1",
        "LISTEN_FDNAMES": "x",
        "CREDENTIALS_DIRECTORY": "/c",
        "STATE_DIRECTORY": "/s",
        "HTTPS_PROXY": "http://proxy",
        "http_proxy": "http://proxy",
        "SSL_CERT_FILE": "/evil",
        "PATH": "/x",
    }
    runtime.scrub_environment(environ)
    assert sorted(environ) == ["CREDENTIALS_DIRECTORY", "LISTEN_FDNAMES", "LISTEN_FDS", "LISTEN_PID", "STATE_DIRECTORY"]


# -- the transport -------------------------------------------------------------------------------------------------


class Vendor(http.server.BaseHTTPRequestHandler):
    seen: ClassVar[list[dict[str, Any]]] = []
    reply: ClassVar[tuple[int, dict[str, str], bytes]] = (200, {}, b"{}")
    declared: int | None = None

    def do_POST(self) -> None:
        size = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(size)
        type(self).seen.append({"path": self.path, "headers": dict(self.headers), "body": body})
        status, headers, data = type(self).reply
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("content-length", str(type(self).declared if type(self).declared is not None else len(data)))
        self.end_headers()
        self.wfile.write(data)
        self.wfile.flush()

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture
def vendor() -> Iterator[tuple[int, type[Vendor]]]:
    Vendor.seen = []
    Vendor.reply = (200, {}, b"{}")
    Vendor.declared = None
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Vendor)
    thread = threading.Thread(target=httpd.serve_forever)
    thread.start()
    yield httpd.server_address[1], Vendor
    httpd.shutdown()
    join_or_fail(thread)
    httpd.server_close()


def req(path: str = "/v1/x", body: bytes = b'{"a":1}', cap: int = 1000) -> VendorRequest:
    return VendorRequest("flat-test", "text", path, body, cap, 5.0)


def loopback(port: int, key: str = GOOD_KEY, calls: list[int] | None = None) -> HttpsTransport:
    def read() -> str:
        if calls is not None:
            calls.append(1)
        return key

    return HttpsTransport(read, host="127.0.0.1", port=port, factory=http.client.HTTPConnection)


def test_one_post_with_the_key_in_the_header_only(vendor: tuple[int, type[Vendor]]) -> None:
    port, handler = vendor
    handler.reply = (200, {"Retry-After": "7"}, b'{"ok":1}')
    calls: list[int] = []
    got = loopback(port, calls=calls).send(req())
    assert (got.status, got.body) == (200, b'{"ok":1}') and got.headers["retry-after"] == "7"
    (seen,) = handler.seen
    assert seen["path"] == "/v1/x" and seen["body"] == b'{"a":1}'
    assert seen["headers"]["x-goog-api-key"] == GOOD_KEY and seen["headers"]["content-type"] == "application/json"
    assert GOOD_KEY.encode() not in seen["body"] and GOOD_KEY not in seen["path"]
    loopback(port, calls=calls).send(req())
    assert len(calls) == 2  # the key is read for every request


def test_a_redirect_is_returned_not_followed(vendor: tuple[int, type[Vendor]]) -> None:
    port, handler = vendor
    handler.reply = (302, {"Location": "http://127.0.0.1:1/elsewhere"}, b"")
    assert loopback(port).send(req()).status == 302
    assert len(handler.seen) == 1


def test_a_reply_is_read_only_up_to_the_cap_plus_one(vendor: tuple[int, type[Vendor]]) -> None:
    port, handler = vendor
    handler.reply = (200, {}, b"x" * 5000)
    assert len(loopback(port).send(req(cap=100)).body) == 101


def test_a_short_body_is_handed_on_with_its_declared_length(vendor: tuple[int, type[Vendor]]) -> None:
    port, handler = vendor
    handler.reply = (200, {}, b"x" * 10)
    handler.declared = 50
    got = loopback(port).send(req())  # handed on as it is: the pipeline compares Content-Length with the body
    assert got.body == b"x" * 10 and got.headers["content-length"] == "50"


def test_a_refused_connection_is_a_transport_error_that_does_not_quote_the_key() -> None:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    with pytest.raises(TransportError) as err:
        loopback(port, key="SENTINELKEY" + "x" * 30).send(req())
    assert "SENTINEL" not in str(err.value) and err.value.__cause__ is None and err.value.__suppress_context__


def test_a_timeout_is_its_own_error() -> None:
    class Slow:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def request(self, *args: Any, **kwargs: Any) -> None:
            raise TimeoutError

        def close(self) -> None:
            pass

    with pytest.raises(TransportTimeout):
        HttpsTransport(lambda: GOOD_KEY, factory=Slow).send(req())  # type: ignore[arg-type]  # a stand-in connection


def test_the_connection_gets_the_request_deadline_and_is_always_closed() -> None:
    log: list[Any] = []

    class Conn:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            log.append((host, port, timeout))

        def request(self, *args: Any, **kwargs: Any) -> None:
            raise OSError("reset")

        def close(self) -> None:
            log.append("closed")

    with pytest.raises(TransportError):
        HttpsTransport(lambda: GOOD_KEY, factory=Conn).send(req())  # type: ignore[arg-type]  # a stand-in connection
    assert log == [(VENDOR_HOST, VENDOR_PORT, 5.0), "closed"]


class Dribble:
    """A connection whose answer outlasts the whole-call deadline: `getresponse` or the body read fires the watchdog."""

    def __init__(self, fire_in: str) -> None:
        self.fire_in = fire_in
        self.fire: Any = None
        self.shutdowns: list[int] = []
        self.closed = False
        outer = self

        class Sock:
            def shutdown(self, how: int) -> None:
                outer.shutdowns.append(how)

        self.sock = Sock()

    def request(self, *args: Any, **kwargs: Any) -> None:
        pass

    def getresponse(self) -> Any:
        outer = self
        if self.fire_in == "headers":
            self.fire()
            raise OSError("shut down")

        class Reply:
            status = 200

            def getheaders(self) -> list[tuple[str, str]]:
                return []

            def read(self, count: int) -> bytes:
                outer.fire()  # the deadline passes while the body trickles in
                return b"part"

        return Reply()

    def close(self) -> None:
        self.closed = True


class Arm:
    def __init__(self) -> None:
        self.seconds: list[float] = []
        self.cancelled = 0
        self.fire: Any = None

    def __call__(self, seconds: float, fire: Any) -> Any:
        self.seconds.append(seconds)
        self.fire = fire
        outer = self

        class Handle:
            def cancel(self) -> None:
                outer.cancelled += 1

        return Handle()


@pytest.mark.parametrize("where", ["headers", "body"])
def test_the_whole_call_has_one_deadline_that_shuts_the_connection_down(where: str) -> None:
    arm = Arm()
    conn = Dribble(where)

    def factory(*args: Any, **kwargs: Any) -> Any:
        conn.fire = arm.fire
        return conn

    def arm_and_link(seconds: float, fire: Any) -> Any:
        handle = arm(seconds, fire)
        conn.fire = fire
        return handle

    transport = HttpsTransport(lambda: GOOD_KEY, factory=factory, arm=arm_and_link)
    with pytest.raises(TransportTimeout):
        transport.send(req())
    assert arm.seconds == [5.0] and arm.cancelled == 1 and conn.closed
    assert conn.shutdowns == [socket.SHUT_RDWR]


def test_the_deadline_watchdog_is_cancelled_after_a_good_answer(vendor: tuple[int, type[Vendor]]) -> None:
    port, handler = vendor
    handler.reply = (200, {}, b"{}")
    arm = Arm()
    transport = HttpsTransport(
        lambda: GOOD_KEY, host="127.0.0.1", port=port, factory=http.client.HTTPConnection, arm=arm
    )
    assert transport.send(req()).status == 200
    assert arm.seconds == [5.0] and arm.cancelled == 1


def test_the_default_watchdog_fires_once_and_can_be_cancelled() -> None:
    fired = threading.Event()
    default_arm(0.01, fired.set)
    assert fired.wait(30)
    quiet = default_arm(3600, fired.clear)
    quiet.cancel()
    assert fired.is_set()


def test_the_destination_is_fixed_and_the_real_connection_refuses_loopback(vendor: tuple[int, type[Vendor]]) -> None:
    assert (VENDOR_HOST, VENDOR_PORT) == ("generativelanguage.googleapis.com", 443)
    port, handler = vendor
    with pytest.raises(TransportError):  # the default factory is the checked, pinned connection
        HttpsTransport(lambda: GOOD_KEY, host="127.0.0.1", port=port).send(req())
    assert handler.seen == []


# -- the entry point, end to end -----------------------------------------------------------------------------------


class Tree:
    """A complete root-owned tree (as this user), a state directory, a credential directory and a listening socket."""

    def __init__(self, tmp: Path, key: Path) -> None:
        self.tmp = tmp
        self.signers = write_config(tmp / "signers", signers_line(LABEL, key.with_suffix(".pub")) + "\n")
        self.revoked = write_config(tmp / "revoked", "")
        self.switch = write_config(tmp / "switch", "enabled\n")
        self.state = tmp / "state"
        self.creds = tmp / "creds"
        self.creds.mkdir()
        (self.creds / "paid-key").write_text(GOOD_KEY + "\n")
        self.config = write_config(tmp / "broker.yaml", self.config_text())
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(str(tmp / "l.sock"))
        self.sock.listen(8)
        self.fd = os.dup(self.sock.fileno())

    def config_text(self, **over: Any) -> str:
        data: dict[str, Any] = {
            "server": {"allowed_uids": [UID], "grace_seconds": 5},
            "prices": prices_data(),
            "caps": {"job_usd": "2.5", "month_usd": "10"},
            "deadline_seconds": 30,
        }
        data.update(over)
        return yaml.safe_dump({k: v for k, v in data.items() if v is not None})

    def environ(self, **over: str) -> dict[str, str]:
        base = {
            "LISTEN_PID": str(PID),
            "LISTEN_FDS": "1",
            "STATE_DIRECTORY": str(self.state),
            "CREDENTIALS_DIRECTORY": str(self.creds),
            "HTTPS_PROXY": "http://proxy",
        }
        base.update(over)
        return base

    def run(self, environ: dict[str, str], transport: Any = None, **kw: Any) -> int:
        return entry.run(
            environ,
            pid=PID,
            config=self.config,
            signers=self.signers,
            revoked=self.revoked,
            switch=self.switch,
            trust_uid=UID,
            require_hardware=False,
            verifier=as_hardware,
            first_fd=self.fd,
            transport=transport,
            handle_signals=False,
            **kw,
        )

    def connect(self) -> socket.socket:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(60)
        client.connect(str(self.tmp / "l.sock"))
        return client


@pytest.fixture
def tree(tmp_path: Path, key: Path) -> Iterator[Tree]:
    t = Tree(tmp_path, key)
    yield t
    t.sock.close()


def ask(tree: Tree, body: bytes) -> list[bytes]:
    client = tree.connect()
    client.sendall(protocol.frame(body, protocol.MAX_REQUEST_FRAME))
    client.shutdown(socket.SHUT_WR)
    data = b""
    while chunk := client.recv(1 << 20):
        data += chunk
    client.close()
    return split_frames(data)


def serve_in_thread(tree: Tree, environ: dict[str, str], transport: Any = None) -> tuple[threading.Thread, list[Any]]:
    ready = threading.Event()
    box: list[Any] = []

    def go() -> None:
        try:

            def on_ready(server: Server) -> None:
                box.append(server)
                ready.set()

            box.append(tree.run(environ, transport, on_ready=on_ready))
        except BaseException as exc:
            box.append(exc)
            ready.set()

    thread = threading.Thread(target=go)
    thread.start()
    assert ready.wait(30)
    return thread, box


def test_the_service_starts_serves_a_status_and_stops_clean(tree: Tree) -> None:
    environ = tree.environ()
    thread, box = serve_in_thread(tree, environ)
    server = box[0]
    assert isinstance(server, Server)
    (frame,) = ask(tree, protocol.request_body("status"))
    data = json.loads(frame)
    assert data["ok"] and data["enabled"] is True and data["key_loaded"] is True
    assert data["epoch"] == (tree.state / "epoch").read_text().strip() and "month_cap" in data
    assert sorted(environ) == ["CREDENTIALS_DIRECTORY", "STATE_DIRECTORY"]  # scrubbed; LISTEN_* consumed
    server.stop()
    join_or_fail(thread)
    assert box[1] == 0


def test_the_switch_file_is_read_per_request_by_the_running_service(tree: Tree) -> None:
    thread, box = serve_in_thread(tree, tree.environ())
    begin = protocol.request_body(
        "begin", model="flat-test", job="j", kind="text", max_output_tokens=5, prompt_bytes=5, max_usd="2"
    )
    assert json.loads(ask(tree, begin)[0])["ok"] is True
    write_config(tree.switch, "off\n")
    assert json.loads(ask(tree, begin)[0])["code"] == "disabled"
    assert json.loads(ask(tree, protocol.request_body("status"))[0])["enabled"] is False
    write_config(tree.switch, "enabled\n")
    assert json.loads(ask(tree, begin)[0])["ok"] is True
    box[0].stop()
    join_or_fail(thread)


def begin_for(tree: Tree, req: Any) -> dict[str, Any]:
    body = protocol.request_body(
        "begin",
        model=req.model,
        job=req.job,
        kind="text",
        max_output_tokens=500,
        prompt_bytes=len(req.prompt),
        max_usd="2.5",
    )
    data: dict[str, Any] = json.loads(ask(tree, body)[0])
    return data


def call_body(key: Path, req: Any, begin: dict[str, Any]) -> bytes:
    """The signed `call` request for an offer the running service made (the wall clock here is the real one)."""
    now = dt.datetime.now(dt.UTC)
    signed = geminisign.canonical(
        {
            "version": 3,
            "nonce": begin["nonce"],
            "epoch": begin["epoch"],
            "model": req.model,
            "kind": "text",
            "max_output_tokens": req.max_output_tokens,
            "thinking_level": "none",
            "max_usd": "2.5",
            "job": req.job,
            "prompt_sha256": gemini.prompt_binding(req.prompt)[0],
            "prompt_bytes": len(req.prompt),
            "quote": "go ahead",
            "quoted_at": gemini.stamp(now - dt.timedelta(minutes=1)),
            "created": gemini.stamp(now),
            "expires_at": gemini.stamp(now + dt.timedelta(minutes=9)),
            "beyond_ceiling": begin["beyond_ceiling"],
            "ledger_head": begin["ledger_head"],
            "issue": "ChiefGyk3D/scrum-around-and-find-out#259",
            "principal": LABEL,
        }
    )
    signature = geminisign.sign(str(key), signed.encode(), geminisign.NAMESPACE, {})
    return protocol.request_body("call", **call_fields(req, signed, signature))


def test_a_whole_paid_call_through_the_entry_point_with_the_fake_vendor(tree: Tree, key: Path) -> None:
    vendor = FakeVendor()
    thread, box = serve_in_thread(tree, tree.environ(), vendor)
    req = text_req()
    reply = json.loads(ask(tree, call_body(key, req, begin_for(tree, req)))[0])
    box[0].stop()
    join_or_fail(thread)
    assert reply["ok"] is True, reply
    assert reply["text"] == "a short answer" and len(vendor.requests) == 1


def test_the_start_recovers_an_interrupted_call_and_empties_the_issued_table(tree: Tree, key: Path) -> None:
    rig = Rig(tree.tmp, key)  # its state directory is the one the service will use
    rig.offer(text_req())
    rig.pipeline.faults = CrashAt("after_reserve")
    with pytest.raises(Crash):
        rig.run(text_req(job="job-two"))
    assert list((tree.state / "issued").iterdir())
    thread, box = serve_in_thread(tree, tree.environ())
    view = box[0].pipeline.ledger.view()
    (call,) = view.calls.values()
    assert call.ambiguous and view.suspended and not list((tree.state / "issued").iterdir())
    box[0].stop()
    join_or_fail(thread)


def test_a_stop_with_a_call_still_in_flight_exits_failed(tree: Tree, key: Path) -> None:
    release = threading.Event()
    entered = threading.Event()

    class Hung(FakeVendor):
        def send(self, request: VendorRequest) -> Any:
            entered.set()
            release.wait(30)
            return super().send(request)

    vendor = Hung()
    config = yaml.safe_load(tree.config.read_text())
    config["server"]["grace_seconds"] = 0
    write_config(tree.config, yaml.safe_dump(config))
    thread, box = serve_in_thread(tree, tree.environ(), vendor)
    req = text_req()
    body = call_body(key, req, begin_for(tree, req))
    client = tree.connect()
    client.sendall(protocol.frame(body, protocol.MAX_REQUEST_FRAME))
    assert entered.wait(30)
    box[0].stop()
    join_or_fail(thread)
    release.set()
    client.close()
    assert box[1] == entry.EXIT_FAILED
    (call,) = box[0].pipeline.ledger.view().calls.values()
    assert call.ambiguous and call.unresolved


@pytest.mark.parametrize(
    "mutate",
    [
        lambda t, e: e.update(LISTEN_PID="1"),
        lambda t, e: e.update(LISTEN_FDS="2"),
        lambda t, e: e.pop("STATE_DIRECTORY"),
        lambda t, e: e.update(STATE_DIRECTORY="relative"),
        lambda t, e: write_config(t.config, t.config_text(extra=1)),
        lambda t, e: write_config(t.config, t.config_text(server=None)),
        lambda t, e: write_config(t.config, t.config_text(prices=None)),
        lambda t, e: write_config(t.config, t.config_text(caps={"job_usd": "2.5", "x": 1})),
        lambda t, e: write_config(t.config, t.config_text(caps={"job_usd": "9"})),
        lambda t, e: write_config(t.config, t.config_text(deadline_seconds=0)),
        lambda t, e: write_config(t.config, t.config_text(deadline_seconds=601)),
        lambda t, e: write_config(t.config, t.config_text(deadline_seconds="30")),
        lambda t, e: write_config(t.config, t.config_text(prices={"models": {}})),
        lambda t, e: t.config.chmod(0o666),
        lambda t, e: (t.tmp / "state").mkdir(mode=0o755),
    ],
)
def test_a_setup_problem_stops_the_service_before_it_serves(tree: Tree, mutate: Any) -> None:
    environ = tree.environ()
    mutate(tree, environ)
    served: list[Server] = []
    with pytest.raises((ListenError, ConfigError, OSError, LedgerError, SafoError)):
        tree.run(environ, FakeVendor(), on_ready=served.append)
    assert served == []


def test_main_exits_failed_and_names_only_the_exception_class(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(runtime, "harden_process", lambda: None)
    monkeypatch.setattr(
        os, "environ", {"LISTEN_PID": "1", "LISTEN_FDS": "1", "STATE_DIRECTORY": "/nonexistent-SENTINEL"}
    )
    assert entry.main() == 4
    err = capsys.readouterr().err
    assert "ListenError" in err and "SENTINEL" not in err and err[-1] == "\n" and err.count("\n") == 1


def test_main_hardens_first_and_a_failed_hardening_is_a_failed_start(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def refuse() -> None:
        raise OSError("no")

    monkeypatch.setattr(runtime, "harden_process", refuse)
    assert entry.main() == 4 and "OSError" in capsys.readouterr().err
