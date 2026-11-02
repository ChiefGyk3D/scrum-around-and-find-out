# SPDX-License-Identifier: Apache-2.0
"""One deadline for resolve plus every connect attempt (#289 B2). A resolver returns several addresses that hang or
refuse; the clock is injected and `socket.create_connection` is a fake that advances it. Nothing here waits on real
time and no address is contacted."""

from __future__ import annotations

import http.client
import socket
from collections.abc import Callable
from typing import Any

import pytest

from safo import netguard
from safo.broker.transport import HttpsTransport
from safo.broker.vendor import TransportTimeout, VendorRequest

ADDRS = ["203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"]


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class FakeSock:
    def __init__(self) -> None:
        self.closed = False
        self.sent: list[bytes] = []
        self.on_setup: Callable[[], None] | None = None

    def setsockopt(self, *args: Any) -> None:
        if self.on_setup:
            self.on_setup()

    def close(self) -> None:
        self.closed = True

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def shutdown(self, how: int) -> None:
        pass


class Net:
    """The fake network: each address hangs (burns its whole timeout), refuses (instantly) or answers."""

    def __init__(self, clock: Clock, plan: dict[str, str]) -> None:
        self.clock = clock
        self.plan = plan
        self.attempts: list[tuple[str, float | None]] = []
        self.socks: list[FakeSock] = []
        self.on_attempt: Callable[[str], None] | None = None
        self.resolve_cost = 0.0
        self.on_setup: Callable[[], None] | None = None  # runs in the connection set-up after the TCP connect

    def resolve(self, host: str, port: int, **kw: Any) -> list[Any]:
        self.clock.now += self.resolve_cost
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in self.plan]

    def connect(self, address: Any, timeout: Any = None, source_address: Any = None) -> FakeSock:
        ip = address[0]
        self.attempts.append((ip, timeout))
        if self.on_attempt:
            self.on_attempt(ip)
        what = self.plan[ip]
        if what == "hang":
            assert timeout is not None, "an attempt with no timeout could hang forever"
            self.clock.now += timeout
            raise TimeoutError("timed out")
        if what == "slow":  # connects, but only after burning the whole timeout
            assert timeout is not None
            self.clock.now += timeout
        elif what == "refuse":
            raise ConnectionRefusedError("refused")
        sock = FakeSock()
        sock.on_setup = self.on_setup
        self.socks.append(sock)
        return sock


@pytest.fixture
def clock() -> Clock:
    return Clock()


def net(monkeypatch: pytest.MonkeyPatch, clock: Clock, plan: dict[str, str]) -> Net:
    fake = Net(clock, plan)
    monkeypatch.setattr(netguard, "resolver", fake.resolve)
    monkeypatch.setattr(socket, "create_connection", fake.connect)
    return fake


def hang(n: int) -> dict[str, str]:
    return {ip: "hang" for ip in ADDRS[:n]}


# -- connect_pinned ---------------------------------------------------------------------------------------------


def test_each_attempt_gets_the_time_that_is_left_never_more_than_its_own_timeout(
    monkeypatch: pytest.MonkeyPatch, clock: Clock
) -> None:
    fake = net(monkeypatch, clock, hang(3))
    with pytest.raises(TimeoutError):
        netguard.connect_pinned(("example.test", 443), 10.0, deadline=clock() + 25.0, clock=clock)
    assert [t for _, t in fake.attempts] == [10.0, 10.0, 5.0]
    assert clock() - 1000.0 <= 25.0


def test_addresses_after_the_deadline_are_not_tried(monkeypatch: pytest.MonkeyPatch, clock: Clock) -> None:
    fake = net(monkeypatch, clock, hang(4))
    with pytest.raises(TimeoutError, match="deadline"):
        netguard.connect_pinned(("example.test", 443), 10.0, deadline=clock() + 20.0, clock=clock)
    assert [ip for ip, _ in fake.attempts] == ADDRS[:2]  # the third and fourth were never contacted
    assert clock() == 1020.0


def test_a_refusal_moves_on_without_spending_time_and_a_later_address_answers(
    monkeypatch: pytest.MonkeyPatch, clock: Clock
) -> None:
    fake = net(monkeypatch, clock, {ADDRS[0]: "refuse", ADDRS[1]: "hang", ADDRS[2]: "ok"})
    sock = netguard.connect_pinned(("example.test", 443), 10.0, deadline=clock() + 25.0, clock=clock)
    assert [id(s) for s in fake.socks] == [id(sock)]
    assert [t for _, t in fake.attempts] == [10.0, 10.0, 10.0]


def test_all_refused_raises_the_last_refusal_not_a_timeout(monkeypatch: pytest.MonkeyPatch, clock: Clock) -> None:
    net(monkeypatch, clock, {ip: "refuse" for ip in ADDRS[:3]})
    with pytest.raises(ConnectionRefusedError):
        netguard.connect_pinned(("example.test", 443), 10.0, deadline=clock() + 25.0, clock=clock)


def test_the_resolver_time_comes_out_of_the_same_deadline(monkeypatch: pytest.MonkeyPatch, clock: Clock) -> None:
    fake = net(monkeypatch, clock, hang(3))
    fake.resolve_cost = 21.0
    with pytest.raises(TimeoutError):
        netguard.connect_pinned(("example.test", 443), 10.0, deadline=clock() + 25.0, clock=clock)
    assert [t for _, t in fake.attempts] == [4.0]  # only what the lookup left


def test_a_lookup_that_uses_the_whole_deadline_leaves_no_attempt(monkeypatch: pytest.MonkeyPatch, clock: Clock) -> None:
    fake = net(monkeypatch, clock, hang(2))
    fake.resolve_cost = 25.0
    with pytest.raises(TimeoutError, match="deadline"):
        netguard.connect_pinned(("example.test", 443), 10.0, deadline=clock() + 25.0, clock=clock)
    assert fake.attempts == []


def test_a_deadline_that_is_exactly_now_allows_no_attempt(monkeypatch: pytest.MonkeyPatch, clock: Clock) -> None:
    fake = net(monkeypatch, clock, hang(1))
    with pytest.raises(TimeoutError):
        netguard.connect_pinned(("example.test", 443), 10.0, deadline=clock(), clock=clock)
    assert fake.attempts == []


def test_a_clock_that_goes_backward_does_not_lengthen_an_attempt(monkeypatch: pytest.MonkeyPatch, clock: Clock) -> None:
    fake = net(monkeypatch, clock, hang(2))
    fake.on_attempt = lambda ip: setattr(clock, "now", clock.now - 100.0) if ip == ADDRS[0] else None
    with pytest.raises(TimeoutError):
        netguard.connect_pinned(("example.test", 443), 10.0, deadline=clock() + 25.0, clock=clock)
    assert all(t is not None and t <= 10.0 for _, t in fake.attempts)


def test_no_timeout_given_the_remaining_time_is_the_attempt_timeout(
    monkeypatch: pytest.MonkeyPatch, clock: Clock
) -> None:
    fake = net(monkeypatch, clock, hang(2))
    with pytest.raises(TimeoutError):
        netguard.connect_pinned(("example.test", 443), None, deadline=clock() + 12.0, clock=clock)
    assert [t for _, t in fake.attempts] == [12.0]


def test_an_address_that_connects_after_the_deadline_is_closed_and_refused(
    monkeypatch: pytest.MonkeyPatch, clock: Clock
) -> None:
    fake = net(monkeypatch, clock, {ADDRS[0]: "slow"})
    with pytest.raises(TimeoutError, match="deadline"):
        netguard.connect_pinned(("example.test", 443), 10.0, deadline=clock() + 10.0, clock=clock)
    assert fake.socks[0].closed


def test_an_expired_flag_stops_the_failover(monkeypatch: pytest.MonkeyPatch, clock: Clock) -> None:
    fake = net(monkeypatch, clock, hang(3))
    fired: list[int] = []
    fake.on_attempt = lambda ip: fired.append(1)
    with pytest.raises(TimeoutError):
        netguard.connect_pinned(
            ("example.test", 443), 10.0, deadline=clock() + 1000.0, clock=clock, expired=lambda: bool(fired)
        )
    assert [ip for ip, _ in fake.attempts] == [ADDRS[0]]


def test_without_a_deadline_the_behavior_is_what_it_was(monkeypatch: pytest.MonkeyPatch, clock: Clock) -> None:
    fake = net(monkeypatch, clock, {ADDRS[0]: "hang", ADDRS[1]: "ok"})
    sock = netguard.connect_pinned(("example.test", 443), 10.0)
    assert [id(s) for s in fake.socks] == [id(sock)] and [t for _, t in fake.attempts] == [10.0, 10.0]


def test_a_blocked_answer_still_refuses_the_whole_name(monkeypatch: pytest.MonkeyPatch, clock: Clock) -> None:
    fake = net(monkeypatch, clock, {ADDRS[0]: "ok", "169.254.169.254": "ok"})
    with pytest.raises(netguard.BlockedDestinationError):
        netguard.connect_pinned(("example.test", 443), 10.0, deadline=clock() + 25.0, clock=clock)
    assert fake.attempts == []


# -- the connection classes and the transport -------------------------------------------------------------------


def request(timeout: float = 25.0) -> VendorRequest:
    return VendorRequest("flat-test", "text", "/v1/x", b"{}", 1000, timeout)


class Arm:
    """The injected watchdog: it only records; a test fires it by hand."""

    def __init__(self) -> None:
        self.fire: Callable[[], None] | None = None
        self.seconds: float | None = None
        self.cancelled = False

    def __call__(self, seconds: float, fire: Callable[[], None]) -> Arm:
        self.seconds, self.fire = seconds, fire
        return self

    def cancel(self) -> None:
        self.cancelled = True


def transport(clock: Clock, arm: Arm) -> HttpsTransport:
    return HttpsTransport(
        lambda: "k",
        host="example.test",
        port=443,
        factory=netguard.PinnedHTTPConnection,
        arm=arm,
        mono=clock,
    )


def test_the_transport_passes_one_deadline_down_so_failover_cannot_outlast_the_call(
    monkeypatch: pytest.MonkeyPatch, clock: Clock
) -> None:
    fake = net(monkeypatch, clock, hang(4))
    arm = Arm()
    with pytest.raises(TransportTimeout):
        transport(clock, arm).send(request(25.0))
    assert [t for _, t in fake.attempts] == [25.0]  # the first attempt may use the whole call; nothing is left after
    assert clock() - 1000.0 <= 25.0 and fake.socks == [] and arm.cancelled


def test_the_transport_with_a_shorter_connect_timeout_still_stops_at_the_call_deadline(
    monkeypatch: pytest.MonkeyPatch, clock: Clock
) -> None:
    fake = net(monkeypatch, clock, hang(4))

    def factory(host: str, port: int, timeout: float) -> Any:
        return netguard.PinnedHTTPConnection(host, port, timeout=10.0)

    t = HttpsTransport(lambda: "k", host="example.test", port=443, factory=factory, arm=Arm(), mono=clock)
    with pytest.raises(TransportTimeout):
        t.send(request(25.0))
    assert [t_ for _, t_ in fake.attempts] == [10.0, 10.0, 5.0]
    assert clock() - 1000.0 <= 25.0


def test_a_watchdog_that_fires_during_a_hanging_first_address_stops_the_request_leaving_on_the_second(
    monkeypatch: pytest.MonkeyPatch, clock: Clock
) -> None:
    fake = net(monkeypatch, clock, {ADDRS[0]: "hang", ADDRS[1]: "ok"})
    arm = Arm()

    def fire_the_watchdog(ip: str) -> None:
        if ip == ADDRS[0]:
            assert arm.fire is not None
            arm.fire()  # the whole-call deadline passes while the first address hangs (sock is still None)

    fake.on_attempt = fire_the_watchdog
    with pytest.raises(TransportTimeout):
        transport(clock, arm).send(request(25.0))
    assert [ip for ip, _ in fake.attempts] == [ADDRS[0]]
    assert all(s.sent == [] for s in fake.socks)


def test_a_connection_made_after_the_deadline_is_closed_and_nothing_is_sent(
    monkeypatch: pytest.MonkeyPatch, clock: Clock
) -> None:
    fake = net(monkeypatch, clock, {ADDRS[0]: "ok"})
    arm = Arm()

    def late_connect(ip: str) -> None:
        clock.now += 26.0  # the connect itself returns after the deadline

    fake.on_attempt = late_connect
    with pytest.raises(TransportTimeout):
        transport(clock, arm).send(request(25.0))
    assert fake.socks and fake.socks[0].closed and fake.socks[0].sent == []


def test_a_watchdog_that_fires_after_a_good_connect_but_before_the_send_stops_the_send(
    monkeypatch: pytest.MonkeyPatch, clock: Clock
) -> None:
    fake = net(monkeypatch, clock, {ADDRS[0]: "ok"})
    arm = Arm()

    def fire_after(ip: str) -> None:
        assert arm.fire is not None
        arm.fire()

    fake.on_attempt = fire_after
    with pytest.raises(TransportTimeout):
        transport(clock, arm).send(request(25.0))
    assert fake.socks[0].sent == [] and fake.socks[0].closed


def test_the_watchdog_is_armed_for_the_call_deadline(monkeypatch: pytest.MonkeyPatch, clock: Clock) -> None:
    net(monkeypatch, clock, hang(1))
    arm = Arm()
    with pytest.raises(TransportTimeout):
        transport(clock, arm).send(request(25.0))
    assert arm.seconds == 25.0


def test_time_spent_in_the_set_up_after_the_tcp_connect_is_checked_before_the_send(
    monkeypatch: pytest.MonkeyPatch, clock: Clock
) -> None:
    fake = net(monkeypatch, clock, {ADDRS[0]: "ok"})
    fake.on_setup = lambda: setattr(clock, "now", clock.now + 26.0)  # stands in for a slow TLS handshake
    with pytest.raises(TransportTimeout):
        transport(clock, Arm()).send(request(25.0))
    assert fake.socks[0].closed and fake.socks[0].sent == []


def test_a_flag_raised_during_the_set_up_after_the_tcp_connect_also_stops_the_send(
    monkeypatch: pytest.MonkeyPatch, clock: Clock
) -> None:
    fake = net(monkeypatch, clock, {ADDRS[0]: "ok"})
    arm = Arm()
    fake.on_setup = lambda: arm.fire() if arm.fire else None  # the watchdog fires; the clock itself has not moved
    with pytest.raises(TransportTimeout):
        transport(clock, arm).send(request(25.0))
    assert fake.socks[0].closed and fake.socks[0].sent == []


def test_the_tls_connection_checks_the_deadline_after_its_handshake_too(
    monkeypatch: pytest.MonkeyPatch, clock: Clock
) -> None:
    closed: list[int] = []

    def slow_handshake(self: Any) -> None:  # stands in for connect + TLS wrap in the standard class
        clock.now += 26.0

    monkeypatch.setattr(http.client.HTTPSConnection, "connect", slow_handshake)
    monkeypatch.setattr(netguard.PinnedHTTPSConnection, "close", lambda self: closed.append(1))
    conn = netguard.PinnedHTTPSConnection("example.test", 443, timeout=25.0)
    conn.bind_deadline(clock() + 25.0, clock)
    with pytest.raises(TimeoutError):
        conn.connect()
    assert closed == [1]
    flagged = netguard.PinnedHTTPSConnection("example.test", 443, timeout=25.0)
    flagged.bind_deadline(clock() + 25.0, clock, lambda: True)
    monkeypatch.setattr(http.client.HTTPSConnection, "connect", lambda self: None)
    with pytest.raises(TimeoutError):
        flagged.connect()
    unbound = netguard.PinnedHTTPSConnection("example.test", 443, timeout=25.0)
    unbound.connect()  # no deadline bound: nothing to check
