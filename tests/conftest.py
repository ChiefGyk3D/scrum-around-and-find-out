# SPDX-License-Identifier: MIT
"""Shared fixtures and one guard that applies to every test: nothing leaves this machine.

Sockets to anywhere but loopback raise, naming the host. There is no opt-out fixture on
purpose: the fake GraphQL server in tests/fakegh answers on 127.0.0.1.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from fakegh import FakeGitHub
from safo.graphql import Client

_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex
_real_create_connection = socket.create_connection
_real_getaddrinfo = socket.getaddrinfo
_real_gethostbyname = socket.gethostbyname
_real_gethostbyname_ex = socket.gethostbyname_ex
_real_getnameinfo = socket.getnameinfo
_real_sendto = socket.socket.sendto
_real_sendmsg = socket.socket.sendmsg


class NetworkAccessDenied(RuntimeError):
    """A test tried to reach a host outside this machine."""


def is_local(host: object) -> bool:
    if host in (None, "", "localhost"):
        return True
    if not isinstance(host, str):
        return False
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False  # resolving a name to decide would be the call we are preventing
    return address.is_loopback or address.is_unspecified


def refuse(where: str, host: object) -> NetworkAccessDenied:
    return NetworkAccessDenied(f"{where}: a test tried to reach {host!r}; only loopback is allowed (tests/conftest.py)")


@pytest.fixture(autouse=True)
def _loopback_only(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    def getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        if not is_local(host):
            raise refuse("getaddrinfo", host)
        return _real_getaddrinfo(host, *args, **kwargs)

    def gethostbyname(host: Any) -> Any:
        if not is_local(host):
            raise refuse("gethostbyname", host)
        return _real_gethostbyname(host)

    def gethostbyname_ex(host: Any) -> Any:
        if not is_local(host):
            raise refuse("gethostbyname_ex", host)
        return _real_gethostbyname_ex(host)

    def getnameinfo(address: Any, *args: Any, **kwargs: Any) -> Any:
        host = address[0] if isinstance(address, tuple) else address
        if not is_local(host):
            raise refuse("getnameinfo", host)
        return _real_getnameinfo(address, *args, **kwargs)

    def create_connection(address: Any, *args: Any, **kwargs: Any) -> Any:
        host = address[0] if isinstance(address, tuple) else address
        if not is_local(host):
            raise refuse("create_connection", host)
        return _real_create_connection(address, *args, **kwargs)

    def connect(self: socket.socket, address: Any) -> Any:
        host = address[0] if isinstance(address, tuple) else address
        if self.family != socket.AF_UNIX and not is_local(host):
            raise refuse("socket.connect", host)
        return _real_connect(self, address)

    def connect_ex(self: socket.socket, address: Any) -> Any:
        host = address[0] if isinstance(address, tuple) else address
        if self.family != socket.AF_UNIX and not is_local(host):
            raise refuse("socket.connect_ex", host)
        return _real_connect_ex(self, address)

    def sendto(self: socket.socket, data: Any, *args: Any, **kwargs: Any) -> Any:
        # sendto has two forms:
        # 2-arg: sendto(data, address) -> args = (address,)
        # 3-arg: sendto(data, flags, address) -> args = (flags, address)
        # In both cases, the address is args[-1]
        if args and isinstance(args[-1], tuple):
            host = args[-1][0]
            if self.family != socket.AF_UNIX and not is_local(host):
                raise refuse("socket.sendto", host)
        return _real_sendto(self, data, *args, **kwargs)

    def sendmsg(self: socket.socket, buffers: Any, ancdata: Any = None, flags: Any = 0, address: Any = None) -> Any:
        if address is not None and isinstance(address, tuple):
            host = address[0]
            if self.family != socket.AF_UNIX and not is_local(host):
                raise refuse("socket.sendmsg", host)
        return _real_sendmsg(self, buffers, ancdata, flags, address)

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket, "gethostbyname", gethostbyname)
    monkeypatch.setattr(socket, "gethostbyname_ex", gethostbyname_ex)
    monkeypatch.setattr(socket, "getnameinfo", getnameinfo)
    monkeypatch.setattr(socket, "create_connection", create_connection)
    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    monkeypatch.setattr(socket.socket, "sendto", sendto)
    monkeypatch.setattr(socket.socket, "sendmsg", sendmsg)
    yield


@pytest.fixture(autouse=True)
def _private_home(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> Path:
    """HOME is an empty temporary directory in every test: no test ever reads the real home or its agent files."""
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    return home


@pytest.fixture
def fake() -> Iterator[FakeGitHub]:
    """A fake GitHub on a loopback port, torn down with the test."""
    with FakeGitHub().serve() as server:
        yield server


@pytest.fixture
def sleeps() -> list[float]:
    """Every backoff the client asked for. Nothing actually sleeps."""
    return []


@pytest.fixture
def client(fake: FakeGitHub, sleeps: list[float]) -> Client:
    return Client(fake.token, fake.url, sleep=sleeps.append)
