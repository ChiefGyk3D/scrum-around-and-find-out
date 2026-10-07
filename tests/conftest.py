# SPDX-License-Identifier: MIT
"""Shared fixtures and one guard that applies to every test: nothing leaves this machine.

Sockets to anywhere but loopback raise, naming the host. There is no opt-out fixture on
purpose: the fake GraphQL server in tests/fakegh answers on 127.0.0.1.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterator
from typing import Any

import pytest

_real_connect = socket.socket.connect
_real_create_connection = socket.create_connection
_real_getaddrinfo = socket.getaddrinfo


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

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", create_connection)
    monkeypatch.setattr(socket.socket, "connect", connect)
    yield
