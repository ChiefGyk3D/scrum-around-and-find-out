# SPDX-License-Identifier: MIT
"""The conftest guard: nothing but loopback."""

from __future__ import annotations

import re
import socket

import pytest

from conftest import NetworkAccessDenied


def test_a_connection_to_a_public_address_is_refused_by_name() -> None:
    with pytest.raises(NetworkAccessDenied, match=re.escape("203.0.113.5")):
        socket.create_connection(("203.0.113.5", 443), timeout=1)


def test_a_name_is_refused_without_resolving_it() -> None:
    with pytest.raises(NetworkAccessDenied, match=re.escape("example.org")):
        socket.getaddrinfo("example.org", 443)


def test_connect_ex_to_a_public_address_is_refused() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(NetworkAccessDenied, match=re.escape("203.0.113.5")):
            sock.connect_ex(("203.0.113.5", 443))
    finally:
        sock.close()


def test_udp_sendto_to_a_public_address_is_refused() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with pytest.raises(NetworkAccessDenied, match=re.escape("203.0.113.5")):
            sock.sendto(b"test", ("203.0.113.5", 53))
    finally:
        sock.close()


def test_gethostbyname_of_a_domain_is_refused() -> None:
    with pytest.raises(NetworkAccessDenied, match=re.escape("example.org")):
        socket.gethostbyname("example.org")


def test_loopback_connect_and_connect_ex_are_allowed() -> None:
    # Create a listening socket on loopback
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        # Test connect
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.connect(("127.0.0.1", port))
            client.close()
        except Exception as e:
            pytest.fail(f"loopback connect should be allowed: {e}")

        # Test connect_ex
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            result = client.connect_ex(("127.0.0.1", port))
            assert result == 0, f"connect_ex should succeed, got {result}"
            client.close()
        except Exception as e:
            pytest.fail(f"loopback connect_ex should be allowed: {e}")
    finally:
        server.close()
