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
