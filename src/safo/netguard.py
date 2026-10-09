# SPDX-License-Identifier: MIT
"""Where an endpoint may point: loopback and the private LAN, never link-local, unspecified, multicast or metadata.

A local model lives on loopback or a LAN address, so those stay allowed. The ranges a hostile `agents.yaml` would aim
at (the link-local block that holds the cloud metadata services, the unspecified address, multicast) are refused, in
every spelling: IPv4-mapped IPv6, and the decimal, octal and hex forms of an IPv4 address.

A name is resolved once, every address it returns is checked, and the caller connects to a checked address, never to
the name again, so a DNS answer that changes between the check and the connection has no effect.
"""

from __future__ import annotations

import http.client
import ipaddress
import re
import socket
from collections.abc import Callable
from typing import Any

# Replaced by a test: no test performs a DNS lookup.
resolver: Callable[..., Any] | None = None

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_METADATA = frozenset(ipaddress.ip_address(a) for a in ("169.254.169.254", "fd00:ec2::254", "100.100.100.200"))
_THIS_NETWORK = ipaddress.ip_network("0.0.0.0/8")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_NUMERIC = re.compile(r"[0-9a-fA-FxX.]+")


class BlockedDestinationError(OSError):
    """The destination is an address a local model is never served from."""


def literal(host: str) -> IPAddress | None:
    """The address a host spelled as an IP stands for (including decimal, octal and hex), else None for a name."""
    host = host.strip("[]")
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    if _NUMERIC.fullmatch(host):
        try:
            return ipaddress.IPv4Address(socket.inet_aton(host))
        except OSError:
            return None
    return None


def _embedded(ip: IPAddress) -> IPAddress:
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        if ip in _NAT64 or (int(ip) < 2**32 and ip != ipaddress.IPv6Address("::1")):
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return ip


def blocked(ip: IPAddress) -> bool:
    ip = _embedded(ip)
    if ip in _METADATA or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
        return True
    return isinstance(ip, ipaddress.IPv4Address) and ip in _THIS_NETWORK


def literal_blocked(host: str) -> bool:
    """For config load: true when the host is an IP, in any spelling, that is not allowed. A name passes here."""
    ip = literal(host)
    return ip is not None and blocked(ip)


def validated_addresses(host: str, port: int) -> list[str]:
    """Resolve once and return the addresses to connect to; one blocked answer refuses the whole name."""
    ip = literal(host)
    if ip is not None:
        if blocked(ip):
            raise BlockedDestinationError("destination address is not allowed")
        return [str(ip)]
    lookup = resolver or socket.getaddrinfo
    found: list[str] = []
    for _family, _type, _proto, _canon, sockaddr in lookup(host, port, type=socket.SOCK_STREAM):
        try:
            address = ipaddress.ip_address(str(sockaddr[0]))
        except ValueError:
            raise BlockedDestinationError("destination address is not allowed") from None
        if blocked(address):
            raise BlockedDestinationError("destination address is not allowed")
        found.append(str(address))
    if not found:
        raise BlockedDestinationError("destination did not resolve")
    return found


def connect_pinned(address: tuple[str, int], timeout: float | None = None, source_address: Any = None) -> socket.socket:
    """`socket.create_connection` that resolves once, checks every answer and connects to a checked address."""
    host, port = address
    last: OSError | None = None
    for ip in validated_addresses(host, port):
        try:
            return socket.create_connection((ip, port), timeout, source_address)
        except OSError as err:
            last = err
    raise last or BlockedDestinationError("destination did not resolve")


class PinnedHTTPConnection(http.client.HTTPConnection):
    """Connects to the checked address; the Host header and the TLS name stay the configured host."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._create_connection = connect_pinned


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._create_connection = connect_pinned
