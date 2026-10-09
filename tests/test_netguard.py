# SPDX-License-Identifier: MIT
"""Endpoint destinations: link-local, unspecified, multicast and cloud-metadata are refused; a LAN or loopback stays.

The resolver is a fake: no test performs a DNS lookup. Rebinding is defended by resolving once and connecting to the
validated address.
"""

from __future__ import annotations

import socket
from typing import Any

import pytest

from agentsdata import A_MODELS, agents_dict
from fakeollama import FakeOllama
from safo import netguard
from safo.agentsfile import Endpoint, parse_agents
from safo.errors import ConfigError
from safo.ollama import EndpointUnreachableError, generate, probe

BLOCKED_LITERALS = [
    "169.254.169.254",
    "169.254.0.1",
    "0.0.0.0",  # noqa: S104 - a refused address in a test, not a bind
    "[::]",
    "[fe80::1]",
    "[fd00:ec2::254]",
    "100.100.100.200",
    "224.0.0.1",
    "[ff02::1]",
    "[::ffff:169.254.169.254]",
    "[::ffff:a9fe:a9fe]",
    "[::ffff:0.0.0.0]",
    "[::169.254.169.254]",
    "2852039166",  # decimal spelling of 169.254.169.254
    "0xa9fea9fe",  # hex
    "0251.0376.0251.0376",  # octal
    "0xa9.0xfe.0xa9.0xfe",
    "169.254.43518",  # partial dotted form
]
ALLOWED_LITERALS = ["127.0.0.1", "[::1]", "10.1.2.3", "192.168.1.5", "172.16.0.9", "[fd12:3456::1]", "ollama.lan"]


def doc_with(url: str) -> dict[str, Any]:
    d = agents_dict()
    d["agents"]["ollama"]["endpoints"][0]["url"] = url
    return d


@pytest.mark.parametrize("host", BLOCKED_LITERALS)
def test_a_blocked_literal_is_refused_at_config_load(host: str) -> None:
    with pytest.raises(ConfigError, match=r"endpoints\[0\]\.url"):
        parse_agents(doc_with(f"http://{host}:11434"))


@pytest.mark.parametrize("host", ALLOWED_LITERALS)
def test_loopback_and_lan_literals_are_accepted_at_config_load(host: str) -> None:
    assert parse_agents(doc_with(f"http://{host}:11434")).agent("ollama").endpoints[0].url.endswith(":11434")


def ep(url: str) -> Endpoint:
    return parse_agents(doc_with(url)).agent("ollama").endpoints[0]


def fake_resolver(table: dict[str, list[str]], calls: list[str] | None = None) -> Any:
    def resolve(host: str, port: Any, *args: Any, **kwargs: Any) -> list[Any]:
        if calls is not None:
            calls.append(host)
        out = []
        for address in table[host]:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            out.append((family, socket.SOCK_STREAM, 6, "", (address, port or 0)))
        return out

    return resolve


def test_a_name_that_resolves_to_metadata_is_refused_at_connect(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(netguard, "resolver", fake_resolver({"evil.example": ["169.254.169.254"]}))
    result = probe(ep("http://evil.example:11434"))
    assert not result.reachable and result.error == "BlockedDestinationError"
    with pytest.raises(EndpointUnreachableError, match="destination"):
        generate(ep("http://evil.example:11434"), A_MODELS[0], "x", think=False, num_ctx=8192, timeout=2)


def test_one_bad_address_among_several_refuses_the_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(netguard, "resolver", fake_resolver({"mixed.example": ["10.0.0.5", "fe80::1"]}))
    assert probe(ep("http://mixed.example:11434")).error == "BlockedDestinationError"


def test_a_mapped_ipv6_answer_for_metadata_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(netguard, "resolver", fake_resolver({"m.example": ["::ffff:169.254.169.254"]}))
    assert probe(ep("http://m.example:11434")).error == "BlockedDestinationError"


def test_the_connection_goes_to_the_validated_address_with_the_original_host_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    with FakeOllama(installed=A_MODELS, loaded=A_MODELS).serve() as server:
        port = server.url.rsplit(":", 1)[1]
        monkeypatch.setattr(netguard, "resolver", fake_resolver({"ollama.lan": ["127.0.0.1"]}, calls))
        result = probe(ep(f"http://ollama.lan:{port}"))
        assert result.reachable and {h for h in server.hosts} == {f"ollama.lan:{port}"}
        assert calls == ["ollama.lan", "ollama.lan"], "one resolution per request, no more"


def test_dns_rebinding_between_check_and_connect_cannot_happen(monkeypatch: pytest.MonkeyPatch) -> None:
    """The first answer is safe, every later one is metadata: the connection still goes to the first answer."""
    answers = iter([["127.0.0.1"], ["169.254.169.254"], ["169.254.169.254"]])

    def rebinding(host: str, port: Any, *args: Any, **kwargs: Any) -> list[Any]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port or 0)) for a in next(answers)]

    with FakeOllama(installed=A_MODELS, loaded=A_MODELS).serve() as server:
        port = server.url.rsplit(":", 1)[1]
        monkeypatch.setattr(netguard, "resolver", rebinding)
        generate(ep(f"http://flip.example:{port}"), A_MODELS[0], "x", think=False, num_ctx=8192, timeout=5)
        assert len(server.generates) == 1


def test_every_spelling_of_metadata_is_refused_at_connect_even_if_config_was_bypassed() -> None:
    for host in ("169.254.169.254", "2852039166", "0xa9fea9fe", "[::ffff:169.254.169.254]"):
        bypass = Endpoint("x", f"http://{host}:11434", ("general",), ("m",), 4096, False)
        assert probe(bypass).error == "BlockedDestinationError", host
