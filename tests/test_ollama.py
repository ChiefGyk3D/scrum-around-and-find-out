# SPDX-License-Identifier: MIT
"""The Ollama client against a fake on loopback: the probe only reads, generate sends think and the context cap."""

from __future__ import annotations

import pytest

from agentsdata import A_MODELS, agents_with
from fakeollama import FakeOllama
from safo.agentsfile import Endpoint
from safo.errors import ApiError
from safo.ollama import EndpointUnreachableError, generate, probe


def endpoint(url: str) -> Endpoint:
    return agents_with(url, url).agent("ollama").endpoints[0]


def test_the_probe_reads_tags_and_ps_and_never_generates() -> None:
    with FakeOllama(installed=[*A_MODELS, "other"], loaded=A_MODELS).serve() as server:
        result = probe(endpoint(server.url))
        assert result.reachable and result.loaded == tuple(A_MODELS) and "other" in result.available
        assert [(m, p) for m, p, _ in server.requests] == [("GET", "/api/tags"), ("GET", "/api/ps")]
        assert server.generates == []


def test_an_endpoint_that_does_not_answer_is_unreachable_not_an_error() -> None:
    result = probe(endpoint("http://127.0.0.1:9"), timeout=1.0)
    assert not result.reachable and result.loaded == () and result.error


def test_generate_sends_think_and_num_ctx_and_reports_the_speed() -> None:
    with FakeOllama(installed=A_MODELS, loaded=A_MODELS).serve() as server:
        done = generate(endpoint(server.url), A_MODELS[0], "Say hi.", think=False, num_ctx=131072, timeout=5)
        body = server.generates[0]
        assert body["think"] is False and body["options"] == {"num_ctx": 131072} and body["stream"] is False
        assert "keep_alive" not in body, "a resident model is never given a keep_alive"
        generate(endpoint(server.url), A_MODELS[1], "x", think=False, num_ctx=8192, timeout=5, keep_alive="30s")
        assert server.generates[1]["keep_alive"] == "30s"
        assert done.response == "A short answer." and done.eval_count == 100 and done.tokens_per_second == 50.0


def test_a_server_error_and_a_dropped_connection_are_distinct() -> None:
    with FakeOllama(installed=A_MODELS, loaded=A_MODELS).serve() as server:
        server.generate_status = 500
        with pytest.raises(ApiError, match="answered 500"):
            generate(endpoint(server.url), A_MODELS[0], "x", think=False, num_ctx=131072, timeout=5)
        server.generate_status = 200
        server.drop_generate = True
        with pytest.raises(EndpointUnreachableError, match="stopped answering"):
            generate(endpoint(server.url), A_MODELS[0], "x", think=False, num_ctx=131072, timeout=5)


@pytest.mark.parametrize("bad", ["sentinel-credential", float("nan"), float("inf"), [], 10**400])
def test_generation_metrics_are_controlled_errors_without_input_echo(bad: object) -> None:
    with FakeOllama(A_MODELS, A_MODELS).serve() as server:
        server.reply["eval_count"] = bad
        with pytest.raises(ApiError) as caught:
            generate(endpoint(server.url), A_MODELS[0], "x", think=False, num_ctx=8192, timeout=5)
        assert "sentinel-credential" not in str(caught.value)


def test_oversized_generation_response_is_rejected() -> None:
    with FakeOllama(A_MODELS, A_MODELS).serve() as server:
        server.reply["response"] = "a" * 1_048_577
        with pytest.raises(ApiError, match="not JSON"):
            generate(endpoint(server.url), A_MODELS[0], "x", think=False, num_ctx=8192, timeout=5)


def test_a_reachable_host_that_never_answers_a_probe_is_unreachable_after_the_timeout() -> None:
    with FakeOllama(A_MODELS, A_MODELS).serve() as server:
        server.stall_seconds = 1.5
        result = probe(endpoint(server.url), timeout=0.3)
        assert not result.reachable and result.loaded == () and result.error


@pytest.mark.parametrize("raw", [b"x" * 1_048_577, b"not json at all", b"\x00\x01garbage", b'{"models": [' * 70])
def test_a_probe_answer_that_is_huge_or_not_json_is_unreachable_not_a_crash(raw: bytes) -> None:
    with FakeOllama(A_MODELS, A_MODELS).serve() as server:
        server.raw_reply = raw
        result = probe(endpoint(server.url))
        assert not result.reachable and result.available == ()


def test_a_generate_answer_that_is_not_json_is_an_api_error_not_a_bare_exception() -> None:
    with FakeOllama(A_MODELS, A_MODELS).serve() as server:
        server.raw_reply = b"<html>proxy error</html>"
        with pytest.raises(ApiError, match="not JSON"):
            generate(endpoint(server.url), A_MODELS[0], "x", think=False, num_ctx=131072, timeout=5)
        server.raw_reply = b'["a", "list"]'
        with pytest.raises(ApiError, match="no response field"):
            generate(endpoint(server.url), A_MODELS[0], "x", think=False, num_ctx=131072, timeout=5)


def test_a_redirect_is_never_followed_so_a_prompt_cannot_be_replayed_to_another_host() -> None:
    with FakeOllama(A_MODELS, A_MODELS).serve() as target, FakeOllama(A_MODELS, A_MODELS).serve() as server:
        server.redirect_to = f"{target.url}/api/generate"
        with pytest.raises(ApiError, match="answered 302"):
            generate(endpoint(server.url), A_MODELS[0], "secret prompt", think=False, num_ctx=131072, timeout=5)
        assert probe(endpoint(server.url)).reachable is False
        assert target.requests == []


def test_a_proxy_in_the_environment_is_not_used(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    with FakeOllama(A_MODELS, A_MODELS).serve() as server:
        assert probe(endpoint(server.url)).reachable
        assert len(server.requests) == 2
