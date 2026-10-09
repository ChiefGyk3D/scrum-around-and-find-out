# SPDX-License-Identifier: MIT
"""A small Ollama client: a read-only probe, and one native generate call.

The probe asks `GET /api/tags` (what is installed) and `GET /api/ps` (what is loaded) and nothing else, with a short
timeout. It never calls `/api/generate`, so it can never load a model and evict a resident one. `generate` is only
reached from `safo local run`, after routing has checked the model and the context size against the endpoint's rules.
"""

from __future__ import annotations

import http.client
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from safo.agentsfile import Endpoint
from safo.bounded import MAX_BYTES, count, loads
from safo.errors import ApiError, SafoError

PROBE_TIMEOUT = 3.0


class EndpointUnreachableError(SafoError):
    """The endpoint did not answer: out of range of the LAN, the VPN is off, or the server is down."""

    exit_code = 1


@dataclass(frozen=True)
class Probe:
    endpoint_id: str
    url: str = field(repr=False)
    reachable: bool
    loaded: tuple[str, ...] = ()
    available: tuple[str, ...] = ()
    error: str = ""


@dataclass(frozen=True)
class Generation:
    response: str
    model: str
    eval_count: int
    prompt_eval_count: int
    eval_duration_ns: int
    thinking: str = ""

    @property
    def tokens_per_second(self) -> float | None:
        return round(self.eval_count / (self.eval_duration_ns / 1e9), 1) if self.eval_duration_ns > 0 else None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is an error: a prompt must never be replayed to a host the configuration did not name."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


# No proxy from the environment either: the endpoint is exactly the configured one.
def _opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def _request(url: str, *, data: bytes | None, timeout: float) -> Any:
    request = urllib.request.Request(  # noqa: S310 - the scheme is checked when the endpoint is parsed
        url, data=data, method="POST" if data is not None else "GET", headers={"Content-Type": "application/json"}
    )
    with _opener().open(request, timeout=timeout) as response:
        return loads(response.read(MAX_BYTES + 1))


def _names(body: Any, key: str) -> tuple[str, ...]:
    rows = body.get(key) if isinstance(body, dict) else None
    return tuple(str(r["name"]) for r in rows or [] if isinstance(r, dict) and "name" in r)


def probe(endpoint: Endpoint, timeout: float = PROBE_TIMEOUT) -> Probe:
    """Reachable, installed models, loaded models. Two GETs; never a generate."""
    try:
        tags = _request(f"{endpoint.url}/api/tags", data=None, timeout=timeout)
        ps = _request(f"{endpoint.url}/api/ps", data=None, timeout=timeout)
    except (OSError, http.client.HTTPException, ValueError) as err:  # URLError, timeouts and resets are OSError
        return Probe(endpoint.id, endpoint.url, False, error=err.__class__.__name__)
    return Probe(endpoint.id, endpoint.url, True, _names(ps, "models"), _names(tags, "models"))


def generate(
    endpoint: Endpoint, model: str, prompt: str, *, think: bool, num_ctx: int, timeout: float, keep_alive: str = ""
) -> Generation:
    """One non-streaming native generate. `think` is always sent: a thinking model spends hundreds of tokens."""
    payload: dict[str, Any] = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "think": think,
        "options": {"num_ctx": num_ctx},
    }
    if keep_alive:
        payload["keep_alive"] = keep_alive  # only for an on-demand model: it unloads soon after
    body = json.dumps(payload).encode()
    try:
        answer = _request(f"{endpoint.url}/api/generate", data=body, timeout=timeout)
    except urllib.error.HTTPError as err:
        raise ApiError(f"{endpoint.id} answered {err.code} to the generate request") from None
    except (OSError, http.client.HTTPException) as err:
        raise EndpointUnreachableError(f"{endpoint.id} stopped answering ({err.__class__.__name__})") from None
    except ValueError:
        raise ApiError(f"{endpoint.id} sent an answer that is not JSON") from None
    if not isinstance(answer, dict) or "response" not in answer:
        raise ApiError(f"{endpoint.id} sent an answer with no response field")
    try:
        metrics = [count(answer.get(k, 0)) for k in ("eval_count", "prompt_eval_count", "eval_duration")]
    except ValueError:
        raise ApiError(f"{endpoint.id} sent invalid generation metrics") from None
    if not isinstance(answer["response"], str):
        raise ApiError(f"{endpoint.id} sent invalid response type")
    return Generation(
        answer["response"],
        str(answer.get("model", model)),
        metrics[0],
        metrics[1],
        metrics[2],
        str(answer.get("thinking", "") or ""),
    )
