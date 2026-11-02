# SPDX-License-Identifier: Apache-2.0
"""The free-tier entry copies every request field through base types once (#217, kept after #287): a lying `str` or
`int` subclass, a request subclass or a wrong type is refused with the field named, nothing is sent or written."""

from __future__ import annotations

import dataclasses
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from geminidata import FAKE_KEY, MODEL, NOW, FakeGemini, ledger_rows, write_config
from safo.gemini import GeminiConfig, RefusedError, Request, ask, load_config

PROMPT = "What changed in the public CVE list?"


@pytest.fixture
def server() -> Iterator[FakeGemini]:
    with FakeGemini().serve() as fake:
        yield fake


@pytest.fixture
def cfg(tmp_path: Path, server: FakeGemini) -> GeminiConfig:
    return load_config(write_config(tmp_path / "gemini.yaml", server.url, tmp_path / "data" / "ledger.jsonl"))


def keys(_tier: str) -> str:
    return FAKE_KEY


def liar(base: type, value: Any) -> Any:
    """A subclass that bends comparison and text on purpose (built with `type` so no checker sees a bad override)."""
    methods = {
        "__eq__": lambda self, other: True,
        "__ne__": lambda self, other: False,
        "__hash__": lambda self: 1,
        "__str__": lambda self: "unapproved-expensive-model",
        "__len__": lambda self: 1,
    }
    return type("Liar", (base,), methods)(value)


FIELDS: dict[str, tuple[type, Any]] = {
    "model": (str, MODEL),
    "prompt": (str, PROMPT),
    "tier": (str, "free"),
    "job": (str, "job-1"),
    "approval": (str, ""),
    "max_output_tokens": (int, 500),
}


def free(**kw: Any) -> Request:
    return Request(**{"model": MODEL, "prompt": PROMPT, "tier": "free", "job": "job-1", "max_output_tokens": 500, **kw})


@pytest.mark.parametrize("field", sorted(FIELDS))
def test_a_lying_subclass_in_any_request_field_is_refused_and_nothing_is_written(
    cfg: GeminiConfig, server: FakeGemini, field: str
) -> None:
    base, value = FIELDS[field]
    bad = dataclasses.replace(free(), **{field: liar(base, value)})
    with pytest.raises(RefusedError, match=field) as err:
        ask(cfg, bad, key_for=keys, now=NOW)
    assert "unapproved-expensive-model" not in str(err.value), "the refusal does not echo the value"
    assert server.requests == [] and not cfg.ledger.exists()
    wrong_values = (b"x", 7, None, 1.5, True) if base is str else ("x", 1.5, None, True, b"1")
    for wrong in wrong_values:
        with pytest.raises(RefusedError, match=field):
            ask(cfg, free(**{field: wrong}), key_for=keys, now=NOW)
    assert server.requests == []


def test_a_request_subclass_is_refused(cfg: GeminiConfig, server: FakeGemini) -> None:
    class Sub(Request):
        pass

    with pytest.raises(RefusedError, match="request"):
        ask(cfg, Sub(**dataclasses.asdict(free())), key_for=keys, now=NOW)
    assert server.requests == []


def test_the_model_is_one_plain_string_in_the_url_the_body_and_the_ledger(
    cfg: GeminiConfig, server: FakeGemini
) -> None:
    ask(cfg, free(max_output_tokens=300), key_for=keys, now=NOW)
    started = next(r for r in ledger_rows(cfg.ledger, everything=True) if r["type"] == "call_start")
    path, _, body = server.requests[0]
    assert started["model"].encode() == MODEL.encode()
    assert path == f"/v1beta/models/{MODEL}:generateContent"
    assert body["generationConfig"]["maxOutputTokens"] == 300


def test_the_config_values_that_reach_a_request_are_exact_base_types(cfg: GeminiConfig) -> None:
    assert type(cfg.max_output_tokens) is int and type(cfg.endpoint) is str
    assert all(type(k) is str for k in cfg.free) and all(type(k) is str for k in cfg.image_models)
