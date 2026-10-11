# SPDX-License-Identifier: MIT
"""Spec test 6: RFC 6901 config pointers address the base agents.yaml only, through a per-setting allowlist."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from evdata import repo
from profiledata import doc, profile
from safo.errors import ConfigError
from safo.evidence import EvidenceError, load_verified_agents, pointer_get, resolve_config


def endpoint_doc(model: str = "small-4b-agent") -> dict[str, Any]:
    d = doc()
    ep = d["agents"]["ollama"]["endpoints"][0]
    ep["models"] = [model, *[m for m in ep["models"] if m != model]]
    ep["protected_models"] = []
    ep["loaded_num_ctx"] = {model: 4096}
    ep["num_ctx_max"] = 8192
    ep["think"] = False
    d["agents"]["ollama"]["endpoints"] = [ep]
    return d


@pytest.mark.parametrize(
    ("ref", "expected"),
    [
        ("/a/b", 1),
        ("/a~1b/c", 2),  # a key containing a slash
        ("/m~0n", 3),  # a key containing a tilde
        ("/k.l", 4),  # a key containing a dot
        ("/a~01", 5),  # ~0 then 1: the literal key "a~1", not "a/"
        ("/list/0", "x"),
        ("/list/1", "y"),
        ("/list/1/", None),
    ],
)
def test_pointer_get_follows_rfc_6901(ref: str, expected: object) -> None:
    data = {"a": {"b": 1}, "a/b": {"c": 2}, "m~n": 3, "k.l": 4, "a~1": 5, "list": ["x", "y"]}
    if expected is None:
        with pytest.raises(EvidenceError):
            pointer_get(data, ref)
    else:
        assert pointer_get(data, ref) == expected


@pytest.mark.parametrize(
    "ref",
    [
        "/list/-",
        "/list/01",
        "/list/+1",
        "/list/1.0",
        "/list/9",
        "/list/x",
        "/nope",
        "/a/b/c",
        "a/b",
        "xa",
        "/m~2n",
        "/m~",
    ],
)
def test_pointer_get_refuses_what_the_rfc_does_not_resolve(ref: str) -> None:
    data = {"a": {"b": 1}, "list": ["x", "y"], "m~n": 3, "m~2n": 4}
    with pytest.raises(EvidenceError):
        pointer_get(data, ref)


def test_the_empty_pointer_is_the_whole_document_and_is_not_on_the_allowlist() -> None:
    assert pointer_get({"a": 1}, "") == {"a": 1}
    with pytest.raises(EvidenceError, match="allowlist"):
        resolve_config({"a": 1}, "", "context_ceiling", "ollama")


def test_an_allowlisted_pointer_resolves_for_its_setting_only() -> None:
    d = endpoint_doc()
    assert (
        resolve_config(d, "/agents/ollama/endpoints/0/num_ctx_max", "context_ceiling", "ollama")[0]
        == "num_ctx_max = 8192"
    )
    assert (
        resolve_config(d, "/agents/ollama/endpoints/0/loaded_num_ctx/small-4b-agent", "context_ceiling", "ollama")[0]
        == "loaded_num_ctx[small-4b-agent] = 4096"
    )
    assert resolve_config(d, "/agents/ollama/endpoints/0/think", "thinking", "ollama")[0] == "think = false"
    for claim, ref in [
        ("thinking", "/agents/ollama/endpoints/0/num_ctx_max"),
        ("context_ceiling", "/agents/ollama/endpoints/0/think"),
        ("context_ceiling", "/agents/ollama/endpoints/0/url"),
        ("thinking", "/agents/ollama/endpoints/0/note"),
        ("context_ceiling", "/version"),
        ("context_ceiling", "/agents/ollama/kind"),
        ("claim", "/agents/ollama/endpoints/0/think"),
        ("output_cap", "/agents/ollama/endpoints/0/num_ctx_max"),
    ]:
        with pytest.raises(EvidenceError, match="allowlist"):
            resolve_config(d, ref, claim, "ollama")


@pytest.mark.parametrize(
    "ref",
    [
        "/other/ollama/endpoints/0/num_ctx_max",
        "/agents/ollama/other/0/num_ctx_max",
        "/agents/ollama/endpoints/00/num_ctx_max",
        "/agents/ollama/endpoints/0/num_ctx_max/x",
        "/agents//endpoints/0/num_ctx_max",
        "/agents/ollama/endpoints/0",
    ],
)
def test_the_allowlist_is_checked_segment_by_segment_against_data_that_would_resolve(ref: str) -> None:
    """Each wrong segment is tried against a document that has a value at that exact place, so only the allowlist stops it."""
    ep = {"num_ctx_max": 1024, "think": False}
    base = {
        "other": {"ollama": {"endpoints": [ep]}},
        "agents": {"ollama": {"other": [ep], "endpoints": [ep, ep], "": {"endpoints": [ep]}}},
    }
    with pytest.raises(EvidenceError, match="allowlist"):
        resolve_config(base, ref, "context_ceiling", "ollama")
    base["agents"]["ollama"]["endpoints"] = {"00": ep}  # type: ignore[index]
    with pytest.raises(EvidenceError, match="allowlist"):
        resolve_config(base, "/agents/ollama/endpoints/00/num_ctx_max", "context_ceiling", "ollama")


def test_a_pointer_into_another_agent_does_not_support_this_agents_claim() -> None:
    d = endpoint_doc()
    with pytest.raises(EvidenceError, match="own"):
        resolve_config(d, "/agents/ollama/endpoints/0/num_ctx_max", "context_ceiling", "codex")


def test_a_key_with_slash_dot_and_tilde_is_addressed_by_its_escaped_form() -> None:
    model = "lib/small.4b~x"
    d = endpoint_doc(model)
    ref = "/agents/ollama/endpoints/0/loaded_num_ctx/lib~1small.4b~0x"
    assert resolve_config(d, ref, "context_ceiling", "ollama")[0] == f"loaded_num_ctx[{model}] = 4096"
    with pytest.raises(EvidenceError):
        resolve_config(d, "/agents/ollama/endpoints/0/loaded_num_ctx/lib/small.4b~x", "context_ceiling", "ollama")


def test_a_list_index_is_canonical() -> None:
    d = endpoint_doc()
    for bad in ("01", "-1", "1", "+0"):
        with pytest.raises(EvidenceError):
            resolve_config(d, f"/agents/ollama/endpoints/{bad}/num_ctx_max", "context_ceiling", "ollama")


def test_a_value_of_the_wrong_type_does_not_resolve() -> None:
    d = endpoint_doc()
    d["agents"]["ollama"]["endpoints"][0]["num_ctx_max"] = "8192"
    with pytest.raises(EvidenceError, match="integer"):
        resolve_config(d, "/agents/ollama/endpoints/0/num_ctx_max", "context_ceiling", "ollama")
    d["agents"]["ollama"]["endpoints"][0]["think"] = 1
    with pytest.raises(EvidenceError, match="boolean"):
        resolve_config(d, "/agents/ollama/endpoints/0/think", "thinking", "ollama")


def cited(tmp_path: Path, ref: str, base: dict[str, Any] | None = None) -> Path:
    d = base or endpoint_doc()
    profile(d, "ollama")["context_ceiling"] = {"value": 1024, "evidence": f"config:{ref}"}
    return repo(tmp_path, d)


def test_a_config_pointer_resolves_through_the_loader(tmp_path: Path) -> None:
    v = load_verified_agents(cited(tmp_path, "/agents/ollama/endpoints/0/num_ctx_max"), trusted=False)
    v.require_clean()
    got = [r for r in v.resolutions if r.field == "agents.ollama.profile.context_ceiling"]
    assert len(got) == 1 and got[0].kind == "config" and got[0].subject == "num_ctx_max = 8192"
    assert len(got[0].excerpt_digest) == 64


def test_the_merged_local_override_cannot_satisfy_or_alter_a_committed_claim(tmp_path: Path) -> None:
    path = cited(tmp_path, "/agents/ollama/endpoints/0/num_ctx_max")
    local = tmp_path / "local.yaml"
    local.write_text(
        "agents:\n  ollama:\n    endpoints:\n"
        "      - {id: lab, url: 'http://127.0.0.1:9', roles: [general], models: [m], num_ctx_max: 4096}\n"
    )
    local.chmod(0o600)
    v = load_verified_agents(path, local, trusted=False)
    # the override replaced the endpoint list, yet the pointer still reads the committed value
    [r] = [r for r in v.resolutions if r.field == "agents.ollama.profile.context_ceiling"]
    assert r.subject == "num_ctx_max = 8192"


def test_an_endpoint_only_the_override_has_is_unresolved(tmp_path: Path) -> None:
    path = cited(tmp_path, "/agents/ollama/endpoints/1/num_ctx_max")
    local = tmp_path / "local.yaml"
    local.write_text(
        "agents:\n  ollama:\n    endpoints:\n"
        "      - {id: one, url: 'http://127.0.0.1:9', roles: [general], models: [m], num_ctx_max: 4096}\n"
        "      - {id: two, url: 'http://127.0.0.1:9', roles: [general], models: [m], num_ctx_max: 4096}\n"
    )
    local.chmod(0o600)
    v = load_verified_agents(path, local, trusted=False)
    assert "ollama" in v.errors_by_agent
    with pytest.raises(ConfigError, match="ollama"):
        v.require_clean()


def test_a_pointer_to_a_missing_endpoint_is_an_error_for_that_agent_only(tmp_path: Path) -> None:
    v = load_verified_agents(cited(tmp_path, "/agents/ollama/endpoints/3/num_ctx_max"), trusted=False)
    assert set(v.errors_by_agent) == {"ollama"}
