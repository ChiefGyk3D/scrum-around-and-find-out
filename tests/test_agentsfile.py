# SPDX-License-Identifier: MIT
"""agents.yaml: it validates with the key named, and the shipped file is the maintainer's measured routing."""

from __future__ import annotations

import copy
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from agentsdata import agents_dict
from safo.agentsfile import load_agents, load_agents_merged, parse_agents
from safo.errors import ConfigError

ROOT = Path(__file__).parent.parent
AGENTS = ROOT / "agents.yaml"


def doc() -> dict[str, Any]:
    from agentsdata import agents_dict

    loaded = agents_dict()
    assert isinstance(loaded, dict)
    return copy.deepcopy(loaded)


def test_the_shipped_file_loads_with_every_agent_and_shape_the_playbook_names() -> None:
    agents = load_agents(AGENTS)
    assert {a.id for a in agents.agents} >= {
        "claude-lead",
        "claude-sonnet",
        "claude-haiku",
        "claude-opus",
        "codex",
        "copilot",
        "maintainer",
    }
    assert {s.name for s in agents.shapes} >= {
        "research",
        "plan-writing",
        "integration-code",
        "well-specified-code",
        "small-mechanical-pr",
        "security-sensitive-design",
        "adversarial-review",
        "security-sensitive-code",
        "ops-runbook",
        "status-headline",
    }
    assert agents.monthly_allowance() == 7000


def test_the_measured_routes() -> None:
    a = parse_agents(doc())
    assert a.shape("research").chain == ("codex", "claude-sonnet")
    assert a.shape("integration-code").chain == ("claude-sonnet", "codex")
    assert a.shape("well-specified-code").chain == ("claude-haiku", "claude-sonnet")
    assert a.shape("small-mechanical-pr").chain == ("copilot", "claude-haiku")
    assert a.shape("small-mechanical-pr").reviewer == ("claude-sonnet",)
    assert a.shape("security-sensitive-design").prefer == ("claude-lead",)
    assert a.shape("security-sensitive-code").prefer == ("claude-sonnet",)
    assert a.shape("security-sensitive-code").reviewer == ("codex", "claude-sonnet")
    assert a.shape("ops-runbook").prefer == ("claude-sonnet",)
    assert a.shape("adversarial-review").prefer == ("codex",)
    assert a.shape("decision").prefer == ("maintainer",)
    assert a.agent("claude-opus").approval_required is True
    for local in ("ci-log-summary", "issue-triage", "changelog-draft", "docs-proofread", "duplicate-issue-search"):
        assert a.shape(local).prefer == ("ollama",) and a.shape(local).reviewer == ("claude-sonnet",), local
    assert a.shape("issue-triage").chain == ("ollama", "claude-haiku")
    headline = a.shape("status-headline")
    assert (headline.prefer, headline.fallback, headline.reviewer) == (("ollama",), (), ("maintainer",))
    assert headline.local_model == "small-4b-agent" and a.warnings == ()
    assert a.shape("duplicate-issue-search").local_model == "embed-small"
    assert (a.shape("ci-log-summary").local_model, a.shape("changelog-draft").local_model) == ("small-4b-agent",) * 2
    assert a.shape("issue-triage").local_model == a.shape("docs-proofread").local_model == ""
    assert a.warnings == ()
    assert any("mutation replay" in s and "missed" in s for s in a.agent("codex").strengths)
    assert any("five-hour window" in c and "78%" in c for c in a.agent("codex").constraints)
    assert any("carried the auth token" in s for s in a.agent("claude-haiku").strengths)
    assert any("Codex adversarial review" in c for c in a.agent("claude-haiku").constraints)
    assert any("id-token: write" in c for c in a.agent("copilot").constraints)
    assert any("400 a day" in c for c in a.agent("copilot").constraints)
    ollama = a.agent("ollama")
    assert any("58 to 116 tokens a second" in s for s in ollama.strengths)
    assert any("114 issues" in s for s in ollama.strengths)
    assert any("same CVE" in c and "false positive" in c for c in ollama.constraints)
    assert any("exactly the num_ctx" in c and "65536" in c for c in ollama.constraints)
    assert any("OLLAMA_VULKAN=0" in c for c in ollama.constraints)
    assert any("on-demand embedding model" in c and "1.1 GB" in c for c in ollama.constraints)
    assert any(r.startswith("Routing order 1:") and "local LLM first" in r for r in a.rules_of_thumb)
    assert [r.split(":")[0] for r in a.rules_of_thumb[:5]] == [f"Routing order {i}" for i in range(1, 6)]


def test_codex_constraints_say_the_lead_runs_the_suite_and_commits() -> None:
    codex = load_agents(AGENTS).agent("codex")
    assert any("cannot commit inside a git worktree" in c for c in codex.constraints)


def test_an_unknown_agent_in_a_shape_names_the_key_and_the_choices() -> None:
    d = doc()
    d["shapes"]["research"]["prefer"] = ["gpt-nine"]
    with pytest.raises(ConfigError, match=r"shapes\.research\.prefer\[0\]: 'gpt-nine' is not an agent"):
        parse_agents(d)


def test_a_bad_kind_a_bad_threshold_and_an_empty_prefer_are_named() -> None:
    d = doc()
    d["agents"]["codex"]["kind"] = "robot"
    with pytest.raises(ConfigError, match=r"agents\.codex\.kind: 'robot' is not one of"):
        parse_agents(d)
    d = doc()
    d["thresholds"][0]["above"] = 180
    with pytest.raises(ConfigError, match=r"thresholds\[0\]\.above: expected a percentage"):
        parse_agents(d)
    d = doc()
    d["thresholds"][0]["meter"] = "vibes"
    with pytest.raises(ConfigError, match=r"thresholds\[0\]\.meter: 'vibes' is not one of five_hour"):
        parse_agents(d)
    d = doc()
    d["shapes"]["research"]["prefer"] = []
    with pytest.raises(ConfigError, match=r"shapes\.research\.prefer: needs at least one agent"):
        parse_agents(d)


def test_unknown_keys_and_a_missing_file_are_config_errors(tmp_path: Path) -> None:
    d = doc()
    d["agents"]["codex"]["colour"] = "green"
    with pytest.raises(ConfigError, match=r"agents\.codex\.colour: unknown key"):
        parse_agents(d)
    with pytest.raises(ConfigError, match="cannot read the agents file"):
        load_agents(tmp_path / "nope.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("a: [unclosed\n")
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_agents(bad)


def test_the_endpoint_rules_are_validated_when_the_file_loads() -> None:
    def bad(mutate: Callable[[dict[str, Any], dict[str, Any]], object]) -> dict[str, Any]:
        data = copy.deepcopy(agents_dict())
        mutate(data["agents"]["ollama"]["endpoints"][0], data)
        return data

    a, b = parse_agents(doc()).agent("ollama").endpoints
    assert dict(a.loaded_num_ctx) == {"resident-12b-thinking": 131072, "small-4b-agent": 8192}
    assert a.ctx_for("small-4b-agent") == 8192 and a.loaded_ctx("nothing") is None
    assert b.roles == ("guard", "embedding") and b.protected_models == ("resident-safety",)
    assert dict(b.loaded_num_ctx) == {"resident-safety": 8192, "embed-small": 2048}
    assert b.on_demand_models == ("embed-small",) and b.keep_alive_for("embed-small") == "30s"
    assert b.keep_alive_for("resident-safety") == "" and b.ctx_for("embed-small") == 2048
    assert all(e.shared_with_production for e in (a, b))
    assert all(set(e.models) <= set(e.protected_models) | set(e.on_demand_models) for e in (a, b))
    with pytest.raises(
        ConfigError, match=r"endpoints\[0\]\.loaded_num_ctx: 'small-4b-agent' is on an endpoint with protected"
    ):
        parse_agents(bad(lambda e, d: e["loaded_num_ctx"].pop("small-4b-agent")))
    with pytest.raises(ConfigError, match=r"endpoints\[0\]\.loaded_num_ctx: 'other' is not an allowed model"):
        parse_agents(bad(lambda e, d: e["loaded_num_ctx"].update(other=4096)))
    with pytest.raises(ConfigError, match=r"endpoints\[0\]\.loaded_num_ctx.small-4b-agent: expected an integer"):
        parse_agents(bad(lambda e, d: e["loaded_num_ctx"].update({"small-4b-agent": "big"})))
    with pytest.raises(ConfigError, match=r"endpoints\[0\]\.on_demand_models: 'nope' is not an allowed model"):
        parse_agents(bad(lambda e, d: e.update(on_demand_models=["nope"], keep_alive="30s")))
    with pytest.raises(ConfigError, match=r"endpoints\[0\]\.on_demand_models: 'small-4b-agent' is also protected"):
        parse_agents(bad(lambda e, d: e.update(on_demand_models=["small-4b-agent"], keep_alive="30s")))
    with pytest.raises(ConfigError, match=r"endpoints\[0\]\.keep_alive: expected a short duration"):
        parse_agents(
            bad(
                lambda e, d: (
                    e["models"].append("tiny"),
                    e["loaded_num_ctx"].update(tiny=2048),
                    e.update(on_demand_models=["tiny"], keep_alive="never"),
                )
            )
        )
    with pytest.raises(ConfigError, match=r"endpoints\[0\]\.models: 'small-7b' is not a protected model"):
        parse_agents(bad(lambda e, d: e["models"].append("small-7b")))
    with pytest.raises(ConfigError, match=r"endpoints\[0\]\.url: expected http"):
        parse_agents(bad(lambda e, d: e.update(url="http://user:pw@host:1")))
    with pytest.raises(ConfigError, match=r"endpoints\[0\]\.roles\[0\]: 'robot' is not one of"):
        parse_agents(bad(lambda e, d: e.update(roles=["robot"])))
    with pytest.raises(ConfigError, match="an ollama agent needs at least one endpoint"):
        parse_agents(bad(lambda e, d: d["agents"]["ollama"].update(endpoints=[])))
    with pytest.raises(ConfigError, match="only an ollama agent has endpoints"):
        parse_agents(bad(lambda e, d: d["agents"]["codex"].update(endpoints=[copy.deepcopy(e)])))
    with pytest.raises(ConfigError, match="endpoint ids must be unique"):
        parse_agents(bad(lambda e, d: d["agents"]["ollama"]["endpoints"][1].update(id="instance-a")))
    warned = parse_agents(bad(lambda e, d: d["shapes"]["issue-triage"]["local"].update(model="nope")))
    assert warned.shape("issue-triage").local_model == "", "a missing pinned model falls back, it does not fail"
    assert (
        "shapes.issue-triage.local.model: 'nope' is not an allowed model of any general endpoint" in warned.warnings[0]
    )


def test_the_shipped_example_uses_placeholder_hosts_only() -> None:
    shipped = load_agents(ROOT / "agents.yaml")
    assert [e.url for e in shipped.agent("ollama").endpoints] == ["http://ollama.lan:11434"]
    endpoint = shipped.agent("ollama").endpoints[0]
    assert endpoint.roles == ("general",) and endpoint.models == ("small-4b-agent",)
    assert endpoint.num_ctx_max == 8192 and dict(endpoint.loaded_num_ctx) == {"small-4b-agent": 8192}
    assert endpoint.protected_models == () and shipped.warnings == ()


def test_the_shipped_local_example_merges_into_a_valid_file() -> None:
    merged = load_agents_merged(ROOT / "agents.yaml", ROOT / "examples" / "agents.local.example.yaml")
    assert [e.id for e in merged.agent("ollama").endpoints] == ["instance-a", "instance-b"]


def test_a_local_file_is_merged_over_the_example_so_real_endpoints_stay_out_of_the_repository(tmp_path: Path) -> None:
    local = tmp_path / "agents.local.yaml"
    local.write_text(
        "agents:\n  ollama:\n    endpoints:\n"
        "      - {id: lab, url: 'http://127.0.0.1:11434', roles: [general, embedding],\n"
        "         models: [small-7b, embed-small], num_ctx_max: 4096}\n"
    )
    merged = load_agents_merged(ROOT / "agents.yaml", local)
    assert [(e.id, e.url) for e in merged.agent("ollama").endpoints] == [("lab", "http://127.0.0.1:11434")]
    assert merged.shape("research").prefer == ("codex",), "everything else comes from the example"
    assert merged.shape("ci-log-summary").local_model == "", "the default uses the first allowed model"
    assert merged.warnings == ()
    assert [
        e.id for e in load_agents_merged(ROOT / "agents.yaml", tmp_path / "absent.yaml").agent("ollama").endpoints
    ] == ["local"]


@pytest.mark.parametrize(
    "raw,message",
    [
        ("version: 1\nversion: 1\n", "duplicate key"),
        ("x: *a\n", "aliases are not allowed"),
        ("x: &a []\n", "anchors are not allowed"),
        ("x: {<<: {a: 1}}\n", "merge keys"),
        ("x: " + "[" * 65 + "0" + "]" * 65, "nesting exceeds maximum depth"),
        ("x: " + "a" * 1_048_576, "exceeds maximum size"),
    ],
    ids=["duplicate", "alias", "anchor", "merge", "depth", "size"],
)
@pytest.mark.parametrize("override", [False, True])
def test_agents_yaml_uses_bounded_hardened_loader(tmp_path: Path, raw: str, message: str, override: bool) -> None:
    from agentsdata import write_agents
    from safo.agentsfile import load_agents_merged

    base = write_agents(tmp_path / "agents.yaml")
    invalid = tmp_path / "invalid.yaml"
    invalid.write_text(raw)
    with pytest.raises(ConfigError, match=message):
        load_agents_merged(base if override else invalid, invalid if override else None)


@pytest.mark.parametrize("suffix", ["?token=sentinel-credential", "#sentinel-credential"])
def test_endpoint_query_and_fragment_are_rejected_without_echo(suffix: str) -> None:
    from agentsdata import agents_dict

    data = agents_dict()
    data["agents"]["ollama"]["endpoints"][0]["url"] += suffix
    with pytest.raises(ConfigError) as caught:
        parse_agents(data)
    assert "sentinel-credential" not in str(caught.value)


def test_loaded_context_cannot_exceed_endpoint_cap() -> None:
    from agentsdata import agents_dict

    data = agents_dict()
    endpoint = data["agents"]["ollama"]["endpoints"][0]
    endpoint["num_ctx_max"] = 256
    with pytest.raises(ConfigError, match="loaded context exceeds num_ctx_max"):
        parse_agents(data)


def test_the_shipped_hooks_section_is_the_default_and_a_file_without_one_gets_it() -> None:
    shipped = load_agents(AGENTS).hooks
    assert shipped.approval_token == "OPUS-APPROVED" and shipped.max_state_age_seconds == 300
    assert shipped.local_step_markers == ("safo local run", "llm-local") and shipped.na_marker == "local-llm: n/a -"
    bare = doc()
    del bare["hooks"]
    assert parse_agents(bare).hooks == shipped


def test_the_hooks_section_is_read_and_lowercases_the_markers_it_matches_against() -> None:
    d = doc()
    d["hooks"] = {
        "approval_token": "MAINTAINER-OK-7",
        "max_state_age_seconds": 900,
        "local_step_markers": ["Run-Local", "local-first"],
        "na_marker": "No-Local-Step:",
    }
    hooks = parse_agents(d).hooks
    assert (hooks.approval_token, hooks.max_state_age_seconds) == ("MAINTAINER-OK-7", 900)
    assert hooks.local_step_markers == ("run-local", "local-first") and hooks.na_marker == "no-local-step:"


@pytest.mark.parametrize(
    "hooks,message",
    [
        ({"approval_token": "short"}, r"hooks\.approval_token: expected at least 8 characters with no whitespace"),
        ({"approval_token": "has space in it"}, r"hooks\.approval_token: expected at least 8"),
        ({"max_state_age_seconds": 10}, r"hooks\.max_state_age_seconds: expected an integer >= 60"),
        ({"max_state_age_seconds": 10**9}, r"hooks\.max_state_age_seconds: expected at most a week"),
        ({"local_step_markers": []}, r"hooks\.local_step_markers: needs at least one marker"),
        ({"local_step_markers": [" "]}, r"hooks\.local_step_markers\[0\]: expected a non-empty string"),
        ({"na_marker": ""}, r"hooks\.na_marker: expected a non-empty string"),
        ({"colour": "green"}, r"hooks\.colour: unknown key"),
    ],
    ids=["short-token", "spaced-token", "age-low", "age-high", "no-markers", "blank-marker", "no-na", "unknown"],
)
def test_the_hooks_section_names_the_key_it_refuses(hooks: dict[str, Any], message: str) -> None:
    d = doc()
    d["hooks"] = hooks
    with pytest.raises(ConfigError, match=message):
        parse_agents(d)


@pytest.mark.parametrize("kind", ["fifo", "oversized"])
def test_agents_hook_inputs_are_bounded_regular_files(tmp_path: Path, kind: str) -> None:
    import os

    path = tmp_path / "agents.yaml"
    if kind == "fifo":
        os.mkfifo(path)
    else:
        path.write_bytes(b" " * 1_048_577)
    with pytest.raises(ConfigError):
        load_agents(path)


def _on_demand_endpoint(keep_alive: str) -> dict[str, Any]:
    data = doc()
    endpoint = data["agents"]["ollama"]["endpoints"][1]
    endpoint["keep_alive"] = keep_alive
    return data


@pytest.mark.parametrize("keep_alive", ["30s", "5m", "10m", "600s"])
def test_a_short_keep_alive_is_accepted(keep_alive: str) -> None:
    assert parse_agents(_on_demand_endpoint(keep_alive)).agent("ollama").endpoints[1].keep_alive == keep_alive


@pytest.mark.parametrize("keep_alive", ["60m", "1000s", "601s", "11m", "1h", "0s", "-5s", "30", "forever", ""])
def test_a_keep_alive_that_is_not_short_is_refused(keep_alive: str) -> None:
    with pytest.raises(ConfigError, match=r"endpoints\[1\]\.keep_alive: expected a short duration"):
        parse_agents(_on_demand_endpoint(keep_alive))


@pytest.mark.parametrize("above", ["high", True, None, -1, 100.5, float("nan"), float("inf")])
def test_a_threshold_that_is_not_a_percentage_is_refused(above: object) -> None:
    d = doc()
    d["thresholds"][0]["above"] = above
    with pytest.raises(ConfigError, match=r"thresholds\[0\]\.above: expected a percentage from 0 to 100"):
        parse_agents(d)


@pytest.mark.parametrize("above", [0, 100, 80.5])
def test_a_threshold_at_the_edges_is_accepted(above: float) -> None:
    d = doc()
    d["thresholds"][0]["above"] = above
    assert parse_agents(d).thresholds[0].above == float(above)


def test_the_state_age_edge_is_a_week() -> None:
    d = doc()
    d["hooks"] = {"max_state_age_seconds": 604800}
    assert parse_agents(d).hooks.max_state_age_seconds == 604800
    d["hooks"] = {"max_state_age_seconds": 604801}
    with pytest.raises(ConfigError, match=r"hooks\.max_state_age_seconds: expected at most a week"):
        parse_agents(d)
    d["hooks"] = {"max_state_age_seconds": 59}
    with pytest.raises(ConfigError, match=r"hooks\.max_state_age_seconds: expected an integer >= 60"):
        parse_agents(d)


@pytest.mark.parametrize(
    "url", ["http://user:pw@ollama.lan:11434", "http://:pw@ollama.lan:1", "http://user@ollama.lan:1"]
)
def test_credentials_in_an_endpoint_url_are_refused_without_echo(url: str) -> None:
    d = doc()
    d["agents"]["ollama"]["endpoints"][0]["url"] = url
    with pytest.raises(ConfigError) as caught:
        parse_agents(d)
    assert "pw" not in str(caught.value).replace("expected", "") and "user" not in str(caught.value)
    assert "endpoints[0].url" in str(caught.value)


def test_a_model_pinned_but_not_allowed_is_refused_on_either_list() -> None:
    d = doc()
    d["agents"]["ollama"]["endpoints"][1]["loaded_num_ctx"]["ghost"] = 2048
    with pytest.raises(ConfigError, match=r"endpoints\[1\]\.loaded_num_ctx: 'ghost' is not an allowed model"):
        parse_agents(d)
    d = doc()
    d["agents"]["ollama"]["endpoints"][1]["on_demand_models"] = ["ghost"]
    with pytest.raises(ConfigError, match=r"endpoints\[1\]\.on_demand_models: 'ghost' is not an allowed model"):
        parse_agents(d)


def test_a_protected_model_without_a_pinned_context_is_refused_on_the_guard_endpoint() -> None:
    d = doc()
    del d["agents"]["ollama"]["endpoints"][1]["loaded_num_ctx"]["resident-safety"]
    with pytest.raises(ConfigError, match=r"endpoints\[1\]\.loaded_num_ctx: 'resident-safety' is on an endpoint"):
        parse_agents(d)


def test_a_shape_naming_a_local_model_no_endpoint_allows_warns_and_falls_back() -> None:
    d = doc()
    d["shapes"]["ci-log-summary"]["local"]["model"] = "ghost"
    parsed = parse_agents(d)
    assert parsed.shape("ci-log-summary").local_model == ""
    assert len(parsed.warnings) == 1 and "falling back" in parsed.warnings[0]
