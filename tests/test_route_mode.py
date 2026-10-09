# SPDX-License-Identifier: MIT
"""route: rules plus live headroom, through the command line."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentsdata import A_MODELS, B_MODELS, write_agents
from fakeollama import FakeOllama
from localcli import cli
from meterdata import codex_session, token_count


def test_route_recommends_from_live_headroom_and_dispatches_nothing(_private_home: Path, tmp_path: Path) -> None:
    codex_session(_private_home, "a", [token_count(83, 10)])
    with FakeOllama(A_MODELS, A_MODELS).serve() as a, FakeOllama(B_MODELS, []).serve() as b:
        agents = write_agents(tmp_path / "agents.yaml", a.url, b.url)
        code, out, _ = cli("route", "research", "--agents", str(agents), home=_private_home)
        assert a.generates == [] and b.generates == []
    assert code == 0
    assert "recommended: claude-sonnet (put Agent = Claude on the card)" in out
    assert "codex: the 5-hour window is at 83%, above 80%" in out
    assert "safo route only recommends" in out


def test_route_names_the_local_endpoint_and_the_command(_private_home: Path, tmp_path: Path) -> None:
    with FakeOllama(A_MODELS, A_MODELS).serve() as a, FakeOllama(B_MODELS, B_MODELS).serve() as b:
        agents = write_agents(tmp_path / "agents.yaml", a.url, b.url)
        code, out, _ = cli("route", "ci-log-summary", "--agents", str(agents), home=_private_home)
        assert b.generates == [], "the guard endpoint's card is never used"
    assert code == 0 and "local: endpoint instance-a, model small-4b-agent" in out
    assert "safo local run --shape ci-log-summary" in out and "reviewer: claude-sonnet" in out


def test_route_falls_back_when_the_endpoints_are_unreachable(_private_home: Path, tmp_path: Path) -> None:
    agents = write_agents(tmp_path / "agents.yaml")
    code, out, _ = cli("route", "ci-log-summary", "--agents", str(agents), home=_private_home)
    assert code == 0 and "recommended: claude-haiku" in out


def test_route_lists_shapes_and_rejects_an_unknown_one(_private_home: Path, tmp_path: Path) -> None:
    agents = write_agents(tmp_path / "agents.yaml")
    code, out, _ = cli("route", "--list", "--agents", str(agents), "--no-usage", home=_private_home)
    assert code == 0 and "ci-log-summary" in out and "research" in out
    code, _, err = cli("route", "nope", "--agents", str(agents), "--no-usage", home=_private_home)
    assert code == 2 and "has no shape 'nope'" in err


def test_the_local_override_file_in_home_is_merged_over_the_example(_private_home: Path, tmp_path: Path) -> None:
    config = _private_home / ".config" / "safo"
    config.mkdir(parents=True)
    with FakeOllama(["small-7b", "embed-small"], []).serve() as lab:
        (config / "agents.local.yaml").write_text(
            "agents:\n  ollama:\n    endpoints:\n"
            f"      - {{id: lab, url: '{lab.url}', roles: [general, embedding],\n"
            "         models: [small-7b, embed-small], num_ctx_max: 4096}\n"
        )
        agents = write_agents(tmp_path / "agents.yaml")
        code, out, _ = cli("route", "ci-log-summary", "--agents", str(agents), home=_private_home)
    assert code == 0 and "local: endpoint lab, model small-7b" in out
    assert "warning:" in out and "'small-4b-agent' is not an allowed model of any general endpoint" in out


def test_route_cli_uses_validated_ai_credit_meter_above_threshold(_private_home: Path, tmp_path: Path) -> None:
    import json

    meter = tmp_path / "credits.json"
    meter.write_text(
        json.dumps(
            {
                "product": "GitHub Copilot",
                "sku": "Copilot AI credits",
                "unit": "ai_credits",
                "month": "2026-10",
                "used": 6500,
            }
        )
    )
    agents = write_agents(tmp_path / "agents.yaml")
    code, out, _ = cli(
        "route",
        "small-mechanical-pr",
        "--agents",
        str(agents),
        "--no-usage",
        "--copilot-meter",
        str(meter),
        "--json",
        home=_private_home,
    )
    assert code == 0
    rec = json.loads(out)
    assert rec["agent"] != "copilot" and any("month" in reason for reason in rec["skipped"])


def test_route_json_contains_warnings_as_one_document(_private_home: Path, tmp_path: Path) -> None:
    import json

    import yaml

    from agentsdata import agents_dict

    data = agents_dict()
    data["shapes"]["ci-log-summary"]["local"]["model"] = "missing-pinned-model"
    path = tmp_path / "agents.yaml"
    path.write_text(yaml.safe_dump(data))
    code, out, _ = cli("route", "ci-log-summary", "--agents", str(path), "--json", "--no-usage", home=_private_home)
    assert code == 0 and json.loads(out)["warnings"]


def test_route_never_reads_an_agents_file_from_the_current_directory(
    _private_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with FakeOllama(A_MODELS, A_MODELS).serve() as a, FakeOllama(B_MODELS, B_MODELS).serve() as b:
        checkout = tmp_path / "checkout"
        checkout.mkdir()
        write_agents(checkout / "agents.yaml", a.url, b.url)
        monkeypatch.chdir(checkout)
        code, out, err = cli("route", "ci-log-summary", home=_private_home)
        assert code == 2 and "agents" in err and out == ""
        assert a.requests == [] and b.requests == []
