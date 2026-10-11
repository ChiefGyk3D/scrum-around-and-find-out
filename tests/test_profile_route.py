# SPDX-License-Identifier: MIT
"""Spec test 19, the degradation part: route reads the verified document; one dangling pointer degrades one agent."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from agentsdata import agents_dict, write_agents
from localcli import cli
from profiledata import claim

SNAPSHOT = Path(__file__).parent / "data" / "route_snapshot.txt"


def snapshot(home: Path, agents: Path) -> str:
    d = yaml.safe_load(agents.read_text())
    out = []
    for shape in d["shapes"]:
        for extra in ([], ["--json"]):
            code, text, err = cli("route", shape, "--agents", str(agents), "--no-usage", *extra, home=home)
            out.append(f"## {shape} {' '.join(extra)} exit={code}\n{text}{err}")
    return "".join(out)


def broken(tmp_path: Path, agent: str = "copilot") -> Path:
    d = agents_dict()
    d["agents"][agent]["profile"]["dont"] = [claim("Merge it without a review.", "lessons:no-such-lesson")]
    path = tmp_path / "agents.yaml"
    path.write_text(yaml.safe_dump(d))
    path.chmod(0o600)
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "lessons.md").write_bytes((Path(__file__).parent.parent / "docs" / "lessons.md").read_bytes())
    return path


def test_route_output_for_resolved_profiles_is_what_it_was_before_this_work(
    _private_home: Path, tmp_path: Path
) -> None:
    assert snapshot(_private_home, write_agents(tmp_path / "agents.yaml")) == SNAPSHOT.read_text()


def test_a_dangling_pointer_routes_that_agent_as_unmeasured_with_the_reason(
    _private_home: Path, tmp_path: Path
) -> None:
    path = broken(tmp_path)
    code, out, err = cli("route", "small-mechanical-pr", "--agents", str(path), "--no-usage", home=_private_home)
    assert code == 0, err
    assert "recommended: copilot" in out, "item 4 is not built: selection is unchanged"
    assert "profile: copilot is treated as unmeasured for this run: " in out
    assert "no-such-lesson" in out and "dont[0]" in out


def test_an_unrelated_shape_still_gets_its_normal_recommendation(_private_home: Path, tmp_path: Path) -> None:
    path = broken(tmp_path)
    (tmp_path / "good").mkdir()
    good = write_agents(tmp_path / "good" / "agents.yaml")
    for shape in ("research", "adversarial-review", "integration-code"):
        _, got, _ = cli("route", shape, "--agents", str(path), "--no-usage", home=_private_home)
        _, want, _ = cli("route", shape, "--agents", str(good), "--no-usage", home=_private_home)
        assert got == want, shape
        assert "unmeasured" not in got


def test_only_the_recommended_agent_is_named(_private_home: Path, tmp_path: Path) -> None:
    path = broken(tmp_path, "codex")
    _, out, _ = cli("route", "small-mechanical-pr", "--agents", str(path), "--no-usage", home=_private_home)
    assert "unmeasured" not in out, "codex is not the recommended agent for this shape"
    _, out, _ = cli("route", "research", "--agents", str(path), "--no-usage", home=_private_home)
    assert "profile: codex is treated as unmeasured" in out


def test_json_gains_a_key_only_when_an_agent_is_degraded(_private_home: Path, tmp_path: Path) -> None:
    path = broken(tmp_path)
    _, out, _ = cli("route", "small-mechanical-pr", "--agents", str(path), "--no-usage", "--json", home=_private_home)
    doc = json.loads(out)
    assert doc["agent"] == "copilot" and "no-such-lesson" in doc["profile_unverified"]["copilot"][0]
    _, out, _ = cli("route", "research", "--agents", str(path), "--no-usage", "--json", home=_private_home)
    assert "profile_unverified" not in json.loads(out)


def test_a_missing_lessons_file_degrades_every_agent_that_cites_it_and_nothing_else(
    _private_home: Path, tmp_path: Path
) -> None:
    path = write_agents(tmp_path / "agents.yaml")
    (tmp_path / "docs" / "lessons.md").unlink()
    code, out, _ = cli("route", "research", "--agents", str(path), "--no-usage", home=_private_home)
    assert code == 0 and "profile: codex is treated as unmeasured" in out
    code, out, _ = cli("route", "decision", "--agents", str(path), "--no-usage", home=_private_home)
    assert code == 0 and "unmeasured" not in out


def test_a_form_error_is_still_global(_private_home: Path, tmp_path: Path) -> None:
    d = agents_dict()
    d["agents"]["codex"]["profile"]["dont"] = [claim("x", "nonsense")]
    path = tmp_path / "agents.yaml"
    path.write_text(yaml.safe_dump(d))
    path.chmod(0o600)
    code, _, err = cli("route", "research", "--agents", str(path), "--no-usage", home=_private_home)
    assert code == 2 and "codex" in err
