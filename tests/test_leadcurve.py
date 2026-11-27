# SPDX-License-Identifier: Apache-2.0
"""safo lead-curve: the lead-session cost curve. Synthetic transcripts in temporary folders only."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from localcli import cli

SECRET = "SENTINEL-prompt-text-4419"
HANDOFF_TEXT = f"Read the handoff note first. {SECRET}"


def stamp(minute: int, day: int = 6) -> str:
    return f"2026-10-{day:02d}T{minute // 60:02d}:{minute % 60:02d}:00.000Z"


def turn(ident: str, ts: str, inp: int = 0, out: int = 0, read: int = 0, write: int = 0) -> dict[str, Any]:
    return {
        "type": "assistant",
        "timestamp": ts,
        "message": {
            "id": ident,
            "model": "claude-sonnet-5-5",
            "content": [{"type": "text", "text": SECRET}],
            "usage": {
                "input_tokens": inp,
                "output_tokens": out,
                "cache_read_input_tokens": read,
                "cache_creation_input_tokens": write,
            },
        },
    }


def user(text: str, ts: str) -> dict[str, Any]:
    return {"type": "user", "timestamp": ts, "message": {"role": "user", "content": text}}


def put(path: Path, rows: list[Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return path


class World:
    def __init__(self, root: Path) -> None:
        self.claude = root / "claude"
        self.claude.mkdir()
        self.home = root / "home"
        self.home.mkdir()

    def lead(self, name: str, rows: list[Any], project: str = "proj-a") -> Path:
        return put(self.claude / project / f"{name}.jsonl", rows)

    def run(self, *argv: str) -> tuple[int, str, str]:
        return cli("lead-curve", "--claude", str(self.claude), *argv, home=self.home)


@pytest.fixture
def world(tmp_path: Path) -> World:
    return World(tmp_path)


def flat(n: int, weight: int = 10, start: int = 0) -> list[Any]:
    return [turn(f"m{i}", stamp(start + i), inp=weight, read=100 * (i + 1)) for i in range(n)]


def field(out: str, prefix: str, key: str) -> float:
    for line in out.splitlines():
        if line.startswith(prefix):
            found = re.search(rf"{re.escape(key)}=([0-9.]+)", line)
            assert found, line
            return float(found.group(1))
    raise AssertionError(f"no line starting {prefix!r}")


def test_buckets_turn_count_and_context(world: World) -> None:
    world.lead("s1", flat(250))
    code, out, err = world.run()
    assert code == 0, err
    assert field(out, "session 1:", "turns") == 250
    # each turn: input 10 + cache read 0.1 * 100*(i+1)  -> bucket 0 is turns 1..100
    first = sum(10 + 0.1 * 100 * (i + 1) for i in range(100))
    second = sum(10 + 0.1 * 100 * (i + 1) for i in range(100, 200))
    assert field(out, "session 1:", "w_0_100") == pytest.approx(first, abs=1)
    assert field(out, "session 1:", "w_100_200") == pytest.approx(second, abs=1)
    assert field(out, "session 1:", "w_300_plus") == 0
    # context of a turn is input + cache read + cache write
    assert field(out, "session 1:", "ctx_first") == 110
    assert field(out, "session 1:", "ctx_last") == 10 + 100 * 250
    assert field(out, "session 1:", "ctx_cumulative") == sum(10 + 100 * (i + 1) for i in range(250))


def test_share_past_turn_200_is_by_count_and_by_weighted_spend(world: World) -> None:
    world.lead("s1", [turn(f"m{i}", stamp(i), inp=10 if i < 200 else 90) for i in range(250)])
    code, out, _ = world.run()
    assert code == 0
    line = next(x for x in out.splitlines() if x.startswith("past turn 200:"))
    assert "20.0% of lead turns" in line  # 50 of 250
    assert "69.2% of weighted spend" in line  # 4500 of 6500


def test_first_turn_where_marginal_spend_passes_one_and_a_half_times_the_early_median(world: World) -> None:
    rows = [turn(f"m{i}", stamp(i), inp=10 if i < 120 else 30) for i in range(150)]
    world.lead("s1", rows)
    code, out, _ = world.run()
    assert code == 0
    for label in ("baseline turns 1-20", "baseline turns 1-100, old definition"):
        line = next(x for x in out.splitlines() if x.startswith(f"marginal threshold [{label}]:"))
        assert "baseline_median=10.0" in line
        assert "first_turn=123" in line  # a 10 turn mean first passes 15 when 3 of its turns are heavy


def test_the_short_baseline_catches_a_climb_the_long_baseline_misses(world: World) -> None:
    # spend 10 for 20 turns, then 100 for turns 21-100, then 100: median(1..100) is 100, median(1..20) is 10
    rows = [turn(f"m{i}", stamp(i), inp=10 if i < 20 else 100) for i in range(150)]
    world.lead("s1", rows)
    _, out, _ = world.run()
    short = next(x for x in out.splitlines() if "[baseline turns 1-20]" in x)
    old = next(x for x in out.splitlines() if "old definition" in x)
    assert "first_turn=21" in short  # the first heavy turn lifts the 10-turn mean to 19, past 15
    assert "first_turn=not reached" in old


def test_threshold_not_reached_is_said_so(world: World) -> None:
    world.lead("s1", [turn(f"m{i}", stamp(i), inp=10) for i in range(150)])
    _, out, _ = world.run()
    assert out.count("first_turn=not reached") == 2


def test_cumulative_turns_at_50_and_80_percent_are_medians_across_sessions(world: World) -> None:
    world.lead("a", [turn(f"a{i}", stamp(i), inp=10) for i in range(10)])  # 50% at turn 5, 80% at turn 8
    world.lead("b", [turn(f"b{i}", stamp(100 + i), inp=10) for i in range(4)])  # 50% at turn 2, 80% at turn 4
    _, out, _ = world.run()
    line = next(x for x in out.splitlines() if x.startswith("cumulative spend"))
    assert "median across 2 sessions" in line
    assert "turn_at_50pct=3.5" in line
    assert "turn_at_80pct=6.0" in line


def test_cumulative_follows_where_the_spend_is(world: World) -> None:
    # 9 cheap turns then one turn holding 91 percent: both marks land on turn 10
    world.lead("a", [turn(f"a{i}", stamp(i), inp=1 if i < 9 else 100) for i in range(10)])
    _, out, _ = world.run()
    line = next(x for x in out.splitlines() if x.startswith("cumulative spend"))
    assert "turn_at_50pct=10.0" in line
    assert "turn_at_80pct=10.0" in line


def test_a_message_split_across_rows_counts_once_and_the_largest_output_wins(world: World) -> None:
    world.lead("s1", [turn("a", stamp(1), inp=5, out=1), turn("a", stamp(1), inp=5, out=4), turn("b", stamp(2), inp=1)])
    _, out, _ = world.run()
    assert field(out, "session 1:", "turns") == 2
    assert field(out, "session 1:", "w_0_100") == pytest.approx(5 + 20 + 1)


def test_handoff_cost_is_measured_for_the_successor_and_estimated_for_the_note(world: World) -> None:
    old = [turn(f"o{i}", stamp(i), inp=10, out=2) for i in range(9)] + [turn("o9", stamp(9), inp=10, out=300)]
    world.lead("old", old)
    new = [user(HANDOFF_TEXT, stamp(60))] + [turn(f"n{i}", stamp(61 + i), inp=1000, write=2000) for i in range(5)]
    world.lead("new", new)
    code, out, _ = world.run()
    assert code == 0
    line = next(x for x in out.splitlines() if x.startswith("handoff 1:"))
    assert "write_note_weighted=1500.0 (estimate)" in line  # 300 output tokens x 5
    assert "successor_first_3_turns_weighted=10500.0 (measured)" in line  # 3 x (1000 + 2500)
    assert "handoffs: 1" in out


def test_a_session_without_the_word_in_its_first_message_is_not_a_handoff(world: World) -> None:
    world.lead("old", [turn("o1", stamp(1), inp=10)])
    world.lead("new", [user("hello", stamp(60)), turn("n1", stamp(61), inp=10)])
    _, out, _ = world.run()
    assert "handoffs: 0" in out
    assert "handoff 1:" not in out


def test_a_handoff_word_in_a_later_message_does_not_count(world: World) -> None:
    world.lead("old", [turn("o1", stamp(1), inp=10)])
    world.lead("new", [user("hello", stamp(60)), user("the handoff", stamp(61)), turn("n1", stamp(62), inp=10)])
    _, out, _ = world.run()
    assert "handoffs: 0" in out


def test_output_has_counts_only(world: World) -> None:
    world.lead("secret-session-name", [user(HANDOFF_TEXT, stamp(1)), turn("a", stamp(2), inp=1)], project="proj-zz")
    code, out, err = world.run()
    assert code == 0
    for text in (out, err):
        assert SECRET not in text
        assert "secret-session-name" not in text
        assert "proj-zz" not in text
        assert str(world.home) not in text
        assert str(world.claude) not in text


def test_the_report_writes_nothing(world: World, tmp_path: Path) -> None:
    world.lead("s1", flat(5))
    before = sorted(str(p) for p in tmp_path.rglob("*"))
    code, _, _ = world.run()
    assert code == 0
    assert sorted(str(p) for p in tmp_path.rglob("*")) == before


def test_agents_are_not_lead_sessions(world: World) -> None:
    world.lead("s1", flat(3))
    put(world.claude / "proj-a" / "s1" / "subagents" / "agent-x.jsonl", flat(40))
    _, out, _ = world.run()
    assert "lead sessions: 1, lead turns: 3" in out


def test_a_symlinked_transcript_is_refused_and_counted(world: World, tmp_path: Path) -> None:
    real = put(tmp_path / "elsewhere.jsonl", flat(3))
    (world.claude / "proj-a").mkdir()
    (world.claude / "proj-a" / "link.jsonl").symlink_to(real)
    code, out, _ = world.run()
    assert code == 0
    assert "lead sessions: 0" in out
    assert "refused 1" in out


def test_a_week_filter_keeps_only_that_weeks_turns(world: World) -> None:
    world.lead("s1", [turn("a", stamp(1, day=6), inp=1), turn("b", stamp(2, day=13), inp=1)])
    _, out, _ = world.run("--week", "2026-W41")
    assert "lead turns: 1" in out


def test_a_bad_week_is_refused(world: World) -> None:
    code, _, err = world.run("--week", "nope")
    assert code != 0
    assert "--week" in err
