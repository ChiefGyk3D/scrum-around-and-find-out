# SPDX-License-Identifier: Apache-2.0
"""safo spend: the weekly spend report. Synthetic transcripts and logs in temporary folders only."""

from __future__ import annotations

import datetime as dt
import json
import os
import signal
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from localcli import cli
from safo.errors import ConfigError
from safo.modes import spend

SECRET = "SENTINEL-prompt-text-7731"
WEEK = "2026-W41"  # 2026-10-05 to 2026-10-11
MON = "2026-10-05T10:00:00.000Z"
TUE = "2026-10-06T10:00:00.000Z"
PREV_SUN = "2026-10-04T23:59:59.000Z"
NEXT_MON = "2026-10-12T00:00:01.000Z"


def msg(
    ident: str,
    ts: str,
    *,
    inp: int = 0,
    out: int = 0,
    read: int = 0,
    write: int = 0,
    model: str = "claude-sonnet-5-5",
    text: str = SECRET,
) -> dict[str, Any]:
    return {
        "type": "assistant",
        "timestamp": ts,
        "message": {
            "id": ident,
            "model": model,
            "content": [{"type": "text", "text": text}],
            "usage": {
                "input_tokens": inp,
                "output_tokens": out,
                "cache_read_input_tokens": read,
                "cache_creation_input_tokens": write,
            },
        },
    }


def put(path: Path, rows: list[Any], tail: str = "") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in rows) + tail, encoding="utf-8")
    return path


class World:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.claude = root / "claude"
        self.codex = root / "codex"
        self.home = root / "home"
        self.home.mkdir()
        self.claude.mkdir()
        self.codex.mkdir()

    def lead(self, name: str, rows: list[Any], tail: str = "") -> Path:
        return put(self.claude / "proj-a" / f"{name}.jsonl", rows, tail)

    def agent(self, session: str, ident: str, kind: str | None, rows: list[Any]) -> Path:
        base = self.claude / "proj-a" / session / "subagents"
        if kind is not None:
            base.mkdir(parents=True, exist_ok=True)
            (base / f"agent-{ident}.meta.json").write_text(json.dumps({"agentType": kind, "description": SECRET}))
        return put(base / f"agent-{ident}.jsonl", rows)

    def run(self, *argv: str, extra_env: dict[str, str] | None = None) -> tuple[int, str, str]:
        full = ["spend", "--claude", str(self.claude), "--codex", str(self.codex), *argv]
        return cli(*full, home=self.home, extra_env=extra_env)

    def report(self, *argv: str) -> dict[str, Any]:
        out = self.root / f"out-{len(list(self.root.glob('out-*.json')))}.json"
        code, _, err = self.run("--json", str(out), *argv)
        assert code == 0, err
        data: dict[str, Any] = json.loads(out.read_text())
        return data


@pytest.fixture
def world(tmp_path: Path) -> World:
    return World(tmp_path)


def standard(world: World) -> None:
    world.lead("s1", [msg("l1", MON, inp=10, out=2, read=100, write=8)])  # weighted 10 + 10 + 10 + 10 = 40
    world.agent("s1", "i1", "implementer", [msg("a1", MON, inp=100, out=10, read=1000, write=0)])  # 100+50+100 = 250
    world.agent("s1", "g1", "general-purpose", [msg("a2", TUE, out=20)])  # 100
    world.agent("s1", "r1", "reviewer", [msg("a3", TUE, inp=60)])  # 60
    world.agent("s1", "r2", "adversarial-reviewer", [msg("a4", TUE, inp=40)])  # 40, pooled with reviewer
    world.agent("s1", "x1", "transcriber", [msg("a5", TUE, inp=5)])  # 5, other
    world.agent("s1", "x2", None, [msg("a6", TUE, inp=5)])  # no meta file: other


# --- weights and pools -----------------------------------------------------------------------------------------


def test_the_weights_are_the_named_constants() -> None:
    assert (spend.WEIGHT_INPUT, spend.WEIGHT_OUTPUT, spend.WEIGHT_CACHE_READ, spend.WEIGHT_CACHE_WRITE) == (
        1.0,
        5.0,
        0.1,
        1.25,
    )
    assert spend.weighted(10, 2, 100, 8) == 40.0


def test_weighted_spend_by_pool_and_shares(world: World) -> None:
    standard(world)
    c = world.report("--week", WEEK)["claude"]
    pools = {k: v["weighted"] for k, v in c["pools"].items()}
    assert pools == {"lead": 40.0, "implementer": 250.0, "general-purpose": 100.0, "reviewer": 100.0, "other": 10.0}
    assert c["weighted_total"] == 500.0
    assert c["agents_weighted"] == 460.0
    assert c["agents_share"] == pytest.approx(0.92, abs=1e-4)
    assert c["pools"]["lead"]["share"] == pytest.approx(0.08, abs=1e-4)
    assert (c["lead_files"], c["agent_files"]) == (1, 6)


def test_cache_read_and_output_shares(world: World) -> None:
    standard(world)
    c = world.report("--week", WEEK)["claude"]
    assert c["cache_read_share_of_weighted"]["lead"] == pytest.approx(10 / 40, abs=1e-4)
    assert c["output_share_of_weighted"]["lead"] == pytest.approx(10 / 40, abs=1e-4)
    assert c["cache_read_share_of_weighted"]["agents"] == pytest.approx(100 / 460, abs=1e-4)
    assert c["output_share_of_weighted"]["agents"] == pytest.approx(150 / 460, abs=1e-4)
    assert c["cache_read_share_of_tokens"]["lead"] == pytest.approx(100 / 120, abs=1e-4)


def test_a_message_split_across_rows_counts_once_and_the_largest_output_wins(world: World) -> None:
    world.lead("s1", [msg("m", MON, out=1), msg("m", MON, out=9), msg("m", MON, out=4), msg("n", MON, out=1)])
    c = world.report("--week", WEEK)["claude"]
    assert c["pools"]["lead"]["weighted"] == (9 + 1) * spend.WEIGHT_OUTPUT
    assert c["pools"]["lead"]["messages"] == 2


def test_synthetic_and_usage_free_messages_are_not_counted(world: World) -> None:
    rows = [msg("m", MON, out=10, model="<synthetic>"), {"type": "assistant", "message": {"id": "z", "model": "x"}}]
    world.lead("s1", [*rows, msg("ok", MON, out=1)])
    assert world.report("--week", WEEK)["claude"]["pools"]["lead"]["messages"] == 1


# --- weeks -----------------------------------------------------------------------------------------------------


def test_messages_are_grouped_by_iso_week_at_the_sunday_monday_edge(world: World) -> None:
    world.lead("s1", [msg("a", PREV_SUN, out=1), msg("b", MON, out=2), msg("c", NEXT_MON, out=4)])
    c = world.report("--week", WEEK)["claude"]
    assert c["pools"]["lead"]["weighted"] == 2 * spend.WEIGHT_OUTPUT
    by_week = c["by_week_weighted"]
    assert set(by_week) == {"2026-W40", "2026-W41", "2026-W42"}
    every = world.report("--week", "all")["claude"]
    assert every["pools"]["lead"]["weighted"] == 7 * spend.WEIGHT_OUTPUT


def test_the_default_week_is_the_week_of_the_clock(world: World) -> None:
    world.lead("s1", [msg("a", MON, out=1)])
    out = world.root / "d.json"
    code, _, err = world.run("--json", str(out))
    assert code == 0, err
    assert json.loads(out.read_text())["week"] == "2026-W41"  # the test clock is 2026-10-07


@pytest.mark.parametrize("bad", ["2026-W54", "2026-41", "W41", "2026-W00", "ALL", "2026-W4x"])
def test_a_bad_week_is_refused(world: World, bad: str) -> None:
    code, _, err = world.run("--week", bad)
    assert code != 0
    assert "--week" in err


def test_a_file_last_written_before_the_week_is_not_opened(world: World) -> None:
    old = world.lead("old", [msg("a", MON, out=100)])
    world.lead("new", [msg("b", MON, out=1)])
    stamp = dt.datetime(2026, 9, 1, tzinfo=dt.UTC).timestamp()
    os.utime(old, (stamp, stamp))
    report = world.report("--week", WEEK)
    assert report["claude"]["pools"]["lead"]["weighted"] == spend.WEIGHT_OUTPUT
    assert report["skipped"]["stale_files"] == 1


# --- lead turns ------------------------------------------------------------------------------------------------


def test_lead_turns_and_the_share_past_turn_200_and_400(world: World) -> None:
    world.lead("s1", [msg(f"m{i}", MON, inp=1) for i in range(450)])
    t = world.report("--week", WEEK)["claude"]["lead_turns"]
    assert t["turns"] == 450
    assert t["weighted_per_turn"] == 1.0
    assert t["share_past_200"] == pytest.approx(250 / 450, abs=1e-4)
    assert t["share_past_400"] == pytest.approx(50 / 450, abs=1e-4)
    assert t["weighted_share_past_400"] == pytest.approx(50 / 450, abs=1e-4)


def test_turn_numbers_count_from_the_start_of_the_file_not_the_start_of_the_week(world: World) -> None:
    early = [msg(f"e{i}", PREV_SUN, inp=1) for i in range(300)]
    late = [msg(f"l{i}", MON, inp=1) for i in range(10)]
    world.lead("s1", early + late)
    t = world.report("--week", WEEK)["claude"]["lead_turns"]
    assert (t["turns"], t["share_past_200"], t["share_past_400"]) == (10, 1.0, 0.0)


# --- per merged PR ---------------------------------------------------------------------------------------------


def test_per_merged_pr_from_a_merge_list_and_not_given_without_one(world: World) -> None:
    standard(world)
    assert world.report("--week", WEEK)["per_merged_pr"] == {"given": False}
    merges = world.root / "merges.txt"
    merges.write_text("# comment\n2026-10-05\n2026-10-06\n\n2026-10-20\nnot-a-date\n2026-13-45\n")
    report = world.report("--week", WEEK, "--merges", str(merges))
    assert report["per_merged_pr"] == {"given": True, "merged_prs": 2, "weighted_per_pr": 250.0}
    assert report["skipped"]["malformed_lines"] == 2


def test_a_week_with_no_merges_has_no_per_pr_number(world: World) -> None:
    standard(world)
    merges = world.root / "merges.txt"
    merges.write_text("2026-10-20\n")
    report = world.report("--week", WEEK, "--merges", str(merges))
    assert report["per_merged_pr"] == {"given": True, "merged_prs": 0, "weighted_per_pr": None}


# --- local use -------------------------------------------------------------------------------------------------


def test_local_use_counts(world: World) -> None:
    calls = world.root / "calls.jsonl"
    put(
        calls,
        [
            {"kind": "call", "id": "a", "ts": "2026-10-06T09:00:00", "task": "triage", "status": "ok"},
            {"kind": "call", "id": "b", "ts": "2026-10-06T09:01:00", "task": "triage", "status": "ok", "project": "x"},
            {"kind": "call", "id": "c", "ts": "2026-10-06T09:02:00", "task": "eval-gemma", "status": "ok"},
            {"kind": "call", "id": "d", "ts": "2026-10-06T09:03:00", "task": "draft", "status": "failed"},
            {"kind": "call", "id": "e", "ts": "2026-10-06T09:04:00", "task": "draft", "project": "none"},
            {"kind": "outcome", "id": "a", "ts": "2026-10-06T10:00:00", "outcome": "accepted"},
            {"kind": "outcome", "id": "b", "ts": "2026-10-06T10:00:00", "outcome": "bogus"},
            {"kind": "call", "id": "f", "ts": "2026-09-01T09:00:00", "task": "triage", "status": "ok"},
            {"ts": "2026-10-06T11:00:00", "task": "smoke", "model": "m"},  # an old row without a kind
        ],
    )
    hooks = world.root / "hooks.jsonl"
    put(
        hooks,
        [
            {"ts": "2026-10-06T09:00:00", "local_step": True, "na": False},
            {"ts": "2026-10-06T09:01:00", "local_step": False, "na": True, "na_reason_class": "code"},
            {"ts": "2026-10-06T09:02:00", "local_step": False, "na": True, "na_reason_class": SECRET},
            {"ts": "2026-10-06T09:03:00", "local_step": False, "na": False},
            {"ts": "2026-08-06T09:03:00", "local_step": True, "na": False},
        ],
    )
    share = world.root / "share.jsonl"
    put(
        share,
        [
            {"ts": "2026-10-06T09:00:00.123456+00:00", "subcommand": SECRET, "exit": 0},
            {"ts": "2026-10-06T09:00:00+00:00", "subcommand": "x", "exit": 1, "outcome": "accepted", "project": "none"},
        ],
    )
    r = world.report("--week", WEEK, "--llm-local", str(calls), "--hook-log", str(hooks), "--share-log", str(share))[
        "local"
    ]
    ll = r["llm_local"]
    assert (ll["real_calls"], ll["eval_calls"], ll["failed_or_busy"], ll["calls_project_none"]) == (4, 1, 1, 3)
    assert (ll["outcome_rows"], ll["by_outcome"]) == (2, {"accepted": 1})
    d = r["dispatches"]
    assert (d["dispatches"], d["local_step"], d["marked_na"], d["with_na_reason_class"]) == (4, 1, 2, 2)
    assert d["local_step_share"] == 0.25
    assert d["na_reason_class_share"] == 0.5
    assert d["by_na_reason_class"] == {"code": 1, "invalid": 1}
    assert r["safo_draft"] == {"found": True, "calls": 2, "exit_ok": 1, "with_outcome": 1, "calls_project_none": 2}


def test_a_missing_default_log_is_reported_not_found_and_a_missing_given_one_is_an_error(world: World) -> None:
    out = world.root / "r.json"
    assert world.run("--json", str(out))[0] == 0
    assert json.loads(out.read_text())["local"]["llm_local"]["found"] is False
    code, _, err = world.run("--llm-local", str(world.root / "absent.jsonl"))
    assert code != 0
    assert "not found" in err


# --- first-turn context ----------------------------------------------------------------------------------------


def instructions(chars: int) -> dict[str, Any]:
    return {
        "type": "attachment",
        "attachment": {"type": "instructions", "files": [{"path": "p", "content": "x" * chars}]},
    }


def skills(chars: int) -> dict[str, Any]:
    return {"type": "attachment", "attachment": {"type": "skill_listing", "content": "y" * chars}}


def test_first_turn_context_and_the_instruction_and_skill_share(world: World) -> None:
    first = msg("a1", MON, inp=2, read=0, write=3498)  # context 3500 tokens, 12,250 characters at 3.5 per token
    world.agent("s1", "i1", "implementer", [instructions(2000), skills(2000), first, msg("a2", MON, inp=9000)])
    world.agent("s1", "i2", "implementer", [msg("b1", MON, inp=1000)])  # no attachments in this transcript
    f = world.report("--week", WEEK)["claude"]["agent_first_turn"]
    assert f["agents"] == 2
    assert f["median_context_tokens"] == (3500 + 1000) / 2
    assert f["agents_showing_instructions_or_skills"] == 1
    assert f["median_instruction_share"] == pytest.approx(2000 / 12250, abs=1e-3)
    assert f["median_skill_listing_share"] == pytest.approx(
        (2000 + 40) / 12250, abs=2e-3
    )  # the listing is sized as JSON
    assert f["median_instruction_and_skill_share"] > f["median_instruction_share"]


def test_attachments_after_the_first_reply_are_not_counted(world: World) -> None:
    world.agent("s1", "i1", "implementer", [msg("a1", MON, inp=100), instructions(5000)])
    f = world.report("--week", WEEK)["claude"]["agent_first_turn"]
    assert f["agents_showing_instructions_or_skills"] == 0
    assert f["median_instruction_and_skill_share"] is None


# --- Codex ------------------------------------------------------------------------------------------------------


def codex_session(world: World, name: str, ts: str, inp: int, cached: int, out: int) -> None:
    meta = {"type": "session_meta", "payload": {"timestamp": ts, "cwd": SECRET}}
    count = {
        "type": "event_msg",
        "payload": {
            "type": "token_count",
            "info": {"total_token_usage": {"input_tokens": inp, "cached_input_tokens": cached, "output_tokens": out}},
        },
    }
    put(world.codex / "2026" / "10" / "06" / f"{name}.jsonl", [meta, count, count])


def test_codex_is_counted_apart_and_never_added_to_claude(world: World) -> None:
    standard(world)
    codex_session(world, "c1", TUE, inp=1000, cached=600, out=10)
    codex_session(world, "c2", PREV_SUN, inp=5000, cached=0, out=0)  # last week
    report = world.report("--week", WEEK)
    assert report["claude"]["weighted_total"] == 500.0
    x = report["codex"]
    assert (x["sessions"], x["uncached_input"], x["cached_input"], x["output"]) == (1, 400, 600, 10)
    assert x["weighted"] == 400 + 10 * spend.WEIGHT_OUTPUT + 600 * spend.WEIGHT_CACHE_READ


# --- baseline and output files ---------------------------------------------------------------------------------


def mode_of(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_the_first_run_writes_the_baseline_0600_and_a_later_run_prints_the_change(world: World) -> None:
    standard(world)
    base = world.root / "base.json"
    code, out, err = world.run("--week", WEEK, "--baseline", str(base))
    assert code == 0, err
    assert "Baseline written" in out
    assert mode_of(base) == stat.S_IRUSR | stat.S_IWUSR
    first = base.read_bytes()
    assert json.loads(first)["metrics"]["claude.weighted_total"] == 500.0
    world.lead("s2", [msg("l9", MON, inp=500)])  # the lead pool grows by 500
    code, out, err = world.run("--week", WEEK, "--baseline", str(base))
    assert code == 0, err
    assert base.read_bytes() == first  # never rewritten
    assert "Baseline written" not in out
    assert "- claude.weighted_total: 1000 (baseline 500, change +500, +100.0%)" in out
    assert "- claude.pool.lead.weighted: 540 (baseline 40, change +500, +1250.0%)" in out
    assert "- claude.pool.implementer.weighted: 250 (baseline 250, change +0, +0.0%)" in out


def test_a_metric_the_baseline_lacks_is_marked_and_a_zero_baseline_has_no_percent(world: World) -> None:
    now = {"a": 5.0, "b": 2.0}
    lines = spend.change_lines(now, {"a": 0.0})
    assert lines == ["- a: 5 (baseline 0, change +5)", "- b: 2 (not in the baseline)"]


def test_an_existing_baseline_is_never_overwritten_even_when_it_is_not_a_baseline(world: World) -> None:
    standard(world)
    base = world.root / "base.json"
    base.write_text("not json")
    code, _, err = world.run("--week", WEEK, "--baseline", str(base))
    assert code != 0
    assert "baseline" in err
    assert base.read_text() == "not json"


@pytest.mark.parametrize(
    "document",
    [
        {"version": 2, "metrics": {}},
        {"version": 1},
        {"version": 1, "metrics": {"a": "text"}},
        {"version": 1, "metrics": {"a": True}},
        {"version": 1, "metrics": {f"k{i}": 1 for i in range(spend.MAX_BASELINE_METRICS + 1)}},
        [1, 2],
    ],
)
def test_a_baseline_with_the_wrong_shape_is_refused(world: World, document: Any) -> None:
    base = world.root / "base.json"
    base.write_text(json.dumps(document))
    code, _, err = world.run("--week", WEEK, "--baseline", str(base))
    assert code != 0
    assert "baseline" in err


def test_a_baseline_with_a_repeated_key_is_refused(world: World) -> None:
    base = world.root / "base.json"
    base.write_text('{"version": 1, "metrics": {"a": 1, "a": 2}}')
    assert world.run("--baseline", str(base))[0] != 0


def test_a_symlinked_baseline_and_a_symlinked_json_target_are_refused(world: World) -> None:
    standard(world)
    target = world.root / "target.json"
    target.write_text("{}")
    link = world.root / "link.json"
    link.symlink_to(target)
    for flag in ("--baseline", "--json"):
        code, _, _ = world.run("--week", WEEK, flag, str(link))
        assert code != 0, flag
    assert target.read_text() == "{}"
    dangling = world.root / "dangling.json"
    dangling.symlink_to(world.root / "nowhere.json")
    assert world.run("--json", str(dangling))[0] != 0
    assert not (world.root / "nowhere.json").exists()


def test_json_is_a_new_file_0600_and_an_existing_one_is_refused_before_any_scan(world: World) -> None:
    standard(world)
    out = world.root / "r.json"
    assert world.run("--week", WEEK, "--json", str(out))[0] == 0
    assert mode_of(out) == stat.S_IRUSR | stat.S_IWUSR
    before = out.read_bytes()
    code, text, err = world.run("--week", WEEK, "--json", str(out))
    assert code != 0
    assert "never overwritten" in err
    assert text == ""  # refused before anything was printed
    assert out.read_bytes() == before


def test_a_failed_write_leaves_no_half_file(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    path = world.root / "half.json"

    def broken(fd: int, data: bytes) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(spend, "write_all", broken)
    with pytest.raises(OSError):
        spend.write_new(path, "x", "the file")
    assert not path.exists()


# --- bounds ----------------------------------------------------------------------------------------------------


def test_too_many_files_stops_the_run(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    world.lead("a", [msg("a", MON, out=1)])
    world.lead("b", [msg("b", MON, out=1)])
    monkeypatch.setattr(spend, "MAX_FILES", 1)
    code, out, err = world.run("--week", WEEK)
    assert code != 0
    assert "more than 1 transcript files" in err
    assert out == ""  # no partial report


def test_a_file_over_the_byte_cap_stops_the_run_and_one_at_the_cap_does_not(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = world.lead("a", [msg("a", MON, out=1)])
    size = path.stat().st_size
    monkeypatch.setattr(spend, "MAX_FILE_BYTES", size)
    assert world.run("--week", WEEK)[0] == 0
    monkeypatch.setattr(spend, "MAX_FILE_BYTES", size - 1)
    code, out, err = world.run("--week", WEEK)
    assert code != 0
    assert "size cap" in err
    assert out == ""


def test_the_run_time_cap_stops_the_run(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    world.lead("a", [msg("a", MON, out=1)])
    monkeypatch.setattr(spend, "MAX_SECONDS", -1.0)
    code, out, err = world.run("--week", WEEK)
    assert code != 0
    assert "seconds" in err
    assert out == ""


def test_folders_nested_too_deep_stop_the_run(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    deep = world.claude / "a" / "b" / "c"
    deep.mkdir(parents=True)
    monkeypatch.setattr(spend, "MAX_DEPTH", 2)
    code, _, err = world.run("--week", WEEK)
    assert code != 0
    assert "nest deeper" in err


def test_an_over_long_line_is_counted_and_skipped_and_the_rest_is_read(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(spend, "MAX_LINE_BYTES", 2000)
    big = msg("big", MON, out=100, text="z" * 5000)
    small = msg("small", MON, out=1, text="ok")
    path = world.lead("a", [big, small, msg("small2", MON, out=2, text="ok")])
    assert max(len(line) for line in path.read_bytes().splitlines()) > 2000
    r = world.report("--week", WEEK)
    assert r["skipped"]["oversize_lines"] == 1
    assert r["claude"]["pools"]["lead"]["weighted"] == 3 * spend.WEIGHT_OUTPUT


def test_a_log_over_the_byte_cap_stops_the_run(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = put(world.root / "calls.jsonl", [{"ts": "2026-10-06T09:00:00", "task": "x"}])
    monkeypatch.setattr(spend, "MAX_LOG_BYTES", calls.stat().st_size - 1)
    code, _, err = world.run("--llm-local", str(calls))
    assert code != 0
    assert "size cap" in err


def test_a_log_with_too_many_lines_stops_the_run(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = put(world.root / "calls.jsonl", [{"ts": "2026-10-06T09:00:00"}] * 3)
    monkeypatch.setattr(spend, "MAX_LOG_LINES", 2)
    code, _, err = world.run("--llm-local", str(calls))
    assert code != 0
    assert "more lines" in err


def test_the_merge_list_has_a_size_cap(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    merges = world.root / "m.txt"
    merges.write_text("2026-10-05\n" * 10)
    monkeypatch.setattr(spend, "MAX_MERGE_BYTES", 20)
    assert world.run("--merges", str(merges))[0] != 0


# --- malformed input -------------------------------------------------------------------------------------------


def test_malformed_lines_are_skipped_and_counted(world: World) -> None:
    good = json.dumps(msg("ok", MON, out=1))
    dup = good.replace('"type": "assistant"', '"type": "assistant", "type": "user"')
    deep = '{"usage": "assistant", "x": ' + "[" * 200 + "]" * 200 + "}"
    bad_count = json.dumps(msg("neg", MON, out=1)).replace('"output_tokens": 1', '"output_tokens": -5')
    tail = (
        "\n".join(
            [
                good,
                '{"usage": "assistant", truncated',
                dup,
                deep,
                bad_count,
                "[1, 2, 3]",
                '"usage" "assistant"',
                '{"type": "assistant", "usage": NaN, "x": "assistant"}',
            ]
        )
        + "\n"
    )
    path = world.lead("a", [], tail)
    assert path.stat().st_size > 0
    r = world.report("--week", WEEK)
    assert r["claude"]["pools"]["lead"]["weighted"] == spend.WEIGHT_OUTPUT  # only the good line
    assert r["skipped"]["malformed_lines"] >= 5


def test_an_invalid_utf8_line_is_skipped(world: World) -> None:
    path = world.lead("a", [msg("ok", MON, out=1)])
    with path.open("ab") as handle:
        handle.write(b'{"usage": "assistant", "x": "\xff\xfe"}\n')
    r = world.report("--week", WEEK)
    assert r["skipped"]["malformed_lines"] == 1
    assert r["claude"]["pools"]["lead"]["messages"] == 1


def test_a_bad_meta_file_makes_the_agent_other(world: World) -> None:
    world.agent("s1", "i1", "implementer", [msg("a", MON, inp=10)])
    meta = world.claude / "proj-a" / "s1" / "subagents" / "agent-i1.meta.json"
    for body in ("{", '{"agentType": 5}', '{"agentType": {"x": 1}}', '{"agentType": "unheard-of"}', "[]"):
        meta.write_text(body)
        c = world.report("--week", WEEK)["claude"]["pools"]
        assert (c["other"]["weighted"], c["implementer"]["weighted"]) == (10.0, 0.0), body


# --- symlinks and special files --------------------------------------------------------------------------------


def test_a_symlink_inside_a_folder_is_refused_and_counted_not_read(world: World) -> None:
    secret = put(world.root / "elsewhere.jsonl", [msg("s", MON, out=999)])
    world.lead("a", [msg("ok", MON, out=1)])
    (world.claude / "proj-a" / "link.jsonl").symlink_to(secret)
    (world.claude / "linked-dir").symlink_to(world.root)
    r = world.report("--week", WEEK)
    assert r["claude"]["pools"]["lead"]["weighted"] == spend.WEIGHT_OUTPUT
    assert r["skipped"]["refused_entries"] == 2


def test_a_fifo_in_a_folder_is_refused_without_waiting(world: World) -> None:
    world.lead("a", [msg("ok", MON, out=1)])
    os.mkfifo(world.claude / "proj-a" / "pipe.jsonl")
    signal.alarm(20)  # a read that waits on the FIFO would hang here
    try:
        r = world.report("--week", WEEK)
    finally:
        signal.alarm(0)
    assert r["skipped"]["refused_entries"] == 1
    assert r["claude"]["pools"]["lead"]["messages"] == 1


def test_a_symlinked_folder_argument_is_refused(world: World) -> None:
    real = world.root / "real"
    real.mkdir()
    link = world.root / "linked"
    link.symlink_to(real)
    code, _, err = world.run("--claude", str(link))
    assert code != 0
    assert "symlink" in err


def test_a_missing_given_folder_is_an_error_and_a_missing_default_is_not(world: World) -> None:
    code, _, err = cli("spend", "--claude", str(world.root / "none"), home=world.home)
    assert code != 0
    assert "not found" in err
    out = world.root / "d.json"
    assert cli("spend", "--json", str(out), home=world.home)[0] == 0
    assert "claude" not in json.loads(out.read_text())


def test_a_symlinked_or_special_log_is_refused(world: World) -> None:
    real = put(world.root / "real.jsonl", [{"ts": "2026-10-06T09:00:00"}])
    link = world.root / "link.jsonl"
    link.symlink_to(real)
    assert world.run("--llm-local", str(link))[0] != 0
    fifo = world.root / "fifo.jsonl"
    os.mkfifo(fifo)
    signal.alarm(20)
    try:
        assert world.run("--hook-log", str(fifo))[0] != 0
    finally:
        signal.alarm(0)
    link_merges = world.root / "merges-link.txt"
    link_merges.symlink_to(real)
    assert world.run("--merges", str(link_merges))[0] != 0


def test_under_actions_a_path_inside_the_workspace_is_refused(world: World) -> None:
    env = {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(world.root)}
    for flag in ("--claude", "--llm-local", "--merges", "--baseline", "--json"):
        code, _, err = cli("spend", flag, str(world.root / "x"), home=world.home, extra_env=env)
        assert code != 0, flag
        assert "GITHUB_WORKSPACE" in err, flag


# --- nothing from a file leaks ---------------------------------------------------------------------------------


def leaks(sentinel: str, *texts: str) -> bool:
    return any(sentinel in text for text in texts)


def test_the_leak_check_bites() -> None:
    assert leaks(SECRET, "a line with SENTINEL-prompt-text-7731 in it")
    assert not leaks(SECRET, "clean")


def test_no_content_label_or_path_reaches_the_output_or_the_files(world: World) -> None:
    secret_dir = world.claude / f"proj-{SECRET}"
    put(secret_dir / f"{SECRET}.jsonl", [msg("l1", MON, inp=1, model=f"model-{SECRET}", text=SECRET)])
    agent_dir = secret_dir / f"{SECRET}" / "subagents"
    put(agent_dir / "agent-z.jsonl", [instructions(10), msg("a1", MON, inp=1, text=SECRET)])
    (agent_dir / "agent-z.meta.json").write_text(json.dumps({"agentType": SECRET, "description": SECRET}))
    codex_session(world, f"cx-{SECRET}", TUE, 10, 5, 1)
    calls = put(
        world.root / f"calls-{SECRET}.jsonl",
        [
            {
                "kind": "call",
                "ts": "2026-10-06T09:00:00",
                "task": SECRET,
                "model": SECRET,
                "project": SECRET,
                "id": SECRET,
            },
            {"kind": "outcome", "ts": "2026-10-06T09:00:00", "outcome": SECRET, "id": SECRET},
        ],
    )
    hooks = put(world.root / "hooks.jsonl", [{"ts": "2026-10-06T09:00:00", "na_reason_class": SECRET, "model": SECRET}])
    share = put(world.root / "share.jsonl", [{"ts": "2026-10-06T09:00:00", "subcommand": SECRET, "outcome": SECRET}])
    merges = world.root / f"merges-{SECRET}.txt"
    merges.write_text(f"2026-10-05\n{SECRET}\n")
    base = world.root / f"base-{SECRET}.json"
    out = world.root / f"out-{SECRET}.json"
    argv = (
        "--week",
        WEEK,
        "--llm-local",
        str(calls),
        "--hook-log",
        str(hooks),
        "--share-log",
        str(share),
        "--merges",
        str(merges),
        "--baseline",
        str(base),
        "--json",
        str(out),
    )
    assert SECRET in secret_dir.name and SECRET in calls.read_text()  # the inputs really carry it
    code, first, err = world.run(*argv)
    assert code == 0, err
    out.unlink()
    code, second, err = world.run(*argv)  # the second run prints the change lines
    assert code == 0, err
    assert "Change since the baseline" in second
    assert not leaks(SECRET, first, second, err, out.read_text(), base.read_text())
    # a bad baseline path and bad inputs say nothing of the path or the content either
    bad = world.root / f"bad-{SECRET}.json"
    bad.write_text(SECRET)
    code, text, err = world.run("--baseline", str(bad))
    assert code != 0
    assert not leaks(SECRET, text, err)


def test_output_lines_carry_no_workflow_command(world: World) -> None:
    standard(world)
    code, out, _ = world.run("--week", WEEK)
    assert code == 0
    assert "::" not in out


def test_the_report_has_every_section_in_text(world: World) -> None:
    standard(world)
    code, out, err = world.run("--week", WEEK)
    assert code == 0, err
    for heading in (
        "# Spend report, 2026-W41",
        "## Weighted spend by pool",
        "## Shares",
        "## Lead turns",
        "## Per merged PR",
        "## Agent first-turn context",
        "## Codex (counted apart, never added to Claude)",
        "## Local use",
    ):
        assert heading in out, heading
    assert "not given" in out


@pytest.fixture(autouse=True)
def _no_alarm() -> Iterator[None]:
    yield
    signal.alarm(0)


def test_the_exclusive_create_refuses_a_file_that_appears_after_the_early_check(tmp_path: Path) -> None:
    path = tmp_path / "late.json"
    path.write_text("theirs")
    with pytest.raises(ConfigError, match="never overwritten"):
        spend.write_new(path, "mine", "the file")
    assert path.read_text() == "theirs"
