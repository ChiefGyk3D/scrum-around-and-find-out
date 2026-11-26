# SPDX-License-Identifier: Apache-2.0
"""Tests for safo-eval (#484): scoring, runner with a fake llm-local on PATH, report, calibration, fixture guard."""

from __future__ import annotations

import json
import re
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest

from safo import localeval as le

FIXTURES = Path(__file__).resolve().parents[1] / "eval" / "fixtures"


def fx(**over: Any) -> le.Fixture:
    base: dict[str, Any] = {
        "id": "t/x",
        "task": "issue-draft",
        "input": "in",
        "facts": (le.Fact("alpha"), le.Fact("beta", (r"b[e3]ta\d",))),
        "forbidden": (r"\b99\b",),
        "max_chars": 100,
        "required_format": "any",
    }
    base.update(over)
    return le.Fixture(**base)


# ---- scoring


def test_full_recall_passes() -> None:
    s = le.score_output(fx(), "Alpha and beta here")
    assert s.recall == 1.0 and s.passed and not s.forbidden_hits


def test_variant_regex_counts_as_fact() -> None:
    s = le.score_output(fx(), "alpha b3ta7")
    assert s.recall == 1.0


def test_recall_threshold_boundary() -> None:
    five = fx(facts=tuple(le.Fact(w) for w in ("a1", "b2", "c3", "d4", "e5")))
    assert le.score_output(five, "a1 b2 c3 d4").passed  # 0.8 passes
    assert not le.score_output(five, "a1 b2 c3").passed  # 0.6 fails


def test_forbidden_hit_fails_even_with_full_recall() -> None:
    s = le.score_output(fx(), "alpha beta 99")
    assert s.recall == 1.0 and s.forbidden_hits and not s.passed


def test_length_bound() -> None:
    s = le.score_output(fx(max_chars=10), "alpha beta and a long tail")
    assert not s.length_ok and not s.passed


def test_json_format_checks() -> None:
    obj = fx(required_format="json-object", facts=(le.Fact("x"),), forbidden=())
    assert le.score_output(obj, '{"x": 1}').format_ok
    assert not le.score_output(obj, "x is not json").format_ok
    assert not le.score_output(obj, "[1, 2]").format_ok


def test_regex_format() -> None:
    f = fx(required_format=r"regex:^(feat|fix): ", facts=(le.Fact("x"),), forbidden=())
    assert le.score_output(f, "fix: x").format_ok
    assert not le.score_output(f, "Here you go\nfix: x").format_ok


def test_unknown_format_is_an_error() -> None:
    with pytest.raises(le.EvalError):
        le.score_output(fx(required_format="weird"), "alpha beta")


# ---- fixture loading


def _write_fixture(root: Path, task: str, name: str, doc: dict[str, Any]) -> None:
    (root / task).mkdir(parents=True, exist_ok=True)
    (root / task / f"{name}.json").write_text(json.dumps(doc), encoding="utf-8")


GOOD: dict[str, Any] = {
    "task": "commit-message",
    "input": "i",
    "facts": ["a", {"text": "b", "variants": ["b+"]}],
    "max_chars": 50,
}


def test_load_fixture_ok(tmp_path: Path) -> None:
    _write_fixture(tmp_path, "commit-message", "01", GOOD)
    (loaded,) = le.load_fixtures(tmp_path)
    assert loaded.id == "commit-message/01" and loaded.facts[1].variants == ("b+",)


@pytest.mark.parametrize(
    "bad",
    [
        {**GOOD, "task": "nope"},
        {**GOOD, "facts": []},
        {**GOOD, "forbidden": ["("]},
        {k: v for k, v in GOOD.items() if k != "max_chars"},
    ],
)
def test_bad_fixtures_rejected(tmp_path: Path, bad: dict[str, Any]) -> None:
    _write_fixture(tmp_path, "commit-message", "01", bad)
    with pytest.raises(le.EvalError):
        le.load_fixtures(tmp_path)


def test_empty_fixture_dir_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(le.EvalError):
        le.load_fixtures(tmp_path)


# ---- runner with a fake llm-local


def make_shim(tmp_path: Path, mode: str = "ok") -> Path:
    """A fake llm-local. mode: ok | busy-n (busy FAKE_BUSY_N times, then ok) | busy | fail | junk."""
    shim = tmp_path / "bin" / "llm-local"
    shim.parent.mkdir(exist_ok=True)
    shim.write_text(
        f"""#!/bin/bash
echo "$@" >> "{tmp_path}/argv.log"
readlink /proc/self/fd/0 >> "{tmp_path}/stdin.log"
mode="{mode}"
if [ "$mode" = "busy-n" ]; then
  n=$(cat "{tmp_path}/n" 2>/dev/null || echo 0)
  echo $((n+1)) > "{tmp_path}/n"
  if [ "$n" -lt "${{FAKE_BUSY_N:-2}}" ]; then exit 75; fi
fi
if [ "$mode" = "busy" ]; then exit 75; fi
if [ "$mode" = "fail" ]; then echo "boom: model not found" >&2; exit 1; fi
if [ "$mode" = "junk" ]; then echo "not json"; exit 0; fi
echo '{{"call_id": "abc123", "model": "m", "response": "alpha and beta"}}'
""",
        encoding="utf-8",
    )
    shim.chmod(shim.stat().st_mode | stat.S_IXUSR)
    return shim


def call_log(tmp_path: Path) -> Path:
    p = tmp_path / "calls.jsonl"
    p.write_text(json.dumps({"id": "abc123", "eval_tokens": 100, "seconds": 2.0}) + "\n", encoding="utf-8")
    return p


def test_run_ok_scores_and_reports_tokens_per_second(tmp_path: Path) -> None:
    exe = str(make_shim(tmp_path))
    rec = le.run_one(fx(), "qwen3.5:4b", exe=exe, call_log=call_log(tmp_path), sleep=lambda _s: None)
    assert rec["status"] == "ok" and rec["score"]["passed"] is True
    assert rec["eval_tokens"] == 100 and rec["call_seconds"] == 2.0
    argv = (tmp_path / "argv.log").read_text()
    assert "--task eval-issue-draft" in argv and "--model qwen3.5:4b" in argv and "--wait 120" in argv


def test_stdin_is_always_dev_null(tmp_path: Path) -> None:
    le.run_one(fx(), "m", exe=str(make_shim(tmp_path)), call_log=call_log(tmp_path), sleep=lambda _s: None)
    assert (tmp_path / "stdin.log").read_text().strip() == "/dev/null"


def test_subprocess_gets_devnull_stdin_and_no_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        seen.update(kw, argv=argv)
        return subprocess.CompletedProcess(argv, 0, '{"call_id": "z", "response": "alpha beta"}', "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    le.run_one(fx(), "m", call_log=Path("/nonexistent/calls.jsonl"))
    assert seen["stdin"] == subprocess.DEVNULL and not seen.get("shell") and isinstance(seen["argv"], list)


def test_busy_is_retried_with_backoff_then_succeeds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_BUSY_N", "2")
    sleeps: list[float] = []
    exe = str(make_shim(tmp_path, "busy-n"))
    rec = le.run_one(fx(), "m", exe=exe, call_log=call_log(tmp_path), sleep=sleeps.append)
    assert rec["status"] == "ok" and rec["attempts"] == 3 and sleeps == [2.0, 4.0]


def test_busy_forever_is_recorded_as_busy_not_failed(tmp_path: Path) -> None:
    sleeps: list[float] = []
    rec = le.run_one(fx(), "m", exe=str(make_shim(tmp_path, "busy")), retries=3, sleep=sleeps.append)
    assert rec["status"] == "busy" and rec["attempts"] == 4 and len(sleeps) == 3


def test_failure_is_recorded_with_reason(tmp_path: Path) -> None:
    rec = le.run_one(fx(), "m", exe=str(make_shim(tmp_path, "fail")), sleep=lambda _s: None)
    assert rec["status"] == "failed" and "boom" in rec["error"] and rec["attempts"] == 1


def test_junk_envelope_is_a_failure(tmp_path: Path) -> None:
    rec = le.run_one(fx(), "m", exe=str(make_shim(tmp_path, "junk")), sleep=lambda _s: None)
    assert rec["status"] == "failed" and "envelope" in rec["error"]


def test_missing_executable_is_a_failure(tmp_path: Path) -> None:
    rec = le.run_one(fx(), "m", exe=str(tmp_path / "nothing-here"), sleep=lambda _s: None)
    assert rec["status"] == "failed" and "error" in rec


def test_run_all_writes_jsonl_one_call_per_run(tmp_path: Path) -> None:
    exe = str(make_shim(tmp_path))
    runs = le.run_all(
        [fx(), fx(id="t/y")], ["m1", "m2"], 2, tmp_path / "o" / "runs.jsonl", exe=exe, call_log=call_log(tmp_path)
    )
    assert len(runs) == 8
    lines = (tmp_path / "o" / "runs.jsonl").read_text().splitlines()
    assert len(lines) == 8 and len((tmp_path / "stdin.log").read_text().splitlines()) == 8
    assert json.loads(lines[0])["repeat"] == 1


# ---- summary, routing, report


def rec(task: str, model: str, status: str = "ok", passed: bool = True, lat: float = 1.0) -> dict[str, Any]:
    r: dict[str, Any] = {"fixture": f"{task}/1", "task": task, "model": model, "status": status, "latency_s": lat}
    if status == "ok":
        r["output"] = "o"
        r["score"] = {
            "recall": 1.0 if passed else 0.2,
            "facts_missed": [],
            "forbidden_hits": [],
            "format_ok": True,
            "length_ok": True,
            "passed": passed,
        }
    return r


def test_summarize_counts_busy_and_failed() -> None:
    runs = [
        rec("pr-summary", "m"),
        rec("pr-summary", "m", passed=False),
        rec("pr-summary", "m", "busy"),
        rec("pr-summary", "m", "failed"),
    ]
    s = le.summarize(runs)[("pr-summary", "m")]
    assert s["busy"] == 1 and s["failed"] == 1 and s["scored"] == 3
    assert s["pass_rate"] == pytest.approx(1 / 3)


def test_all_busy_gives_no_verdict_and_routes_to_claude() -> None:
    s = le.summarize([rec("pr-summary", "m", "busy")])[("pr-summary", "m")]
    assert s["pass_rate"] is None
    assert le.tier_for({"m": s})[0] == "claude"


@pytest.mark.parametrize(
    ("rates", "tier"),
    [
        ({"qwen3.5:4b": 0.9, "gemma4:12b": 0.5}, "local-qwen"),
        ({"qwen3.5:4b": 0.5, "gemma4:12b": 1.0}, "local-gemma"),
        ({"qwen3.5:4b": 1.0, "gemma4:12b": 1.0}, "local-qwen"),
        ({"qwen3.5:4b": 0.89, "gemma4:12b": 0.6}, "local-then-claude-check"),
        ({"qwen3.5:4b": 0.59, "gemma4:12b": 0.1}, "claude"),
    ],
)
def test_tier_thresholds(rates: dict[str, float], tier: str) -> None:
    assert le.tier_for({m: {"pass_rate": r} for m, r in rates.items()})[0] == tier


def test_report_has_table_and_routing_rule() -> None:
    runs = [rec("pr-summary", "qwen3.5:4b") for _ in range(3)] + [rec("commit-message", "qwen3.5:4b", passed=False)]
    text = le.render_report(runs)
    assert "| pr-summary | qwen3.5:4b | 3 | 1.00 |" in text
    assert "## ROUTING TABLE" in text and ">= 0.9: local only" in text
    assert "| pr-summary | local-qwen |" in text and "| commit-message | claude |" in text


# ---- calibration and CLI


def test_calibration_writes_n_outputs_and_is_seedable() -> None:
    runs = [rec("pr-summary", "m") for _ in range(6)] + [rec("pr-summary", "m", "busy")]
    text = le.calibration_sample(runs, 3, seed=1)
    assert text.count("\n## ") == 3
    assert le.calibration_sample(runs, 3, seed=1) == text
    assert le.calibration_sample(runs, 50).count("\n## ") == 6  # never more than the ok runs


def test_cli_run_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "fixtures"
    _write_fixture(root, "commit-message", "01", {**GOOD, "facts": ["alpha"]})
    make_shim(tmp_path)
    monkeypatch.setenv("PATH", f"{tmp_path / 'bin'}:/usr/bin:/bin")
    out = tmp_path / "out"
    argv = ["run", "--models", "m1", "--tasks", "all", "--repeats", "2", "--out", str(out)]
    code = le.entry([*argv, "--fixtures", str(root), "--calibrate", "2"])
    assert code == 0
    assert len((out / "runs.jsonl").read_text().splitlines()) == 2
    assert "## ROUTING TABLE" in (out / "report.md").read_text()
    assert (out / "calibration.md").read_text().count("\n## ") == 2


def test_cli_rejects_unknown_task(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert le.entry(["run", "--models", "m", "--tasks", "bogus", "--out", str(tmp_path)]) == 2
    assert "unknown task" in capsys.readouterr().err


# ---- shipped fixtures guard: collect loosely, assert strictly

LEAKS = [
    re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b"),  # IPv4
    re.compile(r"claude\.ai/code|session_[0-9A-Za-z]{6,}"),  # session URLs
    re.compile(r"\b[A-Z]{1,2}[0-9][A-Z]{1,3}\b"),  # callsign-like
    re.compile(r"[\w.-]+@(?!example\.)[\w-]+\.\w+"),  # email on a non-example domain
    re.compile(r"https?://(?![\w.-]*example\.(com|org|net))[\w.-]+"),  # URL on a non-example domain
]


def leaks(text: str) -> list[str]:
    return [m.group(0) for p in LEAKS for m in p.finditer(text)]


def test_leak_scanner_bites() -> None:
    assert leaks("see 10.1.2.3") and leaks("mail bob@corp.com") and leaks("https://real.corp.net/x")
    assert leaks("callsign W1AW") and leaks("claude.ai/code/abc")
    assert not leaks("https://docs.example.com/setup and alice-example")


def test_shipped_fixtures_cover_every_task_and_are_clean() -> None:
    fixtures = le.load_fixtures(FIXTURES)
    assert len(fixtures) >= 42
    for task in le.TASKS:
        assert len([f for f in fixtures if f.task == task]) >= 6, task
    for f in fixtures:
        assert not leaks(f.input), f.id
        assert not leaks(" ".join(x.text for x in f.facts)), f.id
    assert sum(1 for f in fixtures if len(f.input) > 4000) >= 6


def test_shipped_forbidden_patterns_do_not_match_own_facts() -> None:
    for f in le.load_fixtures(FIXTURES):
        facts_text = " ".join(x.text for x in f.facts)
        for pattern in f.forbidden:
            assert not re.search(pattern, facts_text, re.IGNORECASE), (f.id, pattern)
