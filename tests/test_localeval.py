# SPDX-License-Identifier: Apache-2.0
"""Tests for safo-eval (#484): scoring, runner with a fake llm-local on PATH, report, calibration, fixture guard."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from safo import localeval as le

FIXTURES = Path(__file__).resolve().parents[1] / "eval" / "fixtures"


def fx(**over: Any) -> le.Fixture:
    base: dict[str, Any] = {
        "id": "t/x",
        "task": "commit-message",
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
    assert le.score_output(five, "see a1 b2 c3 d4 now").passed  # 0.8 passes
    assert not le.score_output(five, "see a1 b2 c3 now").passed  # 0.6 fails


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


def tri() -> le.Fixture:  # a json-object fixture
    return fx(task="issue-triage", required_format="json-object", facts=(le.Fact("x"),), forbidden=())


FENCED = '```json\n{"x": 1}\n```'


def test_one_outer_fence_is_stripped_and_flagged() -> None:
    for out in (FENCED, '\n  ```\n{"x": 1}\n```  \n', '```JSON5\n{"x": 1}\n```'):
        s = le.score_output(tri(), out)
        assert s.format_ok and s.passed and s.fenced, out


def test_unfenced_json_passes_with_fenced_false() -> None:
    s = le.score_output(tri(), '{"x": 1}')
    assert s.format_ok and s.passed and not s.fenced


@pytest.mark.parametrize(
    "out",
    [
        'Here you go:\n```json\n{"x": 1}\n```',
        '```json\n{"x": 1}\n```\nHope that helps',
        '```json\n{"x": 1}\n```\n```json\n{"x": 1}\n```',
        '```json\n{"x": 1}',
        '```json {"x": 1} ```',
    ],
)
def test_anything_else_around_the_fence_fails(out: str) -> None:
    s = le.score_output(tri(), out)
    assert not s.format_ok and not s.passed


def test_fence_is_not_stripped_for_non_json_formats() -> None:
    s = le.score_output(fx(required_format="any"), "```\nalpha beta\n```")
    assert s.format_ok and not s.fenced


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
echo '{{"call_id": "abc123", "model": "m", "response": "alpha and beta are here today"}}'
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
    assert "--task eval-commit-message" in argv and "--model qwen3.5:4b" in argv and "--wait 120" in argv


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
    stats = {m: {"pass_rate": r, "ci_low": r} for m, r in rates.items()}
    assert le.tier_for(stats, {m: CAL_OK for m in rates})[0] == tier


CAL_OK = le.agreement(35, 0)  # a calibrated cell: 35 ok verdicts, 0 wrong


def test_few_runs_cannot_qualify_on_luck() -> None:
    # 2 of 2 passes is a 1.00 rate but the Wilson lower bound is about 0.34: claude, not local
    s = le.summarize([rec("pr-summary", "qwen3.5:4b"), rec("pr-summary", "qwen3.5:4b")])[("pr-summary", "qwen3.5:4b")]
    assert s["pass_rate"] == 1.0 and s["ci_low"] < 0.4
    assert le.tier_for({"qwen3.5:4b": s})[0] == "claude"
    many = le.summarize([rec("pr-summary", "qwen3.5:4b") for _ in range(60)])[("pr-summary", "qwen3.5:4b")]
    assert (
        many["ci_low"] >= le.LOCAL_MIN and le.tier_for({"qwen3.5:4b": many}, {"qwen3.5:4b": CAL_OK})[0] == "local-qwen"
    )


def test_wilson_interval_known_values() -> None:
    lo, hi = le.wilson(5, 10)
    assert (round(lo, 3), round(hi, 3)) == (0.237, 0.763)
    assert le.wilson(0, 0) == (0.0, 1.0)
    lo, hi = le.wilson(10, 10)
    assert hi == pytest.approx(1.0) and round(lo, 3) == 0.722


def test_report_has_table_and_routing_rule() -> None:
    runs = [rec("pr-summary", "qwen3.5:4b") for _ in range(40)] + [rec("commit-message", "qwen3.5:4b", passed=False)]
    text = le.render_report(runs, {("pr-summary", "qwen3.5:4b"): CAL_OK})
    assert "| pr-summary | qwen3.5:4b | 40 | 1.00 |" in text
    assert "## ROUTING TABLE" in text and "and calibrated" in text and "local only (local-qwen" in text
    assert "| pr-summary | local-qwen |" in text and "| commit-message | claude |" in text


def test_report_shows_fenced_share_and_confidence() -> None:
    runs = [rec("issue-triage", "m") for _ in range(4)]
    for r in runs[:3]:
        r["score"]["fenced"] = True
    text = le.render_report(runs)
    assert "| fenced |" in text and "| 95% CI |" in text
    assert "| issue-triage | m | 4 | 1.00 | [0.51, 1.00] | 1.00 | 0.75 |" in text
    assert "lower bound" in text


def test_rescore_recomputes_scores_without_calling_the_model(tmp_path: Path) -> None:
    root = tmp_path / "fx"
    _write_fixture(
        root,
        "issue-triage",
        "01",
        {"task": "issue-triage", "input": "i", "facts": ["x"], "max_chars": 100, "required_format": "json-object"},
    )
    old = rec("issue-triage", "m")
    old["fixture"] = "issue-triage/01"
    old["output"] = FENCED
    old["score"]["passed"] = False
    old["score"]["format_ok"] = False
    runs_in = tmp_path / "runs.jsonl"
    runs_in.write_text(json.dumps(old) + "\n", encoding="utf-8")
    out = tmp_path / "o"
    assert le.entry(["report", "--runs", str(runs_in), "--out", str(out), "--rescore", "--fixtures", str(root)]) == 0
    new = json.loads((out / "runs-rescored.jsonl").read_text().splitlines()[0])
    assert new["score"]["passed"] and new["score"]["fenced"]
    assert "| issue-triage | m | 1 | 1.00 |" in (out / "report-rescored.md").read_text()
    assert json.loads(runs_in.read_text())["score"]["passed"] is False  # input untouched


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
    assert len(fixtures) == FIXTURE_TOTAL
    for task in le.TASKS:
        assert len([f for f in fixtures if f.task == task]) == FIXTURE_COUNT[task], task
    for f in fixtures:
        assert not leaks(f.input), f.id
        assert not leaks(" ".join(x.text for x in f.facts)), f.id
    assert sum(1 for f in fixtures if len(f.input) > 4000) >= 6


def test_shipped_forbidden_patterns_do_not_match_own_facts() -> None:
    for f in le.load_fixtures(FIXTURES):
        facts_text = " ".join(x.text for x in f.facts)
        for pattern in f.forbidden:
            assert not re.search(pattern, facts_text, re.IGNORECASE), (f.id, pattern)


# ---- hardened scoring (#484 round 3): word boundaries, structure, copying, facts-only


def test_numeric_and_short_facts_match_on_word_boundaries() -> None:
    f = fx(facts=(le.Fact("60"), le.Fact("137"), le.Fact("Z"), le.Fact("Install")), max_chars=500)
    s = le.score_output(f, "limit is 600 and exit 1370 on a zebra with Uninstall steps")
    assert s.facts_missed == ["60", "137", "Z", "Install"] and not s.passed
    ok = le.score_output(f, "limit is 60 and exit 137 with a trailing Z then Install steps")
    assert ok.recall == 1.0


def test_input_copy_ratio_counts_verbatim_lines_and_shingles() -> None:
    src = "alpha beta gamma delta epsilon zeta\nsecond line of the input text here"
    assert le.copy_ratio(src, src) == 1.0
    assert le.copy_ratio(src, "- alpha beta gamma delta epsilon zeta\nsomething entirely new and different here") == 0.5
    assert le.copy_ratio(src, "nothing in common with it at all, truly") == 0.0
    # a paraphrase that reuses a long run of words is caught by the shingles even when it is one new line
    long_in = "one two three four five six seven eight nine ten eleven twelve"
    assert le.copy_ratio(long_in, "the one two three four five six seven eight nine ten bit") > 0.5


def test_facts_only_guard_needs_connecting_words() -> None:
    f = fx(facts=(le.Fact("alpha"), le.Fact("beta"), le.Fact("gamma")))
    assert le.facts_only(f, "alpha beta gamma")
    assert le.facts_only(f, "alpha, beta; gamma")
    assert not le.facts_only(f, "alpha broke because beta and gamma disagree")


def test_echo_of_input_fails_with_copy_reason() -> None:
    f = fx(
        task="issue-draft", input="Title here\nbody line one is here\nbody line two is here", facts=(le.Fact("body"),)
    )
    s = le.score_output(f, f.input)
    assert not s.passed and "copy" in s.reasons


STRUCT_GOOD: dict[str, tuple[str, str]] = {
    "issue-draft/01-session-timeout": (
        "Session timeout shorter than configured\n"
        "- Users on app.example.com are signed out after 15 minutes, while 60 is expected.\n"
        "- The key session_ttl_minutes in auth.yaml controls it; seen in v2.4.1.",
        "",
    ),
    "issue-triage/01-clear-bug": ('{"label": "bug", "epic": "E1-auth"}', ""),
    "ci-log-digest/01-pytest-fail": (
        "pytest reported 1 failed test: test_invoice_rounding in tests/test_billing.py.\n"
        "The assertion compared 10.05 with 10.04 because invoice rounding looks wrong.\n"
        "The run ended with a non-zero status.",
        "",
    ),
    "pr-summary/01-rename": (
        "Rename load() to load_config(path) so the file to read is passed in.\n"
        "- load_config takes a path and opens it with a context manager.\n"
        "- Updated 3 call sites in cli.py.",
        "",
    ),
    "commit-message/01-fix": (
        "fix: strip the trailing Z in parse_date\n\nISO dates ending in Z returned None. The Z is now removed first.",
        "",
    ),
    "first-pass-review-comment/01-off-by-one": (
        "last_n has an off-by-one error: the slice starts one index too late so it drops the first requested item.",
        "",
    ),
    "doc-skeleton/01-install": (
        "# Installing example-tool\n## Prerequisites\nWhat you need before installing.\n## Install\nHow to install the "
        "CLI.\n## Verify\nHow to check it works.\n## Uninstall\nHow to remove it.",
        "",
    ),
}


def shipped() -> dict[str, le.Fixture]:
    return {f.id: f for f in le.load_fixtures(FIXTURES)}


def test_a_hand_written_good_answer_passes_for_every_task() -> None:
    by_id = shipped()
    assert {by_id[k].task for k in STRUCT_GOOD} == set(le.TASKS)
    for fid, (out, _) in STRUCT_GOOD.items():
        s = le.score_output(by_id[fid], out)
        assert s.passed, (fid, s)


@pytest.mark.parametrize(
    ("fid", "out"),
    [
        ("issue-draft/01-session-timeout", "Session timeout 15 minutes 60 v2.4.1 session_ttl_minutes"),  # no title+body
        ("issue-draft/01-session-timeout", "T" * 90 + "\n- 15 minutes, 60, v2.4.1\n- session_ttl_minutes is the key"),
        ("pr-summary/01-rename", "Rename\n\nMore text\n- load_config path\n- cli.py 3"),  # not one paragraph
        ("pr-summary/01-rename", "Summary of load_config with a path in cli.py 3 places"),  # no bullets
        ("ci-log-digest/01-pytest-fail", "\n".join(["line"] * 7)),
        (
            "ci-log-digest/01-pytest-fail",
            "1 failed\n1 failed in the log\n1 failed\n1 failed\n1 failed\n1 failed\n1 failed",
        ),
        ("first-pass-review-comment/01-off-by-one", "a\nb\nc\nlast_n off-by-one"),
        ("first-pass-review-comment/01-off-by-one", "This is off-by-one. It is in last_n though."),  # split sentences
        ("doc-skeleton/01-install", "# Prerequisites\n# Install\n# Verify\n# Uninstall"),
        (
            "doc-skeleton/01-install",
            "# Title\n## Prerequisites\nx y z\n## Install\n## Verify\nx y z\n## Uninstall\nx y z",
        ),
    ],
)
def test_structure_rules_bite(fid: str, out: str) -> None:
    s = le.score_output(shipped()[fid], out)
    assert not s.passed, s


def test_ci_digest_may_not_quote_a_log_line() -> None:
    f = shipped()["ci-log-digest/01-pytest-fail"]
    quoted = (
        "FAILED tests/test_billing.py::test_invoice_rounding - AssertionError: assert 10.05 == 10.04\n"
        "That is test_billing.py and test_invoice_rounding, 1 failed, 10.05 and 10.04 differ."
    )
    s = le.score_output(f, quoted)
    assert not s.passed and "structure" in s.reasons


def gaming(kind: str, f: le.Fixture) -> str:
    texts = [x.text for x in f.facts]
    if kind == "echo":
        return f.input
    if kind == "facts":
        return " ".join(texts)
    return "\n".join(f"# {t}" for t in texts)


# fixtures shipped per task (#484): every task has 20, 140 in all
FIXTURE_COUNT: dict[str, int] = {task: 20 for task in le.TASKS}
FIXTURE_TOTAL = sum(FIXTURE_COUNT.values())


@pytest.mark.parametrize("kind", ["echo", "facts", "headings"])
def test_gaming_shims_pass_no_fixture_per_task(kind: str) -> None:
    fixtures = le.load_fixtures(FIXTURES)
    assert len(fixtures) == FIXTURE_TOTAL
    for task in le.TASKS:
        mine = [f for f in fixtures if f.task == task]
        assert len(mine) == FIXTURE_COUNT[task], task
        passed = [f.id for f in mine if le.score_output(f, gaming(kind, f)).passed]
        assert passed == [], (kind, task, passed)  # measured: each of these shims passes 0


def test_gaming_guard_bites_on_a_loose_fixture() -> None:
    # the shims do pass a fixture that has no structure, copy or facts-only rule: the test above is not vacuous
    loose = fx(task="issue-triage", required_format="any", facts=(le.Fact("alpha"),), forbidden=())
    assert le.score_output(loose, "alpha").passed


def test_every_fixture_lists_two_wrong_outputs_and_none_passes() -> None:
    fixtures = le.load_fixtures(FIXTURES)
    assert len(fixtures) == FIXTURE_TOTAL
    for f in fixtures:
        assert len(f.wrong) >= 2, f.id
        for w in f.wrong:
            s = le.score_output(f, w)
            assert not s.passed, (f.id, w, s)


@pytest.mark.parametrize(
    ("fid", "wrong"),
    [
        ("first-pass-review-comment/03-unclosed-file", "read_cfg: variable name conflicts with a builtin, rename it."),
        ("first-pass-review-comment/01-off-by-one", "last_n: typo in the docstring +1 line missing."),
        (
            "first-pass-review-comment/04-mutable-default",
            "add_tag: the default value of tag is unclear, add a type hint.",
        ),
        ("first-pass-review-comment/06-wrong-compare", "is_adult: >= is faster than other operators in general."),
        ("commit-message/01-fix", "fix: parse_date returns None for zebra dates\n\nSwitched the zebra handling."),
        (
            "ci-log-digest/03-noisy",
            "build-linux died with exit 1370 after 4120 s of out of memory heartbeat noise.",
        ),
    ],
)
def test_reviewer_found_wrong_outputs_fail(fid: str, wrong: str) -> None:
    assert not le.score_output(shipped()[fid], wrong).passed


# ---- private result files (E3)


def mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


def test_cli_results_are_owner_only_even_with_a_022_umask_and_an_existing_0644_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "fixtures"
    _write_fixture(root, "commit-message", "01", {**GOOD, "facts": ["alpha"]})
    make_shim(tmp_path)
    monkeypatch.setenv("PATH", f"{tmp_path / 'bin'}:/usr/bin:/bin")
    out = tmp_path / "deep" / "out"
    pre = tmp_path / "pre"
    pre.mkdir(mode=0o755)
    old = os.umask(0o022)
    try:
        (pre / "report.md").write_text("old", encoding="utf-8")
        (pre / "report.md").chmod(0o644)
        argv = ["run", "--models", "m", "--tasks", "all", "--repeats", "1", "--fixtures", str(root), "--calibrate", "1"]
        assert le.entry([*argv, "--out", str(out)]) == 0
        assert le.entry([*argv, "--out", str(pre)]) == 0
        runs_in = out / "runs.jsonl"
        assert (
            le.entry(
                ["report", "--runs", str(runs_in), "--out", str(tmp_path / "r1"), "--rescore", "--fixtures", str(root)]
            )
            == 0
        )
        assert le.entry(["calibrate", "--runs", str(runs_in), "--n", "1", "--out", str(tmp_path / "cal" / "d")]) == 0
    finally:
        os.umask(old)
    assert mode(out) == 0o700 and mode(out.parent) == 0o700 and mode(tmp_path / "r1") == 0o700
    assert mode(tmp_path / "cal" / "d") == 0o700
    for p in [*out.iterdir(), *(tmp_path / "r1").iterdir(), *(tmp_path / "cal" / "d").iterdir(), pre / "report.md"]:
        assert mode(p) == 0o600, p
    assert (pre / "report.md").read_text() != "old"
    assert len(list(out.iterdir())) == 3 and len(list((tmp_path / "r1").iterdir())) == 2


def test_results_never_follow_a_symlink(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "fixtures"
    _write_fixture(root, "commit-message", "01", {**GOOD, "facts": ["alpha"]})
    make_shim(tmp_path)
    monkeypatch.setenv("PATH", f"{tmp_path / 'bin'}:/usr/bin:/bin")
    victim = tmp_path / "victim.txt"
    victim.write_text("keep", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    (out / "report.md").symlink_to(victim)
    argv = ["run", "--models", "m", "--repeats", "1", "--fixtures", str(root)]
    assert le.entry([*argv, "--out", str(out)]) == 2
    assert victim.read_text() == "keep"
    linkdir = tmp_path / "linkdir"
    linkdir.symlink_to(tmp_path / "out")
    assert le.entry([*argv, "--out", str(linkdir)]) == 2


# ---- timestamps and time-of-day buckets (E4)


def test_run_record_has_utc_timestamp_hour_and_busy_retries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_BUSY_N", "2")
    exe = str(make_shim(tmp_path, "busy-n"))

    def clock() -> datetime:
        return datetime(2026, 11, 26, 14, 3, 9, tzinfo=UTC)

    r = le.run_one(fx(), "m", exe=exe, call_log=call_log(tmp_path), sleep=lambda _s: None, clock=clock)
    assert r["ts"] == "2026-11-26T14:03:09Z" and r["hour_utc"] == 14 and r["busy_retries"] == 2
    (tmp_path / "x").mkdir()
    ok = le.run_one(fx(), "m", exe=str(make_shim(tmp_path / "x")), call_log=call_log(tmp_path), clock=clock)
    assert ok["busy_retries"] == 0


def test_time_bucket_table_shows_n_and_refuses_small_samples() -> None:
    runs = [rec("pr-summary", "m", lat=2.0, passed=i % 2 == 0) | {"hour_utc": 9, "busy_retries": 1} for i in range(10)]
    runs += [rec("pr-summary", "m") | {"hour_utc": 13, "ts": "2026-11-26T13:00:00Z"} for _ in range(3)]
    runs += [rec("pr-summary", "m")]  # a legacy row: no ts, no hour
    text = le.render_report(runs)
    assert "## TIME OF DAY (UTC, 4-hour buckets)" in text
    assert "| m | 08-12 UTC | 10 | 0.50 | 2.0 | 10 |" in text
    assert "| m | 12-16 UTC | 3 | too few | too few | 0 |" in text
    assert "| m | unknown | 1 | too few | too few | 0 |" in text


def test_hour_is_derived_from_ts_when_missing() -> None:
    r = rec("pr-summary", "m") | {"ts": "2026-11-26T23:59:59Z"}
    assert le.hour_of(r) == 23 and le.hour_of(rec("pr-summary", "m")) is None


def test_rescore_of_legacy_rows_without_ts_still_works(tmp_path: Path) -> None:
    root = tmp_path / "fx"
    _write_fixture(root, "issue-triage", "01", {"task": "issue-triage", "input": "i", "facts": ["x"], "max_chars": 100})
    old = rec("issue-triage", "m") | {"fixture": "issue-triage/01", "output": "x marks"}
    runs_in = tmp_path / "runs.jsonl"
    runs_in.write_text(json.dumps(old) + "\n", encoding="utf-8")
    assert (
        le.entry(["report", "--runs", str(runs_in), "--out", str(tmp_path / "o"), "--rescore", "--fixtures", str(root)])
        == 0
    )
    assert "| m | unknown | 1 |" in (tmp_path / "o" / "report-rescored.md").read_text()


# ---- round 5 (#484): tighter scorers, widened variants, calibration gate


def test_hour_of_rejects_a_json_bool() -> None:
    assert le.hour_of({"hour_utc": True}) is None and le.hour_of({"hour_utc": False}) is None
    assert le.hour_of({"hour_utc": 1}) == 1 and le.hour_of({"hour_utc": 0}) == 0
    assert le._bucket(le.hour_of({"hour_utc": True})) == "unknown"


def test_two_character_facts_are_case_sensitive() -> None:
    f = fx(facts=(le.Fact("Id"),), forbidden=(), max_chars=200)
    assert le.score_output(f, "the Id column is empty").recall == 1.0
    assert le.score_output(f, "the id column is empty").recall == 0.0  # lowercase variant must not count
    long = fx(facts=(le.Fact("Idx"),), forbidden=(), max_chars=200)
    assert le.score_output(long, "the idx column").recall == 1.0  # three characters: case-insensitive again


def test_doc_skeleton_exact_requires_the_stated_version() -> None:
    f = shipped()["doc-skeleton/05-exact"]
    assert "3.7" in [x.text for x in f.facts]
    no_version = (
        "# Release process\n## Versioning\nHow versions work.\n## Tagging\nHow tags work.\n"
        "## Publishing\nHow to publish."
    )
    assert not le.score_output(f, no_version).passed
    assert le.score_output(f, no_version.replace("Release process", "Release process v3.7")).passed


def test_every_must_copy_value_stated_in_an_input_is_a_required_fact() -> None:
    for f in le.load_fixtures(FIXTURES):
        if re.search(r"copy exactly|must be copied|exactly as", f.input, re.IGNORECASE):
            value = re.search(r"\b(?:v)?(\d+(?:\.\d+)+)\b", f.input)
            assert value is not None, f.id
            # the value itself, or the exact token the input says to copy when it is a path such as release/6.2.0
            texts = [x.text for x in f.facts]
            assert any(t == value.group(1) or t.endswith("/" + value.group(1)) for t in texts), f.id


def shim_b(f: le.Fixture) -> str:
    t = [x.text for x in f.facts]
    return f"The change fixes {', '.join(t[:-1])}, and {t[-1]}." if len(t) > 1 else f"The change fixes {t[0]}."


SHAPE: dict[str, str] = {  # the right shape with placeholder text; {f} stands for the facts
    "issue-draft": "Placeholder title for this report\n- Placeholder body sentence about the report.\n- Details: {f}.",
    "issue-triage": '{{"label": "x", "epic": "y", "note": "{f}"}}',
    "ci-log-digest": "A generic summary of the job output goes here. It names what stopped and why, because of {f}.",
    "pr-summary": "Placeholder summary paragraph for the change.\n- Placeholder bullet one.\n- Placeholder two: {f}.",
    "commit-message": "chore: placeholder subject\n\nPlaceholder body text. {f}.",
    "first-pass-review-comment": "Placeholder review remark. {f}. Generic wording that is long enough to read well.",
    "doc-skeleton": "",
}


def shim_e(f: le.Fixture) -> str:
    texts = [x.text for x in f.facts]
    joined = ", ".join(texts)
    if f.task == "doc-skeleton":
        names = f.sections or tuple(texts)
        extra = [t for t in texts if t not in names]
        body = "\n".join(f"## {n}\nPlaceholder text goes here." for n in names)
        return f"# Placeholder title {' '.join(extra)}\n{body}"
    if f.task == "first-pass-review-comment":
        rest = ", ".join(texts[1:])
        return f"The function {texts[0]} is wrong here: {rest} is the defect, and it is a generic remark of filler."
    return SHAPE[f.task].format(f=joined)


# shim (e) is the right shape with filler plus the facts. For these tasks it still passes more than one fixture:
# a pass means the facts are present and the shape is right, not that the answer is meaningful (docs/local-eval.md).
KNOWN_SHIM_E_LIMIT: dict[str, int] = {
    "issue-draft": 20,
    "ci-log-digest": 20,
    "pr-summary": 20,
    "commit-message": 17,
    "first-pass-review-comment": 20,
    "doc-skeleton": 20,
}


def test_known_shim_limitation_is_documented_for_every_listed_task() -> None:
    doc = (Path(__file__).resolve().parents[1] / "docs" / "local-eval.md").read_text(encoding="utf-8")
    assert "a pass means the facts are present and the shape is right, not that the answer is meaningful" in doc.lower()
    section = doc.split("## Known limitation")[1].split("\n## ")[0]
    listed = {t: (int(a), int(b)) for t, a, b in re.findall(r"^- `([a-z-]+)` \((\d+) of (\d+)", section, re.MULTILINE)}
    # the doc list and the test list say the same tasks, with the same exact counts out of the fixtures shipped
    assert listed == {t: (n, FIXTURE_COUNT[t]) for t, n in KNOWN_SHIM_E_LIMIT.items()}


@pytest.mark.parametrize("kind", ["b", "e"])
def test_template_and_shape_shims_pass_only_the_documented_fixtures(kind: str) -> None:
    fixtures = le.load_fixtures(FIXTURES)
    assert len(fixtures) == FIXTURE_TOTAL
    build = shim_b if kind == "b" else shim_e
    for task in le.TASKS:
        mine = [f for f in fixtures if f.task == task]
        assert len(mine) == FIXTURE_COUNT[task], task
        passed = [f.id for f in mine if le.score_output(f, build(f)).passed]
        if kind == "e" and task in KNOWN_SHIM_E_LIMIT:
            assert len(passed) == KNOWN_SHIM_E_LIMIT[task], (task, passed)  # the documented limitation stays exact
        else:
            assert passed == [], (kind, task, passed)  # measured: 0


def test_ci_digest_needs_added_words_and_a_causal_phrase_near_a_fact() -> None:
    f = shipped()["ci-log-digest/01-pytest-fail"]
    full = (
        "pytest reported 1 failed test: test_invoice_rounding in tests/test_billing.py.\n"
        "The assertion compared 10.05 with 10.04 because invoice rounding looks wrong."
    )
    assert le.score_output(f, full).passed
    no_cause = full.replace("because", "and")
    s = le.score_output(f, no_cause)
    assert not s.passed and "structure" in s.reasons  # no causal or locator phrase
    far = full.replace("because invoice", "x " * 60 + "because invoice")
    assert not le.score_output(f, far).passed  # the phrase is nowhere near a fact
    template = "The change fixes test_invoice_rounding, test_billing.py, 10.05, 10.04, and 1 failed."
    assert not le.score_output(f, template).passed  # too few words of its own


def test_review_comment_needs_eight_words_and_a_verb_in_the_defect_sentence() -> None:
    f = shipped()["first-pass-review-comment/01-off-by-one"]
    good = "last_n has an off-by-one error: the slice starts one index too late so it drops the first requested item."
    assert le.score_output(f, good).passed
    short = "last_n has an off-by-one error in the slice."  # under eight words outside the facts
    assert not le.score_output(f, short).passed
    label = "Review for last_n: off-by-one, slice, index, requested, item, late, first, early, wrong, bad."  # no verb
    s = le.score_output(f, label)
    assert not s.passed and "structure" in s.reasons


NEGATED = [  # a sentence that names the defect only to say there is none
    (
        "first-pass-review-comment/02-sql-concat",
        "find_user builds the query from name, so there is no SQL injection risk here.",
    ),
    (
        "first-pass-review-comment/02-sql-concat",
        "find_user is safe because the SQL injection concern does not apply to this query.",
    ),
    (
        "first-pass-review-comment/06-wrong-compare",
        "is_adult is fine: the boundary is correct and the comparison handles the edge.",
    ),
    (
        "first-pass-review-comment/06-wrong-compare",
        "is_adult has no boundary problem, the check is ok and harmless as written here.",
    ),
    (
        "first-pass-review-comment/06-wrong-compare",
        "is_adult handles the boundary correctly, so the comparison is right for every age.",
    ),
    (
        "first-pass-review-comment/02-sql-concat",
        "find_user glues name into the query string. SQL injection is not possible here.",
    ),
    (
        "first-pass-review-comment/02-sql-concat",
        "find_user glues name into the query string, so SQL injection cannot happen.",
    ),
    (
        "first-pass-review-comment/02-sql-concat",
        "find_user glues name into the query string, so SQL injection can not happen.",
    ),
    (
        "first-pass-review-comment/02-sql-concat",
        "find_user glues name into the query string, and SQL injection is impossible.",
    ),
    (
        "first-pass-review-comment/02-sql-concat",
        "find_user glues name into the query string, so SQL injection is a no risk matter.",
    ),
    (
        "first-pass-review-comment/02-sql-concat",
        "find_user glues name into the query string, yet there is no issue with SQL injection at all.",
    ),
    (
        "first-pass-review-comment/02-sql-concat",
        "find_user glues name into the query string; SQL injection is no problem for this caller.",
    ),
    (
        "first-pass-review-comment/02-sql-concat",
        "find_user glues name into the query string, and SQL injection is not an issue for this caller.",
    ),
]
DEFECT_STATING = [  # not, never and without state the defect, so they stay allowed
    (
        "first-pass-review-comment/03-unclosed-file",
        "read_cfg never closes the file handle after reading it, so the descriptor stays open.",
    ),
    (
        "first-pass-review-comment/03-unclosed-file",
        "read_cfg does not close the file after the read, so the handle leaks until exit.",
    ),
    (
        "first-pass-review-comment/03-unclosed-file",
        "read_cfg opens the file without closing it, so the file handle leaks for the whole run.",
    ),
    (
        "first-pass-review-comment/05-long-diff",
        "apply_discount no longer divides pct by 100, so a discount of 15 makes the price negative.",
    ),
    (
        "first-pass-review-comment/03-unclosed-file",
        "read_cfg opens the file and there is no guarantee it closed, so the file handle leaks.",
    ),
    (
        "first-pass-review-comment/03-unclosed-file",
        "read_cfg opens a file here. This is not safe: it leaks the file handle.",
    ),
    (
        "first-pass-review-comment/02-sql-concat",
        "find_user glues name into the query. The query has no escaping, so SQL injection is possible.",
    ),
    (
        "first-pass-review-comment/02-sql-concat",
        "find_user glues name into the query. The fix is correct but SQL injection remains.",
    ),
]


@pytest.mark.parametrize(("fid", "text"), NEGATED)
def test_a_review_comment_that_denies_the_defect_fails(fid: str, text: str) -> None:
    s = le.score_output(shipped()[fid], text)
    assert not s.passed and "structure" in s.reasons, text


@pytest.mark.parametrize(("fid", "text"), DEFECT_STATING)
def test_a_review_comment_that_states_the_defect_with_not_never_without_passes(fid: str, text: str) -> None:
    assert le.score_output(shipped()[fid], text).passed, text


def test_negation_markers_are_documented_and_the_wrong_lists_still_fail() -> None:
    assert set(le.NEGATION_MARKERS) == {"no", "correct", "correctly", "safe", "fine", "ok", "harmless"}
    assert not {"not", "never", "without"} & set(le.NEGATION_MARKERS)
    doc = (Path(__file__).resolve().parents[1] / "docs" / "local-eval.md").read_text(encoding="utf-8")
    assert all(f"`{m}`" in doc for m in le.NEGATION_MARKERS)


CORRECT_ALTS: dict[str, list[str]] = {
    "first-pass-review-comment/02-sql-concat": [
        "find_user builds the query by gluing name into the SQL string, so a crafted value can alter the query.",
        "find_user is concatenating the user name into the statement instead of binding a parameter here.",
        "In find_user the string formatting of name into the query allows an attacker to inject SQL.",
    ],
    "first-pass-review-comment/04-mutable-default": [
        "add_tag uses tags=[] so the default is evaluated once and every call shares the same list.",
        "add_tag has a default that is shared across calls, so tags keep growing between invocations.",
        "The tags default in add_tag is the same list object each time, so earlier tags leak into later calls.",
    ],
}


def test_correct_alternatives_all_pass_and_wrong_lists_still_fail() -> None:
    by_id = shipped()
    for fid, outs in CORRECT_ALTS.items():
        for o in outs:
            assert le.score_output(by_id[fid], o).passed, (fid, o)
    for f in by_id.values():
        for o in f.correct_alts:
            assert le.score_output(f, o).passed, (f.id, o)
        for w in f.wrong:
            assert not le.score_output(f, w).passed, (f.id, w)
    assert sum(len(f.correct_alts) for f in by_id.values() if f.task == "first-pass-review-comment") >= 12


def test_correct_alts_are_loaded_from_the_fixture(tmp_path: Path) -> None:
    _write_fixture(tmp_path, "commit-message", "01", {**GOOD, "correct_alts": ["a b", "a bb"]})
    (loaded,) = le.load_fixtures(tmp_path)
    assert loaded.correct_alts == ("a b", "a bb")


# ---- calibration gate

RUNS_SHA = "ab" * 32  # stands in for the sha256 of a runs file in the in-memory tests


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def passing_runs(task: str, model: str, n: int) -> list[dict[str, Any]]:
    runs = []
    for i in range(n):
        r = rec(task, model)
        r["output"] = f"output {i}"
        runs.append(r)
    return runs


def sample(runs: list[dict[str, Any]], n: int, seed: int = 0) -> dict[str, Any]:
    return le.calibration_file(runs, n, seed, RUNS_SHA)


def ingest(doc: dict[str, Any], runs: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    return le.ingest_verdicts(doc, runs, RUNS_SHA)


def fill(doc: dict[str, Any], ok: int, wrong: int) -> dict[str, Any]:
    entries = doc["entries"]
    for i, e in enumerate(entries):
        e["verdict"] = "ok" if i < ok else "wrong" if i < ok + wrong else ""
    return doc


def test_calibration_file_samples_passing_outputs_per_cell() -> None:
    runs = passing_runs("pr-summary", "m1", 40) + passing_runs("pr-summary", "m2", 10)
    runs += [rec("pr-summary", "m1", passed=False) | {"output": "bad"} for _ in range(5)]
    doc = sample(runs, 30, seed=1)
    by_cell: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for e in doc["entries"]:
        by_cell.setdefault((e["task"], e["model"]), []).append(e)
    assert len(by_cell[("pr-summary", "m1")]) == 30 and len(by_cell[("pr-summary", "m2")]) == 10  # all if fewer
    assert all(e["verdict"] == "" and e["id"] and e["output"].startswith("output") for e in doc["entries"])
    assert len({e["id"] for e in doc["entries"]}) == 40
    assert sample(runs, 30, seed=1) == doc  # seedable
    assert doc["runs_sha256"] == RUNS_SHA and doc["n"] == 30 and doc["seed"] == 1


def test_sample_ids_come_from_the_run_not_from_a_counter() -> None:
    runs = passing_runs("pr-summary", "m1", 40)
    a, b = sample(runs, 20, seed=1), sample(runs, 20, seed=2)
    ids_a = {e["output"]: e["id"] for e in a["entries"]}
    ids_b = {e["output"]: e["id"] for e in b["entries"]}
    common = set(ids_a) & set(ids_b)
    assert common and all(ids_a[o] == ids_b[o] for o in common)  # the same run keeps its id in another draw
    assert not any(re.fullmatch(r"\d{1,6}", e["id"]) for e in a["entries"])
    assert all(e["output_sha256"] == sha(e["output"]) for e in a["entries"])
    moved = [dict(r) for r in runs]
    moved[0]["ts"] = "2026-01-01T00:00:00Z"  # a different run record gets a different id
    assert le.run_id(0, moved[0]) != le.run_id(0, runs[0])
    assert le.run_id(1, runs[0]) != le.run_id(0, runs[0])


def test_perfect_pass_rate_without_calibration_is_only_local_then_claude_check() -> None:
    runs = passing_runs("pr-summary", "qwen3.5:4b", 60)
    stats = le.summarize(runs)[("pr-summary", "qwen3.5:4b")]
    assert stats["ci_low"] >= le.LOCAL_MIN
    tier, why = le.tier_for({"qwen3.5:4b": stats})
    assert tier == "local-then-claude-check" and "calibration" in why
    assert "| pr-summary | local-then-claude-check |" in le.render_report(runs)
    assert "| pr-summary | qwen3.5:4b | 60 |" in le.render_report(runs) and "none" in le.render_report(runs)


def test_thirty_five_ok_verdicts_unlock_local_only_and_nothing_weaker_does() -> None:
    runs = passing_runs("pr-summary", "qwen3.5:4b", 60)
    cell = ("pr-summary", "qwen3.5:4b")
    cal35 = ingest(fill(sample(runs, 35), 35, 0), runs)
    assert cal35[cell]["verdicts"] == 35 and cal35[cell]["ci_low"] >= le.CAL_MIN_LOWER
    assert "| pr-summary | local-qwen |" in le.render_report(runs, cal35)
    weaker = {"34 of 35 ok": (34, 1), "30 of 30 ok": (30, 0), "20 ok 5 wrong": (20, 5)}
    for name, (ok, wrong) in weaker.items():
        cal = ingest(fill(sample(runs, ok + wrong), ok, wrong), runs)
        assert cal[cell]["ok"] == ok and cal[cell]["wrong"] == wrong, name
        assert not le.calibration_ok(cal[cell]), name
        assert "| pr-summary | local-then-claude-check |" in le.render_report(runs, cal), name


def test_calibration_bound_is_two_sided_and_needs_thirty_five_verdicts() -> None:
    assert le.CAL_Z == 1.96 and le.CAL_MIN_VERDICTS == 35 and le.CAL_SAMPLE_DEFAULT == 35
    assert round(le.agreement(35, 0)["ci_low"], 3) == 0.901
    assert le.agreement(30, 0)["ci_low"] < le.CAL_MIN_LOWER
    runs = passing_runs("pr-summary", "qwen3.5:4b", 60)
    cell = ("pr-summary", "qwen3.5:4b")
    few = ingest(fill(sample(runs, 35), 34, 0), runs)
    assert few[cell]["verdicts"] == 34 and le.cal_status(few[cell]) == "partial"
    assert not le.calibration_ok(few[cell])
    assert "| pr-summary | local-then-claude-check |" in le.render_report(runs, few)
    assert le.cal_status(None) == "none"
    assert le.cal_status(ingest(fill(sample(runs, 35), 0, 0), runs).get(cell)) == "none"
    assert le.cal_status(le.agreement(35, 0)) == "done"


def test_a_failed_calibration_is_its_own_status_and_names_the_bound() -> None:
    assert le.cal_status(le.agreement(30, 5)) == "failed"  # 35 verdicts, ok share bound far below 0.9
    assert le.cal_status(le.agreement(34, 1)) == "failed"
    assert le.cal_status(le.agreement(35, 0)) == "done" and le.cal_status(le.agreement(10, 0)) == "partial"
    runs = passing_runs("pr-summary", "qwen3.5:4b", 60)
    cell = ("pr-summary", "qwen3.5:4b")
    bad = {cell: le.agreement(25, 10)}
    lo = f"{bad[cell]['ci_low']:.2f}"
    assert lo == "0.55"
    tier, why = le.tier_for({"qwen3.5:4b": le.summarize(runs)[cell]}, {"qwen3.5:4b": bad[cell]})
    assert tier == "local-then-claude-check" and f"calibration failed: ok lower bound {lo} < 0.9" in why
    text = le.render_report(runs, bad)
    assert "| pr-summary | qwen3.5:4b | failed | 35 |" in text and f"calibration failed: ok lower bound {lo}" in text


def test_calibration_gate_does_not_lower_the_pass_rate_gate() -> None:
    runs = passing_runs("pr-summary", "qwen3.5:4b", 4)  # lower bound far below 0.9
    cal = ingest(fill(sample(runs, 35), 4, 0), runs)
    assert "| pr-summary | local-qwen |" not in le.render_report(runs, cal)
    stats = le.summarize(runs)[("pr-summary", "qwen3.5:4b")]
    assert le.tier_for({"qwen3.5:4b": stats}, {"qwen3.5:4b": CAL_OK})[0] != "local-qwen"


@pytest.mark.parametrize("bad", ["OK", "yes", "Wrong", "ok ", "1", "good", None, True, 1])
def test_bad_verdict_strings_are_rejected(bad: Any) -> None:
    runs = passing_runs("pr-summary", "m", 3)
    doc = sample(runs, 3)
    doc["entries"][0]["verdict"] = bad
    with pytest.raises(le.EvalError):
        ingest(doc, runs)


def test_ingest_rejects_duplicate_ids_and_unknown_cells() -> None:
    runs = passing_runs("pr-summary", "m", 3)
    doc = sample(runs, 3)
    doc["entries"][1]["id"] = doc["entries"][0]["id"]
    with pytest.raises(le.EvalError):
        ingest(doc, runs)
    doc = sample(runs, 3)
    doc["entries"][0]["task"] = "bogus"
    with pytest.raises(le.EvalError):
        ingest(doc, runs)


# ---- the verdicts are bound to the runs that were sampled (finding 1)


def invented_doc(count: int, sha_value: str = RUNS_SHA) -> dict[str, Any]:
    """The reviewer's reproduction: a hand-written file of ok verdicts for ids that were never sampled."""
    entries = [
        {
            "id": f"{i:012x}",
            "task": "pr-summary",
            "model": "qwen3.5:4b",
            "fixture": "pr-summary/1",
            "output": f"invented text {i}",
            "output_sha256": sha(f"invented text {i}"),
            "verdict": "ok",
        }
        for i in range(count)
    ]
    return {"format": le.CAL_FORMAT, "runs_sha256": sha_value, "n": 35, "seed": 0, "entries": entries}


def test_thirty_five_invented_ok_verdicts_are_rejected_and_unlock_nothing() -> None:
    runs = passing_runs("pr-summary", "qwen3.5:4b", 60)
    with pytest.raises(le.EvalError) as err:
        ingest(invented_doc(35), runs)
    text = str(err.value)
    assert "35 of 35" in text and "invented text" not in text  # the count, never the output text
    # one foreign entry among real ones rejects the whole file
    doc = fill(sample(runs, 35), 35, 0)
    doc["entries"][3]["id"] = "0" * 12
    with pytest.raises(le.EvalError, match="1 of 35"):
        ingest(doc, runs)


def test_verdicts_for_really_sampled_ids_are_accepted() -> None:
    runs = passing_runs("pr-summary", "qwen3.5:4b", 60)
    cal = ingest(fill(sample(runs, 35), 35, 0), runs)
    assert le.calibration_ok(cal[("pr-summary", "qwen3.5:4b")])


def test_an_id_from_another_cell_is_rejected() -> None:
    runs = passing_runs("pr-summary", "m1", 40) + passing_runs("pr-summary", "m2", 40)
    doc = fill(sample(runs, 35), 70, 0)
    moved = next(e for e in doc["entries"] if e["model"] == "m2")
    moved["model"] = "m1"  # the id is a real sampled id, but of the other cell
    with pytest.raises(le.EvalError, match="1 of 70"):
        ingest(doc, runs)


def test_a_changed_output_or_output_hash_is_rejected() -> None:
    runs = passing_runs("pr-summary", "m", 40)
    doc = fill(sample(runs, 35), 35, 0)
    doc["entries"][0]["output_sha256"] = sha("some other output")
    with pytest.raises(le.EvalError, match="1 of 35"):
        ingest(doc, runs)
    doc = fill(sample(runs, 35), 35, 0)
    doc["entries"][0]["output"] = "an output nobody sampled"  # hash field untouched, text swapped
    with pytest.raises(le.EvalError, match="1 of 35"):
        ingest(doc, runs)


def test_a_verdict_file_made_for_other_runs_is_rejected() -> None:
    runs = passing_runs("pr-summary", "m", 40)
    doc = fill(sample(runs, 35), 35, 0)
    with pytest.raises(le.EvalError, match="runs file"):
        le.ingest_verdicts(doc, runs, "cd" * 32)  # the runs file changed after sampling
    no_hash = fill(sample(runs, 35), 35, 0)
    del no_hash["runs_sha256"]
    with pytest.raises(le.EvalError, match="runs file"):
        ingest(no_hash, runs)


def agreement_for(runs: list[dict[str, Any]], ok: int, wrong: int) -> dict[str, Any]:
    doc = fill(sample(runs, ok + wrong), ok, wrong)
    return le.agreement_doc(le.ingest_full(doc, runs, RUNS_SHA), RUNS_SHA)


def test_agreement_file_round_trips_and_drives_the_gate() -> None:
    runs = passing_runs("pr-summary", "qwen3.5:4b", 60)
    cal = le.load_agreement(agreement_for(runs, 35, 0), RUNS_SHA)
    assert "| pr-summary | local-qwen |" in le.render_report(runs, cal)


def test_a_hand_edited_agreement_file_is_not_calibrated() -> None:
    runs = passing_runs("pr-summary", "qwen3.5:4b", 60)
    doc = agreement_for(runs, 20, 15)
    doc["cells"][0]["ok"], doc["cells"][0]["wrong"] = 35, 0  # edited counts, integrity field left alone
    with pytest.raises(le.CalibrationMismatch, match="integrity"):
        le.load_agreement(doc, RUNS_SHA)
    doc = agreement_for(runs, 35, 0)
    doc["verdicts"] = doc["verdicts"][:-1]  # a judged entry dropped
    with pytest.raises(le.CalibrationMismatch, match="integrity"):
        le.load_agreement(doc, RUNS_SHA)
    with pytest.raises(le.CalibrationMismatch, match="runs file"):
        le.load_agreement(agreement_for(runs, 35, 0), "cd" * 32)  # a different runs file


def test_cli_ingest_needs_the_runs_and_rejects_invented_files(tmp_path: Path) -> None:
    runs = passing_runs("pr-summary", "qwen3.5:4b", 60)
    runs_in = tmp_path / "runs.jsonl"
    runs_in.write_text("".join(json.dumps(r) + "\n" for r in runs), encoding="utf-8")
    real_sha = hashlib.sha256(runs_in.read_bytes()).hexdigest()
    fake = tmp_path / "fake.json"
    fake.write_text(json.dumps(invented_doc(35, real_sha)), encoding="utf-8")
    fake.chmod(0o600)
    out = tmp_path / "o"
    assert le.entry(["calibrate", "--ingest", str(fake), "--out", str(out)]) == 2  # no --runs
    assert le.entry(["calibrate", "--ingest", str(fake), "--runs", str(runs_in), "--out", str(out)]) == 2
    assert not (out / "calibration-agreement.json").exists()


def cli_calibrate(tmp_path: Path, runs: list[dict[str, Any]], ok: int, wrong: int) -> tuple[Path, Path]:
    runs_in = tmp_path / "runs.jsonl"
    runs_in.write_text("".join(json.dumps(r) + "\n" for r in runs), encoding="utf-8")
    out = tmp_path / "cal"
    assert le.entry(["calibrate", "--runs", str(runs_in), "--out", str(out), "--n", str(ok + wrong)]) == 0
    sample_path = out / "calibration.json"
    sample_path.write_text(json.dumps(fill(json.loads(sample_path.read_text()), ok, wrong)), encoding="utf-8")
    sample_path.chmod(0o600)
    done = tmp_path / "done"
    args = ["calibrate", "--ingest", str(sample_path), "--runs", str(runs_in), "--out", str(done)]
    assert le.entry(args) == 0
    return runs_in, done / "calibration-agreement.json"


def test_cli_a_changed_runs_file_closes_the_gate_loudly(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    runs = passing_runs("pr-summary", "qwen3.5:4b", 60)
    runs_in, agreement_path = cli_calibrate(tmp_path, runs, 35, 0)
    rep = tmp_path / "rep"
    assert le.entry(["report", "--runs", str(runs_in), "--out", str(rep), "--calibration", str(agreement_path)]) == 0
    assert "| pr-summary | local-qwen |" in (rep / "report.md").read_text()
    changed = [dict(r) for r in runs]
    changed[0]["latency_s"] = 99.0  # any change to the runs file changes its hash
    other = tmp_path / "other.jsonl"
    other.write_text("".join(json.dumps(r) + "\n" for r in changed), encoding="utf-8")
    rep2 = tmp_path / "rep2"
    capsys.readouterr()
    assert le.entry(["report", "--runs", str(other), "--out", str(rep2), "--calibration", str(agreement_path)]) == 0
    text = (rep2 / "report.md").read_text()
    assert "| pr-summary | local-qwen |" not in text and "| pr-summary | local-then-claude-check |" in text
    assert "CALIBRATION IGNORED" in text and "WARNING" in capsys.readouterr().err


def test_cli_a_hand_edited_agreement_file_closes_the_gate_loudly(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    runs = passing_runs("pr-summary", "qwen3.5:4b", 60)
    runs_in, agreement_path = cli_calibrate(tmp_path, runs, 20, 15)
    doc = json.loads(agreement_path.read_text())
    doc["cells"][0]["ok"], doc["cells"][0]["wrong"] = 35, 0
    agreement_path.write_text(json.dumps(doc), encoding="utf-8")
    rep = tmp_path / "rep"
    capsys.readouterr()
    assert le.entry(["report", "--runs", str(runs_in), "--out", str(rep), "--calibration", str(agreement_path)]) == 0
    text = (rep / "report.md").read_text()
    assert "| pr-summary | local-qwen |" not in text and "CALIBRATION IGNORED" in text and "integrity" in text
    assert "WARNING" in capsys.readouterr().err


def test_cli_calibrate_sample_then_ingest_then_report(tmp_path: Path) -> None:
    runs = passing_runs("pr-summary", "qwen3.5:4b", 60)
    runs_in, agreement_path = cli_calibrate(tmp_path, runs, 35, 0)
    sample_path = tmp_path / "cal" / "calibration.json"
    doc = json.loads(sample_path.read_text())
    assert len(doc["entries"]) == 35 and mode(sample_path) == 0o600 and mode(tmp_path / "cal") == 0o700
    assert doc["runs_sha256"] == hashlib.sha256(runs_in.read_bytes()).hexdigest()
    assert mode(agreement_path) == 0o600
    rep = tmp_path / "rep"
    assert le.entry(["report", "--runs", str(runs_in), "--out", str(rep), "--calibration", str(agreement_path)]) == 0
    text = (rep / "report.md").read_text()
    assert "| pr-summary | local-qwen |" in text and "done" in text
    plain = tmp_path / "plain"
    assert le.entry(["report", "--runs", str(runs_in), "--out", str(plain)]) == 0
    assert "| pr-summary | local-then-claude-check |" in (plain / "report.md").read_text()


def test_cli_ingest_rejects_bad_verdicts_symlinks_and_open_modes(tmp_path: Path) -> None:
    runs = passing_runs("pr-summary", "m", 3)
    runs_in = tmp_path / "runs.jsonl"
    runs_in.write_text("".join(json.dumps(r) + "\n" for r in runs), encoding="utf-8")
    run_sha = hashlib.sha256(runs_in.read_bytes()).hexdigest()
    base = ["--runs", str(runs_in), "--out", str(tmp_path / "o")]
    doc = le.calibration_file(runs, 3, 0, run_sha)
    doc["entries"][0]["verdict"] = "maybe"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(doc), encoding="utf-8")
    bad.chmod(0o600)
    assert le.entry(["calibrate", "--ingest", str(bad), *base]) == 2
    good = tmp_path / "good.json"
    good.write_text(json.dumps(le.calibration_file(runs, 3, 0, run_sha)), encoding="utf-8")
    good.chmod(0o644)  # group and other can read: refused
    assert le.entry(["calibrate", "--ingest", str(good), *base]) == 2
    good.chmod(0o600)
    link = tmp_path / "link.json"
    link.symlink_to(good)
    assert le.entry(["calibrate", "--ingest", str(link), *base]) == 2
    assert le.entry(["calibrate", "--ingest", str(good), *base]) == 0


def test_read_private_refuses_a_file_owned_by_someone_else(tmp_path: Path) -> None:
    p = tmp_path / "v.json"
    p.write_text("{}", encoding="utf-8")
    p.chmod(0o600)
    assert le._read_private(p) == "{}"
    assert le._read_private(p, uid=os.getuid()) == "{}"
    with pytest.raises(le.EvalError, match="owned by you"):
        le._read_private(p, uid=os.getuid() + 1)  # the owner check bites when the uid differs


# ---- every sampled entry of a cell must be judged (selection bias)

CELL = ("pr-summary", "qwen3.5:4b")


def only_first(doc: dict[str, Any], k: int) -> dict[str, Any]:
    doc["entries"] = doc["entries"][:k]  # the rest of the sample is removed from the file
    return doc


def test_judging_only_the_first_35_of_a_100_sample_does_not_calibrate() -> None:
    runs = passing_runs("pr-summary", "qwen3.5:4b", 120)
    doc = only_first(fill(sample(runs, 100), 35, 0), 35)  # the reviewer's reproduction
    cal = ingest(doc, runs)
    cell = cal[CELL]
    assert cell["verdicts"] == 35 and cell["sampled"] == 100
    assert le.cal_status(cell) == "partial" and not le.calibration_ok(cell)
    text = le.render_report(runs, cal)
    assert "| pr-summary | local-then-claude-check |" in text and "| pr-summary | local-qwen |" not in text
    assert "partial (35 of 100 judged)" in text
    full = ingest(fill(sample(runs, 100), 100, 0), runs)[CELL]  # judging every sampled entry does calibrate
    assert full["verdicts"] == 100 and le.calibration_ok(full) and le.cal_status(full) == "done"


def test_judging_all_of_a_35_entry_sample_calibrates() -> None:
    runs = passing_runs("pr-summary", "qwen3.5:4b", 120)
    cell = ingest(fill(sample(runs, 35), 35, 0), runs)[CELL]
    assert cell["sampled"] == 35 and le.calibration_ok(cell)
    assert "| pr-summary | local-qwen |" in le.render_report(runs, {CELL: cell})


def test_a_sample_under_35_can_never_calibrate_even_when_fully_judged() -> None:
    runs = passing_runs("pr-summary", "qwen3.5:4b", 20)  # only 20 outputs pass
    cell = ingest(fill(sample(runs, 100), 20, 0), runs)[CELL]
    assert cell["sampled"] == 20 and cell["verdicts"] == 20
    assert not le.calibration_ok(cell) and le.cal_status(cell) == "partial"


def test_two_step_ingest_merges_verdicts_and_completes_the_cell() -> None:
    runs = passing_runs("pr-summary", "qwen3.5:4b", 60)
    first = le.ingest_full(fill(sample(runs, 35), 20, 0), runs, RUNS_SHA)  # 20 judged, 15 left empty
    assert first.cells[CELL]["verdicts"] == 20 and not le.calibration_ok(first.cells[CELL])
    second_doc = fill(sample(runs, 35), 35, 0)
    for e in second_doc["entries"][:20]:
        e["verdict"] = ""  # this file only judges the other 15
    both = le.ingest_full(second_doc, runs, RUNS_SHA, prior=first)
    assert both.cells[CELL]["verdicts"] == 35 and le.calibration_ok(both.cells[CELL]) and both.replaced == []
    again = le.load_agreement(le.agreement_doc(both, RUNS_SHA), RUNS_SHA)  # stored and read back
    assert le.calibration_ok(again[CELL])


def test_a_changed_verdict_needs_replace_and_is_logged() -> None:
    runs = passing_runs("pr-summary", "qwen3.5:4b", 60)
    first = le.ingest_full(fill(sample(runs, 35), 35, 0), runs, RUNS_SHA)
    changed = fill(sample(runs, 35), 35, 0)
    changed["entries"][0]["verdict"] = "wrong"
    with pytest.raises(le.EvalError, match="--replace"):
        le.ingest_full(changed, runs, RUNS_SHA, prior=first)
    kept = le.ingest_full(fill(sample(runs, 35), 35, 0), runs, RUNS_SHA, prior=first)  # the same verdicts again
    assert kept.replaced == []
    swapped = le.ingest_full(changed, runs, RUNS_SHA, prior=first, replace=True)
    assert swapped.cells[CELL]["wrong"] == 1 and len(swapped.replaced) == 1
    doc = le.agreement_doc(swapped, RUNS_SHA)
    assert doc["replaced"][0]["id"] == changed["entries"][0]["id"]
    assert le.load_agreement(doc, RUNS_SHA)[CELL]["wrong"] == 1
    doc["replaced"] = []  # the log is part of the integrity field
    with pytest.raises(le.CalibrationMismatch, match="integrity"):
        le.load_agreement(doc, RUNS_SHA)


def test_a_second_ingest_must_use_the_same_sample() -> None:
    runs = passing_runs("pr-summary", "qwen3.5:4b", 120)
    first = le.ingest_full(fill(sample(runs, 100), 35, 0), runs, RUNS_SHA)
    with pytest.raises(le.EvalError, match="sample"):
        le.ingest_full(fill(sample(runs, 35), 35, 0), runs, RUNS_SHA, prior=first)  # another n draws other entries


def test_cli_partial_judging_then_the_rest_with_replace(tmp_path: Path) -> None:
    runs = passing_runs("pr-summary", "qwen3.5:4b", 60)
    runs_in = tmp_path / "runs.jsonl"
    runs_in.write_text("".join(json.dumps(r) + "\n" for r in runs), encoding="utf-8")
    cal_dir, out = tmp_path / "cal", tmp_path / "done"
    assert le.entry(["calibrate", "--runs", str(runs_in), "--out", str(cal_dir), "--n", "35"]) == 0
    sample_path = cal_dir / "calibration.json"
    base = json.loads(sample_path.read_text())

    def ingest_cli(ok: int, start: int = 0, extra: tuple[str, ...] = (), flip: bool = False) -> int:
        d = json.loads(json.dumps(base))
        for i, e in enumerate(d["entries"]):
            e["verdict"] = ("wrong" if flip and i == 0 else "ok") if start <= i < start + ok else ""
        sample_path.write_text(json.dumps(d), encoding="utf-8")
        sample_path.chmod(0o600)
        return le.entry(["calibrate", "--ingest", str(sample_path), "--runs", str(runs_in), "--out", str(out), *extra])

    def report() -> str:
        rep = tmp_path / "rep"
        agreement_path = out / "calibration-agreement.json"
        assert (
            le.entry(["report", "--runs", str(runs_in), "--out", str(rep), "--calibration", str(agreement_path)]) == 0
        )
        return (rep / "report.md").read_text()

    assert ingest_cli(20) == 0
    assert "partial (20 of 35 judged)" in report() and "| pr-summary | local-qwen |" not in report()
    assert ingest_cli(15, start=20) == 0
    assert "| pr-summary | local-qwen |" in report()
    assert ingest_cli(1, flip=True) == 2  # entry 0 was ok, now wrong: refused without --replace
    assert "| pr-summary | local-qwen |" in report()  # the stored file is untouched
    assert ingest_cli(1, flip=True, extra=("--replace",)) == 0
    assert json.loads((out / "calibration-agreement.json").read_text())["replaced"]
