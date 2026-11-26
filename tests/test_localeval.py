# SPDX-License-Identifier: Apache-2.0
"""Tests for safo-eval (#484): scoring, runner with a fake llm-local on PATH, report, calibration, fixture guard."""

from __future__ import annotations

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
    assert le.tier_for({m: {"pass_rate": r, "ci_low": r} for m, r in rates.items()})[0] == tier


def test_few_runs_cannot_qualify_on_luck() -> None:
    # 2 of 2 passes is a 1.00 rate but the Wilson lower bound is about 0.34: claude, not local
    s = le.summarize([rec("pr-summary", "qwen3.5:4b"), rec("pr-summary", "qwen3.5:4b")])[("pr-summary", "qwen3.5:4b")]
    assert s["pass_rate"] == 1.0 and s["ci_low"] < 0.4
    assert le.tier_for({"qwen3.5:4b": s})[0] == "claude"
    many = le.summarize([rec("pr-summary", "qwen3.5:4b") for _ in range(60)])[("pr-summary", "qwen3.5:4b")]
    assert many["ci_low"] >= le.LOCAL_MIN and le.tier_for({"qwen3.5:4b": many})[0] == "local-qwen"


def test_wilson_interval_known_values() -> None:
    lo, hi = le.wilson(5, 10)
    assert (round(lo, 3), round(hi, 3)) == (0.237, 0.763)
    assert le.wilson(0, 0) == (0.0, 1.0)
    lo, hi = le.wilson(10, 10)
    assert hi == pytest.approx(1.0) and round(lo, 3) == 0.722


def test_report_has_table_and_routing_rule() -> None:
    runs = [rec("pr-summary", "qwen3.5:4b") for _ in range(40)] + [rec("commit-message", "qwen3.5:4b", passed=False)]
    text = le.render_report(runs)
    assert "| pr-summary | qwen3.5:4b | 40 | 1.00 |" in text
    assert "## ROUTING TABLE" in text and ">= 0.9: local only" in text
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
        "The assertion compared 10.05 with 10.04, so invoice rounding looks wrong.\n"
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


@pytest.mark.parametrize("kind", ["echo", "facts", "headings"])
def test_gaming_shims_pass_at_most_one_fixture_per_task(kind: str) -> None:
    fixtures = le.load_fixtures(FIXTURES)
    assert len(fixtures) >= 42
    for task in le.TASKS:
        mine = [f for f in fixtures if f.task == task]
        assert len(mine) == 6, task
        passed = [f.id for f in mine if le.score_output(f, gaming(kind, f)).passed]
        assert len(passed) <= 1, (kind, task, passed)


def test_gaming_guard_bites_on_a_loose_fixture() -> None:
    # the shims do pass a fixture that has no structure, copy or facts-only rule: the test above is not vacuous
    loose = fx(task="issue-triage", required_format="any", facts=(le.Fact("alpha"),), forbidden=())
    assert le.score_output(loose, "alpha").passed


def test_every_fixture_lists_two_wrong_outputs_and_none_passes() -> None:
    fixtures = le.load_fixtures(FIXTURES)
    assert len(fixtures) >= 42
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
        assert le.entry(["calibrate", "--runs", str(runs_in), "--n", "1", "--out", str(tmp_path / "cal" / "c.md")]) == 0
    finally:
        os.umask(old)
    assert mode(out) == 0o700 and mode(out.parent) == 0o700 and mode(tmp_path / "r1") == 0o700
    for p in [*out.iterdir(), *(tmp_path / "r1").iterdir(), tmp_path / "cal" / "c.md", pre / "report.md"]:
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
