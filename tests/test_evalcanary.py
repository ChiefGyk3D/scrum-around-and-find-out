# SPDX-License-Identifier: Apache-2.0
"""Tests for safo-eval-canary (#540): baseline compare, drop alert, busy retry, unreachable, hostile baselines."""

from __future__ import annotations

import json
import os
import secrets
import threading
from pathlib import Path
from typing import Any

import pytest

from safo import evalcanary as ec
from safo import localdraft
from safo import localeval as le

FIXTURES = le.FIXTURES_DEFAULT
N_FIX = len(le.load_fixtures(FIXTURES, ["commit-message"]))
MODELS = tuple(dict.fromkeys((localdraft.DRAFT_MODEL, localdraft.DIGEST_MODEL)))


class FakeClient:
    """A fake llm-local: per-model script of pass rate or a failure kind, no process, no network."""

    def __init__(self, plan: dict[str, Any]) -> None:
        self.plan = plan
        self.calls: list[tuple[str, str]] = []
        self.busy_left: dict[str, int] = {}
        self.ok_seen: dict[str, int] = {}

    def __call__(self, fixture: Any, model: str) -> dict[str, Any]:
        self.calls.append((model, fixture.id))
        spec = self.plan[model]
        base = {"fixture": fixture.id, "task": fixture.task, "model": model}
        if spec == "unreachable":
            return {**base, "status": "failed", "error": "exit 2: cannot reach the server"}
        if spec == "oserror":
            return {**base, "status": "failed", "error": "FileNotFoundError: llm-local"}
        if spec == "busy":
            return {**base, "status": "busy"}
        if isinstance(spec, tuple) and spec[0] == "busy-then":
            left = self.busy_left.setdefault(model, spec[1])
            if left > 0:
                self.busy_left[model] = left - 1
                return {**base, "status": "busy"}
            spec = spec[2]
        n_fix = N_FIX
        index = self.ok_seen.get(model, 0)
        self.ok_seen[model] = index + 1
        ok = (index % n_fix) < round(spec * n_fix)
        return {**base, "status": "ok", "score": {"passed": ok}}


def args(tmp: Path, *extra: str) -> list[str]:
    return ["--baseline", str(tmp / "base.json"), "--tasks", "commit-message", "--busy-retries", "2", *extra]


def run(tmp: Path, plan: dict[str, Any], *extra: str) -> tuple[int, FakeClient]:
    client = FakeClient(plan)
    code = ec.entry(args(tmp, *extra), runner=client, sleep=lambda _s: None)
    return code, client


def population(tasks: list[str] | None = None) -> str:
    return ec.population_id(le.load_fixtures(FIXTURES, tasks or ["commit-message"]))


def write_base(tmp: Path, scores: dict[str, float], pop: str | None = None) -> Path:
    path = tmp / "base.json"
    doc = {"version": ec.BASELINE_VERSION, "scores": scores, "population": pop or population()}
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def test_models_come_from_the_existing_config_not_literals() -> None:
    assert ec.canary_models() == MODELS
    assert len(MODELS) == 2


def test_update_baseline_writes_scores_mode_0600(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, _ = run(tmp_path, {m: 0.9 for m in MODELS}, "--update-baseline")
    assert code == 0
    path = tmp_path / "base.json"
    data = json.loads(path.read_text())
    assert set(data["scores"]) == set(MODELS)
    assert all(abs(v - 0.9) < 0.06 for v in data["scores"].values())
    assert (path.stat().st_mode & 0o777) == 0o600


def test_no_write_without_the_flag(tmp_path: Path) -> None:
    path = write_base(tmp_path, {m: 0.9 for m in MODELS})
    before = path.read_bytes()
    code, _ = run(tmp_path, {m: 0.5 for m in MODELS})
    assert code == 1
    assert path.read_bytes() == before


def test_score_within_threshold_is_exit_0(tmp_path: Path) -> None:
    write_base(tmp_path, {m: 0.9 for m in MODELS})
    code, _ = run(tmp_path, {m: 0.85 for m in MODELS})
    assert code == 0


def test_drop_over_threshold_alerts_one_line_exit_1(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write_base(tmp_path, {m: 0.9 for m in MODELS})
    plan = {MODELS[0]: 0.9, MODELS[1]: 0.5}
    code, _ = run(tmp_path, plan)
    err = capsys.readouterr().err
    assert code == 1
    alerts = [ln for ln in err.splitlines() if ln.startswith("ALERT")]
    assert len(alerts) == 1 and MODELS[1] in alerts[0] and MODELS[0] not in alerts[0]


def test_custom_threshold(tmp_path: Path) -> None:
    write_base(tmp_path, {m: 0.9 for m in MODELS})
    assert run(tmp_path, {m: 0.8 for m in MODELS}, "--threshold", "0.05")[0] == 1
    assert run(tmp_path, {m: 0.8 for m in MODELS}, "--threshold", "0.25")[0] == 0


@pytest.mark.parametrize("bad", ["-0.1", "1.5", "nan", "inf", "abc"])
def test_bad_threshold_is_usage_exit_2(tmp_path: Path, bad: str) -> None:
    write_base(tmp_path, {m: 0.9 for m in MODELS})
    code = ec.entry(args(tmp_path, "--threshold", bad), runner=FakeClient({}), sleep=lambda _s: None)
    assert code == 2


def test_busy_then_ok_is_retried_not_a_drop(tmp_path: Path) -> None:
    write_base(tmp_path, {m: 0.9 for m in MODELS})
    n_fix = N_FIX
    plan = {MODELS[0]: ("busy-then", n_fix, 0.9), MODELS[1]: 0.9}
    code, _ = run(tmp_path, plan)
    assert code == 0


def test_busy_all_the_way_is_exit_75_not_alert(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write_base(tmp_path, {m: 0.9 for m in MODELS})
    code, _ = run(tmp_path, {MODELS[0]: "busy", MODELS[1]: 0.9})
    assert code == 75
    assert "ALERT" not in capsys.readouterr().err


@pytest.mark.parametrize("kind", ["unreachable", "oserror"])
def test_unreachable_is_reported_never_a_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str], kind: str) -> None:
    path = write_base(tmp_path, {m: 0.9 for m in MODELS})
    before = path.read_bytes()
    code, _ = run(tmp_path, {MODELS[0]: kind, MODELS[1]: 0.9}, "--update-baseline")
    err = capsys.readouterr().err
    assert code == 3
    assert "unreachable" in err.lower() and "ALERT" not in err
    assert path.read_bytes() == before, "a partial run must not write the baseline"


def test_missing_baseline_without_update_is_exit_2(tmp_path: Path) -> None:
    assert run(tmp_path, {m: 0.9 for m in MODELS})[0] == 2


def test_baseline_missing_a_model_is_exit_2(tmp_path: Path) -> None:
    write_base(tmp_path, {MODELS[0]: 0.9})
    assert run(tmp_path, {m: 0.9 for m in MODELS})[0] == 2


def hostile(tmp: Path, kind: str) -> None:
    path = tmp / "base.json"
    if kind == "symlink":
        target = tmp / "real.json"
        target.write_text(json.dumps({"version": 1, "scores": {m: 0.9 for m in MODELS}}))
        path.symlink_to(target)
    elif kind == "oversized":
        path.write_text(" " * (ec.MAX_BASELINE_BYTES + 10))
    elif kind == "malformed":
        path.write_text("{not json")
    elif kind == "duplicate-key":
        path.write_text('{"version":1,"version":1,"scores":{}}')
    elif kind == "fifo":
        os.mkfifo(path)
    elif kind == "not-object":
        path.write_text("[1,2]")
    elif kind == "wrong-version":
        path.write_text(json.dumps({"version": 2, "scores": {m: 0.9 for m in MODELS}}))
    elif kind == "scores-not-dict":
        path.write_text(json.dumps({"version": 1, "scores": [0.9]}))
    elif kind == "string-score":
        path.write_text(json.dumps({"version": 1, "scores": {m: "0.9" for m in MODELS}}))
    elif kind == "bool-score":
        path.write_text(json.dumps({"version": 1, "scores": {m: True for m in MODELS}}))
    elif kind == "out-of-range":
        path.write_text(json.dumps({"version": 1, "scores": {m: 7 for m in MODELS}}))
    elif kind == "nan":
        path.write_text('{"version":1,"scores":{"' + MODELS[0] + '":NaN}}')
    elif kind == "too-many":
        path.write_text(json.dumps({"version": 1, "scores": {f"m{i}": 0.5 for i in range(100)}}))
    elif kind == "bad-utf8":
        path.write_bytes(bytes([0xFF, 0xFE, 0x80]))
    elif kind == "bad-name":
        path.write_text(json.dumps({"version": 1, "scores": {"../x": 0.5, **{m: 0.9 for m in MODELS}}}))


HOSTILE = [
    "symlink", "oversized", "malformed", "duplicate-key", "fifo", "not-object", "wrong-version",
    "scores-not-dict", "string-score", "bool-score", "out-of-range", "nan", "too-many", "bad-name", "bad-utf8",
]  # fmt: skip


@pytest.mark.parametrize("kind", HOSTILE)
def test_hostile_baseline_is_exit_2_and_never_a_pass(tmp_path: Path, kind: str) -> None:
    hostile(tmp_path, kind)
    client = FakeClient({m: 0.9 for m in MODELS})
    code = ec.entry(args(tmp_path), runner=client, sleep=lambda _s: None)
    assert code == 2
    assert client.calls == [], "the baseline is judged before any model call"


@pytest.mark.parametrize("kind", ["symlink", "fifo"])
def test_update_never_writes_through_a_symlink_or_special_file(tmp_path: Path, kind: str) -> None:
    hostile(tmp_path, kind)
    real = tmp_path / "real.json"
    before = real.read_bytes() if real.exists() else None
    code, _ = run(tmp_path, {m: 0.9 for m in MODELS}, "--update-baseline")
    assert code == 2
    if before is not None:
        assert real.read_bytes() == before


def test_update_replaces_a_malformed_regular_file(tmp_path: Path) -> None:
    hostile(tmp_path, "malformed")
    code, _ = run(tmp_path, {m: 0.9 for m in MODELS}, "--update-baseline")
    assert code == 0
    assert json.loads((tmp_path / "base.json").read_text())["version"] == ec.BASELINE_VERSION


def test_guard_negative_the_hostile_list_is_collected_and_a_good_file_passes(tmp_path: Path) -> None:
    assert len(HOSTILE) >= 10
    write_base(tmp_path, {m: 0.9 for m in MODELS})
    assert run(tmp_path, {m: 0.9 for m in MODELS})[0] == 0


def test_mixed_busy_and_scored_is_busy_not_a_partial_score() -> None:
    records = [{"status": "ok", "score": {"passed": True}}] + [{"status": "busy"}] * 9
    assert ec._classify(records) == ("busy", None)


def test_partly_busy_run_is_exit_75_and_never_writes_the_baseline(tmp_path: Path) -> None:
    class Half:
        def __init__(self) -> None:
            self.n = 0

        def __call__(self, fixture: Any, model: str) -> dict[str, Any]:
            self.n += 1
            if self.n % 2:
                return {"status": "ok", "score": {"passed": True}}
            return {"status": "busy"}

    path = write_base(tmp_path, {m: 0.9 for m in MODELS})
    before = path.read_bytes()
    argv = args(tmp_path, "--update-baseline")
    assert ec.entry(argv, runner=Half(), sleep=lambda _s: None) == 75
    assert path.read_bytes() == before


def _ancestor_link(tmp: Path) -> tuple[Path, Path]:
    outside = tmp / "outside"
    (outside / "sub").mkdir(parents=True)
    (tmp / "alias").symlink_to(outside, target_is_directory=True)
    return tmp / "alias" / "sub" / "base.json", outside / "sub" / "base.json"


def test_write_refuses_a_symlink_in_any_ancestor(tmp_path: Path) -> None:
    via, real = _ancestor_link(tmp_path)
    with pytest.raises(ec.CanaryError):
        ec.write_baseline(via, {m: 0.9 for m in MODELS}, population())
    assert not real.exists()
    assert list(real.parent.iterdir()) == []


def test_read_refuses_a_symlink_in_any_ancestor(tmp_path: Path) -> None:
    via, real = _ancestor_link(tmp_path)
    real.write_text(json.dumps({"version": 1, "scores": {m: 0.9 for m in MODELS}}))
    with pytest.raises(ec.CanaryError):
        ec.read_baseline(via)
    client = FakeClient({m: 0.9 for m in MODELS})
    code = ec.entry(["--baseline", str(via), "--tasks", "commit-message"], runner=client, sleep=lambda _s: None)
    assert code == 2 and client.calls == []


def test_write_creates_missing_folders_privately_and_reads_back(tmp_path: Path) -> None:
    path = tmp_path / "a" / "b" / "base.json"
    ec.write_baseline(path, {m: 0.5 for m in MODELS}, population())
    assert ec.read_baseline(path) == {m: 0.5 for m in MODELS}
    assert (path.parent.stat().st_mode & 0o777) == 0o700
    assert (path.stat().st_mode & 0o777) == 0o600
    assert [p.name for p in path.parent.iterdir()] == ["base.json"]


def test_a_busy_model_beats_a_drop_in_the_other_model(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write_base(tmp_path, {m: 1.0 for m in MODELS})
    code, _ = run(tmp_path, {MODELS[0]: "busy", MODELS[1]: 0.0})
    assert code == 75
    assert "ALERT" not in capsys.readouterr().err


def test_an_unreachable_model_beats_a_drop_in_the_other_model(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write_base(tmp_path, {m: 1.0 for m in MODELS})
    code, _ = run(tmp_path, {MODELS[0]: "unreachable", MODELS[1]: 0.0})
    assert code == 3
    assert "ALERT" not in capsys.readouterr().err


def _exit_runner(error: str) -> Any:
    def call(fixture: Any, model: str) -> dict[str, Any]:
        return {"fixture": fixture.id, "status": "failed", "error": error}

    return call


@pytest.mark.parametrize(
    "error", ["exit 30: x", "exit 31: x", "exit 40: x", "exit 49: x", "exit 3", "exit 33", "exit 5: x"]
)
def test_only_exit_3_and_4_are_model_failures(tmp_path: Path, error: str) -> None:
    path = write_base(tmp_path, {m: 0.9 for m in MODELS})
    before = path.read_bytes()
    assert ec.entry(args(tmp_path, "--update-baseline"), runner=_exit_runner(error), sleep=lambda _s: None) == 3
    assert path.read_bytes() == before
    assert ec.entry(args(tmp_path), runner=_exit_runner(error), sleep=lambda _s: None) == 3


@pytest.mark.parametrize("error", ["exit 3: truncated", "exit 4: over the cap"])
def test_exit_3_and_4_still_count_as_not_passed(error: str) -> None:
    assert ec._classify([{"status": "failed", "error": error}]) == ("ok", 0.0)


@pytest.mark.parametrize(
    "rec",
    [None, "x", 5, {"status": "ok", "score": None}, {"status": "ok", "score": []}, {"status": "ok", "score": "x"}],
)
def test_malformed_runner_records_are_unreachable_not_a_crash(rec: Any) -> None:
    assert ec._classify([rec]) == ("unreachable", None)


def test_an_overlong_baseline_name_is_exit_2_not_a_traceback(tmp_path: Path) -> None:
    long = tmp_path / ("x" * 5000)
    code, _ = run(tmp_path, {m: 0.9 for m in MODELS}, "--update-baseline")
    assert code == 0
    with pytest.raises(ec.CanaryError):
        ec.write_baseline(long, {m: 0.9 for m in MODELS}, population())
    assert (
        ec.entry(
            ["--baseline", str(long), "--update-baseline", "--tasks", "commit-message"],
            runner=FakeClient({m: 0.9 for m in MODELS}),
            sleep=lambda _s: None,
        )
        == 2
    )


@pytest.mark.parametrize(("base", "score"), [(0.8, 0.7), (0.9, 0.8), (0.3, 0.2), (0.7, 0.6), (0.6, 0.5)])
def test_a_drop_of_exactly_the_threshold_is_not_an_alert(base: float, score: float) -> None:
    assert not ec.dropped(base, score, 0.1)
    assert ec.dropped(base, score - 0.01, 0.1)


def test_the_baseline_file_and_folder_are_fsynced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    kinds: list[str] = []
    real = os.fsync

    def spy(fd: int) -> None:
        kinds.append("dir" if os.path.isdir(f"/proc/self/fd/{fd}") else "file")
        real(fd)

    monkeypatch.setattr(os, "fsync", spy)
    ec.write_baseline(tmp_path / "base.json", {m: 0.9 for m in MODELS}, population())
    assert kinds == ["file", "dir"]


def test_a_baseline_from_another_task_set_is_exit_2_before_any_call(tmp_path: Path) -> None:
    write_base(tmp_path, {m: 0.9 for m in MODELS}, pop=population(["pr-summary"]))
    client = FakeClient({m: 0.9 for m in MODELS})
    code = ec.entry(args(tmp_path), runner=client, sleep=lambda _s: None)
    assert code == 2 and client.calls == []


def test_a_baseline_without_a_population_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "base.json"
    path.write_text(json.dumps({"version": 1, "scores": {m: 0.9 for m in MODELS}}))
    assert run(tmp_path, {m: 0.9 for m in MODELS})[0] == 2


def test_the_population_changes_with_the_fixture_set_and_content() -> None:
    one = le.load_fixtures(FIXTURES, ["commit-message"])
    both = le.load_fixtures(FIXTURES, ["commit-message", "pr-summary"])
    assert ec.population_id(one) != ec.population_id(both)
    assert ec.population_id(one) == ec.population_id(list(reversed(one)))
    import dataclasses

    edited = [dataclasses.replace(one[0], input=one[0].input + "x"), *one[1:]]
    assert ec.population_id(one) != ec.population_id(edited)


def test_update_stores_the_population_and_compare_accepts_it(tmp_path: Path) -> None:
    assert run(tmp_path, {m: 0.9 for m in MODELS}, "--update-baseline")[0] == 0
    assert json.loads((tmp_path / "base.json").read_text())["population"] == population()
    assert run(tmp_path, {m: 0.9 for m in MODELS})[0] == 0


# ---- qwen silent-truncation probe (#569) ----

QWEN = localdraft.DIGEST_MODEL
CUT_LINE = (
    "llm-local: prompt truncated by the server: estimate {est} tokens, reported {n}; the answer was not used; "
    "fix: route to a long-context model or shorten the prompt"
)


class FakeProbe:
    """A fake llm-local for the probe: a script of (exit code, stderr) per call, no process, no network."""

    def __init__(self, *script: tuple[int, str]) -> None:
        self.script = list(script)
        self.calls: list[tuple[str, str]] = []

    def __call__(self, model: str, prompt: str) -> tuple[int, str]:
        self.calls.append((model, prompt))
        return self.script.pop(0) if len(self.script) > 1 else self.script[0]


def cut(n: int = 4098) -> tuple[int, str]:
    return 3, CUT_LINE.format(est=12000, n=n) + "\n"


def probe(*script: tuple[int, str], extra: tuple[str, ...] = ()) -> tuple[int, FakeProbe]:
    fake = FakeProbe(*script)
    code = ec.entry(["--probe-only", *extra], probe_runner=fake, sleep=lambda _s: None, nonce="n0nce")
    return code, fake


def test_probe_same_cap_is_ok(capsys: pytest.CaptureFixture[str]) -> None:
    code, fake = probe(cut())
    assert code == 0
    assert [m for m, _ in fake.calls] == [QWEN]  # only the model that truncates, no name repeated in code
    assert "ok" in capsys.readouterr().out


def test_probe_prompt_is_long_nonced_and_free_of_private_text() -> None:
    _, fake = probe(cut())
    prompt = fake.calls[0][1]
    assert len(prompt) > ec.PROBE_MIN_CHARS and "n0nce" in prompt[:80]


def test_probe_cap_changed_alerts_exit_1(capsys: pytest.CaptureFixture[str]) -> None:
    code, _ = probe(cut(8192))
    err = capsys.readouterr().err
    assert code == 1 and err.count("ALERT") == 1 and "8192" in err and "4098" in err


def test_probe_cap_lifted_alerts_exit_1(capsys: pytest.CaptureFixture[str]) -> None:
    code, _ = probe((0, ""))  # the guard saw a full prompt: the cut is gone
    assert code == 1 and "ALERT" in capsys.readouterr().err


def test_probe_expected_cap_is_configurable() -> None:
    assert probe(cut(8192), extra=("--expected-cap", "8192"))[0] == 0
    assert probe(cut(), extra=("--expected-cap", "8192"))[0] == 1


@pytest.mark.parametrize("bad", ["0", "-1", "abc", "9999999999"])
def test_probe_bad_expected_cap_is_usage(bad: str) -> None:
    assert probe(cut(), extra=("--expected-cap", bad))[0] == 2


def test_probe_busy_then_ok_is_retried() -> None:
    code, fake = probe((75, "busy"), (75, "busy"), cut())
    assert code == 0 and len(fake.calls) == 3


def test_probe_busy_all_the_way_is_75_not_alert(capsys: pytest.CaptureFixture[str]) -> None:
    code, _ = probe((75, "busy"))
    assert code == 75 and "ALERT" not in capsys.readouterr().err


@pytest.mark.parametrize(
    "result",
    [
        (2, "cannot reach the server"),
        (4, "prompt too large"),
        (3, "unrelated failure"),
        (3, "x " + CUT_LINE.format(est=1, n=2)),
    ],
)
def test_probe_other_failures_are_unreachable_exit_3_never_an_alert(
    result: tuple[int, str], capsys: pytest.CaptureFixture[str]
) -> None:
    code, _ = probe(result)
    assert code == 3 and "ALERT" not in capsys.readouterr().err


def test_probe_cut_line_must_be_anchored_a_quoted_line_is_not_a_cut() -> None:
    quoted = (3, "noise llm-local: prompt truncated by the server: estimate 1 tokens, reported 4098; x")
    assert probe(quoted)[0] == 3


def _with_scoring(tmp: Path, score: float, *script: tuple[int, str]) -> int:
    plan = {m: score for m in MODELS}
    return ec.entry(
        args(tmp, "--truncation-probe"), runner=FakeClient(plan), probe_runner=FakeProbe(*script), sleep=lambda _s: None
    )


def test_probe_runs_beside_scoring_with_unreachable_over_busy_over_drop(tmp_path: Path) -> None:
    write_base(tmp_path, {m: 0.9 for m in MODELS})
    assert _with_scoring(tmp_path, 0.9, cut()) == 0
    assert _with_scoring(tmp_path, 0.9, cut(8192)) == 1
    assert _with_scoring(tmp_path, 0.9, (75, "b")) == 75
    assert _with_scoring(tmp_path, 0.9, (2, "down")) == 3
    # a score drop (1) never hides an unreachable probe (3) or a busy one (75)
    assert _with_scoring(tmp_path, 0.1, cut()) == 1
    assert _with_scoring(tmp_path, 0.1, (75, "b")) == 75
    assert _with_scoring(tmp_path, 0.1, (2, "down")) == 3


def test_probe_not_run_unless_asked(tmp_path: Path) -> None:
    write_base(tmp_path, {m: 0.9 for m in MODELS})
    fake = FakeProbe(cut(8192))
    code = ec.entry(
        args(tmp_path), runner=FakeClient({m: 0.9 for m in MODELS}), probe_runner=fake, sleep=lambda _s: None
    )
    assert code == 0 and fake.calls == []


def test_probe_with_update_baseline_is_usage(tmp_path: Path) -> None:
    assert (
        ec.entry(
            args(tmp_path, "--update-baseline", "--truncation-probe"), runner=FakeClient({}), sleep=lambda _s: None
        )
        == 2
    )


def test_probe_only_reads_and_writes_no_baseline(tmp_path: Path) -> None:
    code = ec.entry(
        ["--probe-only", "--baseline", str(tmp_path / "none.json")],
        probe_runner=FakeProbe(cut()),
        sleep=lambda _s: None,
        nonce="n0nce",
    )
    assert code == 0 and list(tmp_path.iterdir()) == []


def test_default_probe_runner_calls_llm_local_with_loaded_ctx_and_forced_size(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[list[str]] = []

    class Done:
        returncode, stderr = 3, "x"

    def fake_run(argv: Any, timeout: float) -> Done:
        seen.append(list(argv))
        return Done()

    monkeypatch.setattr(le, "_run_cmd", fake_run)
    ec._default_probe_runner(30)(QWEN, "PROMPT")
    argv = seen[0]
    assert argv[0] == "llm-local" and "--force-size" in argv and argv[-1] == "PROMPT"
    assert "--num-ctx" not in argv and "--no-truncation-guard" not in argv  # llm-local sends the loaded context itself


# ---- #575 follow-ups: caps, precedence, durability, malformed scores, temp names, races ----


@pytest.mark.parametrize(
    "flag",
    [
        ("--busy-retries", str(ec.MAX_BUSY_RETRIES + 1)),
        ("--wait", str(ec.MAX_WAIT + 1)),
        ("--repeats", str(ec.MAX_REPEATS + 1)),
    ],
)
@pytest.mark.parametrize("probe_only", [False, True])
def test_a_flag_above_its_cap_is_exit_2_before_any_call(
    tmp_path: Path, flag: tuple[str, str], probe_only: bool
) -> None:
    write_base(tmp_path, {m: 0.9 for m in MODELS})
    client = FakeClient({m: 0.9 for m in MODELS})
    probe = FakeProbe((0, ""))
    extra = ["--probe-only"] if probe_only else []
    argv = [*args(tmp_path), *extra, *flag]
    assert ec.entry(argv, runner=client, sleep=lambda _s: None, probe_runner=probe) == 2
    assert client.calls == [] and probe.calls == []


@pytest.mark.parametrize(
    "flag",
    [("--busy-retries", str(ec.MAX_BUSY_RETRIES)), ("--wait", str(ec.MAX_WAIT)), ("--repeats", str(ec.MAX_REPEATS))],
)
def test_a_flag_at_its_cap_is_accepted(tmp_path: Path, flag: tuple[str, str]) -> None:
    write_base(tmp_path, {m: 0.9 for m in MODELS})
    argv = ["--baseline", str(tmp_path / "base.json"), "--tasks", "commit-message", *flag]
    client = FakeClient({m: 0.9 for m in MODELS})
    assert ec.entry(argv, runner=client, sleep=lambda _s: None) == 0


def test_one_sleep_is_capped_and_the_total_is_bounded(tmp_path: Path) -> None:
    write_base(tmp_path, {m: 1.0 for m in MODELS})
    naps: list[float] = []
    argv = [
        "--baseline",
        str(tmp_path / "base.json"),
        "--tasks",
        "commit-message",
        "--busy-retries",
        str(ec.MAX_BUSY_RETRIES),
    ]
    code = ec.entry(argv, runner=FakeClient({m: "busy" for m in MODELS}), sleep=naps.append)
    assert code == 75
    assert naps and max(naps) <= ec.MAX_SLEEP
    assert sum(naps) <= ec.MAX_TOTAL_SLEEP


def test_the_probe_shares_the_total_sleep_deadline(tmp_path: Path) -> None:
    write_base(tmp_path, {m: 1.0 for m in MODELS})
    naps: list[float] = []
    argv = [
        "--baseline",
        str(tmp_path / "base.json"),
        "--tasks",
        "commit-message",
        "--truncation-probe",
        "--busy-retries",
        str(ec.MAX_BUSY_RETRIES),
    ]
    ec.entry(argv, runner=FakeClient({m: "busy" for m in MODELS}), sleep=naps.append, probe_runner=FakeProbe((75, "")))
    assert sum(naps) <= ec.MAX_TOTAL_SLEEP


@pytest.mark.parametrize(
    "records",
    [
        [{"status": "failed", "error": "exit 2: offline"}, {"status": "busy"}],
        [{"status": "busy"}, {"status": "failed", "error": "exit 2: offline"}],
        [{"status": "ok", "score": None}, {"status": "busy"}],
        [{"status": "busy"}, {"status": "ok", "score": None}],
        [None, {"status": "busy"}],
        [{"status": "busy"}, "x"],
    ],
)
def test_busy_wins_over_unreachable_or_malformed_in_either_order(records: list[Any]) -> None:
    assert ec._classify(records) == ("busy", None)


def test_unreachable_without_busy_stays_unreachable() -> None:
    assert ec._classify([{"status": "ok", "score": {"passed": True}}, {"status": "failed", "error": "exit 2: x"}]) == (
        "unreachable",
        None,
    )


@pytest.mark.parametrize("first", [True, False])
def test_busy_plus_unreachable_is_retried_and_ends_exit_75(tmp_path: Path, first: bool) -> None:
    write_base(tmp_path, {m: 0.9 for m in MODELS})
    calls = {"n": 0}

    def runner(fixture: Any, model: str) -> dict[str, Any]:
        calls["n"] += 1
        busy = {"status": "busy"}
        bad = {"status": "failed", "error": "exit 2: offline"}
        return (busy if (calls["n"] % 2) == first else bad) | {"fixture": fixture.id}

    naps: list[float] = []
    assert ec.entry(args(tmp_path), runner=runner, sleep=naps.append) == 75
    assert len(naps) >= 2, "the mixed attempt was retried, not given up on at once"


@pytest.mark.parametrize("passed", [None, "true", 1, 0, [], {}])
def test_an_ok_record_with_a_non_bool_passed_is_not_a_failed_run(passed: Any) -> None:
    assert ec._classify([{"status": "ok", "score": {"passed": passed}}]) == ("unreachable", None)
    assert ec._classify([{"status": "ok", "score": {}}]) == ("unreachable", None)


def test_a_malformed_ok_score_never_writes_a_zero_baseline(tmp_path: Path) -> None:
    def runner(fixture: Any, model: str) -> dict[str, Any]:
        return {"status": "ok", "score": {"passed": "yes"}}

    assert ec.entry(args(tmp_path, "--update-baseline"), runner=runner, sleep=lambda _s: None) == 3
    assert not (tmp_path / "base.json").exists()


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -0.1, 1.5, True])
def test_a_score_that_is_not_a_proportion_is_refused_before_it_is_written(tmp_path: Path, bad: Any) -> None:
    with pytest.raises(ec.CanaryError):
        ec.write_baseline(tmp_path / "base.json", {m: bad for m in MODELS}, population())
    assert not (tmp_path / "base.json").exists()
    assert list(tmp_path.iterdir()) == []


def test_new_directory_components_are_fsynced_in_their_parents(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    synced: list[str] = []
    real = os.fsync

    def spy(fd: int) -> None:
        synced.append(os.readlink(f"/proc/self/fd/{fd}"))
        real(fd)

    monkeypatch.setattr(os, "fsync", spy)
    ec.write_baseline(tmp_path / "a" / "b" / "base.json", {m: 0.9 for m in MODELS}, population())
    assert str(tmp_path) in synced, "the parent of the first new folder"
    assert str(tmp_path / "a") in synced, "the parent of the second new folder"
    assert str(tmp_path / "a" / "b") in synced


def test_an_existing_path_costs_no_extra_fsync(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    n: list[int] = []
    real = os.fsync

    def spy(fd: int) -> None:
        n.append(fd)
        real(fd)

    monkeypatch.setattr(os, "fsync", spy)
    ec.write_baseline(tmp_path / "base.json", {m: 0.9 for m in MODELS}, population())
    assert len(n) == 2


def test_a_stale_temp_file_from_a_crashed_run_does_not_block_an_update(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stale = tmp_path / f".base.json.{os.getpid()}.deadbeefdeadbeef.tmp"
    stale.write_text("partial")
    seq = iter(["deadbeefdeadbeef", "0123456789abcdef"])
    monkeypatch.setattr(secrets, "token_hex", lambda _n=8: next(seq))
    ec.write_baseline(tmp_path / "base.json", {m: 0.9 for m in MODELS}, population())
    assert ec.read_baseline(tmp_path / "base.json") == {m: 0.9 for m in MODELS}
    assert stale.read_text() == "partial", "a file this run did not create is never deleted"


def test_the_legacy_pid_named_temp_file_does_not_block_either(tmp_path: Path) -> None:
    (tmp_path / f".base.json.{os.getpid()}.tmp").write_text("partial")
    ec.write_baseline(tmp_path / "base.json", {m: 0.9 for m in MODELS}, population())
    assert ec.read_baseline(tmp_path / "base.json")


def test_a_hard_linked_baseline_is_replaced_not_written_through(tmp_path: Path) -> None:
    outside = tmp_path / "outside.json"
    outside.write_text("keep me")
    (tmp_path / "base.json").hardlink_to(outside)
    ec.write_baseline(tmp_path / "base.json", {m: 0.9 for m in MODELS}, population())
    assert outside.read_text() == "keep me"
    assert ec.read_baseline(tmp_path / "base.json") == {m: 0.9 for m in MODELS}
    assert (tmp_path / "base.json").stat().st_ino != outside.stat().st_ino


def test_concurrent_writers_leave_one_complete_baseline_and_no_temp_files(tmp_path: Path) -> None:
    path = tmp_path / "base.json"
    errors: list[BaseException] = []
    start = threading.Barrier(8)

    def writer(i: int) -> None:
        try:
            start.wait()
            for _ in range(3):
                ec.write_baseline(path, {m: (i % 10) / 10 for m in MODELS}, population())
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    got = ec.read_baseline(path)
    assert len(set(got.values())) == 1 and set(got) == set(MODELS)
    assert [p.name for p in tmp_path.iterdir()] == ["base.json"]


def test_swapping_the_parent_after_the_walk_does_not_redirect_the_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "d"
    parent.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    real = os.rename

    def swap_then_rename(src: Any, dst: Any, **kw: Any) -> None:
        real(parent, tmp_path / "d.moved")
        parent.symlink_to(elsewhere, target_is_directory=True)  # the old name now points somewhere else
        real(src, dst, **kw)

    monkeypatch.setattr(os, "rename", swap_then_rename)
    ec.write_baseline(parent / "base.json", {m: 0.9 for m in MODELS}, population())
    assert list(elsewhere.iterdir()) == [], "nothing landed through the swapped name"
    assert (tmp_path / "d.moved" / "base.json").is_file()


def test_the_exact_threshold_boundary_at_the_command_level(tmp_path: Path) -> None:
    score = round(0.5 * N_FIX) / N_FIX
    write_base(tmp_path, {m: round(score + 0.1, 4) for m in MODELS})
    assert run(tmp_path, {m: 0.5 for m in MODELS})[0] == 0, "a drop of exactly 0.10 is not an alert"
    write_base(tmp_path, {m: round(score + 0.1001, 4) for m in MODELS})
    assert run(tmp_path, {m: 0.5 for m in MODELS})[0] == 1


def test_the_default_runner_sleeps_inside_the_same_total_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stand-in for run_one that is busy on every call and backs off like it (2, 4, 8, 16 seconds) through the
    `sleep` it is given; a sleep it makes on its own (the default) is recorded as unbudgeted."""
    unbudgeted: list[float] = []

    def busy_run_one(fx: Any, model: str, *, sleep: Any = unbudgeted.append, **_kw: Any) -> dict[str, Any]:
        for k in range(4):
            sleep(2.0 * 2**k)
        return {"fixture": fx.id, "task": fx.task, "model": model, "status": "busy"}

    monkeypatch.setattr(le, "run_one", busy_run_one)
    write_base(tmp_path, {m: 1.0 for m in MODELS})
    naps: list[float] = []
    argv = ["--baseline", str(tmp_path / "base.json"), "--tasks", "commit-message", "--busy-retries", "10"]
    assert ec.entry(argv, sleep=naps.append) == 75
    assert unbudgeted == [], "every sleep of the real runner goes through the run's budget"
    assert naps and sum(naps) <= ec.MAX_TOTAL_SLEEP and max(naps) <= ec.MAX_SLEEP
