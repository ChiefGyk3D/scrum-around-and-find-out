# SPDX-License-Identifier: Apache-2.0
"""Tests for safo-eval-canary (#540): baseline compare, drop alert, busy retry, unreachable, hostile baselines."""

from __future__ import annotations

import json
import os
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


def write_base(tmp: Path, scores: dict[str, float]) -> Path:
    path = tmp / "base.json"
    path.write_text(json.dumps({"version": 1, "scores": scores}), encoding="utf-8")
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
    elif kind == "bad-name":
        path.write_text(json.dumps({"version": 1, "scores": {"../x": 0.5, **{m: 0.9 for m in MODELS}}}))


HOSTILE = [
    "symlink", "oversized", "malformed", "duplicate-key", "fifo", "not-object", "wrong-version",
    "scores-not-dict", "string-score", "bool-score", "out-of-range", "nan", "too-many", "bad-name",
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
    assert json.loads((tmp_path / "base.json").read_text())["version"] == 1


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
        ec.write_baseline(via, {m: 0.9 for m in MODELS})
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
    ec.write_baseline(path, {m: 0.5 for m in MODELS})
    assert ec.read_baseline(path) == {m: 0.5 for m in MODELS}
    assert (path.parent.stat().st_mode & 0o777) == 0o700
    assert (path.stat().st_mode & 0o777) == 0o600
    assert [p.name for p in path.parent.iterdir()] == ["base.json"]
