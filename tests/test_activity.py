# SPDX-License-Identifier: Apache-2.0
"""safo-activity: the status line, the table, the event monitor and the five providers (codex, quota, ledger, ollama,
copilot). Everything runs against files under tmp_path, the fake Ollama on loopback and a fake `gh` script; nothing
reads the real home directory or leaves the machine."""

from __future__ import annotations

import io
import json
import os
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest

from fakeollama import FakeOllama
from hooksdata import agents_file
from safo import activity

NOW = time.mktime(time.strptime("2026-11-09 12:00:00", "%Y-%m-%d %H:%M:%S"))  # local noon: no midnight edge


def stamp(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def no_ctrl(text: str) -> bool:
    return not any((ord(c) < 32 and c != "\n") or ord(c) == 127 for c in text)


class Box:
    """A scrubbed home, an empty PATH folder for stubs, and the environment that points at them."""

    def __init__(self, root: Path) -> None:
        self.home = root / "home"
        self.bin = root / "bin"
        self.run = root / "run"
        for p in (self.home, self.bin, self.run):
            p.mkdir(mode=0o700)
        self.vars: dict[str, str] = {
            "HOME": str(self.home),
            "PATH": str(self.bin),
            "XDG_RUNTIME_DIR": str(self.run),
            "XDG_CONFIG_HOME": str(self.home / ".config"),
        }

    @property
    def jobs(self) -> Path:
        d = self.home / ".claude/plugins/data/codex-openai-codex/state/ws/jobs"
        d.mkdir(parents=True, exist_ok=True)
        return d

    @property
    def ledger(self) -> Path:
        d = self.home / ".local/share/safo"
        d.mkdir(parents=True, exist_ok=True)
        return d / "gemini-spend-ledger.jsonl"

    def job(self, name: str, **fields: Any) -> Path:
        path = self.jobs / f"{name}.json"
        path.write_text(json.dumps(fields))
        return path

    def rows(self, *rows: dict[str, Any]) -> Path:
        self.ledger.write_text("".join(json.dumps(r) + "\n" for r in rows))
        return self.ledger

    def rollout(self, name: str, *lines: str, age: float = 0.0) -> Path:
        d = self.home / ".codex/sessions/2026/11/09"
        d.mkdir(parents=True, exist_ok=True)
        path = d / f"rollout-{name}.jsonl"
        path.write_text("".join(line + "\n" for line in lines))
        os.utime(path, (NOW - age, NOW - age))
        return path

    def read(self, only: str = "", network: bool = False) -> activity.Reading:
        return activity.read_all(self.vars, NOW, activity.load_config(self.vars), network=network, only=only)

    def line(self) -> str:
        return activity.render_line(self.read())

    def table(self) -> str:
        return "\n".join(activity.render_table(self.read()))

    def main(self, *argv: str) -> tuple[int, str]:
        out = io.StringIO()
        return activity.main(list(argv), self.vars, out), out.getvalue()


@pytest.fixture
def box(tmp_path: Path) -> Box:
    return Box(tmp_path)


def dead_pid() -> int:
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    return proc.pid


# -- configuration ---------------------------------------------------------------------------------


def test_with_no_configuration_only_the_local_file_providers_are_read(box: Box) -> None:
    cfg = activity.load_config(box.vars)
    assert cfg.providers == ("codex", "quota", "ledger")
    assert "ollama" not in cfg.providers
    assert "copilot" not in cfg.providers
    assert box.line() == ""  # idle: nothing to show


def test_the_environment_wins_over_the_config_file_and_unknown_names_are_noted(box: Box) -> None:
    conf = box.home / ".config/safo"
    conf.mkdir(parents=True)
    (conf / "activity.yaml").write_text("providers: [codex, copilot]\ncopilot:\n  owner: N0TST\n")
    from_file = activity.load_config(box.vars)
    assert from_file.providers == ("codex", "copilot")
    assert from_file.owner == "N0TST"
    box.vars["SAFO_ACTIVITY_PROVIDERS"] = "ledger, bogus ,gemini"
    from_env = activity.load_config(box.vars)
    assert from_env.providers == ("ledger",)  # gemini is an alias of ledger
    assert len(from_env.notes) == 1
    assert "bogus" in from_env.notes[0]


@pytest.mark.parametrize("text", ["providers: [", "- not\n- a mapping", "providers: {a: b}", "\x00\x01"])
def test_a_broken_config_file_falls_back_to_the_defaults(box: Box, text: str) -> None:
    conf = box.home / ".config/safo"
    conf.mkdir(parents=True)
    (conf / "activity.yaml").write_text(text)
    assert activity.load_config(box.vars).providers == activity.DEFAULT_PROVIDERS


def test_a_symlinked_config_file_is_ignored(box: Box, tmp_path: Path) -> None:
    conf = box.home / ".config/safo"
    conf.mkdir(parents=True)
    target = tmp_path / "elsewhere.yaml"
    target.write_text("providers: [copilot]\n")
    (conf / "activity.yaml").symlink_to(target)
    assert activity.load_config(box.vars).providers == activity.DEFAULT_PROVIDERS


# -- codex jobs ------------------------------------------------------------------------------------


def test_codex_counts_live_pids_and_recent_completions_only(box: Box) -> None:
    started = stamp(NOW - 90)
    box.job(
        "live",
        status="running",
        phase="working",
        pid=os.getpid(),
        kindLabel="rescue",
        title="Live job",
        startedAt=started,
    )
    box.job(
        "dead",
        status="running",
        phase="working",
        pid=dead_pid(),
        kindLabel="rescue",
        title="Dead job",
        startedAt=started,
    )
    box.job("zero", status="running", phase="x", pid=0, kindLabel="k", title="Group pid", startedAt=started)
    box.job(
        "new",
        status="completed",
        phase="done",
        pid=None,
        kindLabel="review",
        title="Finished",
        completedAt=stamp(NOW - 60),
    )
    box.job(
        "old",
        status="completed",
        phase="done",
        pid=None,
        kindLabel="review",
        title="Old job",
        completedAt=stamp(NOW - 10800),
    )
    box.job("failed", status="failed", phase="x", pid=os.getpid(), kindLabel="k", title="Failed job", startedAt=started)
    (box.jobs / "bad.json").write_text('{"status":"running","pid": 1234, "title": "broken')
    assert box.line() == "cx 1 run Live job 1\u2713"
    table = box.table()
    assert "Codex: 1 running, 1 done (last 60m)" in table
    assert "Live job" in table
    assert "run  90s" in table
    assert "Finished" in table
    for hidden in ("Dead job", "Group pid", "Old job", "Failed job"):
        assert hidden not in table


def test_a_symlinked_job_file_is_ignored(box: Box, tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    real.write_text(json.dumps({"status": "running", "pid": os.getpid(), "title": "Linked", "startedAt": stamp(NOW)}))
    (box.jobs / "link.json").symlink_to(real)
    assert box.line() == ""


def test_hostile_job_text_is_plain_and_short_in_every_view(box: Box) -> None:
    title = "\x1b[31mRED\x1b[0m \x1b[2J\x1b[HX\ttab\nnewline\x07bell\x00nul " + "A" * 300
    box.job(
        "h",
        status="running",
        phase="do\x1b[2Jne",
        pid=os.getpid(),
        kindLabel="res\x1b]0;pwn\x07c",
        title=title,
        startedAt=stamp(NOW),
    )
    line, table = box.line(), box.table()
    for text in (line, table, json.dumps(activity.render_json(box.read()))):
        assert no_ctrl(text)
    assert "RED" in table
    assert "A" * 60 not in table
    assert len(line.split(" ol")[0]) < 90


def test_the_control_character_guard_bites() -> None:
    assert not no_ctrl("a\x1b[2Jb")
    assert not no_ctrl("a\tb")
    assert no_ctrl("plain text\nsecond line")


def test_clean_keeps_printable_ascii_and_nothing_else() -> None:
    assert activity.clean("a\x1b[2J b\x00\u202e\u00e9  c\n") == "a [2J b c "
    assert activity.clean("x" * 500, 20) == "x" * 20


def test_human_age_steps() -> None:
    assert [activity.human_age(s) for s in (-5, 59, 119, 120, 7199, 7200, 172799, 172800)] == [
        "0s", "59s", "119s", "2m", "119m", "2h", "47h", "2d",
    ]  # fmt: skip


# -- ledger ----------------------------------------------------------------------------------------


def start_row(call: str, job: str, t: float, **extra: Any) -> dict[str, Any]:
    return {"type": "call_start", "call_id": call, "ts": stamp(t), "job": job, **extra}


def end_row(call: str, t: float) -> dict[str, Any]:
    return {"type": "call_end", "call_id": call, "ts": stamp(t)}


def test_ledger_shows_counts_ages_and_never_content(box: Box) -> None:
    path = box.rows(
        {"type": "chain_start", "ts": "2020-01-01T00:00:00Z", "hash": "x"},
        start_row("A", "research-one", NOW - 120, prompt="SECRETPROMPT"),
        start_row("B", "finished-job", NOW - 100, prompt="SECRETPROMPT"),
        end_row("B", NOW - 90),
        start_row("C", "yesterday-job", NOW - 30 * 3600),
    )
    before = path.read_bytes()
    line, table = box.line(), box.table()
    assert line == "gm 3 90s"
    assert "Ledger: 3 entries today, newest 90s ago" in table
    row = next(x for x in table.splitlines() if "research-one" in x)
    assert "in flight 2m" in row
    assert "finished-job" not in table
    assert "yesterday-job" not in table
    assert "call_start today with no call_end" in table
    for text in (line, table, json.dumps(activity.render_json(box.read()))):
        assert "SECRETPROMPT" not in text
    assert path.read_bytes() == before  # read only
    assert path.stat().st_mtime_ns == path.stat().st_mtime_ns


def test_ledger_without_call_rows_says_start_and_end_cannot_be_told_apart(box: Box) -> None:
    box.rows({"type": "usage", "ts": stamp(NOW - 5)})
    assert "cannot be told apart" in box.table()
    assert box.line() == "gm 1 5s"


def test_a_broken_chain_and_garbage_lines_do_not_raise(box: Box) -> None:
    good = json.dumps(start_row("A", "job-a", NOW - 10, hash="not-the-real-hash", prev_hash="nope"))
    box.ledger.write_text("not json\n[1,2]\n" + "[" * 5000 + "\n" + good + "\n" + '{"type":"call_end","call_id":"Z"')
    assert "job-a" in box.table()
    assert box.line() == "gm 1 10s"


def test_ledger_symlink_missing_and_fifo_are_left_out(box: Box, tmp_path: Path) -> None:
    assert box.read().ledger == activity.LedgerSnap()
    real = tmp_path / "real.jsonl"
    real.write_text(json.dumps(start_row("A", "x", NOW)) + "\n")
    box.ledger.symlink_to(real)
    assert box.line() == ""
    assert "Ledger: not found or unreadable (segment omitted)" in box.table()
    box.ledger.unlink()
    os.mkfifo(box.ledger)
    assert activity.tail_rows(box.ledger) is None  # a FIFO is never waited on


def test_ledger_path_comes_from_gemini_yaml_when_it_is_absolute(box: Box, tmp_path: Path) -> None:
    other = tmp_path / "elsewhere.jsonl"
    other.write_text(json.dumps(start_row("A", "moved-job", NOW - 5)) + "\n")
    conf = box.home / ".config/safo"
    conf.mkdir(parents=True)
    (conf / "gemini.yaml").write_text(f"model: x\nledger: {other}\n")
    assert "moved-job" in box.table()
    (conf / "gemini.yaml").write_text("ledger: relative/path.jsonl\n")
    assert activity.ledger_path(box.vars, str(box.home)) == box.home / ".local/share/safo/gemini-spend-ledger.jsonl"


def test_a_huge_ledger_is_tail_read_only(box: Box) -> None:
    filler = json.dumps({"type": "usage", "ts": "2020-01-01T00:00:00Z", "pad": "x" * 200}) + "\n"
    with box.ledger.open("w") as handle:
        handle.write(filler * 6000)  # about 1.3 MB
        handle.write(json.dumps(start_row("A", "tail-job", NOW - 3)) + "\n")
    rows = activity.tail_rows(box.ledger)
    assert rows is not None
    assert len(rows) <= activity.LEDGER_TAIL_LINES
    assert "tail-job" in box.table()


def test_hostile_ledger_job_names_are_sanitized(box: Box) -> None:
    box.rows(start_row("H", "x\x1b[2Jy\x07z" + "B" * 200, NOW - 5))
    table = box.table()
    assert no_ctrl(table)
    assert "B" * 41 not in table


# -- quota: codex rollouts -------------------------------------------------------------------------


def token_event(t: float, primary: Any, secondary: Any, plan: Any = "prolite") -> str:
    limits = {"limit_id": "codex", "primary": primary, "secondary": secondary, "plan_type": plan}
    return json.dumps(
        {"timestamp": stamp(t), "type": "event_msg", "payload": {"type": "token_count", "rate_limits": limits}}
    )


def test_codex_quota_reads_the_last_event_and_omits_a_null_window(box: Box) -> None:
    older = {"used_percent": 7.0, "window_minutes": 10080, "resets_at": None}
    box.rollout(
        "a",
        token_event(NOW - 900, older, None),
        '{"type":"event_msg","payload":{"type":"agent_message"}}',
        token_event(NOW - 240, {"used_percent": 1.0, "window_minutes": 10080, "resets_in_seconds": None}, {
            "used_percent": None, "window_minutes": None, "resets_in_seconds": None}),
    )  # fmt: skip
    quota = box.read().quota
    assert quota is not None
    assert [(w.label, w.percent) for w in quota.codex.windows] == [("wk", 1.0)]
    assert quota.codex.age == 240
    assert quota.codex.plan == "prolite"
    assert box.line() == "cx 1% wk, age 4m"
    table = box.table()
    assert "Quota Codex (prolite): read 4m ago" in table
    assert "  1% used  wk" in table


def test_codex_quota_labels_windows_and_shows_the_time_left(box: Box) -> None:
    primary = {"used_percent": 42.5, "window_minutes": 300, "resets_in_seconds": 5400}
    secondary = {"used_percent": 9, "window_minutes": 10080, "resets_at": NOW + 3 * 86400}
    odd = {"used_percent": 3, "window_minutes": 720}
    box.rollout("a", token_event(NOW - 30, primary, secondary), token_event(NOW - 20, odd, None))
    assert box.line() == "cx 3% 12h, age 20s"
    box.rollout("a", token_event(NOW - 30, primary, secondary))
    assert box.line() == "cx 42% 5h 9% wk, age 30s"
    table = box.table()
    assert "42% used  5h, resets in 90m" in table
    assert "9% used  wk, resets in 3d" in table


def test_a_quota_reading_older_than_30_minutes_is_marked_stale(box: Box) -> None:
    box.rollout("a", token_event(NOW - 3600, {"used_percent": 5, "window_minutes": 300}, None))
    assert box.line() == "cx 5% 5h, age 60m stale"
    assert "STALE" in box.table()


def test_only_the_newest_three_rollouts_are_looked_at(box: Box) -> None:
    box.rollout("old", token_event(NOW, {"used_percent": 99, "window_minutes": 300}, None), age=9000)
    for i in range(3):
        box.rollout(f"empty{i}", '{"type":"event_msg","payload":{"type":"agent_message"}}', age=100 - i)
    assert box.read().quota == activity.QuotaSnap()  # the fourth newest is never opened
    box.rollout("empty0", token_event(NOW - 10, {"used_percent": 8, "window_minutes": 300}, None), age=50)
    assert box.line() == "cx 8% 5h, age 10s"


def test_quota_with_no_sessions_a_malformed_last_line_or_a_huge_file(box: Box) -> None:
    assert box.read().quota == activity.QuotaSnap()
    assert box.line() == ""
    good = token_event(NOW - 60, {"used_percent": 11, "window_minutes": 10080}, None)
    box.rollout("a", good, '{"payload": {"rate_limits": {"primary": ', "[[[[[[")
    assert box.line() == "cx 11% wk, age 60s"
    path = box.rollout("a", good)
    with path.open("a") as handle:  # 3 MB of other events after the reading: it is beyond the 256 KiB tail
        pad = json.dumps({"type": "event_msg", "payload": {"type": "agent_message", "text": "x" * 1000}}) + "\n"
        handle.write(pad * 3000)
    assert box.line() == ""
    with path.open("a") as handle:
        handle.write(token_event(NOW - 5, {"used_percent": 12, "window_minutes": 10080}, None) + "\n")
    assert box.line() == "cx 12% wk, age 5s"


@pytest.mark.parametrize(
    "window",
    [
        {"used_percent": True, "window_minutes": 300},
        {"used_percent": "50", "window_minutes": 300},
        {"used_percent": 150, "window_minutes": 300},
        {"used_percent": -1, "window_minutes": 300},
        {"used_percent": 5, "window_minutes": 0},
        {"used_percent": 5, "window_minutes": 10**9},
        {"used_percent": float("nan"), "window_minutes": 300},
        [1, 2],
        "text",
    ],
)
def test_odd_quota_windows_are_left_out(box: Box, window: Any) -> None:
    box.rollout("a", token_event(NOW - 5, window, None).replace("NaN", "null"))
    assert box.read().quota == activity.QuotaSnap(activity.Quota((), 5.0, "prolite"), activity.Quota())
    assert box.line() == ""


def test_a_hostile_plan_label_is_dropped_and_never_printed(box: Box) -> None:
    window = {"used_percent": 2, "window_minutes": 300}
    for plan in ("pro\x1b[2J", "a" * 40, "pro lite", 7, None):
        box.rollout("a", token_event(NOW - 5, window, None, plan))
        quota = box.read().quota
        assert quota is not None
        assert quota.codex.plan == ""
        assert no_ctrl(box.table() + box.line())
        assert "Quota Codex: read" in box.table()


def test_a_symlinked_rollout_is_not_followed(box: Box, tmp_path: Path) -> None:
    real = tmp_path / "real.jsonl"
    real.write_text(token_event(NOW, {"used_percent": 9, "window_minutes": 300}, None) + "\n")
    d = box.home / ".codex/sessions/2026/11/09"
    d.mkdir(parents=True)
    (d / "rollout-link.jsonl").symlink_to(real)
    assert box.line() == ""


# -- quota: the Claude cache file ------------------------------------------------------------------


def claude_doc(captured: float, *windows: dict[str, Any]) -> dict[str, Any]:
    return {"captured_at": stamp(captured), "windows": list(windows)}


def put_claude(box: Box, doc: Any, mode: int = 0o600) -> Path:
    path = box.home / ".cache/safo/claude-usage.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(doc if isinstance(doc, str) else json.dumps(doc))
    path.chmod(mode)
    return path


def test_claude_quota_present(box: Box) -> None:
    put_claude(
        box,
        claude_doc(
            NOW - 120,
            {"label": "5h", "used_percent": 41.2, "resets_at": stamp(NOW + 3600)},
            {"label": "wk", "used_percent": 12},
        ),
    )
    assert box.line() == "cl 41% 5h 12% wk, age 2m"
    table = box.table()
    assert "Quota Claude: read 2m ago" in table
    assert "41% used  5h, resets in 60m" in table
    assert "12% used  wk" in table
    assert json.loads(json.dumps(activity.render_json(box.read())))["quota"]["claude"]["windows"][0]["label"] == "5h"


def test_claude_quota_stale_missing_and_malformed(box: Box) -> None:
    assert box.line() == ""  # missing: nothing
    path = put_claude(box, claude_doc(NOW - 4000, {"label": "5h", "used_percent": 10}))
    assert box.line() == "cl 10% 5h, age 66m stale"
    for bad in (
        "not json",
        "[]",
        '{"windows": "x", "captured_at": "2026-11-09T11:00:00Z"}',
        json.dumps({"windows": [{"label": "5h", "used_percent": 1}]}),  # no captured_at
        json.dumps(claude_doc(NOW, {"label": "5h", "used_percent": 500}, {"label": "", "used_percent": 5})),
        "[" * 5000,
    ):
        path.write_text(bad)
        assert box.line() == "", bad[:30]
    path.write_text(json.dumps(claude_doc(NOW - 5, {"label": "5\x1b[2Jh", "used_percent": 3})))
    assert no_ctrl(box.line())


def test_claude_quota_refuses_a_symlink_and_a_group_writable_file(box: Box, tmp_path: Path) -> None:
    doc = claude_doc(NOW - 5, {"label": "5h", "used_percent": 3})
    path = put_claude(box, doc, mode=0o620)
    assert box.line() == ""  # group writable
    path.chmod(0o602)
    assert box.line() == ""  # world writable
    path.chmod(0o600)
    assert box.line() == "cl 3% 5h, age 5s"
    path.unlink()
    real = tmp_path / "real.json"
    real.write_text(json.dumps(doc))
    real.chmod(0o600)
    path.symlink_to(real)
    assert box.line() == ""


def test_write_claude_usage_is_atomic_private_and_validates(box: Box) -> None:
    now = time.time()
    doc = claude_doc(now, {"label": "5h", "used_percent": 20, "extra": "dropped"}, {"label": "wk", "used_percent": 5})
    doc["prompt"] = "SECRETPROMPT"
    assert activity.write_claude_usage(doc, box.vars) is True
    path = box.home / ".cache/safo/claude-usage.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    saved = path.read_text()
    assert "SECRETPROMPT" not in saved
    assert "dropped" not in saved
    assert not [p for p in path.parent.iterdir() if p != path]  # no temporary file left behind
    assert box.line().startswith("cl 20% 5h 5% wk, age ")
    bad_docs: list[Any] = [
        {"windows": []},
        {"captured_at": stamp(now), "windows": [{"label": "x", "used_percent": 900}]},
        [1],
        "s",
    ]
    for bad in bad_docs:
        assert activity.write_claude_usage(bad, box.vars) is False
    assert path.read_text() == saved  # a refused document leaves the old file alone


def test_the_quota_provider_makes_no_network_call(box: Box, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: Any, **k: Any) -> Any:
        raise AssertionError("quota touched the network")

    monkeypatch.setattr("socket.socket.connect", boom)
    monkeypatch.setattr("subprocess.run", boom)
    monkeypatch.setattr("subprocess.Popen", boom)
    box.rollout("a", token_event(NOW, {"used_percent": 1, "window_minutes": 300}, None))
    put_claude(box, claude_doc(NOW, {"label": "5h", "used_percent": 2}))
    assert box.line() == "cx 1% 5h, age 0s cl 2% 5h, age 0s"


# -- ollama ----------------------------------------------------------------------------------------


def fake_ss(box: Box, count: int) -> None:
    ss = box.bin / "ss"
    ss.write_text("#!/bin/sh\n" + "".join("echo ESTAB 0 0 a b\n" for _ in range(count)))
    ss.chmod(0o755)


def test_ollama_is_opt_in_and_with_no_endpoint_makes_no_call(box: Box, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr("safo.ollama._request", lambda *a, **k: calls.append("called"))
    assert box.line() == ""  # not enabled: not even looked at
    box.vars["SAFO_ACTIVITY_PROVIDERS"] = "ollama"
    assert box.line() == ""
    assert "Ollama: no endpoint configured" in box.table()
    assert calls == []


def test_ollama_reads_only_the_loaded_listing_from_llm_local_url(box: Box) -> None:
    box.vars["SAFO_ACTIVITY_PROVIDERS"] = "ollama"
    with FakeOllama(installed=["x"], loaded=["qwen3:8b", "reg.example/org/llama3:latest"]).serve() as fake:
        box.vars["LLM_LOCAL_URL"] = fake.url + "/"
        assert box.line() == "ol:qwen3:8b,llama3"
        fake_ss(box, 2)
        assert box.line() == "ol:qwen3:8b,llama3 busy"
        table = box.table()
        assert "Ollama: 2 loaded, 2 established connection(s)" in table
        assert "expiry unknown" in table
        assert {(m, p) for m, p, _ in fake.requests} == {("GET", "/api/ps")}  # never tags, never generate
        assert fake.generates == []


def test_ollama_endpoints_come_from_the_agents_config(box: Box) -> None:
    box.vars["SAFO_ACTIVITY_PROVIDERS"] = "ollama"
    conf = box.home / ".config/safo"
    conf.mkdir(parents=True)
    with FakeOllama(installed=[], loaded=["m1"]).serve() as fake:
        agents_file(conf / "agents.yaml", a_url=fake.url, b_url=fake.url)
        assert box.line() == "ol:m1"
        assert {p for _, p, _ in fake.requests} == {"/api/ps"}


@pytest.mark.parametrize(
    "url",
    [
        "ftp://127.0.0.1:1",
        "http://user:pw@127.0.0.1:1",
        "http://169.254.169.254/",
        "nonsense",
        "http://127.0.0.1:1?x=1",
    ],
)
def test_an_unsound_llm_local_url_is_never_called(box: Box, monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    box.vars.update(SAFO_ACTIVITY_PROVIDERS="ollama", LLM_LOCAL_URL=url)
    calls: list[str] = []
    monkeypatch.setattr("safo.ollama._request", lambda *a, **k: calls.append("called"))
    assert box.line() == ""
    assert calls == []


def test_an_ollama_that_fails_is_left_out_without_an_error(box: Box) -> None:
    box.vars["SAFO_ACTIVITY_PROVIDERS"] = "ollama"
    with FakeOllama(installed=[], loaded=[]).serve() as fake:
        fake.raw_reply = b"<html>not json</html>"
        box.vars["LLM_LOCAL_URL"] = fake.url
        assert box.line() == ""
        assert "Ollama: not answering (segment omitted)" in box.table()
        fake.raw_reply = None
        fake.redirect_to = "http://127.0.0.1:9/"  # a redirect is an error, never followed
        assert box.line() == ""
    box.vars["LLM_LOCAL_URL"] = "http://127.0.0.1:9"  # nothing listens
    assert box.line() == ""


def test_ollama_expiry_notes() -> None:
    assert activity._expiry_note("2099-01-01T00:00:00Z", NOW) == "stays loaded (no expiry)"
    assert activity._expiry_note(stamp(NOW + 300), NOW) == "expires in 5m"
    assert activity._expiry_note("", NOW) == "expiry unknown"


def test_hostile_model_names_are_plain(box: Box) -> None:
    box.vars["SAFO_ACTIVITY_PROVIDERS"] = "ollama"
    with FakeOllama(installed=[], loaded=["evil\x1b[2J\x07" + "Z" * 100]).serve() as fake:
        box.vars["LLM_LOCAL_URL"] = fake.url
        assert no_ctrl(box.line() + box.table())
        assert "Z" * 41 not in box.line()


# -- copilot ---------------------------------------------------------------------------------------

SHA = "abcdef0123456789abcdef0123456789abcdef01"
BOT = {"login": "copilot-pull-request-reviewer[bot]"}


class Gh:
    """A fake `gh`: answers exactly the paths in `routes` and records every argument list it was given."""

    def __init__(self, box: Box, tmp_path: Path) -> None:
        self.routes = tmp_path / "routes.json"
        self.log = tmp_path / "gh.log"
        self.table: dict[str, Any] = {}
        self.save()
        script = box.bin / "gh"
        script.write_text(
            f"#!{sys.executable}\nimport json, sys\nargs = sys.argv[1:]\n"
            f"open({str(self.log)!r}, 'a').write(json.dumps(args) + '\\n')\n"
            f"routes = json.load(open({str(self.routes)!r}))\n"
            "if len(args) == 2 and args[0] == 'api' and args[1] in routes:\n"
            "    print(json.dumps(routes[args[1]]))\n    sys.exit(0)\nsys.exit(1)\n"
        )
        script.chmod(0o755)

    def save(self) -> None:
        self.routes.write_text(json.dumps(self.table))

    def calls(self) -> list[list[str]]:
        return [json.loads(x) for x in self.log.read_text().splitlines()] if self.log.exists() else []

    def pr(
        self,
        repo: str,
        number: int,
        *,
        running: bool = False,
        reviews: list[dict[str, Any]] | None = None,
        comments: list[dict[str, Any]] | None = None,
        runs: list[dict[str, Any]] | None = None,
        sha: str = SHA,
    ) -> None:
        r = f"repos/{repo}"
        self.table[f"{r}/pulls/{number}"] = {"head": {"sha": sha}}
        found = runs if runs is not None else []
        if running:
            found = [*found, {"name": activity.COPILOT_RUN_NAME, "event": "dynamic", "status": "in_progress"}]
        self.table[f"{r}/actions/runs?event=dynamic&head_sha={sha}&per_page=30"] = {"workflow_runs": found}
        self.table[f"{r}/pulls/{number}/reviews?per_page=100"] = reviews or []
        self.table[f"{r}/pulls/{number}/comments?per_page=100"] = comments or []

    def search(self, owner: str, prs: list[tuple[str, int]]) -> None:
        q = quote(f"is:pr is:open user:{owner}")
        items = [{"number": n, "repository_url": f"https://api.github.com/repos/{repo}"} for repo, n in prs]
        self.table[f"search/issues?q={q}&per_page=15"] = {"items": items}


@pytest.fixture
def gh(box: Box, tmp_path: Path) -> Gh:
    box.vars.update(SAFO_ACTIVITY_PROVIDERS="copilot", SAFO_ACTIVITY_COPILOT_OWNER="N0TST")
    return Gh(box, tmp_path)


def review(body: str, sha: str = SHA, user: dict[str, str] = BOT) -> dict[str, Any]:
    return {"user": user, "commit_id": sha, "body": body, "state": "COMMENTED"}


def test_copilot_shows_a_running_review_first(box: Box, gh: Gh) -> None:
    gh.search("N0TST", [("N0TST/a", 3), ("N0TST/b", 9)])
    gh.pr("N0TST/a", 3, running=True)
    gh.pr("N0TST/b", 9, reviews=[review("Looks fine, one note.")])
    gh.save()
    rd = box.read(network=True)
    assert activity.render_line(rd) == "cp 1 run N0TST/a#3"
    table = "\n".join(activity.render_table(rd))
    assert "Copilot: 1 review running, 1 unread (2 open PRs checked)" in table
    assert "N0TST/b#9  unread: 1 review(s) with text, 0 inline comment(s)" in table
    assert "Looks fine" not in table  # counts only, never the text


def test_copilot_unread_means_text_or_an_inline_comment_on_the_current_head(box: Box, gh: Gh) -> None:
    old = "0" * 40
    gh.search("N0TST", [("N0TST/a", 1), ("N0TST/b", 2), ("N0TST/c", 3), ("N0TST/d", 4), ("N0TST/e", 5)])
    gh.pr("N0TST/a", 1, reviews=[review("")])  # an empty body is not unread
    gh.pr("N0TST/b", 2, reviews=[review("old head text", sha=old)])  # not the current head
    gh.pr("N0TST/c", 3, reviews=[review("someone else", user={"login": "human"})])
    gh.pr("N0TST/d", 4, comments=[{"user": BOT, "commit_id": SHA, "body": "SECRETCOMMENT"}])
    gh.pr("N0TST/e", 5, runs=[{"name": "CI", "event": "dynamic", "status": "in_progress"}])  # another workflow
    gh.save()
    rd = box.read(network=True)
    assert rd.copilot is not None
    assert [u[0] for u in rd.copilot.unread] == ["N0TST/d#4"]
    assert rd.copilot.unread[0][1:] == (0, 1)
    assert rd.copilot.running == ()
    assert activity.render_line(rd) == "cp 1 unread N0TST/d#4"
    assert "SECRETCOMMENT" not in json.dumps(activity.render_json(rd))
    assert "SECRETCOMMENT" not in "\n".join(activity.render_table(rd))


def test_copilot_is_silent_when_nothing_runs_and_nothing_is_unread(box: Box, gh: Gh) -> None:
    gh.search("N0TST", [("N0TST/a", 1)])
    gh.pr("N0TST/a", 1, reviews=[review("")])
    gh.save()
    assert activity.render_line(box.read(network=True)) == ""


def test_copilot_asks_only_read_only_rest_paths(box: Box, gh: Gh) -> None:
    gh.search("N0TST", [("N0TST/a", 1)])
    gh.pr("N0TST/a", 1, running=True)
    gh.save()
    box.read(network=True)
    calls = gh.calls()
    assert len(calls) == 5  # search, pull, runs, reviews, comments
    for args in calls:
        assert len(args) == 2
        assert args[0] == "api"
        assert args[1].startswith(("search/issues?", "repos/"))
        assert "graphql" not in args[1]
        assert not args[1].startswith("-")  # no method, field or input flag can be passed


def test_copilot_is_capped_at_15_pull_requests_and_cached_for_60_seconds(box: Box, gh: Gh) -> None:
    prs = [("N0TST/a", n) for n in range(1, 31)]
    gh.search("N0TST", prs)
    for _, n in prs:
        gh.pr("N0TST/a", n)
    gh.save()
    first = box.read(network=True).copilot
    assert first is not None
    assert first.checked == 15
    made = len(gh.calls())
    assert made == 1 + 15 * 4
    again = box.read(network=True).copilot  # within 60 s: from the cache, no gh call
    assert again is not None
    assert again.checked == 15
    assert len(gh.calls()) == made
    stale = activity.copilot_snapshot(box.vars, activity.load_config(box.vars), NOW + 61 + time.time(), fetch=True)
    assert stale is not None
    assert len(gh.calls()) > made  # past 60 s it asks again


def test_the_cache_holds_refs_and_counts_never_review_text(box: Box, gh: Gh) -> None:
    gh.search("N0TST", [("N0TST/a", 1)])
    gh.pr(
        "N0TST/a",
        1,
        reviews=[review("SECRETREVIEW")],
        comments=[{"user": BOT, "commit_id": SHA, "body": "SECRETCOMMENT"}],
    )
    gh.save()
    box.read(network=True)
    cache = box.run / "safo-activity-copilot.json"
    assert stat.S_IMODE(cache.stat().st_mode) == 0o600
    assert "SECRET" not in cache.read_text()


def test_a_status_line_never_waits_for_copilot_and_starts_one_refresh(
    box: Box, gh: Gh, monkeypatch: pytest.MonkeyPatch
) -> None:
    spawned: list[list[str]] = []

    def fake_popen(argv: list[str], **kw: Any) -> None:
        spawned.append(argv)
        assert kw["start_new_session"] is True

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    assert box.line() == ""  # no cache yet: omitted, not waited for
    assert gh.calls() == []
    assert len(spawned) == 1
    assert spawned[0][-1] == "--refresh-copilot"
    assert box.line() == ""
    assert len(spawned) == 1  # a second line within 30 s does not start another


def test_copilot_owner_falls_back_to_the_gh_login_and_failures_leave_it_out(box: Box, gh: Gh) -> None:
    del box.vars["SAFO_ACTIVITY_COPILOT_OWNER"]
    gh.table["user"] = {"login": "N0TST"}
    gh.search("N0TST", [("N0TST/a", 1)])
    gh.pr("N0TST/a", 1, running=True)
    gh.save()
    assert activity.render_line(box.read(network=True)) == "cp 1 run N0TST/a#1"
    for path in list(box.run.glob("safo-activity-copilot*")):
        path.unlink()
    gh.table.clear()
    gh.save()
    rd = box.read(network=True)
    assert activity.render_line(rd) == ""
    assert "Copilot: not available" in "\n".join(activity.render_table(rd))


def test_copilot_without_gh_and_with_a_hostile_repo_name(box: Box, gh: Gh) -> None:
    gh.search("N0TST", [("N0TST/a b", 1), ("../..", 2), ("N0TST/ok", 3)])
    gh.pr("N0TST/ok", 3, running=True)
    gh.save()
    rd = box.read(network=True)
    assert rd.copilot is not None
    assert rd.copilot.running == ("N0TST/ok#3",)
    assert not any(".." in c[1] or " " in c[1] for c in gh.calls())
    (box.bin / "gh").unlink()
    for path in list(box.run.glob("safo-activity-copilot*")):
        path.unlink()
    assert activity.render_line(box.read(network=True)) == ""


def test_one_pull_request_that_fails_is_skipped_not_fatal(box: Box, gh: Gh) -> None:
    gh.search("N0TST", [("N0TST/a", 1), ("N0TST/b", 2)])
    gh.pr("N0TST/b", 2, running=True)  # a/1 has no routes: gh exits 1 for it
    gh.save()
    rd = box.read(network=True).copilot
    assert rd is not None
    assert (rd.checked, rd.running) == (1, ("N0TST/b#2",))


# -- the view modes --------------------------------------------------------------------------------


def test_json_mode_has_the_same_facts(box: Box) -> None:
    box.job(
        "live",
        status="running",
        phase="working",
        pid=os.getpid(),
        kindLabel="rescue",
        title="Live",
        startedAt=stamp(time.time() - 5),
    )
    code, out = box.main("--json")
    doc = json.loads(out)
    assert code == 0
    assert doc["providers"] == ["codex", "quota", "ledger"]
    assert doc["codex"]["running"][0]["title"] == "Live"
    assert doc["ledger"]["readable"] is False
    assert "ollama" not in doc
    assert "copilot" not in doc


def test_table_mode_is_not_cached_and_the_line_is_cached_for_10_seconds(box: Box) -> None:
    box.job(
        "live", status="running", phase="p", pid=os.getpid(), kindLabel="k", title="First", startedAt=stamp(time.time())
    )
    code, first = box.main()
    assert (code, first.startswith("cx 1 run First")) == (0, True)
    cache = box.run / "safo-activity.cache"
    assert stat.S_IMODE(cache.stat().st_mode) == 0o600
    for path in box.jobs.iterdir():
        path.unlink()
    assert box.main()[1] == first  # served from the cache
    assert "Codex: 0 running" in box.main("--table")[1]  # the table is never cached
    os.utime(cache, (time.time() - 30, time.time() - 30))
    assert box.main()[1] == ""  # stale cache: read again


def test_a_symlinked_line_cache_is_not_trusted(box: Box, tmp_path: Path) -> None:
    target = tmp_path / "planted"
    target.write_text("PLANTED")
    (box.run / "safo-activity.cache").symlink_to(target)
    assert box.main()[1] == ""
    assert target.read_text() == "PLANTED"


def test_version_and_bad_arguments(box: Box, capsys: pytest.CaptureFixture[str]) -> None:
    import safo

    assert box.main("--version") == (0, f"safo-activity {safo.__version__}\n")
    for argv in (["--bogus"], ["--table", "--json"], ["--events"], ["--events", "quota"], ["--events", "nope"]):
        code, out = box.main(*argv)
        assert (code, out) == (2, "")
    assert "usage: safo-activity" in capsys.readouterr().err


def test_watch_redraws_with_a_header_until_told_to_stop(box: Box) -> None:
    out = io.StringIO()
    waits: list[float] = []

    def wait(interval: float) -> bool:
        waits.append(interval)
        return len(waits) >= 3

    assert activity.mode_watch(box.vars, out, wait=wait) == 0
    text = out.getvalue()
    assert text.count("safo-activity watch") == 3
    assert waits == [2.0, 2.0, 2.0]
    assert text.count("Codex: 0 running") == 3
    assert no_ctrl(text)  # no screen-clear sequence when not a terminal


# -- the event monitor -----------------------------------------------------------------------------


class Clock:
    """A clock the monitor's wait advances, and a hook that runs between polls to change the world."""

    def __init__(self, script: list[Callable[[], None]] | None = None, step: float = 2.0) -> None:
        self.t = 1000.0
        self.script = script or []
        self.step = step
        self.waits = 0

    def now(self) -> float:
        return self.t

    def wait(self, interval: float) -> bool:
        self.t += self.step
        if self.waits < len(self.script):
            self.script[self.waits]()
        self.waits += 1
        return False


def run_events(box: Box, name: str, clock: Clock, **kw: Any) -> list[str]:
    out = io.StringIO()
    code = activity.mode_events(name, box.vars, out, wait=clock.wait, clock=clock.now, **kw)
    assert code == 0
    return out.getvalue().splitlines()


def test_events_codex_reports_start_and_finish_only(box: Box) -> None:
    live = {"status": "running", "phase": "working", "pid": os.getpid(), "kindLabel": "rescue", "title": "Live job"}

    def start() -> None:
        box.job("e1", **live, startedAt=stamp(time.time()))

    def finish() -> None:
        box.job(
            "e1",
            status="completed",
            phase="done",
            pid=None,
            kindLabel="rescue",
            title="Live job",
            completedAt=stamp(time.time()),
        )

    lines = run_events(box, "codex", Clock([start, finish]), max_polls=4)
    assert lines == [
        "codex: 0 running, 0 done (last 60m)",
        "codex started: Live job (working)",
        "codex finished: Live job",
    ]


def test_events_ollama_load_busy_idle_unload_down_and_back(box: Box) -> None:
    box.vars.update(SAFO_ACTIVITY_PROVIDERS="ollama")
    with FakeOllama(installed=[], loaded=[]).serve() as fake:
        box.vars["LLM_LOCAL_URL"] = fake.url
        fake_ss(box, 0)
        script = [
            lambda: setattr(fake, "loaded", ["qwen3:8b", "llama3"]),
            lambda: fake_ss(box, 2),
            lambda: fake_ss(box, 0),
            lambda: setattr(fake, "loaded", ["qwen3:8b"]),
            lambda: setattr(fake, "raw_reply", b"nope"),
            lambda: setattr(fake, "raw_reply", None),
        ]
        lines = run_events(box, "ollama", Clock(script), max_polls=7, cap=100)
    assert lines[0] == "ollama: 0 loaded, idle"
    assert lines[1:] == [
        "ollama: loaded llama3",
        "ollama: loaded qwen3:8b",
        "ollama: busy (2 conn)",
        "ollama: idle",
        "ollama: unloaded llama3",
        "ollama: unreachable",
        "ollama: reachable again",
    ]  # no unload spam while it was down: only the transition is reported


def test_events_ledger_names_the_action_and_never_the_prompt(box: Box) -> None:
    t = time.time()
    box.rows(start_row("B", "seed", t - 5), end_row("B", t - 4))

    def add() -> None:
        with box.ledger.open("a") as handle:
            handle.write(json.dumps(start_row("N", "research-two", time.time(), prompt="SECRETPROMPT")) + "\n")
            handle.write(json.dumps(start_row("H", "x\x1b[2Jy\x07z", time.time())) + "\n")

    def end() -> None:
        with box.ledger.open("a") as handle:
            handle.write(json.dumps(end_row("N", time.time())) + "\n")

    lines = run_events(box, "ledger", Clock([add, end]), max_polls=3)
    assert lines[0] == "ledger: 0 call(s) in flight today"
    assert "ledger: call started: research-two" in lines
    assert "ledger: call ended: research-two" in lines
    assert len(lines) == 4
    assert no_ctrl("\n".join(lines))
    assert "SECRETPROMPT" not in "\n".join(lines)


def test_events_startup_notes_for_a_ledger_that_cannot_tell_starts_from_ends_or_is_missing(box: Box) -> None:
    assert run_events(box, "ledger", Clock(), max_polls=1)[0] == "ledger: not found or unreadable"
    box.rows({"type": "usage", "ts": stamp(time.time())})
    assert "cannot be told apart" in run_events(box, "ledger", Clock(), max_polls=1)[0]


def test_events_are_capped_at_six_per_window_with_one_dropped_notice(box: Box) -> None:
    t = time.time()
    box.rows(start_row("B", "seed", t - 5), end_row("B", t - 4))

    def burst() -> None:
        with box.ledger.open("a") as handle:
            for n in range(9):
                handle.write(json.dumps(start_row(f"X{n}", f"burst-{n}", time.time())) + "\n")

    lines = run_events(box, "ledger", Clock([burst], step=20.0), window=60.0, max_polls=8)
    assert sum("call started" in x for x in lines) == 6
    notices = [x for x in lines if "dropped" in x]
    assert notices == ["ledger: 3 events dropped in the last 60s (cap 6 per 60s)"]


def test_events_end_after_the_limit_with_a_re_arm_line(box: Box) -> None:
    lines = run_events(box, "codex", Clock(step=600.0), limit=29 * 60.0)
    assert lines[0].startswith("codex: 0 running")
    assert lines[-1] == "codex: 29 minute limit reached, re-arm the monitor"
    assert len(lines) == 2


def test_the_default_limit_is_29_minutes_and_the_cap_is_six() -> None:
    assert activity.EVENTS_LIMIT == 29 * 60
    assert activity.EVENTS_CAP == 6
    assert activity.EVENTS_INTERVAL == 2.0


def test_events_copilot_reports_a_review_starting_and_finishing(box: Box, gh: Gh) -> None:
    gh.search("N0TST", [("N0TST/a", 1)])
    gh.pr("N0TST/a", 1)
    gh.save()

    def wipe_cache() -> None:
        for path in box.run.glob("safo-activity-copilot*"):
            path.unlink()

    def begin() -> None:
        gh.pr("N0TST/a", 1, running=True)
        gh.save()
        wipe_cache()

    def done() -> None:
        gh.pr("N0TST/a", 1, reviews=[review("text")])
        gh.save()
        wipe_cache()

    lines = run_events(box, "copilot", Clock([begin, done]), max_polls=3)
    assert lines == [
        "copilot: 0 review running, 0 unread",
        "copilot: review running N0TST/a#1",
        "copilot: unread N0TST/a#1 (1 review(s) with text, 0 inline)",
        "copilot: review finished N0TST/a#1",
    ]


@pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM])
@pytest.mark.parametrize("args", [["--events", "codex"], ["--watch"]])
def test_a_signal_ends_a_monitor_cleanly_and_promptly(box: Box, sig: signal.Signals, args: list[str]) -> None:
    proc = subprocess.Popen(  # noqa: S603 - our own interpreter
        [sys.executable, "-I", "-c", "import sys; from safo.activity import main; sys.exit(main(sys.argv[1:]))", *args],
        env=box.vars,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    assert proc.stdout is not None
    proc.stdout.readline()  # the first line proves the handlers are installed (startup line or watch header)
    started = time.monotonic()
    proc.send_signal(sig)
    assert proc.wait(timeout=10) == 0
    assert time.monotonic() - started < 5
    proc.stdout.close()


def test_a_provider_that_raises_never_takes_the_view_down(box: Box, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: Any, **k: Any) -> Any:
        raise RuntimeError("provider bug")

    monkeypatch.setattr(activity, "collect_codex", boom)
    monkeypatch.setattr(activity, "collect_ledger", boom)
    assert box.main("--table")[0] == 0
    assert box.main("--json")[0] == 0


# -- pace and the advisory recommendation ----------------------------------------------------------------------------


def win(label: str, percent: float, left_fraction: float | None) -> activity.Window:
    minutes = activity.window_minutes(label)
    assert minutes is not None
    return activity.Window(label, percent, None if left_fraction is None else left_fraction * minutes * 60)


@pytest.mark.parametrize(
    ("ratio", "band"),
    [
        (0.0, "under_pace"),
        (0.8999, "under_pace"),
        (0.9, "on_pace"),
        (1.0, "on_pace"),
        (1.0001, "caution"),
        (1.3, "caution"),
        (1.3001, "over_pace"),
        (5.0, "over_pace"),
    ],
)
def test_pace_band_edges(ratio: float, band: str) -> None:
    assert activity.pace_band(ratio) == band


def test_pace_is_used_percent_over_the_elapsed_share() -> None:
    pace = activity.pace_of(win("wk", 42, 0.72))  # 28% of the week gone
    assert pace is not None
    assert round(pace.elapsed_percent) == 28
    assert round(pace.ratio, 1) == 1.5
    assert pace.band == "over_pace"
    half = activity.pace_of(win("5h", 50, 0.5))
    assert half is not None
    assert (round(half.elapsed_percent), round(half.ratio, 2), half.band) == (50, 1.0, "on_pace")


def test_an_early_reading_is_clamped_to_two_percent_elapsed() -> None:
    pace = activity.pace_of(win("5h", 10, 0.999))  # 0.1% elapsed would give a ratio of 100
    assert pace is not None
    assert pace.elapsed_percent == 2.0
    assert pace.ratio == 5.0
    ahead = activity.pace_of(win("wk", 10, 1.5))  # a reset further off than the window is long
    assert ahead is not None
    assert ahead.elapsed_percent == 2.0


def test_no_pace_without_a_reset_time_or_a_known_length() -> None:
    assert activity.pace_of(win("wk", 10, None)) is None
    assert activity.pace_of(activity.Window("month", 10, 100.0)) is None
    assert [activity.window_minutes(x) for x in ("5h", "wk", "12h", "0h", "h", "5m")] == [
        300,
        10080,
        720,
        None,
        None,
        None,
    ]


def quota_snap(
    cl_wk: tuple[float, float] | None,
    cx_wk: tuple[float, float] | None,
    cl_5h: float | None = None,
    cl_age: float = 60.0,
    cx_age: float = 60.0,
) -> activity.QuotaSnap:
    claude = [win("wk", cl_wk[0], cl_wk[1])] if cl_wk else []
    if cl_5h is not None:
        claude.append(win("5h", cl_5h, 0.5))
    codex = [win("wk", cx_wk[0], cx_wk[1])] if cx_wk else []
    return activity.QuotaSnap(activity.Quota(tuple(codex), cx_age, "prolite"), activity.Quota(tuple(claude), cl_age))


def test_recommendation_prefers_codex_when_claude_runs_ahead_and_codex_has_room() -> None:
    text = activity.recommendation(quota_snap((42, 0.72), (1, 0.9)))
    assert (
        text
        == "Budget: Claude wk 42% (1.5x pace), Codex wk 1% (0.1x pace) - prefer Codex for specified implementer tasks"
    )
    assert activity.recommendation(quota_snap((40, 0.72), (30, 0.7))) is not None  # caution + on_pace


def test_recommendation_says_normal_otherwise_and_holds_new_claude_agents_over_80_percent() -> None:
    normal = activity.recommendation(quota_snap((10, 0.5), (1, 0.5)))
    assert normal is not None
    assert normal.endswith(" - normal")
    both_ahead = activity.recommendation(quota_snap((42, 0.72), (60, 0.5)))  # codex over_pace too
    assert both_ahead is not None
    assert both_ahead.endswith(" - normal")
    held = activity.recommendation(quota_snap((10, 0.5), (1, 0.5), cl_5h=81))
    assert held is not None
    assert held.endswith(" - hold new Claude agents")
    assert activity.recommendation(quota_snap((10, 0.5), (1, 0.5), cl_5h=80)) == normal  # 80 itself is not above
    both = activity.recommendation(quota_snap((42, 0.72), (1, 0.9), cl_5h=95))
    assert both is not None
    assert both.endswith(" - prefer Codex for specified implementer tasks; hold new Claude agents")
    for text in (normal, held, both):
        assert "review" not in text.lower()  # nothing about review routing, security review above all


def test_missing_data_for_either_provider_means_no_line() -> None:
    assert activity.recommendation(activity.QuotaSnap()) is None
    assert activity.recommendation(quota_snap(None, (1, 0.5))) is None
    assert activity.recommendation(quota_snap((42, 0.5), None)) is None
    no_reset = activity.QuotaSnap(
        activity.Quota((activity.Window("wk", 1, None),), 5.0), activity.Quota((win("wk", 42, 0.5),), 5.0)
    )
    assert activity.recommendation(no_reset) is None


def test_a_stale_reading_is_marked_and_left_out_of_the_recommendation() -> None:
    assert activity.recommendation(quota_snap((42, 0.72), (1, 0.9), cl_age=1801)) is None
    assert activity.recommendation(quota_snap((42, 0.72), (1, 0.9), cx_age=1801)) is None
    assert activity.recommendation(quota_snap((42, 0.72), (1, 0.9), cl_age=1800, cx_age=1800)) is not None


def test_the_table_and_json_carry_the_pace_and_the_advice(box: Box) -> None:
    box.rollout(
        "a",
        token_event(
            NOW - 60, {"used_percent": 1.0, "window_minutes": 10080, "resets_in_seconds": 0.9 * 10080 * 60}, None
        ),
    )
    put_claude(
        box,
        claude_doc(
            NOW - 60,
            {"label": "wk", "used_percent": 42, "resets_at": stamp(NOW + 0.72 * 10080 * 60)},
            {"label": "5h", "used_percent": 20},
        ),
    )
    table = box.table()
    assert "42% used  wk, resets in 5" in table
    assert "28% elapsed, 1.5x pace (over_pace)" in table
    assert "10% elapsed, 0.1x pace (under_pace)" in table
    assert (
        "Budget: Claude wk 42% (1.5x pace), Codex wk 1% (0.1x pace) - prefer Codex for specified implementer tasks"
        in table
    )
    assert "advisory only" in table
    doc = activity.render_json(box.read())
    claude = doc["quota"]["claude"]["windows"][0]
    assert (claude["elapsed_percent"], claude["pace_ratio"], claude["band"]) == (28.0, 1.5, "over_pace")
    assert doc["quota"]["claude"]["windows"][1]["band"] is None  # no reset time: no pace
    assert doc["quota"]["recommendation"].startswith("Budget: Claude wk 42%")
    assert "Budget" not in box.line()  # the status line is unchanged


def test_the_view_modes_touch_no_routing_or_settings_file(box: Box) -> None:
    box.rollout(
        "a", token_event(NOW - 60, {"used_percent": 1.0, "window_minutes": 10080, "resets_in_seconds": 9000}, None)
    )
    put_claude(box, claude_doc(NOW - 60, {"label": "wk", "used_percent": 42, "resets_at": stamp(NOW + 9000)}))
    conf = box.home / ".config/safo"
    conf.mkdir(parents=True)
    (conf / "agents.yaml").write_text("sentinel: agents\n")
    settings = box.home / ".claude/settings.json"
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text('{"sentinel": 1}')

    def snapshot() -> dict[str, tuple[bytes, int]]:
        found = {}
        for p in sorted(box.home.rglob("*")):
            if p.is_file() and ".cache" not in p.parts:
                found[str(p)] = (p.read_bytes(), p.stat().st_mtime_ns)
        return found

    before = snapshot()
    for argv in ([], ["--table"], ["--json"]):
        box.main(*argv)
    assert snapshot() == before
    assert not (conf / "mode").exists()
