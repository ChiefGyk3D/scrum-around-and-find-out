# SPDX-License-Identifier: MIT
"""agents-status: the board by agent, Codex sessions and limits from files, Copilot from gh."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from fakegh import FakeGitHub
from safo.agents import read_codex, read_copilot
from safo.graphql import Client
from safo.guardlog import summarise
from safo.modes.agents_status import run
from world import build_world, load_test_board, make_context


def write_session(root: Path, name: str, rows: list[dict[str, object]], age_seconds: float, now: float) -> Path:
    day = root / "2026" / "10" / "07"
    day.mkdir(parents=True, exist_ok=True)
    path = day / f"{name}.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    os.utime(path, (now - age_seconds, now - age_seconds))
    return path


LIMITS: dict[str, Any] = {
    "type": "event_msg",
    "payload": {
        "type": "token_count",
        "rate_limits": {
            "plan_type": "plus",
            "primary": {"used_percent": 29, "resets_at": 1_800_000_000},
            "secondary": {"used_percent": 10, "resets_at": 1_800_400_000},
        },
    },
}


def test_codex_sessions_state_and_the_last_message(tmp_path: Path) -> None:
    now = time.time()
    write_session(
        tmp_path,
        "done",
        [
            {"type": "session_meta", "payload": {"cwd": "/work/widgets"}},
            {"payload": {"type": "task_started"}},
            {"payload": {"type": "task_complete", "last_agent_message": "Plan written.\nSecond line."}},
            LIMITS,
        ],
        60,
        now,
    )
    write_session(
        tmp_path,
        "running",
        [{"type": "session_meta", "payload": {"cwd": "/work/manuals"}}, {"payload": {"type": "task_started"}}],
        120,
        now,
    )
    write_session(
        tmp_path,
        "stuck",
        [{"type": "session_meta", "payload": {"cwd": "/work/old"}}, {"payload": {"type": "task_started"}}],
        3000,
        now,
    )
    write_session(tmp_path, "ancient", [{"type": "session_meta", "payload": {"cwd": "/work/gone"}}], 20 * 3600, now)
    report = read_codex(tmp_path, 12, now)
    by_cwd = {s.cwd: s for s in report.sessions}
    assert set(by_cwd) == {"widgets", "manuals", "old"}
    assert by_cwd["widgets"].state == "done" and by_cwd["widgets"].last == ""
    assert by_cwd["manuals"].state == "running"
    assert by_cwd["old"].state.startswith("stalled? (no output for 50 min)")
    assert report.limits and report.limits.plan == "plus" and report.limits.five_hour_percent == "29"


def test_a_missing_codex_directory_and_a_corrupt_line_are_not_errors(tmp_path: Path) -> None:
    assert read_codex(tmp_path / "nope", 12, time.time()).sessions == ()
    day = tmp_path / "2026" / "10" / "07"
    day.mkdir(parents=True)
    (day / "s.jsonl").write_text("not json\n" + json.dumps({"type": "session_meta", "payload": {"cwd": "/a/b"}}) + "\n")
    assert [s.cwd for s in read_codex(tmp_path, 12, time.time()).sessions] == ["b"]


def test_copilot_tasks_come_from_gh_and_a_failure_is_none() -> None:
    class Done:
        returncode = 0
        stdout = "task one\n\ntask two\n"

    calls = []

    def run(*a: Any, **k: Any) -> Done:
        calls.append(a[0])
        return Done()

    assert read_copilot(run, which=lambda name: "gh") == ["task one", "task two"]
    assert calls == [["gh", "agent-task", "list", "-L", "10"]]

    class Failed:
        returncode = 1
        stdout = ""

    assert read_copilot(lambda *a, **k: Failed(), lambda name: "/usr/bin/gh") is None


def test_the_board_sections_group_working_cards_by_agent_and_list_what_waits_on_you(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    _, project = build_world(fake)
    a = fake.add_content("acme/widgets", "Issue", 1, "Build the thing")
    b = fake.add_content("acme/widgets", "PullRequest", 2, "Review me")
    c = fake.add_content("acme/widgets", "Issue", 3, "Needs a decision")
    d = fake.add_content("acme/widgets", "Issue", 4, "Closed one", state="CLOSED")
    fake.add_item(project, a, Status="In progress", Agent="Claude")
    fake.add_item(project, b, Status="Next", Agent="Codex")
    fake.add_item(project, c, Status="Blocked", Agent="Claude")
    fake.add_item(project, d, Status="In progress", Agent="Claude")
    ctx, out = make_context(fake, load_test_board(), client)
    args = argparse.Namespace(
        hours=12.0, codex_dir=str(tmp_path / "none"), no_codex=False, no_copilot=True, no_guard=False
    )
    assert run(ctx, args) == 0
    text = out.getvalue()
    assert "Waiting on you (Status = Blocked)\n  acme/widgets#3  Needs a decision" in text
    assert "Claude       In progress  acme/widgets#1  Build the thing" in text
    assert "Codex        Next         acme/widgets#2  Review me" in text
    assert "#4" not in text, "closed cards are not work in progress"
    assert "Routing guard (mode: warn)\n" in text and "  no dispatches logged yet" in text
    assert "no Codex sessions in that window" in text
    assert "cannot be listed from a shell" in text
    assert fake.mutations == []


def test_completion_message_containing_a_credential_is_omitted(tmp_path: Path) -> None:
    day = tmp_path / "2026" / "10" / "07"
    day.mkdir(parents=True)
    path = day / "done.jsonl"
    path.write_text(
        json.dumps(
            {"type": "event_msg", "payload": {"type": "task_complete", "last_agent_message": "sentinel-credential"}}
        )
        + "\n"
    )
    report = read_codex(tmp_path, 12, time.time())
    assert report.sessions[0].state == "done"
    assert "sentinel-credential" not in str(report) and report.sessions[0].last == ""


def guard_rows(*rows: dict[str, Any]) -> str:
    return "\n".join(json.dumps(r) for r in rows) + "\n"


def record(
    ts: str, decision: str, model: str | None, rules: list[str], *, local: bool = False, na: bool = False
) -> Any:
    return {
        "ts": ts,
        "decision": decision,
        "mode": "warn",
        "model": model,
        "local_reachable": True,
        "local_step": local,
        "na": na,
        "rules": rules,
        "health": "healthy",
        "diagnostic": "",
    }


def guard_section(fake: FakeGitHub, client: Client, env: dict[str, str]) -> str:
    build_world(fake)
    ctx, out = make_context(fake, load_test_board(), client)
    ctx.env = env
    args = argparse.Namespace(hours=12.0, codex_dir="", no_codex=True, no_copilot=True, no_guard=False)
    assert run(ctx, args) == 0
    return out.getvalue()


def test_the_guard_section_counts_decisions_models_rules_and_what_the_briefs_named(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    folder = tmp_path / "state" / "safo" / "hooks"
    folder.mkdir(parents=True)
    (folder / "log.jsonl").write_text(
        guard_rows(
            record("2026-10-07T09:00:00", "allow", "sonnet", [], local=True),
            record("2026-10-07T09:10:00", "allow", "haiku", [], na=True),
            record("2026-10-07T09:20:00", "warn", None, ["no-model", "no-local-step"]),
            record("2026-10-07T14:05:00", "deny", "opus", ["approval"]),
        )
    )
    text = guard_section(fake, client, {"XDG_STATE_HOME": str(tmp_path / "state"), "HOME": str(tmp_path / "none")})
    assert "Routing guard (mode: warn)\n" in text
    assert "  4 dispatches since 2026-10-07: allow 2, warn 1, deny 1\n" in text
    assert "  models: sonnet 1, haiku 1, none 1, opus 1; briefs with a local step 1, marked n/a 1\n" in text
    assert "  rules flagged: approval 1, no-local-step 1, no-model 1\n" in text
    assert "  last flagged: 14:05 approval\n" in text


def test_the_guard_section_reads_the_mode_and_survives_a_garbled_log(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    home = tmp_path / "home"
    (home / ".config" / "safo").mkdir(parents=True)
    (home / ".config" / "safo" / "mode").write_text("block\n")
    folder = home / ".local" / "state" / "safo" / "hooks"
    folder.mkdir(parents=True)
    (folder / "log.jsonl").write_text(
        "not json\n[1, 2]\n" + guard_rows(record("2026-10-07T09:00:00", "allow", "sonnet", [])) + '{"half": '
    )
    text = guard_section(fake, client, {"HOME": str(home)})
    assert "Routing guard (mode: block)\n" in text
    assert "  1 dispatches since 2026-10-07: allow 1\n" in text
    assert "last flagged" not in text and "rules flagged" not in text


def test_an_unknown_mode_file_is_warn_and_no_home_means_no_log(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    config = tmp_path / "config" / "safo"
    config.mkdir(parents=True)
    (config / "mode").write_text("panic")
    text = guard_section(fake, client, {"XDG_CONFIG_HOME": str(tmp_path / "config")})
    assert "Routing guard (mode: warn)\n" in text and "  no dispatches logged yet" in text


def test_the_guard_section_can_be_skipped(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    ctx, out = make_context(fake, load_test_board(), client)
    args = argparse.Namespace(hours=12.0, codex_dir="", no_codex=True, no_copilot=True, no_guard=True)
    assert run(ctx, args) == 0 and "Routing guard" not in out.getvalue()


@pytest.mark.parametrize(
    "field", ["ts", "decision", "mode", "model", "rules", "local_reachable", "local_step", "na", "health", "diagnostic"]
)
def test_every_output_bearing_log_field_is_validated(tmp_path: Path, field: str) -> None:
    from safo.guardlog import read_log

    good = record("2026-10-07T09:00:00", "allow", "sonnet", [])
    bad = {
        **good,
        field: (
            ["sentinel-token\n\x1b[31m https://private.invalid"]
            if field == "rules"
            else "sentinel-token\n\x1b[31m https://private.invalid"
        ),
    }
    path = tmp_path / "log.jsonl"
    path.write_text(guard_rows(bad, good))
    rows = read_log(path)
    assert rows == [good] and "sentinel-token" not in str(summarise(rows))


def test_a_valid_json_object_without_a_terminating_newline_is_not_counted(tmp_path: Path) -> None:
    from safo.guardlog import read_log

    path = tmp_path / "log.jsonl"
    path.write_text(json.dumps(record("2026-10-07T09:00:00", "allow", "sonnet", [])))
    assert read_log(path) == []


# ---- hostile inputs -------------------------------------------------------------------------------------------


def good_row() -> dict[str, Any]:
    row: dict[str, Any] = record("2026-10-07T09:00:00", "allow", "sonnet", [])
    return row


def test_a_guard_line_over_the_record_cap_is_skipped_and_the_rest_counted(tmp_path: Path) -> None:
    from safo.guardlog import RECORD_CAP, read_log

    path = tmp_path / "log.jsonl"
    padded = json.dumps(good_row()) + " " * RECORD_CAP  # a valid record, only too long
    path.write_text(padded + "\n" + guard_rows(good_row()))
    assert read_log(path) == [good_row()]


def test_garbled_lines_are_skipped_and_valid_ones_survive(tmp_path: Path) -> None:
    from safo.guardlog import read_log

    path = tmp_path / "log.jsonl"
    path.write_bytes(b"\xff\xfe not utf8\n{\n" + guard_rows(good_row()).encode() + b'"just a string"\n')
    assert read_log(path) == [good_row()]


def test_a_log_over_the_file_cap_reads_as_empty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from safo import guardlog

    path = tmp_path / "log.jsonl"
    path.write_text(guard_rows(good_row()) * 3)
    monkeypatch.setattr(guardlog, "FILE_CAP", 100)
    assert guardlog.read_log(path) == []


def test_a_fifo_a_symlink_and_a_directory_are_not_a_log(tmp_path: Path) -> None:
    from safo.guardlog import read_log

    fifo = tmp_path / "fifo.jsonl"
    os.mkfifo(fifo)
    real = tmp_path / "real.jsonl"
    real.write_text(guard_rows(good_row()))
    link = tmp_path / "link.jsonl"
    link.symlink_to(real)
    folder = tmp_path / "dir.jsonl"
    folder.mkdir()
    assert read_log(fifo) == [] and read_log(link) == [] and read_log(folder) == []
    assert read_log(real) == [good_row()]


def test_a_missing_log_creates_nothing_and_an_empty_one_is_no_dispatches(tmp_path: Path) -> None:
    from safo.guardlog import guard_lines, read_log

    env = {"XDG_STATE_HOME": str(tmp_path / "state"), "HOME": str(tmp_path / "home")}
    assert read_log(tmp_path / "state" / "safo" / "hooks" / "log.jsonl") == []
    assert guard_lines(env)[-1] == "  no dispatches logged yet"
    assert not (tmp_path / "state").exists() and not (tmp_path / "home").exists()
    folder = tmp_path / "state" / "safo" / "hooks"
    folder.mkdir(parents=True)
    (folder / "log.jsonl").write_text("")
    assert guard_lines(env)[-1] == "  no dispatches logged yet"


def test_a_log_held_by_a_writer_reads_as_empty_instead_of_blocking(tmp_path: Path) -> None:
    import fcntl

    from safo.guardlog import read_log

    path = tmp_path / "log.jsonl"
    path.write_text(guard_rows(good_row()))
    with open(tmp_path / "log.jsonl.lock", "w") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        started = time.monotonic()
        assert read_log(path) == []
        assert time.monotonic() - started < 5


@pytest.mark.parametrize("ts", ["2026-1-07T09:00:00", "2026-10-07 09:00:00", "2026-10-07T09:00", "2026-13-07T09:00:00"])
def test_a_timestamp_that_is_not_the_exact_iso_form_is_excluded(tmp_path: Path, ts: str) -> None:
    from safo.guardlog import read_log

    path = tmp_path / "log.jsonl"
    path.write_text(guard_rows({**good_row(), "ts": ts}))
    assert read_log(path) == []


def test_an_unknown_model_or_extra_key_is_excluded_and_a_null_model_is_none(tmp_path: Path) -> None:
    from safo.guardlog import read_log

    path = tmp_path / "log.jsonl"
    path.write_text(
        guard_rows({**good_row(), "model": "gpt-9"}, {**good_row(), "extra": 1}, {**good_row(), "model": None})
    )
    assert read_log(path) == [{**good_row(), "model": None}]
    assert dict(summarise(read_log(path)).models) == {"none": 1}


def test_the_last_flagged_dispatch_may_be_the_last_line(tmp_path: Path) -> None:
    from safo.guardlog import read_log

    path = tmp_path / "log.jsonl"
    path.write_text(guard_rows(good_row(), record("2026-10-07T23:59:00", "warn", None, ["no-model"])))
    assert summarise(read_log(path)).last_flagged == "23:59 no-model"


def test_a_session_just_over_fifteen_minutes_is_stalled_and_just_under_is_running(tmp_path: Path) -> None:
    now = time.time()
    rows: list[dict[str, object]] = [
        {"type": "session_meta", "payload": {"cwd": "/w/over"}},
        {"payload": {"type": "task_started"}},
    ]
    write_session(tmp_path, "over", rows, 901, now)
    rows = [{"type": "session_meta", "payload": {"cwd": "/w/under"}}, {"payload": {"type": "task_started"}}]
    write_session(tmp_path, "under", rows, 899, now)
    by_cwd = {s.cwd: s.state for s in read_codex(tmp_path, 12, now).sessions}
    assert by_cwd["over"] == "stalled? (no output for 15 min)" and by_cwd["under"] == "running"


def test_a_session_file_that_is_a_fifo_a_symlink_or_huge_is_skipped_without_blocking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from safo import agents

    now = time.time()
    day = tmp_path / "2026" / "10" / "07"
    day.mkdir(parents=True)
    os.mkfifo(day / "fifo.jsonl")
    outside = tmp_path / "outside.jsonl"
    outside.write_text(json.dumps({"type": "session_meta", "payload": {"cwd": "/w/linked"}}) + "\n")
    (day / "link.jsonl").symlink_to(outside)
    write_session(tmp_path, "big", [{"type": "session_meta", "payload": {"cwd": "/w/big"}}], 10, now)
    write_session(tmp_path, "ok", [{"type": "session_meta", "payload": {"cwd": "/w/ok"}}], 10, now)
    monkeypatch.setattr(agents, "MAX_FILE_BYTES", 10)
    assert [s.cwd for s in read_codex(tmp_path, 12, now).sessions] == []
    monkeypatch.setattr(agents, "MAX_FILE_BYTES", 1 << 20)
    assert sorted(s.cwd for s in read_codex(tmp_path, 12, now).sessions) == ["big", "ok"]


def test_hostile_values_in_a_session_are_shown_safely_or_not_at_all(tmp_path: Path) -> None:
    now = time.time()
    hostile = "::set-output name=x::y\n\x1b[31m" + "A" * 500
    limits: dict[str, object] = {
        "type": "event_msg",
        "payload": {
            "type": "token_count",
            "rate_limits": {
                "plan_type": hostile,
                "primary": {"used_percent": hostile, "resets_at": 10**30},
                "secondary": {"used_percent": True, "resets_at": "soon"},
            },
        },
    }
    rows: list[dict[str, object]] = [{"type": "session_meta", "payload": {"cwd": "/w/" + hostile}}, limits]
    write_session(tmp_path, "h", rows, 10, now)
    report = read_codex(tmp_path, 12, now)
    session = report.sessions[0]
    assert len(session.cwd) <= 32 and "\n" not in session.cwd and "\x1b" not in session.cwd
    assert report.limits == agents_limits("?", "?", "?", "?", "?")


def agents_limits(plan: str, a: str, b: str, c: str, d: str) -> Any:
    from safo.agents import CodexLimits

    return CodexLimits(plan, a, b, c, d)


def test_a_record_that_is_not_an_object_or_has_a_non_object_payload_is_ignored(tmp_path: Path) -> None:
    day = tmp_path / "2026" / "10" / "07"
    day.mkdir(parents=True)
    (day / "s.jsonl").write_text('[1]\n"x"\n{"payload": 3}\n{"payload": {"type": "token_count", "rate_limits": 5}}\n')
    assert [s.state for s in read_codex(tmp_path, 12, time.time()).sessions] == ["running"]


def test_copilot_output_is_capped_and_a_timeout_or_oserror_is_none() -> None:
    class Done:
        returncode = 0
        stdout = "".join(f"task {i} " + "x" * 1000 + "\n" for i in range(50))

    tasks = read_copilot(lambda *a, **k: Done(), which=lambda name: "gh")
    assert tasks is not None and len(tasks) == 10 and all(len(t) <= 200 for t in tasks)

    def hang(*a: Any, **k: Any) -> Any:
        raise subprocess.TimeoutExpired("gh", 30)

    def denied(*a: Any, **k: Any) -> Any:
        raise PermissionError("no")

    assert read_copilot(hang, which=lambda name: "gh") is None
    assert read_copilot(denied, which=lambda name: "gh") is None
    assert read_copilot(hang, which=lambda name: None) is None


def test_copilot_gh_is_run_with_stdin_closed_and_a_fixed_argument_list() -> None:
    seen: dict[str, Any] = {}

    class Done:
        returncode = 0
        stdout = ""

    def spy(argv: list[str], **kwargs: Any) -> Done:
        seen.update(kwargs, argv=argv)
        return Done()

    assert read_copilot(spy, which=lambda name: "/bin/gh") == []
    assert seen["stdin"] is subprocess.DEVNULL and seen["argv"][1:] == ["agent-task", "list", "-L", "10"]


@pytest.mark.parametrize("hours", [0.0, -1.0, float("nan"), float("inf"), 1e9])
def test_hours_must_be_a_sane_positive_number(fake: FakeGitHub, client: Client, hours: float) -> None:
    from safo.errors import ConfigError

    build_world(fake)
    ctx, _ = make_context(fake, load_test_board(), client)
    args = argparse.Namespace(hours=hours, codex_dir="", no_codex=True, no_copilot=True, no_guard=True)
    with pytest.raises(ConfigError, match="--hours"):
        run(ctx, args)


def test_a_card_without_a_repository_is_a_malformed_read_not_a_silent_skip(
    fake: FakeGitHub, client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    from safo.errors import MalformedDataError

    build_world(fake)
    node = {
        "status": {"name": "In progress"},
        "agent": {"name": "Claude"},
        "content": {"__typename": "Issue", "state": "OPEN", "number": 1, "title": "t", "url": "u"},
    }
    monkeypatch.setattr(client, "nodes", lambda *a, **k: iter([node]))
    ctx, _ = make_context(fake, load_test_board(), client)
    args = argparse.Namespace(hours=1.0, codex_dir="", no_codex=True, no_copilot=True, no_guard=True)
    with pytest.raises(MalformedDataError, match="repository or number"):
        run(ctx, args)
