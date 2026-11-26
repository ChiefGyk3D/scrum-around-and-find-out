# SPDX-License-Identifier: Apache-2.0
"""safo-draft (#482): local-first drafts and digests. llm-local and gh are PATH shims; no network, no real server."""

from __future__ import annotations

import datetime as dt
import io
import json
import stat
from pathlib import Path
from typing import Any

import pytest

from safo import localdraft

FOOTER = "🤖 Generated with [Claude Code](https://claude.com/claude-code)"
LLM_SHIM = """#!/usr/bin/env bash
echo "$@" >> "$SHIM_DIR/llm.args"
if [ -t 0 ]; then echo TTY >> "$SHIM_DIR/llm.stdin"; else cat >> "$SHIM_DIR/llm.stdin"; fi
n=$(cat "$SHIM_DIR/llm.count" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$SHIM_DIR/llm.count"
if [ -f "$SHIM_DIR/llm.busy" ] && [ "$n" -le "$(cat "$SHIM_DIR/llm.busy")" ]; then echo "busy" >&2; exit 75; fi
if [ -f "$SHIM_DIR/llm.fail" ]; then echo "connection refused" >&2; exit 7; fi
cat "$SHIM_DIR/llm.reply"
"""
GH_SHIM = """#!/usr/bin/env bash
echo "$@" >> "$SHIM_DIR/gh.args"
cat >> "$SHIM_DIR/gh.stdin"
echo "https://github.com/o/r/issues/9"
"""


class Env:
    def __init__(self, tmp: Path, reply: str = "Short draft body.") -> None:
        self.dir = tmp / "shim"
        self.dir.mkdir()
        bindir = tmp / "bin"
        bindir.mkdir()
        for name, text in (("llm-local", LLM_SHIM), ("gh", GH_SHIM)):
            path = bindir / name
            path.write_text(text)
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
        (self.dir / "llm.reply").write_text(reply)
        self.state = tmp / "state"
        self.env = {
            "PATH": f"{bindir}:/usr/bin:/bin",
            "SHIM_DIR": str(self.dir),
            "XDG_STATE_HOME": str(self.state),
            "HOME": str(tmp),
        }
        self.sleeps: list[float] = []

    def run(self, argv: list[str], stdin: str = "") -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = localdraft.main(
            argv,
            env=self.env,
            out=out,
            err=err,
            stdin=io.StringIO(stdin),
            sleep=self.sleeps.append,
            now=dt.datetime(2026, 11, 26, 12, 0, tzinfo=dt.UTC),
        )
        return code, out.getvalue(), err.getvalue()

    def read(self, name: str) -> str:
        path = self.dir / name
        return path.read_text() if path.exists() else ""

    def metrics(self) -> list[dict[str, Any]]:
        path = self.state / "safo" / "local-share.jsonl"
        return [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return Env(tmp_path)


def test_issue_files_after_yes_and_shows_draft(env: Env) -> None:
    (env.dir / "llm.reply").write_text("Do the thing.\n\nPart of epic #445")
    code, out, _ = env.run(["issue", "--repo", "o/r", "--title", "T", "--yes", "add a thing"])
    assert code == 0
    assert "Do the thing." in out
    assert "--repo o/r" in env.read("gh.args") and "issue create" in env.read("gh.args")
    assert "Do the thing." in env.read("gh.stdin")
    assert "--task draft-issue" in env.read("llm.args")
    assert env.read("llm.stdin") == ""  # stdin was /dev/null, never a tty or an open pipe


def test_model_choice_short_vs_long(env: Env) -> None:
    (env.dir / "llm.reply").write_text("x\n\nPart of epic #445")
    env.run(["issue", "--repo", "o/r", "--title", "T", "--yes", "short"])
    assert "--model qwen3.5:4b" in env.read("llm.args")
    facts = env.dir / "facts.txt"
    facts.write_text("fact line\n" * 200)
    env.run(["issue", "--repo", "o/r", "--title", "T", "--yes", "--facts", str(facts)])
    assert "--model gemma4:12b" in env.read("llm.args")


def test_interactive_decline_does_not_file(env: Env) -> None:
    (env.dir / "llm.reply").write_text("Body\n\nPart of epic #445")
    code, out, _ = env.run(["issue", "--repo", "o/r", "--title", "T", "x"], stdin="n\n")
    assert code == 1
    assert "Body" in out
    assert env.read("gh.args") == ""


def test_interactive_accept_files(env: Env) -> None:
    (env.dir / "llm.reply").write_text("Body\n\nPart of epic #445")
    code, _, _ = env.run(["issue", "--repo", "o/r", "--title", "T", "x"], stdin="y\n")
    assert code == 0
    assert "issue create" in env.read("gh.args")


@pytest.mark.parametrize(
    "bad,reason",
    [
        ("this " + chr(0x2014) + " that", "em dash"),
        ("ssh to 192.168.1.20 now", "IP address"),
        ("see box01.lan for it", "hostname"),
        ("serial: ABC123XYZ", "serial"),
        ("de W1AW calling", "callsign"),
        ("grid EM48ab is mine", "grid square"),
        ("https://claude.ai/code/session_abc", "session URL"),
        ("Claude-Session: abc", "Session trailer"),
        ("works at Acmecorp", "denied word"),
    ],
)
def test_checks_refuse_and_name_reason(env: Env, bad: str, reason: str) -> None:
    env.env["SAFO_DRAFT_DENY"] = "acmecorp"
    (env.dir / "llm.reply").write_text(f"{bad}\n\nPart of epic #445")
    code, out, err = env.run(["issue", "--repo", "o/r", "--title", "T", "--yes", "x"])
    assert code == 1
    assert reason in out + err
    assert env.read("gh.args") == ""
    assert bad in out  # the failed draft is still shown


def test_checks_allow_placeholders_and_clean_text(env: Env) -> None:
    assert localdraft.check_text("issue", "N0CALL on FN31pr uses K8S and 10 items\n\nPart of epic #445") == []


def test_issue_needs_epic_line_or_flag(env: Env) -> None:
    (env.dir / "llm.reply").write_text("Body only")
    code, out, err = env.run(["issue", "--repo", "o/r", "--title", "T", "--yes", "x"])
    assert code == 1 and "epic" in (out + err).lower()
    assert env.read("gh.args") == ""
    code, _, _ = env.run(["issue", "--repo", "o/r", "--title", "T", "--yes", "--epic", "445", "x"])
    assert code == 0
    assert "Part of epic #445" in env.read("gh.stdin")


def test_pr_gets_exact_footer_and_files(env: Env) -> None:
    code, out, _ = env.run(["pr", "--repo", "o/r", "--title", "T", "--head", "feat/x", "--yes", "x"])
    assert code == 0
    body = env.read("gh.stdin")
    assert body.rstrip("\n").endswith(FOOTER)
    assert "pr create" in env.read("gh.args") and "--head feat/x" in env.read("gh.args")
    assert FOOTER in out


def test_pr_footer_check_bites() -> None:
    assert localdraft.check_text("pr", "body") != []
    assert localdraft.check_text("pr", f"body\n\n{FOOTER}") == []
    assert localdraft.check_text("pr", f"{FOOTER}\nmore") != []


def test_comment_files_on_number(env: Env) -> None:
    code, _, _ = env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "x"])
    assert code == 0
    assert "issue comment 5" in env.read("gh.args")


def test_busy_retries_with_backoff_then_succeeds(env: Env) -> None:
    (env.dir / "llm.busy").write_text("2")
    code, _, _ = env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "x"])
    assert code == 0
    assert env.read("llm.count").strip() == "3"
    assert env.sleeps == [5, 10]
    assert "--wait" in env.read("llm.args")


def test_busy_gives_up_after_bound(env: Env) -> None:
    (env.dir / "llm.busy").write_text("99")
    code, _, err = env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "x"])
    assert code == 75
    assert env.read("llm.count").strip() == str(localdraft.RETRIES)
    assert env.read("gh.args") == ""
    assert "busy" in err.lower()


def test_failure_reported_never_falls_back(env: Env) -> None:
    (env.dir / "llm.fail").write_text("1")
    code, _, err = env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "x"])
    assert code == 7
    assert "connection refused" in err
    assert "NOT verified" in err and "Twingate" in err
    assert env.read("gh.args") == ""
    assert env.read("llm.count").strip() == "1"


def test_missing_llm_local_is_reported(env: Env) -> None:
    env.env["PATH"] = "/nonexistent"
    code, _, err = env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "x"])
    assert code != 0 and "llm-local" in err and "NOT verified" in err


CI_LOG = """\
build\tTest\t2026-11-26T10:00:01.123Z ##[error]Process completed with exit code 1.
build\tTest\t2026-11-26T10:00:02.123Z FAILED tests/test_a.py::test_one - AssertionError
build\tTest\t2026-11-26T10:00:03.123Z FAILED tests/test_b.py::test_two - AssertionError
build\tTest\t2026-11-26T10:00:04.123Z all good here
build\tLint\t2026-11-26T10:00:05.123Z ##[error]Process completed with exit code 1.
"""


def test_group_ci_lines_counts_in_code() -> None:
    groups = localdraft.group_ci_log(CI_LOG)
    assert groups[0] == (2, "##[error]Process completed with exit code N.")
    assert (1, "FAILED tests/test_a.py::test_one - AssertionError") in groups
    assert all("all good" not in g[1] for g in groups)


def test_digest_ci_log_sends_only_grouped_lines(env: Env) -> None:
    (env.dir / "llm.reply").write_text("one\ntwo")
    log = env.dir / "ci.log"
    log.write_text(CI_LOG)
    code, out, _ = env.run(["digest", "ci-log", str(log)])
    assert code == 0
    sent = env.read("llm.args")
    assert "2 x ##[error]Process completed with exit code N." in sent
    assert "all good" not in sent and "10:00:01" not in sent
    assert "one" in out and "2 x ##[error]" in out
    assert "--task digest-ci-log" in sent


def test_digest_ci_log_reads_stdin_and_skips_model_when_clean(env: Env) -> None:
    code, out, _ = env.run(["digest", "ci-log", "-"], stdin="all fine\nok\n")
    assert code == 0 and "no failure lines" in out
    assert env.read("llm.count") == ""


AUDIT = """\
DRIFT o/r#12 missing Kind
DRIFT o/r#13 missing Kind
DRIFT o/r#14 missing Epic
ok o/r#15
"""


def test_group_board_drift_counts_in_code() -> None:
    groups = localdraft.group_board_drift(AUDIT)
    assert groups[0] == (2, "DRIFT #N missing Kind")
    assert (1, "DRIFT #N missing Epic") in groups


def test_digest_board_drift(env: Env) -> None:
    (env.dir / "llm.reply").write_text("summary")
    code, out, _ = env.run(["digest", "board-drift", "-"], stdin=AUDIT)
    assert code == 0 and "summary" in out
    assert "2 x DRIFT #N missing Kind" in env.read("llm.args")
    assert "--task digest-board-drift" in env.read("llm.args")


def test_metrics_line_has_no_content_and_report(env: Env) -> None:
    env.env["SAFO_DRAFT_DENY"] = ""
    (env.dir / "llm.reply").write_text("SECRETBODY\n\nPart of epic #445")
    env.run(["issue", "--repo", "o/r", "--title", "T", "--yes", "PRIVATEPROMPT"])
    rows = env.metrics()
    assert len(rows) == 1
    row = rows[0]
    assert set(row) == {"ts", "subcommand", "model", "exit", "chars_in", "chars_out"}
    assert row["subcommand"] == "issue" and row["exit"] == 0 and row["model"] == "qwen3.5:4b"
    assert row["chars_in"] > 0 and row["chars_out"] > 0
    raw = (env.state / "safo" / "local-share.jsonl").read_text()
    assert "SECRETBODY" not in raw and "PRIVATEPROMPT" not in raw
    code, out, _ = env.run(["--report"])
    assert code == 0 and "2026-W48" in out and "issue" in out


def test_failed_call_is_logged_with_exit(env: Env) -> None:
    (env.dir / "llm.fail").write_text("1")
    env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "x"])
    assert env.metrics()[-1]["exit"] == 7


def test_report_counts_per_week(env: Env) -> None:
    path = env.state / "safo"
    path.mkdir(parents=True)
    rows = [
        {
            "ts": "2026-11-16T10:00:00+00:00",
            "subcommand": "issue",
            "model": "m",
            "exit": 0,
            "chars_in": 1,
            "chars_out": 1,
        },
        {
            "ts": "2026-11-17T10:00:00+00:00",
            "subcommand": "digest-ci-log",
            "model": "m",
            "exit": 0,
            "chars_in": 1,
            "chars_out": 1,
        },
        {"ts": "2026-11-26T10:00:00+00:00", "subcommand": "pr", "model": "m", "exit": 7, "chars_in": 1, "chars_out": 0},
    ]
    (path / "local-share.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\nnot json\n")
    code, out, _ = env.run(["--report"])
    assert code == 0
    assert "2026-W47" in out and "2026-W48" in out
    line47 = next(x for x in out.splitlines() if "2026-W47" in x)
    assert "2" in line47
