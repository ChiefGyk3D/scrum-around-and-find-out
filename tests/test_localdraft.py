# SPDX-License-Identifier: Apache-2.0
"""safo-draft (#482): local-first drafts and digests. llm-local and gh are PATH shims; no network, no real server."""

from __future__ import annotations

import datetime as dt
import io
import json
import re
import stat
from pathlib import Path
from typing import Any

import pytest

from safo import localdraft

FOOTER = "🤖 Generated with [Claude Code](https://claude.com/claude-code)"
LLM_SHIM = """#!/usr/bin/env bash
if [ "$1" = "--outcome" ]; then
  echo "$2 $3" >> "$SHIM_DIR/llm.outcomes"
  if [ -f "$SHIM_DIR/llm.outcome.fail" ]; then echo "not recorded" >&2; exit 1; fi
  exit 0
fi
echo "$@" >> "$SHIM_DIR/llm.args"
if [ -t 0 ]; then echo TTY >> "$SHIM_DIR/llm.stdin"; else cat >> "$SHIM_DIR/llm.stdin"; fi
n=$(cat "$SHIM_DIR/llm.count" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$SHIM_DIR/llm.count"
if [ -f "$SHIM_DIR/llm.callid" ]; then echo "llm-local: call id $(cat "$SHIM_DIR/llm.callid")-$n" >&2; fi
if [ -f "$SHIM_DIR/llm.busy" ] && [ "$n" -le "$(cat "$SHIM_DIR/llm.busy")" ]; then echo "busy" >&2; exit 75; fi
if [ -f "$SHIM_DIR/llm.fail" ]; then echo "connection refused" >&2; exit 7; fi
if [ -f "$SHIM_DIR/llm.sleep" ]; then exec sleep 5; fi
cat "$SHIM_DIR/llm.reply"
"""
GH_SHIM = """#!/usr/bin/env bash
echo "$@" >> "$SHIM_DIR/gh.args"
cat >> "$SHIM_DIR/gh.stdin"
if [ -f "$SHIM_DIR/gh.sleep" ]; then exec sleep 5; fi
if [ -f "$SHIM_DIR/gh.fail" ]; then echo "HTTP 404" >&2; exit "$(cat "$SHIM_DIR/gh.fail")"; fi
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


def test_draft_defaults_to_gemma_short_and_long(env: Env) -> None:
    (env.dir / "llm.reply").write_text("x\n\nPart of epic #445")
    env.run(["issue", "--repo", "o/r", "--title", "T", "--yes", "short"])
    assert "--model gemma4:12b" in env.read("llm.args")
    assert "qwen" not in env.read("llm.args")
    facts = env.dir / "facts.txt"
    facts.write_text("fact line\n" * 200)
    env.run(["issue", "--repo", "o/r", "--title", "T", "--yes", "--facts", str(facts)])
    assert "--model gemma4:12b" in env.read("llm.args")


def test_pr_and_comment_default_to_gemma(env: Env) -> None:
    (env.dir / "llm.reply").write_text("Body text.")
    env.run(["pr", "--repo", "o/r", "--title", "T", "--yes", "short"])
    assert "--model gemma4:12b" in env.read("llm.args")
    env.run(["comment", "--repo", "o/r", "--number", "3", "--yes", "short"])
    assert "--model gemma4:12b" in env.read("llm.args")


def test_model_flag_still_overrides(env: Env) -> None:
    (env.dir / "llm.reply").write_text("x\n\nPart of epic #445")
    env.run(["issue", "--repo", "o/r", "--title", "T", "--yes", "--model", "qwen3.5:4b", "short"])
    assert "--model qwen3.5:4b" in env.read("llm.args")
    assert env.metrics()[-1]["model"] == "qwen3.5:4b"


def test_interactive_decline_does_not_file(env: Env) -> None:
    (env.dir / "llm.reply").write_text("Body\n\nPart of epic #445")
    code, out, _ = env.run(["issue", "--repo", "o/r", "--title", "T", "x"], stdin="n\n")
    assert code == localdraft.EXIT_DECLINED
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
    ],
)
def test_checks_refuse_and_name_reason(env: Env, bad: str, reason: str) -> None:
    env.env["SAFO_DRAFT_DENY"] = "acmecorp"
    (env.dir / "llm.reply").write_text(f"{bad}\n\nPart of epic #445")
    code, out, err = env.run(["issue", "--repo", "o/r", "--title", "T", "--yes", "x"])
    assert code == 1
    assert reason in out + err
    assert env.read("gh.args") == ""
    assert bad in out  # the failed draft is still shown (unless a private deny entry matched, see round 4b tests)


def test_checks_allow_placeholders_and_clean_text(env: Env) -> None:
    assert localdraft.check_text("issue", "N0CALL and N0TST on FN31pr use 10 items\n\nPart of epic #445") == []


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
    assert set(row) == {
        "ts",
        "subcommand",
        "model",
        "exit",
        "chars_in",
        "chars_out",
        "call_id",
        "project",
        "outcome",
        "outcome_recorded",
    }
    assert row["subcommand"] == "issue" and row["exit"] == 0 and row["model"] == "gemma4:12b"
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


EPIC = "\n\nPart of epic #445"


# finding 1: timeouts
def test_llm_local_timeout_has_own_code_and_message(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(localdraft, "LLM_TIMEOUT", 1)
    (env.dir / "llm.sleep").write_text("1")
    code, _, err = env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "x"])
    assert code == localdraft.EXIT_TIMEOUT != localdraft.EXIT_REFUSED
    assert "timed out" in err and "NOT verified" in err and "Twingate" in err
    assert env.metrics()[-1]["exit"] == localdraft.EXIT_TIMEOUT
    assert env.read("gh.args") == ""


def test_gh_timeout_says_state_unknown(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(localdraft, "GH_TIMEOUT", 1)
    (env.dir / "gh.sleep").write_text("1")
    code, _, err = env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "x"])
    assert code == localdraft.EXIT_TIMEOUT
    assert "unknown" in err and "check with gh" in err
    assert env.metrics()[-1]["exit"] == localdraft.EXIT_TIMEOUT


# finding 2: facts decoding
def test_facts_with_invalid_utf8_do_not_crash(env: Env) -> None:
    facts = env.dir / "facts.bin"
    facts.write_bytes(b"ok " + bytes([0xFF, 0xFE]) + b" tail")
    code, _, err = env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "--facts", str(facts)])
    assert code == 0, err
    assert "tail" in env.read("llm.args")


# finding 3: byte cap
def test_facts_cap_counts_bytes_and_refuses_before_llm_local(env: Env) -> None:
    facts = env.dir / "facts.txt"
    facts.write_text(chr(0xE9) * 100_000)  # 200000 bytes in UTF-8
    code, _, err = env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "--facts", str(facts)])
    assert code == localdraft.EXIT_ERROR
    assert "too large" in err and "NOT verified" not in err
    assert env.read("llm.count") == ""
    assert env.read("gh.args") == ""


def test_facts_cap_does_not_refuse_small_multibyte(env: Env) -> None:
    facts = env.dir / "facts.txt"
    facts.write_text(chr(0xE9) * 10_000)
    code, _, err = env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "--facts", str(facts)])
    assert code == 0, err


# finding 4: title checks
def test_title_is_checked_even_with_yes(env: Env) -> None:
    (env.dir / "llm.reply").write_text("Clean body" + EPIC)
    title = f"de W1AW at 10.0.0.5 {chr(0x2014)} now"
    code, out, err = env.run(["issue", "--repo", "o/r", "--title", title, "--yes", "x"])
    assert code == localdraft.EXIT_REFUSED
    text = out + err
    assert "title" in text and "callsign" in text and "IP address" in text and "em dash" in text
    assert env.read("gh.args") == ""
    code, _, _ = env.run(["issue", "--repo", "o/r", "--title", "Clean title", "--yes", "x"])
    assert code == 0


def test_pr_title_is_checked(env: Env) -> None:
    code, out, _ = env.run(["pr", "--repo", "o/r", "--title", "see box01.lan", "--yes", "x"])
    assert code == localdraft.EXIT_REFUSED and "title" in out and env.read("gh.args") == ""


# finding 5: em dash variants
@pytest.mark.parametrize("cp", [0x2014, 0xFE58, 0xFE31, 0x2E3A, 0x2E3B])
def test_em_dash_variants_blocked(cp: int) -> None:
    assert any("em dash" in x for x in localdraft.check_text("comment", f"a {chr(cp)} b"))


def test_en_dash_and_hyphen_are_not_em_dashes() -> None:
    assert localdraft.check_text("comment", f"a {chr(0x2013)} b - c") == []


# finding 6: heuristics
@pytest.mark.parametrize(
    "text,reason",
    [
        ("de KD2ABC here", "callsign"),
        ("de VK3AB here", "callsign"),
        ("my call is g4xyz ok", "callsign"),
        ("callsign: kd2abc", "callsign"),
        ("locator em48 is mine", "grid square"),
        ("grid em48ab", "grid square"),
        ("grid: Fn31PQ", "grid square"),
        ("at EM48ab today", "grid square"),
        ("at em48AB today", "grid square"),
        ("host fe80::1 up", "IP address"),
        ("addr 2001:db8:85a3::8a2e:370:7334 x", "IP address"),
        ("see [::1]:8080", "IP address"),
        ("SN: ABC12345", "serial"),
        ("sn ABC12345", "serial"),
        ("serial ABC12345", "serial"),
        ("claude.ai/code/session_abc", "session URL"),
        ("www.claude.ai/chat/abc", "session URL"),
    ],
)
def test_tightened_heuristics(text: str, reason: str) -> None:
    assert any(reason in x for x in localdraft.check_text("comment", text)), text


@pytest.mark.parametrize(
    "text",
    [
        "N0CALL and N0TST",
        "grid FN31pr",
        "the cluster and 10 items",
        "at 12:30:45 on std::vector, note::x",
        "the serial numbers are listed",
        "see claude.ai for docs",
        "version 1.2.3 build 4567",
    ],
)
def test_tightened_heuristics_do_not_overblock_these(text: str) -> None:
    assert localdraft.check_text("comment", text) == [], text


def test_allow_list_passes_a_specific_token(env: Env) -> None:
    assert localdraft.check_text("comment", "see B2X1", allow=["B2X1"]) == []
    assert localdraft.check_text("comment", "see W1AW") != []
    assert localdraft.check_text("comment", "see W1AW", allow=["w1aw"]) == []
    assert localdraft.check_text("comment", "de W1AW", allow=["KD2ABC"]) != []
    env.env["SAFO_DRAFT_ALLOW"] = "W1AW"
    (env.dir / "llm.reply").write_text("de W1AW")
    code, _, _ = env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "x"])
    assert code == 0


# finding 7: footer variant
def test_pr_footer_variant_is_replaced(env: Env) -> None:
    (env.dir / "llm.reply").write_text("Body\n\n🤖 Generated with Claude Code (variant)")
    code, _, _ = env.run(["pr", "--repo", "o/r", "--title", "T", "--yes", "x"])
    assert code == 0
    body = env.read("gh.stdin")
    assert body.rstrip("\n").endswith(FOOTER)
    assert body.count("Generated with") == 1 and "variant" not in body


# finding 8: metrics file mode
def test_existing_metrics_file_is_tightened(env: Env) -> None:
    directory = env.state / "safo"
    directory.mkdir(parents=True)
    directory.chmod(0o777)
    path = directory / "local-share.jsonl"
    path.write_text("")
    path.chmod(0o666)
    env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "x"])
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert len(env.metrics()) == 1


# finding 9: exit codes
def test_exit_codes_are_distinct_and_documented() -> None:
    codes = {
        localdraft.EXIT_OK,
        localdraft.EXIT_REFUSED,
        localdraft.EXIT_ERROR,
        localdraft.EXIT_DECLINED,
        localdraft.EXIT_TIMEOUT,
        localdraft.EXIT_INTERNAL,
        localdraft.EXIT_BUSY,
        localdraft.EXIT_GH_FAILED,
    }
    assert len(codes) == 8
    text = localdraft.parser().format_help().lower()
    for name in ("declined", "refused", "timeout", "unexpected"):
        assert name in text


def test_unexpected_exception_gets_own_code(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> str:
        raise RuntimeError("kaboom")

    monkeypatch.setattr(localdraft, "call_local", boom)
    code, _, err = env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "x"])
    assert code == localdraft.EXIT_INTERNAL and "kaboom" in err
    assert env.metrics()[-1]["exit"] == localdraft.EXIT_INTERNAL


# round 2 finding 1: IPv6 behind a label
@pytest.mark.parametrize(
    "text",
    [
        "ipv6:fe80::1",
        "addr:2001:db8::1",
        "x_fe80::1",
        "fe80::1",
        "(fe80::1)",
        "host=fd00::abcd",
        "[fe80::1]",
        "ip6=fe80::1",
        "a,fe80::1",
        "fe80::1%eth0",
        "got 2001:db8::1: and more",
        "got 2001:db8::1, and more",
        "got 2001:db8::1.",
    ],
)
def test_ipv6_is_caught_behind_labels(text: str) -> None:
    assert any("IP address" in x for x in localdraft.check_text("comment", text)), text


@pytest.mark.parametrize(
    "text",
    ["at 12:30:45 today", "mac aa:bb:cc:dd:ee:ff here", "std::vector and note::x", "time 1:2:3"],
)
def test_ipv6_scan_does_not_flag_times_macs_or_scopes(text: str) -> None:
    assert localdraft.check_text("comment", text) == [], text


# round 2 finding 2 and 3: metrics file and directory symlinks
def test_symlinked_metrics_file_is_not_written_through(env: Env, tmp_path: Path) -> None:
    directory = env.state / "safo"
    directory.mkdir(parents=True)
    target = tmp_path / "victim.txt"
    target.write_text("keep")
    target.chmod(0o644)
    (directory / "local-share.jsonl").symlink_to(target)
    code, _, _ = env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "x"])
    assert code == 0
    assert target.read_text() == "keep" and stat.S_IMODE(target.stat().st_mode) == 0o644


def test_symlinked_state_directory_is_not_chmodded_or_logged(env: Env, tmp_path: Path) -> None:
    real = tmp_path / "elsewhere"
    real.mkdir()
    real.chmod(0o755)
    env.state.mkdir()
    (env.state / "safo").symlink_to(real)
    code, _, _ = env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "x"])
    assert code == 0
    assert stat.S_IMODE(real.stat().st_mode) == 0o755
    assert list(real.iterdir()) == []


# round 2 finding 4: gh failure has its own code
def test_gh_failure_maps_to_fixed_code(env: Env) -> None:
    (env.dir / "gh.fail").write_text("1")
    code, _, err = env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "x"])
    assert code == localdraft.EXIT_GH_FAILED == 13
    assert "gh failed" in err and "HTTP 404" in err
    assert env.metrics()[-1]["exit"] == 13


def test_gh_failure_code_is_not_passed_through(env: Env) -> None:
    (env.dir / "gh.fail").write_text("10")
    code, _, _ = env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "x"])
    assert code == localdraft.EXIT_GH_FAILED
    assert "13" in localdraft.parser().format_help()
    assert "| 13 |" in Path(localdraft.__file__).parents[2].joinpath("docs", "local-draft.md").read_text()


# round 3 (Daybreak round 1)
ZW = chr(0x200B)
SHY = chr(0xAD)


@pytest.mark.parametrize(
    "text",
    [
        f"de W1{ZW}AW",
        "de W1<!-- -->AW",
        "de W1<b></b>AW",
        "192&#46;168&#46;1&#46;20",
        "192&amp;#46;168&amp;#46;1&amp;#46;20",
        "192\\.168\\.1\\.20",
        f"fe80:{ZW}:1",
        "fe80\\:\\:1",
        "box01&#46;internal",
        "serial: ABC<!-- -->123XYZ",
        "https://claude&#46;ai/code/session_abc",
        f"Claude{ZW}-Session: abc",
        f"Claude{SHY}-Session: abc",
        "Acme<!-- -->corp",
        f"Acme{chr(0xFEFF)}corp",
        "a &#8212; b",
        "a &mdash; b",
        "a &amp;mdash; b",
        "".join(chr(c) for c in (0xFF17, 0xFF12, 0xFF0E)) + "1.1.1",  # full-width 72. under NFKC
    ],
)
def test_f1_obfuscated_text_is_blocked(text: str) -> None:
    assert localdraft.check_text("comment", text, deny=["Acmecorp"]) != [], text
    assert localdraft.check_title(text, deny=["Acmecorp"]) != [], text


def test_f1_ordinary_text_and_comparisons_still_pass() -> None:
    assert localdraft.check_text("comment", "a < b, 1 < 2, x<=y, a > b", deny=["Acmecorp"]) == []


def test_f1_canonicalize_is_bounded_and_idempotent_on_plain_text() -> None:
    assert localdraft.canonicalize("plain text") == "plain text"
    assert localdraft.canonicalize("&amp;#46;") == "&amp;#46;"  # entities are refused, never decoded (round 4b)


@pytest.mark.parametrize("text", ["w1aw", "W1AW", "em48", "EM48", "fn31pq", "call w1aw/p", "x em48."])
def test_f2_bare_callsign_and_four_char_grid_blocked(text: str) -> None:
    why = localdraft.check_text("comment", text)
    assert any("callsign" in x or "grid" in x for x in why), text


@pytest.mark.parametrize(
    "text",
    [
        "N0CALL N0TST FN31pr",
        "commit 3f786850e387550fdab836ed7e6dc881de23001b",
        "id 123e4567-e89b-12d3-a456-426614174000",
        "version 1.2.3 build 4567 and ipv6 x86_64",
    ],
)
def test_f2_allowed_and_long_tokens_pass(text: str) -> None:
    assert localdraft.check_text("comment", text) == [], text


def test_f3_deny_value_split_between_title_and_body() -> None:
    why = localdraft.check_draft("issue", "Acme", "corp\n\nPart of epic #445", deny=["Acmecorp"])
    assert any("title and body combined" in x for x in why), why
    why = localdraft.check_draft("issue", "Acme", "\ncorp\n\nPart of epic #445", deny=["Acmecorp"])
    assert any("title and body combined" in x for x in why), why


def test_f3_deny_value_split_by_line_break_in_body() -> None:
    assert localdraft.check_text("comment", "works at Acme\ncorp today", deny=["Acmecorp"]) != []
    assert localdraft.check_text("comment", "works at Acme corp today", deny=["Acmecorp"]) != []


def test_f3_split_is_blocked_end_to_end(env: Env) -> None:
    env.env["SAFO_DRAFT_DENY"] = "Acmecorp"
    (env.dir / "llm.reply").write_text("corp\n\nPart of epic #445")
    code, out, _ = env.run(["issue", "--repo", "o/r", "--title", "Acme", "--yes", "x"])
    assert code == 1 and "title and body combined" in out
    assert env.read("gh.args") == ""


def test_f3_clean_title_and_body_pass_together() -> None:
    assert localdraft.check_draft("issue", "Fix the retry bound", "Body here.\n\nPart of epic #445") == []


def _within_deadline(seconds: int, fn: Any) -> None:
    """Run fn under a hard wall-clock alarm so slow code fails the test fast instead of hanging the job."""
    import signal

    def expired(signum: int, frame: Any) -> None:
        raise AssertionError(f"still running after {seconds} s: a check is not linear")

    previous = signal.signal(signal.SIGALRM, expired)
    signal.alarm(seconds)
    try:
        fn()
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def test_f4_checks_are_linear() -> None:
    import time

    def measure(text: str) -> None:
        start = time.process_time()
        localdraft.check_text("comment", text)
        localdraft.check_draft("issue", text[:300], text)
        # CPU time, not wall clock: load on the machine cannot fail it, quadratic code still does
        assert time.process_time() - start < 2.0, text[:12]

    for text in ("a." * 10000, "a." * 9990 + "invalid", "http://" * 2800, "\n" * 20000, "a:" * 10000, "<!--" * 5000):
        _within_deadline(6, lambda t=text: measure(t))


def test_f4_deadline_helper_bites() -> None:
    import time

    with pytest.raises(AssertionError, match="still running"):
        _within_deadline(1, lambda: time.sleep(5))


def test_title_over_cap_is_refused_at_once(env: Env) -> None:
    import time

    env.env["SAFO_DRAFT_DENY"] = "Acmecorp"
    start = time.process_time()
    code, out, err = env.run(["issue", "--repo", "o/r", "--title", "Acmecorp" * 250_000, "--yes", "x"])
    assert time.process_time() - start < 0.1
    assert code == localdraft.EXIT_ERROR
    assert "title too long" in err and "Nothing was filed" in err
    assert "Acmecorp" not in out + err
    assert env.read("gh.args") == "" and env.read("llm.args") == ""
    assert env.metrics()[-1]["exit"] == localdraft.EXIT_ERROR


def test_title_at_cap_is_accepted(env: Env) -> None:
    (env.dir / "llm.reply").write_text("Body.\n\nPart of epic #445")
    code, _, _ = env.run(["issue", "--repo", "o/r", "--title", "t" * localdraft.MAX_TITLE_CHARS, "--yes", "x"])
    assert code == 0


def test_check_draft_bounds_title_itself() -> None:
    why = localdraft.check_draft("issue", "t" * 2_000_000, "Body.\n\nPart of epic #445")
    assert any("title too long" in x for x in why)


def test_allow_entries_split_on_commas_and_whitespace(env: Env) -> None:
    env.env["SAFO_DRAFT_ALLOW"] = "x1c, a1b"
    assert localdraft.allow_words(env.env) == ["x1c", "a1b"]
    path = env.dir / "allow.txt"
    path.write_text("# note\nk8s e2e\n\nw3c, i2c\n")
    path.chmod(0o600)
    env.env["SAFO_DRAFT_ALLOW_FILE"] = str(path)
    assert localdraft.allow_words(env.env) == ["x1c", "a1b", "k8s", "e2e", "w3c", "i2c"]


@pytest.mark.parametrize("var", ["SAFO_DRAFT_ALLOW_FILE", "SAFO_DRAFT_DENY_FILE"])
def test_oversize_config_file_is_refused(env: Env, var: str) -> None:
    path = env.dir / "big.txt"
    path.write_text("abc\n" * 17_000)
    path.chmod(0o600)
    env.env[var] = str(path)
    code, _, err = env.run(["issue", "--repo", "o/r", "--title", "T", "--yes", "x"])
    assert code == localdraft.EXIT_ERROR and "larger than 65536 bytes" in err
    assert env.read("llm.args") == ""


def test_f4_long_model_output_is_refused(env: Env) -> None:
    (env.dir / "llm.reply").write_text("word " * 4001 + "\n\nPart of epic #445")
    code, _, err = env.run(["issue", "--repo", "o/r", "--title", "T", "--yes", "x"])
    assert code == localdraft.EXIT_ERROR
    assert "draft too long to check safely" in err
    assert env.read("gh.args") == ""
    assert env.metrics()[-1]["exit"] == localdraft.EXIT_ERROR


def test_f4_output_at_the_cap_is_checked_normally(env: Env) -> None:
    (env.dir / "llm.reply").write_text("word " * 3990 + "\n\nPart of epic #445")
    code, _, _ = env.run(["issue", "--repo", "o/r", "--title", "T", "--yes", "x"])
    assert code == 0


@pytest.mark.parametrize("text", ["fe80::1x", "2001:db8::1_ab", "fe80::abcd", "x fe80::1xyz"])
def test_f5_ipv6_followed_by_word_characters_is_flagged(text: str) -> None:
    assert any("IP address" in x for x in localdraft.check_text("comment", text)), text


@pytest.mark.parametrize(
    "text", ["std::vector", "note::x", "12:30:45", "aa:bb:cc:dd:ee:ff", "a::b_c", "use fe80:: here"]
)
def test_f5_scope_times_and_macs_still_not_flagged(text: str) -> None:
    assert not any("IP address" in x for x in localdraft.check_text("comment", text)), text


# round 4a: S1 SSID callsigns, S2 IPv6 prefixes, S3 padding and scope heuristic
@pytest.mark.parametrize("text", ["W1AW-7", "w1aw-15", "de W1AW-9", "call w1aw-0.", "x (W1AW-12) y"])
def test_s1_callsign_with_ssid_is_blocked(text: str) -> None:
    assert any("callsign" in x for x in localdraft.check_text("comment", text)), text


@pytest.mark.parametrize("text", ["my-w1aw-x", "w1aw-x", "w1aw-123", "w1aw-7a", "a-w1aw-7"])
def test_s1_hyphen_is_a_separator_so_these_are_blocked(text: str) -> None:
    assert any("callsign" in x for x in localdraft.check_text("comment", text)), text


@pytest.mark.parametrize("text", ["2001:db8::", "fd00:1234::", "see fe80:1::, ok", "net 2001:db8:abcd::/48"])
def test_s2_ipv6_prefixes_are_flagged(text: str) -> None:
    assert any("IP address" in x for x in localdraft.check_text("comment", text)), text


@pytest.mark.parametrize("text", ["e::", "a::", "std::vector", "note::x", "fe80::", "12:30:45", "aa:bb:cc:dd:ee:ff"])
def test_s2_one_hextet_prefixes_and_non_addresses_stay_unflagged(text: str) -> None:
    assert not any("IP address" in x for x in localdraft.check_text("comment", text)), text


@pytest.mark.parametrize(
    "text",
    [
        "fe80::1" + "." * 60,
        "2001:db8::1" + ":" * 50,
        "fe80::1xyz",
        "2001:db8::1g",
        "2001:db8::a1xyz",
        "fe80::1:abcdz",
    ],
)
def test_s3_padding_and_trailing_word_characters_do_not_hide_an_address(text: str) -> None:
    assert any("IP address" in x for x in localdraft.check_text("comment", text)), text


@pytest.mark.parametrize("text", ["std::vector", "note::x", "a::b_c", "use fe80:: here"])
def test_s3_scope_and_single_hextet_cases_stay_unflagged(text: str) -> None:
    assert not any("IP address" in x for x in localdraft.check_text("comment", text)), text


# round 4b: fail closed on exotic text, refuse HTML, exact private values
def _why(text: str, **kw: Any) -> list[str]:
    return localdraft.check_text("comment", text, **kw)


def _deny_file(env: Env, text: str, mode: int = 0o600) -> Path:
    path = Path(env.env["HOME"]) / ".config" / "safo" / "draft-deny"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)
    return path


# item 1: fail closed charset
@pytest.mark.parametrize(
    "text",
    [
        "de W1\u0301AW",  # combining acute after a digit
        "de W1\ufe0fAW",  # variation selector
        "grid F\u0301N31",
        "a \u202e b",  # bidi override
        "a \U000e0041 b",  # tag character
        "a\u200bb",  # zero width space
        "a\u00a0b",  # non-breaking space (NFKC would turn it into a plain space)
        "a\u3000b",  # ideographic space
        "a\u2028b",  # line separator
        "a\ue000b",  # private use
        "a\x1bb",  # control character
        "a\ud800b",  # lone surrogate
    ],
)
def test_r4b1_exotic_characters_are_refused(text: str) -> None:
    assert any("unusual or invisible character" in x for x in _why(text)), repr(text)
    assert any("unusual or invisible character" in x for x in localdraft.check_title(text)), repr(text)


def test_r4b1_ordinary_text_with_accents_and_emoji_passes() -> None:
    assert _why("Caf\u00e9 na\u00efve, tab\there\r\nline two") == []
    assert _why("Cafe\u0301 decomposed composes under NFKC") == []
    assert localdraft.check_text("pr", f"Body\n\n{FOOTER}") == []
    assert _why("done \u2705 \U0001f916") == []


def test_r4b1_exotic_draft_is_never_filed_even_with_yes(env: Env) -> None:
    (env.dir / "llm.reply").write_text("de W1\u0301AW\n\nPart of epic #445")
    code, out, _ = env.run(["issue", "--repo", "o/r", "--title", "T", "--yes", "x"])
    assert code == localdraft.EXIT_REFUSED and "unusual or invisible character" in out
    assert env.read("gh.args") == ""


# item 2: HTML is refused, not decoded
@pytest.mark.parametrize(
    "text",
    [
        '<img src="invalid" alt="W1&#65;W">',
        "Acme<!-- -->corp",
        "<b>x</b>",
        "a</div>",
        "x<!doctype",
        "x<?php",
        "tom &amp; jerry",
        "&#65;",
        "&#x41;",
        "&copy 2026",
        "&#65 next",
        "R&D",
        "\uff1cb\uff1e",  # full-width angle brackets are < and > under NFKC
    ],
)
def test_r4b2_html_is_refused(text: str) -> None:
    assert any("HTML is not allowed in drafts" in x for x in _why(text)), text
    assert any("HTML is not allowed" in x for x in localdraft.check_title(text)), text


@pytest.mark.parametrize("text", ["a < b", "x<=y", "1 < 2 and 3 > 2", "a<1", "if x <- y then", "fish & chips"])
def test_r4b2_comparisons_and_loose_ampersands_stay_allowed(text: str) -> None:
    assert _why(text) == [], text


def test_r4b2_canonicalize_no_longer_decodes_or_strips_html() -> None:
    assert localdraft.canonicalize("&#46; <b>x</b> <!-- c -->") == "&#46; <b>x</b> <!-- c -->"


# item 3: markdown punctuation
@pytest.mark.parametrize(
    "text",
    [
        "de W1**AW**",
        "grid FN**31**",
        "see box.**lan**",
        "ssh 192.168.**1**.1",
        "serial: ABC**123**",
        "https://claude.**ai**/share/secret",
        "de W1`AW`",
        "de W1~~AW~~",
        "de W1\\AW",
    ],
)
def test_r4b3_markdown_punctuation_does_not_hide_a_token(text: str) -> None:
    assert _why(text) != [], text
    assert localdraft.check_title(text) != [], text


def test_r4b3_markdown_split_deny_value_is_blocked() -> None:
    assert _why("works at Ac**me** Corp", deny=["Acme Corp"]) != []
    assert localdraft.canonicalize("a*b`c~d\\e_f-g") == "abcde_f-g"  # underscore and hyphen stay


# item 4: hyphen and underscore are separators
@pytest.mark.parametrize(
    "text",
    ["call-W1AW", "grid-FN31", "w1aw_x", "https://example.test/path/W1AW-x", "my-w1aw-x", "x_EM48_y", "grid-EM48ab"],
)
def test_r4b4_hyphen_and_underscore_are_separators(text: str) -> None:
    assert any("callsign" in x or "grid" in x for x in _why(text)), text


def test_r4b4_long_hex_and_uuid_do_not_collide() -> None:
    assert _why("commit 3f786850e387550fdab836ed7e6dc881de23001b") == []
    assert _why("id 550e8400-e29b-41d4-a716-446655440000") == []
    # four-hex-character groups can have the shape of a callsign (a1bc) or a grid (ab12); a whole UUID is not flagged
    assert _why("id 123e4567-a1bc-12d3-ab12-426614174000") == []
    assert _why("id 123e4567-a1bc-12d3-ab12-426614174000".upper()) == []
    assert _why("bare group a1bc") != []  # the mask is for whole UUIDs only


# item 5: allow list
def test_r4b5_only_the_owner_placeholders_are_built_in() -> None:
    assert _why("N0CALL N0TST FN31pr") == []
    for text in ("FN31", "K3S", "K8S", "K1ABC", "fn31pr", "FN31PR", "P2P", "W3C", "N8N", "I2C", "M3U"):
        assert _why(f"see {text} here") != [], text


def test_r4b5_example_allow_file_is_loadable_and_comment_headed(env: Env) -> None:
    example = Path(localdraft.__file__).parents[2] / "contrib" / "draft-allow.example.txt"
    lines = example.read_text().splitlines()
    assert lines[0].startswith("#") and "SAFO_DRAFT_ALLOW_FILE" in "\n".join(lines[:5])
    tokens = [x for x in lines if x and not x.startswith("#")]
    assert {"K8S", "K3S", "E2E", "FN31", "W3C"} <= set(tokens)
    copy = Path(env.env["HOME"]) / "allow.txt"
    copy.write_text(example.read_text())
    copy.chmod(0o600)
    env.env["SAFO_DRAFT_ALLOW_FILE"] = str(copy)
    (env.dir / "llm.reply").write_text("the K3S and K8S cluster")
    code, _, _ = env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "x"])
    assert code == 0


def test_r4b5_world_writable_allow_file_is_refused(env: Env) -> None:
    copy = Path(env.env["HOME"]) / "allow.txt"
    copy.write_text("K3S\n")
    copy.chmod(0o666)
    env.env["SAFO_DRAFT_ALLOW_FILE"] = str(copy)
    code, _, err = env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "x"])
    assert code == localdraft.EXIT_ERROR and "writable" in err
    assert env.read("llm.count") == ""


# item 6: exact private deny file
@pytest.mark.parametrize(
    "text",
    ["Acme-Corp", "Ac**me** Corp", "A c m e C o r p", "ACME corp", "Acme\ncorp", "ac_me.corp", "A\u200bcme Corp"],
)
def test_r4b6_deny_value_is_matched_squashed(text: str) -> None:
    why = _why(f"works at {text} today", deny=["Acme Corp"])
    assert any("matched private deny entry #1" in x for x in why), text


def test_r4b6_deny_matching_covers_title_body_and_their_join() -> None:
    why = localdraft.check_draft("issue", "Ac", "me Corp\n\nPart of epic #445", deny=["x y z", "Acme Corp"])
    assert any("title and body combined" in x and "private deny entry #2" in x for x in why), why
    why = localdraft.check_draft("issue", "At Acme-Corp", "Body\n\nPart of epic #445", deny=["Acme Corp"])
    assert any(x.startswith("title: ") and "#1" in x for x in why), why


def test_r4b6_deny_file_end_to_end_never_prints_or_logs_the_value(env: Env) -> None:
    _deny_file(env, "# private values\n\nQuux Industries\nAcme Corp\n")
    (env.dir / "llm.reply").write_text("We work with Ac**me** Corp.\n\nPart of epic #445")
    code, out, err = env.run(["issue", "--repo", "o/r", "--title", "T", "--yes", "PROMPT Acme Corp"])
    assert code == localdraft.EXIT_REFUSED
    assert "matched private deny entry #4" in out  # line number in the file, comments and blanks counted
    for stream in (out, err, (env.state / "safo" / "local-share.jsonl").read_text()):
        assert "Acme" not in stream and "Ac**me**" not in stream and "Quux" not in stream
    assert env.read("gh.args") == ""
    assert env.metrics()[-1]["exit"] == localdraft.EXIT_REFUSED


def test_r4b6_deny_hit_in_the_title_never_prints_the_title(env: Env) -> None:
    _deny_file(env, "Acme Corp\n")
    code, out, err = env.run(["issue", "--repo", "o/r", "--title", "About Acme-Corp", "--yes", "x"])
    assert code == localdraft.EXIT_REFUSED and "title: matched private deny entry #1" in out
    assert "Acme" not in out + err


def test_r4b6_other_failures_still_print_the_draft(env: Env) -> None:
    _deny_file(env, "Acme Corp\n")
    (env.dir / "llm.reply").write_text("de W1AW\n\nPart of epic #445")
    code, out, _ = env.run(["issue", "--repo", "o/r", "--title", "T", "--yes", "x"])
    assert code == localdraft.EXIT_REFUSED and "de W1AW" in out


def test_r4b6_short_value_is_a_config_error_naming_the_line_not_the_value(env: Env) -> None:
    _deny_file(env, "# c\nAcme Corp\n\nzq\n")
    code, out, err = env.run(["issue", "--repo", "o/r", "--title", "T", "--yes", "x"])
    assert code == localdraft.EXIT_ERROR
    assert "line 4" in err and "zq" not in err + out
    assert env.read("llm.count") == "" and env.read("gh.args") == ""
    _deny_file(env, "a-b\n")  # squashes to two characters
    code, _, err = env.run(["issue", "--repo", "o/r", "--title", "T", "--yes", "x"])
    assert code == localdraft.EXIT_ERROR and "line 1" in err


def test_r4b6_symlinked_deny_file_is_refused(env: Env, tmp_path: Path) -> None:
    real = tmp_path / "real-deny"
    real.write_text("Acme Corp\n")
    real.chmod(0o600)
    link = Path(env.env["HOME"]) / ".config" / "safo" / "draft-deny"
    link.parent.mkdir(parents=True)
    link.symlink_to(real)
    code, _, err = env.run(["issue", "--repo", "o/r", "--title", "T", "--yes", "x"])
    assert code == localdraft.EXIT_ERROR and "symlink" in err
    assert env.read("llm.count") == ""


@pytest.mark.parametrize("mode", [0o666, 0o662, 0o620, 0o626])
def test_r4b6_group_or_world_writable_deny_file_is_refused(env: Env, mode: int) -> None:
    _deny_file(env, "Acme Corp\n", mode)
    code, _, err = env.run(["issue", "--repo", "o/r", "--title", "T", "--yes", "x"])
    assert code == localdraft.EXIT_ERROR and "writable" in err
    assert env.read("llm.count") == ""


def test_r4b6_group_readable_deny_file_is_accepted(env: Env) -> None:
    _deny_file(env, "Acme Corp\n", 0o640)
    code, _, _ = env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "x"])
    assert code == 0


def test_r4b6_fifo_deny_file_is_refused_without_hanging(env: Env) -> None:
    import os

    path = Path(env.env["HOME"]) / ".config" / "safo" / "draft-deny"
    path.parent.mkdir(parents=True)
    os.mkfifo(path)
    code, _, err = env.run(["issue", "--repo", "o/r", "--title", "T", "--yes", "x"])
    assert code == localdraft.EXIT_ERROR and "regular file" in err


def test_r4b6_missing_default_file_notes_it_once_and_continues(env: Env) -> None:
    code, _, err = env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "x"])
    assert code == 0
    assert err.count("no private deny file configured: only heuristics are active") == 1


def test_r4b6_present_file_prints_no_note(env: Env) -> None:
    _deny_file(env, "Acme Corp\n")
    _, _, err = env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "x"])
    assert "no private deny file" not in err


def test_r4b6_explicit_missing_file_is_refused(env: Env) -> None:
    env.env["SAFO_DRAFT_DENY_FILE"] = str(Path(env.env["HOME"]) / "typo")
    code, _, err = env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "x"])
    assert code == localdraft.EXIT_ERROR and "not found" in err


def test_r4b6_env_deny_list_uses_the_same_squashed_matching(env: Env) -> None:
    env.env["SAFO_DRAFT_DENY"] = "Acme Corp, Quux Industries"
    (env.dir / "llm.reply").write_text("hello Quux-Industries\n\nPart of epic #445")
    code, out, _ = env.run(["issue", "--repo", "o/r", "--title", "T", "--yes", "x"])
    assert code == localdraft.EXIT_REFUSED and "matched private deny entry" in out and "Quux" not in out
    env.env["SAFO_DRAFT_DENY"] = "zq"
    code, _, err = env.run(["issue", "--repo", "o/r", "--title", "T", "--yes", "x"])
    assert code == localdraft.EXIT_ERROR and "zq" not in err


# item 7: IPv6 scope rule
@pytest.mark.parametrize(
    "text",
    ["fe80::abcdxyz", "2001:db8::deadbeefSECRET", "fe80::1xyz", "fe80::abcd_x", "fe80::1_x", "x fe80::1:2:3_ok"],
)
def test_r4b7_addresses_followed_by_letters_are_flagged(text: str) -> None:
    assert any("IP address" in x for x in _why(text)), text


@pytest.mark.parametrize(
    "text", ["std::vector", "note::x", "a::b_c", "use fe80:: here", "12:30:45", "aa:bb:cc:dd:ee:ff"]
)
def test_r4b7_scopes_times_and_macs_are_not_flagged(text: str) -> None:
    assert not any("IP address" in x for x in _why(text)), text


def test_r4b7_known_overblock_is_documented_and_real() -> None:
    assert any("IP address" in x for x in _why("Config::default"))
    assert "Config::default" in Path(localdraft.__file__).parents[2].joinpath("docs", "local-draft.md").read_text()


# round 5, R1: homoglyphs fail closed, deny matching on an ASCII skeleton
_NO_REDUCE = "characters that cannot be reduced to ASCII"


@pytest.mark.parametrize(
    "text",
    [
        "Acme Corp".replace("A", chr(0x410)),  # Cyrillic capital A
        "Acme Corp".replace("o", chr(0x3BF)),  # Greek omicron
        "Acme Corp".replace("o", chr(0x43E)),  # Cyrillic o
        "Ac" + chr(0x435) + "me Corp",  # Cyrillic e in the middle of the word
        "Cl" + chr(0x131) + "ent",  # dotless i
        "Cherokee " + chr(0x13AA),
        "Armenian " + chr(0x585),
        "small cap " + chr(0x1D00),
        "inverted ohm " + chr(0x2127),
    ],
)
def test_r5_1_unreducible_letters_are_refused(text: str) -> None:
    assert any(x.startswith(_NO_REDUCE) for x in _why(text)), ascii(text)
    assert any(_NO_REDUCE in x for x in localdraft.check_title(text)), ascii(text)


def test_r5_1_homoglyph_in_deny_word_is_refused_and_never_echoed() -> None:
    text = f"hello {chr(0x410)}cme Corp"
    why = _why(text, deny=["Acme Corp"])
    assert any(x.startswith(_NO_REDUCE) for x in why)
    assert not any("Acme" in x or "cme" in x or chr(0x410) in x for x in why)
    combined = localdraft.check_draft("comment", chr(0x410) + "cme", "Corp", deny=["Acme Corp"])
    assert any(_NO_REDUCE in x for x in combined)
    assert not any(chr(0x410) in x or "Acme" in x for x in combined)


def test_r5_1_fullwidth_letters_fold_and_match() -> None:
    text = "".join(chr(ord(c) + 0xFEE0) if c.isalpha() else c for c in "Acme Corp")
    why = _why(text, deny=["Acme Corp"])
    assert not any(x.startswith(_NO_REDUCE) for x in why)
    assert any("matched private deny entry" in x for x in why)


def test_r5_1_accented_latin_reduces_and_matches_both_ways() -> None:
    accented = "Caf" + chr(0xE9)
    assert _why(accented) == []
    assert any("matched private deny entry" in x for x in _why("Cafe", deny=[accented]))
    assert any("matched private deny entry" in x for x in _why(accented, deny=["Cafe"]))
    assert any("matched private deny entry" in x for x in _why("Cafe" + chr(0x301), deny=[accented]))


def test_r5_1_plain_ascii_and_emoji_still_pass() -> None:
    assert _why("plain ascii text 123") == []
    assert _why("done " + chr(0x2705) + " " + chr(0x1F916)) == []
    assert localdraft.check_text("pr", f"Body\n\n{FOOTER}") == []


def test_r5_1_unreducible_deny_value_is_a_config_error(env: Env) -> None:
    env.env["SAFO_DRAFT_DENY"] = "Acme " + chr(0x41F) + "orp"
    code, _, err = env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "x"])
    assert code == localdraft.EXIT_ERROR and chr(0x41F) not in err and "Acme" not in err


# round 5, R2: markdown links are refused
@pytest.mark.parametrize(
    "text",
    [
        "see [text](https://example.test/x)",
        "![alt](https://example.test/x.png)",
        "[id]: https://example.test/x",
        "   [id]: https://example.test/x",
        "see [text][id] here",
        "[W1](x)AW",
        "[link](https://example.test/W1AW)",
        "a *[x]*(y)",
    ],
)
def test_r5_2_markdown_links_are_refused(text: str) -> None:
    assert any(re.search("markdown (links|reference definitions) are not allowed", x) for x in _why(text)), text


@pytest.mark.parametrize(
    "text",
    ["- [x] done", "- [ ] todo", "a[0] = 1", "see [x] and [y]", "https://example.test/path", "[x]", "a [b] c: d"],
)
def test_r5_2_checkboxes_brackets_and_bare_urls_pass(text: str) -> None:
    assert not any("markdown links" in x for x in _why(text)), text


def test_r5_2_bare_url_is_still_scanned_as_written() -> None:
    assert any("callsign" in x for x in _why("see https://example.test/W1AW"))
    assert any("session URL" in x for x in _why("see https://claude.ai/chat/x"))


def test_r5_2_pr_footer_is_exempt() -> None:
    assert localdraft.check_text("pr", f"Body\n\n{FOOTER}") == []
    assert any("markdown links" in x for x in localdraft.check_text("pr", f"[a](b)\n\n{FOOTER}"))


def test_r5_new_scans_are_linear() -> None:
    import time

    for text in ("a::" * 6600, "[" * 19000 + "]", "[a]" * 6000, "!" * 19000, ":" * 19000, "a:" * 9900, "é" * 9000):
        start = time.process_time()
        localdraft.check_text("comment", text)
        assert time.process_time() - start < 2.0, text[:6]


_IPV6_MIXES = [":", "::", ":a", "1:", "a::", "a:", "1::", ":::a", ":.", "ab:cd::", "f:e::", "a:b:c:d:e:f:1:"]


class _CountingDict:
    """Stands in for `dict` inside localdraft (check_text only uses `fromkeys`). `_has_ipv6` builds its candidates
    with `dict.fromkeys(cands)`, once per start position, so counting there measures the candidates examined
    without any cost in production code."""

    work = 0

    @classmethod
    def fromkeys(cls, iterable: Any, value: Any = None) -> dict[Any, Any]:
        items = list(iterable)
        cls.work += 1 + len(items)  # one for the start position, one per candidate string
        return dict.fromkeys(items, value)


def _ipv6_work(monkeypatch: pytest.MonkeyPatch, unit: str, size: int) -> int:
    text = (unit * (size // len(unit) + 1))[:size]
    monkeypatch.setattr(localdraft, "dict", _CountingDict, raising=False)
    _CountingDict.work = 0
    localdraft.check_text("comment", text)
    return _CountingDict.work


def _assert_work_is_linear(work: dict[int, int], label: str) -> None:
    """Work at 4x the size is at most 4.5x (linear is 4x, quadratic 16x), and under 4 units
    per input character (measured: at most 1)."""
    small, big = work[5000], work[20000]
    assert big <= 4.5 * max(small, 1), (label, work)
    assert big <= 4 * 20000, (label, work)
    assert work[10000] <= 2.5 * max(small, 1), (label, work)


@pytest.mark.parametrize("unit", _IPV6_MIXES)
def test_r6_ipv6_scan_scales_linearly(unit: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # counted work, not time: the result is the same on an idle laptop and a loaded runner
    # the only clock left is a generous wall deadline that catches a hang
    def run() -> None:
        work = {size: _ipv6_work(monkeypatch, unit, size) for size in (5000, 10000, 20000)}
        _assert_work_is_linear(work, unit)

    _within_deadline(10, run)


def test_r6_work_guard_bites() -> None:
    # quadratic work grows 16x from 5000 to 20000 characters, above the 4.5x bound
    with pytest.raises(AssertionError):
        _assert_work_is_linear({5000: 5000**2, 10000: 10000**2, 20000: 20000**2}, "quadratic")
    # a linear count with too high a constant fails the absolute bound
    with pytest.raises(AssertionError):
        _assert_work_is_linear({5000: 5 * 5000, 10000: 5 * 10000, 20000: 5 * 20000}, "heavy")


def test_r6_work_guard_passes_linear_and_constant() -> None:
    _assert_work_is_linear({5000: 5000, 10000: 10000, 20000: 20000}, "linear")
    _assert_work_is_linear({5000: 1, 10000: 1, 20000: 1}, "constant")


def test_r6_work_counter_sees_the_scan() -> None:
    # the counting hook must be wired to the real scan, or every count above would be a vacuous zero
    mp = pytest.MonkeyPatch()
    try:
        assert _ipv6_work(mp, "a::", 300) > 0
    finally:
        mp.undo()


# round 5, R3: IPv6 scope-likeness is decided per candidate
@pytest.mark.parametrize(
    "text",
    [
        "fe80::abcdxyz",
        "2001:db8::deadbeefSECRET",
        "fe80::1_x",
        "fe80::abcd_x",
        "std::vector fe80::1",
        "a::b::fe80::1",
        "fe80::1::note::x",
        "std::fe80::1",
        "fe80::1::std::vector",
    ],
)
def test_r5_3_real_addresses_are_flagged(text: str) -> None:
    assert any("IP address" in x for x in _why(text)), text


@pytest.mark.parametrize(
    "text", ["std::vector", "note::x", "a::b_c", "use fe80:: here", "12:30:45", "aa:bb:cc:dd:ee:ff"]
)
def test_r5_3_scopes_times_and_macs_stay_unflagged(text: str) -> None:
    assert not any("IP address" in x for x in _why(text)), text


# round 6, M1: reference definitions inside block quotes, list items and multi-line labels
@pytest.mark.parametrize(
    "text",
    [
        "> [id]: https://example.test/x",
        ">[id]: https://example.test/x",
        "- [id]: https://example.test/x",
        "* [id]: https://example.test/x",
        "+ [id]: https://example.test/x",
        "1. [id]: https://example.test/x",
        "12) [id]: https://example.test/x",
        "> - [id]: https://example.test/x",
        ">> 1. * [id]: https://example.test/x",
        "  \t> \t- [id]: https://example.test/x",
        "[long\nlabel]: https://example.test/x",
        "[a\nb\nc]: https://example.test/x",
        "> [long\n> label]: https://example.test/x",
        "intro\n\n- [long\n  label]: https://example.test/x",
        "[id]: https://example.test/x",
    ],
)
def test_r6_m1_nested_and_multiline_definitions_are_refused(text: str) -> None:
    assert any(re.search("markdown (links|reference definitions) are not allowed", x) for x in _why(text)), ascii(text)


@pytest.mark.parametrize(
    "text",
    [
        "- [x] done",
        "- [ ] todo",
        "> - [x] done",
        "1. [ ] todo",
        "a[0] = 1",
        "see [1]",
        "- see [1] for: more",
        "[x]",
        "[open\n\nnew paragraph]: x",
        "[open\nno colon here]",
    ],
)
def test_r6_m1_checkboxes_and_prose_still_pass(text: str) -> None:
    assert not any("markdown " in x for x in _why(text)), ascii(text)


def test_r6_m1_scan_is_linear() -> None:
    import time

    for text in ("> " * 9000, "- " * 9000, "[\n" * 9000, ">" * 19000 + "[a]", "1. " * 6000):
        start = time.process_time()
        localdraft.check_text("comment", text)
        assert time.process_time() - start < 2.0, text[:6]


# round 6, M2: every non-ASCII character reduces or is on the allowlist
_NO_REDUCE_ANY = "characters that cannot be reduced to ASCII"


@pytest.mark.parametrize(
    "cp",
    [0x2C6F, 0xA7B3, 0x2B9, 0x2C2, 0x2208, 0x13AA, 0x1100, 0x20AC, 0xA3, 0x2211, 0x2022 + 0x1000, 0x2192 + 4, 0x2776],
)
def test_r6_m2_symbols_and_lookalikes_are_refused(cp: int) -> None:
    text = "pay " + chr(cp) + " now"
    why = _why(text)
    assert any(x.startswith(_NO_REDUCE_ANY) for x in why), hex(cp)
    assert not any(chr(cp) in x for x in why)


@pytest.mark.parametrize(
    "text",
    [
        chr(0x2018) + "quoted" + chr(0x2019) + " " + chr(0x201C) + "x" + chr(0x201D),
        "a " + chr(0x2013) + " b",
        chr(0x2022) + " bullet",
        "wait" + chr(0x2026),
        "3 " + chr(0xD7) + " 4",
        chr(0x2190) + chr(0x2191) + chr(0x2192) + chr(0x2193),
        chr(0x1F680) + chr(0x1F916) + chr(0x2705) + chr(0x274C) + chr(0x26A0) + chr(0x1F7E2) + chr(0x2B07),
        "Caf" + chr(0xE9),
    ],
)
def test_r6_m2_typography_and_emoji_pass(text: str) -> None:
    assert _why(text) == [], ascii(text)


def test_r6_m2_dingbat_digits_stay_refused() -> None:
    assert any(x.startswith(_NO_REDUCE_ANY) for x in _why(chr(0x2776)))
    assert any(x.startswith(_NO_REDUCE_ANY) for x in _why(chr(0x2793)))


def test_r6_m2_precomposed_accent_squashes_to_ascii() -> None:
    assert localdraft._skeleton("Caf" + chr(0xE9)) == ("Cafe", True)
    assert localdraft._squash("Caf" + chr(0xE9)) == "cafe"
    assert localdraft._skeleton("a" + chr(0x2208) + "b")[1] is False
    assert localdraft._skeleton("a" + chr(0x2192) + "b") == ("ab", True)


# round 7 item 1: SSID handling
@pytest.mark.parametrize("text", ["N0TST-7", "FN31pr-1", "N0CALL-15", "call N0TST-7 here"])
def test_r7_allowed_placeholder_with_ssid_passes(text: str) -> None:
    assert _why(text) == []


@pytest.mark.parametrize("text", ["W1AW-7", "w1aw-15", "de W1AW-7", "x W1AW-7 y"])
def test_r7_real_callsign_with_ssid_is_blocked(text: str) -> None:
    assert any("callsign" in x for x in _why(text)), text


def test_r7_allow_file_entry_covers_the_ssid_form() -> None:
    assert _why("K8S-2", allow=["k8s"]) == []
    assert any("callsign" in x for x in _why("K8S-2"))


# round 7 item 2: an empty deny file is not silent
def test_r7_empty_default_deny_file_notes_once_and_continues(env: Env) -> None:
    _deny_file(env, "# only a comment\n\n")
    code, _, err = env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "x"])
    assert code == 0
    assert err.count("deny file has no entries: only heuristics are active") == 1


def test_r7_empty_explicit_deny_file_is_an_error(env: Env) -> None:
    path = env.dir / "deny.txt"
    path.write_text("# nothing\n")
    path.chmod(0o600)
    env.env["SAFO_DRAFT_DENY_FILE"] = str(path)
    code, _, err = env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "x"])
    assert code == localdraft.EXIT_ERROR and "no entries" in err
    assert env.read("llm.args") == ""


def test_r7_nonempty_deny_file_prints_no_empty_note(env: Env) -> None:
    _deny_file(env, "Acme Corp\n")
    _, _, err = env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "x"])
    assert "no entries" not in err


# round 7 item 3: inline comments and common words
def test_r7_inline_comment_is_stripped_in_deny_file(env: Env) -> None:
    _deny_file(env, "acme corp # my employer\n")
    entries = localdraft.load_deny(env.env, io.StringIO())
    assert [e.squashed for e in entries] == ["acmecorp"]
    assert _why("hi Acme-Corp", deny=entries) != []


def test_r7_hash_without_leading_space_stays_in_the_value(env: Env) -> None:
    _deny_file(env, "acme#corp\n")
    entries = localdraft.load_deny(env.env, io.StringIO())
    assert [e.squashed for e in entries] == ["acmecorp"]


def test_r7_inline_comment_is_stripped_in_allow_file(env: Env) -> None:
    path = env.dir / "allow.txt"
    path.write_text("k8s # kubernetes\ne2e\t# tests\n")
    path.chmod(0o600)
    env.env["SAFO_DRAFT_ALLOW_FILE"] = str(path)
    assert localdraft.allow_words(env.env) == ["k8s", "e2e"]


def test_r7_common_word_deny_entry_warns_with_line_numbers_only(env: Env) -> None:
    _deny_file(env, "# c\nAcme Corp\nThe\nhome # h\n")
    err = io.StringIO()
    localdraft.load_deny(env.env, err)
    text = err.getvalue()
    assert text.count("common English word") == 1 and "lines 3, 4" in text
    assert "Acme" not in text and "home" not in text.replace("lines", "")


def test_r7_uncommon_deny_entry_does_not_warn(env: Env) -> None:
    _deny_file(env, "Acme Corp\n")
    err = io.StringIO()
    localdraft.load_deny(env.env, err)
    assert "common English word" not in err.getvalue()


def test_r7_failure_sets_code() -> None:
    assert localdraft.Failure("x", 7).code == 7


# round 8: any paragraph that holds a `[` and a later `]:` is refused (broad, simple, fails closed)
_BS = chr(92)


@pytest.mark.parametrize(
    "text",
    [
        "[a" + _BS + "]\nb]: https://example.test/x",
        "[a\nb" + _BS + "]\nc]: https://example.test/x",
        _BS + "[x" + _BS + "] then more text]: https://example.test/x",
        "a" + _BS + "]b]: https://example.test/x",
        "the range is [0, 5]: inclusive",
        "note about arr[0]: the first item",
        "intro\n\n> - [a\n> b]: https://example.test/x",
    ],
)
def test_r8_paragraph_with_open_bracket_then_close_colon_is_refused(text: str) -> None:
    assert any("markdown reference definitions are not allowed" in x for x in _why(text)), ascii(text)


@pytest.mark.parametrize(
    "text",
    ["- [x] done", "- [ ] todo", "a[0] = 1", "see [1]", "ok]: fine", "[open\n\nnew paragraph]: x", "[a]\n\nok]: x"],
)
def test_r8_allowed_forms_still_pass(text: str) -> None:
    assert not any("reference definitions" in x for x in _why(text)), ascii(text)


def test_r8_scan_is_linear() -> None:
    import time

    for text in ("[" * 20000, "]" * 20000, "[]" * 10000, (_BS + "[" + "]:") * 6600, "[" + "]:" * 10000):
        start = time.process_time()
        _within_deadline(6, lambda t=text: localdraft.check_text("comment", t))
        assert time.process_time() - start < 2.0, text[:6]


# Round 11: only an explicit allowlist of pictographs (replaces the round 9 name denylist and range allowance).
_DENY = "matched private deny entry"
_FORBIDDEN_WORDS = (
    "DIGIT", "LETTER", "LATIN", "KEYCAP", "NUMBER", "SQUARED", "CIRCLED", "NEGATIVE", "PARENTHESIZED",
    "INPUT SYMBOL",
)  # fmt: skip


def _name_ok(c: str) -> bool:
    import unicodedata

    name = unicodedata.name(c)
    decomposed = unicodedata.normalize("NFKD", c)
    return not any(w in name for w in _FORBIDDEN_WORDS) and not any(x.isalnum() and x.isascii() for x in decomposed)


def _picto() -> list[str]:
    return sorted(localdraft._PICTOGRAPHS)


def test_r11_every_allowlisted_pictograph_is_accepted() -> None:
    assert len(_picto()) >= 30
    for c in _picto():
        assert localdraft._allowed_symbol(c), hex(ord(c))
        assert _why("done " + c) == [], hex(ord(c))
    assert localdraft.check_text("pr", f"Body\n\n{FOOTER}") == []
    assert chr(0x1F916) in localdraft._PICTOGRAPHS


def test_r11_allowlist_is_small_and_has_no_letter_or_digit_names() -> None:
    import unicodedata

    assert len(localdraft._PICTOGRAPHS) <= 45
    assert chr(0x1F517) not in localdraft._PICTOGRAPHS  # link symbol is not on the owner list
    assert chr(0x1F4AF) not in localdraft._PICTOGRAPHS  # hundred points shows digits
    for c in _picto():
        name = unicodedata.name(c)
        assert not any(w in name for w in _FORBIDDEN_WORDS), name
        decomposed = unicodedata.normalize("NFKD", c)
        assert not any(x.isalnum() and x.isascii() for x in decomposed), name
    # the guard bites: a keycap and a squared letter would fail the name test
    for bad in (chr(0x1F51F), chr(0x1F170), chr(0x1F4AF)):
        assert bad not in localdraft._PICTOGRAPHS
    assert any(w in unicodedata.name(chr(0x1F51F)) for w in _FORBIDDEN_WORDS)


def test_r11_every_other_pictograph_code_point_is_refused() -> None:
    def sweep() -> None:
        refused = 0
        for n in (*range(0x1F300, 0x1FB00), *range(0x2600, 0x27C0)):
            c = chr(n)
            if c in localdraft._PICTOGRAPHS:
                assert _name_ok(c), hex(n)  # an allowlisted code point must pass the name test
                continue
            assert not localdraft._allowed_symbol(c), hex(n)
            assert not localdraft._skeleton(c)[1], hex(n)
            refused += 1
        assert refused > 2000

    _within_deadline(30, sweep)
    assert any(_NO_REDUCE in x for x in _why("x " + chr(0x1F517)))


def test_r11_reviewer_reproductions_refused() -> None:
    k = chr(0x1F51F)
    for text in (
        "FN" + k + "pr",
        "W" + k + "AW",
        "serial " + k + "23456",
        "FN" + chr(0x1F522) + "pr",
        *(chr(n) for n in (*range(0x1F519, 0x1F51E), 0x1F6BE, 0x1F3E7, 0x2B55, 0x2613, 0x274E, 0x1F5D9)),
        *(chr(n) for n in (*range(0x1F5F4, 0x1F5F8), *range(0x1F7A8, 0x1F7AF))),
    ):
        assert any(_NO_REDUCE in x for x in _why(text)), ascii(text)
    for deny in ([], ["FN31pr"]):
        assert any(_NO_REDUCE in x for x in _why("FN" + k + "pr", deny=deny))


def test_r11_removed_x_marks_and_letterlike_signs_refused() -> None:
    for n in (0x2715, 0x2716, 0x2717, 0x2718, 0xAE, 0xA9, 0x1F4AF, 0x1F51E, 0x1F3B1):
        assert any(_NO_REDUCE in x for x in _why("a" + chr(n) + "b")), hex(n)


def test_r11_multiplication_sign_and_cross_mark_are_an_x() -> None:
    m, cross = chr(0xD7), chr(0x274C)
    assert any(_DENY in x for x in _why("Acme" + m + "Labs", deny=["AcmeXLabs"]))
    assert any(_TOUCH in x for x in _why("3" + m + "4"))  # round 13: touching a digit is refused
    assert _why("3 " + m + " 4") == []
    assert any(_DENY in x for x in _why("AcmeXLabs", deny=["Acme" + m + "Labs"]))
    assert any(_DENY in x for x in _why("Acme" + m + "Labs", deny=["Acme" + m + "Labs"]))
    assert any(_DENY in x for x in _why("Acme" + cross + "labs", deny=["Acmexlabs"]))
    assert any(_DENY in x for x in _why("Acmexlabs", deny=["Acme" + cross + "labs"]))
    assert any(_DENY in x for x in _why("Acme" + cross + "labs", deny=["Acme"]))


def test_r11_colored_circles_are_an_o() -> None:
    for n in (0x1F534, 0x1F7E2, 0x1F7E1):
        c = chr(n)
        assert any(_DENY in x for x in _why("F" + c + c + "d", deny=["Food"])), hex(n)
        assert any(_DENY in x for x in _why("Foo", deny=["F" + c + c])), hex(n)
        assert any(_DENY in x for x in _why("Fo" + c + " bar", deny=["Foobar"])), hex(n)
        assert _why("status " + c + " ok") == []
        assert any(_TOUCH in x for x in _why("Fo" + c + " bar"))
    assert any(_DENY in x for x in _why("Fo" + chr(0x1F534), deny=["Foo"]))


# round 10: refusals name the offending line and say what to change, and never echo the draft
_SECRET_WORDS = ("zebrafish", "quokka", "marmoset")


def _find(why: list[str], needle: str) -> str:
    hits = [x for x in why if needle in x]
    assert len(hits) == 1, (needle, why)
    return hits[0]


def _no_echo(message: str) -> None:
    assert not any(w in message for w in _SECRET_WORDS), message


def test_r10_refdef_message_names_line_and_action() -> None:
    text = "first zebrafish line\n\nsecond quokka line\nthird [marmoset] line\nfourth: ok]: tail"
    msg = _find(_why(text), "reference definitions")
    assert msg == (
        "markdown reference definitions are not allowed in drafts: a `[` followed later by `]:` in the same "
        "paragraph (line 5). Reword it, put the text in a code span without brackets, or split the paragraph; "
        "write URLs plainly."
    )
    _no_echo(msg)


def test_r10_refdef_line_in_first_paragraph_and_escaped_bracket() -> None:
    assert "(line 1)" in _find(_why("[zebrafish]: x"), "reference definitions")
    assert "(line 3)" in _find(_why("a\n\nzebrafish \\] and ]: x"), "reference definitions")


def test_r10_html_message_names_line_and_action() -> None:
    msg = _find(_why("zebrafish\nquokka\nfile <module> marmoset"), "HTML is not allowed")
    assert msg == (
        "HTML is not allowed in drafts (line 3): remove the angle-bracket text; write `{name}` instead of "
        "`<name>`; a pasted traceback with `<module>` must be rewritten without the angle brackets."
    )
    _no_echo(msg)
    assert "(line 2)" in _find(_why("zebrafish\nR&D quokka\n"), "HTML is not allowed")


def test_r10_link_message_names_line_and_action() -> None:
    msg = _find(_why("zebrafish\n\nquokka [x](http://example.com/marmoset)"), "markdown links")
    assert msg == "markdown links are not allowed in drafts (line 3): write the URL plainly."
    _no_echo(msg)


def test_r10_unusual_character_message_names_line() -> None:
    msg = _find(_why("zebrafish\nquokka" + chr(0x200B) + "marmoset"), "unusual or invisible characters")
    assert msg == (
        "unusual or invisible characters (line 2): remove them (a stray variation selector, zero-width or "
        "combining character)"
    )
    _no_echo(msg)


def test_r10_unreducible_message_names_line() -> None:
    text = "zebrafish\nquokka\nmarmoset " + chr(0x410)
    msg = _find(_why(text), _NO_REDUCE)
    assert msg == (
        "characters that cannot be reduced to ASCII (line 3): remove emoji and other symbols, or use only the "
        "allowed pictographs listed in docs/local-draft.md"
    )
    _no_echo(msg)
    assert chr(0x410) not in msg


def test_r10_title_refusal_says_line_one() -> None:
    assert any("(line 1)" in x for x in localdraft.check_title("zebrafish <b>"))


def test_r10_deny_hit_prints_only_the_entry_number() -> None:
    why = _why("line one\nline two zebrafish\n", deny=["zebrafish"])
    hits = [x for x in why if "matched private deny entry" in x]
    assert len(hits) == 1
    assert "line" not in hits[0].replace("deny entry", "")
    assert "zebrafish" not in hits[0]
    assert not any("zebrafish" in x for x in why)


# round 12
_VS = chr(0xFE0F)
_UNUSUAL = "unusual or invisible characters"


def test_r12_variation_selector_after_an_allowed_pictograph_passes() -> None:
    for n in (0x2705, 0x2714, 0x26A0, 0x274C):
        text = "done " + chr(n) + _VS + " ok"
        assert _why(text) == [], hex(n)
        assert localdraft.check_title(text) == [], hex(n)


def test_r12_variation_selector_elsewhere_is_refused() -> None:
    for text in (
        "de W1" + _VS + "AW",
        _VS,
        "a " + _VS + " b",
        "a" + chr(0x2705) + _VS + _VS,
        "a " + _VS + _VS,
        "a" + chr(0x1F517) + _VS,  # not an allowed pictograph
        "a" + chr(0x2022) + _VS,
    ):
        assert any(_UNUSUAL in x or _NO_REDUCE in x for x in _why(text)), ascii(text)
        assert any(_UNUSUAL in x or _NO_REDUCE in x for x in localdraft.check_title(text)), ascii(text)
    assert any(_UNUSUAL in x for x in _why(_VS))
    assert any(_UNUSUAL in x for x in _why("a" + chr(0x2705) + _VS + _VS))


def test_r12_stripped_variation_selector_never_hides_a_value() -> None:
    check = chr(0x2705)
    assert localdraft._squash("Ac" + check + _VS + "me") == "acme"
    assert any(_DENY in x for x in _why("Ac" + check + _VS + "me", deny=["Acme"]))
    assert any("callsign" in x for x in _why("W1" + check + _VS + "AW W1AW"))


def test_r12_new_pictographs_are_allowed_and_names_pass() -> None:
    for n in (0x2B50, 0x2795, 0x1F3AF, 0x1F4CA, 0x1F6A8, 0x1F9EA):
        c = chr(n)
        assert c in localdraft._PICTOGRAPHS and _name_ok(c), hex(n)
        assert _why("done " + c) == [], hex(n)
    assert len(localdraft._PICTOGRAPHS) <= 45
    for n in (0x1F517, 0x1F4AF):
        assert any(_NO_REDUCE in x for x in _why("a" + chr(n))), hex(n)


def test_r12_messages_are_actionable_and_hold_no_text() -> None:
    why = _why("zebrafish\nquokka" + chr(0x1F517))
    assert _find(why, _NO_REDUCE).endswith(
        "(line 2): remove emoji and other symbols, or use only the allowed pictographs listed in docs/local-draft.md"
    )
    assert not any(chr(0x1F517) in x for x in why)


def test_r12_one_reason_per_class_in_check_draft() -> None:
    why = localdraft.check_draft("comment", "Title", "one\ntwo\nthree " + chr(0x410))
    assert len([x for x in why if _NO_REDUCE in x]) == 1, why
    assert "(line 3)" in _find(why, _NO_REDUCE)
    why = localdraft.check_draft("comment", "Title", "para\n\nsee [a] and ]: x")
    assert len([x for x in why if "reference definitions" in x]) == 1, why
    why = localdraft.check_draft("comment", "T" + chr(0x410), "body")
    assert len([x for x in why if _NO_REDUCE in x]) == 1, why
    why = localdraft.check_draft("issue", "Acme", "corp\n\nPart of epic #445", deny=["Acmecorp"])
    assert len([x for x in why if "title and body combined" in x and _DENY in x]) == 1, why


def test_r12_lookalike_symbols_match_both_readings() -> None:
    m, cross, circle = chr(0xD7), chr(0x274C), chr(0x1F534)
    assert any(_DENY in x for x in _why("Acme" + m + "Labs", deny=["AcmexLabs"]))  # letter reading
    assert any(_DENY in x for x in _why("Acme" + m + "Labs", deny=["AcmeLabs"]))  # dropped reading
    assert any(_DENY in x for x in _why("Fo" + circle + "o", deny=["Foo"]))  # dropped reading
    assert any(_DENY in x for x in _why("Fo" + circle + "o", deny=["Fooo"]))  # letter reading
    assert any(_DENY in x for x in _why("Acmexlabs", deny=["Acme" + cross + "labs"]))
    assert any(_DENY in x for x in _why("Acmelabs", deny=["Acme" + cross + "labs"]))
    assert any(_DENY in x for x in _why("Acme" + cross + "labs", deny=["Acme" + cross + "labs"]))
    both = localdraft.check_draft("comment", "Acme" + m, "Labs", deny=["AcmeLabs"])
    assert any(_DENY in x for x in both), both
    assert not any(_DENY in x for x in _why("Acme Co" + m + "ffee", deny=["Acmetea"]))


# round 13: look-alike symbols touching a letter or digit are refused, and every heuristic runs on all readings
_TOUCH = "a look-alike symbol touches a letter or digit"
_LONG = "draft too long to check safely"
_SELECTOR = chr(0xFE0F)


def _lookalike_cases() -> list[str]:
    m, cross, red = chr(0xD7), chr(0x274C), chr(0x1F534)
    return [
        "x1" + m + "x",
        "FN31p" + m,
        "F" + red + "31pr",
        "box.l" + red + "cal",
        "serial AB" + cross + "1234",
        "3" + m + "4",
        m + "a",
    ]


@pytest.mark.parametrize("selector", ["", _SELECTOR])
def test_r13_touching_lookalikes_are_refused(selector: str) -> None:
    cross, red = chr(0x274C), chr(0x1F534)
    for text in _lookalike_cases():
        for sym in (cross, red):
            if sym in text:
                text = text.replace(sym, sym + selector)
        assert any(_TOUCH in x for x in _why(text)), ascii(text)
        assert any(_TOUCH in x for x in localdraft.check_title(text)), ascii(text)
    for n in (0xD7, 0x274C, 0x1F534, 0x1F7E2, 0x1F7E1):
        c = chr(n) + (selector if n != 0xD7 else "")
        for text in ("a" + c, c + "a", "7" + c, c + "7", "Caf" + chr(0xE9) + c):
            assert any(_TOUCH in x for x in _why(text)), (hex(n), ascii(text))
    why = _why("fine\nsecond " + chr(0xD7) + "a")
    assert any(_TOUCH in x and "(line 2)" in x for x in why), why


def test_r13_standalone_lookalikes_pass() -> None:
    m, cross, red, green, yellow = chr(0xD7), chr(0x274C), chr(0x1F534), chr(0x1F7E2), chr(0x1F7E1)
    for text in (
        "done " + cross,
        cross + " failed",
        cross + _SELECTOR + " failed",
        "- " + red + " down\n- " + green + " up\n- " + yellow + " slow",
        "status: " + red + ", then " + green + ".",
        "3 " + m + " 4",
        "(" + red + ")",
        "a " + cross + _SELECTOR + ", b",
    ):
        assert _why(text) == [], ascii(text)


def test_r13_selector_forms_are_judged_like_plain_forms() -> None:
    red = chr(0x1F534)
    assert _why("a" + red + _SELECTOR) == _why("a" + red) != []


def test_r13_letter_reading_alone_catches_a_heuristic_hit() -> None:
    m = chr(0xD7)
    text = m + ".lan"  # letter reading `x.lan`; the dropped reading `.lan` and the raw text hold no host
    assert localdraft._skeleton(text, False)[0] == ".lan"
    assert "hostname found" in _why(text)
    assert _why(".lan") == []


def test_r13_dropped_reading_alone_catches_a_heuristic_hit() -> None:
    m = chr(0xD7)
    text = (
        "serial " + m + " ABC1234"
    )  # dropped reading `serial  ABC1234`; the letter reading `serial x ABC1234` has none
    assert localdraft._skeleton(text)[0] == "serial x ABC1234"
    assert "serial number found" in _why(text)
    assert "serial number found" not in _why("serial x ABC1234")


def test_r13_skeleton_keeps_ascii_structure() -> None:
    m = chr(0xD7)
    for letters, want in ((True, "box.x lan:\n7, x"), (False, "box. lan:\n7, ")):
        assert localdraft._skeleton("box." + m + " lan:\n7, " + m, letters)[0] == want


def test_r13_deny_matching_still_works_for_the_repro_inputs() -> None:
    m, red = chr(0xD7), chr(0x1F534)
    assert any(_DENY in x for x in _why("Acme" + m + "Labs", deny=["AcmexLabs"]))
    assert any(_DENY in x for x in _why("Acme" + m + "Labs", deny=["AcmeLabs"]))
    assert any(_DENY in x for x in _why("Fo" + red + "o", deny=["Foo"]))


def test_r13_nfkc_expansion_is_refused_before_the_scans() -> None:
    import time

    text = chr(0xFDFA) * 20000
    start = time.process_time()
    why = _why(text)
    title = localdraft.check_draft("issue", "T", text + "\n\nPart of epic #1")
    spent = time.process_time() - start
    assert why == [x for x in why if _LONG in x] and why, why
    assert spent < 1.0, spent
    assert any(_LONG in x for x in localdraft.check_draft("comment", None, text)), title
    assert not any(_LONG in x for x in _why(chr(0xFDFA) * 100))  # a short expanding text is still checked


# round 14: a draft that could not be fully checked is withheld, and the deny match still runs on the bounded source
_WITHHELD = "could not be fully checked"
_BIG = chr(0xFDFA) * 4445  # 80010 characters after NFKC, under the 20000-character source cap


def _run_big(env: Env, body: str, title: str = "T", deny: str = "ZebraEmployer") -> tuple[int, str]:
    env.env["SAFO_DRAFT_DENY"] = deny
    (env.dir / "llm.reply").write_text(body + "\n\nPart of epic #445")
    code, out, _ = env.run(["issue", "--repo", "o/r", "--title", title, "--yes", "x"])
    assert env.read("gh.args") == ""
    return code, out


def test_r14_expanding_draft_with_deny_value_is_withheld(env: Env) -> None:
    code, out = _run_big(env, _BIG + " ZebraEmployer")
    assert code == localdraft.EXIT_REFUSED
    assert _WITHHELD in out and "matched private deny entry SAFO_DRAFT_DENY#1" in out
    assert "ZebraEmployer" not in out and chr(0xFDFA) not in out and "Part of epic" not in out
    assert "(line" not in out


def test_r14_expanding_draft_without_deny_hit_is_withheld(env: Env) -> None:
    code, out = _run_big(env, _BIG + " harmless words")
    assert code == localdraft.EXIT_REFUSED
    assert _WITHHELD in out and _LONG in out
    assert "harmless" not in out and chr(0xFDFA) not in out and "(line" not in out


def test_r14_deny_value_split_across_title_and_body_is_refused_silently(env: Env) -> None:
    code, out = _run_big(env, _BIG + " Employer", title="Zebra")
    assert code == localdraft.EXIT_REFUSED
    assert (
        _WITHHELD in out and "title and body combined" in out and "matched private deny entry SAFO_DRAFT_DENY#1" in out
    )
    assert "Zebra" not in out and "Employer" not in out and chr(0xFDFA) not in out


def test_r14_long_title_is_withheld() -> None:
    title = "SecretTitleText " + "a" * 400
    why = localdraft.check_draft("issue", title, "ok\n\nPart of epic #1", deny=["SecretTitleText"])
    assert any("too long to check safely" in x for x in why) and any(_DENY in x for x in why)
    assert any("too long to check safely" in x for x in localdraft.check_title(title))


def test_r14_overlong_text_still_names_the_deny_entry() -> None:
    why = localdraft.check_text("comment", "a" * 20001 + " ZebraEmployer", deny=["ZebraEmployer"])
    assert any(_DENY in x and "#1" in x for x in why) and any("too long to check safely" in x for x in why)


def test_r14_normal_refusal_still_prints_the_draft(env: Env) -> None:
    env.env["SAFO_DRAFT_DENY"] = "ZebraEmployer"
    (env.dir / "llm.reply").write_text("call KB1ABC now\n\nPart of epic #445")
    code, out, _ = env.run(["issue", "--repo", "o/r", "--title", "T", "--yes", "x"])
    assert code == localdraft.EXIT_REFUSED and "call KB1ABC now" in out and _WITHHELD not in out


# the bounded deny paths, called directly (a mutation that dropped them once survived the suite)
def test_check_text_runs_the_bounded_deny_match_on_an_nfkc_expanding_body() -> None:
    why = localdraft.check_text("comment", _BIG + " ZebraEmployer", deny=["ZebraEmployer"])
    assert any(_DENY in x for x in why) and any(_LONG in x for x in why)
    assert not any("ZebraEmployer" in x for x in why)  # the reason never holds the value


def test_check_title_runs_the_bounded_deny_match_on_an_overlong_title() -> None:
    title = "a" * 290 + " ZebraEmployer " + "b" * 10
    assert len(title) > localdraft.MAX_TITLE_CHARS
    why = localdraft.check_title(title, deny=["ZebraEmployer"])
    assert any(x.startswith("title: ") and _DENY in x for x in why)
    assert any("too long" in x for x in why)
    assert not any("ZebraEmployer" in x for x in why)


def test_the_no_deny_note_is_not_printed_when_the_env_list_supplies_entries(env: Env) -> None:
    env.env["SAFO_DRAFT_DENY"] = "ZebraEmployer"
    err = io.StringIO()
    entries = localdraft.load_deny(env.env, err)
    assert [e.squashed for e in entries] == ["zebraemployer"]
    assert "no private deny file" not in err.getvalue()
    code, _, run_err = env.run(["comment", "--repo", "o/r", "--number", "5", "--yes", "x"])
    assert code == 0 and "no private deny file" not in run_err


def test_the_no_deny_note_is_printed_when_nothing_supplies_an_entry(env: Env) -> None:
    for value in (None, "", " , "):
        if value is not None:
            env.env["SAFO_DRAFT_DENY"] = value
        err = io.StringIO()
        assert localdraft.load_deny(env.env, err) == []
        assert err.getvalue().count("no private deny file configured: only heuristics are active") == 1, value


# issue #505: call id, project and outcome for every local draft
EDITOR_SHIM = """#!/usr/bin/env bash
echo "EDITEDLINE" >> "$1"
"""
ISSUE = ["issue", "--repo", "Own/proj", "--title", "T"]


def _with_id(env: Env, value: str = "abc") -> None:
    (env.dir / "llm.callid").write_text(value)
    _reply(env)


def _reply(env: Env) -> None:
    (env.dir / "llm.reply").write_text("Do the thing.\n\nPart of epic #445")


def _editor(env: Env, tmp_path: Path) -> None:
    path = tmp_path / "editor.sh"
    path.write_text(EDITOR_SHIM)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    env.env["VISUAL"] = str(path)


def _outcomes(env: Env) -> list[str]:
    return env.read("llm.outcomes").splitlines()


def test_call_id_and_project_are_recorded(env: Env) -> None:
    _with_id(env)
    code, _, _ = env.run([*ISSUE, "--yes", "x"])
    row = env.metrics()[-1]
    assert code == 0 and row["call_id"] == "abc-1" and row["project"] == "Own/proj"


def test_unmodified_draft_is_accepted(env: Env) -> None:
    _with_id(env)
    code, _, err = env.run([*ISSUE, "--yes", "x"])
    assert code == 0 and _outcomes(env) == ["abc-1 accepted"] and "not recorded" not in err
    row = env.metrics()[-1]
    assert row["outcome"] == "accepted" and row["outcome_recorded"] is True


def test_footer_append_is_a_mechanical_edit_still_accepted(env: Env) -> None:
    _with_id(env)
    code, _, _ = env.run(["pr", "--repo", "Own/proj", "--title", "T", "--yes", "x"])
    assert code == 0 and _outcomes(env) == ["abc-1 accepted"] and FOOTER in env.read("gh.stdin")


def test_human_edit_is_rewritten(env: Env, tmp_path: Path) -> None:
    _with_id(env)
    _editor(env, tmp_path)
    code, _, _ = env.run([*ISSUE, "x"], stdin="e\ny\n")
    assert code == 0 and "EDITEDLINE" in env.read("gh.stdin")
    assert _outcomes(env) == ["abc-1 rewritten"]
    assert env.metrics()[-1]["outcome"] == "rewritten"


def test_decline_is_discarded(env: Env) -> None:
    _with_id(env)
    code, _, _ = env.run([*ISSUE, "x"], stdin="n\n")
    assert code == localdraft.EXIT_DECLINED and _outcomes(env) == ["abc-1 discarded"]
    assert env.read("gh.args") == "" and env.metrics()[-1]["outcome"] == "discarded"


def test_refused_by_a_check_is_discarded(env: Env) -> None:
    _with_id(env)
    (env.dir / "llm.reply").write_text("bad " + localdraft.EM_DASHES[0] + " dash\n\nPart of epic #445")
    code, _, _ = env.run([*ISSUE, "--yes", "x"])
    assert code == localdraft.EXIT_REFUSED and _outcomes(env) == ["abc-1 discarded"]
    assert env.read("gh.args") == ""


def test_fact_error_is_never_set_automatically(env: Env) -> None:
    _with_id(env)
    env.run([*ISSUE, "--yes", "x"])
    env.run([*ISSUE, "x"], stdin="n\n")
    assert all("fact-error" not in x for x in _outcomes(env))


def test_outcome_failure_never_blocks_filing(env: Env) -> None:
    _with_id(env)
    (env.dir / "llm.outcome.fail").write_text("1")
    code, _, err = env.run([*ISSUE, "--yes", "x"])
    assert code == 0 and "issue create" in env.read("gh.args")
    assert "outcome not recorded (1 draft)" in err and "Short draft" not in err
    row = env.metrics()[-1]
    assert row["outcome"] == "accepted" and row["outcome_recorded"] is False and row["exit"] == 0


def test_missing_call_id_is_none_and_carries_on(env: Env) -> None:
    _reply(env)
    code, _, err = env.run([*ISSUE, "--yes", "x"])
    row = env.metrics()[-1]
    assert code == 0 and row["call_id"] == "none" and _outcomes(env) == []
    assert row["outcome_recorded"] is False and "outcome not recorded" in err
    assert "issue create" in env.read("gh.args")


def test_retry_records_the_id_of_the_accepted_call(env: Env) -> None:
    _with_id(env)
    (env.dir / "llm.busy").write_text("1")
    code, _, _ = env.run([*ISSUE, "--yes", "x"])
    assert code == 0 and env.metrics()[-1]["call_id"] == "abc-2" and _outcomes(env) == ["abc-2 accepted"]


def test_no_draft_text_in_any_row(env: Env, tmp_path: Path) -> None:
    _with_id(env)
    _editor(env, tmp_path)
    (env.dir / "llm.reply").write_text("SECRETBODY text\n\nPart of epic #445")
    env.run([*ISSUE, "PRIVATEPROMPT"], stdin="e\ny\n")
    env.run([*ISSUE, "PRIVATEPROMPT"], stdin="n\n")
    env.run(["--outcome", "abc-1", "fact-error"])
    raw = (env.state / "safo" / "local-share.jsonl").read_bytes()
    assert raw.count(b"\n") == 3
    for needle in (b"SECRETBODY", b"PRIVATEPROMPT", b"EDITEDLINE"):
        assert needle not in raw


def test_fact_error_mark_calls_llm_local_and_appends_a_row(env: Env) -> None:
    code, _, _ = env.run(["--outcome", "abc-1", "fact-error"])
    assert code == 0 and _outcomes(env) == ["abc-1 fact-error"]
    row = env.metrics()[-1]
    assert row["subcommand"] == "outcome" and row["call_id"] == "abc-1" and row["outcome_recorded"] is True


def test_fact_error_mark_failure_is_reported_and_kept(env: Env) -> None:
    (env.dir / "llm.outcome.fail").write_text("1")
    code, _, err = env.run(["--outcome", "abc-1", "fact-error"])
    assert code == localdraft.EXIT_ERROR and "not recorded" in err
    assert env.metrics()[-1]["outcome_recorded"] is False


@pytest.mark.parametrize("args", [["abc-1", "accepted"], ["--bad", "fact-error"], ["a b", "fact-error"]])
def test_outcome_flag_only_takes_fact_error_and_a_clean_id(env: Env, args: list[str]) -> None:
    code, _, err = env.run(["--outcome", *args])
    assert code == localdraft.EXIT_ERROR and "fact-error" in err
    assert _outcomes(env) == [] and env.metrics() == []


def _row(ts: str, sub: str, **more: object) -> dict[str, object]:
    return {"ts": ts, "subcommand": sub, "model": "m", "exit": 0, "chars_in": 1, "chars_out": 1, **more}


def test_report_outcome_counts_rates_projects_and_unrecorded(env: Env) -> None:
    (env.state / "safo").mkdir(parents=True)
    d = "2026-11-26T10:00:00+00:00"
    rows = [
        _row(d, "issue", call_id="a", project="Own/one", outcome="accepted", outcome_recorded=True),
        _row(d, "pr", call_id="b", project="Own/one", outcome="rewritten", outcome_recorded=True),
        _row(d, "issue", call_id="c", project="Own/two", outcome="discarded", outcome_recorded=True),
        _row(d, "comment", call_id="none", project="Own/two", outcome="accepted", outcome_recorded=False),
        _row(d, "digest-ci-log", call_id="e", project="none"),
        _row(d, "outcome", call_id="a", outcome="fact-error", outcome_recorded=True),
        _row("2026-11-17T10:00:00+00:00", "issue"),
    ]
    (env.state / "safo" / "local-share.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    code, out, _ = env.run(["--report"])
    assert code == 0
    assert "2026-W48: 5 calls, 0 failed" in out and "2026-W47: 1 calls" in out
    assert "outcomes of 4 drafts: accepted=1 (25%), rewritten=1 (25%), discarded=1 (25%), fact-error=1 (25%)" in out
    assert "outcome not recorded: 1 of 4 (25%)" in out
    assert "project Own/one: accepted=0 (0%), rewritten=1 (50%), discarded=0 (0%), fact-error=1 (50%)" in out
    assert "project Own/two: accepted=1 (50%), rewritten=0 (0%), discarded=1 (50%)" in out


def test_report_still_works_without_outcome_rows(env: Env) -> None:
    (env.state / "safo").mkdir(parents=True)
    (env.state / "safo" / "local-share.jsonl").write_text(json.dumps(_row("2026-11-26T10:00:00+00:00", "pr")) + "\n")
    code, out, _ = env.run(["--report"])
    assert code == 0 and "2026-W48: 1 calls" in out and "outcomes" not in out


def test_project_comes_from_repo_or_the_cwd_remote(env: Env, tmp_path: Path) -> None:
    repo = tmp_path / "work"
    for sub in ("objects", "refs"):
        (repo / ".git" / sub).mkdir(parents=True)
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (repo / ".git" / "config").write_text('[remote "origin"]\n\turl = git@github.com:Own/proj.git\n')
    env.env["PWD"] = str(repo)
    assert localdraft.project_of(env.env, None) == "Own/proj"
    assert localdraft.project_of(env.env, "a/b") == "a/b"
    assert localdraft.project_of(env.env, "not a repo; rm") == "none"
    env.env["PWD"] = str(tmp_path / "shim")
    assert localdraft.project_of(env.env, None) == "none"
    env.env["PWD"] = str(repo)
    _with_id(env)
    code, _, _ = env.run(["digest", "ci-log", "-"], stdin="Error: boom\n")
    row = env.metrics()[-1]
    assert code == 0 and row["project"] == "Own/proj" and row["call_id"] == "abc-1" and "outcome" not in row


def test_argparse_errors_go_to_the_caller_stderr(env: Env) -> None:
    """A parse error must land in the injected stream on every Python version, not the process stderr."""
    code, out, err = env.run(["--outcome", "abc-1"])
    assert code == localdraft.EXIT_ERROR and "--outcome" in err and out == ""
    assert _outcomes(env) == [] and env.metrics() == []
