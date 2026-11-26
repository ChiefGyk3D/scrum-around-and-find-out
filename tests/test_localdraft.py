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
    assert any("unusual character" in x for x in _why(text)), repr(text)
    assert any("unusual character" in x for x in localdraft.check_title(text)), repr(text)


def test_r4b1_ordinary_text_with_accents_and_emoji_passes() -> None:
    assert _why("Caf\u00e9 na\u00efve, tab\there\r\nline two") == []
    assert _why("Cafe\u0301 decomposed composes under NFKC") == []
    assert localdraft.check_text("pr", f"Body\n\n{FOOTER}") == []
    assert _why("done \u2705 \U0001f916") == []


def test_r4b1_exotic_draft_is_never_filed_even_with_yes(env: Env) -> None:
    (env.dir / "llm.reply").write_text("de W1\u0301AW\n\nPart of epic #445")
    code, out, _ = env.run(["issue", "--repo", "o/r", "--title", "T", "--yes", "x"])
    assert code == localdraft.EXIT_REFUSED and "unusual character" in out
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
    assert any("HTML is not allowed in drafts; use plain markdown" in x for x in _why(text)), text
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
    example = Path(localdraft.__file__).parents[2] / "docs" / "draft-allow.example.txt"
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
