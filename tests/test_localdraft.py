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
        "N0CALL and N0TST and K1ABC",
        "grid FN31pr and fn31PR",
        "the K8S cluster, P2P and E2E",
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


def test_f1_ordinary_entities_still_pass() -> None:
    assert localdraft.check_text("comment", "a &amp; b, 1 &lt; 2, R&amp;D", deny=["Acmecorp"]) == []


def test_f1_canonicalize_is_bounded_and_idempotent_on_plain_text() -> None:
    assert localdraft.canonicalize("plain text") == "plain text"
    assert localdraft.canonicalize("&amp;amp;amp;amp;#46;").count("#46") >= 0  # terminates after 3 rounds


@pytest.mark.parametrize("text", ["w1aw", "W1AW", "em48", "EM48", "fn31pq", "call w1aw/p", "x em48."])
def test_f2_bare_callsign_and_four_char_grid_blocked(text: str) -> None:
    why = localdraft.check_text("comment", text)
    assert any("callsign" in x or "grid" in x for x in why), text


@pytest.mark.parametrize(
    "text",
    [
        "N0CALL N0TST K1ABC FN31pr fn31",
        "K8S k8s P2P b2b E2E a2a M2M H2O h2o",
        "commit 3f786850e387550fdab836ed7e6dc881de23001b",
        "id 123e4567-e89b-12d3-a456-426614174000",
        "id ab12-cd34-ef56 and w1aw_x and my-w1aw-x",
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


def test_f4_checks_are_linear() -> None:
    import time

    for text in ("a." * 32000, "a." * 31990 + "invalid", "http://" * 9000, "\n" * 30000, "a:" * 32000, "<!--" * 16000):
        start = time.perf_counter()
        localdraft.check_text("comment", text)
        localdraft.check_draft("issue", text, text)
        assert time.perf_counter() - start < 1.0, text[:12]


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
def test_s1_hyphen_then_letter_or_longer_stays_a_longer_token(text: str) -> None:
    assert not any("callsign" in x for x in localdraft.check_text("comment", text)), text


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
