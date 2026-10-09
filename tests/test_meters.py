# SPDX-License-Identifier: MIT
"""The local meters, against synthetic files under a temporary home. Never the real home directory."""

from __future__ import annotations

import datetime as dt
import json
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from meterdata import NOW, assistant, claude_transcript, codex_session, token_count, touch
from safo.meters.claude import family_of, read_claude_usage
from safo.meters.codex import read_codex_usage
from safo.meters.copilot import read_copilot_usage

SINCE = NOW - dt.timedelta(days=7)
SRC = Path(__file__).parent.parent / "src" / "safo"


def test_codex_windows_plan_and_session_tokens(_private_home: Path) -> None:
    codex_session(
        _private_home,
        "a",
        [
            {"type": "session_meta", "payload": {"cwd": "/work/widgets"}},
            token_count(20, 5, tokens=1000),
            token_count(56, 14, tokens=27_000),
        ],
    )
    usage = read_codex_usage(_private_home, SINCE, NOW)
    assert usage.found and usage.plan == "plus"
    assert (usage.five_hour_percent, usage.weekly_percent) == (56.0, 14.0)
    assert usage.sessions[0].cwd == "widgets" and usage.sessions[0].input_tokens == 27_000
    assert usage.input_tokens == 27_000


def test_the_newest_session_wins_and_old_sessions_are_outside_the_window(_private_home: Path) -> None:
    codex_session(_private_home, "old", [token_count(90, 90)], age_hours=24 * 30)
    codex_session(_private_home, "mid", [token_count(10, 3)], age_hours=5)
    codex_session(_private_home, "new", [token_count(33, 7)], age_hours=1)
    usage = read_codex_usage(_private_home, SINCE, NOW)
    assert [s.name for s in usage.sessions] == ["mid", "new"]
    assert usage.five_hour_percent == 33.0


def test_a_half_written_last_line_is_skipped_not_an_error(_private_home: Path) -> None:
    codex_session(
        _private_home, "live", [token_count(40, 8)], raw_tail='{"type": "event_msg", "payload": {"type": "tok'
    )
    usage = read_codex_usage(_private_home, SINCE, NOW)
    assert usage.five_hour_percent == 40.0 and usage.unreadable_files == 0


def test_a_window_that_has_already_reset_is_unknown_not_stale(_private_home: Path) -> None:
    codex_session(_private_home, "old", [token_count(95, 40, resets_in_hours=-2)])
    usage = read_codex_usage(_private_home, SINCE, NOW)
    assert usage.five_hour_percent is None and usage.five_hour_resets_at is not None
    assert usage.weekly_percent == 40.0, "the weekly window resets a day later and is still live"


def test_no_codex_directory_is_not_found_not_zero(_private_home: Path) -> None:
    usage = read_codex_usage(_private_home, SINCE, NOW)
    assert not usage.found and usage.five_hour_percent is None


def test_claude_usage_per_family_with_subagent_transcripts_and_duplicate_rows_collapsed(_private_home: Path) -> None:
    lead = [
        assistant("m1", "claude-opus-4", 100),
        assistant("m1", "claude-opus-4", 250),  # the same reply, written again with its final output count
        assistant("m2", "claude-sonnet-4", 40, cache_read=500),
        {"type": "user", "message": {"role": "user", "content": "hi"}},
        assistant("m3", "<synthetic>", 1),
    ]
    sub = [assistant("s1", "claude-haiku-4", 7), assistant("s2", "claude-sonnet-4", 60)]
    claude_transcript(_private_home, "proj-a/session.jsonl", lead)
    claude_transcript(_private_home, "proj-a/session/subagents/agent-1.jsonl", sub)
    usage = read_claude_usage(_private_home, SINCE)
    fam = usage.by_family
    assert usage.found and usage.files == 2
    assert (fam["opus"].messages, fam["opus"].output_tokens) == (1, 250)
    assert (fam["sonnet"].messages, fam["sonnet"].output_tokens, fam["sonnet"].cache_read_tokens) == (2, 100, 500)
    assert fam["haiku"].messages == 1 and "other" not in fam


def test_claude_rows_before_the_window_are_left_out_and_bad_lines_skipped(_private_home: Path) -> None:
    path = claude_transcript(
        _private_home,
        "p/s.jsonl",
        [assistant("old", "claude-sonnet-4", 999, when_hours_ago=24 * 30), assistant("new", "claude-sonnet-4", 5)],
    )
    path.write_text(path.read_text() + "not json\n")
    touch(path, 1)
    usage = read_claude_usage(_private_home, SINCE)
    assert usage.by_family["sonnet"].output_tokens == 5


def test_family_of() -> None:
    assert [family_of(m) for m in ("claude-opus-4-1", "Claude-Sonnet-5", "claude-haiku-4", "gpt-5")] == [
        "opus",
        "sonnet",
        "haiku",
        "other",
    ]


def runner(outputs: dict[tuple[str, ...], tuple[int, str]]) -> Callable[..., SimpleNamespace]:
    def run(argv: list[str], **_: object) -> SimpleNamespace:
        code, out = outputs.get(tuple(argv[1:]), (1, ""))
        return SimpleNamespace(returncode=code, stdout=out)

    return run


def test_copilot_sessions_this_month_from_dated_lines() -> None:
    listing = "task a  2026-10-03T10:00:00Z  done\ntask b  2026-10-06  done\ntask c  2026-09-28  done\n"
    run = runner({("agent-task", "list", "-L", "200"): (0, listing)})
    usage = read_copilot_usage(run, lambda name: "/usr/bin/gh", "2026-10", billing=False, allowance=300)
    assert usage.available and usage.sessions == 2 and usage.sessions_exact
    assert usage.premium_requests is None and usage.monthly_percent is None


def test_a_listing_with_no_dates_counts_everything_and_says_it_is_not_exact() -> None:
    run = runner({("agent-task", "list", "-L", "200"): (0, "task a  about 3 days ago\ntask b  about 1 hour ago\n")})
    usage = read_copilot_usage(run, lambda name: "gh", "2026-10", billing=False, allowance=None)
    assert usage.sessions == 2 and not usage.sessions_exact


def test_billing_is_read_only_when_asked_and_a_refusal_is_unknown_not_a_guess() -> None:
    body = json.dumps(
        {
            "usageItems": [
                {
                    "product": "GitHub Copilot",
                    "sku": "Copilot premium requests",
                    "unitType": "premium_requests",
                    "grossQuantity": 120.5,
                },
                {"product": "Actions", "grossQuantity": 9},
            ]
        }
    )
    ok = runner(
        {
            ("agent-task", "list", "-L", "200"): (0, ""),
            ("api", "user", "--jq", ".login"): (0, "someone\n"),
            ("api", "/users/someone/settings/billing/premium_request/usage?year=2026&month=10"): (0, body),
        }
    )
    usage = read_copilot_usage(ok, lambda name: "gh", "2026-10", billing=True, allowance=300)
    assert usage.premium_requests == 120.5 and usage.monthly_percent is None
    refused = runner(
        {("agent-task", "list", "-L", "200"): (0, ""), ("api", "user", "--jq", ".login"): (0, "someone\n")}
    )
    usage = read_copilot_usage(refused, lambda name: "gh", "2026-10", billing=True, allowance=300)
    assert usage.premium_requests is None and usage.monthly_percent is None


def test_without_gh_copilot_is_unavailable_and_nothing_is_run() -> None:
    def boom(*a: object, **k: object) -> None:
        raise AssertionError("must not run")

    usage = read_copilot_usage(boom, lambda name: None, "2026-10", billing=True, allowance=300)
    assert not usage.available and usage.sessions is None


def test_a_failing_gh_is_unknown() -> None:
    run = runner({})
    usage = read_copilot_usage(run, lambda name: "gh", "2026-10", billing=False, allowance=300)
    assert usage.available and usage.sessions is None


def test_the_readers_never_look_up_the_real_home_directory() -> None:
    for path in (SRC / "meters").glob("*.py"):
        text = path.read_text()
        assert "Path.home" not in text and "expanduser" not in text and "os.path.expanduser" not in text, path.name
        assert "urllib" not in text and "socket" not in text, f"{path.name} must make no network call of its own"


@pytest.mark.parametrize(
    "raw",
    [
        "x" * 16_777_217,
        '{"payload":' + "[" * 65 + "0" + "]" * 65 + "}",
        json.dumps(
            {"payload": {"type": "token_count", "info": {"total_token_usage": {"input_tokens": "sentinel-credential"}}}}
        ),
        '{"payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":NaN}}}}',
    ],
)
def test_codex_untrusted_transcript_is_bounded_and_controlled(_private_home: Path, raw: str) -> None:
    path = codex_session(_private_home, "bad", [])
    path.write_text(raw + "\n")
    usage = read_codex_usage(_private_home, SINCE, NOW)
    assert usage.input_tokens == 0 and usage.five_hour_percent is None


@pytest.mark.parametrize(
    "row",
    [
        {
            "product": "Other copilot product",
            "sku": "Copilot premium requests",
            "unitType": "premium_requests",
            "grossQuantity": 99,
        },
        {"product": "GitHub Copilot", "sku": "Other", "unitType": "premium_requests", "grossQuantity": 99},
        {"product": "GitHub Copilot", "sku": "Copilot premium requests", "unitType": "ai_credits", "grossQuantity": 99},
        {
            "product": "GitHub Copilot",
            "sku": "Copilot premium requests",
            "unitType": "premium_requests",
            "grossQuantity": "bad",
        },
    ],
)
def test_billing_products_units_and_quantities_cannot_be_assumed_equivalent(row: dict[str, Any]) -> None:
    from safo.meters.copilot import _premium_requests

    body = json.dumps({"usageItems": [row]})
    assert _premium_requests(body) in (None, 0.0)
    run = runner(
        {
            ("api", "user", "--jq", ".login"): (0, "someone"),
            ("api", "/users/someone/settings/billing/premium_request/usage?year=2026&month=10"): (0, body),
        }
    )
    reading = read_copilot_usage(run, lambda name: "gh", "2026-10", billing=True, allowance=7000)
    assert reading.monthly_percent is None


def test_codex_non_numeric_token_values_mark_the_file_unreadable(_private_home: Path) -> None:
    for name, value in (("text", "100_some_text"), ("huge", 10**400), ("negative", -5), ("float", 1.5)):
        path = codex_session(_private_home, name, [])
        raw = '{"payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":%s}}}}'
        path.write_text(raw % (json.dumps(value) if not isinstance(value, int) or value < 10**300 else "1" + "0" * 400))
    usage = read_codex_usage(_private_home, SINCE, NOW)
    assert usage.unreadable_files == 4 and usage.sessions == ()


def test_codex_nan_literal_is_a_skipped_line_not_a_counted_value(_private_home: Path) -> None:
    path = codex_session(_private_home, "nan", [token_count(10, 2, tokens=500)])
    path.write_text(
        path.read_text() + '{"payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":NaN}}}}\n'
    )
    usage = read_codex_usage(_private_home, SINCE, NOW)
    assert usage.input_tokens == 500 and usage.unreadable_files == 0


def test_codex_window_edges(_private_home: Path) -> None:
    codex_session(_private_home, "a", [token_count(100, 101)])
    usage = read_codex_usage(_private_home, SINCE, NOW)
    assert usage.five_hour_percent == 100.0 and usage.weekly_percent is None, "over 100% is not a reading"
    assert read_codex_usage(_private_home, NOW, NOW).sessions == (), "a file older than the window is left out"


@pytest.mark.parametrize("model", ["<synthetic>", "<something>", "", "<internal-model>"])
def test_claude_synthetic_and_blank_model_names_are_ignored(_private_home: Path, model: str) -> None:
    claude_transcript(_private_home, "p/s.jsonl", [assistant("m1", model, 99), assistant("m2", "claude-haiku-4", 3)])
    usage = read_claude_usage(_private_home, SINCE)
    assert list(usage.by_family) == ["haiku"] and usage.by_family["haiku"].output_tokens == 3


def test_claude_duplicate_ids_keep_the_largest_output_in_either_order(_private_home: Path) -> None:
    for order in ((250, 100), (100, 250)):
        rows = [assistant("same", "claude-sonnet-4", n) for n in order]
        path = claude_transcript(_private_home, "p/order.jsonl", rows)
        assert read_claude_usage(_private_home, SINCE).by_family["sonnet"].output_tokens == 250
        path.unlink()


def test_claude_bad_usage_values_skip_the_row(_private_home: Path) -> None:
    bad = assistant("b", "claude-sonnet-4", 1)
    bad["message"]["usage"]["output_tokens"] = "sentinel-credential"
    claude_transcript(_private_home, "p/s.jsonl", [bad, assistant("ok", "claude-sonnet-4", 4)])
    assert read_claude_usage(_private_home, SINCE).by_family["sonnet"].output_tokens == 4


def test_copilot_only_this_months_dated_lines_count_across_formats() -> None:
    listing = "a 2026-10-01\nb 2026-10-31T23:59:59Z\nc 2026-11-01\nd 2025-10-05\ne 12026-10-05\n"
    run = runner({("agent-task", "list", "-L", "200"): (0, listing)})
    usage = read_copilot_usage(run, lambda name: "gh", "2026-10", billing=False, allowance=None)
    assert usage.sessions == 2 and usage.sessions_exact


def test_copilot_a_gh_that_hangs_or_dies_is_unknown_and_gh_gets_no_stdin() -> None:
    import subprocess

    def hang(argv: list[str], **_: object) -> SimpleNamespace:
        raise subprocess.TimeoutExpired(argv, 30)

    usage = read_copilot_usage(hang, lambda name: "gh", "2026-10", billing=True, allowance=None)
    assert usage.available and usage.sessions is None and usage.premium_requests is None
    seen: dict[str, Any] = {}

    def spy(argv: list[str], **kw: Any) -> SimpleNamespace:
        seen.update(kw)
        return SimpleNamespace(returncode=0, stdout="")

    read_copilot_usage(spy, lambda name: "gh", "2026-10", billing=False, allowance=None)
    assert seen["stdin"] == subprocess.DEVNULL


def test_a_billing_login_that_is_not_a_login_is_never_put_in_a_path() -> None:
    called: list[tuple[str, ...]] = []

    def run(argv: list[str], **_: object) -> SimpleNamespace:
        called.append(tuple(argv[1:]))
        return SimpleNamespace(returncode=0, stdout="../../evil?x=1\n" if argv[1:3] == ["api", "user"] else "")

    reading = read_copilot_usage(run, lambda name: "gh", "2026-10", billing=True, allowance=None)
    assert reading.premium_requests is None
    assert not any("evil" in part for call in called for part in call)
