# SPDX-License-Identifier: Apache-2.0
"""The outcomes log: validated records, one line each, and a monthly summary."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from safo import outcomes
from safo.errors import ConfigError

ROOT = Path(__file__).parent.parent
GOOD = {
    "date": "2026-10-07",
    "card": "https://github.com/acme/widgets/pull/9",
    "agent": "copilot",
    "shape": "small-mechanical-pr",
    "review_rounds": 2,
    "findings": {"important": 1},
    "tokens": None,
    "requests": 3,
    "note": "Needed fixes.",
}


def test_the_seed_file_validates_and_carries_the_measured_day() -> None:
    rows = outcomes.load(ROOT / "examples" / "outcomes-2026-10.jsonl")
    assert len(rows) == 9
    copilot = [r for r in rows if r.agent == "copilot"]
    assert len(copilot) == 4 and all(r.needed_fixes for r in copilot)
    assert any(r.finding_count and "important" in r.findings for r in copilot), "the functional bug its own test hid"
    local = next(r for r in rows if r.agent == "ollama")
    assert local.tokens == 436 and "50 tokens a second" in local.note
    assert any("14%" in r.note and "56%" in r.note and "27M" in r.note for r in rows)
    assert any(r.agent == "codex" and r.findings == {"unrated": 40} for r in rows)


def test_a_record_round_trips_as_one_line(tmp_path: Path) -> None:
    log = tmp_path / "o.jsonl"
    record = outcomes.validate(GOOD)
    outcomes.append(log, record)
    outcomes.append(log, record)
    assert len(log.read_text().splitlines()) == 2
    assert outcomes.load(log)[0] == record


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"date": "yesterday"}, "date: expected YYYY-MM-DD"),
        ({"card": "https://example.org/x"}, "card: expected a https://github.com"),
        ({"agent": ""}, "agent: expected a non-empty string"),
        ({"review_rounds": -1}, "review_rounds: expected an integer >= 0"),
        ({"review_rounds": True}, "review_rounds: expected an integer >= 0"),
        ({"findings": {"scary": 1}}, "findings: expected counts keyed by"),
        ({"tokens": "lots"}, "tokens: expected an integer >= 0 or null"),
        ({"note": "two\nlines"}, "note: expected one line of text"),
        ({"colour": "red"}, "colour: unknown key"),
    ],
)
def test_a_bad_record_names_the_key(change: dict[str, object], message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        outcomes.validate({**GOOD, **change})


def test_a_bad_record_never_reaches_the_file(tmp_path: Path) -> None:
    log = tmp_path / "o.jsonl"
    bad = outcomes.Outcome("2026-10-07", None, "codex", "research", -1)
    with pytest.raises(ConfigError):
        outcomes.append(log, bad)
    assert not log.exists()


def test_a_note_cannot_inject_a_second_record(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="one line"):
        outcomes.validate({**GOOD, "note": 'x"}\n{"agent": "forged'})


def test_load_names_the_line_of_a_corrupt_log(tmp_path: Path) -> None:
    log = tmp_path / "o.jsonl"
    log.write_text(json.dumps(GOOD) + "\nnot json\n")
    with pytest.raises(ConfigError, match=r"o.jsonl:2: not valid bounded JSON"):
        outcomes.load(log)


def test_findings_parse() -> None:
    assert outcomes.parse_findings("critical=0,important=2") == {"critical": 0, "important": 2}
    assert outcomes.parse_findings("") == {}
    with pytest.raises(ConfigError, match="severity"):
        outcomes.parse_findings("huge=1")


def test_the_summary_is_per_agent_for_one_month_only() -> None:
    rows = [
        outcomes.validate(GOOD),
        outcomes.validate({**GOOD, "review_rounds": 1, "findings": {}, "requests": 2}),
        outcomes.validate({**GOOD, "date": "2026-09-30", "agent": "codex"}),
    ]
    [summary] = outcomes.summarise(rows, "2026-10")
    assert (summary.agent, summary.tasks, summary.needed_fixes, summary.review_rounds) == ("copilot", 2, 1, 3)
    assert summary.findings == {"important": 1} and summary.requests == 5


FULLWIDTH_DATE = "".join(chr(0xFF10 + int(c)) if c.isdigit() else c for c in "2026-10-07")


@pytest.mark.parametrize("date", ["2026-13-01", "2026-10-07 10:00:00", "2026-10-07\n", FULLWIDTH_DATE, "2026-02-30"])
def test_outcome_dates_must_be_canonical(date: str) -> None:
    raw = {"date": date, "card": None, "agent": "codex", "shape": "research", "review_rounds": 1}
    with pytest.raises(ConfigError, match="YYYY-MM-DD"):
        outcomes.validate(raw)


@pytest.mark.parametrize("month", ["2026-1", "2026-13", "2026"])
def test_report_month_must_be_canonical(month: str) -> None:
    with pytest.raises(ConfigError, match="YYYY-MM"):
        outcomes.summarise([], month)


# -- hostile cases beyond the brief ----------------------------------------------------------------------------------


LINE_BREAKS = ["a\r b", "a" + chr(0x2028) + "b", "a" + chr(0x2029) + "b", "a\x85b", "a\x00b", "a\x1b[31mb", "a\x0bb"]


@pytest.mark.parametrize("text", [*LINE_BREAKS, "x" * 501])
def test_a_note_is_one_short_line_of_printable_text(text: str) -> None:
    with pytest.raises(ConfigError, match="note"):
        outcomes.validate({**GOOD, "note": text})


def test_an_empty_note_is_valid() -> None:
    assert outcomes.validate({**GOOD, "note": ""}).note == ""


FULLWIDTH_DATE = "".join(chr(0xFF10 + int(c)) if c.isdigit() else c for c in "2026-10-07")


@pytest.mark.parametrize("date", ["2026-13-01", "2026-10-07 10:00:00", "2026-10-07\n", FULLWIDTH_DATE, "2026-02-30"])
def test_impossible_and_non_ascii_dates_are_refused(date: str) -> None:
    with pytest.raises(ConfigError, match="YYYY-MM-DD"):
        outcomes.validate({**GOOD, "date": date})


@pytest.mark.parametrize(
    "card",
    [
        "https://google.com/search?q=safo",
        "https://github.com/acme/widgets/pull/9\n",
        "https://github.com/acme/widgets/pull/9?x=1",
        "http://github.com/acme/widgets/pull/9",
        "https://github.com/acme/widgets/pull/9 ",
    ],
)
def test_a_card_must_be_exactly_a_github_issue_or_pull_url(card: str) -> None:
    with pytest.raises(ConfigError, match="card"):
        outcomes.validate({**GOOD, "card": card})


@pytest.mark.parametrize("value", [1.5, "1", None, [1], 10**13])
def test_review_rounds_is_a_small_integer(value: object) -> None:
    with pytest.raises(ConfigError, match="review_rounds"):
        outcomes.validate({**GOOD, "review_rounds": value})


@pytest.mark.parametrize("key", ["tokens", "requests"])
@pytest.mark.parametrize("value", [-500, -1, 1.5, True, 10**13])
def test_token_and_request_counts_are_bounded_nonnegative_integers(key: str, value: object) -> None:
    with pytest.raises(ConfigError, match=key):
        outcomes.validate({**GOOD, key: value})


@pytest.mark.parametrize("agent", ["a b", "a\nb", "a;b", "x" * 65, "n\u00e9"])
def test_agent_and_shape_are_identifiers(agent: str) -> None:
    for key in ("agent", "shape"):
        with pytest.raises(ConfigError, match=key):
            outcomes.validate({**GOOD, key: agent})


@pytest.mark.parametrize(
    "text",
    [
        "critical=1,invalid=2",
        "critical=1,important=abc",
        "critical=-1",
        "critical=" + chr(0xB2),
        "critical=1,critical=2",
        "critical",
    ],
)
def test_findings_text_is_strict(text: str) -> None:
    with pytest.raises(ConfigError, match="findings"):
        outcomes.parse_findings(text)


def test_a_record_is_ascii_on_disk_so_no_unicode_line_break_can_split_it(tmp_path: Path) -> None:
    log = tmp_path / "o.jsonl"
    outcomes.append(log, outcomes.validate({**GOOD, "note": "caf\u00e9"}))
    assert log.read_bytes().isascii() and outcomes.load(log)[0].note == "caf\u00e9"


def test_append_refuses_a_symlinked_or_fifo_log_and_never_follows_it(tmp_path: Path) -> None:
    import os

    target = tmp_path / "victim.txt"
    target.write_text("keep\n")
    link = tmp_path / "o.jsonl"
    link.symlink_to(target)
    with pytest.raises(ConfigError, match="outcomes log"):
        outcomes.append(link, outcomes.validate(GOOD))
    assert target.read_text() == "keep\n"
    fifo = tmp_path / "fifo.jsonl"
    os.mkfifo(fifo)
    with pytest.raises(ConfigError, match="outcomes log"):
        outcomes.append(fifo, outcomes.validate(GOOD))
    with pytest.raises(ConfigError, match="outcomes log"):
        outcomes.load(fifo)
    with pytest.raises(ConfigError, match="outcomes log"):
        outcomes.load(link)


def test_a_log_without_a_final_newline_is_not_glued_to_the_next_record(tmp_path: Path) -> None:
    log = tmp_path / "o.jsonl"
    log.write_text(json.dumps(GOOD))
    outcomes.append(log, outcomes.validate(GOOD))
    assert len(outcomes.load(log)) == 2


def test_the_log_is_private_and_oversize_logs_are_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = tmp_path / "o.jsonl"
    outcomes.append(log, outcomes.validate(GOOD))
    assert (log.stat().st_mode & 0o777) == 0o600
    monkeypatch.setattr(outcomes, "MAX_LOG_BYTES", 10)
    with pytest.raises(ConfigError, match="outcomes log"):
        outcomes.load(log)
    with pytest.raises(ConfigError, match="outcomes log"):
        outcomes.append(log, outcomes.validate(GOOD))


def test_concurrent_appends_lose_nothing(tmp_path: Path) -> None:
    import threading

    log = tmp_path / "o.jsonl"
    record = outcomes.validate(GOOD)
    errors: list[Exception] = []

    def work() -> None:
        try:
            for _ in range(5):
                outcomes.append(log, record)
        except Exception as error:
            errors.append(error)

    threads = [threading.Thread(target=work) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors and len(outcomes.load(log)) == 20


# ---- model and credits_used (issue #23, item 3) ----

OLD_LINE = (ROOT / "examples" / "outcomes-2026-10.jsonl").read_text().splitlines()[0]


def test_old_lines_without_the_new_fields_validate_and_round_trip_byte_stable() -> None:
    record = outcomes.validate(json.loads(OLD_LINE))
    assert record.model is None and record.credits_used is None
    assert record.to_json() == OLD_LINE, "unset new fields add no keys"


def test_model_and_credits_round_trip_when_set(tmp_path: Path) -> None:
    record = outcomes.validate({**GOOD, "model": "claude-sonnet-5-5", "credits_used": 7})
    assert (record.model, record.credits_used) == ("claude-sonnet-5-5", 7)
    log = tmp_path / "o.jsonl"
    outcomes.append(log, record)
    assert outcomes.load(log) == [record]
    assert json.loads(log.read_text())["credits_used"] == 7


def test_null_model_and_credits_are_accepted_as_unknown() -> None:
    record = outcomes.validate({**GOOD, "model": None, "credits_used": None})
    assert record.model is None and record.credits_used is None


@pytest.mark.parametrize("model", ["gpt-5.4", "claude-sonnet-5-5", "a", "x" * 64, "Llama_3.1-8B"])
def test_good_model_names(model: str) -> None:
    assert outcomes.validate({**GOOD, "model": model}).model == model


@pytest.mark.parametrize(
    "model",
    [
        "", "two words", "line\nbreak", "line\rbreak", "tab\there", "sep\u2028arator", "para\u2029graph", "nel\x85x",
        "nul\x00", "caf\u00e9", "\uff47pt", "x" * 65, ".leading-dot", "-dash", "a/b", "a;b", 'q"uote', 5, 1.5, True,
        ["a"], {"a": 1},
    ],
)  # fmt: skip
def test_hostile_model_is_refused(model: object) -> None:
    with pytest.raises(ConfigError, match="model: expected"):
        outcomes.validate({**GOOD, "model": model})


@pytest.mark.parametrize("credits", [0, 1, 10**12])
def test_good_credits(credits: int) -> None:
    assert outcomes.validate({**GOOD, "credits_used": credits}).credits_used == credits


@pytest.mark.parametrize("credits", [-1, 1.5, 2.0, True, False, "3", "", 10**12 + 1, 10**30, [1], {"n": 1}])
def test_hostile_credits_are_refused(credits: object) -> None:
    with pytest.raises(ConfigError, match="credits_used: expected an integer >= 0 or null"):
        outcomes.validate({**GOOD, "credits_used": credits})


def test_a_hostile_model_loaded_from_a_log_names_the_line(tmp_path: Path) -> None:
    log = tmp_path / "o.jsonl"
    log.write_text(json.dumps({**GOOD, "model": "ok"}) + "\n" + json.dumps({**GOOD, "model": "bad model"}) + "\n")
    with pytest.raises(ConfigError, match=r"o.jsonl:2.model: expected"):
        outcomes.load(log)


def test_a_bad_model_never_reaches_the_file(tmp_path: Path) -> None:
    log = tmp_path / "o.jsonl"
    bad = outcomes.Outcome("2026-10-07", None, "codex", "research", 1, model="x\ny")
    with pytest.raises(ConfigError):
        outcomes.append(log, bad)
    assert not log.exists()


def test_unknown_keys_still_fail_next_to_the_new_ones() -> None:
    with pytest.raises(ConfigError, match="credits: unknown key"):
        outcomes.validate({**GOOD, "model": "m", "credits": 1})


def _row(
    agent: str, model: str | None, rounds: int, credits: int | None, findings: dict[str, int] | None = None
) -> outcomes.Outcome:
    return outcomes.validate(
        {**GOOD, "agent": agent, "model": model, "credits_used": credits, "review_rounds": rounds,
         "findings": findings or {}}
    )  # fmt: skip


def test_model_summary_groups_by_agent_and_model_and_never_divides_by_zero() -> None:
    rows = [
        _row("copilot", "gpt-5.4", 1, 10),
        _row("copilot", "gpt-5.4", 3, 30, {"important": 2, "minor": 1}),
        _row("copilot", "gpt-5.4", 1, None),
        _row("copilot", None, 1, None),
        _row("codex", "gpt-5.4", 0, 4),
        _row("copilot", "claude-sonnet-5-5", 2, 6, {"critical": 1}),
        outcomes.validate({**GOOD, "date": "2026-09-01", "agent": "codex"}),
    ]
    got = outcomes.summarise_models(rows, "2026-10")
    assert [(m.agent, m.model) for m in got] == [
        ("codex", "gpt-5.4"),
        ("copilot", "claude-sonnet-5-5"),
        ("copilot", "gpt-5.4"),
        ("copilot", "unknown"),
    ]
    codex, sonnet, gpt, unknown = got
    assert (gpt.runs, gpt.review_rounds, gpt.needed_fixes) == (3, 5, 1)
    assert gpt.rounds_per_run == pytest.approx(5 / 3) and gpt.fix_share == pytest.approx(1 / 3)
    assert gpt.findings == {"important": 2, "minor": 1}
    assert (gpt.credits_total, gpt.credits_known) == (40, 2)
    assert gpt.credits_per_run == 20 and gpt.credits_per_clean_run == 10 and gpt.credits_per_fixed_run == 30
    assert unknown.credits_total == 0 and unknown.credits_known == 0
    assert unknown.credits_per_run is None and unknown.credits_per_clean_run is None
    assert unknown.credits_per_fixed_run is None
    assert codex.credits_per_fixed_run is None and codex.credits_per_clean_run == 4
    assert sonnet.credits_per_clean_run is None and sonnet.credits_per_fixed_run == 6


def test_model_summary_is_deterministic_under_input_order() -> None:
    rows = [_row("b", "m2", 1, 1), _row("a", "m1", 1, 2), _row("a", None, 1, None), _row("b", "m1", 1, 3)]
    assert outcomes.summarise_models(rows, "2026-10") == outcomes.summarise_models(rows[::-1], "2026-10")
    assert outcomes.summarise_models([], "2026-10") == []
    with pytest.raises(ConfigError, match="YYYY-MM"):
        outcomes.summarise_models([], "2026-1")
