# SPDX-License-Identifier: MIT
"""Duplicate JSON keys are refused at every nesting level, by the shared loader and by each caller of it."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from meterdata import NOW, assistant, claude_transcript, codex_session, token_count
from safo import bounded, hooks, outcomes
from safo.agents import _rows
from safo.errors import ConfigError
from safo.meters.claude import read_claude_usage
from safo.meters.codex import read_codex_usage
from safo.modes.hooks import read_settings
from safo.modes.sync import read_event

SINCE = NOW - dt.timedelta(days=7)
GOOD = {
    "date": "2026-10-07",
    "card": "https://github.com/acme/widgets/pull/9",
    "agent": "codex",
    "shape": "small-mechanical-pr",
    "review_rounds": 1,
    "findings": {"important": 1},
}
TOP = '{"agent": "codex", "agent": "x"}'
NESTED = '{"a": {"b": [1, {"k": 1, "k": 2}]}}'


@pytest.mark.parametrize("text", [TOP, NESTED, '{"a": 1, "a": 1}', '[{"x": 1, "x": 2}]'])
def test_loads_refuses_a_repeated_key_at_any_depth(text: str) -> None:
    with pytest.raises(bounded.DuplicateKeyError):
        bounded.loads(text)
    with pytest.raises(bounded.DuplicateKeyError):
        bounded.loads(text.encode())


def test_the_error_names_the_key_and_never_a_value_or_a_huge_key() -> None:
    with pytest.raises(ValueError, match="'agent'") as err:
        bounded.loads('{"agent": "SECRET-VALUE", "agent": "x"}')
    assert "SECRET-VALUE" not in str(err.value)
    big = "k" * 5000
    with pytest.raises(ValueError) as err2:
        bounded.loads(json.dumps({"x": 1}).replace('"x": 1', f'"{big}": 1, "{big}": 2'))
    assert len(str(err2.value)) < 200


def test_distinct_and_equal_looking_keys_still_load() -> None:
    assert bounded.loads('{"a": {"a": 1}, "b": [{"a": 1}, {"a": 2}]}') == {"a": {"a": 1}, "b": [{"a": 1}, {"a": 2}]}


def test_outcomes_log_line_with_a_repeated_top_level_key_is_refused(tmp_path: Path) -> None:
    log = tmp_path / "o.jsonl"
    log.write_text(json.dumps(GOOD)[:-1] + ', "agent": "x"}\n')
    with pytest.raises(ConfigError, match=r"o\.jsonl:1.*duplicate.*'agent'"):
        outcomes.load(log)


def test_outcomes_log_line_with_a_repeated_key_inside_findings_is_refused(tmp_path: Path) -> None:
    log = tmp_path / "o.jsonl"
    line = json.dumps(GOOD).replace('{"important": 1}', '{"important": 1, "important": 9}')
    log.write_text(line + "\n")
    with pytest.raises(ConfigError, match=r"duplicate.*'important'"):
        outcomes.load(log)


def test_outcomes_log_line_with_a_nested_repeat_deeper_in_an_unknown_field_is_refused(tmp_path: Path) -> None:
    log = tmp_path / "o.jsonl"
    log.write_text(json.dumps(GOOD)[:-1] + ', "extra": {"q": [{"z": 1, "z": 2}]}}\n')
    with pytest.raises(ConfigError, match=r"duplicate.*'z'"):
        outcomes.load(log)


def test_a_claude_transcript_line_with_a_repeated_key_is_skipped_like_other_bad_lines(_private_home: Path) -> None:
    path = claude_transcript(_private_home, "p/s.jsonl", [assistant("m1", "claude-sonnet-4", 5)])
    dup = json.dumps(assistant("m2", "claude-sonnet-4", 7)).replace('"type": "assistant"', '"type": "a", "type": "b"')
    path.write_text(path.read_text() + dup + "\n")
    usage = read_claude_usage(_private_home, SINCE)
    assert usage.by_family["sonnet"].output_tokens == 5 and usage.by_family["sonnet"].messages == 1


def test_a_codex_session_line_with_a_repeated_key_is_skipped_not_counted(_private_home: Path) -> None:
    path = codex_session(_private_home, "dup", [token_count(10, 2, tokens=500)])
    dup = json.dumps(token_count(90, 90, tokens=9000)).replace(
        '"type": "event_msg"', '"type": "x", "type": "event_msg"'
    )
    path.write_text(path.read_text() + dup + "\n")
    usage = read_codex_usage(_private_home, SINCE, NOW)
    assert usage.input_tokens == 500 and usage.unreadable_files == 0


def test_agents_hook_session_rows_skip_a_line_with_a_repeated_key(tmp_path: Path) -> None:
    path = tmp_path / "s.jsonl"
    path.write_text('{"a": 1}\n{"a": 1, "a": 2}\n{"a": 3}\n')
    assert list(_rows(path)) == [{"a": 1}, {"a": 3}]


def test_json_lines_marks_a_repeated_key_row_as_unparsed(tmp_path: Path) -> None:
    path = tmp_path / "s.jsonl"
    path.write_text('{"a": 1, "a": 2}\n{"a": 3}\n')
    assert bounded.json_lines(path) == [(1, None), (2, {"a": 3})]


def test_read_json_refuses_a_repeated_key(tmp_path: Path) -> None:
    path = tmp_path / "c.json"
    path.write_text('{"product": "x", "product": "GitHub Copilot"}')
    with pytest.raises(ValueError, match="duplicate"):
        bounded.read_json(path)


def test_probe_state_with_a_repeated_key_is_not_trusted(tmp_path: Path) -> None:
    folder = tmp_path / "state"
    folder.mkdir(mode=0o700)
    path = folder / "state.json"
    path.write_text(json.dumps({"reachable": True, "ts": 1.0}))
    assert hooks.read_state(path) is not None
    path.write_text('{"reachable": false, "reachable": true, "ts": 1.0}')
    assert hooks.read_state(path) is None


def test_settings_with_a_repeated_key_are_refused_not_merged(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text('{"hooks": {}, "hooks": {"x": 1}}')
    with pytest.raises(ConfigError, match="invalid JSON"):
        read_settings(path)


def test_an_event_payload_with_a_repeated_key_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "e.json"
    path.write_text('{"action": "opened", "action": "closed"}')
    with pytest.raises(ConfigError, match="cannot read the event payload"):
        read_event(str(path))


def test_the_guard_log_skips_a_line_with_a_repeated_key(tmp_path: Path) -> None:
    from safo import guardlog

    folder = tmp_path / "state"
    folder.mkdir(mode=0o700)
    log = folder / "log.jsonl"
    record = hooks.log_record("2026-10-07T12:00:00", "deny", sorted(guardlog.MODES)[0], None, True)
    good = json.dumps(record)
    assert guardlog.valid_record(record)
    log.write_text(good + "\n" + good[:-1] + ', "decision": "allow"}\n')
    assert guardlog.read_log(log) == [record]


def test_no_source_file_calls_json_loads_on_a_file_or_response_it_does_not_own() -> None:
    """The only `json.loads` left in src/ parse text this program just produced or a GitHub API response."""
    root = Path(__file__).parent.parent / "src" / "safo"
    found = sorted(
        f"{p.relative_to(root)}"
        for p in root.rglob("*.py")
        if p.name != "bounded.py" and "json.loads(" in p.read_text()
    )
    assert found == ["graphql.py", "modes/hooks.py", "modes/outcome.py", "outcomes.py"]
