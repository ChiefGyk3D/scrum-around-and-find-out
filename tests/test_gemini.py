# SPDX-License-Identifier: Apache-2.0
"""The Gemini wrapper (#200): free-tier limits, the ledger, the transport (the paid path is the broker's, #287).

Hermetic: a fake Gemini on loopback, a temporary ledger and config, a fake key. Every check that protects money has a
test that fails when the check is removed.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import os
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

from geminidata import (
    FAKE_KEY,
    IMAGE_MODEL,
    MODEL,
    NOW,
    FakeGemini,
    config_dict,
    hard_timeout,
    ledger_rows,
    minutes_ago,
    pathological,
    seed,
    start_row,
    write_config,
)
from safo.errors import ConfigError
from safo.gemini import (
    GeminiConfig,
    Ledger,
    Locations,
    OutcomeUnknownError,
    RateLimitStopError,
    RefusedError,
    Request,
    ask,
    doppler_key_provider,
    load_config,
    quota_line,
)
from safo.gemini import fixed_locations as real_fixed_locations  # bound before the autouse seam replaces it


@pytest.fixture
def server() -> Iterator[FakeGemini]:
    with FakeGemini().serve() as fake:
        yield fake


@pytest.fixture
def ledger(tmp_path: Path) -> Path:
    return tmp_path / "data" / "ledger.jsonl"


@pytest.fixture
def cfg(tmp_path: Path, server: FakeGemini, ledger: Path) -> GeminiConfig:
    return load_config(write_config(tmp_path / "gemini.yaml", server.url, ledger))


class Keys:
    """A key provider that records which tier was asked for, so a test can prove a paid key was never asked for."""

    def __init__(self) -> None:
        self.asked: list[str] = []

    def __call__(self, tier: str) -> str:
        self.asked.append(tier)
        return FAKE_KEY


def free(prompt: str = "What changed in the CVE list?", **kw: Any) -> Request:
    return Request(**{"model": MODEL, "prompt": prompt, "tier": "free", **kw})


# -- configuration -------------------------------------------------------------------------------------------------


def test_the_config_loads_with_its_free_limits_and_no_paid_setting(cfg: GeminiConfig) -> None:
    assert cfg.free[MODEL].rpm == 3 and cfg.image_models == frozenset({IMAGE_MODEL})
    assert not hasattr(cfg, "paid_config") and not hasattr(cfg, "prices") and not hasattr(cfg, "signing_key")


@pytest.mark.parametrize(
    "extra",
    [
        {"caps": {"job_usd": 2}},
        {"paid": {MODEL: {"input_per_mtok": 1, "output_per_mtok": 2, "valid_through": "2026-12-31"}}},
        {"signing": {"key": "/x", "principal": "p"}},
        {"price_source": "https://example.com"},
    ],
)
def test_the_settings_that_belonged_to_the_in_process_paid_path_are_refused(
    tmp_path: Path, ledger: Path, extra: dict[str, Any]
) -> None:
    path = tmp_path / "c.yaml"
    path.write_text(yaml.safe_dump(config_dict("http://127.0.0.1:9", ledger, **extra)))
    with pytest.raises(ConfigError):
        load_config(path)


def test_the_free_limits_are_supplied_never_guessed(tmp_path: Path, ledger: Path) -> None:
    data = config_dict("http://127.0.0.1:9", ledger)
    data["free"] = {MODEL: {"rpm": 3}}
    path = tmp_path / "c.yaml"
    path.write_text(yaml.safe_dump(data))
    with pytest.raises(ConfigError, match="rpd"):
        load_config(path)


@pytest.mark.parametrize("endpoint", ["http://example.com", "https://example.com", "http://10.0.0.5:8080", "ftp://x"])
def test_the_key_only_goes_to_the_vendor_or_loopback(tmp_path: Path, ledger: Path, endpoint: str) -> None:
    path = tmp_path / "c.yaml"
    path.write_text(yaml.safe_dump(config_dict(endpoint, ledger)))
    with pytest.raises(ConfigError, match="endpoint"):
        load_config(path)


def test_the_vendor_endpoint_is_accepted(tmp_path: Path, ledger: Path) -> None:
    path = tmp_path / "c.yaml"
    path.write_text(yaml.safe_dump(config_dict("https://generativelanguage.googleapis.com", ledger)))
    assert load_config(path).endpoint == "https://generativelanguage.googleapis.com"


def test_a_duplicate_key_and_an_alias_are_refused(tmp_path: Path) -> None:
    dup = tmp_path / "d.yaml"
    dup.write_text("version: 1\nversion: 1\n")
    alias = tmp_path / "a.yaml"
    alias.write_text("version: &a 1\nendpoint: *a\n")
    for path in (dup, alias):
        with pytest.raises(ConfigError):
            load_config(path)


# -- the quota line ------------------------------------------------------------------------------------------------


def test_the_free_quota_line_says_used_of_limit_window_and_reset(cfg: GeminiConfig) -> None:
    seed(cfg.ledger, start_row(minutes_ago(0.5), call_id="a") + start_row(minutes_ago(100), call_id="b", tokens=40))
    line = quota_line(cfg, free(), NOW)
    assert line.startswith(f"QUOTA free {MODEL}:")
    assert "requests per minute 1 of 3" in line
    assert "requests per day 2 of 5" in line
    assert "input tokens per minute 10 of 1000" in line
    assert "resets 2026-10-30T00:00-07:00" in line and "midnight Pacific" in line


def test_a_free_line_cannot_be_made_without_the_maintainers_numbers(cfg: GeminiConfig) -> None:
    other = dataclasses.replace(cfg, free={})
    with pytest.raises(RefusedError, match="quota line"):
        quota_line(other, free(), NOW)


# -- free tier -----------------------------------------------------------------------------------------------------


def test_a_free_call_sends_one_request_with_the_free_key_and_logs_usage(cfg: GeminiConfig, server: FakeGemini) -> None:
    keys = Keys()
    reply = ask(cfg, free(), key_for=keys, now=NOW)
    assert reply.text == "A cited answer." and keys.asked == ["free"]
    assert len(server.requests) == 1
    path, headers, body = server.requests[0]
    assert path == f"/v1beta/models/{MODEL}:generateContent"
    assert headers["x-goog-api-key"] == FAKE_KEY
    assert body["contents"][0]["parts"][0]["text"].startswith("What changed")
    rows = ledger_rows(cfg.ledger)
    assert [r["type"] for r in rows] == ["call_start", "call_end"]
    assert rows[0]["tier"] == "free" and rows[0]["model"] == MODEL
    assert rows[1]["status"] == "ok" and rows[1]["prompt_tokens"] == 10 and rows[1]["output_tokens"] == 20
    assert rows[1]["actual_usd"] == 0 and rows[0]["est_usd"] == 0


def test_the_key_never_reaches_the_ledger_or_the_reply(cfg: GeminiConfig) -> None:
    reply = ask(cfg, free(), key_for=Keys(), now=NOW)
    assert FAKE_KEY not in cfg.ledger.read_text() and FAKE_KEY not in repr(reply)


def test_a_new_ledger_is_private_and_existing_lines_are_never_changed(cfg: GeminiConfig) -> None:
    ask(cfg, free(), key_for=Keys(), now=NOW)
    assert stat.S_IMODE(os.stat(cfg.ledger).st_mode) == 0o600
    before = cfg.ledger.read_bytes()
    ask(cfg, free(), key_for=Keys(), now=NOW + dt.timedelta(minutes=5))
    assert cfg.ledger.read_bytes().startswith(before) and len(cfg.ledger.read_bytes()) > len(before)


def test_the_per_minute_request_limit_stops_before_anything_is_sent(cfg: GeminiConfig, server: FakeGemini) -> None:
    for i in range(3):
        seed(cfg.ledger, start_row(minutes_ago(0.2 * (i + 1)), call_id=f"r{i}"))
    with pytest.raises(RefusedError, match="per minute"):
        ask(cfg, free(), key_for=Keys(), now=NOW)
    assert server.requests == []


def test_requests_older_than_a_minute_do_not_count_toward_the_minute(cfg: GeminiConfig, server: FakeGemini) -> None:
    for i in range(3):
        seed(cfg.ledger, start_row(minutes_ago(1.5 + i), call_id=f"r{i}"))
    ask(cfg, free(), key_for=Keys(), now=NOW)
    assert len(server.requests) == 1


def test_the_per_day_limit_resets_at_midnight_pacific(cfg: GeminiConfig, server: FakeGemini) -> None:
    just_after = dt.datetime(2026, 10, 30, 7, 5, tzinfo=dt.UTC)  # 00:05 Pacific
    for i in range(5):  # all before midnight Pacific, yet within the last 24 hours
        seed(cfg.ledger, start_row(dt.datetime(2026, 10, 30, 6, 50 - i, tzinfo=dt.UTC), call_id=f"r{i}"))
    ask(cfg, free(), key_for=Keys(), now=just_after)
    assert len(server.requests) == 1
    for i in range(5):  # five calls after midnight Pacific fill the day
        seed(cfg.ledger, start_row(dt.datetime(2026, 10, 30, 7, 1, i, tzinfo=dt.UTC), call_id=f"n{i}"))
    with pytest.raises(RefusedError, match="per day"):
        ask(cfg, free(), key_for=Keys(), now=just_after + dt.timedelta(minutes=1))
    assert len(server.requests) == 1


def test_the_input_token_limit_counts_this_prompt_too(cfg: GeminiConfig, server: FakeGemini) -> None:
    seed(cfg.ledger, start_row(minutes_ago(0.3), tokens=990, call_id="big"))
    with pytest.raises(RefusedError, match="input tokens"):
        ask(cfg, free("x" * 200), key_for=Keys(), now=NOW)
    assert server.requests == []


def test_a_429_is_final_and_never_falls_through_to_a_paid_call(cfg: GeminiConfig, server: FakeGemini) -> None:
    server.status = 429
    server.body = {"error": {"code": 429, "status": "RESOURCE_EXHAUSTED", "message": "quota"}}
    server.headers_out = {"Retry-After": "30"}
    keys = Keys()
    with pytest.raises(RateLimitStopError) as stopped:
        ask(cfg, free(), key_for=keys, now=NOW)
    assert len(server.requests) == 1, "no retry"
    assert keys.asked == ["free"], "the paid key is never fetched"
    assert "QUOTA free" in str(stopped.value) and "stopped" in str(stopped.value)
    assert ledger_rows(cfg.ledger)[-1]["status"] == "rate_limited"


def test_a_rate_limited_call_still_counts_toward_the_local_counter(cfg: GeminiConfig, server: FakeGemini) -> None:
    server.status = 429
    with pytest.raises(RateLimitStopError):
        ask(cfg, free(), key_for=Keys(), now=NOW)
    assert "requests per minute 1 of 3" in quota_line(cfg, free(), NOW)


def test_image_models_are_paid_only(cfg: GeminiConfig, server: FakeGemini) -> None:
    other = dataclasses.replace(cfg, free={**cfg.free, IMAGE_MODEL: cfg.free[MODEL]})
    with pytest.raises(RefusedError, match="paid"):
        ask(other, Request(model=IMAGE_MODEL, prompt="p", tier="free"), key_for=Keys(), now=NOW)
    assert server.requests == []


def test_an_unlisted_model_is_refused(cfg: GeminiConfig, server: FakeGemini) -> None:
    with pytest.raises(RefusedError, match="not configured"):
        ask(cfg, Request(model="gemini-9", prompt="p", tier="free"), key_for=Keys(), now=NOW)
    assert server.requests == []


def test_a_model_name_cannot_rewrite_the_url(cfg: GeminiConfig) -> None:
    with pytest.raises(RefusedError, match="model"):
        ask(cfg, Request(model="../x?key=1", prompt="p", tier="free"), key_for=Keys(), now=NOW)


def test_a_prompt_with_a_secret_shape_is_refused_before_sending(cfg: GeminiConfig, server: FakeGemini) -> None:
    for secret in ("AIza" + "A" * 35, "ghp_" + "a" * 36, "-----BEGIN RSA PRIVATE KEY-----"):
        with pytest.raises(RefusedError, match="secret"):
            ask(cfg, free(f"look at {secret}"), key_for=Keys(), now=NOW)
    assert server.requests == []


# -- transport -----------------------------------------------------------------------------------------------------


def test_a_redirect_is_refused_and_the_second_server_never_sees_the_key(cfg: GeminiConfig, server: FakeGemini) -> None:
    with FakeGemini().serve() as elsewhere:
        server.redirect_to = elsewhere.url + "/steal"
        with pytest.raises(OutcomeUnknownError):
            ask(cfg, free(), key_for=Keys(), now=NOW)
        assert elsewhere.requests == []
    assert len(server.requests) == 1


@pytest.mark.parametrize("fault", ["drop", "500", "garbage", "huge"])
def test_an_ambiguous_outcome_is_never_replayed(cfg: GeminiConfig, server: FakeGemini, fault: str) -> None:
    if fault == "drop":
        server.drop = True
    elif fault == "500":
        server.status = 500
    elif fault == "garbage":
        server.raw = b"not json"
    else:
        server.raw = b"{" + b" " * 2_000_000 + b"}"
    with pytest.raises(OutcomeUnknownError, match="not repeated"):
        ask(cfg, free(), key_for=Keys(), now=NOW)
    assert len(server.requests) == 1
    assert ledger_rows(cfg.ledger)[-1]["status"] == "ambiguous"


def test_a_timeout_after_sending_is_ambiguous_and_bounded(cfg: GeminiConfig, server: FakeGemini) -> None:
    server.stall = 1.5
    quick = dataclasses.replace(cfg, timeout_seconds=0.3)
    with pytest.raises(OutcomeUnknownError):
        ask(quick, free(), key_for=Keys(), now=NOW)
    assert len(server.requests) == 1


def test_a_definite_client_error_is_reported_without_a_retry(cfg: GeminiConfig, server: FakeGemini) -> None:
    server.status = 400
    server.body = {"error": {"code": 400, "status": "INVALID_ARGUMENT", "message": "bad shape"}}
    with pytest.raises(RefusedError, match="400"):
        ask(cfg, free(), key_for=Keys(), now=NOW)
    assert len(server.requests) == 1
    assert ledger_rows(cfg.ledger)[-1]["status"] == "http_error"


# -- the ledger ----------------------------------------------------------------------------------------------------


def test_a_corrupt_ledger_stops_every_call(cfg: GeminiConfig, server: FakeGemini) -> None:
    cfg.ledger.parent.mkdir(parents=True, exist_ok=True)
    cfg.ledger.write_text('{"type": "funding", "amount_usd": 25}\nnot json\n')
    with pytest.raises(RefusedError, match="ledger"):
        ask(cfg, free(), key_for=Keys(), now=NOW)
    assert server.requests == []


def test_the_maintainers_own_rows_do_not_break_the_ledger(cfg: GeminiConfig) -> None:
    seed(
        cfg.ledger,
        [
            {"date": "2026-10-29", "type": "funding", "amount_usd": 25, "source": "maintainer statement"},
            {"date": "2026-10-29", "type": "usage", "amount_usd": 1.5, "note": "vendor-observed"},
        ],
    )
    assert "requests per minute 0 of 3" in quota_line(cfg, free(), NOW)


def test_a_ledger_that_is_a_symlink_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "real.jsonl"
    target.write_text("")
    link = tmp_path / "link.jsonl"
    link.symlink_to(target)
    with pytest.raises(RefusedError, match="ledger"):
        Ledger(link).read()


def test_tests_never_write_the_real_ledger(cfg: GeminiConfig, tmp_path: Path) -> None:
    assert str(cfg.ledger).startswith(str(tmp_path))
    assert "safo-dev" not in str(cfg.ledger)


# -- the key -------------------------------------------------------------------------------------------------------


def test_the_key_is_read_by_name_from_doppler_without_argv_exposure(cfg: GeminiConfig, tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    record = tmp_path / "argv.txt"
    script = bin_dir / "doppler"
    script.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > {record}\nprintf "%s" "{FAKE_KEY}"\n')
    script.chmod(0o755)
    provider = doppler_key_provider(cfg, {"PATH": str(bin_dir)})
    assert provider("free") == FAKE_KEY
    argv = record.read_text().split()
    assert "GEMINI_API_KEY" in argv and "image-gen" in argv and "prd" in argv and "prd_paid" not in argv
    assert FAKE_KEY not in argv
    record.unlink()
    with pytest.raises(RefusedError, match="broker"):
        provider("paid")  # there is no paid key to read here: the secret tool is not even run
    assert not record.exists()


def test_a_missing_secret_tool_is_a_refusal_not_a_leak(cfg: GeminiConfig) -> None:
    with pytest.raises(RefusedError, match="secret"):
        doppler_key_provider(cfg, {"PATH": ""})("free")


def test_a_malformed_key_is_refused_without_echoing_it(cfg: GeminiConfig, tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    script = bin_dir / "doppler"
    script.write_text('#!/bin/sh\nprintf "SECRET-VALUE with spaces\\nsecond line"\n')
    script.chmod(0o755)
    with pytest.raises(RefusedError) as err:
        doppler_key_provider(cfg, {"PATH": str(bin_dir)})("free")
    assert "SECRET-VALUE" not in str(err.value)


# -- review round: fixed locations, floors, private terms, the race, legacy ledgers ----------------------------------


def test_the_fixed_locations_ignore_the_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import pwd

    monkeypatch.setenv("HOME", str(tmp_path / "elsewhere"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("SAFO_GEMINI_CONFIG", str(tmp_path / "x.yaml"))
    found = real_fixed_locations()
    home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
    assert found.home == home
    assert found.config == home / ".config" / "safo" / "gemini.yaml"
    assert found.approvals == home / ".local" / "state" / "safo" / "gemini" / "approvals"
    assert str(tmp_path) not in str(found)


def test_the_default_ledger_is_under_the_fixed_home(tmp_path: Path) -> None:
    from safo.gemini import default_ledger

    assert default_ledger(tmp_path) == tmp_path / ".local" / "share" / "safo" / "gemini-spend-ledger.jsonl"


def test_a_missing_ledger_is_refused_when_another_exists_beside_it(cfg: GeminiConfig) -> None:
    other = cfg.ledger.parent.parent / "older" / cfg.ledger.name
    other.parent.mkdir(parents=True)
    other.write_text('{"type": "usage", "date": "2026-10-29", "amount_usd": 5}\n')
    with pytest.raises(RefusedError, match="another ledger"):
        ask(cfg, free(), key_for=Keys(), now=NOW)
    assert not cfg.ledger.exists()


def test_an_unknown_ledger_row_type_is_reported(cfg: GeminiConfig) -> None:
    seed(cfg.ledger, [{"date": "2026-10-29", "type": "usgae", "amount_usd": 9}])
    with pytest.raises(RefusedError, match="unknown"):
        quota_line(cfg, free(), NOW)


def test_two_callers_racing_for_the_last_room_cannot_both_proceed(
    cfg: GeminiConfig, server: FakeGemini, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = Ledger.read
    calls = {"n": 0}

    def racing(self: Ledger) -> list[dict[str, Any]]:
        calls["n"] += 1
        if calls["n"] == 2:  # the locked re-check: another caller has used the room since the first read
            for i in range(3):
                seed(cfg.ledger, start_row(minutes_ago(0.1 * (i + 1)), call_id=f"race{i}"))
        return real(self)

    monkeypatch.setattr(Ledger, "read", racing)
    with pytest.raises(RefusedError, match="per minute"):
        ask(cfg, free(), key_for=Keys(), now=NOW)
    assert server.requests == []


def test_the_prompt_is_checked_against_the_private_terms(cfg: GeminiConfig, server: FakeGemini, tmp_path: Path) -> None:
    terms = tmp_path / "terms.txt"
    terms.write_text("# mine\nacme-internal\n")
    withterms = dataclasses.replace(cfg, private_terms=str(terms))
    with pytest.raises(RefusedError, match="private term") as err:
        ask(withterms, free("about ACME-Internal tooling"), key_for=Keys(), now=NOW)
    assert "acme" not in str(err.value).lower()
    ask(withterms, free("about public things"), key_for=Keys(), now=NOW)
    assert len(server.requests) == 1


@pytest.mark.parametrize("content", [None, "(unclosed\n", "x" * 70_000])
@hard_timeout(30)
def test_an_unreadable_or_invalid_terms_file_stops_the_call(
    cfg: GeminiConfig, server: FakeGemini, tmp_path: Path, content: str | None
) -> None:
    terms = tmp_path / "terms.txt"
    if content is not None:
        terms.write_text(content)
    broken = dataclasses.replace(cfg, private_terms=str(terms))
    with pytest.raises(RefusedError, match="private terms"):
        ask(broken, free(), key_for=Keys(), now=NOW)
    assert server.requests == []


def test_the_default_terms_file_is_the_fixed_one(
    cfg: GeminiConfig, server: FakeGemini, gemini_locations: Locations
) -> None:
    default = dataclasses.replace(cfg, private_terms="default")
    with pytest.raises(RefusedError, match="private terms"):
        ask(default, free(), key_for=Keys(), now=NOW)
    gemini_locations.terms.write_text("zzz-private\n")
    ask(default, free(), key_for=Keys(), now=NOW)
    assert len(server.requests) == 1


def test_the_config_accepts_only_none_default_or_an_absolute_terms_path(tmp_path: Path, ledger: Path) -> None:
    path = tmp_path / "c.yaml"
    path.write_text(yaml.safe_dump(config_dict("http://127.0.0.1:9", ledger, private_terms="relative.txt")))
    with pytest.raises(ConfigError, match="private_terms"):
        load_config(path)


@hard_timeout(30)
def test_the_terms_loader_refuses_dangerous_shapes_and_accepts_plain_ones(tmp_path: Path) -> None:
    from safo.gemini import load_private_terms

    for bad in (pathological("nested_y"), pathological("alternation_y"), ".*x", "a+", "(a)\\1", "(unclosed", "x" * 300):
        path = tmp_path / "t.txt"
        path.write_text(f"ok-term\n{bad}\n")
        with pytest.raises(RefusedError, match="private terms"):
            load_private_terms(str(path))
    path.write_text("# c\nacme-internal\nproject [a-z]{1,30}\n\\bfoo\\d{2,5}\\b\n")
    assert len(load_private_terms(str(path))) == 3
    path.write_text("\n".join(f"t{i}" for i in range(501)))
    with pytest.raises(RefusedError, match="private terms"):
        load_private_terms(str(path))


@hard_timeout(30)
def test_the_wrapper_matches_private_terms_on_the_folded_prompt(
    cfg: GeminiConfig, server: FakeGemini, tmp_path: Path
) -> None:
    terms = tmp_path / "terms.txt"
    terms.write_text("acme-internal\n")
    withterms = dataclasses.replace(cfg, private_terms=str(terms))
    for disguised in ("about \u0430cme-internal", "about ac\u200bme-internal"):
        with pytest.raises(RefusedError, match="private term"):
            ask(withterms, free(disguised), key_for=Keys(), now=NOW)
    assert server.requests == []


def test_ask_refuses_a_prompt_with_a_lone_surrogate_cleanly(
    cfg: GeminiConfig, server: FakeGemini, tmp_path: Path
) -> None:
    with pytest.raises(RefusedError, match="not valid text"):
        ask(cfg, free("x \ud800 foo"), key_for=Keys(), now=NOW)
    assert server.requests == []
