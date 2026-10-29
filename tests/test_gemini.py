# SPDX-License-Identifier: Apache-2.0
"""The Gemini wrapper (#200): free-tier limits, the paid gate, the ledger, the transport.

Hermetic: a fake Gemini on loopback, a temporary ledger and config, a fake key. Every check that protects money has a
test that fails when the check is removed.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import os
import stat
from collections.abc import Iterator
from decimal import Decimal
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
    ledger_rows,
    minutes_ago,
    seed,
    start_row,
    write_config,
)
from safo.errors import ConfigError
from safo.gemini import (
    ApprovalStore,
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


@pytest.fixture
def store(tmp_path: Path) -> ApprovalStore:
    return ApprovalStore(tmp_path / "state" / "approvals")


class Keys:
    """A key provider that records which tier was asked for, so a test can prove paid was never touched."""

    def __init__(self) -> None:
        self.asked: list[str] = []

    def __call__(self, tier: str) -> str:
        self.asked.append(tier)
        return FAKE_KEY


def free(prompt: str = "What changed in the CVE list?", **kw: Any) -> Request:
    return Request(**{"model": MODEL, "prompt": prompt, "tier": "free", **kw})


def approve(store: ApprovalStore, **kw: Any) -> str:
    args: dict[str, Any] = {
        "model": MODEL,
        "max_usd": Decimal("1.50"),
        "job": "job-1",
        "quote": "yes, spend up to 1.50 on this research",
        "quoted_at": NOW - dt.timedelta(minutes=5),
        "now": NOW,
        "ttl_minutes": 60,
        "beyond_ceiling": False,
    }
    args.update(kw)
    return store.issue(**args).id


def paid(approval: str, **kw: Any) -> Request:
    args: dict[str, Any] = {
        "model": MODEL,
        "prompt": "Summarize these public advisories.",
        "tier": "paid",
        "job": "job-1",
        "approval": approval,
        "max_output_tokens": 500,
    }
    args.update(kw)
    return Request(**args)


# -- configuration -------------------------------------------------------------------------------------------------


def test_the_config_loads_and_carries_the_price_date(cfg: GeminiConfig) -> None:
    assert cfg.price_checked == dt.date(2026, 10, 29)
    assert cfg.free[MODEL].rpm == 3 and cfg.prices[MODEL].input_per_mtok == Decimal("0.75")


def test_the_free_limits_are_supplied_never_guessed(tmp_path: Path, ledger: Path) -> None:
    data = config_dict("http://127.0.0.1:9", ledger)
    data["free"] = {MODEL: {"rpm": 3}}
    path = tmp_path / "c.yaml"
    path.write_text(yaml.safe_dump(data))
    with pytest.raises(ConfigError, match="rpd"):
        load_config(path)


@pytest.mark.parametrize(
    "caps",
    [{"job_usd": 2.01, "month_usd": 10, "block_usd": 2}, {"job_usd": 2, "month_usd": 10.5, "block_usd": 2}],
)
def test_a_config_cannot_raise_the_caps(tmp_path: Path, ledger: Path, caps: dict[str, float]) -> None:
    path = tmp_path / "c.yaml"
    path.write_text(yaml.safe_dump(config_dict("http://127.0.0.1:9", ledger, caps=caps)))
    with pytest.raises(ConfigError, match="cap"):
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


def test_the_paid_quota_line_shows_spent_estimate_total_and_the_ceiling(
    cfg: GeminiConfig, store: ApprovalStore
) -> None:
    seed(cfg.ledger, start_row(minutes_ago(2000), tier="paid", usd=3.25, call_id="p"))
    line = quota_line(cfg, paid(approve(store)), NOW)
    assert line.startswith(f"QUOTA paid {MODEL}:")
    assert "spent 3.25 of 10.00 USD this month" in line
    assert "of the 2.00 USD job cap" in line and "after this job" in line
    assert "beyond ceiling: no" in line


def test_beyond_ceiling_is_marked_once_the_month_passes_ten(cfg: GeminiConfig, store: ApprovalStore) -> None:
    seed(cfg.ledger, start_row(minutes_ago(2000), tier="paid", usd=10.0, call_id="p"))
    assert "beyond ceiling: YES" in quota_line(cfg, paid(approve(store)), NOW)


# -- free tier -----------------------------------------------------------------------------------------------------


def test_a_free_call_sends_one_request_with_the_free_key_and_logs_usage(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    keys = Keys()
    reply = ask(cfg, free(), store=store, key_for=keys, now=NOW)
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


def test_the_key_never_reaches_the_ledger_or_the_reply(cfg: GeminiConfig, store: ApprovalStore) -> None:
    reply = ask(cfg, free(), store=store, key_for=Keys(), now=NOW)
    assert FAKE_KEY not in cfg.ledger.read_text() and FAKE_KEY not in repr(reply)


def test_a_new_ledger_is_private_and_existing_lines_are_never_changed(cfg: GeminiConfig, store: ApprovalStore) -> None:
    ask(cfg, free(), store=store, key_for=Keys(), now=NOW)
    assert stat.S_IMODE(os.stat(cfg.ledger).st_mode) == 0o600
    before = cfg.ledger.read_bytes()
    ask(cfg, free(), store=store, key_for=Keys(), now=NOW + dt.timedelta(minutes=5))
    assert cfg.ledger.read_bytes().startswith(before) and len(cfg.ledger.read_bytes()) > len(before)


def test_the_per_minute_request_limit_stops_before_anything_is_sent(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    for i in range(3):
        seed(cfg.ledger, start_row(minutes_ago(0.2 * (i + 1)), call_id=f"r{i}"))
    with pytest.raises(RefusedError, match="per minute"):
        ask(cfg, free(), store=store, key_for=Keys(), now=NOW)
    assert server.requests == []


def test_requests_older_than_a_minute_do_not_count_toward_the_minute(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    for i in range(3):
        seed(cfg.ledger, start_row(minutes_ago(1.5 + i), call_id=f"r{i}"))
    ask(cfg, free(), store=store, key_for=Keys(), now=NOW)
    assert len(server.requests) == 1


def test_the_per_day_limit_resets_at_midnight_pacific(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    just_after = dt.datetime(2026, 10, 30, 7, 5, tzinfo=dt.UTC)  # 00:05 Pacific
    for i in range(5):  # all before midnight Pacific, yet within the last 24 hours
        seed(cfg.ledger, start_row(dt.datetime(2026, 10, 30, 6, 50 - i, tzinfo=dt.UTC), call_id=f"r{i}"))
    ask(cfg, free(), store=store, key_for=Keys(), now=just_after)
    assert len(server.requests) == 1
    for i in range(5):  # five calls after midnight Pacific fill the day
        seed(cfg.ledger, start_row(dt.datetime(2026, 10, 30, 7, 1, i, tzinfo=dt.UTC), call_id=f"n{i}"))
    with pytest.raises(RefusedError, match="per day"):
        ask(cfg, free(), store=store, key_for=Keys(), now=just_after + dt.timedelta(minutes=1))
    assert len(server.requests) == 1


def test_the_input_token_limit_counts_this_prompt_too(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    seed(cfg.ledger, start_row(minutes_ago(0.3), tokens=990, call_id="big"))
    with pytest.raises(RefusedError, match="input tokens"):
        ask(cfg, free("x" * 200), store=store, key_for=Keys(), now=NOW)
    assert server.requests == []


def test_a_429_is_final_and_never_falls_through_to_paid(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    server.status = 429
    server.body = {"error": {"code": 429, "status": "RESOURCE_EXHAUSTED", "message": "quota"}}
    server.headers_out = {"Retry-After": "30"}
    keys = Keys()
    approval = approve(store)  # an approval exists, and must still not be used by a free call
    with pytest.raises(RateLimitStopError) as stopped:
        ask(cfg, free(), store=store, key_for=keys, now=NOW)
    assert len(server.requests) == 1, "no retry"
    assert keys.asked == ["free"], "the paid key is never fetched"
    assert "QUOTA free" in str(stopped.value) and "stopped" in str(stopped.value)
    assert ledger_rows(cfg.ledger)[-1]["status"] == "rate_limited"
    assert not (store.folder / f"{approval}.used").exists()


def test_a_rate_limited_call_still_counts_toward_the_local_counter(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    server.status = 429
    with pytest.raises(RateLimitStopError):
        ask(cfg, free(), store=store, key_for=Keys(), now=NOW)
    assert "requests per minute 1 of 3" in quota_line(cfg, free(), NOW)


def test_image_models_are_paid_only(cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore) -> None:
    other = dataclasses.replace(cfg, free={**cfg.free, IMAGE_MODEL: cfg.free[MODEL]})
    with pytest.raises(RefusedError, match="paid"):
        ask(other, Request(model=IMAGE_MODEL, prompt="p", tier="free"), store=store, key_for=Keys(), now=NOW)
    assert server.requests == []


def test_an_unlisted_model_is_refused(cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore) -> None:
    with pytest.raises(RefusedError, match="not configured"):
        ask(cfg, Request(model="gemini-9", prompt="p", tier="free"), store=store, key_for=Keys(), now=NOW)
    assert server.requests == []


def test_a_model_name_cannot_rewrite_the_url(cfg: GeminiConfig, store: ApprovalStore) -> None:
    with pytest.raises(RefusedError, match="model"):
        ask(cfg, Request(model="../x?key=1", prompt="p", tier="free"), store=store, key_for=Keys(), now=NOW)


def test_a_prompt_with_a_secret_shape_is_refused_before_sending(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    for secret in ("AIza" + "A" * 35, "ghp_" + "a" * 36, "-----BEGIN RSA PRIVATE KEY-----"):
        with pytest.raises(RefusedError, match="secret"):
            ask(cfg, free(f"look at {secret}"), store=store, key_for=Keys(), now=NOW)
    assert server.requests == []


# -- transport -----------------------------------------------------------------------------------------------------


def test_a_redirect_is_refused_and_the_second_server_never_sees_the_key(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    with FakeGemini().serve() as elsewhere:
        server.redirect_to = elsewhere.url + "/steal"
        with pytest.raises(OutcomeUnknownError):
            ask(cfg, free(), store=store, key_for=Keys(), now=NOW)
        assert elsewhere.requests == []
    assert len(server.requests) == 1


@pytest.mark.parametrize("fault", ["drop", "500", "garbage", "huge"])
def test_an_ambiguous_outcome_is_never_replayed(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, fault: str
) -> None:
    if fault == "drop":
        server.drop = True
    elif fault == "500":
        server.status = 500
    elif fault == "garbage":
        server.raw = b"not json"
    else:
        server.raw = b"{" + b" " * 2_000_000 + b"}"
    with pytest.raises(OutcomeUnknownError, match="not repeated"):
        ask(cfg, free(), store=store, key_for=Keys(), now=NOW)
    assert len(server.requests) == 1
    assert ledger_rows(cfg.ledger)[-1]["status"] == "ambiguous"


def test_a_timeout_after_sending_is_ambiguous_and_bounded(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    server.stall = 1.5
    quick = dataclasses.replace(cfg, timeout_seconds=0.3)
    with pytest.raises(OutcomeUnknownError):
        ask(quick, free(), store=store, key_for=Keys(), now=NOW)
    assert len(server.requests) == 1


def test_a_definite_client_error_is_reported_without_a_retry(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    server.status = 400
    server.body = {"error": {"code": 400, "status": "INVALID_ARGUMENT", "message": "bad shape"}}
    with pytest.raises(RefusedError, match="400"):
        ask(cfg, free(), store=store, key_for=Keys(), now=NOW)
    assert len(server.requests) == 1
    assert ledger_rows(cfg.ledger)[-1]["status"] == "http_error"


# -- the paid gate -------------------------------------------------------------------------------------------------


def test_a_paid_call_without_an_approval_is_refused(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    keys = Keys()
    with pytest.raises(RefusedError, match="approval"):
        ask(cfg, paid(""), store=store, key_for=keys, now=NOW)
    with pytest.raises(RefusedError, match="approval"):
        ask(cfg, paid("0123456789abcdef"), store=store, key_for=keys, now=NOW)
    assert server.requests == [] and keys.asked == []


def test_an_approved_paid_call_logs_estimate_and_actual_and_spends_the_record(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    approval = approve(store)
    keys = Keys()
    reply = ask(cfg, paid(approval), store=store, key_for=keys, now=NOW)
    assert keys.asked == ["paid"] and len(server.requests) == 1
    assert server.requests[0][2]["generationConfig"]["maxOutputTokens"] == 500
    start, end = ledger_rows(cfg.ledger)
    assert start["tier"] == "paid" and start["approval"] == approval and start["est_usd"] > 0
    expected = (Decimal(10) * Decimal("0.75") + Decimal(20) * Decimal("3.75")) / Decimal(1_000_000)
    assert Decimal(str(end["actual_usd"])) == expected and reply.cost_usd == expected
    assert Decimal(str(start["est_usd"])) >= expected, "the estimate is an upper bound"
    assert (store.folder / f"{approval}.used").exists()


def test_an_approval_is_single_use(cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore) -> None:
    approval = approve(store)
    ask(cfg, paid(approval), store=store, key_for=Keys(), now=NOW)
    with pytest.raises(RefusedError, match="already used"):
        ask(cfg, paid(approval), store=store, key_for=Keys(), now=NOW)
    assert len(server.requests) == 1


def test_an_expired_approval_is_refused(cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore) -> None:
    approval = approve(store, ttl_minutes=10)
    with pytest.raises(RefusedError, match="expired"):
        ask(cfg, paid(approval), store=store, key_for=Keys(), now=NOW + dt.timedelta(minutes=11))
    assert server.requests == []


@pytest.mark.parametrize("field", ["model", "job"])
def test_an_approval_is_for_its_own_model_and_job(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, field: str
) -> None:
    approval = approve(store)
    cfg2 = dataclasses.replace(cfg, prices={**cfg.prices, "other": cfg.prices[MODEL]})
    request = paid(approval, **({"model": "other"} if field == "model" else {"job": "job-2"}))
    with pytest.raises(RefusedError, match=field):
        ask(cfg2, request, store=store, key_for=Keys(), now=NOW)
    assert server.requests == []


def test_the_job_cap_of_two_dollars_is_a_hard_limit(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    with pytest.raises(ConfigError, match="2"):
        approve(store, max_usd=Decimal("2.01"))
    approval = approve(store, max_usd=Decimal("2.00"))
    # 600k tokens of output at 3.75 per million is 2.25 USD: over the cap whatever was approved
    with pytest.raises(RefusedError, match="job cap"):
        ask(cfg, paid(approval, max_output_tokens=600_000), store=store, key_for=Keys(), now=NOW)
    assert server.requests == [] and not (store.folder / f"{approval}.used").exists()


def test_the_estimate_must_fit_the_approved_amount(cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore) -> None:
    approval = approve(store, max_usd=Decimal("0.01"))
    with pytest.raises(RefusedError, match="approved"):
        ask(cfg, paid(approval, max_output_tokens=10_000), store=store, key_for=Keys(), now=NOW)
    assert server.requests == []


def test_the_monthly_ceiling_needs_an_explicit_beyond_ceiling_approval(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    seed(cfg.ledger, start_row(minutes_ago(3000), tier="paid", usd=9.999, call_id="p"))
    plain = approve(store)
    with pytest.raises(RefusedError, match="ceiling"):
        ask(cfg, paid(plain), store=store, key_for=Keys(), now=NOW)
    assert server.requests == [] and not (store.folder / f"{plain}.used").exists()
    beyond = approve(store, beyond_ceiling=True)
    ask(cfg, paid(beyond), store=store, key_for=Keys(), now=NOW)
    assert len(server.requests) == 1


def test_an_ambiguous_paid_call_counts_its_estimate_as_spent(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    server.status = 503
    approval = approve(store)
    with pytest.raises(OutcomeUnknownError):
        ask(cfg, paid(approval), store=store, key_for=Keys(), now=NOW)
    assert "spent 0.001884 of 10.00" in quota_line(cfg, paid(approve(store)), NOW)
    assert (store.folder / f"{approval}.used").exists(), "an ambiguous call does not free its approval for a replay"


def test_a_stale_price_table_refuses_a_paid_estimate(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    later = NOW + dt.timedelta(days=90)  # past the table's valid_through of 2026-12-31
    approval = approve(store, now=later, quoted_at=later - dt.timedelta(minutes=5))
    with pytest.raises(RefusedError, match="price"):
        ask(cfg, paid(approval), store=store, key_for=Keys(), now=later)
    assert server.requests == []


def test_a_corrupt_ledger_stops_every_call(cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore) -> None:
    cfg.ledger.parent.mkdir(parents=True, exist_ok=True)
    cfg.ledger.write_text('{"type": "funding", "amount_usd": 25}\nnot json\n')
    with pytest.raises(RefusedError, match="ledger"):
        ask(cfg, free(), store=store, key_for=Keys(), now=NOW)
    assert server.requests == []


def test_the_maintainers_own_rows_do_not_break_the_ledger(cfg: GeminiConfig, store: ApprovalStore) -> None:
    seed(
        cfg.ledger,
        [
            {"date": "2026-10-29", "type": "funding", "amount_usd": 25, "source": "maintainer statement"},
            {"date": "2026-10-29", "type": "usage", "amount_usd": 1.5, "note": "vendor-observed"},
        ],
    )
    assert "spent 1.50 of 10.00" in quota_line(cfg, paid(approve(store)), NOW)


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


# -- approvals -----------------------------------------------------------------------------------------------------


def test_an_approval_carries_the_quote_and_time(store: ApprovalStore) -> None:
    approval = store.issue(
        model=MODEL,
        max_usd=Decimal("1"),
        job="j",
        quote="go ahead, one dollar",
        quoted_at=NOW - dt.timedelta(minutes=1),
        now=NOW,
        ttl_minutes=30,
        beyond_ceiling=False,
    )
    data = json.loads((store.folder / f"{approval.id}.json").read_text())
    assert data["quote"] == "go ahead, one dollar" and data["quoted_at"].startswith("2026-10-29T19:59")
    assert stat.S_IMODE(os.stat(store.folder / f"{approval.id}.json").st_mode) == 0o600


@pytest.mark.parametrize(
    "bad",
    [
        {"quote": ""},
        {"quote": "x" * 600},
        {"quoted_at": NOW + dt.timedelta(minutes=5)},
        {"quoted_at": NOW - dt.timedelta(days=2)},
        {"ttl_minutes": 0},
        {"ttl_minutes": 5000},
        {"job": ""},
        {"max_usd": Decimal(0)},
    ],
)
def test_an_approval_needs_a_real_quote_time_job_and_amount(store: ApprovalStore, bad: dict[str, Any]) -> None:
    with pytest.raises(ConfigError):
        approve(store, **bad)


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
    assert provider("paid") == FAKE_KEY
    assert "prd_paid" in record.read_text().split()


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


def test_a_missing_ledger_is_refused_when_another_exists_beside_it(cfg: GeminiConfig, store: ApprovalStore) -> None:
    other = cfg.ledger.parent.parent / "older" / cfg.ledger.name
    other.parent.mkdir(parents=True)
    other.write_text('{"type": "usage", "date": "2026-10-29", "amount_usd": 5}\n')
    with pytest.raises(RefusedError, match="another ledger"):
        ask(cfg, free(), store=store, key_for=Keys(), now=NOW)
    assert not cfg.ledger.exists()


def test_an_unknown_ledger_row_type_is_reported(cfg: GeminiConfig, store: ApprovalStore) -> None:
    seed(cfg.ledger, [{"date": "2026-10-29", "type": "usgae", "amount_usd": 9}])
    with pytest.raises(RefusedError, match="unknown"):
        quota_line(cfg, free(), NOW)


def test_two_callers_racing_for_the_last_room_cannot_both_proceed(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, monkeypatch: pytest.MonkeyPatch
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
        ask(cfg, free(), store=store, key_for=Keys(), now=NOW)
    assert server.requests == []


def test_zero_token_counts_on_a_paid_answer_do_not_record_zero_spend(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    server.body = {
        "candidates": [{"content": {"parts": [{"text": "word " * 400}]}}],
        "usageMetadata": {"promptTokenCount": 0, "candidatesTokenCount": 0},
    }
    approval = approve(store)
    reply = ask(cfg, paid(approval, prompt="x" * 900), store=store, key_for=Keys(), now=NOW)
    start, end = ledger_rows(cfg.ledger)
    assert end["actual_usd"] > 0 and Decimal(str(end["actual_usd"])) == Decimal(str(start["est_usd"]))
    assert reply.cost_usd > 0


def test_plausible_counts_are_recorded_as_reported(cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore) -> None:
    ask(cfg, paid(approve(store)), store=store, key_for=Keys(), now=NOW)
    _, end = ledger_rows(cfg.ledger)
    assert (
        Decimal(str(end["actual_usd"])) == (Decimal(10) * Decimal("0.75") + Decimal(20) * Decimal("3.75")) / 1_000_000
    )


def test_the_prompt_is_checked_against_the_private_terms(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, tmp_path: Path
) -> None:
    terms = tmp_path / "terms.txt"
    terms.write_text("# mine\nacme-internal\n")
    withterms = dataclasses.replace(cfg, private_terms=str(terms))
    with pytest.raises(RefusedError, match="private term") as err:
        ask(withterms, free("about ACME-Internal tooling"), store=store, key_for=Keys(), now=NOW)
    assert "acme" not in str(err.value).lower()
    ask(withterms, free("about public things"), store=store, key_for=Keys(), now=NOW)
    assert len(server.requests) == 1


@pytest.mark.parametrize("content", [None, "(unclosed\n", "x" * 70_000])
def test_an_unreadable_or_invalid_terms_file_stops_the_call(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, tmp_path: Path, content: str | None
) -> None:
    terms = tmp_path / "terms.txt"
    if content is not None:
        terms.write_text(content)
    broken = dataclasses.replace(cfg, private_terms=str(terms))
    with pytest.raises(RefusedError, match="private terms"):
        ask(broken, free(), store=store, key_for=Keys(), now=NOW)
    assert server.requests == []


def test_the_default_terms_file_is_the_fixed_one(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, gemini_locations: Locations
) -> None:
    default = dataclasses.replace(cfg, private_terms="default")
    with pytest.raises(RefusedError, match="private terms"):
        ask(default, free(), store=store, key_for=Keys(), now=NOW)
    gemini_locations.terms.write_text("zzz-private\n")
    ask(default, free(), store=store, key_for=Keys(), now=NOW)
    assert len(server.requests) == 1


def test_the_config_accepts_only_none_default_or_an_absolute_terms_path(tmp_path: Path, ledger: Path) -> None:
    path = tmp_path / "c.yaml"
    path.write_text(yaml.safe_dump(config_dict("http://127.0.0.1:9", ledger, private_terms="relative.txt")))
    with pytest.raises(ConfigError, match="private_terms"):
        load_config(path)


def test_a_bidi_control_in_the_quote_is_refused(store: ApprovalStore) -> None:
    with pytest.raises(ConfigError, match="quote"):
        approve(store, quote="yes‮ up to 1.50")
