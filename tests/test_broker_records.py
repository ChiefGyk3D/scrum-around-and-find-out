# SPDX-License-Identifier: Apache-2.0
"""Schema version 3: the signed approval text and the ledger rows, parsed strictly."""

from __future__ import annotations

import copy
import datetime as dt
import json
from typing import Any

import pytest

from brokerdata import EPOCH, FLAT, NOW, PROMPT, approval, image_text, request, signed_text
from safo import geminisign
from safo.broker.errors import LedgerError, Refused
from safo.broker.records import ROWS, ApprovalV3, check_binding, parse_approval, parse_stamp, validate_row


def good() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(signed_text())
    return data


def canon(data: dict[str, Any]) -> str:
    return geminisign.canonical(data)


# -- the approval --------------------------------------------------------------------------------------------------


def test_a_good_text_approval_parses() -> None:
    got = parse_approval(signed_text())
    assert isinstance(got, ApprovalV3)
    assert (got.kind, got.count, got.image_size, got.max_micro, got.beyond_ceiling) == ("text", 0, "", 2_500_000, False)
    assert got.expires_at == dt.datetime(2026, 10, 30, 12, 9, tzinfo=dt.UTC)


def test_a_good_image_approval_parses() -> None:
    got = parse_approval(image_text())
    assert (got.kind, got.count, got.image_size, got.aspect_ratio) == ("image", 1, "1K", "1:1")


@pytest.mark.parametrize("version", [1, 2])
def test_older_versions_are_refused_with_the_ask_again_message(version: int) -> None:
    with pytest.raises(Refused) as err:
        parse_approval(signed_text(version=version))
    assert err.value.code == "bad_approval"
    assert "fresh one" in str(err.value)
    assert "older format" in str(err.value)


@pytest.mark.parametrize("version", [0, 4, 99, -3, "3", 3.0, True, None, [3]])
def test_other_versions_are_refused(version: Any) -> None:
    data = good()
    data["version"] = version
    with pytest.raises(Refused) as err:
        parse_approval(canon(data))
    assert err.value.code == "bad_approval"


def test_every_required_field_is_required_and_no_extra_is_allowed() -> None:
    names = list(good())
    assert len(names) == 19
    for name in names:
        data = good()
        del data[name]
        with pytest.raises(Refused):
            parse_approval(canon(data))
    with pytest.raises(Refused):
        parse_approval(canon({**good(), "extra": 1}))
    for name in ("count", "image_size", "aspect_ratio"):  # image fields are forbidden on a text approval
        with pytest.raises(Refused):
            parse_approval(canon({**good(), name: 1}))
    for name in ("count", "image_size", "aspect_ratio"):  # and required on an image one
        data = json.loads(image_text())
        del data[name]
        with pytest.raises(Refused):
            parse_approval(canon(data))


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("nonce", "short"),
        ("nonce", "ABCDEF0123456789"),
        ("nonce", "g" * 16),
        ("nonce", 123),
        ("epoch", "x" * 16),
        ("model", "Bad Model"),
        ("model", ""),
        ("kind", "video"),
        ("kind", None),
        ("max_output_tokens", 0),
        ("max_output_tokens", -1),
        ("max_output_tokens", True),
        ("max_output_tokens", 1.5),
        ("max_output_tokens", "5"),
        ("max_output_tokens", 10_000_001),
        ("thinking_level", ""),
        ("thinking_level", 5),
        ("max_usd", "0"),
        ("max_usd", "2.50"),  # not the canonical spelling
        ("max_usd", "02"),
        ("max_usd", "1.0000001"),
        ("max_usd", 2.5),
        ("max_usd", "-1"),
        ("max_usd", "1e1"),
        ("job", "a b"),
        ("job", ""),
        ("job", "x" * 65),
        ("prompt_sha256", "A" * 64),
        ("prompt_sha256", "a" * 63),
        ("prompt_bytes", -1),
        ("prompt_bytes", 200_001),
        ("prompt_bytes", True),
        ("quote", ""),
        ("quote", "line\nbreak"),
        ("quote", "x" * 501),
        ("quote", 5),
        ("quoted_at", "2026-10-30 11:59:00"),
        ("quoted_at", "2026-10-30T11:59:00+00:00"),
        ("created", "2026-13-30T11:59:00Z"),
        ("expires_at", "2026-10-30T11:59:00Z"),  # not after created
        ("expires_at", "2026-10-30T13:00:01Z"),  # more than 60 minutes
        ("beyond_ceiling", 1),
        ("beyond_ceiling", "false"),
        ("ledger_head", "z" * 64),
        ("issue", "x" * 81),
        ("principal", ""),
        ("principal", "x" * 65),
    ],
)
def test_each_field_is_checked(name: str, value: Any) -> None:
    data = good()
    data[name] = value
    with pytest.raises(Refused) as err:
        parse_approval(canon(data))
    assert err.value.code == "bad_approval"


def test_the_text_must_be_the_canonical_bytes_that_were_signed() -> None:
    text = signed_text()
    parsed = json.loads(text)
    variants = [
        json.dumps(parsed),
        json.dumps(parsed, indent=2),
        " " + text,
        text + "\n",
        json.dumps(dict(reversed(list(parsed.items()))), separators=(",", ":")),
        text.replace("go ahead", "go ah\\u0065ad"),  # an escape spelling of the same text
    ]
    for variant in variants:
        assert variant != text
        with pytest.raises(Refused):
            parse_approval(variant)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "[]",
        "null",
        "3",
        '"x"',
        "{",
        '{"version":3,"version":3}',  # duplicate key
        '{"a":' * 100 + "1" + "}" * 100,  # deep
        "x" * 20_000,
        '{"version":NaN}',
        '{"version":3}',
    ],
)
def test_hostile_text_is_one_typed_refusal(text: str) -> None:
    with pytest.raises(Refused) as err:
        parse_approval(text)
    assert err.value.code == "bad_approval"


@pytest.mark.parametrize("value", [None, 3, b"{}", ["x"], {"version": 3}])
def test_the_text_must_be_a_string(value: Any) -> None:
    with pytest.raises(Refused):
        parse_approval(value)


def test_a_str_subclass_text_is_refused() -> None:
    class Lying(str):
        pass

    with pytest.raises(Refused):
        parse_approval(Lying(signed_text()))


def test_timestamps_are_exactly_the_stamp_format() -> None:
    assert parse_stamp("2026-10-30T12:00:00Z") == NOW
    bad = ("2026-10-30T12:00:00", "2026-10-30T12:00:00z", "2026-02-30T12:00:00Z", "2026-10-30T24:00:00Z", None, 5)
    for text in (*bad, " 2026-10-30T12:00:00Z"):
        assert parse_stamp(text) is None


# -- the binding ---------------------------------------------------------------------------------------------------


def test_the_binding_accepts_the_matching_request() -> None:
    req = request()
    check_binding(approval(req), req, epoch=EPOCH, now=NOW)


@pytest.mark.parametrize(
    ("over", "code"),
    [
        ({"epoch": "cd" * 16}, "bad_approval"),
        ({"model": "other-model"}, "model_mismatch"),
        ({"job": "other-job"}, "job_mismatch"),
        ({"prompt_sha256": "0" * 64}, "digest_mismatch"),
        ({"prompt_bytes": 1}, "digest_mismatch"),
        ({"kind": "image"}, "bad_approval"),
        ({"count": 1}, "bad_approval"),
        ({"image_size": "1K"}, "bad_approval"),
        ({"aspect_ratio": "1:1"}, "bad_approval"),
        ({"max_output_tokens": 999}, "bad_approval"),
        ({"thinking_level": "minimal"}, "bad_approval"),
        ({"expires_at": NOW}, "expired"),
        ({"expires_at": NOW - dt.timedelta(seconds=1)}, "expired"),
        ({"created": NOW + dt.timedelta(minutes=2)}, "bad_approval"),
    ],
)
def test_each_signed_field_must_match_the_request(over: dict[str, Any], code: str) -> None:
    req = request()
    with pytest.raises(Refused) as err:
        check_binding(approval(req, **over), req, epoch=EPOCH, now=NOW)
    assert err.value.code == code


def test_one_changed_prompt_byte_is_a_different_prompt() -> None:
    signed = request(prompt=PROMPT)
    for changed in (PROMPT + "\n", PROMPT[:-1], PROMPT.replace("a", "b", 1), PROMPT + " ", "﻿" + PROMPT):
        with pytest.raises(Refused) as err:
            check_binding(approval(signed), request(prompt=changed), epoch=EPOCH, now=NOW)
        assert err.value.code == "digest_mismatch"
    check_binding(approval(signed), request(prompt=PROMPT), epoch=EPOCH, now=NOW)


def test_the_last_second_of_an_approval_is_expired_not_valid() -> None:
    req = request()
    appr = approval(req, expires_at=NOW + dt.timedelta(seconds=1))
    check_binding(appr, req, epoch=EPOCH, now=NOW)
    with pytest.raises(Refused):
        check_binding(appr, req, epoch=EPOCH, now=NOW + dt.timedelta(seconds=1))


# -- ledger rows ---------------------------------------------------------------------------------------------------

H = "a" * 64
ID = "b" * 32
N = "c" * 16
ROW_SAMPLES: dict[str, dict[str, Any]] = {
    "approval_used": {"nonce": N, "call_id": ID, "model": FLAT, "job": "j", "epoch": EPOCH},
    "call_start": {
        "call_id": ID,
        "nonce": N,
        "model": FLAT,
        "kind": "text",
        "job": "j",
        "reserved_micro": 5,
        "prompt_sha256": H,
        "prompt_bytes": 3,
        "image_size": "",
        "count": 0,
    },
    "call_sent": {"call_id": ID},
    "call_end": {"call_id": ID, "status": "ok", "actual_micro": 3, "released_micro": 2, "breach": False},
    "ambiguous_call": {"call_id": ID, "model": FLAT, "reserved_micro": 5, "reason": "timeout"},
    "suspended": {"call_id": ID, "model": FLAT, "reason": "breach"},
    "ambiguous_resolved": {"call_id": ID, "actual_micro": 4},
    "suspension_cleared": {"model": FLAT},
    "admin_action": {
        "action": "clear",
        "uid": 0,
        "sudo_uid": 1000,
        "model": FLAT,
        "month": "",
        "add_micro": 0,
        "reason": "billing page",
    },
}


def row(kind: str, **over: Any) -> dict[str, Any]:
    out = {"type": kind, "ts": "2026-10-30T12:00:00Z", "v": 3, "prev_hash": H, "hash": H, **ROW_SAMPLES[kind]}
    out.update(over)
    return out


def test_every_row_type_has_a_sample_and_each_sample_validates() -> None:
    assert set(ROW_SAMPLES) == set(ROWS)
    for kind in ROWS:
        assert validate_row(row(kind)) == kind


@pytest.mark.parametrize("kind", sorted(ROW_SAMPLES))
def test_a_row_must_be_exactly_its_keys(kind: str) -> None:
    for name in list(row(kind)):
        broken = row(kind)
        del broken[name]
        with pytest.raises(LedgerError):
            validate_row(broken)
    with pytest.raises(LedgerError):
        validate_row({**row(kind), "extra": 1})


@pytest.mark.parametrize("kind", sorted(ROW_SAMPLES))
def test_each_row_field_rejects_wrong_types_and_ranges(kind: str) -> None:
    for name, value in ROW_SAMPLES[kind].items():
        wrongs: list[Any] = [None, [], {}, 1.5, -1, True, "", "Z Z", 10**13, "x" * 200]
        if type(value) is bool:
            wrongs = [0, 1, "true", None]
        for wrong in wrongs:
            if wrong == value and type(wrong) is type(value):
                continue
            if (kind, name, wrong) == ("call_start", "image_size", ""):
                continue  # an empty size is what a text call records
            if kind == "admin_action" and (name, wrong) in [
                ("sudo_uid", -1),  # no sudo
                ("reason", ""),
                ("reason", "Z Z"),  # a reason is free printable text
                ("month", ""),  # a clear names no month
                ("model", ""),  # an adjustment names no model
            ]:
                continue
            bad = copy.deepcopy(row(kind))
            bad[name] = wrong
            with pytest.raises(LedgerError):
                validate_row(bad)


@pytest.mark.parametrize("version", [0, 1, 2, 4, 99, "3", 3.0, True, None])
def test_a_row_of_another_schema_version_is_refused(version: Any) -> None:
    with pytest.raises(LedgerError):
        validate_row(row("call_sent", v=version))


@pytest.mark.parametrize(
    "bad", [{}, {"type": 1}, {"type": "mystery"}, {"type": []}, {"type": None}, {"type": "chain_start"}]
)
def test_unknown_or_missing_types_are_refused(bad: dict[str, Any]) -> None:
    with pytest.raises(LedgerError):
        validate_row(bad)


def test_chain_start_must_have_no_legacy_rows() -> None:
    start = {"type": "chain_start", "ts": "2026-10-30T12:00:00Z", "legacy_rows": 0, "prev_hash": H, "hash": H}
    assert validate_row(start) == "chain_start"
    for bad in (
        {**start, "legacy_rows": 1},
        {**start, "legacy_rows": True},
        {**start, "ts": "x"},
        {**start, "extra": 1},
    ):
        with pytest.raises(LedgerError):
            validate_row(bad)
