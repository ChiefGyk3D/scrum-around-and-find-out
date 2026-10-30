# SPDX-License-Identifier: Apache-2.0
"""Signed approvals at the paid gate (#200): what a record must be, and what each refusal protects.

The record is `{"payload": canonical JSON, "signature": SSH signature}`. A test forges what an attacker could try (an
unsigned record, an edited payload, a signature by another key or namespace, an old head, a replayed nonce) and shows
the paid call is refused with nothing sent.
"""

from __future__ import annotations

import datetime as dt
import json
import secrets
from collections.abc import Iterator
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from geminidata import MODEL, NOW, FakeGemini, ledger_rows, make_key, minutes_ago, seed, start_row, write_config
from safo import geminisign
from safo.errors import ConfigError
from safo.gemini import (
    ApprovalStore,
    GeminiConfig,
    Ledger,
    Locations,
    RefusedError,
    Request,
    approval_problem,
    ask,
    load_config,
    open_store,
    stamp,
)

KEY_ARGS: dict[str, Any] = {
    "model": MODEL,
    "max_usd": Decimal("1.50"),
    "job": "job-1",
    "quote": "yes, up to 1.50",
    "quoted_at": NOW - dt.timedelta(minutes=5),
    "now": NOW,
    "ttl_minutes": 60,
    "beyond_ceiling": False,
}


@pytest.fixture
def server() -> Iterator[FakeGemini]:
    with FakeGemini().serve() as fake:
        yield fake


@pytest.fixture
def cfg(tmp_path: Path, server: FakeGemini) -> GeminiConfig:
    return load_config(write_config(tmp_path / "gemini.yaml", server.url, tmp_path / "data" / "ledger.jsonl"))


@pytest.fixture
def key(gemini_locations: Locations) -> str:
    return str(gemini_locations.home / "key")


@pytest.fixture
def store(cfg: GeminiConfig, gemini_locations: Locations, key: str) -> ApprovalStore:
    return open_store(gemini_locations, cfg.ledger, key, "test-key-a")


def keys(_prompt: str) -> str:
    return "FAKE-KEY-for-tests-0123456789"


def paid(record_id: str, **kw: Any) -> Request:
    args: dict[str, Any] = {
        "model": MODEL,
        "prompt": "Summarize these public advisories.",
        "tier": "paid",
        "job": "job-1",
        "approval": record_id,
        "max_output_tokens": 500,
    }
    args.update(kw)
    return Request(**args)


def payload_for(store: ApprovalStore, **over: Any) -> dict[str, Any]:
    """What `issue` would sign, as a dict, so a test can change one field and sign it for real."""
    assert store.ledger is not None
    with store.ledger.lock():
        head = store.ledger.ensure_chain(stamp(NOW))
    data: dict[str, Any] = {
        "version": 1,
        "nonce": secrets.token_hex(8),
        "model": MODEL,
        "max_usd": "1.50",
        "job": "job-1",
        "quote": "yes, up to 1.50",
        "quoted_at": stamp(NOW - dt.timedelta(minutes=5)),
        "created": stamp(NOW),
        "expires_at": stamp(NOW + dt.timedelta(minutes=60)),
        "beyond_ceiling": False,
        "ledger_head": head,
        "issue": "",
        "principal": "test-key-a",
    }
    data.update(over)
    return data


def forge(store: ApprovalStore, data: dict[str, Any], *, key: str, namespace: str = geminisign.NAMESPACE) -> str:
    """Write a record for `data` signed with `key` (a real signature by whichever key the test picks)."""
    text = geminisign.canonical(data)
    armor = geminisign.sign(key, text.encode(), namespace, {})
    store.folder.mkdir(parents=True, exist_ok=True)
    (store.folder / f"{data['nonce']}.json").write_text(json.dumps({"payload": text, "signature": armor}))
    return str(data["nonce"])


def refuse_and_send_nothing(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, record: str, match: str, **kw: Any
) -> None:
    with pytest.raises(RefusedError, match=match):
        ask(cfg, paid(record, **kw), store=store, key_for=keys, now=NOW)
    assert server.requests == []


# -- the happy path and what it records ------------------------------------------------------------------------------


def test_a_signed_approval_spends_once_and_the_ledger_names_who_approved(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    record = store.issue(**KEY_ARGS)
    assert record.principal == "test-key-a" and record.ledger_head
    ask(cfg, paid(record.id), store=store, key_for=keys, now=NOW)
    rows = ledger_rows(cfg.ledger, everything=True)
    issued = next(r for r in rows if r["type"] == "approval_issued")
    used = next(r for r in rows if r["type"] == "approval_used")
    assert issued["principal"] == used["principal"] == "test-key-a" and issued["tier"] == used["tier"] == 1
    assert issued["nonce"] == used["nonce"] == record.id and issued["key_kind"] == "software"
    assert [r["type"] for r in rows if r["type"] in ("call_start", "call_end")] == ["call_start", "call_end"]
    assert ask_again_refused(cfg, store, record.id)


def ask_again_refused(cfg: GeminiConfig, store: ApprovalStore, record_id: str) -> bool:
    try:
        ask(cfg, paid(record_id), store=store, key_for=keys, now=NOW)
    except RefusedError as err:
        return "already used" in str(err)
    return False


def test_the_record_holds_a_payload_and_a_signature_not_plain_fields(store: ApprovalStore) -> None:
    record = store.issue(**KEY_ARGS)
    outer = json.loads((store.folder / f"{record.id}.json").read_text())
    assert set(outer) == {"payload", "signature"} and outer["signature"].startswith("-----BEGIN SSH SIGNATURE-----")
    assert json.loads(outer["payload"])["principal"] == "test-key-a"
    assert outer["payload"] == geminisign.canonical(json.loads(outer["payload"]))


# -- refusals ---------------------------------------------------------------------------------------------------------


def test_the_old_unsigned_format_authorizes_nothing(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    old = {
        "id": "0123456789abcdef",
        "model": MODEL,
        "max_usd": "1.50",
        "job": "job-1",
        "quote": "yes",
        "quoted_at": stamp(NOW),
        "created": stamp(NOW),
        "expires_at": stamp(NOW + dt.timedelta(hours=1)),
        "beyond_ceiling": False,
        "issue": "",
    }
    store.folder.mkdir(parents=True)
    (store.folder / "0123456789abcdef.json").write_text(json.dumps(old))
    refuse_and_send_nothing(cfg, server, store, "0123456789abcdef", "not a signed approval")
    assert approval_problem(store, "0123456789abcdef", NOW) is not None


@pytest.mark.parametrize("signature", ["", "nonsense"])
def test_a_payload_with_no_real_signature_authorizes_nothing(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, signature: str
) -> None:
    data = payload_for(store)
    store.folder.mkdir(parents=True)
    (store.folder / f"{data['nonce']}.json").write_text(
        json.dumps({"payload": geminisign.canonical(data), "signature": signature})
    )
    refuse_and_send_nothing(cfg, server, store, data["nonce"], "signature")


def test_an_edited_payload_no_longer_verifies(cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore) -> None:
    record = store.issue(**{**KEY_ARGS, "max_usd": Decimal("0.50")})
    path = store.folder / f"{record.id}.json"
    outer = json.loads(path.read_text())
    outer["payload"] = outer["payload"].replace('"max_usd":"0.50"', '"max_usd":"1.50"')
    path.write_text(json.dumps(outer))
    refuse_and_send_nothing(cfg, server, store, record.id, "does not verify")


def test_a_signature_by_a_key_nobody_enrolled_is_refused(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, tmp_path: Path
) -> None:
    stranger = str(make_key(tmp_path / "stranger"))
    nonce = forge(store, payload_for(store), key=stranger)
    refuse_and_send_nothing(cfg, server, store, nonce, "enrolled")


def test_a_signature_for_another_namespace_is_refused(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, key: str
) -> None:
    nonce = forge(store, payload_for(store), key=key, namespace="file")
    refuse_and_send_nothing(cfg, server, store, nonce, "namespace")


def test_a_validly_signed_amount_over_the_cap_is_refused(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, key: str
) -> None:
    nonce = forge(store, payload_for(store, max_usd="5.00"), key=key)
    refuse_and_send_nothing(cfg, server, store, nonce, "caps")


def test_a_validly_signed_long_lifetime_is_refused(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, key: str
) -> None:
    long = stamp(NOW + dt.timedelta(days=3))
    nonce = forge(store, payload_for(store, expires_at=long), key=key)
    refuse_and_send_nothing(cfg, server, store, nonce, "caps")


def test_a_payload_that_is_not_canonical_is_refused_even_if_signed(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, key: str
) -> None:
    data = payload_for(store)
    text = json.dumps(data, sort_keys=True, indent=1)
    armor = geminisign.sign(key, text.encode(), geminisign.NAMESPACE, {})
    store.folder.mkdir(parents=True)
    (store.folder / f"{data['nonce']}.json").write_text(json.dumps({"payload": text, "signature": armor}))
    refuse_and_send_nothing(cfg, server, store, data["nonce"], "malformed")


def test_a_record_copied_to_another_id_is_refused(cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore) -> None:
    record = store.issue(**KEY_ARGS)
    (store.folder / "ffffffffffffffff.json").write_text((store.folder / f"{record.id}.json").read_text())
    refuse_and_send_nothing(cfg, server, store, "ffffffffffffffff", "malformed")


def test_the_principal_in_the_signed_text_must_be_the_signer(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, key: str
) -> None:
    nonce = forge(store, payload_for(store, principal="someone-else"), key=key)
    refuse_and_send_nothing(cfg, server, store, nonce, "malformed")


def test_a_wrong_model_or_job_is_still_refused_when_signed(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    record = store.issue(**KEY_ARGS)
    refuse_and_send_nothing(cfg, server, store, record.id, "job", job="job-2")


def test_an_expired_signed_approval_is_refused(cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore) -> None:
    record = store.issue(**{**KEY_ARGS, "ttl_minutes": 10})
    with pytest.raises(RefusedError, match="expired"):
        ask(cfg, paid(record.id), store=store, key_for=keys, now=NOW + dt.timedelta(minutes=11))
    assert server.requests == []


# -- single use is in the ledger -------------------------------------------------------------------------------------


def test_a_nonce_stays_spent_when_the_marker_file_is_deleted(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    record = store.issue(**KEY_ARGS)
    ask(cfg, paid(record.id), store=store, key_for=keys, now=NOW)
    (store.folder / f"{record.id}.used").unlink()
    refuse_and_send_nothing_after(cfg, server, store, record.id)


def refuse_and_send_nothing_after(cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, record: str) -> None:
    with pytest.raises(RefusedError, match="already used"):
        ask(cfg, paid(record), store=store, key_for=keys, now=NOW)
    assert len(server.requests) == 1
    assert approval_problem(store, record, NOW) == "this approval record was already used"


# -- the signature binds the ledger it was made against --------------------------------------------------------------


def test_an_approval_signed_against_a_ledger_that_was_replaced_is_refused(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    seed(cfg.ledger, start_row(minutes_ago(3000), tier="paid", usd=9.0, call_id="p"))
    record = store.issue(**KEY_ARGS)
    cfg.ledger.unlink()
    cfg.ledger.with_name(cfg.ledger.name + ".head").unlink()
    for height in Ledger(cfg.ledger).height_file.parent.glob("*"):  # an attacker who can also remove the height record
        height.unlink()
    Ledger(cfg.ledger).append({"type": "usage", "date": "2026-10-29", "amount_usd": 0, "note": "fresh start"})
    refuse_and_send_nothing(cfg, server, store, record.id, "ledger head")
    assert "ledger head" in str(approval_problem(store, record.id, NOW))


def test_a_head_that_never_existed_is_refused(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, key: str
) -> None:
    nonce = forge(store, payload_for(store, ledger_head="0" * 64), key=key)
    refuse_and_send_nothing(cfg, server, store, nonce, "ledger head")


def test_a_record_stays_valid_while_the_ledger_grows(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    record = store.issue(**KEY_ARGS)
    seed(cfg.ledger, start_row(minutes_ago(1), call_id="x"))
    ask(cfg, paid(record.id), store=store, key_for=keys, now=NOW)
    assert len(server.requests) == 1


# -- who may sign, at the moment of spending -------------------------------------------------------------------------


def test_a_key_revoked_after_the_approval_cannot_spend_it(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, gemini_locations: Locations
) -> None:
    record = store.issue(**KEY_ARGS)
    pub = (gemini_locations.home / "key.pub").read_text().split()
    gemini_locations.revoked.write_text(f"{pub[0]} {pub[1]} lost\n")
    gemini_locations.revoked.chmod(0o644)
    refuse_and_send_nothing(cfg, server, store, record.id, "revoked")


def test_issue_refuses_when_the_key_is_not_enrolled_and_writes_nothing(
    cfg: GeminiConfig, gemini_locations: Locations, tmp_path: Path
) -> None:
    stranger = str(make_key(tmp_path / "stranger"))
    store = open_store(gemini_locations, cfg.ledger, stranger, "test-key-a")
    with pytest.raises(RefusedError, match="enrolled"):
        store.issue(**KEY_ARGS)
    assert not store.folder.exists() or list(store.folder.glob("*.json")) == []


def test_issue_refuses_when_the_signer_is_not_the_named_principal(
    cfg: GeminiConfig, gemini_locations: Locations, key: str
) -> None:
    store = open_store(gemini_locations, cfg.ledger, key, "backup-1")
    with pytest.raises(RefusedError, match="principal"):
        store.issue(**KEY_ARGS)
    assert not store.folder.exists() or list(store.folder.glob("*.json")) == []


def test_issue_needs_signing_to_be_set_up(cfg: GeminiConfig, gemini_locations: Locations) -> None:
    for store in (
        open_store(gemini_locations, cfg.ledger, "", "test-key-a"),
        open_store(gemini_locations, cfg.ledger, "/x", ""),
        ApprovalStore(gemini_locations.approvals),
    ):
        with pytest.raises(ConfigError, match="signing is not set up"):
            store.issue(**KEY_ARGS)


def test_a_store_with_no_trust_files_refuses_every_record(cfg: GeminiConfig, tmp_path: Path) -> None:
    with pytest.raises(RefusedError, match="not set up"):
        ApprovalStore(tmp_path / "a").load("0123456789abcdef")


def test_the_default_refuses_a_software_approval_key(cfg: GeminiConfig, gemini_locations: Locations, key: str) -> None:
    import dataclasses

    strict = dataclasses.replace(gemini_locations, require_hardware=True)
    store = open_store(strict, cfg.ledger, key, "test-key-a")
    with pytest.raises(RefusedError, match="not a hardware key"):
        store.issue(**KEY_ARGS)


# -- a rewound ledger cannot replay an approval (a: issuance, b: short window, c: height record) ----------------------


def rewind(cfg: GeminiConfig, keep_through: str, *, drop_height: bool) -> None:
    """What an attacker with write access to the ledger can do: cut it back to a chosen row, make the head file agree,
    and (optionally) remove the separately kept height record too."""
    lines = cfg.ledger.read_text().splitlines()
    kept: list[str] = []
    for line in lines:
        kept.append(line)
        if json.loads(line).get("hash") == keep_through:
            break
    else:
        raise AssertionError("row not found")
    cfg.ledger.write_text("\n".join(kept) + "\n")
    first = next(i for i, x in enumerate(kept) if json.loads(x)["type"] == "chain_start")
    cfg.ledger.with_name(cfg.ledger.name + ".head").write_text(f"{len(kept) - first} {keep_through}\n")
    if drop_height:
        for height in Ledger(cfg.ledger).height_file.parent.glob("*"):
            height.unlink()


def row_hash(cfg: GeminiConfig, kind: str) -> str:
    return str(next(r["hash"] for r in ledger_rows(cfg.ledger, everything=True) if r["type"] == kind))


def test_an_approval_rewound_to_its_signed_head_loses_its_issuance_and_is_refused(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    seed(cfg.ledger, start_row(minutes_ago(30), call_id="old"))
    record = store.issue(**KEY_ARGS)
    rewind(cfg, record.ledger_head, drop_height=True)  # the head is still a member of the chain
    assert record.ledger_head in {r.get("hash") for r in ledger_rows(cfg.ledger, everything=True)}
    refuse_and_send_nothing(cfg, server, store, record.id, "issuance")
    assert "issuance" in str(approval_problem(store, record.id, NOW))


def test_an_issuance_row_by_another_principal_does_not_count(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, key: str
) -> None:
    data = payload_for(store)
    nonce = forge(store, data, key=key)
    assert store.ledger is not None
    with store.ledger.lock():
        store.ledger.append({"type": "approval_issued", "nonce": nonce, "principal": "someone-else", "ts": stamp(NOW)})
    refuse_and_send_nothing(cfg, server, store, nonce, "issuance")


def test_an_issuance_row_recorded_before_the_head_does_not_count(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, key: str
) -> None:
    data = payload_for(store)
    assert store.ledger is not None
    with store.ledger.lock():
        store.ledger.append(
            {"type": "approval_issued", "nonce": data["nonce"], "principal": "test-key-a", "ts": stamp(NOW)}
        )
        data["ledger_head"] = store.ledger.state().head  # signed after the issuance row, so it is not after the head
    nonce = forge(store, data, key=key)
    refuse_and_send_nothing(cfg, server, store, nonce, "issuance")


def test_a_rewind_to_just_after_the_issuance_is_caught_by_the_height_record(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    record = store.issue(**KEY_ARGS)
    issued = row_hash(cfg, "approval_issued")
    height_before = Ledger(cfg.ledger).state().chained
    ask(cfg, paid(record.id), store=store, key_for=keys, now=NOW)
    assert len(server.requests) == 1
    rewind(cfg, issued, drop_height=False)  # drops approval_used and the call rows
    (store.folder / f"{record.id}.used").unlink()
    with pytest.raises(RefusedError, match=rf"recorded height {height_before + 3}") as err:
        ask(cfg, paid(record.id), store=store, key_for=keys, now=NOW)
    assert "shorter" in str(err.value)
    assert len(server.requests) == 1, "the replay sent nothing"


def test_the_height_record_is_kept_apart_from_the_ledger_and_only_grows(
    cfg: GeminiConfig, store: ApprovalStore
) -> None:
    ledger = Ledger(cfg.ledger)
    assert not ledger.height_file.exists()
    store.issue(**KEY_ARGS)
    first = ledger.height_file.read_text().split()
    assert ledger.height_file.parent != cfg.ledger.parent and first[0] == str(ledger.state().chained)
    seed(cfg.ledger, start_row(minutes_ago(1), call_id="x"))
    assert int(ledger.height_file.read_text().split()[0]) == ledger.state().chained > int(first[0])


def test_a_height_record_that_the_chain_no_longer_matches_is_refused(cfg: GeminiConfig, store: ApprovalStore) -> None:
    store.issue(**KEY_ARGS)
    ledger = Ledger(cfg.ledger)
    count = ledger.height_file.read_text().split()[0]
    ledger.height_file.write_text(f"{count} {'0' * 64}\n")
    with pytest.raises(RefusedError, match="height record"):
        ledger.read()
    ledger.height_file.write_text("garbage\n")
    with pytest.raises(RefusedError, match="height record"):
        ledger.read()


def test_a_signed_lifetime_over_an_hour_is_refused_and_the_default_is_ten_minutes(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, key: str
) -> None:
    with pytest.raises(ConfigError, match="1 to 60"):
        store.issue(**{**KEY_ARGS, "ttl_minutes": 61})
    nonce = forge(store, payload_for(store, expires_at=stamp(NOW + dt.timedelta(minutes=61))), key=key)
    refuse_and_send_nothing(cfg, server, store, nonce, "caps")
    from safo.modes.gemini import brief_namespace

    assert brief_namespace(["approve", "--model", MODEL]).ttl_minutes == 10


def test_a_replaced_ledger_is_caught_by_the_height_record_when_that_was_left_alone(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    store.issue(**KEY_ARGS)
    cfg.ledger.unlink()
    cfg.ledger.with_name(cfg.ledger.name + ".head").unlink()
    with pytest.raises(RefusedError, match="height"):
        Ledger(cfg.ledger).append({"type": "usage", "date": "2026-10-29", "amount_usd": 0, "note": "fresh start"})
    assert server.requests == []
