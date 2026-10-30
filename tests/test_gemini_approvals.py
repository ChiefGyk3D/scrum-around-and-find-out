# SPDX-License-Identifier: Apache-2.0
"""Signed approvals at the paid gate (#200): what a record must be, and what each refusal protects.

The record is `{"payload": canonical JSON, "signature": SSH signature}`. A test forges what an attacker could try (an
unsigned record, an edited payload, a signature by another key or namespace, an old head, a replayed nonce) and shows
the paid call is refused with nothing sent.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import secrets
import unicodedata
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

PROMPT = "Summarize these public advisories."

KEY_ARGS: dict[str, Any] = {
    "prompt": PROMPT,
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
        "prompt": PROMPT,
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
        "version": 2,
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
        "prompt_sha256": hashlib.sha256(PROMPT.encode()).hexdigest(),
        "prompt_bytes": len(PROMPT.encode()),
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

# -- the signature binds the prompt (#217) ---------------------------------------------------------------------------

A_PROMPT = "Summarize these public advisories."
NFC = unicodedata.normalize("NFC", "Résumé of the public advisories.")
NFD = unicodedata.normalize("NFD", NFC)


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def forge_issued(
    store: ApprovalStore, data: dict[str, Any], *, key: str, row: dict[str, Any] | None = None, with_row: bool = True
) -> str:
    """Forge a signed record AND the ledger issuance row after its head, so only the fields under test can refuse it."""
    nonce = forge(store, data, key=key)
    assert store.ledger is not None
    if with_row:
        issued = {"type": "approval_issued", "nonce": nonce, "principal": "test-key-a", "ts": stamp(NOW)}
        issued.update({"prompt_sha256": data.get("prompt_sha256", ""), "prompt_bytes": data.get("prompt_bytes", 0)})
        issued.update(row or {})
        with store.ledger.lock():
            store.ledger.append(issued)
    return nonce


def test_the_issued_payload_and_ledger_row_carry_the_prompt_digest_and_length(
    cfg: GeminiConfig, store: ApprovalStore
) -> None:
    record = store.issue(**KEY_ARGS)
    data = json.loads(json.loads((store.folder / f"{record.id}.json").read_text())["payload"])
    assert data["version"] == 2
    assert data["prompt_sha256"] == sha(A_PROMPT) and data["prompt_bytes"] == len(A_PROMPT.encode())
    assert record.prompt_sha256 == sha(A_PROMPT) and record.prompt_bytes == len(A_PROMPT.encode())
    row = next(r for r in ledger_rows(cfg.ledger, everything=True) if r["type"] == "approval_issued")
    assert row["prompt_sha256"] == sha(A_PROMPT) and row["prompt_bytes"] == len(A_PROMPT.encode())


@pytest.mark.parametrize(
    ("approved", "sent"),
    [
        pytest.param(A_PROMPT, A_PROMPT.replace("public", "publiC"), id="one-byte"),
        pytest.param(A_PROMPT, A_PROMPT + "\n", id="trailing-newline"),
        pytest.param(A_PROMPT, A_PROMPT[:-1], id="shorter"),
        pytest.param(NFC, NFD, id="unicode-normalization"),
        pytest.param(NFD, NFC, id="unicode-normalization-reverse"),
    ],
)
def test_an_approval_for_one_prompt_is_refused_for_another_and_is_not_spent(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, approved: str, sent: str
) -> None:
    assert approved != sent and sha(approved) != sha(sent)
    record = store.issue(**{**KEY_ARGS, "prompt": approved})
    refuse_and_send_nothing(cfg, server, store, record.id, "prompt", prompt=sent)
    assert not store.is_used(record.id), "a refused prompt must not burn the approval"
    assert not [r for r in ledger_rows(cfg.ledger, everything=True) if r["type"] == "approval_used"]
    ask(cfg, paid(record.id, prompt=approved), store=store, key_for=keys, now=NOW)  # the exact prompt still works
    assert len(server.requests) == 1


def test_a_mismatch_says_the_approval_does_not_cover_this_prompt(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    record = store.issue(**KEY_ARGS)
    with pytest.raises(RefusedError, match="does not cover this prompt"):
        ask(cfg, paid(record.id, prompt=A_PROMPT + " "), store=store, key_for=keys, now=NOW)


@pytest.mark.parametrize("missing", ["prompt_sha256", "prompt_bytes"])
def test_a_validly_signed_approval_without_the_prompt_field_is_refused(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, key: str, missing: str
) -> None:
    data = payload_for(store)
    del data[missing]
    nonce = forge_issued(store, data, key=key)
    refuse_and_send_nothing(cfg, server, store, nonce, "prompt")
    assert "prompt" in str(approval_problem(store, nonce, NOW))


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param("", id="empty"),
        pytest.param("ab" * 31, id="short"),
        pytest.param("AB" * 32, id="uppercase"),
        pytest.param("zz" * 32, id="not-hex"),
        pytest.param(5, id="not-text"),
        pytest.param(None, id="null"),
    ],
)
def test_a_malformed_digest_in_a_signed_approval_is_refused(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, key: str, bad: object
) -> None:
    nonce = forge_issued(store, payload_for(store, prompt_sha256=bad), key=key)
    refuse_and_send_nothing(cfg, server, store, nonce, "prompt")


@pytest.mark.parametrize("bad", [-1, True, "3", None, 10**9])
def test_a_malformed_prompt_length_in_a_signed_approval_is_refused(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, key: str, bad: object
) -> None:
    nonce = forge_issued(store, payload_for(store, prompt_bytes=bad), key=key)
    refuse_and_send_nothing(cfg, server, store, nonce, "prompt")


def test_a_right_digest_with_a_wrong_signed_length_is_refused(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, key: str
) -> None:
    nonce = forge_issued(store, payload_for(store, prompt_bytes=len(PROMPT) + 1), key=key)
    refuse_and_send_nothing(cfg, server, store, nonce, "prompt")


@pytest.mark.parametrize("old", [1, 0, 3, "2", None])
def test_an_approval_of_another_version_fails_closed_with_a_clear_message(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, key: str, old: object
) -> None:
    nonce = forge_issued(store, payload_for(store, version=old), key=key)
    refuse_and_send_nothing(cfg, server, store, nonce, "older format|version")
    assert "fresh" in str(approval_problem(store, nonce, NOW))


def test_a_version_one_approval_is_never_read_as_unbound(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, key: str
) -> None:
    data = payload_for(store, version=1)
    del data["prompt_sha256"], data["prompt_bytes"]  # exactly what the old code signed
    nonce = forge_issued(store, data, key=key, with_row=False)
    refuse_and_send_nothing(cfg, server, store, nonce, "no prompt binding")


def test_the_positive_control_a_forged_record_with_a_matching_row_is_accepted(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, key: str
) -> None:
    nonce = forge_issued(store, payload_for(store), key=key)
    ask(cfg, paid(nonce), store=store, key_for=keys, now=NOW)
    assert len(server.requests) == 1


@pytest.mark.parametrize(
    "row",
    [
        pytest.param({"prompt_sha256": sha("another prompt")}, id="other-digest"),
        pytest.param({"prompt_sha256": ""}, id="empty-digest"),
        pytest.param({"prompt_sha256": None}, id="null-digest"),
        pytest.param({"prompt_bytes": 1}, id="other-length"),
        pytest.param({"prompt_bytes": None}, id="no-length"),
    ],
)
def test_a_signed_digest_that_the_nonce_record_does_not_confirm_is_refused(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, key: str, row: dict[str, Any]
) -> None:
    nonce = forge_issued(store, payload_for(store), key=key, row=row)
    refuse_and_send_nothing(cfg, server, store, nonce, "issuance")


def test_an_issuance_row_without_the_digest_does_not_confirm_the_approval(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, key: str
) -> None:
    data = payload_for(store)
    nonce = forge(store, data, key=key)
    assert store.ledger is not None
    with store.ledger.lock():  # a row from before the field existed
        store.ledger.append({"type": "approval_issued", "nonce": nonce, "principal": "test-key-a", "ts": stamp(NOW)})
    refuse_and_send_nothing(cfg, server, store, nonce, "issuance")


def test_a_replay_still_fails_and_a_mismatch_does_not_hide_it(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    record = store.issue(**KEY_ARGS)
    ask(cfg, paid(record.id), store=store, key_for=keys, now=NOW)
    assert ask_again_refused(cfg, store, record.id)
    with pytest.raises(RefusedError, match="already used"):
        ask(cfg, paid(record.id, prompt="something else"), store=store, key_for=keys, now=NOW)
    assert len(server.requests) == 1


def test_expiry_is_unchanged_by_the_binding(cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore) -> None:
    record = store.issue(**{**KEY_ARGS, "ttl_minutes": 10})
    ask(cfg, paid(record.id), store=store, key_for=keys, now=NOW + dt.timedelta(minutes=9))
    again = store.issue(**{**KEY_ARGS, "ttl_minutes": 10})
    with pytest.raises(RefusedError, match="expired"):
        ask(cfg, paid(again.id), store=store, key_for=keys, now=NOW + dt.timedelta(minutes=10))


def test_the_digest_is_compared_with_compare_digest_on_bytes(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    import hmac

    from safo import gemini

    calls: list[tuple[object, object]] = []
    real = hmac.compare_digest

    def spy(a: Any, b: Any) -> bool:
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(gemini.hmac, "compare_digest", spy)
    record = store.issue(**KEY_ARGS)
    ask(cfg, paid(record.id), store=store, key_for=keys, now=NOW)
    digest = sha(A_PROMPT).encode()
    assert [c for c in calls if c == (digest, digest)], "the digest was compared as bytes with compare_digest"
    assert all(type(a) is bytes and type(b) is bytes for a, b in calls)


def test_a_str_subclass_cannot_bend_the_digest_comparison() -> None:
    from safo.gemini import digests_equal

    class Liar(str):
        def __eq__(self, other: object) -> bool:
            return True

        def __ne__(self, other: object) -> bool:
            return False

        def encode(self, *args: Any, **kw: Any) -> bytes:
            return b"x" * 64

        __hash__ = str.__hash__

    good = sha(A_PROMPT)
    assert digests_equal(good, good)
    assert not digests_equal(Liar("0" * 64), good) and not digests_equal(good, Liar(good))
    assert not digests_equal(good, sha("other")) and not digests_equal(good, "") and not digests_equal(good, 5)


def test_the_free_path_needs_no_approval_and_leaves_no_binding(
    cfg: GeminiConfig, server: FakeGemini, store: ApprovalStore
) -> None:
    reply = ask(
        cfg,
        Request(model=MODEL, prompt="What changed in the CVE list?", tier="free"),
        store=store,
        key_for=keys,
        now=NOW,
    )
    assert reply.text and len(server.requests) == 1
    assert not [r for r in ledger_rows(cfg.ledger, everything=True) if r["type"].startswith("approval")]


def test_the_issued_payload_satisfies_the_passkey_expect_mapping(store: ApprovalStore) -> None:
    from safo import geminipasskey
    from safo.geminipasskey import Tier2Refused

    record = store.issue(**KEY_ARGS)
    text = json.loads((store.folder / f"{record.id}.json").read_text())["payload"]
    expect = {"nonce": record.id, "model": MODEL, "prompt_sha256": sha(A_PROMPT)}
    geminipasskey._check_approval(text, expect, NOW)  # same field name, same digest form: no refusal
    with pytest.raises(Tier2Refused, match="prompt_sha256"):
        geminipasskey._check_approval(text, {**expect, "prompt_sha256": sha(A_PROMPT + "\n")}, NOW)


def test_issue_refuses_a_prompt_that_cannot_be_encoded(store: ApprovalStore) -> None:
    with pytest.raises(RefusedError, match="prompt"):
        store.issue(**{**KEY_ARGS, "prompt": "lone \ud800 surrogate"})
