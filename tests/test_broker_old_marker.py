# SPDX-License-Identifier: Apache-2.0
"""Recovery refuses an earlier-month marker with no ledger row, and the runbook says what to do (#278)."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from brokerdata import new_ledger, state_dir
from safo.broker.errors import LedgerError
from safo.broker.ledger import CallLedger
from test_broker_admin import reserve

REFUSAL = "a used marker from an earlier month has no ledger row; root must reconcile it"
NOW = dt.datetime(2026, 10, 30, 12, 0, 0, tzinfo=dt.UTC)
DOCS = Path(__file__).resolve().parent.parent / "docs" / "gemini-broker.md"


def _stray(tmp: Path, ts: str) -> None:
    template = next((state_dir(tmp) / "used").iterdir())
    data = json.loads(template.read_text()) | {"nonce": "e" * 16, "call_id": "d" * 32, "ts": ts}
    stray = state_dir(tmp) / "used" / ("e" * 16)
    stray.write_text(json.dumps(data))
    stray.chmod(0o600)


def test_recovery_refuses_a_marker_from_an_earlier_month_with_no_ledger_row(tmp_path: Path) -> None:
    reserve(new_ledger(tmp_path), now=NOW)
    _stray(tmp_path, "2026-09-30T23:59:59Z")
    before = (state_dir(tmp_path) / "ledger.jsonl").read_bytes()
    with pytest.raises(LedgerError) as caught:
        CallLedger(state_dir(tmp_path)).recover(NOW + dt.timedelta(seconds=30))
    assert str(caught.value) == REFUSAL
    assert (state_dir(tmp_path) / "ledger.jsonl").read_bytes() == before  # and it wrote nothing


def test_a_marker_from_this_month_is_still_rebuilt_by_recovery(tmp_path: Path) -> None:
    reserve(new_ledger(tmp_path), now=NOW)
    _stray(tmp_path, "2026-10-01T00:00:00Z")
    assert "d" * 32 in CallLedger(state_dir(tmp_path)).recover(NOW + dt.timedelta(seconds=30))


def test_the_runbook_quotes_the_refusal_and_names_the_supported_step() -> None:
    text = " ".join(DOCS.read_text().split())
    assert REFUSAL in text
    assert "reconcile --billing-usd TOTAL --month YYYY-MM --reason TEXT" in text
    assert "Do not delete or edit the marker" in text
