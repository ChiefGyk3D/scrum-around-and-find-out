# SPDX-License-Identifier: Apache-2.0
"""The hash-chained ledger (#200): tamper evidence for the month's spend.

A chain proves that rows were not silently edited, removed or reordered after `chain_start`. It does not stop someone
who rewrites the whole file AND the head file; the signed approval's ledger head is what ties a rewrite to a fresh
signature (tests/test_gemini_approvals.py).
"""

from __future__ import annotations

import hashlib
import itertools
import json
from pathlib import Path

import pytest

from safo.gemini import Ledger, RefusedError, snapshot

LEGACY = [
    {"date": "2026-10-29", "type": "funding", "amount_usd": 25, "source": "maintainer statement"},
    {"date": "2026-10-29", "type": "usage", "amount_usd": 0, "note": "two rejected test calls"},
]


@pytest.fixture
def path(tmp_path: Path) -> Path:
    p = tmp_path / "data" / "ledger.jsonl"
    p.parent.mkdir()
    p.write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in LEGACY))
    return p


def chained(path: Path, extra: int = 4) -> Ledger:
    ledger = Ledger(path)
    for i in range(extra):
        ledger.append({"type": "usage", "date": "2026-10-29", "amount_usd": i, "note": f"n{i}"})
    return ledger


def lines(path: Path) -> list[str]:
    return path.read_text().splitlines()


def write(path: Path, rows: list[str]) -> None:
    path.write_text("\n".join(rows) + "\n")


def test_the_old_rows_stay_byte_for_byte_and_a_chain_start_is_appended(path: Path) -> None:
    before = path.read_bytes()
    chained(path, 1)
    assert path.read_bytes().startswith(before)
    first = json.loads(lines(path)[2])
    assert first["type"] == "chain_start" and first["legacy_rows"] == 2
    assert first["prev_hash"] == hashlib.sha256(before).hexdigest()
    assert len(snapshot(Ledger(path).read()).heads) == 2


def test_every_new_row_carries_the_hash_of_the_one_before(path: Path) -> None:
    chained(path, 3)
    rows = [json.loads(x) for x in lines(path)[2:]]
    for earlier, later in itertools.pairwise(rows):
        assert later["prev_hash"] == earlier["hash"]


def test_a_ledger_with_no_legacy_rows_and_none_at_all_chains_too(tmp_path: Path) -> None:
    ledger = chained(tmp_path / "new" / "l.jsonl", 2)
    assert ledger.state().started and ledger.state().chained == 3


def mutations(path: Path) -> dict[str, list[str]]:
    rows = lines(path)  # 2 legacy, chain_start (index 2), then rows 3..6
    swapped = [*rows[:3], rows[4], rows[3], *rows[5:]]
    edited = json.loads(rows[4])
    edited["amount_usd"] = 0.0001
    return {
        "a deleted middle row": rows[:4] + rows[5:],
        "a reordered pair": swapped,
        "an edited row": [*rows[:4], json.dumps(edited, sort_keys=True), *rows[5:]],
        "an edited legacy row": [rows[0].replace("25", "1"), *rows[1:]],
        "a deleted legacy row": rows[1:],
        "a deleted chain_start": rows[:2] + rows[3:],
        "an unchained row appended": [*rows, json.dumps({"type": "usage", "date": "2026-10-29", "amount_usd": 0})],
        "a duplicated row": [*rows, rows[-1]],
        "a second chain_start": [*rows, rows[2]],
    }


@pytest.mark.parametrize(
    "name",
    [
        "a deleted middle row",
        "a reordered pair",
        "an edited row",
        "an edited legacy row",
        "a deleted legacy row",
        "a deleted chain_start",
        "an unchained row appended",
        "a duplicated row",
        "a second chain_start",
    ],
)
def test_tampering_is_found_and_every_call_refuses_with_the_line_number(path: Path, name: str) -> None:
    chained(path, 4)
    write(path, mutations(path)[name])
    with pytest.raises(RefusedError, match=r"(line \d+|legacy rows|chain_start|no chain)"):
        Ledger(path).read()
    with pytest.raises(RefusedError):
        Ledger(path).append({"type": "usage", "date": "2026-10-29", "amount_usd": 1, "note": "x"})


def test_the_message_names_the_line(path: Path) -> None:
    chained(path, 4)
    write(path, mutations(path)["an edited row"])
    with pytest.raises(RefusedError, match="line 5"):
        Ledger(path).read()


def test_a_truncated_tail_is_found_through_the_head_file(path: Path) -> None:
    ledger = chained(path, 4)
    kept = lines(path)[:-2]
    write(path, kept)
    with pytest.raises(RefusedError, match="shorter than its head file"):
        ledger.read()


def test_a_head_file_that_disagrees_is_found(path: Path) -> None:
    ledger = chained(path, 3)
    ledger.head_file.write_text(f"3 {'0' * 64}\n")
    with pytest.raises(RefusedError, match="head file"):
        ledger.read()
    ledger.head_file.write_text("garbage\n")
    with pytest.raises(RefusedError, match="malformed"):
        ledger.read()


def test_the_chain_survives_a_stale_head_file_after_a_crash(path: Path) -> None:
    """A crash between the row and the head file leaves the head behind; the chain itself is the authority."""
    ledger = chained(path, 3)
    rows = [json.loads(x) for x in lines(path)[2:]]
    ledger.head_file.write_text(f"3 {rows[2]['hash']}\n")
    assert ledger.read()


def test_a_chained_row_with_no_chain_start_is_found(path: Path) -> None:
    chained(path, 2)
    write(path, [x for x in lines(path) if '"chain_start"' not in x])
    with pytest.raises(RefusedError, match="no chain_start"):
        Ledger(path).read()


def test_a_missing_ledger_beside_another_stays_refused(tmp_path: Path) -> None:
    other = tmp_path / "old" / "l.jsonl"
    other.parent.mkdir()
    other.write_text("{}\n")
    with pytest.raises(RefusedError, match="another ledger"):
        Ledger(tmp_path / "new" / "l.jsonl").read()


def test_a_broken_chain_is_not_extended(path: Path) -> None:
    chained(path, 2)
    original = lines(path)
    write(path, original[:3] + original[4:])
    size = path.stat().st_size
    with pytest.raises(RefusedError):
        Ledger(path).append({"type": "usage", "date": "2026-10-29", "amount_usd": 1, "note": "x"})
    assert path.stat().st_size == size


def test_a_chain_start_that_miscounts_the_legacy_rows_is_found_even_when_every_hash_fits(path: Path) -> None:
    """A whole-chain rewrite with consistent hashes still cannot change how many old rows there were."""
    from safo.gemini import _chain_hash

    prefix = path.read_bytes()
    start = {
        "type": "chain_start",
        "ts": "2026-10-29T00:00:00Z",
        "legacy_rows": 1,
        "prev_hash": hashlib.sha256(prefix).hexdigest(),
    }
    start["hash"] = _chain_hash(start)
    with path.open("a") as handle:
        handle.write(json.dumps(start) + "\n")
    with pytest.raises(RefusedError, match="legacy rows"):
        Ledger(path).read()
