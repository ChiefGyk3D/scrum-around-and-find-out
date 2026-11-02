# SPDX-License-Identifier: Apache-2.0
"""What a process that reaches the broker socket can do WITHOUT a signed approval (#299).

The terminal-only start of the broker client and the guard's text patterns are defense in depth: a program running
as the maintainer can open a pseudo terminal, and can talk to the socket without the client at all. What holds is
the broker: a spend needs an approval signed with the hardware key, and that needs a touch (and a PIN when the key
requires one). This file pins the list of what is reachable without one, so the documentation
(docs/gemini-broker.md) cannot drift from the code, and proves that none of it spends, suspends a model or writes
the ledger."""

from __future__ import annotations

from pathlib import Path

import pytest

from geminidata import make_key
from pipedata import Rig, text_req
from safo.broker import protocol
from safo.broker.errors import Refused
from safo.broker.issue import MAX_OUTSTANDING


@pytest.fixture(scope="module")
def key(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return make_key(tmp_path_factory.mktemp("keys") / "a")


@pytest.fixture
def rig(tmp_path: Path, key: Path) -> Rig:
    return Rig(tmp_path, key)


def test_the_operations_that_carry_no_approval_are_exactly_status_begin_and_check() -> None:
    """A new operation without an approval field fails here, and must be written up in the docs and reasoned about."""
    no_approval = {name for name, op in protocol.OPERATIONS.items() if "approval" not in op.required}
    assert no_approval == {"status", "begin", "check"}
    assert {name for name in protocol.OPERATIONS if name not in no_approval} == {"call", "dryrun"}


def test_begin_spends_nothing_suspends_nothing_and_writes_no_ledger_row(rig: Rig) -> None:
    before = rig.ledger.view()
    for _ in range(MAX_OUTSTANDING):
        rig.offer(text_req())
    after = rig.ledger.view()
    assert after.head == before.head and after.calls == before.calls == {}
    assert after.suspended == before.suspended == {}
    assert after.month_spent(rig.clock.wall()) == before.month_spent(rig.clock.wall()) == 0


def test_the_only_cost_of_begin_is_the_outstanding_slots_which_expire(rig: Rig) -> None:
    """Availability, not money: four live nonces make a fifth `begin` busy until one expires (ten minutes)."""
    for _ in range(MAX_OUTSTANDING):
        rig.offer(text_req())
    with pytest.raises(Refused) as err:
        rig.offer(text_req())
    assert err.value.code == "busy"
    assert rig.ledger.view().calls == {}


def test_a_call_without_a_valid_signature_is_refused_before_the_ledger_or_the_vendor(rig: Rig) -> None:
    req = text_req()
    offer = rig.offer(req)
    text = rig.text(req, offer)
    with pytest.raises(Refused):
        rig.pipeline.call(req, text, "not a signature")
    assert rig.ledger.view().calls == {} and rig.vendor.requests == []
    assert rig.ledger.view().suspended == {}
