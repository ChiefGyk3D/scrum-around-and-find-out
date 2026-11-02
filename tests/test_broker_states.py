# SPDX-License-Identifier: Apache-2.0
"""The call state machine: every pair of the six states, written out independently of the table under test."""

from __future__ import annotations

import itertools
from typing import Any

import pytest

from safo.broker.errors import IllegalTransition
from safo.broker.states import TRANSITIONS, CallState, advance

R, S, T, A, U, C = (
    CallState.RESERVED,
    CallState.SENT,
    CallState.SETTLED,
    CallState.AMBIGUOUS,
    CallState.SUSPENDED,
    CallState.CLEARED,
)
LEGAL = {
    (R, S),  # the request is about to leave
    (R, T),  # refused before it left: nothing billed
    (R, A),  # crash recovery found a spend with no `call_sent`
    (S, T),  # the outcome is known
    (S, A),  # the outcome is not known
    (T, U),  # a breach stops the model
    (A, U),  # an ambiguous call stops the model
    (U, C),  # root clears
}


def test_there_are_six_states_and_thirty_six_pairs() -> None:
    assert len(list(CallState)) == 6
    assert len(list(itertools.product(CallState, CallState))) == 36


@pytest.mark.parametrize(("src", "dst"), list(itertools.product(CallState, CallState)), ids=lambda s: s.value)
def test_every_pair_is_legal_or_rejected(src: CallState, dst: CallState) -> None:
    if (src, dst) in LEGAL:
        assert advance(src, dst) is dst
    else:
        with pytest.raises(IllegalTransition):
            advance(src, dst)


def test_the_table_is_exactly_the_legal_set() -> None:
    assert {(a, b) for a, targets in TRANSITIONS.items() for b in targets} == LEGAL


def test_nothing_moves_to_itself_or_backward_and_cleared_is_final() -> None:
    assert not TRANSITIONS[C]
    for state in CallState:
        assert state not in TRANSITIONS[state]
    order = [R, S, T, A, U, C]
    for src, targets in TRANSITIONS.items():
        for dst in targets:
            assert order.index(dst) > order.index(src) or (src, dst) == (R, A)


def test_the_only_way_to_a_cleared_call_goes_through_suspended() -> None:
    assert {src for src, targets in TRANSITIONS.items() if C in targets} == {U}
    assert {src for src, targets in TRANSITIONS.items() if U in targets} == {T, A}


@pytest.mark.parametrize("bad", ["settled", None, 3, object()])
def test_a_state_must_be_a_state(bad: Any) -> None:
    with pytest.raises(IllegalTransition):
        advance(bad, S)
    with pytest.raises(IllegalTransition):
        advance(R, bad)
