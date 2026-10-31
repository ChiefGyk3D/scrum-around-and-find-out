# SPDX-License-Identifier: Apache-2.0
"""The call state machine (docs/gemini-broker.md, "A call, step by step" and "Cost", rules 6 and 7).

reserved   the spend is written (`call_start`); nothing has left yet
sent       the request is about to leave or has left (`call_sent`, written before the connection opens)
settled    the outcome is known and the cost recorded (`call_end`)
ambiguous  the request left or may have left and what was billed is not known; the whole reservation stays counted
suspended  the model is stopped (after a breach, or after an ambiguous call) until root clears it
cleared    root cleared the suspension (for an ambiguous call, after entering the real amount)

Every pair not listed in TRANSITIONS is illegal and rejected.
"""

from __future__ import annotations

import enum

from safo.broker.errors import IllegalTransition


class CallState(enum.Enum):
    RESERVED = "reserved"
    SENT = "sent"
    SETTLED = "settled"
    AMBIGUOUS = "ambiguous"
    SUSPENDED = "suspended"
    CLEARED = "cleared"


S = CallState
TRANSITIONS: dict[CallState, frozenset[CallState]] = {
    # settled straight from reserved is a definite refusal before the request left (nothing billed)
    # ambiguous straight from reserved is crash recovery (a spend with no `call_sent`)
    S.RESERVED: frozenset({S.SENT, S.SETTLED, S.AMBIGUOUS}),
    S.SENT: frozenset({S.SETTLED, S.AMBIGUOUS}),
    S.SETTLED: frozenset({S.SUSPENDED}),  # only after a breach; the ledger checks that
    S.AMBIGUOUS: frozenset({S.SUSPENDED}),
    S.SUSPENDED: frozenset({S.CLEARED}),
    S.CLEARED: frozenset(),
}


def advance(current: CallState, target: CallState) -> CallState:
    """The new state, or IllegalTransition. No state changes itself, and none moves backward."""
    if type(current) is not CallState or type(target) is not CallState:
        raise IllegalTransition("a call state is one of the six named states")
    if target not in TRANSITIONS[current]:
        raise IllegalTransition(f"a call cannot go from {current.value} to {target.value}")
    return target
