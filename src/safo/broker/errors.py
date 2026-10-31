# SPDX-License-Identifier: Apache-2.0
"""The broker's errors. A message is a fixed sentence: it never echoes a client string, a prompt or a key."""

from __future__ import annotations

from safo.errors import SafoError

# The reply codes the design lists (docs/gemini-broker.md, "The socket protocol"), plus the two marked (added).
CODES = frozenset(
    {
        "bad_request",
        "disabled",
        "bad_approval",
        "revoked",
        "expired",
        "used",
        "digest_mismatch",
        "model_mismatch",
        "job_mismatch",
        "over_job_cap",
        "over_approved",
        "needs_block_approval",
        "month_cap",
        "model_suspended",
        "busy",
        "internal",
        "model_refused",  # (added) a model the broker will not call: Pro class, or not in the allow-list
        "prices_expired",  # (added) the price table is past its valid_through
    }
)


class BrokerError(SafoError):
    """Anything the broker core reports."""

    code = "internal"


class Refused(BrokerError):
    """Nothing was spent and nothing was sent: the request, the approval or a cap stopped it."""

    def __init__(self, code: str, message: str) -> None:
        if code not in CODES:
            raise ValueError("unknown reply code")
        super().__init__(message)
        self.code = code


class LedgerError(BrokerError):
    """The ledger or the state directory cannot be trusted. Nothing is reserved until root has looked at it."""

    exit_code = 4


class IllegalTransition(BrokerError):
    """A call was asked to move between states the design does not allow."""

    exit_code = 4
