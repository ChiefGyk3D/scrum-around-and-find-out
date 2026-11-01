# SPDX-License-Identifier: Apache-2.0
"""`begin`: the broker hands out the nonce and the numbers an approval must carry (docs/gemini-broker.md, "The socket
protocol" and decision 5). An approval can therefore only be made for a request the broker has seen.

`issued/NONCE` holds what was handed out. A `call` finds its nonce there, unexpired, and the approval must agree with
it; the file is removed once the spend is recorded. At most four nonces are outstanding. The directory is private to the
broker user and is emptied by `flush` (a service restart). Nothing here reads the clock: `now` is a parameter.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import json
import os
import re
import secrets
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from safo import gemini
from safo.bounded import loads, read_bounded
from safo.broker.errors import LedgerError, Refused
from safo.broker.ledger import GENESIS, CallLedger
from safo.broker.money import MAX_MICRO
from safo.broker.policy import BrokerRequest, Policy, canonical_broker_request
from safo.broker.prices import reserve_amount, typical_estimate
from safo.broker.records import NONCE, ApprovalV3, parse_stamp
from safo.guardlog import ensure_dir, file_lock, write_text

ISSUED_DIR = "issued"
MAX_OUTSTANDING = 4
DEFAULT_TTL = dt.timedelta(minutes=10)
ISSUED_BYTES = 4096
# what `write_text` leaves behind if the process dies between creating the temporary file and renaming it
TEMP_NAME = re.compile(r"\.[0-9a-f]{16,64}\.[A-Za-z0-9_]{1,16}")
_KEYS = {
    "nonce",
    "epoch",
    "model",
    "kind",
    "job",
    "count",
    "image_size",
    "aspect_ratio",
    "prompt_bytes",
    "max_output_tokens",
    "max_micro",
    "beyond_ceiling",
    "ledger_head",
    "created",
    "expires_at",
}


@dataclasses.dataclass(frozen=True)
class Offer:
    nonce: str
    epoch: str
    expires_at: dt.datetime
    ledger_head: str
    estimate_micro: int
    reserve_micro: int
    thinking_level: str
    beyond_ceiling: bool
    max_micro: int


def _plain(now: object) -> dt.datetime:
    try:
        return gemini.plain_time(now, "now")
    except gemini.RefusedError:
        raise Refused("bad_request", "the time is not a plain time with a time zone") from None


class Issuer:
    def __init__(self, ledger: CallLedger, policy: Policy, epoch: str, *, ttl: dt.timedelta = DEFAULT_TTL) -> None:
        self.ledger = ledger
        self.policy = policy
        self.epoch = epoch
        self.ttl = ttl
        self.dir = ledger.dir / ISSUED_DIR
        self.faults: Callable[[str], None] = lambda point: None

    # -- files

    def _path(self, nonce: str) -> Path:
        if NONCE.fullmatch(nonce) is None:
            raise LedgerError("a nonce is a short lowercase hex string")
        return self.dir / nonce

    def _read(self, nonce: str) -> dict[str, Any] | None:
        try:
            data = loads(read_bounded(self._path(nonce), ISSUED_BYTES))
        except FileNotFoundError:
            return None
        except (OSError, ValueError, UnicodeError, RecursionError):
            raise LedgerError("an issued nonce record cannot be read; root must look at it") from None
        if not isinstance(data, dict) or set(data) != _KEYS or data["nonce"] != nonce:
            raise LedgerError("an issued nonce record is malformed; root must look at it")
        return data

    def _names(self) -> list[str]:
        try:
            names = os.listdir(self.dir)
        except FileNotFoundError:
            return []
        except OSError:
            raise LedgerError("the issued folder cannot be read") from None
        for name in names:
            if NONCE.fullmatch(name) is None and TEMP_NAME.fullmatch(name) is None:
                raise LedgerError("the issued folder holds a file that is not a nonce")
        return sorted(names)

    def _nonces(self) -> list[str]:
        return [name for name in self._names() if NONCE.fullmatch(name)]

    def _sweep_temporary(self) -> None:
        """Remove what a killed write left. Only called holding the issued lock, which every writer holds, so no
        write is in flight; a link is removed, never followed."""
        for name in self._names():
            if TEMP_NAME.fullmatch(name):
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(self.dir / name)

    @staticmethod
    def _expiry(data: dict[str, Any]) -> dt.datetime:
        when = parse_stamp(data["expires_at"])
        if when is None:
            raise LedgerError("an issued nonce record has a bad time; root must look at it")
        return when

    # -- operations

    @contextlib.contextmanager
    def _issued_lock(self) -> Iterator[None]:
        """The lock every writer of the issued table holds. Only the timeout of TAKING it is `busy`, as the ledger
        lock's timeout is; an exception raised by the work under the lock passes through unchanged."""
        with contextlib.ExitStack() as stack:
            try:
                stack.enter_context(file_lock(self.dir.parent / "issued.lock", timeout=self.ledger.lock_seconds))
            except TimeoutError:
                raise Refused("busy", "another operation holds the approval table") from None
            yield

    def begin(
        self,
        req: BrokerRequest,
        *,
        prompt_bytes: int,
        max_micro: int,
        now: dt.datetime,
    ) -> Offer:
        """Check the request against the allow-list and the caps, then issue a nonce. `req.prompt` is not used (the
        client sends the size at this step, never the text); the shape of everything else is the call's shape."""
        now = _plain(now)
        shape = canonical_broker_request(dataclasses.replace(req, prompt=""))
        price = self.policy.allowed(shape.model)
        if shape.thinking_level != price.thinking_level_sent:
            raise Refused("bad_request", "the thinking level is not the one the broker sends for this model")
        if type(max_micro) is not int or not 0 < max_micro <= MAX_MICRO:
            raise Refused("bad_request", "the maximum cost is out of range")
        reservation = reserve_amount(
            price,
            kind=shape.kind,
            prompt_bytes=prompt_bytes,
            max_output_tokens=shape.max_output_tokens,
            image_size=shape.image_size,
            count=shape.count,
            today=now.astimezone(dt.UTC).date(),
        )
        estimate = typical_estimate(price, prompt_bytes=prompt_bytes, image_size=shape.image_size, count=shape.count)
        view = self.ledger.view()
        if shape.model in view.suspended:
            raise Refused("model_suspended", "this model is stopped until root clears it")
        month = view.month_spent(now)
        beyond = month + reservation.total_micro > self.policy.caps.month_micro
        self.policy.check_unverified(price, reservation.total_micro)
        self.policy.check_caps(
            reservation.total_micro, max_micro=max_micro, beyond_ceiling=beyond, month_spent_micro=month
        )
        head = view.head or GENESIS
        ensure_dir(self.dir)
        with self._issued_lock():
            self._sweep_temporary()
            live = self._prune(now)
            if live >= MAX_OUTSTANDING:
                raise Refused("busy", "too many approvals are outstanding; use or wait for one")
            nonce = secrets.token_hex(16)
            expires = now + self.ttl
            record = {
                "nonce": nonce,
                "epoch": self.epoch,
                "model": shape.model,
                "kind": shape.kind,
                "job": shape.job,
                "count": shape.count,
                "image_size": shape.image_size,
                "aspect_ratio": shape.aspect_ratio,
                "prompt_bytes": prompt_bytes,
                "max_output_tokens": shape.max_output_tokens,
                "max_micro": max_micro,
                "beyond_ceiling": beyond,
                "ledger_head": head,
                "created": gemini.stamp(now),
                "expires_at": gemini.stamp(expires),
            }
            write_text(
                self._path(nonce),
                json.dumps(record, sort_keys=True) + "\n",
                before_replace=lambda: self.faults("issued_before_replace"),
            )
            self.faults("issued_after_write")
        return Offer(
            nonce,
            self.epoch,
            expires,
            head,
            estimate,
            reservation.total_micro,
            price.thinking_level_sent,
            beyond,
            max_micro,
        )

    def _prune(self, now: dt.datetime) -> int:
        live = 0
        for name in self._nonces():
            data = self._read(name)
            if data is None:
                continue
            if now >= self._expiry(data):
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(self._path(name))
            else:
                live += 1
        return live

    def check(self, approval: ApprovalV3, *, now: dt.datetime) -> None:
        """The approval's nonce was handed out by `begin`, has not expired, and the approval says what was asked for."""
        data = self._read(approval.nonce)
        if data is None:
            raise Refused("bad_approval", "this approval's nonce was not issued by the broker, or the broker restarted")
        if now >= self._expiry(data):
            raise Refused("expired", "this approval's nonce has expired; ask for a fresh one")
        same = (
            data["epoch"] == approval.epoch
            and data["model"] == approval.model
            and data["kind"] == approval.kind
            and data["job"] == approval.job
            and data["count"] == approval.count
            and data["image_size"] == approval.image_size
            and data["aspect_ratio"] == approval.aspect_ratio
            and data["prompt_bytes"] == approval.prompt_bytes
            and data["max_output_tokens"] == approval.max_output_tokens
            and data["max_micro"] == approval.max_micro
            and data["beyond_ceiling"] == approval.beyond_ceiling
            and data["ledger_head"] == approval.ledger_head
            and (created := parse_stamp(data["created"])) is not None
            and approval.created >= created
        )
        if not same:
            raise Refused("bad_approval", "this approval does not match what was asked for when the nonce was issued")

    def consume(self, nonce: str) -> None:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self._path(nonce))

    def state(self, nonce: str, now: dt.datetime) -> str:
        """For the dispatch guard: `live`, `used`, `expired` or `unknown`. Spends nothing."""
        if NONCE.fullmatch(nonce) is None:
            return "unknown"
        if self.ledger.marker_exists(nonce) or nonce in self.ledger.view().spent_nonces:
            return "used"
        data = self._read(nonce)
        if data is None:
            return "unknown"
        return "expired" if now >= self._expiry(data) else "live"

    def flush(self) -> int:
        """A restart empties the table: every nonce handed out must be asked for again. Returns how many went."""
        with self._issued_lock():
            self._sweep_temporary()
            names = self._nonces()
            for name in names:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(self._path(name))
        return len(names)
