# SPDX-License-Identifier: Apache-2.0
"""One paid call, start to finish (docs/gemini-broker.md, "A call, step by step"), against an injected transport.

verify the signed approval -> reserve the worst case (written BEFORE anything leaves) -> build the request from the
fixed template -> write `call_sent` -> send through the transport -> classify the answer -> settle, or make the call
ambiguous. Nothing here opens a socket, reads a key or reads the clock: the transport, the wall clock and the monotonic
clock are all parameters.

Outcomes, and what the ledger gets:

* refused before the spend (a bad or replayed approval, a cap): `Refused`, nothing recorded;
* failed after the spend and before the request could leave: `call_end` `not_sent`, nothing billed;
* 429: `rate_limited`, zero cost, final; a definite 4xx: `vendor_refused`, zero cost;
* a good answer: `ok` with the cost from the reported usage; over the signed output cap it is also a breach (the model
  is suspended) and is recorded at the cap or the reported usage, whichever is higher;
* a timeout, a transport error, a 3xx/408/5xx, a short, oversized or malformed body, a reply for another model or with
  unusable usage: AMBIGUOUS. The whole reservation stays counted and the model is suspended until root clears it. The
  request is never repeated.

Whatever raises after the spend, the call ends settled or ambiguous in the ledger (or, if the process dies, at the next
`recover`); there is no path that leaves the reserved amount free.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
from collections.abc import Callable, Mapping

from safo import gemini, geminisign
from safo.broker.approval import verify_approval
from safo.broker.errors import Refused
from safo.broker.images import Image
from safo.broker.issue import Issuer
from safo.broker.ledger import CallLedger, Ticket
from safo.broker.money import MICRO, ceil_div
from safo.broker.policy import BrokerRequest, Policy, Priced, canonical_broker_request
from safo.broker.vendor import (
    RawReply,
    Reply,
    Transport,
    TransportTimeout,
    Unreadable,
    VendorRequest,
    actual_cost,
    body_prompt,
    build_request,
    parse_reply,
    retry_after_seconds,
)

PIPELINE_FAULTS = ("after_verify", "after_reserve", "after_build", "after_send", "after_settle")
DEFAULT_DEADLINE_SECONDS = 180.0
Faults = Callable[[str], None]


@dataclasses.dataclass(frozen=True)
class Receipt:
    call_id: str
    nonce: str
    epoch: str
    model: str
    kind: str
    count: int
    image_size: str
    prompt_sha256: str
    tokens_in: int | None
    tokens_out: int | None
    reserved_micro: int
    actual_micro: int
    released_micro: int
    breach: bool
    cap_breach: bool
    estimated: bool  # the reservation stood in for a usage figure that could not be trusted
    extra_images: int
    images: tuple[tuple[int, str, int, str], ...]  # index, mime, bytes, sha256
    month_spent_micro: int
    ledger_head: str
    ts: str


@dataclasses.dataclass(frozen=True)
class CallResult:
    """`code` is `ok`, `rate_limited`, `vendor_refused` or `outcome_unknown`. `text` and `images` are empty unless the
    code is `ok`. A refusal before the spend is a `Refused` exception instead."""

    code: str
    receipt: Receipt
    text: str = ""
    images: tuple[Image, ...] = ()
    retry_after: int | None = None


def _header(headers: Mapping[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if type(key) is str and key.lower() == name and type(value) is str:
            return value
    return None


class Pipeline:
    def __init__(
        self,
        ledger: CallLedger,
        policy: Policy,
        issuer: Issuer,
        trust: geminisign.Trust,
        transport: Transport,
        *,
        epoch: str,
        wall: Callable[[], dt.datetime],
        mono: Callable[[], float],
        deadline_seconds: float = DEFAULT_DEADLINE_SECONDS,
        faults: Faults | None = None,
    ) -> None:
        self.ledger = ledger
        self.policy = policy
        self.issuer = issuer
        self.trust = trust
        self.transport = transport
        self.epoch = epoch
        self.wall = wall
        self.mono = mono
        self.deadline = deadline_seconds
        self.faults: Faults = faults or (lambda point: None)

    # -- the call

    def call(self, req: BrokerRequest, payload: str, signature: str) -> CallResult:
        req = canonical_broker_request(req)
        approval = verify_approval(payload, signature, self.trust, now=self.wall())
        self.faults("after_verify")

        def last_look() -> None:  # under the ledger lock, just before the spend: a key revoked a moment ago is caught
            now = self.wall()
            verify_approval(payload, signature, self.trust, now=now)
            self.issuer.check(approval, now=now)

        ticket = self.ledger.reserve(req, approval, self.policy, epoch=self.epoch, now=self.wall(), pre_spend=last_look)
        self.faults("after_reserve")
        try:
            self.issuer.consume(approval.nonce)
            priced = self.policy.price(req, self.wall())
            vendor = build_request(req, priced.price, self.deadline)
            if not gemini.digests_equal(gemini.prompt_binding(body_prompt(vendor))[0], approval.prompt_sha256):
                raise Refused("internal", "the request body is not the prompt the approval covers")
            self.faults("after_build")
        except Exception:
            self.ledger.settle(ticket.call_id, "not_sent", 0, self.wall())
            raise
        try:
            self.ledger.mark_sent(ticket.call_id, self.wall())
        except Exception:
            self._ambiguous(ticket, req, priced, "connection")
            raise
        start = self.mono()
        try:
            raw = self.transport.send(vendor)
        except TransportTimeout:
            return self._ambiguous(ticket, req, priced, "timeout")
        except Exception:  # a reset, a short body, anything: the request may have left
            return self._ambiguous(ticket, req, priced, "connection")
        self.faults("after_send")
        if self.mono() - start > self.deadline:  # the answer came after the deadline: treated as no answer
            return self._ambiguous(ticket, req, priced, "timeout")
        return self._classify(req, ticket, priced, vendor, raw)

    # -- classifying the answer

    def _classify(
        self, req: BrokerRequest, ticket: Ticket, priced: Priced, vendor: VendorRequest, raw: RawReply
    ) -> CallResult:
        if type(raw) is not RawReply or type(raw.status) is not int or type(raw.body) is not bytes:
            return self._ambiguous(ticket, req, priced, "unreadable")
        status = raw.status
        if status == 429:
            retry = retry_after_seconds(
                _header(raw.headers, "retry-after") if isinstance(raw.headers, Mapping) else None
            )
            return self._finished(ticket, req, priced, "rate_limited", "rate_limited", 0, retry_after=retry)
        if 400 <= status < 500 and status != 408:
            return self._finished(ticket, req, priced, "vendor_refused", "vendor_refused", 0)
        if status != 200:  # 1xx, 2xx other than 200, 3xx (a redirect is never followed), 408, 5xx, anything else
            return self._ambiguous(ticket, req, priced, "status")
        if len(raw.body) > vendor.max_reply_bytes:
            return self._ambiguous(ticket, req, priced, "unreadable")
        length = _header(raw.headers, "content-length") if isinstance(raw.headers, Mapping) else None
        if length is not None and (not length.isascii() or not length.isdigit() or int(length) != len(raw.body)):
            return self._ambiguous(ticket, req, priced, "unreadable")  # a short or padded body
        try:
            reply = parse_reply(req, raw.body, priced.prompt_bytes)
        except Unreadable as err:
            return self._ambiguous(ticket, req, priced, err.reason)
        if reply.parts_returned and reply.usage.output_tokens < priced.price.image_tokens.get(req.image_size, 0):
            return self._ambiguous(ticket, req, priced, "usage")  # an image of this size is at least this many tokens
        cost = actual_cost(priced.price, reply.usage, reply.parts_returned)
        if reply.cap_exceeded:  # decision 13: recorded at the cap or the reported usage, whichever is higher
            out_rate = max(priced.price.text_output_per_mtok, priced.price.image_output_per_mtok)
            at_cap = priced.reservation.input_micro + ceil_div(req.max_output_tokens * out_rate, MICRO)
            cost = max(cost, at_cap)
        deliver = req.kind == "text" or (len(reply.images) == req.count and not reply.image_refused)
        return self._finished(
            ticket,
            req,
            priced,
            "ok" if deliver else "vendor_refused",
            "ok",
            cost,
            reply=reply,
            cap_breach=reply.cap_exceeded,
        )

    # -- the two ways a call ends

    def _finished(
        self,
        ticket: Ticket,
        req: BrokerRequest,
        priced: Priced,
        code: str,
        status: str,
        cost: int,
        *,
        reply: Reply | None = None,
        retry_after: int | None = None,
        cap_breach: bool = False,
    ) -> CallResult:
        try:
            done = self.ledger.settle(ticket.call_id, status, cost, self.wall(), cap_breach=cap_breach)
        except Exception:
            with contextlib.suppress(Exception):  # the answer could not be recorded: keep the whole reservation counted
                self.ledger.mark_ambiguous(ticket.call_id, "unreadable", self.wall())
            raise
        self.faults("after_settle")
        keep = reply is not None and code == "ok"
        images = reply.images if reply is not None and keep else ()
        receipt = self._receipt(
            ticket,
            req,
            priced,
            actual=done.actual_micro,
            released=done.released_micro,
            breach=done.breach,
            cap_breach=cap_breach,
            estimated=False,
            usage=(reply.usage.input_tokens, reply.usage.output_tokens) if reply is not None else None,
            extra=reply.extra_images if reply is not None else 0,
            images=images,
        )
        return CallResult(code, receipt, reply.text if keep and reply is not None else "", images, retry_after)

    def _ambiguous(self, ticket: Ticket, req: BrokerRequest, priced: Priced, reason: str) -> CallResult:
        self.ledger.mark_ambiguous(ticket.call_id, reason, self.wall())
        self.faults("after_settle")
        receipt = self._receipt(
            ticket,
            req,
            priced,
            actual=ticket.reserved_micro,
            released=0,
            breach=False,
            cap_breach=False,
            estimated=True,
            usage=None,
            extra=0,
            images=(),
        )
        return CallResult("outcome_unknown", receipt)

    def _receipt(
        self,
        ticket: Ticket,
        req: BrokerRequest,
        priced: Priced,
        *,
        actual: int,
        released: int,
        breach: bool,
        cap_breach: bool,
        estimated: bool,
        usage: tuple[int, int] | None,
        extra: int,
        images: tuple[Image, ...],
    ) -> Receipt:
        now = self.wall()
        view = self.ledger.view()
        return Receipt(
            call_id=ticket.call_id,
            nonce=ticket.nonce,
            epoch=self.epoch,
            model=req.model,
            kind=req.kind,
            count=req.count,
            image_size=req.image_size,
            prompt_sha256=priced.prompt_sha256,
            tokens_in=None if usage is None else usage[0],
            tokens_out=None if usage is None else usage[1],
            reserved_micro=ticket.reserved_micro,
            actual_micro=actual,
            released_micro=released,
            breach=breach,
            cap_breach=cap_breach,
            estimated=estimated,
            extra_images=extra,
            images=tuple((i.index, i.mime, len(i.data), i.sha256) for i in images),
            month_spent_micro=view.month_spent(now),
            ledger_head=view.head,
            ts=gemini.stamp(now),
        )
