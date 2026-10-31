# SPDX-License-Identifier: Apache-2.0
"""A rig for the broker pipeline tests: a throwaway ed25519 key, a temporary allowed-signers file, a ledger, an issuer,
a fake vendor and a fake clock. Software keys stand in for a hardware key, as in the existing signing tests."""

from __future__ import annotations

import datetime as dt
import os
from pathlib import Path
from typing import Any

from brokerdata import EPOCH, FLAT, policy
from fakevendor import START, FakeClock, FakeVendor
from geminidata import signers_line
from safo import gemini, geminisign
from safo.broker.issue import Issuer, Offer
from safo.broker.ledger import CallLedger, Faults
from safo.broker.money import format_usd
from safo.broker.pipeline import Pipeline
from safo.broker.policy import BrokerRequest, Caps
from safo.geminisign import Trust

LABEL = "yubikey-a"
IMAGE_MODEL = "gemini-nano-banana-2.1"
IMAGE_PROMPT = "a small blue square on a white page"


def text_req(**over: Any) -> BrokerRequest:
    base: dict[str, Any] = {
        "model": FLAT,
        "kind": "text",
        "job": "job-one",
        "prompt": "say hello to the broker",
        "max_output_tokens": 500,
        "thinking_level": "none",
    }
    base.update(over)
    return BrokerRequest(**base)


def image_req(**over: Any) -> BrokerRequest:
    base: dict[str, Any] = {
        "model": IMAGE_MODEL,
        "kind": "image",
        "job": "job-img",
        "prompt": IMAGE_PROMPT,
        "max_output_tokens": 4000,
        "thinking_level": "minimal",
        "count": 1,
        "image_size": "1K",
        "aspect_ratio": "1:1",
    }
    base.update(over)
    return BrokerRequest(**base)


class Rig:
    def __init__(self, tmp: Path, key: Path, *, faults: Faults | None = None, pipeline_faults: Faults | None = None):
        self.tmp = tmp
        self.key = key
        self.signers = tmp / "signers"
        self.revoked = tmp / "revoked"
        self.signers.write_text(signers_line(LABEL, key.with_suffix(".pub")) + "\n")
        self.signers.chmod(0o644)
        self.revoked.write_text("")
        self.revoked.chmod(0o644)
        self.trust = Trust(self.signers, self.revoked, os.geteuid(), False, False)
        self.clock = FakeClock()
        self.vendor = FakeVendor(self.clock)
        self.faults = faults
        self.pipeline_faults = pipeline_faults
        self.policy = policy(Caps())
        self.build()

    def build(self) -> None:
        self.ledger = CallLedger(self.tmp / "state", faults=self.faults)
        self.ledger.open()
        self.issuer = Issuer(self.ledger, self.policy, EPOCH)
        self.pipeline = Pipeline(
            self.ledger,
            self.policy,
            self.issuer,
            self.trust,
            self.vendor,
            epoch=EPOCH,
            wall=self.clock.wall,
            mono=self.clock.mono,
            faults=self.pipeline_faults,
        )

    def restart(self, faults: Faults | None = None) -> None:
        """A new process on the same state directory: new objects, recovery run, the issued table emptied."""
        self.faults = faults
        self.pipeline_faults = None
        self.build()
        self.ledger.recover(self.clock.wall())

    # -- an approval
    def offer(self, req: BrokerRequest, *, max_micro: int = 2_500_000, prompt_bytes: int | None = None) -> Offer:
        size = len(req.prompt.encode()) if prompt_bytes is None else prompt_bytes
        return self.issuer.begin(req, prompt_bytes=size, max_micro=max_micro, now=self.clock.wall())

    def text(self, req: BrokerRequest, offer: Offer, **over: Any) -> str:
        digest, size = gemini.prompt_binding(req.prompt)
        now = self.clock.wall()
        data: dict[str, Any] = {
            "version": 3,
            "nonce": offer.nonce,
            "epoch": offer.epoch,
            "model": req.model,
            "kind": req.kind,
            "max_output_tokens": req.max_output_tokens,
            "thinking_level": req.thinking_level,
            "max_usd": format_usd(2_500_000),
            "job": req.job,
            "prompt_sha256": digest,
            "prompt_bytes": size,
            "quote": "go ahead",
            "quoted_at": gemini.stamp(now - dt.timedelta(minutes=1)),
            "created": gemini.stamp(now - dt.timedelta(minutes=1)),
            "expires_at": gemini.stamp(now + dt.timedelta(minutes=9)),
            "beyond_ceiling": offer.beyond_ceiling,
            "ledger_head": offer.ledger_head,
            "issue": "ChiefGyk3D/scrum-around-and-find-out#258",
            "principal": LABEL,
        }
        if req.kind == "image":
            data |= {"count": req.count, "image_size": req.image_size, "aspect_ratio": req.aspect_ratio}
        for key, value in over.items():
            if value is None:
                data.pop(key, None)
            else:
                data[key] = value
        return geminisign.canonical(data)

    def sign(self, text: str, namespace: str = geminisign.NAMESPACE, key: Path | None = None) -> str:
        return geminisign.sign(str(key or self.key), text.encode(), namespace, {})

    def approved(self, req: BrokerRequest, **over: Any) -> tuple[str, str]:
        offer = self.offer(req)
        text = self.text(req, offer, **over)
        return text, self.sign(text)

    def run(self, req: BrokerRequest, **over: Any) -> Any:
        payload, signature = self.approved(req, **over)
        return self.pipeline.call(req, payload, signature)


def start() -> dt.datetime:
    return START
