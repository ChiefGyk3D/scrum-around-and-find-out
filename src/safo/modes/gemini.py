# SPDX-License-Identifier: Apache-2.0
"""gemini: ask the free tier a public-material question, and gate every paid one (#200).

    safo gemini quota   --model M [--paid ...]            print the quota line and send nothing
    safo gemini approve --model M --max-usd X --job J --quote Q --quoted-at T --prompt-file F
                                                           print the quota line, then write one single-use approval
    safo gemini ask     --model M --material public --prompt-file F [--paid --job J --approval ID]
                                                           print the quota line, send ONE request, log it

Read docs/gemini.md. `approve` records what the maintainer said; run it only after he has said yes in his own message.
"""

from __future__ import annotations

import argparse
import datetime as dt
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import NoReturn

from safo import output
from safo.bounded import read_bounded
from safo.context import LocalContext
from safo.errors import EXIT_OK, ConfigError
from safo.gemini import (
    MAX_PROMPT_BYTES,
    ApprovalStore,
    GeminiConfig,
    Ledger,
    RefusedError,
    Request,
    ask,
    doppler_key_provider,
    estimate_usd,
    fixed,
    gemini_state_dir,
    load_config,
    money,
    paid_quota,
    quota_line,
    snapshot,
)
from safo.guardlog import config_dir
from safo.modes import LocalMode, register_local


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("action", choices=["quota", "approve", "ask"])
    parser.add_argument(
        "--config", default="", help="gemini.yaml (default: $SAFO_GEMINI_CONFIG, else ~/.config/safo/gemini.yaml)"
    )
    parser.add_argument("--model", required=True, help="a model named in the config")
    parser.add_argument("--paid", action="store_true", help="the paid tier: needs --job and --approval")
    parser.add_argument("--job", default="", help="the job an approval is for")
    parser.add_argument("--approval", default="", help="the id `approve` printed")
    parser.add_argument("--prompt-file", default="", help="the prompt, from a file (never argv)")
    parser.add_argument("--cap", default="", help="ask: refuse when the estimate is over this many USD (at most 2)")
    parser.add_argument("--max-output-tokens", type=int, default=0, help="a hard output limit (default: the config's)")
    parser.add_argument("--material", default="", help="ask: must be `public`; nothing private goes to Gemini")
    parser.add_argument("--max-usd", default="", help="approve: the most this job may cost, at most 2")
    parser.add_argument("--quote", default="", help="approve: the maintainer's message, as he wrote it")
    parser.add_argument("--quoted-at", default="", help="approve: when he wrote it, UTC, YYYY-MM-DDTHH:MM:SSZ")
    parser.add_argument("--ttl-minutes", type=int, default=60, help="approve: how long the record lives (at most 1440)")
    parser.add_argument("--beyond-ceiling", action="store_true", help="approve: this job may pass the 10 USD month")
    parser.add_argument("--issue", default="", help="approve: the tracking issue, owner/repo#N")


class BriefParseError(ValueError):
    """The command in a brief is not one the real parser accepts."""


class _BriefParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise BriefParseError(message)


def brief_namespace(tokens: list[str]) -> argparse.Namespace:
    """What the CLI would make of these arguments: the same definitions (`add_arguments`), no abbreviations, and an
    error for anything it would reject. The dispatch guard reads a brief's command with this, so the two cannot
    disagree about what a spelling means."""
    parser = _BriefParser(prog="safo gemini", add_help=False, allow_abbrev=False)
    add_arguments(parser)
    return parser.parse_args(tokens)


def _config(ctx: LocalContext, args: argparse.Namespace) -> GeminiConfig:
    chosen = args.config or ctx.env.get("SAFO_GEMINI_CONFIG", "")
    if not chosen:
        folder = config_dir(ctx.env)
        if folder is None:
            raise ConfigError("HOME is not set, so the Gemini config cannot be found; pass --config")
        chosen = str(folder / "gemini.yaml")
    return load_config(chosen, ctx.env)


def _prompt(args: argparse.Namespace) -> str:
    if not args.prompt_file:
        return ""
    path = Path(args.prompt_file)
    try:
        raw = read_bounded(path, MAX_PROMPT_BYTES + 1)
    except OSError as err:
        raise ConfigError(f"cannot read the prompt file: {err.strerror}") from None
    if len(raw) > MAX_PROMPT_BYTES:
        raise ConfigError(f"the prompt file is larger than {MAX_PROMPT_BYTES} bytes; cut it down")
    try:
        return raw.decode("utf-8")
    except UnicodeError:
        raise ConfigError("the prompt file is not UTF-8 text") from None


def _request(args: argparse.Namespace) -> Request:
    return Request(
        model=args.model,
        prompt=_prompt(args),
        tier="paid" if args.paid or args.action == "approve" else "free",
        job=args.job,
        approval=args.approval,
        max_output_tokens=args.max_output_tokens,
    )


def _approve(ctx: LocalContext, args: argparse.Namespace, cfg: GeminiConfig, store: ApprovalStore, req: Request) -> int:
    line = quota_line(cfg, req, ctx.now)  # first: an approval is refused when the line cannot be produced
    ctx.say(line)
    try:
        amount = Decimal(args.max_usd)
    except InvalidOperation:
        raise ConfigError("--max-usd: expected a number of USD") from None
    estimate = estimate_usd(cfg, req, ctx.now)
    if estimate > cfg.job_cap:
        raise RefusedError(
            f"the estimate {money(estimate)} USD is over the {money(cfg.job_cap)} USD job cap; lower the output limit"
        )
    if estimate > amount:
        raise RefusedError(
            f"the estimate {money(estimate)} USD is over the amount to be approved ({money(amount)} USD)"
        )
    if paid_quota(cfg, snapshot(Ledger(cfg.ledger).read()), req, ctx.now).beyond and not args.beyond_ceiling:
        raise RefusedError(
            f"this job would pass the {money(cfg.month_cap)} USD monthly ceiling; past it every further "
            f"{money(cfg.block)} USD needs its own approval that says so: add --beyond-ceiling only if he said that"
        )
    try:
        quoted = dt.datetime.strptime(args.quoted_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)
    except ValueError:
        raise ConfigError("--quoted-at: expected the time of his message, UTC, as YYYY-MM-DDTHH:MM:SSZ") from None
    if ctx.dry_run:
        ctx.say("dry run: no approval record written")
        return EXIT_OK
    record = store.issue(
        model=req.model,
        max_usd=amount,
        job=req.job,
        quote=args.quote,
        quoted_at=quoted,
        now=ctx.now,
        ttl_minutes=args.ttl_minutes,
        beyond_ceiling=args.beyond_ceiling,
        issue_ref=args.issue,
    )
    ctx.say(
        f"approval record {record.id}: {req.model}, job {record.job}, up to {money(amount)} USD, "
        f"single use, expires {record.expires_at.strftime('%Y-%m-%dT%H:%M:%SZ')}. It records the quote; "
        "it is not proof that he said it."
    )
    return EXIT_OK


def run(ctx: LocalContext, args: argparse.Namespace) -> int:
    cfg = _config(ctx, args)
    store = ApprovalStore(gemini_state_dir(ctx.env) / "approvals")
    req = _request(args)
    if args.action == "quota":
        ctx.say(quota_line(cfg, req, ctx.now))
        return EXIT_OK
    if args.action == "approve":
        return _approve(ctx, args, cfg, store, req)
    if args.material != "public":
        raise ConfigError("--material public is required: private or sensitive material never goes to Gemini")
    ctx.say(quota_line(cfg, req, ctx.now))
    if args.cap:
        try:
            cap = Decimal(args.cap)
        except InvalidOperation:
            raise ConfigError("--cap: expected a number of USD") from None
        if req.tier == "paid" and estimate_usd(cfg, req, ctx.now) > cap:
            raise RefusedError(f"the estimate is over the --cap of {money(cap)} USD; nothing was sent")
    if ctx.dry_run:
        ctx.say("dry run: no request sent, no key read, nothing logged")
        return EXIT_OK
    reply = ask(cfg, req, store=store, key_for=doppler_key_provider(cfg, ctx.env), now=ctx.now)
    output.block(ctx.out, reply.text.splitlines() or [""])
    suffix = " (estimate)" if reply.estimated else ""
    ctx.say(
        f"usage: tokens {reply.prompt_tokens} in, {reply.output_tokens} out; cost {fixed(reply.cost_usd)} USD{suffix}"
    )
    if reply.note:
        ctx.say(f"note: {reply.note}")
    ctx.say(reply.quota_line)
    return EXIT_OK


register_local(
    LocalMode("gemini", "ask the free Gemini tier a public question; gate every paid call", add_arguments, run)
)
