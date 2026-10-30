# SPDX-License-Identifier: Apache-2.0
"""gemini: ask the free tier a public-material question, and gate every paid one (#200).

    safo gemini quota   --model M [--paid ...]            print the quota line and send nothing
    safo gemini approve --model M --max-usd X --job J --quote Q --quoted-at T --prompt-file F
                                                           print the quota line, then write one single-use approval
    safo gemini ask     --model M --material public --prompt-file F [--paid --job J --approval ID]
                                                           print the quota line, send ONE request, log it
    safo gemini keys    list | check | propose PUBKEY_FILE --label NAME
                                                           read-only: the enrolled approval keys (never edits them)
    safo gemini usage   --amount-usd X --on-date YYYY-MM-DD --note TEXT
                                                           add a vendor-observed spend row to the chained ledger

Read docs/gemini.md. `approve` asks the maintainer's security key to SIGN his approval (a touch); run it only after he
has said yes in his own message, and he touches the key only after reading the quota line.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import os
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn, TextIO

from safo import gemini, geminisign, output
from safo.bounded import read_bounded
from safo.context import LocalContext
from safo.errors import EXIT_OK, ConfigError
from safo.gemini import (
    DEFAULT_TTL_MINUTES,
    MAX_APPROVED_PROMPT_CHARS,
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
    load_config,
    money,
    open_store,
    paid_quota,
    prompt_binding,
    quota_line,
    snapshot,
    too_long,
    usd_amount,
)
from safo.modes import LocalMode, register_local


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("action", choices=["quota", "approve", "ask", "keys", "usage"])
    parser.add_argument("keys_action", nargs="?", choices=["list", "check", "propose"], help="keys: what to do")
    parser.add_argument("keys_file", nargs="?", default="", help="keys propose: the public key file (.pub)")
    parser.add_argument("--label", default="", help="keys propose: the principal label, such as yubikey-a")
    parser.add_argument("--amount-usd", default="", help="usage: the spend to add, in USD")
    parser.add_argument("--on-date", default="", help="usage: the date of that spend, YYYY-MM-DD")
    parser.add_argument("--note", default="", help="usage: where the number came from")
    parser.add_argument("--model", default="", help="a model named in the config (not needed for keys and usage)")
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
    parser.add_argument(
        "--ttl-minutes", type=int, default=DEFAULT_TTL_MINUTES, help="approve: how long the record lives (at most 60)"
    )
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
    ns = parser.parse_args(tokens)
    if ns.action in ("quota", "approve", "ask") and not ns.model:
        raise BriefParseError("the following arguments are required: --model")
    if ns.action not in ("keys",) and (ns.keys_action or ns.keys_file):
        raise BriefParseError("unrecognized arguments: a word after the action")
    return ns


def _config() -> GeminiConfig:
    """The config is at the fixed location; no flag and no variable names another."""
    loc = gemini.fixed_locations()
    return load_config(loc.config, loc.home)


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


def _is_tty(stream: object) -> bool:
    check = getattr(stream, "isatty", None)
    try:
        return bool(check()) if callable(check) else False
    except (OSError, ValueError):
        return False


def _ask_line(ctx: LocalContext, stdin: TextIO, prompt: str) -> str:
    ctx.say(prompt)
    return stdin.readline()


def approve_flow(
    ctx: LocalContext,
    args: argparse.Namespace,
    cfg: GeminiConfig,
    store: ApprovalStore,
    req: Request,
    *,
    interactive: bool,
    confirm: Callable[[str], str],
) -> int:
    """Write one approval record, but only for a person at a terminal who types the confirmation phrase.

    `interactive` and `confirm` are arguments, not flags: the command line passes the real streams, and only a test can
    pass anything else. The ceiling flag comes from the ledger here, never from the caller."""
    if not ctx.dry_run:
        gemini.require_paid()  # a dry run spends nothing and writes nothing, so it can still test a key
    if not req.prompt:
        raise ConfigError("approve needs --prompt-file: an approval covers the exact prompt that `ask` will read")
    # One snapshot: the display, the digest and the signature all come from this text, never from `req` again.
    text = bytes.decode(gemini.prompt_bytes(req.prompt), "utf-8")
    req = dataclasses.replace(req, prompt=text)
    if len(text) > MAX_APPROVED_PROMPT_CHARS:
        raise RefusedError(too_long(len(text)))
    digest, size = prompt_binding(text)  # the same bytes `ask` sends, from the same file
    line = quota_line(cfg, req, ctx.now)  # first: an approval is refused when the line cannot be produced
    ctx.say(line)
    amount = usd_amount(args.max_usd, "--max-usd")
    estimate = estimate_usd(cfg, req, ctx.now)
    if estimate > cfg.job_cap:
        raise RefusedError(
            f"the estimate {money(estimate)} USD is over the {money(cfg.job_cap)} USD job cap; lower the output limit"
        )
    if estimate > amount:
        raise RefusedError(
            f"the estimate {money(estimate)} USD is over the amount to be approved ({money(amount)} USD)"
        )
    beyond = paid_quota(cfg, snapshot(Ledger(cfg.ledger).read()), req, ctx.now).beyond
    try:
        quoted = dt.datetime.strptime(args.quoted_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)
    except ValueError:
        raise ConfigError("--quoted-at: expected the time of his message, UTC, as YYYY-MM-DDTHH:MM:SSZ") from None
    if not interactive:
        raise RefusedError(
            "approve needs a person at a terminal: standard input and output must both be one. "
            "The quota line above is what the person would be shown"
        )
    phrase = f"approve {req.job}"
    ctx.say(f"quote of his message ({args.quoted_at}): {args.quote}")
    ctx.say(f"prompt: {len(text)} characters, {size} bytes, SHA-256 {digest}")
    ctx.say("--- the WHOLE prompt starts (line by line; non-ASCII and control characters are escaped) ---")
    for number, row in enumerate(text.split("\n"), 1):
        ctx.say(f"{number:4d}| {row!a}")
    ctx.say("--- the prompt ends ---")
    ctx.say(
        f"you are approving up to {money(amount)} USD on {req.model} for job {req.job}"
        + (" and it PASSES the monthly ceiling" if beyond else "")
    )
    ctx.say(
        "your security key will blink next. Touch it only because you have just read the quota line, the quote and "
        "the whole prompt and its digest above and they are right; the signature covers that exact prompt and no "
        "other. "
        "If you did not start this, do not touch it."
    )
    if confirm(f"type exactly `{phrase}` to approve, anything else cancels: ").strip() != phrase:
        raise RefusedError("not confirmed; no approval record was written")
    if ctx.dry_run:
        # signs a throw-away text in another namespace and checks it: tests the key and the enrollment, spends nothing,
        # writes no record and no ledger row
        trust = store.trust
        if trust is None or not store.signing_key or not store.signing_principal:
            raise RefusedError("signing is not set up (signing.key and signing.principal in gemini.yaml)")
        text = geminisign.canonical({"dry_run": True, "job": req.job})
        armor = geminisign.sign(store.signing_key, text.encode(), geminisign.DRYRUN_NAMESPACE, ctx.env)
        who = geminisign.verify(trust, text.encode(), armor, namespace=geminisign.DRYRUN_NAMESPACE, now=ctx.now)
        if who.label != store.signing_principal:
            raise RefusedError("the key that signed is not the principal named in gemini.yaml")
        ctx.say(
            f"dry run: the signature verifies. principal {who.label}, {who.key_type}, {who.fingerprint}, "
            f"touch {'seen' if who.user_present else 'not shown (a software key reports none)'}, "
            f"PIN {'seen' if who.user_verified else 'not shown'}. No approval record and no ledger row were written."
        )
        return EXIT_OK
    record = store.issue(
        model=req.model,
        max_usd=amount,
        job=req.job,
        quote=args.quote,
        quoted_at=quoted,
        now=ctx.now,
        ttl_minutes=args.ttl_minutes,
        beyond_ceiling=beyond,
        prompt=text,
        issue_ref=args.issue,
    )
    ctx.say(
        f"approval record {record.id}: {req.model}, job {record.job}, up to {money(amount)} USD, "
        f"single use, signed by {record.principal}, expires {record.expires_at.strftime('%Y-%m-%dT%H:%M:%SZ')}."
    )
    return EXIT_OK


def _trust() -> geminisign.Trust:
    loc = gemini.fixed_locations()
    return geminisign.Trust(loc.signers, loc.revoked, loc.trust_uid, loc.require_hardware, loc.revocation_required)


def run_keys(ctx: LocalContext, args: argparse.Namespace) -> int:
    """Read-only. The maintainer enrolls, rotates or revokes a key by editing the two trust files by hand."""
    trust = _trust()
    if args.keys_action in ("list", "check") and not os.path.lexists(trust.signers) and not gemini.paid_enabled():
        ctx.say("no allowed-signers file, and paid use is disabled: there are no approval keys to list or check")
        return EXIT_OK
    if args.keys_action == "list":
        for row in geminisign.key_rows(trust, ctx.now) or ["(no key is enrolled)"]:
            ctx.say(row)
        return EXIT_OK
    if args.keys_action == "check":
        problems, warnings = geminisign.check_report(trust, ctx.now)
        for line in problems:
            ctx.say(f"PROBLEM: {line}")
        for line in warnings:
            ctx.say(f"WARNING: {line}")
        if problems:
            raise RefusedError("keys check found problems (above)")
        ctx.say(f"ok: every enrolled key parses, none carries no-touch-required ({len(warnings)} warnings)")
        return EXIT_OK
    if args.keys_action == "propose":
        if not args.keys_file or not args.label:
            raise ConfigError("keys propose needs a public key file and --label NAME")
        for line in geminisign.propose_line(trust, Path(args.keys_file), args.label):
            ctx.say(line)
        return EXIT_OK
    raise ConfigError("keys: say list, check or propose")


def run_usage(ctx: LocalContext, args: argparse.Namespace, cfg: GeminiConfig) -> int:
    amount = usd_amount(args.amount_usd, "--amount-usd")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.on_date):
        raise ConfigError("--on-date: expected YYYY-MM-DD")
    if not args.note.strip() or len(args.note) > 300:
        raise ConfigError("--note: say where the number came from (1 to 300 characters)")
    if ctx.dry_run:
        ctx.say("dry run: nothing written")
        return EXIT_OK
    ledger = Ledger(cfg.ledger)
    with ledger.lock():
        ledger.append(
            {"type": "usage", "date": args.on_date, "amount_usd": float(amount), "note": args.note.strip()},
            ts=gemini.stamp(ctx.now),
        )
    ctx.say(f"added {money(amount)} USD for {args.on_date} to the chained ledger")
    return EXIT_OK


def run(ctx: LocalContext, args: argparse.Namespace) -> int:
    if args.action != "keys" and (args.keys_action or args.keys_file):
        raise ConfigError("unrecognized arguments: a word after the action")
    if args.action == "keys":
        return run_keys(ctx, args)
    cfg = _config()
    if args.action == "usage":
        return run_usage(ctx, args, cfg)
    if not args.model:
        raise ConfigError("--model is required")
    store = open_store(gemini.fixed_locations(), cfg.ledger, cfg.signing_key, cfg.signing_principal, ctx.env)
    req = _request(args)
    if args.action == "quota":
        ctx.say(quota_line(cfg, req, ctx.now))
        return EXIT_OK
    if args.action == "approve":
        stdin = ctx.stdin if ctx.stdin is not None else sys.stdin
        return approve_flow(
            ctx,
            args,
            cfg,
            store,
            req,
            interactive=_is_tty(stdin) and _is_tty(ctx.out),
            confirm=lambda prompt: _ask_line(ctx, stdin, prompt),
        )
    if args.material != "public":
        raise ConfigError("--material public is required: private or sensitive material never goes to Gemini")
    ctx.say(quota_line(cfg, req, ctx.now))
    if args.cap:
        cap = usd_amount(args.cap, "--cap")
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
