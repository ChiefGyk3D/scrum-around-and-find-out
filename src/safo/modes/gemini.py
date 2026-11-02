# SPDX-License-Identifier: Apache-2.0
"""gemini: ask the free tier a public-material question; reach the paid tier only through the broker (#200, #287).

    safo gemini quota   --model M                          print the free quota line and send nothing
    safo gemini ask     --model M --material public --prompt-file F
                                                           print the quota line, send ONE free-tier request, log it
    safo gemini paid    --model M --job J --prompt-file F --max-output-tokens N --max-usd X --quote Q --quoted-at T
                                                           ONE paid call through the broker: shows the whole approval,
                                                           asks for the touch on the security key, sends once
    safo gemini paid-dryrun                                test the signer and the broker with a throw-away signature:
                                                           no call, no reservation, no charge
    safo gemini keys    list | check | propose PUBKEY_FILE --label NAME
                                                           read-only: the enrolled approval keys (never edits them)

The paid path exists only through the broker (docs/gemini-broker.md): this program holds no paid key, signs nothing
for a call itself and sends no paid request. `paid` and `paid-dryrun` are the broker client run from this command
group; `--paid`, `--approval`, `--cap` and `approve` are recognized only so that the dispatch guard keeps reading a
brief that names them as a paid step, and the command refuses them. Read docs/gemini.md.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn

from safo import gemini, geminisign, output
from safo.bounded import read_bounded
from safo.context import LocalContext
from safo.errors import EXIT_OK, ConfigError
from safo.gemini import (
    MAX_PROMPT_BYTES,
    PAID_ELSEWHERE,
    GeminiConfig,
    RefusedError,
    Request,
    ask,
    doppler_key_provider,
    fixed,
    load_config,
    quota_line,
)
from safo.modes import LocalMode, register_local

if TYPE_CHECKING:
    from safo.broker import client


PAID_ACTIONS = ("paid", "paid-dryrun")


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("action", choices=["quota", "approve", "ask", "keys", "paid", "paid-dryrun"])
    parser.add_argument("keys_action", nargs="?", choices=["list", "check", "propose"], help="keys: what to do")
    parser.add_argument("keys_file", nargs="?", default="", help="keys propose: the public key file (.pub)")
    parser.add_argument("--label", default="", help="keys propose: the principal label, such as yubikey-a")
    parser.add_argument("--model", default="", help="a model named in the config (not needed for keys)")
    parser.add_argument("--prompt-file", default="", help="the prompt, from a file (never argv)")
    parser.add_argument("--max-output-tokens", type=int, default=0, help="a hard output limit (default: the config's)")
    parser.add_argument("--material", default="", help="ask: must be `public`; nothing private goes to Gemini")
    # Recognized so the dispatch guard reads a brief that names them as a paid step; the command refuses them (#287).
    parser.add_argument("--paid", action="store_true", help="REMOVED: the paid path is `safo gemini paid`")
    parser.add_argument("--approval", default="", help="REMOVED: an approval is signed for one call by `paid`")
    parser.add_argument("--cap", default="", help="REMOVED")
    parser.add_argument("--ttl-minutes", type=int, default=0, help="REMOVED")
    parser.add_argument("--amount-usd", default="", help="REMOVED")
    parser.add_argument("--on-date", default="", help="REMOVED")
    parser.add_argument("--note", default="", help="REMOVED")
    # paid, paid-dryrun
    parser.add_argument("--job", default="", help="paid: the job an approval is for; paid-dryrun: a label")
    parser.add_argument("--max-usd", default="", help="paid: the most this call may cost, at most 2")
    parser.add_argument("--quote", default="", help="paid: the maintainer's message, as he wrote it")
    parser.add_argument("--quoted-at", default="", help="paid: when he wrote it, UTC, YYYY-MM-DDTHH:MM:SSZ")
    parser.add_argument("--issue", default="", help="paid: the tracking issue, owner/repo#N")
    parser.add_argument("--kind", choices=["text", "image"], default="text", help="paid: text or image")
    parser.add_argument("--count", type=int, default=None, help="paid image: how many images (default 1)")
    parser.add_argument("--image-size", default="", help="paid image: the size, such as 1K")
    parser.add_argument("--aspect-ratio", default="", help="paid image: the ratio, such as 1:1 (default 1:1)")


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
    if ns.action in ("quota", "approve", "ask", "paid") and not ns.model:
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
        tier="free",
        job=args.job,
        approval="",
        max_output_tokens=args.max_output_tokens,
    )


def _trust() -> geminisign.Trust:
    loc = gemini.fixed_locations()
    return geminisign.Trust(loc.signers, loc.revoked, loc.trust_uid, loc.require_hardware, loc.revocation_required)


def run_keys(ctx: LocalContext, args: argparse.Namespace) -> int:
    """Read-only. The maintainer enrolls, rotates or revokes a key by editing the two trust files by hand."""
    trust = _trust()
    if args.keys_action in ("list", "check") and not os.path.lexists(trust.signers):
        ctx.say("no allowed-signers file: there are no approval keys to list or check")
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


def broker_setup(ctx: LocalContext) -> tuple[client.ClientConfig, client.Deps]:
    """The broker client's configuration and dependencies for this command: ~/.config/safo/broker-client.yaml (and the
    root-owned file beside it), the broker's socket, the signer, the terminal. The one seam a test replaces."""
    from safo.broker import client  # deferred: the guard's entry point must not load the client at import

    cfg = client.load_client_config(home=ctx.home)
    stdin = ctx.stdin if ctx.stdin is not None else sys.stdin
    return cfg, client.default_deps(cfg, ctx.env, stdin, ctx.out, ctx.home)


def run_paid(ctx: LocalContext, args: argparse.Namespace) -> int:
    """ONE paid call, through the broker client and nowhere else. The model, job, amount, quote and prompt are checked
    by the client before a socket is opened; the person sees the whole approval and touches the key."""
    from safo.broker import client

    if args.kind == "text" and (args.count is not None or args.image_size or args.aspect_ratio):
        raise ConfigError("a text request has no image count, size or aspect ratio")
    image = args.kind == "image"
    params = client.PaidParams(
        model=args.model,
        job=args.job,
        kind=args.kind,
        prompt=_prompt(args),
        max_output_tokens=args.max_output_tokens,
        max_usd=args.max_usd,
        quote=args.quote,
        quoted_at=args.quoted_at,
        issue=args.issue,
        count=(1 if args.count is None else args.count) if image else 0,
        image_size=args.image_size,
        aspect_ratio=(args.aspect_ratio or "1:1") if image else "",
    )
    if ctx.dry_run:
        client.check_params(params)  # the same checks the client makes first; no socket, no key, no broker
        ctx.say("dry run: the request is well formed; nothing was signed, sent or reserved")
        return EXIT_OK
    cfg, deps = broker_setup(ctx)
    return client.run_paid(params, cfg, deps, ctx.out, ctx.out)


def run_paid_dryrun(ctx: LocalContext, args: argparse.Namespace) -> int:
    from safo.broker import client

    if ctx.dry_run:
        ctx.say("dry run: nothing was signed or sent")
        return EXIT_OK
    cfg, deps = broker_setup(ctx)
    return client.run_dryrun(cfg, deps, ctx.out, ctx.out, args.job or "signer-check")


def run(ctx: LocalContext, args: argparse.Namespace) -> int:
    if args.action != "keys" and (args.keys_action or args.keys_file):
        raise ConfigError("unrecognized arguments: a word after the action")
    removed = (
        args.action == "approve"
        or args.paid
        or args.approval
        or args.cap
        or args.ttl_minutes
        or args.amount_usd
        or args.on_date
        or args.note
    )
    if removed:
        raise RefusedError(PAID_ELSEWHERE)  # before a config, a prompt or a key is read
    if args.action == "keys":
        return run_keys(ctx, args)
    if args.action == "paid":
        return run_paid(ctx, args)
    if args.action == "paid-dryrun":
        return run_paid_dryrun(ctx, args)
    cfg = _config()
    if not args.model:
        raise ConfigError("--model is required")
    req = _request(args)
    if args.action == "quota":
        ctx.say(quota_line(cfg, req, ctx.now))
        return EXIT_OK
    if args.material != "public":
        raise ConfigError("--material public is required: private or sensitive material never goes to Gemini")
    ctx.say(quota_line(cfg, req, ctx.now))
    if ctx.dry_run:
        ctx.say("dry run: no request sent, no key read, nothing logged")
        return EXIT_OK
    reply = ask(cfg, req, key_for=doppler_key_provider(cfg, ctx.env), now=ctx.now)
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
    LocalMode(
        "gemini", "ask the free Gemini tier a public question; paid calls only through the broker", add_arguments, run
    )
)
