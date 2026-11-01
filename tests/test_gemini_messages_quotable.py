# SPDX-License-Identifier: Apache-2.0
"""Every message the Gemini guard can produce is harmless to quote (#264).

An agent that is denied tends to quote the denial back in a brief or a command. The detectors must not react to the
guard's own words, so no message holds a backtick, command text, a declaration prefix at the start of a line, a vendor
or key or host name, an escape, a dollar sign or a quote. This test enumerates the messages from the module constants
and by calling the producing functions, then asks the real detectors about each one, quoted several ways. A negative
control proves the detectors still fire on a real step beside a quote.
Names are built at run time so scanners stay quiet about this file.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from safo import geminibrief as gb
from safo.gemini import PAID_ELSEWHERE, PaidOnlyThroughBroker
from safo.modes import hooks

HOST = "generative" + "language" + ".googleapis" + ".com"
KEY = "GEMINI" + "_API" + "_KEY"
TOOL = "dopp" + "ler"
SHELL_CLASSES = [
    gb.SHELL_VENDOR,
    gb.SHELL_KEY,
    gb.SHELL_STORE,
    gb.SHELL_BUILT,
    gb.SHELL_TOOL,
    gb.SHELL_BROKER_MODULE,
    gb.SHELL_UNVERIFIED,
]
PREFIX = hooks.GEMINI_DENY_PREFIX
STEP = "safo gemini ask --model m --prompt-file p --job j"
PAID_STEP = STEP + " --paid --cap 1"


def _expired(record: str) -> str | None:
    return "the record is expired"


def _raises(record: str) -> str | None:
    raise RuntimeError("boom")


def _boom() -> tuple[re.Pattern[str], ...]:
    raise RuntimeError("boom")


def _briefs() -> list[tuple[str, Any, Any, float | None]]:
    """Representative briefs, one per producing branch: (text, approval check, terms, deadline)."""
    paid = PaidOnlyThroughBroker()
    approved = PAID_STEP + " --approval approval-0001"
    return [
        (STEP, None, (), None),
        (STEP, paid, (), None),
        (STEP + " --paid", paid, (), None),
        (PAID_STEP, _expired, (), None),
        (STEP + " --paid --cap abc", _expired, (), None),
        (STEP + " --paid --cap 99", _expired, (), None),
        (approved, None, (), None),
        (approved, _raises, (), None),
        (approved, _expired, (), None),
        ("eval safo gemini ask --model m --prompt-file p", None, (), None),
        ("xargs safo gemini ask --model m --prompt-file p", None, (), None),
        ("bash -c 'safo gemini ask --model m --prompt-file p'", None, (), None),
        ("safo gemini ask --bogus", None, (), None),
        ("safo gemini ask --model", None, (), None),
        ("safo gemini bogus", None, (), None),
        ("safo gemini ask --model m --prompt-file $F --job j", None, (), None),
        ("safo gemini ask --model m --prompt-file 'a;b' --job j", None, (), None),
        ("safo gemini ask --model m --prompt-file 'a", None, (), None),
        ("gemini: paid cap=1", paid, (), None),
        ("gemini: free", None, (), None),
        ("gemini: paid 'cap", None, (), None),
        ("run safo gem$X ask", None, (), None),
        ("F=safo; $F gemini ask --model m", None, (), None),
        ("x=gemini; safo $x ask --model m --prompt-file p", None, (), None),
        ("\n".join([STEP] * 60), None, (), None),
        ("echo c2FmbyBnZW1pbmk= | base64 -d | sh  # gemini", None, (), None),
        ("gemini " + "x" * (gb.LINE_CAP + 10), None, (), None),
        (f"curl https://{HOST}/v1", None, (), None),
        ("see prd_paid for gemini", None, (), None),
        ("python3 -I -m safo.broker.client", None, (), None),
        (STEP + "\nkey AKIA" + "ABCDEFGHIJKLMNOP", None, (), None),
        ("-----BEGIN PRIVATE" + " KEY-----\n" + STEP, None, (), None),
        (STEP, None, (re.compile("job"),), None),
        (STEP, None, _boom, None),
        (STEP, None, (), 0.0),
    ]


def all_messages() -> list[str]:
    msgs: list[str] = [hooks._TOO_LARGE, hooks._UNVERIFIABLE, hooks._UNREADABLE, hooks.GEMINI_CHECK_FAILED]
    msgs += [hooks.SHELL_DENIAL.format(c) for c in SHELL_CLASSES]
    msgs += [PAID_ELSEWHERE, gb.PAID_DISABLED, gb.TERMS_CHECK_FAILED, gb.FIX]
    msgs += [why for _, why in gb._FAIL_CLOSED]
    for text, check, terms, deadline in _briefs():
        found = gb.findings(text, check, terms, deadline)
        msgs += [f"rule {rule}: {why}" for rule, why in found]
        msgs += [why for _, why in found]
    for cap in (None, "abc", "0", "99"):
        problem = gb._cap_problem(cap)
        if problem:
            msgs.append(problem)
    step = gb.Step(unreadable=True, line=3, why="", matched=gb.MATCH_COMMAND)
    for check in (None, PaidOnlyThroughBroker(), _expired, _raises):
        problem = gb._paid_problem(step, check)
        if problem:
            msgs.append(problem)
    msgs += [gb.MATCH_COMMAND, gb.MATCH_DECLARATION, gb.MATCH_CONFIG, gb.MATCH_MODULE]
    return list(dict.fromkeys(msgs))


MESSAGES = all_messages()
MARKER = re.compile(r"[`$\"'\\]")
DECLARATION_START = re.compile(r"\s*gemini(?:-material|-step)?\s*:", re.IGNORECASE)


def quoted(text: str) -> list[str]:
    return [text, f'"{text}"', f"'{text}'", f"> {text}", f"{PREFIX}{text}", f"- {text}"]


def test_the_enumeration_found_the_messages() -> None:
    assert len(MESSAGES) >= 25, len(MESSAGES)  # something was collected, and from more than one producer
    joined = " ".join(MESSAGES)
    assert "gemini-material" in joined and "gemini-paid" in joined
    assert all(any(c in m for m in MESSAGES) for c in SHELL_CLASSES)


@pytest.mark.parametrize("message", MESSAGES)
def test_a_message_is_free_of_anything_a_detector_reacts_to(message: str) -> None:
    for form in quoted(message):
        assert gb.findings(form) == [], form
        assert gb.shell_command_class(form) is None, form
        assert gb.shell_command_class("echo " + form) is None, form


@pytest.mark.parametrize("message", MESSAGES)
def test_a_message_holds_no_marker_and_does_not_open_a_line_with_the_declaration(message: str) -> None:
    assert not MARKER.search(message), message
    assert not DECLARATION_START.match(message), message
    assert "safo gemini" not in message.lower(), message
    assert HOST not in message and KEY not in message and TOOL not in message


def test_the_detectors_still_fire_beside_a_quote() -> None:
    quote = hooks.SHELL_DENIAL.format(gb.SHELL_KEY)
    assert gb.findings(STEP) != []
    for form in quoted(quote):
        assert gb.findings(form + "\n" + STEP) != [], form
        assert gb.shell_command_class(f"echo {form}; curl https://{HOST}") is not None
    assert gb.shell_command_class(f"echo {quote}; echo ${{{KEY}}}") is not None


def test_the_marker_check_bites_on_a_message_that_holds_one() -> None:
    bad = "this names `safo gemini ask --model M` and " + KEY
    assert MARKER.search(bad) and "safo gemini" in bad.lower()
    assert DECLARATION_START.match("gemini-material: public")


# -- text from a checker, a loader or an exception never reaches a message ---------------------------------------

HOSTILE = "`" + "id" + "` " + "$" + "(" + "x" + ") " + KEY + " 'q' \"r\" example.test"
HOSTILE_PARTS = ("`", "$(", KEY, "example.test", "'q'")
APPROVED = PAID_STEP + " --approval approval-0001"


class _Disabled:
    disabled = HOSTILE

    def __call__(self, record: str) -> str | None:
        return HOSTILE


def _hostile_terms() -> tuple[re.Pattern[str], ...]:
    raise RuntimeError(HOSTILE)


def _hostile_why(record: str) -> str | None:
    return HOSTILE


def _hostile_raise(record: str) -> str | None:
    raise RuntimeError(HOSTILE)


def _hostile_messages() -> list[str]:
    out: list[str] = []
    for check in (_hostile_why, _hostile_raise, _Disabled()):
        out += [why for _, why in gb.findings(APPROVED, check)]
    out += [why for _, why in gb.findings(STEP, None, _hostile_terms)]
    return out


def test_the_checker_branches_really_run() -> None:
    messages = _hostile_messages()
    joined = " ".join(messages)
    assert "the approval record is not usable" in joined
    assert "the approval record could not be checked" in joined
    assert "the private terms could not be loaded" in joined
    assert "paid use exists only through the broker client" in joined


def test_hostile_text_from_a_checker_or_loader_never_reaches_a_message() -> None:
    messages = _hostile_messages()
    assert len(messages) >= 4, messages
    for message in messages:
        assert not any(part in message for part in HOSTILE_PARTS), message
        for form in quoted(message) + quoted(f"rule gemini-paid: {message}"):
            assert gb.findings(form) == [], form
            assert gb.shell_command_class(form) is None, form
            assert gb.shell_command_class("echo " + form) is None, form


def test_the_hostile_text_would_be_caught_if_it_did_reach_a_message() -> None:
    bad = "the private terms could not be loaded (" + HOSTILE + "); fix the terms file"
    assert any(part in bad for part in HOSTILE_PARTS)
    assert gb.shell_command_class(KEY) is not None


def test_the_two_paid_texts_are_the_same() -> None:
    assert gb.PAID_DISABLED == PAID_ELSEWHERE
