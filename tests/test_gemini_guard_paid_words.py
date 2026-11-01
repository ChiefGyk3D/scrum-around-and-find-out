# SPDX-License-Identifier: Apache-2.0
"""The guard keeps denying paid use outside the broker flow (#287). The broker entries (`paid`, `paid-dryrun`) are paid
action words: a command that uses one, written out, built at run time, spread over a variable or split across
arguments, is denied or treated as unreadable exactly like the same shape with `approve` on main. Nothing is allowed
through in a brief; the real command a person types at a terminal is not a brief, and the shell check lets it pass."""

from __future__ import annotations

import pytest

from safo import geminibrief
from safo.gemini import PaidOnlyThroughBroker

PUBLIC = "gemini-material: public\n"


def rules(text: str) -> set[str]:
    return {rule for rule, _ in geminibrief.findings(text + PUBLIC, PaidOnlyThroughBroker())}


# Each shape is denied on main with `approve` (the reference, asserted here against the same code path), and must be
# denied with each paid word.
SHAPES = [
    "safo gemini {w} --model m --job j --prompt-file p --max-usd 1\n",
    "A={w}; safo gemini $A --model m --job j --max-usd 1\n",
    'eval "safo gemini {w} --model m --job j --max-usd 1"\n',
    "eval 'safo gemini '{w}' --model m'\n",
    "bash -c 'safo gemini {w} --model m --job j --max-usd 1'\n",
    "echo {w} --model m --job j | xargs safo gemini\n",
    "echo {w} | xargs -I{{}} safo gemini {{}} --model m --job j --max-usd 1\n",
    "echo {w} | xargs safo gemini\n",
    "echo --model m --job j --max-usd 1 > o; echo {w} | xargs safo gemini $(cat o)\n",
    "for a in {w}; do safo gemini $a --model m; done\n",
    "W={w}\nsafo gemini --model m --job j --max-usd 1 $W\n",
    "safo gemini $X {w}\n",
    "safo gemini $X --job j --max-usd 1\n",
    "printf '%s\\n' {w} | xargs -n1 safo gemini\n",
    # prose-looking and table-looking lines that hold a real command (the neutralizing rewrite must not hide them)
    "| step | `echo {w} | xargs safo gemini` |\n",
    "| step | `safo gemini {w} --model m --job j --max-usd 1` |\n",
    "| a | b |\n| `safo gemini x {w}` | `echo {w} | xargs safo gemini` |\n",
    "safo gemini x {w}\n",
    "the user then runs safo gemini {w} --model m\n",
    "note: echo ok | safo gemini x {w}\n",
    "echo {w} | sh -c 'xargs safo gemini'\n",
]


SHAPE_COUNT = 21  # the exact size of SHAPES; a shape removed or added must change this number on purpose


def test_the_shape_list_has_exactly_the_expected_shapes() -> None:
    """The parametrized test below cannot pass by collecting less: the list is counted, and no shape repeats."""
    assert len(SHAPES) == SHAPE_COUNT
    assert len(set(SHAPES)) == SHAPE_COUNT


def test_every_shape_is_denied_on_main_for_approve() -> None:
    """The reference: each shape is a denied shape for `approve`. A shape that is not denied fails here, it is never
    skipped, so the paid-word comparison below cannot lose a shape quietly."""
    not_denied = [s for s in SHAPES if "gemini-paid" not in rules(s.format(w="approve"))]
    assert not_denied == []
    assert "gemini-paid" not in rules("echo hello\n")  # the negative case: the reference does tell denied from allowed


@pytest.mark.parametrize("word", ["paid", "paid-dryrun"])
@pytest.mark.parametrize("shape", SHAPES)
def test_every_shape_denied_for_approve_is_denied_for_the_paid_words(shape: str, word: str) -> None:
    assert "gemini-paid" in rules(shape.format(w="approve")), shape
    assert "gemini-paid" in rules(shape.format(w=word)), shape.format(w=word)


@pytest.mark.parametrize("word", ["paid", "paid-dryrun"])
def test_a_word_split_across_two_arguments_is_unreadable(word: str) -> None:
    half = len(word) // 2
    brief = f'set -- {word[:half]} {word[half:]}\nsafo gemini "$1$2" --model m --job j --max-usd 1\n'
    assert "gemini-paid" in rules(brief)


@pytest.mark.parametrize(
    "prose",
    [
        "The paid tier is used through the broker when the maintainer allows it.\n",
        "Paid use needs a touch on the security key.\n",
        "Run `safo gemini quota --model gemini-3.6-flash` to see the line.\n",
        "| Tier | What signs |\n|---|---|\n| paid | a hardware key |\n",
        "Use the `paid` command of the broker, or `paid-dryrun` to test the key.\n",
        "See `docs/gemini-broker.md` about gemini and the paid path.\n",
    ],
)
def test_prose_and_markdown_code_spans_stay_allowed(prose: str) -> None:
    assert "gemini-paid" not in rules(prose)


def test_the_real_broker_command_is_not_blocked_by_the_shell_check() -> None:
    """A person at a terminal types it; it names no vendor host, SDK or key, so the Bash check lets it through. (A brief
    that carries it is denied by the rule above: a brief cannot be a person at a terminal.)"""
    command = "safo gemini paid --model m --job j --prompt-file p --max-output-tokens 100 --max-usd 1 --quote q"
    assert geminibrief.shell_command_class(command) is None
    assert geminibrief.shell_command_class("safo gemini paid-dryrun") is None
    assert "gemini-paid" in rules(command + "\n")


# -- the broker client's own module entry (#299) ----------------------------------------------------------------------
# `python3 -I -m safo.broker.client` reaches the same paid call as `safo gemini paid`, but without the wrapper (its
# sanitized environment, private directory and closed descriptors). It is a paid command word like `paid`: denied in a
# brief, unreadable in run-time forms, and refused by the Bash check (an agent never runs it; a person types it at a
# terminal, where no hook reads it). `safo gemini paid` itself stays allowed by the Bash check, as before.
MODULE = "safo" + "." + "broker" + "." + "client"
MODULE_PATH = "src/safo/broker/client.py"
MODULE_SHAPES = [
    # the entry itself, as the module docstring writes it, and spellings of the interpreter and the option
    "python3 -I -m {m} --model m --job j --prompt-file p --max-usd 1\n",
    "python -m {m} --model m\n",
    "python3 -Im {m} --model m\n",
    "/usr/bin/python3.12 -I -m {m} --model m --job j\n",
    "env -i python3 -I -m {m} --model m\n",
    "python3 -I -m '{m}' --model m\n",
    'python3 -I -m "safo.broker.""client" --model m\n',
    "python3 -I -m {m} --help\n",
    # the wrapped and indirect forms of the paid-word list above
    "A={m}; python3 -I -m $A --model m --job j --max-usd 1\n",
    'eval "python3 -I -m {m} --model m --job j --max-usd 1"\n',
    "eval 'python3 -I -m '{m}' --model m'\n",
    "bash -c 'python3 -I -m {m} --model m --job j --max-usd 1'\n",
    "echo {m} --model m --job j | xargs python3 -I -m\n",
    "echo {m} | xargs -I{{}} python3 -I -m {{}} --model m --job j --max-usd 1\n",
    "echo {m} | xargs python3 -m\n",
    "echo --model m --job j --max-usd 1 > o; echo {m} | xargs python3 -m $(cat o)\n",
    "for a in {m}; do python3 -I -m $a --model m; done\n",
    "W={m}\npython3 -I -m $W --model m --job j --max-usd 1\n",
    "python3 -I -m $X {m}\n",
    "python3 -I -m $X --job j --max-usd 1\n",
    "printf '%s\\n' {m} | xargs -n1 python3 -m\n",
    "echo {m} | sh -c 'xargs python3 -m'\n",
    # prose-looking and table-looking lines that hold a real command
    "| step | `echo {m} | xargs python3 -m` |\n",
    "| step | `python3 -I -m {m} --model m --job j --max-usd 1` |\n",
    "| a | b |\n| `python3 -m {m}` | `echo {m} | xargs python3 -m` |\n",
    "the user then runs python3 -I -m {m} --model m\n",
    "note: echo ok | python3 -I -m {m}\n",
    # other ways to start the same code
    "python3 -I src/safo/broker/client.py --model m --job j\n",
    "python3 -I -X dev src/safo/broker/client.py --model m\n",
    "cd src/safo/broker && python3 -I client.py --model m\n",
    "echo src/safo/broker/client.py | xargs python3 -I\n",
    "python3 -I -c 'import {m} as c; c.main()'\n",
    "python3 -I -c 'from safo.broker import client; client.main()'\n",
    "python3 -I -c 'from {m} import main; main()'\n",
    'python3 -I -c \'import runpy; runpy.run_module("{m}", run_name="__main__")\'\n',
    'python3 -I -c \'import importlib; importlib.import_module("safo.broker." + "client").main()\'\n',
    "python3 - <<EOF\nimport {m}\nEOF\n",
    "python3 -I -m $1$2 --model m\nset -- safo.broker. client\n",
    # script paths that are not normalized: repeated slashes, dot segments, parent segments, an absolute path
    "python3 -I src//safo/broker/client.py --model m\n",
    "python3 -I src/safo/./broker/client.py --model m\n",
    "python3 -I src/safo/other/../broker/client.py --model m\n",
    "python3 -I /home/u/src/safo///broker//client.py --model m\n",
    "python3 -I ./src/safo/broker/./client.py --model m\n",
    "cd src/safo/broker && python3 -I ../broker/client.py --model m\n",
    "cd src/safo/broker && python3 -I ./client.py --model m\n",
    # a -m value that ends in client with other leading parts, while the broker is named
    "python3 -I -m other.broker.client --model m\n",
    "cd src && python3 -I -m safo.broker.client --model m\n",
    "cd src/safo/broker && python3 -I -m client --model m\n",
    "python3 -I -m x.y.client --model m # the broker client\n",
    # a name built from parts, and dynamic imports
    'python3 -I -c \'import importlib; n = "safo." + "broker." + "cli" + "ent"; importlib.import_module(n).main()\'\n',
    'python3 -I -c \'__import__("safo" + ".broker" + ".client")\'\n',
    "python3 -I -c '" + "ex" + 'ec("import safo.broker." + "client")\'\n',  # split so the hygiene scan sees no call
    'python3 -I -c \'import runpy; runpy.run_module("saf" + "o.broker.cli" + "ent", run_name="__main__")\'\n',
    "python3 - <<EOF\nimport importlib\nn = 'safo.' + 'broker'\nm = importlib.import_module(n + '.cl' + 'ient')\nEOF\n",
    'python3 -I -c \'import importlib; importlib.import_module("saf" + "o.br" + "oker.client")\'\n',
]
MODULE_SHAPE_COUNT = 55  # exact: a shape removed or added must change this number on purpose


def test_the_module_shape_list_has_exactly_the_expected_shapes() -> None:
    assert len(MODULE_SHAPES) == MODULE_SHAPE_COUNT
    assert len(set(MODULE_SHAPES)) == MODULE_SHAPE_COUNT


@pytest.mark.parametrize("shape", MODULE_SHAPES)
def test_every_module_entry_shape_is_denied_in_a_brief(shape: str) -> None:
    assert "gemini-paid" in rules(shape.format(m=MODULE)), shape


@pytest.mark.parametrize("shape", MODULE_SHAPES)
def test_every_module_entry_shape_is_refused_by_the_shell_check(shape: str) -> None:
    assert geminibrief.shell_command_class(shape.format(m=MODULE)) is not None, shape


def test_the_shell_class_for_the_module_entry_is_a_fixed_phrase_that_repeats_nothing() -> None:
    found = geminibrief.shell_command_class(f"python3 -I -m {MODULE} --model secretmodelname")
    assert found == geminibrief.SHELL_BROKER_MODULE
    assert "secretmodelname" not in (found or "") and MODULE not in (found or "")


@pytest.mark.parametrize(
    "text",
    [
        f"The `{MODULE}` module signs the request and prints the receipt.\n",
        f"Edit {MODULE_PATH} and run `python3 -m pytest tests/test_broker_client.py`.\n",
        f"python3 -m mypy {MODULE_PATH}\n",
        f"python3 -m ruff check {MODULE_PATH}\n",
        f"git diff origin/main -- {MODULE_PATH}\n",
        f"python3 -m pytest --cov={MODULE} tests\n",
        "python3 -I -m safo.broker.admin check-install\n",
        "python3 -I -m safo.broker\n",
        "python3 -m pytest -k client tests\n",
        "python3 -m venv .venv && .venv/bin/python -m pip install -e .\n",
        "python3 -m pytest tests/test_broker_client.py\n",
        "python3 -m mypy src/safo//broker/../broker/client.py\n",
        "python3 -I -m other.module --x\n",
        "python3 -c 'import importlib; print(importlib.import_module(\"json\").__name__)'\n",
        "python3 scripts/other_client.py\n",
    ],
)
def test_naming_the_module_or_its_file_without_running_it_stays_allowed(text: str) -> None:
    assert "gemini-paid" not in rules(text)
    assert geminibrief.shell_command_class(text.strip("\n").replace("`", "")) is None


def test_the_real_broker_command_is_still_allowed_by_the_shell_check_and_denied_in_a_brief() -> None:
    """Unchanged: `safo gemini paid` is what a person types; only the module entry is newly refused."""
    assert geminibrief.shell_command_class("safo gemini paid --model m --job j") is None
    assert "gemini-paid" in rules("safo gemini paid --model m --job j\n")


def test_a_long_run_of_interpreter_options_is_read_without_backtracking() -> None:
    """The script-path reader repeats over interpreter options; a hostile run of them must not make it slow, whether
    the path follows (denied) or not (allowed)."""
    import time

    options = "-x " * 1200
    for tail, denied in (("src/safo/broker/client.py", True), ("src/safo/other.py", False)):
        command = f"python3 {options}{tail}"
        assert len(command) < geminibrief.LINE_CAP
        start = time.monotonic()
        found = geminibrief.shell_command_class(command)
        assert time.monotonic() - start < 2.0
        assert (found is not None) is denied, tail
        if denied:
            assert found == geminibrief.SHELL_BROKER_MODULE


def test_a_long_line_that_names_the_broker_client_is_refused_unread() -> None:
    line = "echo " + "x " * geminibrief.LINE_CAP + " broker client\n"
    assert "gemini-paid" in rules(line)
    assert geminibrief.shell_command_class(line) is not None
    assert "gemini-paid" not in rules("echo " + "x " * geminibrief.LINE_CAP + "\n")


# -- the route detector is bounded work that obeys the guard deadline (#299) ------------------------------------------
# No wall time here: work is counted as scanner steps (ticks the detector reports to the guard) and the deadline is an
# injected clock that advances one unit per reading.

HOSTILE_LINES = {
    "a long run of spaces after -m": "broker python3 -m" + " " * 3900 + "x",
    "a long run of tabs and spaces": "broker python3 -m" + " \t" * 1900 + "x",
    "a long run of options": "broker python3 " + "-x " * 1200,
    "repeated dot segments": "broker python3 src/" + "./" * 1900 + "client.py",
    "repeated parent segments": "broker python3 src/a/" + "../a/" * 600 + "client.py",
    "repeated slashes": "broker python3 " + "/" * 3800 + "client.py",
    "repeated dots": "broker python3 " + "." * 3900,
    "a long quoted string": "broker python3 -m '" + "a" * 3900 + "'",
    "many quotes": "broker python3 -m " + "''" * 1900,
    "many python words": "broker " + "python3 " * 490 + "-m",
    "many dashes": "broker python3 " + "-m " * 1200,
}


def route_steps(lines: list[str]) -> tuple[bool, int]:
    steps = [0]

    def tick() -> None:
        steps[0] += 1

    found = geminibrief.broker_module_route(lines, tick=tick)
    return found, steps[0]


@pytest.mark.parametrize("name", list(HOSTILE_LINES))
def test_a_hostile_line_costs_a_bounded_number_of_scanner_steps(name: str) -> None:
    line = HOSTILE_LINES[name]
    assert len(line) < geminibrief.LINE_CAP
    _, steps = route_steps([line])
    assert 1 <= steps <= 30  # a line costs a few rule steps, however it is shaped
    _, many = route_steps([line] * 200)
    assert many <= 200 * 30 + 30  # and the cost grows with the line count, not with anything inside a line


def test_the_hostile_line_table_is_not_trimmed() -> None:
    assert len(HOSTILE_LINES) == 11


def test_whitespace_runs_are_squeezed_before_any_rule_reads_the_line() -> None:
    assert len(geminibrief._compact("a" + " " * 3900 + "\t" * 50 + "b")) == 3
    assert geminibrief._compact("x \t\n y") == "x y"


def test_no_route_pattern_has_two_adjacent_unbounded_whitespace_repeats() -> None:
    """The shape that cost 0.2 s a line (`\\s*=?\\s*` over a long run of spaces): a source guard on every pattern."""
    import re

    bad = re.compile(r"\\s\*(?:=\?)?\\s\*|\\s\+(?:=\?)?\\s[*+]")
    patterns = {n: p for n, p in vars(geminibrief).items() if n.startswith("_BM_") and isinstance(p, re.Pattern)}
    assert len(patterns) >= 10, "something was collected"
    assert [n for n, p in patterns.items() if bad.search(p.pattern)] == []
    assert bad.search(r"-[a-z]*m\s*=?\s*x")  # the negative case: the guard does catch the old shape


class StepClock:
    """A monotonic clock that advances one unit per reading, in place of wall time."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        self.now += 1.0
        return self.now


def slow_route(monkeypatch: pytest.MonkeyPatch) -> StepClock:
    """The injected clock, and a route detector whose line reading takes 1000 units (stands in for slow regex work)."""
    clock = StepClock()
    monkeypatch.setattr("safo.geminibrief.time.monotonic", clock)
    monkeypatch.setattr("safo.modes.hooks.time.monotonic", clock)
    flat = geminibrief._flat_paths

    def slow(v: str) -> str:
        clock.now += 1000.0
        return flat(v)

    monkeypatch.setattr(geminibrief, "_flat_paths", slow)
    return clock


def test_the_shell_check_obeys_its_deadline_inside_the_route_detector(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = slow_route(monkeypatch)
    command = "python3 -m pytest\npython3 -m ruff check"  # nothing wrong with it, but reading it is slow
    found = geminibrief.shell_command_class(command, deadline=clock.now + 500)
    assert found == geminibrief.SHELL_UNVERIFIED  # a late answer is "could not be checked", never "fine"


def test_the_brief_scan_fails_closed_on_its_deadline_inside_the_route_detector(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = slow_route(monkeypatch)
    got = geminibrief.findings(
        "python3 -m pytest\npython3 -m ruff check\n" + PUBLIC, PaidOnlyThroughBroker(), deadline=clock.now + 500
    )
    assert "gemini-paid" in {rule for rule, _ in got}


def test_the_oversized_event_scan_obeys_its_deadline_inside_the_route_detector(monkeypatch: pytest.MonkeyPatch) -> None:
    from safo.modes.hooks import EventScan

    clock = slow_route(monkeypatch)
    scan = EventScan(clock.now + 500)
    with pytest.raises(TimeoutError):
        scan.feed(b"broker python3 -m pytest\npython3 -m ruff check")


# -- every cap fails closed (#299) -------------------------------------------------------------------------------------
# A bound on a line or on a count in a denylist detector must refuse what it cannot read, never skip it. Each case below
# is a cap, one past it, and an ordinary input that must still pass.

MODULE_ENTRY = "python3 -I -m " + MODULE


def test_a_line_over_the_line_cap_that_could_hold_the_pattern_is_refused_and_ordinary_code_is_not() -> None:
    cap = geminibrief.LINE_CAP
    at_cap = "python3 " + "x" * (cap - len("python3 "))
    assert len(at_cap) == cap and geminibrief.broker_module_route([at_cap]) is False
    assert geminibrief.broker_module_route([at_cap + "x"]) is True  # one past the cap, an interpreter named: unread
    assert geminibrief.broker_module_route(["print(1)  # " + "x" * cap]) is False  # ordinary long code: no pieces
    assert geminibrief.broker_module_route(["x" * cap + " broker"]) is True
    assert geminibrief.broker_module_route(["import os\n" * 10, "y = 1  # " + "z" * (cap * 3)]) is False


@pytest.mark.parametrize("prefix_length", [301, 1001, 3000])
def test_a_long_prefix_before_the_module_entry_or_a_built_module_is_still_denied(prefix_length: int) -> None:
    prefix = ("echo " + "x " * prefix_length)[:prefix_length]
    for tail in (
        "&& " + MODULE_ENTRY + " --model m",  # the entry
        "&& python3 -I -m $M --model m",  # a module built at run time (safo and broker are named below)
        "&& cd src/safo/broker && python3 -I client.py",
    ):
        line = f"{prefix} {tail}"
        assert len(line) < geminibrief.LINE_CAP
        assert "gemini-paid" in rules("safo broker note\n" + line + "\n"), (prefix_length, tail)
        assert geminibrief.shell_command_class("# safo broker\n" + line) is not None, (prefix_length, tail)


@pytest.mark.parametrize("prefix_length", [301, 1001, 3000])
def test_an_interpreter_far_before_the_expanded_module_word_is_still_found(prefix_length: int) -> None:
    line = "safo broker python3 -I " + "-W ignore " * (prefix_length // 10) + "-m $M --model m"
    assert geminibrief.broker_module_route([line]) is True
    plain = "safo broker python3 -I " + "-W ignore " * (prefix_length // 10) + "-m pytest tests"
    assert geminibrief.broker_module_route([plain]) is False  # the same line with a plain module is fine


def test_an_import_list_longer_than_the_old_bound_still_ends_in_the_client_name() -> None:
    names = ", ".join(f"n{i}" for i in range(300))
    command = f"python3 -c 'from safo.broker import {names}, client'"
    assert len(command) < geminibrief.LINE_CAP and len(names) > 301
    assert geminibrief.shell_command_class(command) == geminibrief.SHELL_BROKER_MODULE
    assert "gemini-paid" in rules(command + "\n")
    other = f"python3 -c 'from safo.broker import {names}, admin'"
    assert geminibrief.shell_command_class(other) is None  # the same list without the client name


def test_the_candidate_cap_is_one_past_it_refused_and_exactly_it_is_read() -> None:
    cap = geminibrief.MAX_ROUTE_LINES
    filler = ["python3 -m pytest tests"] * cap
    assert geminibrief.broker_module_route(filler) is False  # exactly the cap: read, and there is nothing in it
    assert geminibrief.broker_module_route([*filler, "python3 -m pytest tests"]) is True  # one past: unread, refused
    assert geminibrief.broker_module_route(["print(1)"] * (cap * 3)) is False  # lines with no hint are not counted


def test_the_real_entry_among_more_candidate_lines_than_the_cap_is_denied() -> None:
    filler = ["python3 -m pytest tests"] * (geminibrief.MAX_ROUTE_LINES + 5)
    command = "\n".join([*filler, MODULE_ENTRY])
    assert geminibrief.shell_command_class(command[: geminibrief.SHELL_CAP]) is not None
    assert "gemini-paid" in rules(command + "\n")
    pieces = "\n".join([*filler, "python3 -I -m $1$2", "set -- safo.broker. client"])
    assert "gemini-paid" in rules(pieces + "\n")


def test_split_pieces_are_candidates_on_the_joined_form_not_the_raw_one() -> None:
    """Lines whose hint appears only after the plus signs and the dot segments are removed still count as candidates."""
    split = ['n = "br" + "oker"'] * (geminibrief.MAX_ROUTE_LINES + 1)
    assert geminibrief.broker_module_route(split) is True
    dotted = ["x = 'src/./safo/../safo/' + 'br' + 'oker'"] * (geminibrief.MAX_ROUTE_LINES + 1)
    assert geminibrief.broker_module_route(dotted) is True
    assert geminibrief.broker_module_route(['n = "ab" + "cd"'] * (geminibrief.MAX_ROUTE_LINES + 1)) is False


def test_no_route_pattern_has_a_length_bound_that_could_skip_a_match() -> None:
    """A `{n,m}` bound on a route pattern is a place the pattern silently stops matching; the patterns are linear
    without one (possessive flag clusters, one-space-squeezed input), so none is allowed."""
    import re

    bound = re.compile(r"\{\d*,\d+\}")
    patterns = {n: p for n, p in vars(geminibrief).items() if n.startswith("_BM_") and isinstance(p, re.Pattern)}
    assert len(patterns) >= 10, "something was collected"
    assert [n for n, p in patterns.items() if bound.search(p.pattern)] == []
    assert bound.search("[^;]{0,300}")  # the negative case: the guard does see a bound


# -- a line over the cap is refused when ANY route hint is in it, in any spelling (#299) ------------------------------
# The rule: a line over LINE_CAP is judged after it is normalized (quotes, backslashes and invisible characters removed,
# whitespace squeezed, plus-joined pieces joined, dot and parent segments collapsed). If any hint a route rule uses is
# in the result, the line is refused unread; a long line with none of them (ordinary prose or data) is not.


def test_the_hint_list_is_the_union_of_what_the_route_rules_need() -> None:
    assert set(geminibrief._ROUTE_HINTS) >= {
        "broker",
        "client",
        "python",
        "runpy",
        "safo",
        "importlib",
        "__import__",
        "import_module",
        "run_",
        "exec",
        "eval",
    }


@pytest.mark.parametrize("hint", geminibrief._ROUTE_HINTS)
def test_an_over_cap_line_with_any_route_hint_is_refused_at_the_bound_plus_one(hint: str) -> None:
    cap = geminibrief.LINE_CAP
    pad = "z" * (cap - len(hint) - 1)
    at_cap = f"{pad} {hint}"
    assert len(at_cap) == cap
    assert geminibrief.broker_module_route([at_cap + "z"]) is True  # one past the cap: refused, not skipped
    assert geminibrief.shell_command_class(at_cap + "z") is not None
    assert "gemini-paid" in rules(at_cap + "z\n")


@pytest.mark.parametrize("hint", ["broker", "importlib", "run_module", "exec"])
def test_an_over_cap_line_with_a_plus_joined_hint_is_refused(hint: str) -> None:
    half = len(hint) // 2
    line = "z" * geminibrief.LINE_CAP + f" {hint[:half]} + {hint[half:]}"
    assert geminibrief.broker_module_route([line]) is True
    quoted = "z" * geminibrief.LINE_CAP + f" \"{hint[:half]}\" + '{hint[half:]}'"
    assert geminibrief.broker_module_route([quoted]) is True


def test_an_over_cap_line_with_no_route_hint_is_not_refused() -> None:
    prose = ("The quick brown fox jumps over the lazy dog. " * 120)[: geminibrief.LINE_CAP + 1]
    assert len(prose) > geminibrief.LINE_CAP
    for hint in geminibrief._ROUTE_HINTS:
        assert hint not in prose
    assert geminibrief.broker_module_route([prose]) is False
    assert geminibrief.broker_module_route(["x = 1;" * 2000]) is False


# -- an expansion anywhere in a word that starts a flag cluster ending in m (#299) -----------------------------------

EXPANDED_WORDS = [
    "python3 -I -m$M --model m",  # the module glued to the flag
    "python3 -mfoo$X --model m",  # m, text, then an expansion
    "python3 -mfoo.bar${X:-y} --model m",
    "python3 -I -m${M:-safo.bro}ker.client",
    "python3 -I -m$(echo x) --model m",
    "python3 -I -m`echo x` --model m",
    "python3 -$Xm foo --model m",  # an expansion inside the cluster, before the m
    "python3 -I$Xm foo --model m",
    "python3 -I -m'$M' --model m",  # quoted forms
    'python3 -I -m"$M" --model m',
    "python3 -I -m ${A${B}} --model m",  # nested, in the following word
    "python3 -I -m foo$X --model m",  # the following word, as before
    "python3 -I -m $M --model m",
    "python3 -I -m `echo x` --model m",
]
EXPANDED_COUNT = 14


def test_the_expanded_word_table_is_not_trimmed() -> None:
    assert len(EXPANDED_WORDS) == EXPANDED_COUNT and len(set(EXPANDED_WORDS)) == EXPANDED_COUNT


@pytest.mark.parametrize("command", EXPANDED_WORDS)
def test_a_module_word_with_an_expansion_anywhere_is_unreadable_while_the_broker_is_named(command: str) -> None:
    text = "# safo broker note\n" + command + "\n"
    assert "gemini-paid" in rules(text), command
    assert geminibrief.shell_command_class(text) == geminibrief.SHELL_BROKER_MODULE, command


@pytest.mark.parametrize(
    "command",
    [
        "python3 -I -m pytest tests",
        "python3 -I -m pytest -k 'a or b' tests",
        "python3 -c 'print(1)' $X",
        "python3 -m ruff check .",
        "python3 -W error -m pytest",
    ],
)
def test_a_plain_module_word_stays_allowed_while_the_broker_is_named(command: str) -> None:
    text = "# safo broker note\n" + command + "\n"
    assert geminibrief.shell_command_class(text) is None, command


@pytest.mark.parametrize("hint", ["importlib", "client", "exec", "python"])
def test_the_oversized_event_scan_holds_an_over_cap_line_with_a_route_hint(hint: str) -> None:
    import time

    from safo.modes.hooks import EventScan

    scan = EventScan(time.monotonic() + 30)
    scan.feed(("z" * (geminibrief.LINE_CAP + 1) + f" {hint}").encode())
    assert scan.hit
    quiet = EventScan(time.monotonic() + 30)
    quiet.feed(("z" * (geminibrief.LINE_CAP + 1) + " plain words").encode())
    assert not quiet.hit
