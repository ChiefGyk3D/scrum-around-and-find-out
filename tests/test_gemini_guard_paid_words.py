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
    'python3 -I -c \'exec("import safo.broker." + "client")\'\n',
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
