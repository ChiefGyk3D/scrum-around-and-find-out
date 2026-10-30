# SPDX-License-Identifier: Apache-2.0
"""The private-terms search, run in a child process that can be killed (#200).

`re` cannot be interrupted from inside the interpreter, so a term that turns out slow would hold the dispatch guard past
its deadline. `private_term_hit` in `safo.gemini` runs this file with `python -I <this file> <cpu seconds>`, passes the
terms and the texts on standard input, and kills the child at the deadline; a child that does not answer in time is a
denial, never a pass. The worker is found by path and imports nothing from the package, so it runs from a source
checkout with no install and no PYTHONPATH. It also limits itself: a CPU limit and an alarm of its own, and on Linux a
signal when its parent dies, so it cannot outlive the process that started it.

Standard input: one line per term (`flags TAB pattern`), an empty line, then the texts separated by NUL.
A term reaching no further than TERMS_OVERLAP sees chunks of TERMS_CHUNK characters; a wider one sees the whole text.
"""

from __future__ import annotations

import importlib
import os
import re
import signal
import sys

TERMS_OVERLAP = 200  # chunks overlap by this much, so a term that reaches no further than this cannot straddle a gap
TERMS_CHUNK = 4000  # characters one term sees at a time
_UNKNOWN = 10**9  # the reach of a term whose shape cannot be read: wider than any overlap


def reach(pattern: str, flags: int = 0) -> int:
    """The most characters a match of `pattern` can need, looking ahead and behind included, plus one
    character of context at each end for the anchors. A shape that cannot be
    read, or an unbounded one, counts as wider than any overlap."""
    try:
        parser = importlib.import_module("re._parser")
        tree = parser.parse(pattern, flags)
        constants = importlib.import_module("re._constants")
    except (re.error, RecursionError, OverflowError, ImportError):
        return _UNKNOWN
    total = [tree.getwidth()[1] + 2]  # anchors (^ $ \b \B \A \Z) look one character past each end

    def walk(items: object) -> None:
        for op, av in items:  # type: ignore[attr-defined]
            if op in (constants.ASSERT, constants.ASSERT_NOT):
                total[0] += av[1].getwidth()[1]
                walk(av[1])
            elif op == constants.SUBPATTERN:
                walk(av[3])
            elif op == constants.BRANCH:
                for branch in av[1]:
                    walk(branch)
            elif op in (constants.MAX_REPEAT, constants.MIN_REPEAT, constants.POSSESSIVE_REPEAT):
                walk(av[2])
            elif op == constants.ATOMIC_GROUP:
                walk(av)

    walk(tree)
    return int(min(total[0], _UNKNOWN))


def hit(terms: tuple[re.Pattern[str], ...], texts: list[str]) -> bool:
    """True when any term matches any text. A term whose reach fits the overlap sees overlapping chunks; a wider one
    (the loader refuses them, so only a hand-built term gets here) is searched over the whole text, inside the same
    killable worker, so no term can be missed at a chunk boundary."""
    step = TERMS_CHUNK - TERMS_OVERLAP
    narrow = tuple(t for t in terms if reach(getattr(t, "pattern", ""), getattr(t, "flags", 0)) <= TERMS_OVERLAP)
    wide = tuple(t for t in terms if t not in narrow)
    for text in texts:
        for term in wide:
            if term.search(text):
                return True
        for start in range(0, max(len(text), 1), step):
            end = min(start + TERMS_CHUNK, len(text))
            for term in narrow:
                if _found(term, text, start, end):
                    return True
    return False


def _found(term: re.Pattern[str], text: str, start: int, end: int) -> bool:
    """A match in text[start:end] that is also a match in the whole text, so ^, $, \\A, \\Z and \\b mean the real
    edges of the text and not the edges of the window. `pos` keeps the context before the window; a match found
    against the window's cut end is confirmed against the full text before it counts."""
    pos = start
    while pos < end:
        found = term.search(text, pos, end)
        if found is None:
            return False
        if end >= len(text) or term.match(text, found.start()):
            return True
        pos = found.start() + 1
    return False


def limit_self(seconds: int) -> None:
    """A CPU limit, an alarm, and (Linux) death with the parent. Each is a guard on top of the parent's kill."""
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (seconds, seconds + 1))
    except (ImportError, ValueError, OSError):
        pass
    if hasattr(signal, "alarm"):
        signal.alarm(seconds + 1)
    try:
        import ctypes

        ctypes.CDLL(None).prctl(1, int(signal.SIGKILL), 0, 0, 0)  # PR_SET_PDEATHSIG
    except (ImportError, OSError, AttributeError):
        pass


def main(argv: list[str]) -> int:
    limit_self(max(int(argv[1]) if len(argv) > 1 else 5, 1))
    head, _, body = sys.stdin.read().partition("\n\n")
    terms = []
    for line in head.splitlines():
        flags, _, pattern = line.partition("\t")
        terms.append(re.compile(pattern, int(flags)))
    os.write(1, b"1\n" if hit(tuple(terms), body.split("\x00")) else b"0\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
