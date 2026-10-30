# SPDX-License-Identifier: Apache-2.0
"""The private-terms search, run in a child process that can be killed (#200).

`re` cannot be interrupted from inside the interpreter, so a term that turns out slow would hold the dispatch guard past
its deadline. `private_term_hit` in `safo.gemini` runs this file with `python -I <this file> <cpu seconds>`, passes the
terms and the texts on standard input, and kills the child at the deadline; a child that does not answer in time is a
denial, never a pass. The worker is found by path and imports nothing from the package, so it runs from a source
checkout with no install and no PYTHONPATH. It also limits itself: a CPU limit and an alarm of its own, and on Linux a
signal when its parent dies, so it cannot outlive the process that started it.

Standard input: one line per term (`flags TAB pattern`), an empty line, then the texts separated by NUL. Each term sees
at most TERMS_CHUNK characters at a time.
"""

from __future__ import annotations

import os
import re
import signal
import sys

TERMS_CHUNK = 4000  # characters one term sees at a time (chunks overlap by 200)


def hit(terms: tuple[re.Pattern[str], ...], texts: list[str]) -> bool:
    """True when any term matches any chunk of any text."""
    step = TERMS_CHUNK - 200
    for text in texts:
        for start in range(0, max(len(text), 1), step):
            chunk = text[start : start + TERMS_CHUNK]
            for term in terms:
                if term.search(chunk):
                    return True
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
