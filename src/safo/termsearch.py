# SPDX-License-Identifier: Apache-2.0
"""The private-terms search, run in a child process that can be killed (#200).

`re` cannot be interrupted from inside the interpreter, so a term that turns out slow would hold the dispatch guard past
its deadline. `private_term_hit` in `safo.gemini` runs this module with `python -I -m safo.termsearch`, passes the terms
and the texts as JSON on standard input, and kills the child at the deadline; a child that does not answer in time is a
denial, never a pass. Each term sees at most TERMS_CHUNK characters at a time.
"""

from __future__ import annotations

import json
import re
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


def main() -> int:
    data = json.loads(sys.stdin.read())
    terms = tuple(re.compile(pattern, flags) for pattern, flags in data["terms"])
    sys.stdout.write("1" if hit(terms, [str(t) for t in data["texts"]]) else "0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
