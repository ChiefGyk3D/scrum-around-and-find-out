# Impacted tests

`scripts/impacted-tests.py` prints the test files worth running for a set of changed files, so an agent can do a
targeted run instead of the full suite. CI stays the judge: the full gate runs there on every pull request, and this
tool never replaces it. Agents use it only to pick targeted runs while they work.

```sh
scripts/impacted-tests.py src/safo/spend.py docs/spend-report.md   # changed files as arguments
scripts/impacted-tests.py --base origin/main                       # or `git diff --name-only origin/main`
```

Output is test paths only, one per line, sorted and bounded. Exit codes:

| Exit | Meaning |
|---|---|
| 0 | Run the printed tests. |
| 3 | Run the full suite. Stdout is the single line `ALL`; stderr gives a one-line reason. |
| 2 | Usage error (no files, an unsafe path or ref, an unknown option). |

Check the exit code before passing the output to pytest: on exit 3 run the whole suite instead.

## What it selects

- The test for a changed `src/safo` module by naming convention (`tests/test_<module>.py` and `tests/test_<module>_*.py`).
- Every test that imports the changed module, directly or through other modules (the reverse import closure over
  `src`, `tests` and `packaging`, parsed with `ast`; imports inside functions count, relative imports are resolved).
- A changed test file itself, and for a changed test helper the tests that import it.
- Five always-run guard tests, so a cheap run can never skip them: `tests/test_docs.py` (the mode registry and the
  docs promises), `tests/test_readme_links.py`, `tests/test_duplicate_keys.py`, `tests/test_output.py` and
  `tests/test_privacy.py`.

Documentation files (`docs/`, any `*.md`, `LICENSE`, `NOTICE`) map to the guards alone.

## When it says ALL

Any changed file that maps to no test (a module nothing tests, `pyproject.toml`, a workflow, `agents.yaml`, data
files), a file it cannot parse, a symlinked Python file, a missing guard test, more than 400 selected tests, or a
failing `git diff`. One unmapped file makes the whole answer ALL.

## Limits

The tool reads files and parses them with `ast`; it never imports or runs anything from the tree it analyses. It
cannot see dynamic imports or a test that loads a script by path, so a change that only those reach is selected by
naming alone. That is the reason CI runs everything.

Tests: `tests/test_impacted_tests.py`.
