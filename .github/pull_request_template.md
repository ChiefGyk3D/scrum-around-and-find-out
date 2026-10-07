## What and why

<!-- What does this change, and why? The "why" is what a reader of the docs wants most. -->

## Checklist

- [ ] `make check` passes (ruff, mypy --strict, pytest); a failing test names its fix, apply it rather than editing the test
- [ ] **Docs:** if this changes what a person would read (a mode, a board.yaml key, an Action input, a rule), the page under `docs/` changes in this pull request
- [ ] If a GraphQL document changed: `tests/test_documents.py` still passes, and the fake in `tests/fakegh/` models the real behaviour
- [ ] If a third-party action was added to `action.yml`: pinned by commit with a `# vX.Y.Z` comment, and added to the Actions allow-list (`scripts/apply-baseline.sh`)
- [ ] No hostnames, machine identifiers, regions, employer names or callsigns anywhere under `docs/`, `examples/` or `README.md`
