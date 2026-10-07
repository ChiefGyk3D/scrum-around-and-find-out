# Security Policy

## Supported versions

safo is a GitHub Action and a small command line, consumed by workflows that pin a commit. The latest
release is the supported one; a caller pinned to an older commit should move to a current one to pick
up fixes.

## Reporting a vulnerability

Please report security issues **privately**, not in a public issue.

- Preferred: open a
  [GitHub Security Advisory](https://github.com/ChiefGyk3D/scrum-around-and-find-out/security/advisories/new)
  for this repository. It notifies the maintainer directly and keeps the report private until a fix is out.
- If you cannot use Security Advisories, contact the maintainer through the profile at
  [github.com/ChiefGyk3D](https://github.com/ChiefGyk3D).

Please include the affected mode or Action input, what you expected, what happened, and the smallest
`board.yaml` that shows it.

## What to expect

A small, one-maintainer project: no formal SLA, but anything that could expose a token, write to a board it
should not, or run a caller's data as code is looked at first. Target timelines: an acknowledgement within
14 days, and public disclosure once a fix is released or 120 days after the report, whichever comes first.
Credit is given in the fix unless you ask not to be named.

## Scope

In scope: `action.yml`, the `safo` package, and the scripts under `scripts/`. The fake GitHub server under
`tests/` is test support, not a supported artifact.

## What safo is careful about

- The token is held by one object, never printed, never put in an exception message.
- A GitHub App token is the only credential the Action takes for an organization board; a personal token is
  refused there unless the caller opts in with `allow-token-for-org`.
- Inputs reach the shell only through environment variables, and `board.yaml` is read with `yaml.safe_load` only.
- Every action in this repository is pinned by commit.
