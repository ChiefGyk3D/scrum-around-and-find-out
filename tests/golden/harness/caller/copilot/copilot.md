HEADER
# Caller guidance: copilot

This page is for whoever briefs copilot. The model does not read it.

## Use

- Install `copilot/copilot-instructions.md` where Copilot reads repository instructions. Copilot reads that file and never this page.

## Briefing guidance

### Do

- Give it small single-repo pull requests. (`lessons:every-copilot-pull-request-needed-fixes`)

### Review gate

- Review is required, and the reviewer must differ from the author.
- Read the stated acceptance criteria first, then judge whether the test would fail if the stated behaviour were broken, ideally by breaking it. (`lessons:every-copilot-pull-request-needed-fixes`)

### Model layer: gpt-5.1

#### Do not

- Trust its tests. (`lessons:every-copilot-pull-request-needed-fixes`)

### Model layer: o3

Nothing is claimed about this model: its profile is unmeasured.

- Thinking: on. (`lessons:every-copilot-pull-request-needed-fixes`)
