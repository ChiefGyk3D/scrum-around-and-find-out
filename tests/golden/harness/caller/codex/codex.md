HEADER
# Caller guidance: codex

This page is for whoever briefs codex. The model does not read it.

## Use

- Prepend `codex/codex.prompt.md` to a self-contained prompt. Codex cannot resume a thread across git worktrees, so the preamble and the prompt are the whole standing context.

## Briefing guidance

### Do

- Give it a self-contained prompt. (`lessons:every-copilot-pull-request-needed-fixes`)

### Do not

- Expect it to commit inside a git worktree. (`lessons:codexs-sandbox-cannot-commit-inside-a-git-worktree`)
