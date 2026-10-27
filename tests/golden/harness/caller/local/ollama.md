HEADER
# Caller guidance: ollama

This page is for whoever briefs ollama. The model does not read it.

## Use

- Send `local/ollama.wrapper.txt` with the task in its task slot. The model reads that file and never this page.
- Send `think=false` with the request. It is a setting of the call, not part of the prompt.

## Briefing guidance

### Limits

- Context ceiling: put at most 2048 tokens in a brief. (`lessons:codexs-sandbox-cannot-commit-inside-a-git-worktree`)
- Output cap: ask for at most 512 tokens in a reply. (`lessons:codexs-sandbox-cannot-commit-inside-a-git-worktree`)
- Thinking: off. (`lessons:codexs-sandbox-cannot-commit-inside-a-git-worktree`)

### Do

- Treat its output as a draft. (`lessons:codexs-sandbox-cannot-commit-inside-a-git-worktree`)
