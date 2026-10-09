# agents-status

One read-only view of what every agent is doing. It starts nothing, stops nothing and edits nothing.

```sh
safo --board board.yaml agents-status            # the board, Codex and Copilot
safo --board board.yaml agents-status --hours 24 # Codex sessions from the last day
safo --board board.yaml agents-status --no-codex --no-copilot
safo --board board.yaml agents-status --no-guard # without the routing-guard counts
```

## Sections

1. **Waiting on you.** Open cards whose Status is in `agents.waiting` (default Blocked), with their links.
2. **Board.** Open cards whose Status is in `agents.working` (default In progress and Next), grouped by the Agent field.
3. **Routing guard.** The guard's mode and what the dispatch guard (see [Usage](usage.md)) has logged: dispatches, the
   decisions (allow, warn, deny), the models used, the rules that were broken and when the last flagged dispatch
   happened. It reads the log under `$XDG_STATE_HOME/safo/hooks` (or `~/.local/state/safo/hooks`) and says so when
   there is none. `--no-guard` skips it.
4. **Codex.** Sessions touched in the last N hours (default 12) from `~/.codex/sessions`: when, running, done or
   `stalled?` (running, but silent for 15 minutes), the working directory's name and the last message's first line; then the
   plan's 5-hour and weekly usage and when each resets.
5. **Copilot.** `gh agent-task list`; if that is unavailable it says what is needed.
6. **Claude.** A reminder: subagents live inside the Claude Code session and cannot be listed from a shell.

## Credentials

On a laptop `safo` uses `gh auth token` (the active account, or `--gh-user NAME`). The token needs the `project` scope:
`gh auth refresh -s project`. Nothing is written anywhere.
