# Roles

| Role | Who | Does | Does not |
|---|---|---|---|
| Lead | Claude (the session the maintainer talks to) | Plans, splits work into cards, sets the Agent field, writes briefs, reviews results, keeps the board current | Merge, or decide what only the maintainer can |
| Implementer and reviewer | Claude subagents, Sonnet by default | Implement a task from a complete brief; review another agent's work | Pick their own scope |
| Mechanical coder | Claude Haiku | Mechanical code from a complete spec, transcribed exactly (a plan's own bugs come along, so it is reviewed) | Anything that needs judgment |
| Deep reviewer | Claude Opus | A genuinely hard judgment problem, or a whole-branch design review of something risky | Run by default: use only with the maintainer's OK and the reason stated |
| Research, planning and attack | Codex | Research, plans, and the adversarial review of security-sensitive code | Resume across git worktrees (see [Lessons](lessons.md)) |
| Small fixes | Copilot coding agent | Small, fully specified issues and deferred minor items | Anything with open design questions |
| Maintainer | A person | Decisions, bench and hardware work, and every merge | |

## Defaults and why

- **Sonnet is the default for implementation and review.** Opus burns the plan's allowance several times faster, so it is a
  deliberate choice: the lead names the reason and gets a yes first, and never upgrades silently.
- **Haiku only for work with no judgment in it.** If a brief needs the word "decide", it is not a Haiku task.
- **Every card carries an Agent.** An unassigned card is unowned work; `agents-status` shows it as `unassigned`.
- **The maintainer merges.** Agents open pull requests and report; a person decides. That is the one gate that never moves.
