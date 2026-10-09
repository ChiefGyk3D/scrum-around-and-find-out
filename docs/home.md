# Scrum Around and Find Out

A GitHub Project defined as code, an Action that applies it and keeps it current, and a playbook for running a
small team of AI agents (Claude, Codex, Copilot) under one human maintainer, with the lessons that shaped it.

## Read in this order

- [Why](why.md): the problem, and the idea that the board is the one place work is visible.
- [Roles](roles.md) and [Routing](routing.md): who does what, and which agent a task goes to (routing is generated from `agents.yaml`).
- [Usage, routing and outcomes](usage.md): measure what each agent has left, get a recommendation, and keep a log of how it went.
- [safo hooks](hooks.md): how Claude Code is made to hold the lead to `agents.yaml`, and what the guard cannot prove.
- [Handoff](handoff.md): how work moves from a card to a merged pull request without losing the thread.
- [Limits](limits.md): reading each tool's real usage and deciding when to switch.
- [Board](board.md) and the [board.yaml reference](board-yaml.md): the project as code.
- [agents-status](agents-status.md): one read-only view of what every agent is doing.
- [Lessons](lessons.md): what went wrong, the evidence, and the rule the code enforces now.
- [Adoption](adoption.md): create an App, write a `board.yaml`, run it.
- [Privacy check](privacy.md): what the public files are scanned for, and how to add your own private terms safely.

The source of these pages is the `docs/` directory of the repository. The wiki is a generated mirror: edit the
files, not the wiki.
