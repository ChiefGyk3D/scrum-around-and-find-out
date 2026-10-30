# Scrum Around and Find Out

A GitHub Project defined as code, an Action that applies it and keeps it current, and a playbook for running a
small team of AI agents (Claude, Codex, Copilot) under one human maintainer, with the lessons that shaped it.

## Read in this order

- [Why](why.md): the problem, and the idea that the board is the one place work is visible.
- [Roles](roles.md) and [Routing](routing.md): who does what, and which agent a task goes to (routing is generated from `agents.yaml`).
- [Personas](personas.md): the four roles (implementer, reviewer, adversarial reviewer, transcriber) and six packs defined in the Department of Internal Arguments, how SAFO relates to them, and how to install and update them.
- [Agent profiles](profiles.md): how to brief each agent, with every claim tied to a pointer at a measurement (the loader, the evidence check and the rendering into `examples/harness/` are built).
- [Usage, routing and outcomes](usage.md): measure what each agent has left, get a recommendation, and keep a log of how it went.
- [No hidden work](no-hidden-work.md): the hard rule: an issue and a board card before any work starts, and how it is enforced.
- [Threat model before build](threat-model.md): an AI-facing issue names its threat model, or says why none applies, and how the file itself is checked.
- [Gemini](gemini.md): the free-only provider for public material, and the approval gate on every paid call.
- [Gemini keys](gemini-keys.md): enrolling, rotating, backing up and revoking the security keys that sign paid approvals.
- [Gemini passkeys](gemini-passkeys.md): the passkey tier, designed and tested against a fake verifier, not shippable until a dependency is chosen.
- [safo hooks](hooks.md): how Claude Code is made to hold the lead to `agents.yaml`, and what the guard cannot prove.
- [The orchestrator](orchestrator.md): the lead is a project manager and never waits; the 2026-10-25 incident and the monitor-agent brief.
- [Look before instructing](look-before-instructing.md): prior art, then the vendor's docs page, then the live system; never a click path from memory.
- [Done means verified](done-means-verified.md): "done" needs an observation this turn through the user's path, plus the destructive-step checklist.
- [Access planning](access-planning.md): plan the whole job, ask once for the union of scopes, no broader fallback, drop write scopes at the end.
- [Act, then report](act-then-report.md): a known fix inside approval is done this turn; the four reasons to ask; reports open with the result.
- [Where unfixed security findings live](security-findings.md): a safe summary in public, the detail in a local ignored path or a draft advisory.
- [Handoff](handoff.md): how work moves from a card to a merged pull request without losing the thread.
- [The review loop](review-loop.md): the implement, review, fix and adversarial cycle, with what the build showed.
- [Claude Code plugins](plugins.md): set up the Codex and Ollama plugins, and where each one fits.
- [Local LLM](local-llm.md): what a local model is good and bad at, and the guard that keeps it from evicting a resident model.
- [Limits](limits.md): reading each tool's real usage and deciding when to switch.
- [Board](board.md) and the [board.yaml reference](board-yaml.md): the project as code.
- [Approval issues](approvals.md): how a gate or change approval is read and what it must say.
- [agents-status](agents-status.md): one read-only view of what every agent is doing.
- [Lessons](lessons.md): what went wrong, the evidence, and the rule the code enforces now.
- [Measurements](measurements.md): what the first month measured, dated and aggregated, and what is not measured yet.
- [Adoption](adoption.md): create an App, write a `board.yaml`, run it.
- [Privacy check](privacy.md): what the public files are scanned for, and how to add your own private terms safely.

The source of these pages is the `docs/` directory of the repository. The wiki is a generated mirror: edit the
files, not the wiki.
