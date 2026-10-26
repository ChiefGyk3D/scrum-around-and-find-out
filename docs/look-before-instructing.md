# Look before instructing

**The rule.** Before the lead tells the maintainer to click, run or configure anything, it reads the sources in a fixed
order: prior art, then the vendor's own docs page, then the live system. Never a UI path, a flag or an API behavior from
memory. What was read is marked verified; what was not is marked inferred, and stays marked every time it is restated.

## The order

1. **Prior art.** Grep the maintainer's notes and the sibling repositories' docs for the vendor's name, and read every hit
   in full, not the first screen. A lesson that was already written down is the cheapest source there is.
2. **The vendor's docs page itself,** through a docs tool or a fetch. Note the page's date. A search summary or a
   paraphrase from a fetch tool is a lead to follow, never a source.
3. **The live system,** through its API or CLI, read-only first.

Then:

- If an API or CLI can do the step, and the step is inside what the maintainer approved, do it. Do not instruct a click
  (see [Act, then report](act-then-report.md)).
- Mark each statement **verified** (with the page, its date, or the command that showed it) or **inferred**.
- If a source is silent, read the next one: the changelog, the API reference, the error text. "I don't know" is not an
  answer while a docs page is one fetch away.
- Before describing a screen, ask for a screenshot and read all of it.
- When you were wrong, say so in one line and do not imply the maintainer did it wrong.

## Why: 2026-10-24 and 2026-10-25

The lead gave Cloudflare Pages setup instructions from memory and from a search summary it had itself called stale. The
dashboard path it described led the maintainer to create a Worker, not a Pages project, and about an hour went. Several
versions of the token setup followed, one built on a template name taken from that same summary. At one point the lead
answered "I don't know" for something the docs answered on one page.

The lesson had been recorded the day before, in the maintainer's notes and in the project's deploy docs. Only the first 40
lines of the notes file were read. The tool's own error text, a few hours in, already named the API fix.

Vendor dashboards change often, and recall of them is a guess that reads like an instruction. A wrong click path costs the
maintainer far more than a minute of reading costs the lead. The first sign of being wrong should have been "let me check
the documentation".

## How it is enforced

**Doctrine only, not enforced.** No hook reads a reply to see whether a click path was verified, and none checks that a
notes file was read to the end. `safo hooks guard` ([safo hooks](hooks.md)) checks the briefs a lead sends (an explicit
model, the approval token, a local-model step, an `issue:` line) and whether the lead is waiting; it says nothing about
where an instruction came from. A Stop-hook heuristic that flags unverified click paths is a separate optional idea, not
built. What exists is the discipline above and review: a reviewer who sees an instruction with no source asks for one.

A brief that sends an agent to research a vendor should carry the prior-art line itself, for example:

```
Prior art first: grep -ril <vendor> <notes dir> <sibling repos' docs>, and read every hit in full before the docs page.
```

## Checklist

- [ ] Grepped prior art for the vendor and read every hit to the end.
- [ ] Read the vendor's docs page itself and noted its date; a search summary counted only as a lead.
- [ ] Checked the live system through its API or CLI where one exists.
- [ ] Every step is marked verified or inferred, and inferred stays marked on restatement.
- [ ] A step an API can do was done, not described as a click.
- [ ] A silent source led to the next source, not to "I don't know".

Related: [Done means verified](done-means-verified.md), [The orchestrator](orchestrator.md), [Lessons](lessons.md).
