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

The lead gave instructions for setting up Cloudflare Pages versus a Worker from memory and from a search summary. The
lesson had been recorded the day before, but only the first 40 lines of that file were read.

Vendor dashboards change often, and recall of them is a guess that reads like an instruction. A wrong click path costs the
maintainer far more than a minute of reading costs the lead.

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

## Research discipline for delegated work (#353)

The same rule holds when the lead delegates the looking. Measured on 2026-11-07: a task to find what Tuxedo says about
the Intel ME went to an `implementer` agent. That type has Read, Grep, Glob, Edit, Write, Bash and Skill, and no
WebSearch or WebFetch. It fetched the vendor's pages with curl, got script-built pages and reported "no statement
found". The lead relayed that as an open decision. The maintainer then found the vendor's own press release with one web
search ("tuxedo computers intel me"). In the same session three agents hit a 403 or a blocked page and fell back to
Wikipedia or "not read" without saying that they had tried another route.

Three rules now measure it. All three are **warn only**: there is no deny path, `block` mode included, until a week of
measurements ([measurements](measurements.md)) says otherwise.

- `research-route` (dispatch). A brief whose task is to find or verify a fact about a vendor, product, standard,
  advisory or document (keywords from the `intent_keywords` setting, matched without case) is flagged when its
  `subagent_type` is not in the `search_types` setting. An unknown type is allowed with a visible warning, never
  blocked. A missing type counts as `general-purpose`, which Claude Code uses by default.
- `research-ladder` (dispatch). The same brief must carry a `research:` line of at least four characters after the colon,
  naming the ladder: prior art, then the vendor page, then a web search with the exact query, then an archive or second
  source, then the live system. The stop rule: report "not found" only after at least two distinct web search queries,
  each listed in the report.
- `report-not-found` (report shape). `safo handoff shape <owner/repo> <pr>` reads the newest report from an OWNER, MEMBER
  or COLLABORATOR with a `ROLE:` and `HEAD:` header and flags one that says not found, could not find, unverified,
  blocked, 403, could not read, not read or no statement found, unless it lists at least two distinct `query:` or
  `search:` lines or names a `fallback:`, `archive:` or `second source:` line. **It checks the shape of the text, not the
  truth**: a report can list two queries it never ran. The exit code is 0 for OK and WARN, 2 when no report can be read.

`research: n/a - <why>` on a brief turns off the first two for that brief, the same way `local-llm: n/a -` does for the
local step; the reason must be on the same line. Configure everything in the `research` block of `hooks` in `agents.yaml`
(`route`, `ladder` and `report_not_found` switch one rule each; see [safo hooks](hooks.md)). `safo hooks status` counts
`research-route` and `research-ladder` among the rules flagged. The lead-side heuristic (a relayed "not found" with no
search in the turn) is part of the optional Stop-hook idea in #84, not built here.

## Checklist

- [ ] Grepped prior art for the vendor and read every hit to the end.
- [ ] Read the vendor's docs page itself and noted its date; a search summary counted only as a lead.
- [ ] Checked the live system through its API or CLI where one exists.
- [ ] Every step is marked verified or inferred, and inferred stays marked on restatement.
- [ ] A step an API can do was done, not described as a click.
- [ ] A silent source led to the next source, not to "I don't know".
- [ ] Research went to an agent type that can search, with a `research:` line, and "not found" came with two listed queries.

Related: [Done means verified](done-means-verified.md), [The orchestrator](orchestrator.md), [Lessons](lessons.md).
