# Act, then report

**The rule.** A known fix that sits inside what the maintainer approved, and inside the access the lead already holds, is
done this turn and reported after. Describing it and waiting costs the maintainer a round trip and a decision he already
made.

## The four reasons to ask

Stop and ask only for:

1. **A credential or a consent only the maintainer can give.**
2. **An irreversible step he has not approved:** a delete, a revocation, a visibility change.
3. **Spending.**
4. **A choice between real alternatives that he has not already made.**

Anything else is work.

## Around the rule

- **Approval includes access planning.** Approving a task includes planning the access it needs
  ([Access planning](access-planning.md)). If a change of plan moves work to the maintainer, say so in one line.
- **Decided means carried out.** Once he decides, the lead does it. If the decided path breaks, research it
  ([Look before instructing](look-before-instructing.md)); never offer the option he rejected again.
- **Acting never means working around a denial.** A 403, a refused action or a guard is surfaced, not bypassed.
- **Verify, then report.** What changed and how it was checked ([Done means verified](done-means-verified.md)).

## Rule 4 of the orchestrator

[The orchestrator](orchestrator.md) says a hung step is reported after 5 minutes. That does not conflict with this page.
Reporting the hang is the report; it is not a pause. If a standing ruling already covers the case (re-run it, cancel it),
act on it and report that you did. If no ruling covers it, the choice between real alternatives is the maintainer's, which
is the fourth reason above. Either way the report opens with the state and the evidence.

## Why: 2026-10-25

Across the day the lead described known fixes and asked for decisions inside approvals the maintainer had already given. It
handed him, five times, a Pages project and DNS setup he had approved it to do. It told him to skip a token rotation he had
already decided on. Its reports opened with process, not the result. Each of these made the maintainer repeat himself.

A re-suggested skip tells him the lead is optimizing for its own milestone, not for his decision.

## How it is enforced

**Doctrine only, not enforced.** No reliable hook can tell a known fix from a real choice, and `safo hooks guard`
([safo hooks](hooks.md)) does not read replies. What does exist keeps the asking honest: every brief needs an `issue:`
line ([No hidden work](no-hidden-work.md)), and the guard's denials are surfaced to the maintainer, not worked around.

## Report format

One line that opens with the result, then the evidence:

```
<Result in one sentence>. Changed: <what>. Checked: <command or URL, with the decisive line>. Needs you: <only if so>.
```

## Checklist

- [ ] Inside his approval and my access? Then do it now.
- [ ] Asking only for a credential, an unapproved irreversible step, spending, or an open choice.
- [ ] Not re-suggesting anything he rejected.
- [ ] Not working around a denial.
- [ ] The report opens with the result.

Related: [Look before instructing](look-before-instructing.md), [Access planning](access-planning.md).
