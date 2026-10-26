# Where unfixed security findings live

A finding that is not fixed yet is a map for an attacker. This page says where it may be written down, what a public
issue may say about it, and why a Critical or High finding is fixed without waiting for a go-ahead.

This is doctrine only. Nothing here scans issue text for exploit detail; that check is out of scope (issue 93).

## The rule

Exploit-level detail about an unfixed finding stays out of public repositories and out of synced configuration trees (a
dotfiles repository, or any directory a sync tool pushes on its own). Until the fix ships, it lives in exactly one of two
places:

1. **A gitignored local path.** A file outside every tracked tree, or inside one only if the ignore rule is in place and
   checked (`git check-ignore -v <path>` names the rule). Not a scratch note in a synced directory, and not a file that a
   later `git add -A` can pick up.
2. **A draft GitHub security advisory on the affected repository.** It is private to the maintainers and any collaborators
   added to it, and it is where a fix can be developed before it is public. The reporting route for outsiders is
   described in [SECURITY.md](https://github.com/ChiefGyk3D/scrum-around-and-find-out/blob/main/SECURITY.md).

Pick the advisory when the finding belongs to one repository and someone else may need to read it. Pick the local path when
it is a working note for the person fixing it. Either way, the detail moves to the public record only after the fix has
shipped, and then as the fix's own description.

## What a public issue carries: the safe summary

A public issue about an unfixed finding is still filed first, because [no hidden work](no-hidden-work.md) applies to a
security fix like any other. It carries a safe summary:

- That a finding exists, and which component or area it is in, at the level of "the deploy workflow" and no finer.
- The severity class (Critical, High, Medium, Low), as a label or a word.
- Its status: open, fix in progress, fix shipped.
- Where the detail lives, by name only ("draft advisory on this repository", "local note held by the fixer"). Never a
  path, a URL to a private resource, or an identifier of a private system.
- After the fix ships: the fix's pull request.

It does not carry: a payload, a reproduction, the request or parameter or file that is vulnerable, a working command, an
exposed hostname or address, a token or any part of one, the name of the exposed system, or a log excerpt that shows
any of these. If a sentence would help someone attack the unfixed thing, it is not part of the summary.

## Critical and High are fixed without waiting

A Critical or High finding, from a scan, a dependency alert, a review or a threat model, is fixed without waiting for the
maintainer's go-ahead. The order is:

1. The issue (safe summary) and the board card, before work starts.
2. The fix, on a branch, with a pull request that links the issue.
3. The report to the maintainer, after, saying what was found and what was done.

This does not cover merging past a red gate, switching off a check, anything destructive or irreversible, spending, or
anything outward-facing the maintainer has not approved. Those still stop and ask. Medium and Low findings are recorded
and mentioned, with no obligation to fix them unprompted.

One consequence: do not publish a document that lists an unfixed Critical or High (a threat model, an audit, a roadmap).
Fix first, then publish.

## Worked examples (2026-10-25)

During the session of 2026-10-25, findings turned up in two projects. The lead published only a safe summary in each:
no-php-no-cry issue 27 and Reach-Around issue 206. Neither issue's contents are reproduced here, on purpose. The point is
the shape: the public issue named that a finding existed and where it was tracked, and the detail stayed in one of the two
allowed places until the fix shipped. The rule was followed in both cases but was not written down, which is why this page
exists. (Which of the two places each project used is not recorded here; it was not verified.)

## Where this is linked

The agent brief template in [The orchestrator](orchestrator.md) carries a `findings:` line that points at this page. See also
[Threat model before build](threat-model.md), whose output must not list an unfixed Critical or High while it is public,
and [Privacy check](privacy.md) for what the public files are scanned for.
