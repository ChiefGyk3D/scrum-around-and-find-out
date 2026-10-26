# Where unfixed security findings live

A finding that is not fixed yet is a map for an attacker. This page says where it may be written down, what a public
issue may say about it.

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

## Worked example (invented)

Suppose a review finds that an unauthenticated endpoint in a deploy workflow lets anyone trigger a release. This is a
fictional finding.

- **The private note** (local ignored path or draft advisory) holds everything: the file and the endpoint, how it is
  reached, a reproduction, what an attacker gains, the proposed fix, and any value seen while testing.
- **The public tracker** holds a title such as "Security fix in the deploy workflow" and one line, "details held privately
  until fixed", with the severity word. No file, no endpoint, and no weakness class finer than the area ("deploy
  workflow").
- **After the fix ships**, the pull request description and the issue are updated with the detail, because it is no longer
  a map to anything open.

## Where this is linked

The agent brief template in [The orchestrator](orchestrator.md) carries a `findings:` line that points at this page. See also
[Privacy check](privacy.md) for what the public files are scanned for.
