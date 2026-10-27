# Approval issues

Part of the process-method work (spec `docs/superpowers/specs/2026-10-26-process-profiles.md`, section 3.2).
`src/safo/approvals.py` decides whether a gate, change or freeze issue counts as an approval. It reads, it never
writes, and it answers `approved`, `open` (with the reason line) or `UNKNOWN`. A read it cannot finish in full is
`UNKNOWN`, never a pass.

## Naming the entry (M13)

A change approval must say which change it approves. The issue **body** must hold exactly one line of this form,
and nothing else on that line:

    Entry: owner/repo#N

- `owner/repo#N` is the `add` or `remove` reference of the `changes` entry, in ASCII. The owner and repository are
  compared after an ASCII-only case fold; the number is compared as an integer.
- The line starts at column 0 and stands alone as a paragraph: the start of the body or a blank line before it, and
  the end of the body or a blank line after it. A blank line is only spaces and tabs.
- The title is never used. A prose mention is not an entry. A second `Entry:` line, even an equal one, means the
  approval is not for this change.

## The body is plain ASCII prose

The body grammar is deliberately narrow, because the human approver sees plain text and the reader must see exactly
that. It does not try to model Markdown (containers, fences, link definitions and their parser differences);
instead any construct it cannot be sure of makes the answer `UNKNOWN`, with a fixed line that names the class and
never the content:

- **Unusual characters.** Anything but printable ASCII, tab, and `\n` or `\r\n` line ends: no no-break space, bidi
  mark, zero-width character, NEL, line or paragraph separator, vertical tab, form feed, other control character or
  lone carriage return.
- **Raw HTML.** Any `<` that begins a tag, comment, declaration, processing instruction or autolink, anywhere,
  even in code. A bare `<` in prose (`a < b`, `<3`) is fine.
- **Markdown structure.** Any of these on any line, before, around or after the Entry line: a fence (three
  backticks or three tildes anywhere in the line); a thematic break; a heading (ATX or a setext underline); a list
  marker or a quote marker; a table (any `|`); indented code (four spaces, or a tab, at the start of a non-blank line);
  a line ending in a backslash; and **any square bracket** (`[` or `]`), since links, images and reference or footnote
  definitions all need one.
- **Markup characters (an allow-list).** A body line may hold only ASCII letters and digits, space, tab and the marks
  `. , : ; ! ? ' " ( ) # / @ + - =`. Everything else, including `* _ ` ~ & $ { } ^ %`, is refused, because inline
  Markdown and character references can make a line render as an entry line it does not read as (`**Entry:**`,
  `&#69;ntry:`). Only the Entry line itself may hold `_`, since a repository name may.
- **Entry look-alikes.** No other line may contain the word `Entry` (any case, optional whitespace) followed by a colon.
  A prose sentence that says "Entry:" is therefore refused; word it differently.

Write the approval as ordinary sentences, a blank line, the Entry line, a blank line, and optionally more sentences.

## Edits after the approval

The approval is refused when the issue was edited, renamed or reopened at or after the close. The comparison is
`>=` because GitHub timestamps have one-second resolution: an edit in the same second as the close cannot be
ordered, so it does not pass. Re-approving means reopening and closing the issue again, which moves the close time.
Timestamps that cannot be true (the issue created after its close, or an edit, rename or reopen before it was
created) make the answer `UNKNOWN`.

## Who counts

The close must be manual (no `closer`), completed, not a duplicate, and not performed through a GitHub App. The App
check is the REST cross-check, and `verdict()` computes it itself from the REST read, an `EventsRead`. An
`EventsRead` cannot be built by hand: only `events_from_rest()` makes one, from the pages of REST events, and it
is complete only when the paginated read reached the end and every page parsed. It approves only when its newest
`closed` event is the close GraphQL showed and `performed_via_github_app` is null. A missing, incomplete, mismatched
or look-alike read is `UNKNOWN`.

The REST transport that fetches those pages is a later unit. Until it exists, no caller can produce an `EventsRead`
from the network, so nothing approves in production.

The closer must be a `User` whose `databaseId` is in the board file's approver list. A login is never the identity;
it only words the line.

The issue must have been opened by an account whose author association is `OWNER`, `MEMBER` or `COLLABORATOR`.
That is a filter, not a grant of trust: `COLLABORATOR` can include outside collaborators with only read or triage
access. The actor table (the approver list, by id) decides who approves.
