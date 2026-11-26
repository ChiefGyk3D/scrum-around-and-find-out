# Local-first drafts and digests (`safo-draft`)

`safo-draft` makes the local model the easy path for text work (issue #482). It wraps `llm-local`, checks the draft in
code, and files with `gh` only after a yes. It is a wrapper, not a guard: nothing forces its use, and the dispatch guard
is untouched.

## Commands

```
safo-draft issue   --repo o/r --title T [--epic N] [--facts FILE] [--model M] [--yes] [PROMPT]
safo-draft pr      --repo o/r --title T [--head B] [--base B] [--facts FILE] [--yes] [PROMPT]
safo-draft comment --repo o/r --number N [--facts FILE] [--yes] [PROMPT]
safo-draft digest ci-log [FILE|-]
safo-draft digest board-drift [FILE|-]
safo-draft --report
```

Example, as the lead would use it:

```
safo-draft issue --repo o/r --title "Fix the retry bound" --epic 445 --yes "retry bound is off by one in wait-ci"
gh run view 123 --log-failed | safo-draft digest ci-log -
safo audit | safo-draft digest board-drift -
```

## What the checks do and do not guarantee

- **The private deny file is the guarantee for named private values.** Put your real callsign, grid, employer name and
  handles there, one per line, never in this repository. A value in that file is found in every draft or title, however
  it is spaced or decorated (see below).
- **The heuristics are defense in depth.** They catch the usual shapes (callsign, grid, address, hostname, serial,
  session link) and over-block on purpose; a shape that is not listed here is not caught.
- **Private values nobody told the tool about are not guaranteed.** A hostname without a private suffix, an address
  written in words, a name the deny file lacks: all pass.
- The checks run on the draft, not on what the model was sent: `--facts` and the prompt go to the local model only.

## What it does

- **Models.** `qwen3.5:4b` for short input, `gemma4:12b` when the prompt and facts exceed 600 characters; `--model`
  overrides. `llm-local` is always called with stdin from /dev/null, because it hangs on an open stdin.
- **Checks before filing** (a failing draft is printed with the reasons and never filed, even with `--yes`). The
  same checks run on the body and on `--title` (a title failure is named `title: ...`): no em dash (U+2014 and the
  look-alikes U+FE58, U+FE31, U+2E3A, U+2E3B; the horizontal bar U+2015 is not blocked), no IPv4 or IPv6 address, no
  `.lan`/`.local`/`.internal` style hostname, no serial number (`serial`, `serial number`, `s/n`, `SN` followed by a
  value of 6 or more characters with a digit), no claude.ai URL (with or without a scheme) or `Claude-Session:`
  trailer, no callsign or grid shape, no HTML, no unusual characters, and no private deny entry.
- **Unusual characters fail closed.** After Unicode NFKC normalization, a draft or title is refused when it holds a
  combining mark (categories Mn, Me), a format character (Cf: zero-width, bidi, variation selectors and tag characters
  such as U+E0041), a control character other than newline, carriage return and tab (Cc), a private-use, unassigned or
  surrogate character (Co, Cn, Cs), a line or paragraph separator, or any space other than the plain U+0020 (a
  non-breaking space is refused, and the raw text is checked for it because NFKC would fold it to a plain space).
  Ordinary letters and digits, punctuation, precomposed accented letters (`Caf` plus U+00E9) and symbol emoji
  (category So, such as the robot in the pull request footer) are fine. A letter plus a combining accent that NFKC
  composes (`e` plus U+0301) passes; one it cannot compose (`1` plus U+0301) is refused. An emoji written with a
  variation selector is refused.
- **Non-ASCII characters fail closed.** After NFKC the text is decomposed (NFKD) and combining marks are dropped,
  giving an ASCII skeleton. Every non-ASCII character must either reduce to printable ASCII (`Caf` plus U+00E9
  reduces to `Cafe`; a fullwidth letter is folded by NFKC) or be on a short allowlist: curly single and double quotes
  (U+2018 to U+201D), en dash U+2013, bullet U+2022, ellipsis U+2026, the multiplication sign U+00D7, arrows U+2190 to
  U+2193, and an explicit list of 45 pictographs (below). Nothing else outside ASCII passes: no emoji range, no
  name test. Every other code point, including every emoji not on the list, the ballot-x marks U+2715 to U+2718,
  U+00AE and U+00A9, is refused. The list: check mark U+2714, white heavy check mark U+2705, cross mark U+274C,
  warning sign U+26A0, rocket U+1F680, robot face U+1F916, eyes U+1F440, thumbs up U+1F44D, thumbs down U+1F44E,
  party popper U+1F389, wrench U+1F527, hammer U+1F528, bug U+1F41B, locked U+1F512, key U+1F511, fire U+1F525,
  sparkles U+2728, heavy exclamation mark U+2757, light bulb U+1F4A1, memo U+1F4DD, package U+1F4E6, books U+1F4DA,
  hourglass U+231B, stopwatch U+23F1, black right arrow U+27A1, up arrow U+2B06, down arrow U+2B07, clipboard
  U+1F4CB, pushpin U+1F4CC, magnifying glass U+1F50D, gear U+2699, shield U+1F6E1, thinking face U+1F914, waving hand
  U+1F44B, folded hands U+1F64F, clapping hands U+1F44F, red circle U+1F534, green circle U+1F7E2 and yellow circle
  U+1F7E1, white medium star U+2B50, heavy plus sign U+2795, direct hit U+1F3AF, bar chart U+1F4CA, police car
  light U+1F6A8 and test tube U+1F9EA. The link symbol U+1F517 is not on it (it is not on the owner list) and neither is
  hundred points U+1F4AF (it shows digits). Add a pictograph only with a test that its name has no letter or digit
  (the guard test caps the list at 45 and checks each name for DIGIT, LETTER, LATIN, KEYCAP, NUMBER, SQUARED,
  CIRCLED, NEGATIVE, PARENTHESIZED and INPUT SYMBOL). The multiplication sign U+00D7 and the cross mark count as
  the letter `x` for matching, and the three circles count as the letter `o` (they can read as one), in drafts and
  in deny values alike (`Acme` plus U+00D7 plus `Labs` matches a deny value `AcmeXLabs`). A person may read such a symbol either way, so
  matching checks both readings: the letter and the symbol dropped (the same text also matches `AcmeLabs`); a deny value
  that holds one is matched in both forms too. Characters that NFKC folds
  to ASCII (circled M, the trade mark sign) are kept as the letters they fold to. Anything else (Cyrillic, Greek,
  Armenian, Cherokee, Hangul jamo, dotless i, small capitals, modifier
  letters, letterlike symbols, operator lookalikes such as U+2208, currency signs such as the euro sign, other
  arrows) refuses the draft or title with "characters that cannot be reduced to ASCII (line N): remove emoji and other symbols, or use only the allowed
  pictographs listed in docs/local-draft.md"; the reason never holds the characters. Currency signs are refused on purpose: write `EUR` or `USD`. The variation selector U+FE0F is
  allowed only directly after an allowed pictograph (white heavy check mark plus U+FE0F); it is then removed before
  every check and the skeleton. Anywhere else (after a letter or digit, at the start, after a space, twice in a row,
  after a symbol not on the list) it is refused as "unusual or invisible characters (line N): remove them (a stray
  variation selector, zero-width or combining character)". A look-alike symbol (the multiplication sign, the cross mark, the red, green and yellow circles) that directly touches an ASCII letter or digit on either side (a variation selector after a pictograph is ignored) is refused: "a look-alike symbol touches a letter or digit (line N): write the letter or leave a space". Standing alone is fine: `done` plus a space and the cross mark, a list marker, a circle before a space or punctuation, `3 x 4` with spaces; for `3x4` write the letter. Every heuristic (callsign, grid, hostname, IP, serial, session URL and trailer, links, HTML) runs on four texts: the raw text, its canonical form, and the ASCII skeleton of the canonical form read two ways (look-alikes as `x` and `o`, and look-alikes dropped). The skeleton keeps every ASCII character, so spaces, dots and punctuation stay. Each reason is reported once by class. Work is bounded: a text over 20000 characters, or whose NFKC form is over 80000 characters (one character such as U+FDFA expands 18 times), is refused as "draft too long to check safely" before any scan. Deny matching and squashing use the skeleton, so a lookalike cannot slip a private value past the
  match. A deny value that holds such a character is a config error naming the line.
- **Markdown links and reference definitions are refused.** Inline links and images (`](` and `![`) and reference uses
  (`][`) fail with "markdown links are not allowed in drafts (line N): write the URL plainly.". Reference definitions are
  refused by a broad rule with no parsing, because the rendered text differs from the source the checks see. Split the
  text into paragraphs on blank lines and refuse a paragraph when it holds a `[` and, anywhere after the first `[`,
  the two characters `]:` (leading block markers need no special handling: the rule is already that broad).
  Also refused: a paragraph with an escaped bracket (backslash then `[` or `]`) and a later `]:`, whatever comes
  before it. The reason is "markdown reference definitions are not allowed in drafts: a `[` followed later by `]:` in the
  same paragraph (line N). Reword it, put the text in a code span without brackets, or split the paragraph; write
  URLs plainly." Only `str.find` runs, so the scan is linear. Allowed: `- [x] done`, `[ ]`, `a[0]`, `see [1]` (no colon), and a `]:` in a
  paragraph with no earlier `[` (`ok]: fine`). Known over-blocks, accepted as the safe side: `the range is [0, 5]:
  inclusive`, `arr[0]: the first item`, and any paragraph that mixes a `[` with a later `]:` for another reason.
  Rewrite those without the colon right after the bracket. Bare URLs are scanned as written. The exact pull request
  footer line is exempt.
- **HTML is refused, not decoded.** A draft with an HTML tag, comment or declaration (`<` followed by a letter, `!`, `/`
  or `?`) or a character reference (`&name;`, `&#65;`, `&#x41;`, and the same without the semicolon when a word
  boundary follows) fails with "HTML is not allowed in drafts (line N): remove the angle-bracket text; write `{name}` instead of
  `<name>`; a pasted traceback with `<module>` must be rewritten without the angle brackets." `a < b` and `x<=y` pass. This also
  refuses `R&D` and `AT&T` (write "R and D"), and a URL query such as `?a=1&b=2`; use a plain link without the query.
  Nothing is decoded or stripped, which keeps the checking surface small.
- **Refusals name the line, never the text.** The link, reference definition, HTML, unusual character and
  unreducible character reasons end with or hold the 1-based line number of the first offence and a short fixed
  instruction. No text from the draft is ever printed in a reason, so a private value cannot leak through one. For a
  title and body checked together, line 1 is the title. A refusal is reported once: the same reason found in the body,
  the title and the join is listed with the body or title line number only; a deny value split across the title and
  body keeps its own combined reason. A deny hit still prints only `matched private deny entry #N`.
- **Render-equivalent text.** Every token check runs on the raw text and on its canonical form, and a hit on either
  blocks. The canonical form is NFKC with `*`, backtick, `~` and backslash removed (they vanish when Markdown renders,
  so `W1**AW**`, `box.**lan**`, `192.168.**1**.1` and `https://claude.**ai**/x` are read as what they spell). `_` and
  `-` are not removed.
- **The private deny file.** `SAFO_DRAFT_DENY_FILE` (default `~/.config/safo/draft-deny`) holds one value per line;
  blank lines and lines starting with `#` are ignored. A hash preceded by whitespace starts an inline comment, so
  `acme corp # my employer` is the value `acme corp`; a hash with no whitespace before it stays part of the value
  (`acme#corp`). The allow file takes the same inline comments. A deny value that squashes to a very common English
  word (`the`, `home`, `work`, `test`, `user`, `data`, and about 200 more, built in) prints a one-time stderr warning
  naming the line numbers, never the values, because it would block ordinary text. A comma separated `SAFO_DRAFT_DENY` still works and is matched
  the same way. Matching is exact on a squashed form: NFKC, lowercase, and every character that is not an ASCII letter
  or digit deleted, for the title, the body and the two read together, and for every deny value. So the value
  `Acme Corp` matches `Acme-Corp`, `Ac**me** Corp`, `A c m e C o r p`, `ACME corp` and a value split by a line break or
  by title and body. A value that squashes to fewer than 3 characters is a config error: the run stops before any
  call, naming the line number and never the value. The file must be a regular file (not a symlink, not a FIFO) owned
  by you and not group or world writable, else the run stops with that reason. A missing default file prints once to
  stderr `no private deny file configured: only heuristics are active` and the run continues; a missing file named by
  `SAFO_DRAFT_DENY_FILE` is an error (a typo must not switch the guarantee off). A deny file that exists but holds no entries (empty or only
  comments) is treated the same way: the default file prints once to stderr `deny file has no entries: only heuristics
  are active` and the run continues; an empty file named by `SAFO_DRAFT_DENY_FILE` is an error (exit 2). A reason reads
  `matched private deny entry #4` (the line number; `SAFO_DRAFT_DENY#2` for the second comma separated value) and never
  holds the value. When an entry matches, the draft itself is not printed (it would hold the value), and the metrics
  line never holds content.
- **Title and body together.** After the per-field checks the title and body are also checked joined by a newline and
  joined with nothing between them (raw and canonical), so a value split between them is caught. The reason reads
  `title and body combined: ...`.
- **IPv6.** A run of hex digits, colons and dots is tried as an address, also behind a label (`ipv6:`, `addr:`), with a
  `%zone`, before punctuation, and before trailing word characters (`fe80::1x`, `fe80::abcdxyz`,
  `2001:db8::deadbeefSECRET` are flagged). For each `::` in a run, the prefix up to and including it, and the prefix plus
  the hextets directly after it, are tried as separate candidates. Scope-likeness is decided per candidate, for the
  identifier right after that candidate's own `::`: it is held to the stricter rule (two or more hextets before the
  `::`) only when that character is a letter that is not a hex digit (`std::vector`, `note::x`), or when the word there
  holds an underscore and both sides are one or two hex characters (`a::b_c`). A scope-like `::` elsewhere in the same
  run does not hide a real address (`fe80::1::note::x`, `a::b::fe80::1` are flagged). Times and MAC addresses (`12:30:45`, `aa:bb:cc:dd:ee:ff`) do not
  parse as addresses, and a prefix with fewer than two hextets before a trailing `::` (`fe80::`, `e::`) is not flagged.
  Over-blocking is accepted: a name such as `Config::default` starts with hex characters after the `::` and is flagged
  as an address.
- **Callsign and grid heuristics, and the over-blocking tradeoff.** A callsign is flagged by shape (1-2 letters, one
  digit, 1-3 letters) in any case with no cue word needed: `W1AW`, `w1aw`, and with an SSID suffix of a hyphen and one
  or two digits (`W1AW-7`). A 4-character grid square (two letters A-R, two digits: `EM48`) is flagged the same way,
  and so is the 6-character form (`EM48ab`), and either form after `grid`, `locator` or `maidenhead`. A hyphen or
  underscore is a separator, not part of the token: `call-W1AW`, `grid-FN31`, `w1aw_x`, `my-w1aw-x` and
  `https://example.test/path/W1AW-x` are blocked. Only ASCII letters and digits next to the shape keep it from
  matching, so a 40-hex commit hash is not flagged, and a whole UUID (8-4-4-4-12 hex) is masked first because its
  four-character groups (`a1bc`, `ab12`) have those shapes; a lone `a1bc` is flagged. Over-blocking is the safe side:
  a lowercase word such as `ab12`, `id01` or `a1b` is blocked and a human lists the legitimate ones in an allow list.
- **The allow list.** Only the owner placeholders `N0CALL`, `N0TST` and `FN31pr` are built in, exact and
  case-sensitive (`fn31pr` and `FN31` are blocked). Technical tokens with the shape, such as `K8S`, `K3S`, `E2E`,
  `P2P`, `W3C`, `I2C`, are blocked by default. `docs/draft-allow.example.txt` lists the usual ones: copy the lines you
  want into your own file and point `SAFO_DRAFT_ALLOW_FILE` at it (one per line or comma separated, any mix of commas and
  whitespace; blank lines and `#` comment lines are skipped; matching ignores case; the file follows the same ownership and permission rules as the deny file). `SAFO_DRAFT_ALLOW` takes the same, one per line or comma separated. Allow and deny files over 64 KB (65536 bytes)
  are refused.
- **Footers.** A pull request body must end with the robot-emoji line `Generated with [Claude Code](https://claude.com/claude-code)`
  (exact text in the checks); the wrapper appends it when the model left it out, and replaces a footer variant (a last
  line with "Generated with" and "Claude Code") rather than keeping it. An issue needs an `Epic:` or `Part of epic #N`
  line; `--epic N` adds it when missing.
- **Digests.** Failure lines (or audit drift lines) are normalized, grouped and counted in code. Only the grouped lines
  go to the model, for a five-line summary. With no failure lines the model is not called.
- **Busy queue.** Exit 75 from `llm-local` is retried (each call passes `--wait 60`), with 5 s and 10 s and 20 s
  backoff, four tries in all, then exit 75.
- **Size and timeouts.** The whole prompt is capped at 100000 encoded bytes (the kernel allows 131072 per argument). A
  larger input is refused before `llm-local` is called, exit 2, with a message saying it is a local input error and
  nothing was sent; it is not truncated. Model output over 20000 characters is refused as `draft too long to check safely` (exit 2, nothing filed). A title over 300 characters is refused as `title too long` (exit 2, before any model call, nothing filed; the message never echoes the title), and `check_draft` and `check_text` refuse over-long inputs themselves. `--facts` is decoded as UTF-8 with replacement. A timeout of `llm-local`
  (900 s) exits 11, with the Twingate/server NOT verified line. A timeout of `gh` (120 s) exits 11 and says the filing
  state is unknown: check with `gh` before retrying.
- **Any other failure** exits non-zero, prints the exact failure, and states that Twingate and the local server were NOT
  verified. There is no fallback to a Claude model; the decision to use one is the owner's.

## Metrics

Every call appends one JSON line to `~/.local/state/safo/local-share.jsonl` (`$XDG_STATE_HOME/safo/`):
`ts`, `subcommand`, `model`, `exit`, `chars_in`, `chars_out`. No content is stored. An existing file is set to mode
0600 and the state directory to 0700 on every write. A symlinked state directory, or one not owned by you, is skipped: nothing is logged and nothing is chmodded. A symlinked log file is never written through. `safo-draft --report` prints calls
and failures per ISO week, per subcommand.

## Exit codes

| code | meaning |
| --- | --- |
| 0 | done |
| 1 | refused: the draft or the title failed a check (never filed, even with `--yes`) |
| 2 | error: usage, a missing tool, input too large, or a config file problem |
| 10 | declined: you answered no at the prompt |
| 11 | timeout: `llm-local` or `gh` (for `gh` the filing state is unknown) |
| 12 | unexpected internal error (a bug; the message names it) |
| 13 | `gh` failed when filing or commenting (nonzero exit; the message has gh's own code and text) |
| 75 | local queue still busy after the retries |

Any other code is the `llm-local` exit code passed through, so a passed-through 10, 11, 12 or 13 is ambiguous: read the
message. A failing `gh` is always 13, never gh's own code. The table is also in `safo-draft --help`. Before this change a decline exited 1.
