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
- **HTML is refused, not decoded.** A draft with an HTML tag, comment or declaration (`<` followed by a letter, `!`, `/`
  or `?`) or a character reference (`&name;`, `&#65;`, `&#x41;`, and the same without the semicolon when a word
  boundary follows) fails with "HTML is not allowed in drafts; use plain markdown". `a < b` and `x<=y` pass. This also
  refuses `R&D` and `AT&T` (write "R and D"), and a URL query such as `?a=1&b=2`; use a plain link without the query.
  Nothing is decoded or stripped, which keeps the checking surface small.
- **Render-equivalent text.** Every token check runs on the raw text and on its canonical form, and a hit on either
  blocks. The canonical form is NFKC with `*`, backtick, `~` and backslash removed (they vanish when Markdown renders,
  so `W1**AW**`, `box.**lan**`, `192.168.**1**.1` and `https://claude.**ai**/x` are read as what they spell). `_` and
  `-` are not removed.
- **The private deny file.** `SAFO_DRAFT_DENY_FILE` (default `~/.config/safo/draft-deny`) holds one value per line;
  blank lines and lines starting with `#` are ignored. A comma separated `SAFO_DRAFT_DENY` still works and is matched
  the same way. Matching is exact on a squashed form: NFKC, lowercase, and every character that is not an ASCII letter
  or digit deleted, for the title, the body and the two read together, and for every deny value. So the value
  `Acme Corp` matches `Acme-Corp`, `Ac**me** Corp`, `A c m e C o r p`, `ACME corp` and a value split by a line break or
  by title and body. A value that squashes to fewer than 3 characters is a config error: the run stops before any
  call, naming the line number and never the value. The file must be a regular file (not a symlink, not a FIFO) owned
  by you and not group or world writable, else the run stops with that reason. A missing default file prints once to
  stderr `no private deny file configured: only heuristics are active` and the run continues; a missing file named by
  `SAFO_DRAFT_DENY_FILE` is an error (a typo must not switch the guarantee off). A reason reads
  `matched private deny entry #4` (the line number; `SAFO_DRAFT_DENY#2` for the second comma separated value) and never
  holds the value. When an entry matches, the draft itself is not printed (it would hold the value), and the metrics
  line never holds content.
- **Title and body together.** After the per-field checks the title and body are also checked joined by a newline and
  joined with nothing between them (raw and canonical), so a value split between them is caught. The reason reads
  `title and body combined: ...`.
- **IPv6.** A run of hex digits, colons and dots is tried as an address, also behind a label (`ipv6:`, `addr:`), with a
  `%zone`, before punctuation, and before trailing word characters (`fe80::1x`, `fe80::abcdxyz`,
  `2001:db8::deadbeefSECRET` are flagged). The prefix up to the last `::` is tried too. A run is C++ scope-like, and
  held to the stricter rule (two or more hextets before the `::`), only when the character right after its last `::` is
  a letter that is not a hex digit (`std::vector`, `note::x`), or when the word there holds an underscore and both
  sides are one or two hex characters (`a::b_c`). Times and MAC addresses (`12:30:45`, `aa:bb:cc:dd:ee:ff`) do not
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
  want into your own file and point `SAFO_DRAFT_ALLOW_FILE` at it (one token per line, `#` comment lines, matching
  ignores case; the file follows the same ownership and permission rules as the deny file). `SAFO_DRAFT_ALLOW` takes a
  comma separated list.
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
  nothing was sent; it is not truncated. Model output over 20000 characters is refused as `draft too long to check safely` (exit 2, nothing filed). `--facts` is decoded as UTF-8 with replacement. A timeout of `llm-local`
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
