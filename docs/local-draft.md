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

## What it does

- **Models.** `qwen3.5:4b` for short input, `gemma4:12b` when the prompt and facts exceed 600 characters; `--model`
  overrides. `llm-local` is always called with stdin from /dev/null, because it hangs on an open stdin.
- **Checks before filing** (a failing draft is printed with the reasons and never filed, even with `--yes`). The
  same checks run on the body and on `--title` (a title failure is named `title: ...`): no em dash (U+2014 and the
  look-alikes U+FE58, U+FE31, U+2E3A, U+2E3B; the horizontal bar U+2015 is not blocked), no IPv4 or IPv6 address (an IPv6 address is found behind a label such as `ipv6:` or `addr:`, with a `%zone`, or before punctuation), no
  `.lan`/`.local`/`.internal` style hostname, no serial number (`serial`, `serial number`, `s/n`, `SN` followed by a
  value of 6 or more characters with a digit), no claude.ai URL (with or without a scheme) or `Claude-Session:`
  trailer, no word from `SAFO_DRAFT_DENY` (comma separated; or one per line in the file named by
  `SAFO_DRAFT_DENY_FILE`). The employer name and private hostnames are configured there, never in this repository.
- **Render-equivalent text.** Every check runs on the raw text and on its canonical form, and a hit on either blocks.
  The canonical form is what a reader sees after rendering: Unicode NFKC, all format and zero-width characters dropped
  (category Cf, so U+200B to U+200D, U+2060, U+FEFF, the soft hyphen and bidi marks), HTML entities decoded (numeric
  and named, so `&#46;` and `&amp;#46;` become a dot), HTML comments and tags removed (`W1<!-- -->AW` and `W1<b></b>AW`
  collapse to `W1AW`), and Markdown backslash escapes removed. This repeats to a fixed point, at most 3 rounds.
  Ordinary entities (`a &amp; b`) still pass.
- **Title and body together.** After the per-field checks the title and body are also checked joined by a newline and
  joined with nothing between them (raw and canonical), so a `SAFO_DRAFT_DENY` value split between them is caught. The
  reason reads `title and body combined: ...`. A denied value is also found across a line break or space inside one
  field (whitespace is ignored when matching a deny value).
- **IPv6.** A run of hex digits, colons and dots is tried as an address, also behind a label (`ipv6:`, `addr:`), with a
  `%zone`, before punctuation, and before trailing word characters (`fe80::1x`, `2001:db8::1_ab` are flagged). Skipped:
  the C++ style scope (`::` followed by an identifier that is not a hex group, `std::vector`, `note::x`), runs with
  times and MAC addresses (`12:30:45`, `aa:bb:cc:dd:ee:ff` do not parse as addresses), and an address with
  nothing after its `::` (`fe80::`).
- **Callsign and grid heuristics, and the over-blocking tradeoff.** A callsign is flagged by shape (1-2 letters, one
  digit, 1-3 letters) in any case with no cue word needed: `W1AW`, `w1aw` and `fn31pq`-style tokens are all blocked. A
  4-character grid square (two letters A-R, two digits: `EM48`, `em48`) is flagged the same way, and so is the
  6-character form (`EM48ab`), and either form after `grid`, `locator` or `maidenhead`. The shape must stand alone: a
  match inside a longer alphanumeric, hyphenated or underscore token is ignored, so 40-hex commit hashes, UUIDs and
  long identifiers do not trigger. The owner's callsign and grid must never be published, so over-blocking is the
  safe side and false positives are an accepted tradeoff: a lowercase word such as `ab12`, `id01` or `a1b` is blocked
  and a human lists the legitimate ones in the allow list. Every blocked draft is printed with its reasons.
  Passing tokens: the placeholders `N0CALL`, `N0TST`, `K1ABC`, `FN31pr` (and `FN31`), the technical tokens `K8S`,
  `P2P`, `B2B`, `E2E`, `A2A`, `M2M`, `H2O`, and from round 3 `K3S`, `N8N`, `W3C`, `C2PA`, `I2C`, `I2S`, `E2EE`,
  `L2TP`, `M3U`, plus anything listed (comma separated, case-insensitive) in `SAFO_DRAFT_ALLOW` or one per line in
  `SAFO_DRAFT_ALLOW_FILE`. Project-specific ids that have the shape (this repository's own `T9H`, `U5A` task ids) go in
  `SAFO_DRAFT_ALLOW`. Not caught: a hostname that has no private suffix, an address written in words. Hostnames beyond
  the suffix list are config-driven through `SAFO_DRAFT_DENY`, not guessed. The deny and allow settings are the backstop
  for everything the heuristics miss: put the real callsign, grid and hostnames in `SAFO_DRAFT_DENY`.
- **Footers.** A pull request body must end with `🤖 Generated with [Claude Code](https://claude.com/claude-code)`; the
  wrapper appends it when the model left it out, and replaces a footer variant (a last line with "Generated with" and
  "Claude Code") rather than keeping it. An issue needs an `Epic:` or `Part of epic #N` line; `--epic N`
  adds it when missing.
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
| 2 | error: usage, a missing tool, or input too large |
| 10 | declined: you answered no at the prompt |
| 11 | timeout: `llm-local` or `gh` (for `gh` the filing state is unknown) |
| 12 | unexpected internal error (a bug; the message names it) |
| 13 | `gh` failed when filing or commenting (nonzero exit; the message has gh's own code and text) |
| 75 | local queue still busy after the retries |

Any other code is the `llm-local` exit code passed through, so a passed-through 10, 11, 12 or 13 is ambiguous: read the
message. A failing `gh` is always 13, never gh's own code. The table is also in `safo-draft --help`. Before this change a decline exited 1.
