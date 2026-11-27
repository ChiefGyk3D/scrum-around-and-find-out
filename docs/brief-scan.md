# Brief secret scan (`safo-brief-scan`)

Design note for #537 (epic #518). A standalone check that scans the text of an agent brief or report for secrets and
private data before it leaves the machine. It is a separate entry point, not a `safo` subcommand and not part of the
dispatch guard: a new top-level subcommand would have to be added to `TOP_LEVEL_COMMANDS`, which is guard code and
frozen. Nothing in this repository wires it into a hook; the settings change is the maintainer's to make.

## Contract

    safo-brief-scan [FILE ...]            scan files, or stdin when no file (or `-`) is given
    safo-brief-scan --hook                read a Claude Code hook JSON document on stdin and scan its tool input

| Exit | Meaning |
| --- | --- |
| 0 | nothing found |
| 1 | one or more findings (plain mode) |
| 2 | the input could not be read or checked: missing, unreadable, symlink, FIFO, over the size cap, not UTF-8, bad usage. Fail closed: never read as a pass |

In `--hook` mode a finding is also exit 2, because that is the code a Claude Code hook uses to block a call; stderr then
carries the finding list for the model to read.

## Output (stderr, never the secret)

One line per finding: `SOURCE:LINE: TYPE [hash]`. `hash` is the first 6 hex characters of the SHA-256 of the matched
text, shown only for the credential classes, which are high entropy. The private-data classes (hostname, address,
serial, callsign, grid square, a deny-list term) are low entropy, so a hash prefix would let a reader guess them; they
show `-` instead. A deny-list finding names the entry label (`#4` is line 4 of the file), as `safo-draft` does. At most
200 findings are printed; the exit code still reports the rest.

## What it looks for (reuse first)

- Credential shapes: `safo.gemini.SECRET_SHAPES` (Google, GitHub, AWS, `sk-`, Slack, Doppler tokens and PEM private
  key headers), used unchanged.
- Three shapes added here because the list has none: an `Authorization` or bare bearer header with a token, a JWT
  (three dot separated base64url parts, first two starting `eyJ`), and a `password`, `secret`, `token` or `api_key`
  assignment with a long mixed value (shell references and low-variety fillers are not values).
- Private data: the detectors of `safo.localdraft` (IPv4 and IPv6 addresses, private hostnames, serial numbers, callsign
  and grid-square shapes with `N0CALL`, `N0TST` and `FN31pr` allowed, claude.ai session URLs, and the private deny file
  `SAFO_DRAFT_DENY_FILE` / `SAFO_DRAFT_DENY`, see [Privacy check](privacy.md)). `SAFO_DRAFT_ALLOW` and
  `SAFO_DRAFT_ALLOW_FILE` extend the allowed callsign and grid tokens. The Markdown, HTML and epic checks of the draft
  checker are not used: a brief may hold all of those.
- Each line is scanned raw and again in NFKC form, so a full-width look-alike is not a bypass.

## Bounds and failure

- No network, no subprocess, nothing written.
- Input is read as bytes with a hard cap of 1 MiB (files by descriptor, no symlink, regular files only); one byte over
  is exit 2, never a truncated scan. Invalid UTF-8 is exit 2.
- Hook JSON is parsed with `safo.bounded.loads` (size and depth limits, duplicate keys refused); every string inside
  `tool_input` is scanned, labelled by its key path.

## False-positive control: the allow marker

A line may carry `safo-scan-allow: REASON` (REASON at least 8 characters). Findings on that line are then suppressed
and counted on stderr (`allowed: N`, with the line numbers, never the reason or the match). A marker with no reason or
a short one suppresses nothing and is a finding of its own (`allow-marker-without-reason`). The reason text is scanned
separately for credential shapes, so a secret cannot be hidden in a reason. A marker applies to its own line only.

## Not covered

A value that is split, encoded or paraphrased is not found; this is a shape check and a second line of defense, not a
guarantee. A finding means remove the value, never reword it around the check.
