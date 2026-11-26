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
- **Checks before filing** (a failing draft is printed with the reasons and never filed, even with `--yes`): no em
  dash, no IP address or `.lan`/`.local`/`.internal` style hostname, no serial number, no amateur radio callsign or
  grid square (`N0CALL`, `N0TST`, `FN31pr` pass), no claude.ai URL or `Claude-Session:` trailer, no word from
  `SAFO_DRAFT_DENY` (comma separated; or one per line in the file named by `SAFO_DRAFT_DENY_FILE`). The employer name
  is configured there and is not written in this repository.
- **Footers.** A pull request body must end with `🤖 Generated with [Claude Code](https://claude.com/claude-code)`; the
  wrapper appends it when the model left it out. An issue needs an `Epic:` or `Part of epic #N` line; `--epic N`
  adds it when missing.
- **Digests.** Failure lines (or audit drift lines) are normalized, grouped and counted in code. Only the grouped lines
  go to the model, for a five-line summary. With no failure lines the model is not called.
- **Busy queue.** Exit 75 from `llm-local` is retried (each call passes `--wait 60`), with 5 s and 10 s and 20 s
  backoff, four tries in all, then exit 75.
- **Any other failure** exits non-zero, prints the exact failure, and states that Twingate and the local server were NOT
  verified. There is no fallback to a Claude model; the decision to use one is the owner's.

## Metrics

Every call appends one JSON line to `~/.local/state/safo/local-share.jsonl` (`$XDG_STATE_HOME/safo/`):
`ts`, `subcommand`, `model`, `exit`, `chars_in`, `chars_out`. No content is stored. `safo-draft --report` prints calls
and failures per ISO week, per subcommand.

## Exit codes

0 done, 1 refused (failed a check, or not confirmed), 2 error, 75 local queue still busy; any other code is the
`llm-local` or `gh` exit code.
