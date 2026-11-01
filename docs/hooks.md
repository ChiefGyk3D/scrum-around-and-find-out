# safo hooks

`safo hooks` turns the routing rules in `agents.yaml` into two Claude Code hooks, so they are enforced and not
remembered. The guard is a speed bump and an audit trail, not a security boundary: whoever writes a brief can type the
approval token, and that includes a model that a prompt injection has talked into it.

| Command | Claude Code event | What it does |
|---|---|---|
| `safo hooks install [--settings PATH] [--mode warn\|block] [--command safo]` | none | Merges the two hooks into a `settings.json` (default `~/.claude/settings.json`). Keeps every other hook and setting, is a no-op when run again, keeps a private backup before it replaces the file, and refuses to overwrite a file that changed while it worked (bytes, or the file itself: device, inode, size and modification time are checked again just before the replace, so a rename-over with identical bytes is caught too, with `settings changed while installing`). `--dry-run` writes nothing. |
| `safo hooks probe` | SessionStart | Asks each Ollama endpoint in `agents.yaml` which models are loaded (two bounded GETs, never a generate), saves the answer and tells the session whether the local LLM is reachable. |
| `safo-guard` (or `python3 -m safo.guard`) | PreToolUse, matcher `Agent\|Task\|Bash` | The guard's own entry point, the command `install` writes (see [The guard's own entry point](#the-guards-own-entry-point)). Checks each subagent brief against four rules (below), and each Bash call of the lead against the lead-never-waits rule (the fifth). Two more rules cover Gemini (the sixth and seventh, which deny in every mode). A rerun of `install` moves an older `Agent\|Task` matcher to this one. |
| `safo hooks mode warn\|block` | none | `warn` reports a broken rule and allows the dispatch (the default); `block` denies it. |
| `safo hooks status [--session ID --agents PATH] [--settings PATH]` | none | Which form of the guard hook is installed (`new`, `legacy`, `mixed`, `absent`, `ineffective`, `unknown`), the mode, the retained counts, the health of the hooks and of the last probe. |

A line `safo hooks guard ...` from an earlier install is the legacy form. It keeps working (see below) and `install`
migrates it.

## The guard's own entry point

The hook runs `safo-guard`, or `python3 -m safo.guard`, never `safo hooks guard`. The guard is a short-lived process
and the old form had to guess from a garbled command line whether it was the guard (fifteen review passes on PR #116
each found another line that skipped the verdict). The new entry never parses subcommands: it reads only `--agents` and
`--agents-local` (`--opt V` or `--opt=V`, the last one wins, an empty value is absent, a value that starts with one dash
is a path, a following word that starts with `--` is not taken as the value) and ignores every other word, `--help` and
`--version` included. It uses no argparse, imports no mode, writes nothing to standard error and prints no help. The
event on standard input gets its verdict through the same code as before and the process ends exactly once, inside the
deadline. A command line it cannot make sense of changes nothing about that: the event is still read and judged with
default configuration discovery and the block semantics; only an unreadable event takes the cannot-tell path (the
visible degraded allow).

`install` writes the launcher you chose, resolved the same way: `safo` gives `safo-guard`, `python3 -m safo` gives
`python3 -m safo.guard`, and the absolute path of a safo executable gives the `safo-guard` script beside it (which must
exist). `--agents` and `--agents-local` follow as before. A rerun of `install` replaces an existing legacy
`safo hooks guard` line with the new one, in place, and touches no other hook; a legacy line with a different launcher
is still a "migrate by hand" refusal. `safo hooks status` shows the installed form: `new`, `legacy`, `mixed` (both), `absent`, or `unknown` (the file cannot be
read as settings). It counts an entry as the guard by the SAME rule `install` accepts one (one function,
`entry_problems` in the hooks module of the safo package): the type is `command` and the matcher is `Agent|Task|Bash` (or the older
`Agent|Task` that `install` migrates). A guard-shaped command under another matcher (`Read`, empty, a regex that
leaves out Agent) or another type (`prompt`, `agent`, none) would never run, so status says `ineffective (wrong
matcher, wrong type: ...)`, never `new` or `legacy`; `install` refuses the same entry as ambiguous, to be fixed by
hand. An ineffective duplicate beside a working entry is also `ineffective`, and names the working form after
"another entry is effective". A command that is not a string is not a guard entry at all (`absent`).

Legacy routing (`guard_words` in `safo.modes.hooks`) stays exactly as it was for lines already installed, and is frozen:
it is not extended. Changing the code does not touch your live `settings.json`; re-installing the live hook is a separate
step you run yourself after the release (`safo hooks install`, then `safo hooks status`).

## The four rules

1. **An explicit, known model.** A brief with no `model` is flagged (`no-model`). A model counts as explicit only when it
   is an exact id or model name of an agent in `agents.yaml` (or a full `claude-<family>-<version>` id of one). `inherit`,
   any unrecognised name and a fork with no model resolve to a parent model the hook cannot see, so they are flagged as
   `unknown-model` unless the approval token is in the brief, the same as Opus; in `block` mode that is a denial. The log
   records the model as `unknown`, never the value that was sent.
2. **The approval token.** A known model that `agents.yaml` marks `approval_required` needs `hooks.approval_token` in the
   brief, found however it is cased or wrapped. Put it there only with the maintainer's recorded OK. **The token is a
   speed bump against accidents, not proof of the maintainer's approval**: it travels in model-written text, so a
   prompt-injected model, or any quoted source material, can forge it. `block` mode therefore does not prove a human said
   yes; it only makes forgetting visible.
3. **A local step or a reason for none**, while the last probe is fresh and found the local LLM reachable: a marker from
   `hooks.local_step_markers`, or `hooks.na_marker` followed by a reason.
4. **No hidden work.** A brief carries a line of its own, `issue: owner/repo#N` or `issue: KEY-N`, naming an issue that
   exists and is open (`no-issue`, `issue-unusable`, `issue-unverified`). A GitHub issue is checked with a read-only `gh issue
   view`; in `block` mode a lookup that fails denies. Nothing is exempt unless `hooks.tracking_exempt_repos` lists the
   repository. See [No hidden work](no-hidden-work.md).

## The fifth rule: the lead never waits

The lead session is a project manager; every wait is delegated ([The orchestrator](orchestrator.md)). A Bash call in the
lead session that waits in the foreground is flagged (`warn`) or denied (`block`) with `lead-waits` in the log and a
message that says to rerun it with `run_in_background` or hand it to a Sonnet monitor agent. The message and the log carry
the rule name only, never the command.

What the guard does not decide is what to do about a hung step. That is orchestrator rule 4, in [The orchestrator](orchestrator.md): if a
standing ruling covers it, act on it and report; otherwise report it with evidence and a recommendation.

A small tokenizer splits the call into simple commands, and a wait counts only at **command position**: the first word
after leading `VAR=value` assignments, the shell keywords `do`, `then`, `else`, `if`, `!` and `{`, and these transparent
wrappers (with their options and operands): `time`, `nohup`, `command`, `exec`, `nice`, `env`, `sudo`, `timeout`,
`stdbuf`, `setsid`, `flock` (its lock operand, or `-c 'command line'`), `ionice`, `taskset`, `chrt`, `unbuffer`,
`xargs` and `parallel` (its command ends at `:::`). Commands are
separated by `;`, `&&`, `||`, `|`, `&`, a newline and subshell parentheses. Arguments are data, so `echo gh run watch`
and `echo sleep 60` are not waits.

| Found | Example |
|---|---|
| `gh run watch` | `gh run watch 123 --exit-status` |
| `gh pr checks` with `--watch` or `-w` | `gh pr checks 12 --watch` |
| `watch` at command position (it re-runs a command until stopped; `watch -g` too) | `watch -n 5 gh pr checks 1` |
| a `sleep`, of any length, in the condition or the body (`do` ... `done`) of a `while`, `until` or `for` loop | `until gh run view 9 \| grep -q completed; do sleep 10; done` |
| `sleep` at or above the **threshold** (10 seconds by default; the sleeps of one command add up; an argument the hook cannot read, such as `sleep $n`, counts as over) | `sleep 120`, `sleep 5; sleep 6` |

A sleep counts for a loop only when it is in that loop, its condition (`while sleep 1; do :; done`) or its body:
`while read l; do echo "$l"; done < f; sleep 1` is a one-second pause after a loop, not a poll.

Quoting decides what is code. Single-quoted text, double-quoted text, quoted heredoc bodies and comments are data.
Code inside `$(...)`, backticks, `${...}` (for example `${value:-$(sleep 60)}`), the body of an unquoted heredoc
(`cat <<EOF` followed by a line `$(sleep 60)`) and the word of a here-string (`cat <<< "$(sleep 60)"`; `<<<'...'`
is data) is scanned, also inside double quotes. The body of `$((...))` and `$[...]` is arithmetic and not a command;
only a substitution nested in it runs (`$(( $(sleep 60) + 1 ))`). Before anything else the scanner removes every
backslash-newline the way bash does: not inside single quotes or `$'...'`, not in a comment (which ends at its
newline), not in the body of a heredoc whose delimiter is quoted; it does inside double quotes and in an unquoted
heredoc body, where a line ending in a backslash is joined to the next one BEFORE it is compared with the delimiter. A heredoc delimiter is read as the
complete shell word, quote-removed, the way bash reads it: `<<EOF`, `<<'EOF'`, `<<"EOF"`, `<<\EOF`, `<<E'OF'`,
`<<$'EOF'` and `<<-EOF` all end at a line that is exactly `EOF`. If any part of the delimiter is quoted the body is
opaque data; otherwise its substitutions run and are scanned. The following also count as code the call runs, so they
are scanned: the string given to `bash -c`, `sh -c`, `zsh -c` (also `-lc`), the arguments of `eval`, the split string
of `env -S` / `env --split-string`, and the command that `xargs` and `find -exec` (also `-execdir`, `-ok`, `-okdir`)
run. The same words as arguments to any other command are data.

A function defined in the call (`name() { ... }`, `function name { ... }`) does not wait by being defined. Its body is
scanned only if the same call later invokes the name at command position; `echo name` does not. A function nested in
another is dormant until ITS OWN name is invoked (`outer() { inner() { sleep 60; }; }; outer` only defines `inner`). A
function body that is not a brace group, such as `name() ( ... )`, is read as live code. A marker comment inside a
dormant body exempts nothing (see below).

**Constructs the scanner will not guess at are their own verdicts.** Each is denied by `block` mode and shown as a
warning by `warn` mode, with a content-free message that names only the kind, and a real marker can exempt it like
any flagged call. All the kinds the rule emits: `gh-run-watch`, `gh-pr-checks-watch`, `watch`, `sleep-loop`,
`long-sleep`, and the fail-closed `unscannable-depth`, `unscannable-brace`, `unscannable-indirect`,
`unscannable-timeout`:

- `unscannable-brace`: an unquoted brace expansion (`{a,b}` with a comma, or `{1..3}`) in a COMMAND word builds the
  command at run time (`{sleep,60}`, `sl{e..e}ep 60`). In an argument (`echo {a,b}`), a group (`{ cmd; }`), `${var}` or
  quotes it is not an expansion of the command and is fine.
  A brace expansion in a wrapper's option, option value or operand counts too, because it changes how many words the
  wrapper takes and so which word is the wrapped command: `timeout {1,sleep} 60`, `sudo -u {root,sleep} 60`,
  `flock {f,sleep} 60`, `taskset {1,sleep} 60`, `stdbuf -i {0,1} sleep 60`, through any chain of wrappers. A brace
  word AFTER the wrapped command (`timeout 5 ls {a,b}`) is just its argument and is fine, as are quoted or escaped
  braces.
- `unscannable-indirect`: the call defines a function AND runs a variable- or substitution-expanded word at command
  position (`f() { sleep 60; }; x=f; $x`). A call that defines no function and uses `$x` stays a documented limit.
  `parallel` is also unscannable-indirect when its template is empty (the commands come from the `:::` arguments or
  from input), when its first word is a replacement string (`parallel {} ::: 'sleep 60'`), or when it has an option
  the scanner does not know (`-I`, `--replace`, `--arg-sep`, `-X`, `-S` / `--sshlogin` / `--ssh`...), because an
  unknown option may take a value that hides the command. The ordinary shapes (`parallel -j 4 sleep 60 ::: 1 2`)
  are scanned.
- `unscannable-timeout`: the scan ran past the guard's own deadline (the same budget as the other lookups); every
  unbounded scanning loop checks it, including the quote, substitution and continuation helpers and the reason check.
  After a timeout a marker is never honored (the reason check also honors the deadline), so the call is judged as the
  wait or `unscannable-timeout` it is. Inputs of
  at most 8 KiB are cached (16 entries); a larger input is scanned once per call and not kept.
- `unscannable-depth`: see next.

**Nesting beyond three levels is its own verdict.** Executable syntax (`$(...)`, backticks, `${...}`, `bash -c` and
`eval` strings) nested deeper than 3 cannot be checked here, so the hook does not pass it silently: it reports
`unscannable-depth`, which `block` mode denies and `warn` mode shows as a warning. The message names the rule and the
limit and never echoes the command. The same applies to a call so deeply nested that the scanner runs out of stack. A
`# lead-wait: ok - <reason>` marker can exempt it, like any other flagged call. Simplify the command, or run it with
`run_in_background`.

Not flagged: `sleep 1` or `sleep 9` in a one-shot command (below the threshold, a pause and not a wait); the words
`gh run watch` in a commit message, a quoted string, a comment, an `echo` or a `cat <<'EOF'` heredoc body.

What the hook reads from the event, and what it does not:

- **Lead or sub-agent.** An event raised inside a sub-agent carries an `agent_id`; the event of the lead's own thread does
  not. The rule skips any event with an `agent_id`, because a monitor agent is allowed to watch. This relies on the host
  adding the field. Evidence that it does: an official Claude Code plugin's hook skips sub-agent events with
  `"agent_id" in data`. It was not observed from a live SAFO session here (see Known limits).
- **Background or not.** The Bash tool's input carries `run_in_background`, which the hook reads from `tool_input`. Only the
  boolean `true` counts: `"true"`, `1` and `"yes"` do not. A command that backgrounds itself in the shell (`sleep 60 &`) is
  not the same thing and is not treated as background (`nohup sleep 60 &` is still flagged; only the payload flag exempts).

Configuration, in `agents.yaml` (everything is optional):

```yaml
hooks:
  lead_wait:
    mode: follow                 # follow (use `safo hooks mode`), off, warn or block, for this rule alone
    sleep_threshold_seconds: 10  # 1 to 3600
    exempt_repos:                # a repository whose lead may wait, with the reason it may
      - repo: owner/scratch-repo
        reason: a throwaway repository where nobody waits on the lead
```

Exemptions are never silent:

- A repository entry without a `reason` (at least 12 characters after trimming) makes `agents.yaml` fail to load, so a
  reasonless exemption is refused outright. It applies to the repository bound at SessionStart, the same binding the
  tracking opt-out uses, and to no other.
- A single call can carry a comment, `# lead-wait: ok - <reason>`, with a stated reason: at least 12 characters, of
  which at least 8 are letters (any script) or ASCII digits, counted after combining marks and zero-width or other
  format characters are removed. `!!!!!!!!!!!!` is twelve characters and no reason; neither is padding with
  zero-width joiners or combining marks, nor full-width, Arabic-Indic or circled digits. The marker counts only in a real shell comment: a `#` that begins a word outside quotes. The same text
  inside a quoted string (`echo 'lead-wait: ok - ...'`, a commit message), inside any heredoc body whatever the
  spelling of its delimiter, after an escaped `\#`, or as plain arguments is data and exempts nothing. The call is one
  decision, so the comment may sit on the wait's line or on another line of the same call. A comment in a function
  body counts only if that function is invoked in the call; in a dormant body it exempts nothing. A marker with no reason, or a
  placeholder, is ignored and the call is flagged; the message says a reason is required. An exempted call is allowed
  and logged as `allow` with the `lead-waits` rule, so exemptions can be counted. The reason itself stays in the
  transcript and is never written to the log.
- A repository exemption in `agents.yaml` follows the same reason rule, or the file fails to load.
- Like the approval token, both are speed bumps: an agent with shell access can type a marker. Their job is to make a
  deliberate wait a written decision. The rule is a speed bump against accidents, not a sandbox: an actor who can
  already run arbitrary Bash as the same user can also edit the guard's config, mode file and logs.

## The sixth and seventh rules: Gemini

Two rules protect money and privacy for the Gemini provider ([Gemini](gemini.md)). Unlike the five above, they deny
**even in warn mode**: a paid step with no approval record is blocked, not noted, and private material for the free tier
is blocked, not noted. The log records `gemini-paid` or `gemini-material` and never the brief; the denial message names
the missing thing and never repeats the brief's text.

A brief names a Gemini step with a declaration line (`gemini: free ...` or `gemini: paid cap=1.50 approval=ID`), a
`safo gemini ask|approve` command, or the raw vendor host. A free-text mention is not a step. A command is read with the
parser the CLI itself uses (the same options, no abbreviations), so the guard and the CLI cannot disagree about a
spelling; a command that parser rejects is treated as a paid, unapproved step. `ask` takes `--cap USD`, and the wrapper
refuses when its estimate is over it.

6. **`gemini-paid`.** A paid step (`paid`, `--paid`, `tier=paid`, or the paid secret-store config `prd_paid` named anywhere
   in the brief) is refused outright, with a message that says paid use is disabled and names the rule, the line and the class of phrase that matched (a `safo gemini` command, a `gemini:` declaration, or the paid config name; never the brief's own words or arguments), while the root-owned paid-use switch is off (the
   default; see [Gemini](gemini.md)). Once it is on, a paid step states a cap above 0 and at most 2 USD and an approval id whose record exists, carries a valid signature by an
   enrolled security key (see [Gemini](gemini.md)), was signed against a ledger head that is still in the ledger chain, has
   not expired and has not been used (its nonce is not spent in the ledger). A check that raises, or a guard with no approval folder to look in, blocks.
7. **`gemini-material`.** Every Gemini step needs the line `gemini-material: public`. A secret-shaped string (an API key, a
   token, a private key block) anywhere in the brief, or a match for one of the maintainer's private terms (the terms the fixed Gemini config names, by
   default `privacy-terms.txt` beside it, loaded by the same strict loader the wrapper uses; no environment variable
   changes it; read, never written, never repeated), blocks it. A mention that sends nothing (an `approve` or `quota`
   command with no prompt file) does not need the line. The vendor host written out in a brief is blocked too: call Gemini only through `safo gemini`.

What the guard covers is stated narrowly, because it is a speed bump and the wrapper holds the gates. After folding the
text (NFKD with invisible, combining and control characters removed, NFKC, common Cyrillic and Greek look-alike letters
mapped to Latin), replacing a markdown link by its text and joining line continuations, it treats these as Gemini steps
that must pass the strict check:

- a declaration line in the exact grammar, `gemini: free` or `gemini: paid cap=USD approval=ID` (also as a list item), with
  nothing after the tier but `key=value` pairs, so `Gemini: free tier only` in a sentence is prose;
- a literal `safo gemini <action>` command: a `safo` word, then in the same simple command (no `;`, `|` or `&` between,
  however many flags sit in between) a `gemini` word, then an action word
  (`ask`, `approve`, `quota`), also inside a quoted string. Words are cut the way bash cuts them (single and double
  quotes, a backslash escape): the arguments end at an unquoted `; | & )`, a redirection and its operand are skipped the
  way the shell skips them, and an operator or a shell expansion character inside an argument makes the step unreadable,
  as does a word with a quote or backslash anywhere but its outer edges (`"a"';'`), an operator touching a quoted word
  with no space, and an option-like `--` word straight after the cut. The arguments are read with the parser the CLI uses. A path such
  as `src/safo/gemini.py` or a model id such as `gemini-3.6-flash` is an argument or a name, never a command start;
- these named forms: a `safo` or `gemini` word beside a shell expansion, glob, brace, backtick or `%` and an `ask` or
  `approve` word; and, when the brief names `gemini` and an action anywhere, any line that runs `safo` through `$`, a
  function, `xargs`, `eval`, `alias` or `-c` (so `echo ask --paid | xargs safo gemini` and `alias g='safo gemini'` then
  `g ask --paid` are caught);
- a command built from variables, escapes or substitutions. **No value is ever resolved and no shell is modeled**: a Gemini
  command that is built from variables is blocked by design, and a command made only of literal words stays readable.
  Shell comments are cut off first, the way bash cuts them: a `#` that starts a word (at the start, or after an ASCII
  space, tab, newline or one of `; & | ( ) < >`), outside single quotes, double quotes and `$'...'` words. The cut fails
  closed: when the comment text holds `$`, a backtick, `;`, `|` or `&`, or the text before the `#` holds `$'` or a
  non-ASCII space, the whole line is read. A name counts as assigned when it is set anywhere in
  the brief (`NAME=value`, a prefix assignment, `export`, `declare`, `readonly`, `local`, an array, `printf -v`, a `for` or
  `read` variable), in any order. When the brief names the Gemini surface (`safo`, `gemini`, the vendor host, an SDK, the
  paid config, or words built with escapes), it is unreadable if an assigned name is the command word (also after
  `env`, `do`, `then` and the like), or is referenced on a line that carries a Gemini option or action (`--paid`,
  `--approval`, `--cap`, `ask`, `approve`); or if an escape (an ANSI-C `$'...'` word, a hex, octal or `\u` escape, `printf -v`)
  is the command word or sits on such a line; or if a command segment (the words between `; | & ( ) < >`) holds the word
  `gemini`, the vendor host, an SDK or the paid config and, in that same segment, any variable or expansion. No visible
  option or action is needed for that last rule, so `safo gemini ${X} ${Y}` is blocked. **No Gemini word is needed at all for one more rule**: a Gemini-risk token on a
  line (`--paid`, `--approval`, `--cap` as an option of its own, `approve` as a word of its own, not `--cap-add` or
  `approver`) whose command word is a variable or other expansion (also inside a `bash -c` style command string) makes
  the brief relevant and unreadable. On a line with `--paid`, `--approval`, `--cap` or `approve` followed by an option, **any expansion after the first word of
  the command** makes the line unreadable (NAME=value words before the command are skipped), so no wrapper (`env`, `time`,
  `nohup`, a quoted, backslashed or path-named one) needs to be named or tracked. A brace expansion that bash would perform
  (`{a,b}` or `{x..y}`, nested too, never `${...}`, whose commas and closing brace belong to it alone) counts as a
  possible risk token, and so does any brace in a word that is only partly quoted (a word that is one quoted string is
  not expanded by the shell). A brace expansion also makes an expansion after the first word of the command unreadable, as
  a risk flag does: no word is built or
  enumerated, the line is only scanned once, and a line past the length bound is judged by its marks without being cut. So words built by substitutions, interpreters, `tr`, `awk`, `sed`, a sourced file
  or the environment are caught when the action or flag stands on the page. An expansion that nothing in the
  brief assigned, as the command word or on a line with a Gemini option, blocks when the brief names both `safo` and
  `gemini`. An **unrelated construct** (an array, a function, `eval`, `xargs`, an assignment from an expansion, a shell
  or interpreter `-c`) blocks only beside a `--paid` or `approve` step; beside a free command it is left alone, as it
  is in a brief that names no Gemini command. A line the lexer cannot read that holds an expansion is unreadable.
  Backtick command substitutions are recognized only where a command word or a value would stand and only when they
  start with a common command word (`echo`, `printf`, `cat`, `base64`, ...); markdown code spans are not substitutions.
  Escape-built words make a brief relevant on their own. The false blocks this adds, by design: a brief that names the
  Gemini surface and runs a command through a variable it assigned; a brief with escape sequences that does so; a
  command segment with the word `gemini` and any `$` expansion, even in prose; any brace expansion on a line whose command
  is an expansion (`$BIN ask --{a,b}ccount`) or that has an expansion in an argument (`docker run --cap-{add,drop}=X $IMAGE`); a line with `--paid`, `--approval`, `--cap` or `approve --...` and an
  expansion in any argument (`deploy $X --paid`); a line that starts with an expansion and
  carries `--paid`, `--approval`, `--cap` or the word `approve`; a comment that holds `$`, a backtick, `;`, `|` or `&`
  (read as code); and **here-documents**: their bodies are read like any other lines and are not skipped, because a
  here-document can be fed to `bash`, `sh -s` or `source /dev/stdin` and run, so skipping bodies would be a way around the
  guard; shell examples inside a here-document can therefore false-block an ordinary brief. Time is checked once per line and the
  tracked names are capped at 2000. The message names the construct;
- base64, openssl, xxd, rev or printf escapes piped to a shell; the vendor host in any case; the Google genai SDK; the
  paid secret-store config name. These are looked for in the text before markdown links are rewritten, so a host that
  sits only in a link target is seen. A link to the vendor's documentation (`ai.google.dev`) is a mention and passes; the
  API host (`generativelanguage.googleapis.com`) in a link is the API named and is blocked, like a URL in a command.

### Shell commands (Bash)

The same rules also look at every Bash call, the lead's and a sub-agent's, in the foreground or the background, before
the lead-never-waits rule runs. This is a cheap, fail-closed deny, not a shell model. A command is denied, in every mode,
when it names the vendor API host, the Google genai SDK, the key variable (`GEMINI_API_KEY`), the paid config
(`prd_paid`), the secret-store project (`image-gen`), or the config `prd` beside `doppler` (the names in
[Gemini keys](gemini-keys.md) and `examples/gemini.example.yaml`). Quotes, backslashes, line continuations, comments and
look-alike letters are removed or folded first, the same views the brief scan uses, so `gen""erative...` is seen. Two
more forms are denied without a name on the page: a word built with escapes (an ANSI-C `$'...'` word, a hex, octal or
`\u` escape, `printf -v`) in a command that also runs a network tool or `doppler`, and `doppler` with any `$` expansion
or backtick. Nothing is resolved: a variable's value is never looked up.

One narrow relaxation exists (#264), and nothing else is relaxed: a brief that quotes this denial word for word is
prose, not a Gemini step. The exact fixed sentence (one alternative per phrase class) is removed before the brief is
read, and anything beside it is still read. A here-document written into a file is not relaxed: every such command is
judged by the strict rule. The denial only points to the wrapper and gives no other instruction.

Nothing else is exempt: not the wrapper, not a working directory, not a tool name, not this repository. `safo gemini ...`
commands as documented name none of the protected names, so the check does not touch them; a command that does spell one
out is denied however it is called or wherever it runs (reading this repository's docs with such a command is denied too;
the normal `make check`, `pytest` and `git` commands name none and pass). A renamed or hijacked wrapper (an alias, a
function, a changed `PYTHONPATH`) is covered only to the extent the protected names appear in the command text. A command
longer than 64 KiB is denied unread as "could not be checked in time": no normalization runs on it, so a hostile length costs
nothing, and the shorter ones are checked against the deadline line by line. The
denial names the rule (`gemini-material`) and a fixed phrase class, such as "the vendor API host or SDK", and points at the
wrapper; it never repeats the command. A command that cannot be checked before the deadline is denied.

Not covered, by design: names built from variables (`a=generative; b=language; curl https://$a$b...` with no
`doppler`), names decoded (`base64 -d | xargs curl`) or read from a file or the environment, a script or program the
command merely runs, a shadowed Python module defined outside the command (a file named like an installed module on the
import path), an alias or function defined by a shell startup file the guard never sees, and anything the folding and regexes do not name. The wrapper holds the real gates.

That is the whole claim. Not covered: a wrapper script or alias under another name that hides `safo`, a command written
to a file and run later, other shells than bash, and any language that calls `safo` or the API from inside a program. It does not promise to read every way a shell can build a command: a form outside the list above
is not seen. A line over 4000 characters that mentions any of these, more than 50 commands, or a check that runs past the
guard's deadline is blocked, and so is a private-terms file that does not load or a terms search that does not finish
(see [Gemini](gemini.md)). Every block names the line, the reason and the fix. A false positive is a block, not a leak;
the test suite runs the guard over the repository's own docs and sets a ceiling on false positives. It is a speed bump
against an honest or prompt-injected model writing a brief, not a sandbox, and raw SDK use outside a brief or a shell command is out of its
reach. The guard is not the gate that holds: the approval record, the caps and the free-tier limits are enforced again by
the wrapper itself, which raises before any request when a paid call has no live record. When the dispatch event cannot be
read (over 1 MiB, not valid JSON, cut short, or timed out), or `agents.yaml` cannot be loaded, these two rules still
run or are applied as a literal check (see Failing safe).

## Failing safe

A hook sits inside someone's session, so every error lets the work through, visibly.

- Malformed, oversized (over 1 MiB), non-object or missing-field input, a standard input that never arrives (5 s), an
  unreadable or invalid `agents.yaml`, a corrupt mode file, a failed state or log write, an unexpected exception and a
  command line the hook cannot parse (see the next bullet) all exit 0, print the fixed line `SAFO routing guard degraded: enforcement may be
  incomplete; inspect safo hooks status.` as hook JSON, and add an enum-only record to the log. No exception text, input
  value or prompt is echoed or stored.
- **The Gemini rules do not fail open.** They need nothing from `agents.yaml`, so when it cannot be loaded the brief is
  still checked by `gemini-paid` and `gemini-material`, and a violation is denied (the degraded notice stays in the same
  answer). When the event itself cannot be used, the decision is never made from a prefix. An event over 1 MiB is read
  to its end, up to 8 MiB and 4 seconds, and the whole stream is checked for Gemini markers as it goes (the end of each
  chunk is carried into the next, so a marker cannot hide at a boundary): the words `safo` and `gemini` both seen, the
  vendor host, an SDK name, the paid config name, or a decode-to-shell form, after the same normalization the brief scan
  uses (fullwidth and look-alike letters folded, invisible characters removed, quotes and backslashes removed, JSON
  escapes such as `\n` and `\uXXXX` decoded). The event scan also denies what the brief scan's flow rule blocks, without
  lines (more than 2000 assigned names, the brief scan's own cap, or more than 50000 referenced names is itself a marker, never a
  silent stop; a risk token together with any expansion anywhere in the stream is one too, as is a brace expansion inside a word that holds `--`, `appro`, `cap` or `paid`): an ANSI-C word with an escape, `printf -v` with escapes, or a name assigned anywhere and referenced anywhere while
  `safo`, `gemini` or escape-built words are named. A marker anywhere is **denied** with the diagnostic kept. An event longer
  than 8 MiB, or one that does not finish arriving or cannot be checked within the time, is **denied** as too large or
  incomplete to check. Only an oversized event whose whole stream was read and checked and held no marker is the degraded
  allow. Malformed JSON within the cap is checked whole the same way. A standard input that stalls after some bytes is
  checked for markers and denied either way; one that never delivers a single byte is the degraded allow. No other rule
  changes.
- What a failure switches off: input or configuration failures switch off every rule except those two; a state failure (missing, invalid,
  future-dated or other-session state, or a re-probe that failed) switches off only the local-step rule; a mode failure
  falls back to `warn`.
- Editing `agents.yaml` mid-session changes the name of the session's probe file (it hashes the merged configuration), so
  the saved probe no longer applies. The first dispatch after the edit probes again at once, without the one-a-minute
  limit and with up to 3 s per request (a stale state's re-probe uses 1.5 s), and the guard adds one line saying
  the local LLM was probed now. That is not a degraded state. If the re-probe finds the
  endpoint unreachable, the dispatch is degraded and the notice's diagnostic is `reprobe-timeout`, so an outage is
  told apart from an edit; later dispatches retry at the usual one-a-minute rate. The log keeps its fixed diagnostic
  list, so that record says `probe`. SAFO does not carry the session's repository binding (`tracking_exempt_repos`) to
  the new file name, so after an edit the exemption does not apply until the next `startup`; this is bookkeeping, not
  protection (see the same-user limit below).
- A hook command line never reaches argparse's writing paths. argparse prints usage and the error to standard error
  synchronously before it exits 2, and a full stderr pipe would block that until the host killed the hook (fail-open,
  SAFO #130); exit 2 is also what a host reads as a BLOCK. So the real entry (the module form and the console script)
  recognizes `hooks guard` before argparse is even built and parses its arguments by hand: exactly what `safo hooks
  install` writes, `--agents PATH` and `--agents-local PATH`, each at most once, in either order. Those go straight into
  the guard. Any other guard command line (an unknown flag, a missing value, a repeated flag, `--help`, a stale or hand
  edited install) is a configuration error and not a policy decision: nothing is written to standard error, argparse's
  exit 2 is never used, and the hook answers with the same visible degraded allow as every other failure, through the
  bounded write: exit 0 if the line was delivered, 1 if not. The same holds for `hooks probe`: in the real entry,
  when standard input is not a terminal, the hook parsers print nothing (usage, error and help are suppressed) and the
  failed parse becomes the degraded line. A person at a terminal still gets argparse's usage and help, and `hooks status`
  (a command a person types) keeps argparse's messages.
- The guard has one clock, and it starts when the PROCESS started, not when the guard's code first runs. `safo` records
  the process start the moment it is imported: on Linux from `/proc` (the process age is `/proc/uptime` minus the start
  time in `/proc/self/stat`; both count from boot, so the difference is exact, and reading them cannot block); anywhere
  else, or if the age looks wrong (negative, or over a minute: a long-lived process, or clocks that disagree), it is
  the time of the import, the earliest point left; the fallback is exercised by a test and documented here. The age is
  a difference of two boot-time values, so a suspend does not distort it. The real entry
  (the module form and the console script, through the `run` function of the cli module) arms the guard with it; a test calling `main()` in a
  long-lived process does not, so its budget starts when the guard does. Interpreter start-up, package imports, the
  parser and argument parsing are therefore INSIDE the budget. With the host timeout T (10 s in the installed
  settings, scaled in tests) the points are all measured from the process start:
  - the decision is written by `decide_by = T - m`, where the margin `m = max(2 s, 0.2 T)`, clamped to 40% of T for a
    very small scaled budget: 8 s for T = 10, 3 s for T = 5;
  - lookups, the re-probe and every other pre-decision wait stop one reserve earlier, at `decide_by - min(1 s, 0.1 T)`
    (7 s for T = 10), so there is time to compute and write the line;
  - the post-delivery work (the log and the markers) is waited for until `T - 1 s`, plus 0.5 s, still before T (9.5 s).
  The decision write itself is given until `decide_by`, with NO minimum: a full pipe whose reader never drains it ends
  the process with exit 2 at about 8 s, 2 s before the host would kill it. If `decide_by` has already passed when the
  line is about to be written (a late start), nothing is waited for and nothing is written: a denial exits 2, anything
  else is a silent exit 0. No wait of the guard, pre-decision or after the line, ends later than `T - 0.25 s` from the
  process start. A process whose start-up alone reaches the host's timeout cannot be made safe from inside the Python
  entry; the boundary there is the host (`onFailure: block`) or an external launcher, as SAFO #130 tracks. The rule from SAFO #130 stands: a
  hook the host kills at T is fail-open and its output is discarded, so everything above exists to be out before T. A
  test runs the guard under a watchdog that SIGKILLs its process group at the scaled T and checks that the line and exit
  code came first, for a full stdout pipe, an invalid `SAFO_APPEND_LOCK_TIMEOUT` with a full stderr pipe, and a cold
  start that sleeps before `safo` is imported (Linux; elsewhere the start-up before the import is not counted).
  Importing any module on the guard's path performs no I/O at all (no write to stdout or stderr, no warning): the
  lock-timeout warning is kept in the `LOCK_TIMEOUT_WARNING` variable of the guardlog module and printed by the cli module's `main()` only for commands that are
  not hooks, after they ran. The decision is computed and then written
  and flushed to standard output FIRST, on both the Agent and the Bash path (one shared function); only then is the
  log appended, best effort. A re-probe gets at most what leaves two requests per endpoint and 2 s for the issue
  lookup, and is cut off in total at twice that per-request time (a socket timeout is per read, so a server that sends a
  byte at a time would otherwise hold it); an endpoint still silent then counts as unreachable. If less than 0.5 s per
  request is left, the re-probe is skipped (nothing is claimed, so a later dispatch may try) and the notice names
  `reprobe-skipped`. The event read on standard input also stops at the clock (the lesser of 5 s and what is left).
- Loading `agents.yaml` runs under a wall-clock bound: a daemon worker thread is joined for the time left until the
  guard's deadline (at least 0.25 s) and LEFT RUNNING if it is still going (the process ends right after the decision). A thread works the same on Linux and macOS and
  in any thread; a signal timer would not. On expiry there is no configuration, so every rule is off, as for an
  unreadable `agents.yaml`: a visible degraded allow (log diagnostic `timeout`) with the notice `budget exceeded:
  configuration load timed out, rules disabled`. That is fail-open and is stated as such. The realistic trigger is a
  wedged filesystem or kernel read, which cannot be made without privilege. It is NOT an ordinary FIFO: the production
  reader opens with `O_NONBLOCK` and refuses a non-regular file, so a planted FIFO is rejected at once as a `config`
  failure and never reaches the timeout (a test runs the real loader on a FIFO and pins that). The timeout path itself
  is tested with a synthetic loader that never returns, and says so. What stays unbounded: the read keeps blocking until the process ends
  (it only reads), a state-file read or `fsync` that blocks is not interrupted, and a host that kills the hook before
  the line is out prints nothing. If the load finishes but the clock is past its deadline, the re-probe and the issue
  lookup are skipped and the notice says `budget exceeded: lookups skipped`; a brief whose issue could not be verified
  then follows the usual rules (denied in block mode, flagged in warn mode).
- Delivery is an explicit step: every character of the line is written (a text stream's `write()` returns how many it
  took; a short count is written again from where it stopped, and no progress, or a return that is not a count, is a
  failure), then it is flushed. If that fails (a closed or broken pipe) nothing else is done: no log append, no second
  line, no diagnostic, because once any byte of a decision was attempted nothing else is ever written to standard
  output. The guard's decision path writes NOTHING to standard error (a stderr write cannot be made safe against a
  second writer sharing the pipe, and it was advisory; the exit code and the next dispatch's notice carry the
  information). The one exception is the start-up warning for an invalid `SAFO_APPEND_LOCK_TIMEOUT`, an operator
  misconfiguration, written once at import. The tests that run the guard as a real process use `posix_spawn` (POSIX
  only); none of them needs `/proc`. The exit code says what was lost: a denial that could not be delivered exits 2, which Claude Code reads as "block this call" (so it
  never fails open); any other undelivered line exits 1, a non-blocking error. This is the one case where the guard
  exits 2. That the host treats exit 2 as a block and exit 1 as non-blocking is the host's documented hook contract,
  not verified by a test here. A failure in the diagnostic path is caught and becomes the same exit code.
- The invariant, true by construction because the guard is a short-lived PROCESS: a thread cannot be cancelled, so
  nothing relies on cancelling one. Bounded work runs in daemon threads that the main thread waits for with a deadline.
  When one overruns, the main thread goes on without it, delivers the decision, and the process then ENDS through
  `os._exit` (the guard's only exit point, taken even when everything finished normally): every thread stops at
  once, runs no clean-up, and a blocked call can never resume. In detail:
  - The decision is written and flushed by a thread that the main thread waits for until `decide_by` (see the clock
    above). A reader that keeps a full pipe open and never drains it
    cannot hold the decision back: at the deadline the line counts as undelivered and the process ends with exit 2
    for a denial (the host then relies on exit 2) or exit 1 otherwise. Flags on the shared file description are never
    changed. A write that returns a short count is written again until complete; no progress is a failure.
  - If a PRE-decision worker overran (config load, state and mode reads, the re-probe), the verdict is computed from
    what is available, the line goes out, and the process ends at once: no audit or decision write is attempted in
    that dispatch (it is not logged; the line carries the slow-state notice). A pre-decision worker that was left
    running can write only probe and health caches while the main thread computes and writes the line: the re-probe's
    lock file, its `.attempt` marker and the saved probe state. Those are hints that can change the NEXT dispatch's
    notice or health, never a verdict. That short span, from the overrun to the exit, is the only time a left-behind
    thread can act.
  - Otherwise, after the line is out, the audit and decision writes run in one worker that the main thread waits for
    until the same deadline: the `.repo` modification time (a hint), the clear of the log-failed marker whose notice
    was in the line, the claim of the probe notice, the log append, and the recording of a failed append. If it is not
    done by the deadline the process ends. What a deadline-driven exit can still allow: a system call already
    entered at the moment of the exit may complete; nothing is started after it. A wedged append therefore leaves no
    log-failed marker, and the next dispatch cannot report it.
  - Inventory of writes. BEFORE the decision: only the re-probe's (the lock file and its directory, the `.attempt`
    marker, the probe-state lock and replace, and its clean-up unlink), each in a pre-decision worker. AFTER the
    delivered line, in the post-delivery worker: the `.repo` utime, the marker clear or junk removal (rename to a side
    name, delete, put back), the side-object pruning, the notice claim, the log lock, the append and any quarantine of
    a corrupt log, and the log-failed temp file, install and blocker removal. Everything after the line is bounded by
    the process exit.
  - The tests run the guard as a real process with each of those steps blocked behind a barrier file, check the process
    ended with the right exit code and the line was out in time, then release the barrier and compare a snapshot of
    every path, mode, modification time, size and inode under the state folder: nothing changes.
- The verdict never depends on state writes. Everything that touches the state folder before the verdict (the saved
  probe state, the re-probe's lock and `.attempt` marker, the probe, the save of the probe state, and the pure read of
  the bound repository) runs under a bound, in a daemon worker thread
  that is left running if it does not finish (the process ends right after the decision): a read batch gets at most 1.0 s (at least 0.25 s, and not past the hard
  limit), and the re-probe gets its own total (twice the per-request time plus its slack) plus 1.0 s for its file work,
  never past the deadline. If any of it does not finish, probe health is `unknown` (the local-step rule is off, as for
  any unknown state), the repository counts as NOT BOUND (the existing fallback: no `tracking_exempt_repos` or
  `lead_wait` exemption, so a brief without an open issue, or a wait, is judged by the rule), no further state work
  is done in that dispatch, and the verdict is computed from the configuration alone. The line carries the fixed
  notice `state folder slow: probe state skipped`.
- The mode file read is bounded the same way (at most 1.0 s, at least 0.25 s, not past the hard limit). The documented
  fallback for an unreadable mode file is `warn`, which would let a violation of an explicit rule through as a warning,
  so on a TIMEOUT the verdict is computed in `block` mode: fail closed on a slow mode file. The line says `state folder
  slow: mode file skipped`. (A mode file that is merely unreadable or invalid still falls back to `warn` with the
  `mode` notice, as before.) `lead_wait.mode` set explicitly to `warn` in `agents.yaml` stays what it says.
- Between a computed decision and its emit, the only other state-folder work is a READ-ONLY check of the first-notice
  flag (when the probe is not healthy) and a READ-ONLY inspection of the log-failed marker, under the same bound (at most
  1.0 s, at least 0.25 s, not past the hard limit). The worker changes nothing. The flag is claimed, and any junk at the
  marker name removed, by the post-delivery worker (see the invariant above) only after the line that carries that notice was delivered; an undelivered
  line, or a process killed between the emit and the claim, leaves both as they were, so the notice or the marker
  comes back on the next dispatch. If the check does not finish it is skipped: the decision goes out WITHOUT those
  notices, with the fixed text `notices skipped: state folder slow`, and the flag and the marker are left as they
  were (the check is read-only, so a worker that finishes later creates nothing and leaves no descriptor open). The once-per-session
  probe notice appears only while it is unclaimed: another notice in the same line does not bring it back.
- A computed denial is recorded when the verdict is computed, so an unexpected failure anywhere between the verdict and
  the emit exits 2 (block) instead of falling through to a generic diagnostic and exit 0.
- Because the decision is printed before the log is touched, a failed or skipped log write can no longer appear in the
  same JSON line. Persistence is best effort and catches any exception (not only I/O errors). It is reported by a small
  marker file (`log-failed` in the state folder) that the NEXT guard run reads and reports as
  `previous log write failed` in its own line (log diagnostic `log-write`). The marker is opened relative to a
  descriptor of the state folder (checked on the descriptor: ours, not writable by others), never blocks, never follows
  a link, and must be a regular file of ours. The first install of a failure is an atomic rename of a fresh file (new
  inode, new token) over the marker, so every failure has its own identity. A run records the identity it read (device,
  inode, mode, modification time in ns, size) and removes the marker only if it still has that identity, so a failure
  written by another run in between is kept and reported next. If the rename fails because a directory is in the way,
  only that observed blocker is removed; only if the removal really happened is the install retried, and then with a
  hard link, which never overwrites. There is NO rename fallback: where the filesystem has no hard links (EPERM,
  EOPNOTSUPP, ENOTSUP, EXDEV, ENOSYS) or the name is taken (EEXIST) the retry installs nothing, this run's temp file is
  dropped, and the failure is not recorded until the blocker is gone by hand (the decision is unaffected); a rename
  would overwrite a newer marker, and a look at the name before it is a race. If the blocker was replaced meanwhile, the newer marker is left alone, this run's
  temp file is dropped, and the failure counts as recorded because a marker exists. Junk at the name (directory, FIFO,
  link, foreign or loose-mode file) is removed after the line is delivered, by one look, an atomic rename to a unique
  side name, and a second look at the MOVED object: only an object that still has the observed identity is deleted
  (rmdir or unlink chosen from that same look). The answer is True only if the object is really gone: a directory that
  is not empty stays under its side name and the answer is False. At most 8 side objects (hidden entries named after the marker, with a random suffix) are
  kept: empty directories and our own regular files among them are pruned first, and at the cap nothing more is moved
  aside, so repeated planting cannot grow the folder without bound. Anything else that was moved is put back without
  overwriting (a hard link) and, if it cannot be put back (the name is taken, or there are no hard links), it is KEPT
  under its side name, never deleted. Side objects are pruned only when they are older than five minutes (by ctime,
  which a rename updates, so one a live run has just moved aside is never old) and are named exactly as the guard names
  them (pid and a random id), and then only an empty directory or a regular file that is ours; links, FIFOs, other
  names and directories with content are never pruned (they still count toward the cap). The junk is reported once as
  `log-failed marker unusable` (in that line). Remaining windows,
  all inside the same-user residual (#61): between the first look and the rename a replacement is briefly moved aside,
  so a concurrent reader can miss a marker for a moment; the five-field identity tuple is best effort (a recycled inode, or a
  filesystem with coarse timestamps, could repeat it); and a failure landing between a marker's identity check and its removal by a clear can still be lost. A
  line carries every applicable notice, highest priority first (`mode` or `mode file skipped`, `state folder slow`, `notices skipped`, the
  marker's notice, `budget exceeded`, the probe notice), and the marker is deleted only after a line that shows its
  notice was delivered. The marker is same-user writable like the rest of the state: it can only add a notice and
  never grants anything.
- The limit of what writing the decision first covers (vendor documentation for Claude Code hooks, fetched through a
  summarizing tool, so taken from an extraction, not read in full): a PreToolUse command hook that reaches its timeout
  does NOT block the call, and its output is discarded, unless the hook entry sets `onFailure: "block"`. So the
  decision first only helps when the line is out before the host's timeout; a hook that is killed at the timeout is
  fail-open. Whether the settings that `safo hooks install` writes should set `onFailure: "block"` is tracked separately
  (SAFO #130) and is a settings decision for the maintainer; this document does not change it. Anything this page says
  about what the host does after a flushed decision and a later kill is therefore subject to that rule.
- A log that is not valid UTF-8 anywhere (a complete line or the incomplete tail) is corruption. `append_log` moves it to
  the log's file name plus `.corrupt-<UTC timestamp>-<pid>` (mode 0600, same folder, same trusted-directory rules) and starts a fresh
  log. It never touches `log.jsonl.1`, the real archive. At most 5 such files are kept; the oldest names are deleted
  beyond that, so repeated corruption cannot fill the disk. It does not raise. The same-user residual (#61) still holds
  here: an actor running as the same user can damage, replace or delete the log and these files; the log is advisory
  telemetry, not tamper-evident evidence.
- A re-probe that times out stores an unreachable state for `max_state_age_seconds` (300 s by default), so later
  dispatches log health `healthy` and `local_reachable` false with no notice, as after a stale-state re-probe.
- The line shown after the first probe under a new configuration says there was no saved probe for it (an edit, or a
  session with no probe yet; SAFO cannot tell which) and that no `tracking_exempt_repos` binding carries over.
- `safo hooks probe` run by hand on a terminal waits a quarter of a second for an event; if none arrives it prints a
  usage line and exits 0, with no log entry. An event that does arrive (a wrapper that gives the hook a pty) is
  processed as usual, and so is a piped payload.
- Same-user limit, tracked in #61 (Guard the guard). The probe state, the `.repo` binding, the `.attempt` marker and the
  log are files under the same user id as the model the guard governs. An actor that can write the state directory can
  forge a fresh `{reachable: false}` state (which switches the local-step rule off), forge a `<probe>.repo` file (which
  grants a repository exemption: a test pins this), pre-create `.attempt` (which suppresses a re-probe for a minute),
  delete the state and `.attempt` before each dispatch (which forces the slow re-probe every time), or append a valid
  record to the log (which can make `safo hooks status` read healthy). The log is advisory telemetry, not evidence.
  SAFO does not try to stop this here, and none of the above is a security boundary; the guard stays a speed bump
  against accidents.
- A denial that was computed survives a log failure.
- stdout is exactly one JSON line or nothing. `probe` and `guard` never exit 2 (a host reads that as a denial), even for a bad flag. The one exception: a guard denial whose line could not be delivered exits 2 so the host blocks (see Failing safe).
- The host's own timeout (15 s for the probe, 10 s for the guard in the installed settings) is the last backstop. How a
  given Claude Code version treats a timed-out or crashed hook is not verified here.

## What is stored

Under `$XDG_STATE_HOME/safo/hooks` (default `~/.local/state/safo/hooks`), mode 0600: `log.jsonl` (decision, mode, model
identifier or `unknown`, booleans, rule names, health, diagnostic enum; at most 2048 bytes a record, 4 MiB, one archive)
and per-session probe files named by a hash of the session id and the merged configuration, holding a completion time,
booleans and role flags. No prompt, description, address, endpoint name or loaded-model name is stored. Probe files
untouched for a week are removed when a session starts. The mode lives in `~/.config/safo/mode`.

SAFO creates its own state and config directories mode 0700. Before it uses one, the directory must be owned by the
effective user and not group- or world-writable; otherwise the feature degrades visibly instead of trusting it: the
guard allows with the degraded notice and writes no log, lock or state there, the probe reports a state-write
failure, and an untrusted config directory means the mode file is ignored (`warn`, health degraded). The reason is
that a lock is a pathname's inode: anyone who can write the directory can unlink a held lock and make a second one, or
replace the mode, state and log files.

## Installing safely

Run `safo hooks install --dry-run --settings /tmp/try.json` first. Start in `warn`, read `safo hooks status`, then
switch to `block`. Before recommending `block`, run the disposable real-session smoke test listed in the plan (Task
T9h, step 5): fixture tests cannot show that a real Claude Code session displays the warning or honours a denial.

## Where the local files may live

Under GitHub Actions the agents file, the local override and the outcomes log are refused when they lie inside
`$GITHUB_WORKSPACE`, by the path as written or after following links, and every explicit path is refused when
`GITHUB_WORKSPACE` is unset; only the home defaults remain. Accepted residual: outside Actions, an explicit `--agents`,
`--log` or `$SAFO_AGENTS` naming a file in the current directory is the user's own deliberate choice and is allowed
(the current directory is never searched on its own).

## Endpoint destinations

An Ollama endpoint may be loopback or a private LAN address. Link-local, unspecified, multicast and cloud-metadata
addresses (including IPv4-mapped IPv6 and decimal, octal and hex spellings) are refused when `agents.yaml` is loaded
and again at connect time. A name is resolved once, every address it returns is checked, and the connection goes to the
checked address with the original `Host` header, so a DNS answer that changes between the check and the connection has
no effect.

## Log append wait

`SAFO_APPEND_LOCK_TIMEOUT` is how many seconds a log append waits for another writer's lock. Default `3.0`; the value
is read once when `safo` starts. A value that is not a number, not finite (`nan`, `inf`, `1e999`) or not above 0 is
ignored: the default is used and one line naming the variable is printed to stderr after the command has run, for every command that is not a hook (a
hook never prints it, and nothing is written when `safo` is imported). A value above
the maximum of `5` is clamped to 5. A bad value never stops `safo` from starting.

The value is read with Python's `float` syntax, so `1_0`, non-ASCII digits and tiny values such as `1e-5` count as
numbers; anything above 5 (including the underscore forms) is clamped.

Budget: the host gives the guard 10 s, and the guard runs on one clock from the start of the process (see Failing safe
for the arithmetic: the decision is out by 8 s). The decision is written and flushed first. The append then waits for the lock for the setting or for what is left until 9 s,
whichever is less. If less than 0.05 s is left, or the clock is already past 9 s, the append is skipped: it is never
started late and never stretched past 9 s. A longer setting therefore does not extend the hook. A skipped or failed
append is reported, on the next guard run, as `previous log write failed` (see Failing safe). The
configuration load and the notice I/O are bounded in wall time (see Failing safe). A hook killed at the host's
timeout is fail-open and its output is discarded unless the hook entry sets `onFailure: "block"` (SAFO #130). The append itself is not interruptible once it holds the lock (fsync can block). The
other lock users (mode, probe state) keep their 0.5 s wait.

## Known limits

- The lead-never-waits rule is a tokenizer, not a shell parser. It is a speed bump against accidents, not a sandbox:
  an actor who can already run arbitrary Bash as the same user can also edit the guard's config, mode file and logs.
  These cannot be decided from the text of one call. Each is allowed, and each has a test that asserts exactly that, so
  the docs and the code cannot drift:
  - [limit: variable-built command] `cmd='sleep 60'; $cmd`.
  - [limit: variable passed to a shell] `c='sleep 60'; bash -c "$c"`: the string is a variable, not text.
  - [limit: encoded payload piped to a shell] `echo c2xlZXAgNjA= | base64 -d | sh`.
  - [limit: interpreter] `python3 -c` or `perl -e` with a sleep call inside, and any other language's sleep or poll.
  - [limit: script file] `bash poll.sh`: the file is not read, so a loop in it is not seen.
  - [limit: alias] `alias w='sleep 60'; w`: an alias defined earlier or in a startup file.
  - [limit: remote command] `ssh host 'sleep 60'`: the wait runs elsewhere (and still holds the thread).
  - [limit: variable behind eval] `x="sleep 60"; eval "$x"` with no function defined in the call.
  - [limit: variable behind command] `x=sleep; command $x 60`: the word after a wrapper is a variable.
  - [limit: variable behind exec] `x=sleep; exec $x 60`.
  (When the same call also defines a function, a variable-expanded command word is `unscannable-indirect` instead.)
  Also not seen: `timeout ... tail -f`, a function defined in an earlier call, and a wait inside a function body that
  is not a brace group. Shell grammar is approximated: `case` arms are read as plain commands, and `${...}` is read for
  its substitutions only. `parallel` options are a fixed list, and an option outside it is `unscannable-indirect`. Executable syntax nested deeper than 3 levels, a brace-built command, an
  indirect call next to a function definition and a scan that runs out of time are reported as `unscannable-*`
  rather than guessed at. The cheap pre-check tokenizes any call that contains a quote, backslash, `$`, backtick or
  `{` (or the word `parallel`), so a word built from pieces (`sl''eep 60`, `sl{e,e}p`) is not missed; a call with none of those and
  none of `sleep`, `watch`, `checks` reads no configuration and logs nothing. It would rather miss the cases above
  than flag text. Whether a given Claude Code version puts `agent_id` on sub-agent events was not verified in a live
  SAFO session; if it did not, a sub-agent's watch would be flagged as the lead's (a warning in `warn` mode, a denial in
  `block`). Test that in a disposable session before `block`.

- The approval token is forgeable (see rule 2). A channel the model cannot write to, such as a signed or
  session-bound approval the maintainer issues outside the conversation, is future work; v0.1.0 has none, and nothing in
  `block` mode should be read as proof of approval.
- Directory checks look at the SAFO directory itself, not the path above it, and the installer's own lock and temp file
  sit beside the settings file you name (for example `/tmp`), which it does not require to be private.
- The installer narrows the replace race but pathname operations cannot close it: an external writer can still land
  between the final identity check and the rename.
