# Gemini

> **Status.** The free research path is live: `quota`, `ask` and `keys` need no root file. **The paid path exists only
> through the broker** ([Gemini broker](gemini-broker.md)): a separate program, running as its own user, that alone holds
> the paid API key, the spend ledger and the single-use approval records. The program on this page holds no paid key, signs
> nothing for a call and sends no paid request. The in-process paid code that used to live here (`ask --paid`, the local
> `approve`, the approval records, the paid spend counter and the paid key read) was **deleted**, not just disabled (#287);
> `ask --paid`, `--approval`, `--cap` and `approve` are recognized only so the dispatch guard keeps reading a brief that
> names them as a paid step, and the command refuses them with a message that points to the broker. Two commands are the
> broker client run from this command group: `safo gemini paid` (one paid call) and `safo gemini paid-dryrun` (test the
> signer and the broker, no call).

Gemini is a **free-only** research provider for **public material** on this page's command. It is in [the roster](routing.md)
as the agent `gemini`, and the shape `public-source-research` prefers it. This page is what the code does, what it cannot
do, and what the maintainer has to supply. Decisions are in issues #195 (the spend gate), #196 (the provider), #200 (this
build) and #287 (removing the in-process paid path).

## Why free-only, and what never goes to it

The vendor's terms say that prompts sent through the free tier may be **used for training** and **read by human
reviewers**, and tell you not to submit sensitive, confidential or personal information. So nothing private ever goes to
Gemini: no repository-private data, no secrets, no personal data, no callsign or grid square, no employer details, no
unfixed vulnerability detail. The work is OSINT-style gathering of **public sources**, authorized and defensive only, about
organizations, public infrastructure, CVEs, vendors and public documents; never about a private individual. Adversarial and
exploit work stays on the cyber-program tiers. Text work the local LLM can do stays local-first. Every claim Gemini cites is
checked at its source URL before anyone relies on it.

## The gates, all in code

A model never counts, caps or approves anything here.

1. **The free tier follows your own limits.** `safo gemini ask` counts requests per minute, input tokens per minute and
   requests per day from the ledger, per model. The day ends at **midnight Pacific**, where the vendor resets it. The
   per-model numbers are shown in AI Studio and nowhere else, so they are values in `gemini.yaml` that you supply; the
   example file ships deliberately tiny ones. A model with no limits configured gets no quota line and no call. The ledger
   is only our own count (other users of the same project are invisible to it), so the vendor's answer is the authority.
2. **A 429 is final.** On HTTP 429 (`RESOURCE_EXHAUSTED`) the job stops and reports the quota line, exit code 3. Nothing is
   retried and a free call **never falls through to a paid call**: there is no paid key in this program to fall through to.
3. **Money goes through the broker, and only there.** `ask` refuses a paid request before it runs any gate or reads any
   key; the dispatch guard denies a brief with a paid step in every guard mode, `warn` included, because a paid call needs
   a person's touch on a security key at a terminal.

## Paid calls: only through the broker

The paid API key exists **only in the broker's own credential** (an encrypted, root-owned file that systemd hands to the
broker user; the maintainer's account cannot read it). It is not in `gemini.yaml`, not in the secret manager configs this program reads, not in the
environment and not in any file this program opens. `gemini.yaml` no longer has a `paid_config` setting, a `signing` block,
caps or a price table; a file that still has one is refused when it loads, with the key named, so a stale copy cannot sit
there looking active.

- `safo gemini paid --model M --job J --prompt-file F --max-output-tokens N --max-usd X --quote Q --quoted-at T`
  `[--issue I] [--kind text|image --count N --image-size S --aspect-ratio R]` runs the broker client
  (`src/safo/broker/client.py`): it checks the request, asks the broker for an offer, shows the **whole** approval text and
  the whole prompt with its digest, waits for you to type `approve <job>`, signs with the security key (a touch), sends
  ONE `call` and prints the broker's receipt. It never retries and never tries another tier. The settings it reads are
  `~/.config/safo/broker-client.yaml` and the root-owned `/etc/safo/broker-client.yaml` (the socket); see the broker page.
- `safo gemini paid-dryrun [--job LABEL]` signs one throw-away text in the dry-run namespace
  (`safo-gemini-approval-dryrun`, which cannot approve a call) and asks the broker's `dryrun` operation to verify it. It
  tests the key, the enrollment, the touch and whether the broker's switch is on, and the broker spends and records
  nothing. The global `--dry-run` flag on either command stops before any signing or socket.
- Both need a person at a terminal (standard input and output) and refuse otherwise. Nothing on the command line, in the
  environment or in `gemini.yaml` moves the broker's socket or turns paid use on; the switch is a root-owned file the
  broker reads (see the broker page).
- A subagent brief cannot carry a paid step. `gemini: paid ...`, `--paid`, `approve`, `paid` and `paid-dryrun` are all
  read as paid steps and denied. This is the guard grammar after #287: the guard no longer looks up an approval record,
  because no such record exists any more.

The caps (2 USD per job, 10 USD per month), the price table, the approval text (version 3, with the prompt digest and the
nonce), the single-use and replay rules, the spend ledger and the image handling are the broker's, and are documented in
[Gemini broker](gemini-broker.md) and [its threat model](gemini-broker-threat-model.md).

## Who can approve: the enrolled keys

An approval is a signature by a hardware security key over the text the broker's offer defines. The trust is two
**maintainer-edited public files** at fixed locations, `/etc/safo/gemini-allowed-signers` and
`/etc/safo/gemini-revoked-signers`, which the broker also reads (on every request). Each must be a regular file **owned by
root**, not writable by group or others, under directories that are root-owned and not writable by others; the code never
writes to them. That stops an agent running as the maintainer from enrolling its own key. No flag, environment variable or
`gemini.yaml` setting moves them or relaxes the rules; only a test, through the `fixed_locations` function argument, can.
Several keys can be enrolled, each under its own label; see [Gemini keys](gemini-keys.md) for adding, rotating, backing up
and revoking them. Only hardware keys (`ed25519-sk`, `ecdsa-sk`) count for a paid approval (the broker refuses a software
key), and a key with `no-touch-required` is refused when the file is loaded.

What `ssh-keygen -Y verify` does not say, the code reads from the public signature itself: the signer's key (so the
revocation list is consulted by key), the namespace, and for a hardware key the authenticator's flags: **user presence
must be set** (the touch), and **user verification (the PIN)** where the maintainer wrote `require-pin` for that key. Those
flags are part of what the key signs, so they are authentic once the signature verifies; they are only as honest as
the authenticator that reports them.

The config and the private-terms file are at **fixed locations** taken from the account database, not from `$HOME`, an XDG
variable, a flag or `SAFO_GEMINI_CONFIG`. The ledger location is a key in that fixed config, and if the ledger is missing
while another `gemini-spend-ledger.jsonl` sits in a sibling folder, every call is refused instead of starting an empty
ledger that reads 0.

The threat model for the approval and the spend state is [the broker's](gemini-broker-threat-model.md). The residual risks
stay what they were: **social engineering** of the touch (a tired maintainer who touches a blinking key approves whatever
was signed), and a **compromised signing step** (code that runs as the **same user** can replace `ssh-keygen`, `safo` or
the terminal, and show one text while signing another; the verifier checks the signed text, not what was displayed). The
typed `approve <job>` on a real **terminal** is what ties a touch to a spend. A paid key an agent can read would be
worse than either, which is why the paid key exists only in the broker's credential: **there is no paid key here**. What remains true for any approval: **touch the key
only after reading the whole approval text and the whole prompt and its digest, and never for a prompt you did not
start.** The approval covers that exact prompt: one changed byte, a trailing newline or another Unicode form is a
different prompt with a different digest, and a prompt over **4000 characters** is refused because the person signing must
be able to read all of it.

## The free ledger

`gemini-spend-ledger.jsonl` lives outside git (default `~/.local/share/safo/`, or the path in `gemini.yaml`), is created
mode 600 and is **append-only and hash-chained**: the wrapper only appends, under a lock, and fsyncs. The first time it
writes, it appends a `chain_start` row that records the hash of the exact bytes of every older row; from then on each
row carries `prev_hash` and its own `hash`. The older rows are never edited. If anything after (or before) `chain_start`
is deleted, edited, reordered or cut off, every call refuses and names the line. A second copy of the newest hash sits in
a small head file beside it (the ledger name plus a head suffix) catches a truncated tail, and a **height record** kept
apart from the ledger, in the fixed state folder (`heights`), remembers the longest chain this wrapper has seen and
refuses a shorter one, naming the recorded height. A call writes a `call_start` row (time, model, tier, estimated tokens,
job) before the request leaves and a `call_end` row after (status, HTTP status, usage). A start with no end counts as a
request made. Rows are **not added by hand** once the chain has started (that would break it). Rows of the removed paid
path (`approval_issued`, `approval_used`, paid calls, `usage`) still parse if an older ledger holds them, but nothing
writes them and nothing counts spend from them: the paid spend is the broker's ledger, read with the broker's admin
command. Any line the reader cannot parse stops every call, because a counter that skips a line could undercount. A
ledger that is a symlink or a pipe is refused. Tests use a temporary ledger and never the real one. A row of an unknown
type stops every call and is named by its record number, rather than being ignored.

## Private terms

Before anything is sent, the wrapper checks the prompt itself, not only the brief, against the same secret shapes and
against the maintainer's private terms (default `~/.config/safo/privacy-terms.txt`, or the path in `private_terms`), on
the text as written and on its folded form (invisible characters removed, look-alike letters mapped). The dispatch guard
reads the terms with the **same loader** (the fixed config's setting, never `SAFO_PRIVACY_EXTRA_FILE` or an XDG variable).

A term is a plain word or phrase with a few bounded repeats. Refused when the file loads, with the line number: a pattern
that can match nothing at all (`x{0,5}`, `^`, `\b`, an empty group), an unbounded repeat (`+`, `*`), a repeat inside a
repeat or of something that can match nothing, an alternation inside a repeat, a back reference, more than 8 optional parts and alternatives together (each doubles the work), two wildcard repeats (`.`, `\w`, `\s`, `\S`) next to each other, and repeats whose upper
bounds multiply to more than 10000 (so `foo.{0,50}bar.{0,50}baz` loads, `.{0,99}.{0,99}.{0,99}z` does not). At most 500
terms of at most 200 characters. These shape rules keep a search short, but they cannot prove it: the search itself also
runs in a **child process that is killed after a few seconds**, and a search that does not finish counts as a match, so
the guard denies and the wrapper sends nothing. The worker is found by file path and needs no install; it also limits
itself (a CPU limit, an alarm of its own, and on Linux a signal when its parent dies) so it cannot outlive the process that
started it. Each term sees at most 4000 characters at a time. A file that is missing,
unreadable or oversized stops the call; `private_terms: none` is the written opt-out. `--material public` is still a
statement by the caller: no code can know that a text is public, so these checks only catch what looks like a secret or
matches a term the maintainer listed.

## The wrapper's own process (#221)

`safo gemini ...` does not trust the process it was started in. At the entry, before it reads a config, a prompt or a key:

- **Which command runs is decided by the real parser.** The entry asks the same top-level parser the command uses (so
  abbreviations, `=` forms and a value that looks like a mode are read exactly as the command reads them); there is no
  second scanner to disagree with it.
- **It refuses to run** when an interpreter startup variable (any name starting `PYTHON`, such as `PYTHONPATH`,
  `PYTHONSTARTUP`, `PYTHONHOME`, `PYTHONUSERBASE`), a shell startup variable (`BASH_ENV`, `ENV`) or a loader or locale
  search variable (any `LD_*`, `GCONV_PATH`, `LOCPATH`, `NLSPATH`) is set. The error names
  the variables, never their values, and nothing runs. Unset them and run again.
- **It re-starts itself** as `<absolute interpreter> -I -c <boot> <package folder> ...`: no user site, no `PYTHON*`
  variables, no current directory on the import path, and the `safo` package that launched it is first on the path, so no
  other copy wins. A failure to start the child stops the call; it never falls back to running in place.
- **The child checks that it is the child.** The interpreter flag alone proves nothing, so the child carries on only when
  its environment is exactly the allow-list for its action and its working directory is the fresh private folder named by
  `TMPDIR` under the scratch root. A process that merely runs `python -I -m safo gemini ...` in a dirty place is refused.
- **The child's environment is an allow-list**, built in the `wrapper` module, never a copy of yours: `PATH` fixed to
  `/usr/local/bin:/usr/bin:/bin`, `LANG` and `LC_ALL` fixed to the UTF-8 C locale, `TMPDIR` set to the child's own
  directory, and `HOME` from the account database. Per action, and only that action: `ask` receives the secret-store token
  variable (the one secret it needs for the FREE key, when you set it); `paid` and `paid-dryrun` receive `SSH_AUTH_SOCK`,
  `DISPLAY`, `WAYLAND_DISPLAY` and `TERM` (the signer needs them) and no secret at all. A signing provider library or an
  askpass program named by the caller is never passed on. Proxy variables, `LD_*`, `XDG_*`, the other secret-store
  variables, tokens and every other secret are dropped. The secret tool must therefore be found in one of the three fixed
  PATH directories.
- **The child runs with no shell**, a fixed argument vector, a fresh private (mode 0700) working directory under
  `~/.local/state/safo/wrapper` (every folder on that path is opened without following a symlink and must be yours) that
  is removed afterward, and `close_fds`, so a descriptor above 2 inherited from the caller does not reach it. Standard
  input reaches only `paid` and `paid-dryrun` (which ask the person a question); every other action gets `/dev/null`, and a
  closed 0, 1 or 2 is replaced by `/dev/null`. `--prompt-file` and the `keys propose` file are made absolute before the
  directory changes.

### What the startup refusal covers, and what it cannot (#267)

This is not a sandbox: the child runs as your user. Precisely:

- **Covered: the child.** It starts with `-I` and an allow-list environment, so nothing the caller set reaches the code
  that reads the config, the prompt or a key, and the caller's working directory, user site and `PYTHON*` variables
  cannot change what it imports.
- **Covered, as early as this program can: the refusal.** It is the first statement of the entry function in the `cli` module (any command line
  that has the word `gemini` among its arguments), before the hook clock, the guard entry or any parsing, and it is made
  again on the parsed command. A startup variable beside such a command line stops it with nothing else run.
- **Not covered: anything that acts before the first line of this program.** The installed `safo` console script starts
  a **plain** interpreter, so `sitecustomize` and `usercustomize`, `.pth` files, modules found through `PYTHONPATH` and the
  loader (`LD_PRELOAD`) have already run in the parent when the refusal happens. The refusal names the variable and stops
  the command; it cannot undo what already ran, and a caller who controls the process that starts `safo` is not stopped.
  Defense in depth only. The fix is a launcher that starts `python -I` before importing anything of ours; that follow-up
  is tracked in issue #267.

`tests/test_wrapper_isolation.py` runs a fake child that dumps its environment and import path under a hostile
environment.

## The key

The free key lives in the secret store, project `image-gen`, config `prd`; `gemini.yaml` holds **names only** (`secrets:
{project, free_config, key_name}`). At call time the wrapper runs `doppler secrets get <name> --plain --project <project>
--config <config>` (a fixed argument list of names, an absolute executable from PATH, no shell, stdin closed) and reads the
value from the pipe, so it is never on a command line, in a file, in the ledger or in a message; a value that is not one
plain printable run is refused without being repeated. **There is no paid key here:** the key provider reads the free key
and refuses any other tier before it runs the tool, and no setting names a paid config. The paid key is the broker's
credential and nothing else. Tests never need a key: they use a fake server and a fake key.

## The transport (the free tier)

One request, once. The key goes in the `x-goog-api-key` header to the host in `endpoint`, which the config loader accepts
only as `https://generativelanguage.googleapis.com` (or loopback `http`, for tests). The connection goes to a checked
address, no proxy from the environment is used, a **redirect is refused** and never followed (so the key cannot be carried to
another host), every answer is size-capped, and there are timeouts on connect and read. The broker has its own transport.

After the request leaves, a timeout, a closed connection, a 5xx (or 408), a redirect, an oversized or unreadable answer is
**unknown, not failed**: it is logged as ambiguous, the command exits 4, and the call is **not replayed**. A definite 4xx
other than 429 is reported once. There is no retry loop, so there is no backoff to bound. Retry-After on a 429 is shown
only when it is a finite number of seconds under a day.

## What the guard checks

The dispatch guard ([Hooks](hooks.md)) denies a brief that names a paid Gemini step (always: there is no approval record to
look up, see above), and a brief that names a step that sends anything without `gemini-material: public`, or with
something shaped like a secret, or a term from the maintainer's private terms, in it. These two rules, `gemini-paid` and
`gemini-material`, deny **even in warn mode**. The guard is a speed bump against an honest or prompt-injected model writing
a brief, not a sandbox. It reads a literal `safo gemini <action>` command (`ask`, `quota`, `approve`, `paid`,
`paid-dryrun`), a declaration line in the exact grammar, and a short list of named forms (the vendor host, the Google
genai SDK, the paid config name, decode-to-shell pipes, and `safo` run through a variable, function, `xargs`, `eval` or
`-c` when the brief also names Gemini and an action); the list is in [Hooks](hooks.md), and a way of building a command
that is not on it is not seen. A false positive is a block. The same rules also look at each Bash call: a shell command that names the vendor
host, its SDK, the key variable or the secret-store project and config names is denied (there is no exemption, the wrapper included; what it covers and does not is in
[Hooks](hooks.md#shell-commands-bash)). That check resolves nothing: names built from variables, decoded or read from a file or the environment, scripts the
command merely runs, a shadowed Python module defined outside the command, and an alias or function from a shell startup
file are not seen (a renamed or hijacked wrapper is covered only to the extent the protected names appear in the command text). The wrapper holds
the real gates. Raw SDK use inside a
program is out of its reach. When `agents.yaml` cannot be loaded the Gemini rules still apply to the brief. When
the event cannot be used, it is never judged from a prefix: an oversized event is read to the end (up to 8 MiB and a few
seconds) and checked whole for Gemini markers, a marker anywhere is denied, an event past the hard limit or that does not
finish in time is denied as too large or incomplete to check, and only a whole stream with no marker is the degraded
allow (details in [Hooks](hooks.md)). If another rule of the guard raises an error, the Gemini rules are run again on their
own, so a violation is still denied. A Gemini command built from variables is blocked by design: the guard reads literal
commands and models no shell. A Gemini-risk option (`--paid`, `--approval`, `--cap`) or the word `approve` on a line
whose command is an expansion is blocked even when no Gemini word is on the page, and here-document bodies are read
like any other line (they can be run by a shell), which can false-block shell examples inside a here-document. The gate
that holds is in the code: `ask` raises on a paid request before any request, and the only paid path is the broker, which
verifies a fresh signature for every call.

## What is not built or not verified

- Image generation is paid-only, and the free tier refuses a model listed under `image_models` in `gemini.yaml`; image
  requests are the broker's (`safo gemini paid --kind image`), documented on the broker page.
- Whether the vendor API reports remaining quota is unverified, so the local counter is the only meter and a 429 or the
  vendor dashboard is the authority when they disagree.
- Grounding with Google Search, Deep Research agents and batch are not used; they are billed differently and need their own
  design and approval.
- The vendor-side 25 USD automatic reload the maintainer described is a spend path this program cannot see. The broker's
  ceiling of 10 USD a month stays well under the vendor's own monthly limit, which is the backstop outside our code.


## Installing it

1. Copy `examples/gemini.example.yaml` to `~/.config/safo/gemini.yaml` (mode 600; this path is fixed) and replace the free-tier limits with
   the ones AI Studio shows. Point `ledger:` at the existing ledger if you keep one. That is all a free-only user needs:
   no paid key, no `/etc/safo`.
2. `safo gemini quota --model gemini-3.6-flash` prints the quota line and sends nothing. `safo gemini keys check` checks the
   enrolled keys.
3. For paid use, follow the broker's setup runbook ([Gemini broker](gemini-broker.md)), enroll at least two security keys
   by following [Gemini keys](gemini-keys.md), write `~/.config/safo/broker-client.yaml`, and test with
   `safo gemini paid-dryrun` (no call, no charge).
4. The agent entry, the shape and the board option are in `agents.yaml` and the board files. A live `agents.yaml` and a
   live project need the same additions by hand; `safo audit` reports the missing Agent option.
