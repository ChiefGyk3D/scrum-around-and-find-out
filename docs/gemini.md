# Gemini

Gemini is a **free-only** research provider for **public material**. It is in [the roster](routing.md) as the agent
`gemini`, and the shape `public-source-research` prefers it. This page is what the code does, what it cannot do, and what
the maintainer has to supply. Decisions are in issues #195 (the spend gate), #196 (the provider) and #200 (this build).

## Why free-only, and what never goes to it

The vendor's terms say that prompts sent through the free tier may be **used for training** and **read by human
reviewers**, and tell you not to submit sensitive, confidential or personal information. So nothing private ever goes to
Gemini: no repository-private data, no secrets, no personal data, no callsign or grid square, no employer details, no
unfixed vulnerability detail. The work is OSINT-style gathering of **public sources**, authorized and defensive only, about
organizations, public infrastructure, CVEs, vendors and public documents; never about a private individual. Adversarial and
exploit work stays on the cyber-program tiers. Text work the local LLM can do stays local-first. Every claim Gemini cites is
checked at its source URL before anyone relies on it.

## The three gates, all in code

A model never counts, caps or approves anything here.

1. **The free tier follows your own limits.** `safo gemini ask` counts requests per minute, input tokens per minute and
   requests per day from the ledger, per model. The day ends at **midnight Pacific**, where the vendor resets it. The
   per-model numbers are shown in AI Studio and nowhere else, so they are values in `gemini.yaml` that you supply; the
   example file ships deliberately tiny ones. A model with no limits configured gets no quota line and no call. The ledger
   is only our own count (other users of the same project are invisible to it), so the vendor's answer is the authority.
2. **A 429 is final.** On HTTP 429 (`RESOURCE_EXHAUSTED`) the job stops and reports the quota line, exit code 3. Nothing is
   retried and a free call **never falls through to paid**: the paid key is not even read.
3. **Money needs its own approval record.** See below. No record, no paid call, and in the dispatch guard no record means
   a denial in every guard mode, `warn` included.

## Paid calls

Paid use is for what the free tier cannot do (image generation is paid-only: the free quota for image models is zero) or
what needs a model that has no free tier. Every monetary action needs a fresh, explicit, single-use **approval record**.

- **What a record is.** A file with a quote of the maintainer's message, the time of that message, the model, a maximum
  amount of at most 2 USD, a job name, an expiry (at most 24 hours, and it ends with the job) and whether it may pass the
  monthly ceiling. It is created by `safo gemini approve`, which the lead runs **only after the maintainer has said yes in
  his own message**. A record is evidence of what was said, not proof that it was said: the quote is there so he can check
  it afterwards, the same as the approval token in [Hooks](hooks.md).
- **Single use.** The call spends the record before the request leaves (an exclusive marker file), so a crash or a timeout
  cannot allow a replay. It is bound to its model and its job, so it cannot be inherited by a sub-agent or reused by a
  second job. A job can never start another job: each paid call needs a record of its own.
- **Caps.** At most **2 USD per job** and **10 USD per month**. The estimate is an upper bound (the prompt counted at three
  bytes a token, plus every output token the request allows) and must fit the job cap and the approved amount. Past 10 USD
  in a month, each further 2 USD block needs its own record that says so; `approve` sets that flag from the ledger in
  code (it is not an option), shows it to the person approving, and the call is refused without it. The month is the UTC calendar month; whether that matches the vendor's billing cycle is unverified.
- **The quota line comes first.** `safo gemini approve` prints it before it writes anything, and refuses to approve if it
  cannot produce it. Free: model, used X of Y per minute, per day and input tokens, the window and the reset. Paid: spent A
  of the 10 USD ceiling, this job's estimate C of the 2 USD cap, the running total after the job, and `beyond ceiling: YES`
  once past it.
- **Estimates and actuals.** Prices come from a table in `gemini.yaml` with the date it was read (`price_checked`, and
  `valid_through` per model). The table was last read against the vendor page on 2026-10-29 (the page itself says it was
  updated 2026-10-28); re-read it before you rely on it, because several prices change on 2026-12-31. A paid estimate from a
  table past its `valid_through` is refused. After each call the actual usage and cost are logged. A paid answer is never recorded cheaper than the sizes of what
  was sent and received allow: counts below a floor from those sizes (including zero) are replaced by the estimate. Output tokens include
  thinking tokens, as the vendor bills them.

```bash
# the maintainer said yes in his own message; a person runs this at a terminal, quoting him exactly (see "Who can approve"):
safo gemini approve --model gemini-3.6-flash --prompt-file prompt.txt --max-output-tokens 1000 \
  --max-usd 1.50 --job research-1 --quote "yes, up to 1.50 on this" --quoted-at 2026-10-29T15:00:00Z --issue owner/repo#200
safo gemini ask --model gemini-3.6-flash --paid --job research-1 --approval <id printed above> \
  --prompt-file prompt.txt --max-output-tokens 1000 --material public
```

A subagent brief names the step so the guard can see it (see [Hooks](hooks.md)):

```text
gemini: paid model=gemini-3.6-flash cap=1.50 approval=<id>
gemini-material: public
```

## Who can approve, and the residual

`safo gemini approve` refuses unless standard input **and** standard output are a terminal. It prints the quota line and
the quote, and writes the record only after the person types `approve <job>` exactly. The ceiling flag is not an option;
it is derived from the ledger. The config, the approval folder and the private-terms file are at **fixed locations** taken
from the account database, not from `$HOME`, an XDG variable, a flag or `SAFO_GEMINI_CONFIG`; tests move them only through
a function argument no command line can reach. The ledger's own location is a key in that fixed config, and if the ledger is
missing while another `gemini-spend-ledger.jsonl` sits in a sibling folder, every call is refused instead of starting an
empty ledger that reads 0 spent.

Be plain about what the terminal check is worth. It only stops accidents and a prompt-injected command line that has no
pseudo-terminal; `script -qec` or any pty gives a process one, and it passes. It is not a barrier against the same user:
a process running as the maintainer can write a record file directly, edit the config, or **delete or move the ledger,
which resets the month total to 0** (only the sibling-ledger refusal catches a leftover copy). The approval is evidence of
the maintainer's word, not proof of it. Real protection needs a channel the agent's UID cannot write: a separate account
or a root-owned record store that only a human-run tool can add to, or a signed approval token checked by a service the
agent cannot reach. That costs a second account or a small service and an install step, and it is not built here. Until it
is, the backstop outside this code is the vendor-side monthly limit and the automatic-reload settings on the paid account,
which no process here can change.

## The ledger

`gemini-spend-ledger.jsonl` lives outside git (default `~/.local/share/safo/`, or the path in `gemini.yaml`), is created
mode 600 and is **append-only**: the wrapper only appends, under a lock, and fsyncs. A call writes a `call_start` row (time,
model, tier, estimated tokens and cost, job, approval) before the request leaves and a `call_end` row after (status, HTTP
status, usage, actual cost). A start with no end, and an ambiguous end, count their **estimate** as spent. The maintainer
may add `{"type": "usage", "date": "YYYY-MM-DD", "amount_usd": N}` rows by hand, for example from the vendor's own
billing page; they count toward the month. Any line the reader cannot parse stops every call, because a counter that skips
a line could undercount. A ledger that is a symlink or a pipe is refused. Tests use a temporary ledger and never the real one. A row of an unknown type (a misspelled `usage`, say) stops every call
and is named by its record number, rather than being ignored.

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

## The key

Keys live in Doppler project `image-gen`: config `prd` is the free key, config `prd_paid` the paid one. `gemini.yaml` holds
**names only**. At call time the wrapper runs `doppler secrets get <name> --plain --project <project> --config <config>`
(a fixed argument list of names, an absolute executable from PATH, no shell, stdin closed) and reads the value from the pipe,
so it is never on a command line, in a file, in the ledger or in a message; a value that is not one plain printable run is
refused without being repeated. The paid key is read only after every paid gate has passed. Tests never need a key: they use
a fake server and a fake key.

## The transport

One request, once. The key goes in the `x-goog-api-key` header to the host in `endpoint`, which the config loader accepts
only as `https://generativelanguage.googleapis.com` (or loopback `http`, for tests). The connection goes to a checked
address, no proxy from the environment is used, a **redirect is refused** and never followed (so the key cannot be carried to
another host), every answer is size-capped, and there are timeouts on connect and read.

After the request leaves, a timeout, a closed connection, a 5xx (or 408), a redirect, an oversized or unreadable answer is
**unknown, not failed**: it is logged as ambiguous, a paid one counts its estimate as spent, the command exits 4, and the
call is **not replayed**. A definite 4xx other than 429 is reported once. There is no retry loop, so there is no backoff to
bound. Retry-After on a 429 is shown only when it is a finite number of seconds under a day.

## What the guard checks

The dispatch guard ([Hooks](hooks.md)) denies a brief that names a paid Gemini step with no live approval record or no cap
of at most 2 USD, and a brief that names a step that sends anything without `gemini-material: public`, or with something
shaped like a secret, or a term from the maintainer's private terms, in it. These two rules, `gemini-paid` and
`gemini-material`, deny **even in warn mode**. The guard is a speed bump against an honest or prompt-injected model writing
a brief, not a sandbox. It reads a literal `safo gemini <action>` command, a declaration line in the exact grammar, and a
short list of named forms (the vendor host, the Google genai SDK, the paid config name, decode-to-shell pipes, and `safo`
run through a variable, function, `xargs`, `eval` or `-c` when the brief also names Gemini and an action); the list is in
[Hooks](hooks.md), and a way of building a command that is not on it is not seen. A false positive is a block. Raw SDK use
outside a brief is out of its reach, and **above 1 MiB the whole hook fails open** with a degraded notice, the Gemini rules
included (changing the hook's core to read further was left alone). The gates that hold are in the wrapper: a paid call
without a live approval record raises before any request.

## What is not built or not verified

- Image generation is paid-only, and the wrapper refuses it on the free tier, but **no image request is built**: the
  request shape for the image models is unverified here. Only text generation is sent.
- Whether the vendor API reports remaining quota is unverified, so the local counter is the only meter and a 429 or the
  vendor dashboard is the authority when they disagree.
- Grounding with Google Search, Deep Research agents and batch are not used; they are billed differently and need their own
  design and approval.
- The vendor-side 25 USD automatic reload the maintainer described is a spend path this gate cannot see. The internal
  ceiling of 10 USD a month stays well under the vendor's own monthly limit, which is the backstop outside our code.

## Installing it

1. Copy `examples/gemini.example.yaml` to `~/.config/safo/gemini.yaml` (mode 600; this path is fixed) and replace the free-tier limits with
   the ones AI Studio shows. Point `ledger:` at the existing ledger if you keep one.
2. `safo gemini quota --model gemini-3.6-flash` prints the quota line and sends nothing.
3. The agent entry, the shape and the board option are in `agents.yaml` and the board files. A live `agents.yaml` and a
   live project need the same additions by hand; `safo audit` reports the missing Agent option.
