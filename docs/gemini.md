# Gemini

> **Status.** The free research path is live: `quota`, `ask` without `--paid`, and `keys` need no root file and no key.
> The paid path is built but **disabled** by a root-owned switch file (`/etc/safo/gemini-paid-enabled`, which must say
> `enabled`; absent means disabled) until a state authority outside the maintainer's account exists to hold the spend
> and single-use state. While it is off, `ask --paid` and `approve` are refused with a message that says so, and the
> dispatch guard blocks any brief with a paid step. The approval machinery below stays in the tree, tested, for when the
> switch is turned on. Nothing on the command line, in the environment or in `gemini.yaml` can turn it on.

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
3. **Money needs its own signed approval.** See below. No valid signature by an enrolled security key, no paid call, and in
   the dispatch guard no record means a denial in every guard mode, `warn` included.

## Paid calls

**Disabled for now.** Everything in this section describes the path that runs only when the root-owned switch is on
(`/etc/safo/gemini-paid-enabled`, owned by root, not group- or other-writable, under root-owned directories, containing the
line `enabled`; it is read with the same ownership walk as the trust files). Without it, every paid call and every
`approve` is refused with "paid use is disabled" and the guard blocks paid steps. A `--dry-run` of `safo gemini approve`
still works, because it signs a throw-away text and spends and writes nothing.

Paid use is for what the free tier cannot do (image generation is paid-only: the free quota for image models is zero) or
what needs a model that has no free tier. Every monetary action needs a fresh, explicit, single-use **approval record**.

- **What a record is.** A **signature** made by the maintainer's hardware security key (a touch) over a canonical JSON
  text: the model, a maximum of at most 2 USD, a job name, a short expiry (10 minutes by default, never above 60, and it ends
  with the job),
  whether it passes the monthly ceiling, a one-time nonce, the quote of his message and its time, the signing principal
  (the label of the enrolled key) and the **ledger head** at signing time. It is made by `safo gemini approve`, which the
  lead runs **only after the maintainer has said yes in his own message**; the maintainer then reads the quota line and
  the quote and touches the key. The wrapper checks the signature with `ssh-keygen -Y verify` against **public keys only**
  (see "Who can approve"). A file with no signature, or in the older unsigned format, authorizes nothing. The quote is
  there so he can check afterwards what he approved, the same as the approval token in [Hooks](hooks.md).
- **Single use.** The call spends the nonce before the request leaves: an exclusive marker file **and** an
  `approval_used` row in the hash-chained ledger (which row records the principal and the tier). The ledger row is
  authoritative; the marker file is a second record, not the one that decides. A record is bound to its model and its job, so it
  cannot be inherited by a sub-agent or reused by a second job. A job can never start another job: each paid call needs
  a record of its own. A record also binds the ledger head: if the ledger it was signed against is no longer in the
  current chain, it is refused. Its own `approval_issued` row, written when it was signed, must also be in the chain
  **after** that head, so a ledger rewound to the signed head (which is still a member of the chain) has lost it and the
  approval is refused. What single use does and does not stop is spelled out under "Residual risk".
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
# the maintainer said yes in his own message; a person runs this at a terminal, quoting him exactly, then touches the key:
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

## Who can approve: signed approvals

`safo gemini approve` refuses unless standard input **and** standard output are a terminal. It prints the quota line and
the quote, tells the person that the key will blink and to touch it only after reading them, and asks them to type
`approve <job>` exactly. Only then does it call `ssh-keygen -Y sign -n safo-gemini-approval` with the key named in
`gemini.yaml` (`signing: {key: /absolute/path, principal: yubikey-a}`). The code never opens that file: it hands the
path to `ssh-keygen`, which asks the hardware key for the signature. With the global `--dry-run` flag, `safo gemini approve` runs the same
flow signs and verifies a throw-away text in another namespace (`safo-gemini-approval-dryrun`): it tests the key, the
enrollment and the touch, spends nothing, and writes no record and no ledger row.

The trust is two **maintainer-edited public files** at fixed locations, `/etc/safo/gemini-allowed-signers` and
`/etc/safo/gemini-revoked-signers`. The code requires each to be a regular file **owned by root**, not writable by group
or others, under directories that are root-owned and not writable by others, and it never writes to them. That is the
rule that stops an agent running as the maintainer from enrolling its own key: the agent's account cannot write there.
No flag, environment variable or `gemini.yaml` setting moves them or relaxes the rules; only a test, through the
`fixed_locations` function argument, can. Several keys can be enrolled, each under its own label; see
[Gemini keys](gemini-keys.md) for adding, rotating, backing up and revoking them. Only hardware keys (`ed25519-sk`,
`ecdsa-sk`) count, unless a key carries a written per-key opt-in; a key with `no-touch-required` is refused when the file
is loaded.

What `ssh-keygen -Y verify` does not say, the code reads from the public signature itself: the signer's key (so the
revocation list is consulted by key), the namespace, and for a hardware key the authenticator's flags: **user presence
must be set** (the touch), and **user verification (the PIN)** where the maintainer wrote `require-pin` for that key. Those
flags are part of what the key signs, so they are authentic once the signature verifies; they are only as honest as
the authenticator that reports them.

The config, the approval folder and the private-terms file are at **fixed locations** taken from the account database,
not from `$HOME`, an XDG variable, a flag or `SAFO_GEMINI_CONFIG`. The ledger location is a key in that fixed
config, and if the ledger is missing while another `gemini-spend-ledger.jsonl` sits in a sibling folder, every call is
refused instead of starting an empty ledger that reads 0 spent.

### Threat model (the approval and the ledger)

*Assets.* The paid Gemini key and the money it spends (a 2 USD job cap, a 10 USD month, a 30 USD vendor limit behind it);
the integrity of the spend ledger; the maintainer's trust file (which keys may approve).

*Actors.* The maintainer (holds the hardware key). A model or agent running as the same user, the maintainer's account (can run
commands, write that account's files, read its environment, and may be prompt-injected). A process on the same machine
as another user. Someone who steals a key. Someone who persuades the maintainer to touch.

*Trust boundaries.* The agent's account versus root (the trust files). The agent's account versus the hardware key (the
private half never leaves it; a signature needs a touch). The approval text versus the signed bytes (a signature covers
the canonical text, nothing else). The ledger file versus the signed head.

*Abuse cases, and what stops each.*

1. *The agent writes its own approval record.* A record without a valid signature by an enrolled key is refused (tests:
   unsigned, old format, edited payload, signature by an unenrolled key, wrong namespace, non-canonical text).
2. *The agent enrolls its own key.* It cannot write the root-owned trust file, and the code refuses a trust file the
   agent's account owns or can write (test: owner, group and world write, writable directory, symlink, missing file).
3. *Reusing an approval.* A nonce is single use and spent in the chained ledger; a signature is for one model, one job, at
   most 2 USD and a short expiry. These hold against a cooperating or confused caller and by the short signed expiry (see
   Residual risk).
4. *The month total.* The ledger is hash-chained (an edit, a removal or a reordering is found and named by line) and a
   signed approval binds the ledger head it was made against (tests). The state lives under the maintainer's account (see
   Residual risk).
5. *A key without a touch.* `no-touch-required` is refused at load; a hardware signature without the touch flag is
   refused; a software key is refused by default.
6. *A lost key.* Add it to the revocation list; a signature from it is refused even while it is still enrolled (test).
7. *The agent makes the key blink (confused deputy).* An agent can run `approve` or any `ssh-keygen -Y sign`, and the key
   will blink. The typed `approve <job>` on a real terminal and the quota line printed first are what tie a touch to a
   spend: **touch the key only after reading the quota line and the quote, and never for a prompt you did not start.**

*Residual risk, stated plainly.*

- **Social engineering of the touch.** A tired maintainer who touches a blinking key approves whatever was signed. The
  signed text is bounded (2 USD, one job, minutes) and the ledger names the principal, but the touch is a human decision.
- **Compromise of the signing step.** `approve` runs as the maintainer's account; code that replaces `ssh-keygen`,
  `safo` itself, or the terminal can show one quota line and sign another text. The verifier checks the signed text, not
  what was displayed. A hardware key with a display (not assumed here) would close this.
- **The key is still readable.** The paid API key lives in the secret store that the maintainer's account can read. An
  agent running as him could call the vendor directly, bypassing `safo` and this gate. The signed approval protects the
  wrapper path and the guard; the **vendor-side monthly limit** is the backstop for everything else.
- **The approval, ledger and spend state live under the maintainer's account.** Single use and the monthly total are
  therefore enforced against a cooperating or confused caller and by the short signed expiry (10 minutes by default,
  never above 60). They are **not** enforced against a hostile process running as that same account. For that reason
  paid use stays disabled by the root-owned switch until a state authority outside that account exists; the work is
  tracked in #205. What is in place: the nonce's `approval_used` row; the approval's own `approval_issued` row, which
  must follow the head it was signed against; the height record, kept apart from the ledger in the fixed state folder,
  which refuses a chain shorter than the longest one seen and names the recorded height; and the signed expiry. The
  vendor-side limits remain the backstop. When you archive or replace the ledger on purpose, remove its height record
  (the `heights` folder next to the approvals) too, or every call is refused.
- **Inputs to `ssh-keygen` are sealed.** The signature and the allowed-signers line it verifies against are held in
  sealed in-memory files (memfd, write, grow and shrink sealed) and reach it as `/dev/fd` paths, the message goes in on
  standard input, and when signing the message is on standard input and the signature comes back on standard output.
  The key `ssh-keygen` reports verifying must equal the enrolled key that was looked up. Where sealed memory is not
  available, nothing is verified. Linux only.
- **The chain is tamper-evident, not tamper-proof.** It shows an edit or a removal to a reader; it does not prevent one,
  and the quota line the maintainer reads at `approve` is computed from the file as it is. A cut-off tail is found only
  while the head file, the height record or a signed approval still remembers it. The same state-authority work (#205)
  applies.
- **Trust-file location.** `/etc/safo` must really be root-owned. The code checks ownership; it cannot prove that
  nobody holds root.
- **Software and agent-held keys** are weaker than a hardware key. They work only with a written opt-in, and `keys check`
  says so.
- **Assurance Tier 2 (passkeys) is not built.** See [Gemini keys](gemini-keys.md).

## The ledger

`gemini-spend-ledger.jsonl` lives outside git (default `~/.local/share/safo/`, or the path in `gemini.yaml`), is created
mode 600 and is **append-only and hash-chained**: the wrapper only appends, under a lock, and fsyncs. The first time it
writes, it appends a `chain_start` row that records the hash of the exact bytes of every older row; from then on each
row carries `prev_hash` and its own `hash`. The older rows are never edited. If anything after (or before) `chain_start`
is deleted, edited, reordered or cut off, every call refuses and names the line. A second copy of the newest hash sits in
a small head file beside it (the ledger name plus a head suffix) catches a truncated tail, and a **height record** kept
apart from the ledger, in the fixed state folder (`heights`, beside the approvals), remembers the longest chain this
wrapper has seen and refuses a shorter one, naming the recorded height; a signed approval also binds the head it was made
against. A call writes a `call_start` row (time, model, tier, estimated tokens and cost, job, approval) before the
request leaves and a `call_end` row after (status, HTTP status, usage, actual cost); `approval_issued` and
`approval_used` rows record the nonce, the signing principal and the tier. A start with no end, and an ambiguous end,
count their **estimate** as spent. Rows are **no longer added by hand** once the chain has started (that would break it):
use `safo gemini usage --amount-usd N --on-date YYYY-MM-DD --note "where the number came from"` for spend you read on the
vendor's billing page; it adds a chained `usage` row that counts toward the month. Any line the reader cannot parse stops
every call, because a counter that skips a line could undercount. A ledger that is a symlink or a pipe is refused. Tests
use a temporary ledger and never the real one. A row of an unknown type stops every call and is named by its record
number, rather than being ignored.

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
[Hooks](hooks.md), and a way of building a command that is not on it is not seen. A false positive is a block. The same rules also look at each Bash call: a shell command that names the vendor
host, its SDK, the key variable or the secret-store project and config names is denied unless it is the `safo gemini`
wrapper itself (there is no other exemption; what it covers and does not is in
[Hooks](hooks.md#shell-commands-bash)). That check resolves nothing: names built from variables, decoded or read from a file or the environment, scripts the
command merely runs, a shadowed Python module defined outside the command, and an alias or function from a shell startup
file are not seen (a function or alias of the wrapper's name defined in the command itself is denied). The wrapper holds
the real gates. Raw SDK use inside a
program is out of its reach. When `agents.yaml` cannot be loaded the Gemini rules still apply to the brief. When
the event cannot be used, it is never judged from a prefix: an oversized event is read to the end (up to 8 MiB and a few
seconds) and checked whole for Gemini markers, a marker anywhere is denied, an event past the hard limit or that does not
finish in time is denied as too large or incomplete to check, and only a whole stream with no marker is the degraded
allow (details in [Hooks](hooks.md)). If another rule of the guard raises an error, the Gemini rules are run again on their
own, so a violation is still denied. A Gemini command built from variables is blocked by design: the guard reads literal
commands and models no shell. A Gemini-risk option (`--paid`, `--approval`, `--cap`) or the word `approve` on a line
whose command is an expansion is blocked even when no Gemini word is on the page, and here-document bodies are read
like any other line (they can be run by a shell), which can false-block shell examples inside a here-document. The gates that hold are in the wrapper: a paid call
without a live, signed approval record raises before any request.

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
   the ones AI Studio shows. Point `ledger:` at the existing ledger if you keep one. That is all a free-only user needs:
   no key, no `/etc/safo`. Add the `signing:` block only when paid use is enabled.
2. Only when paid use is enabled: enroll at least two security keys by following [Gemini keys](gemini-keys.md) and create
   the switch file. Until then no paid call can be approved.
3. `safo gemini quota --model gemini-3.6-flash` prints the quota line and sends nothing. `safo gemini keys check` checks the
   enrolled keys. A dry run of `safo gemini approve` (the global `--dry-run` flag; the key guide has the full command)
   tests a key without spending.
4. The agent entry, the shape and the board option are in `agents.yaml` and the board files. A live `agents.yaml` and a
   live project need the same additions by hand; `safo audit` reports the missing Agent option.
