# safo-digest: run a command, keep the full output out of the lead's context

Issue #531, child of the token-savings epic #518. A lead session that reads 4,000 lines of `gh`, test or CI output
pays for every line on every later turn. `safo-digest` runs the command, saves all of its output to a private file and
prints a small digest. The lead reads the digest and opens the file only when it needs a line the digest left out.

```
safo-digest [--config FILE] [--timeout SECONDS] [--max-lines N] [--max-bytes N] -- CMD ARG...
```

Everything after `--` is the command, as an argument list. No shell is ever started, so `;`, `|`, `$(...)` and
globs are plain text. Standard input is closed. The command runs in its own process group; on a timeout, and again
when it ends, the whole group is killed, so nothing it started outlives the run.

## What is printed

One header line, then the body, and never more than `max_bytes` bytes in total (the cut is last, and marked `[cut]`):

```
safo-digest: cmd=pytest exit=1 lines=5120 bytes=412330 saved=~/.local/state/safo-digest/20261127T150014-...-pytest.log
-- first failures --
FAILED tests/test_x.py::test_boom - assert 1 == 2
-- output --
(head lines)
... 5050 lines omitted, see the saved file ...
(tail lines)
```

- The header carries the command name (never its arguments, which may hold tokens), the exit code, the line and byte
  counts and the saved path (`~` stands for your home).
- First failures (only when the exit code is not 0): the first lines that contain fail, failed, error, traceback,
  panic, fatal, exception or assert, a quarter of the line budget at most.
- Then the head and the tail of the output. Output short enough to fit is printed whole.
- Each line is cut to 200 characters. Escape sequences (colors, cursor moves, titles), control characters, bidi and
  other invisible format characters and the text before a carriage return (progress bars) are removed; bytes that are
  not UTF-8 show as U+FFFD. The saved file keeps every byte exactly as the command wrote it.

## Exit code

The command's own code (killed by a signal: 128 plus the signal number), except:

| code | meaning |
| ---- | ------- |
| 124  | timeout; the process group was killed; the header says `timeout=Ns` |
| 125  | refused or misused: not on the allow list, bad config, unsafe output directory, bad options. Nothing was run. |
| 127  | the executable was not found on an absolute `PATH` entry, or could not be started |

A command that itself exits 124, 125 or 127 cannot be told apart by the code alone; read the header line.

## Config

Default `~/.config/safo/digest.toml`, or `$SAFO_DIGEST_CONFIG`, or `--config`. It is never read from the current
directory. It is opened without following a symlink and must be a regular file of yours that is not group or world
writable, under 64 KiB. Unknown keys are an error.

```toml
out_dir = "/home/you/.local/state/safo-digest"   # absolute; default is this path under your home
allow = [                                        # required; a command runs only if its argv starts with a prefix
  ["gh", "pr", "checks"],
  ["gh", "run", "view"],
  ["/home/you/venv/bin/python", "-m", "pytest"],
]
max_lines = 40            # 3 to 1000, header included (default 40)
max_bytes = 4000          # 256 to 65536, whole digest (default 4000)
timeout = 300             # seconds, above 0 and up to 86400 (default 300)
max_file_bytes = 268435456  # saved-file cap (default 256 MiB); past it the rest is read and dropped, and the
                            # header says file-truncated
redact_words = ["MyEmployer"]   # extra words to replace with <redacted> in the digest
```

The allow list is explicit and has no default: an empty or missing list refuses everything. A bare command name is
looked up only on absolute `PATH` entries (an empty or relative entry cannot put a program from the current directory
first), and the resolved absolute path is what runs. The `--timeout`, `--max-lines` and `--max-bytes` flags override
the config for one call, inside the same bounds.

## The saved file

`out_dir` is created at mode 0700 if missing (parents too). Every component of the path is opened with
`O_NOFOLLOW`, so a symlink anywhere in it is refused; the final directory must be owned by you with no group or other
access, or the run is refused before the command starts. Each output file is created exclusively (`O_EXCL`,
`O_NOFOLLOW`) with mode 0600, named by UTC time, process id, a random token and the command name, so an existing file
or a planted symlink is never written through. Files are never deleted by this tool; prune the directory yourself.

## Redaction is best effort

The digest (the header and the lines shown) replaces: your user name, this machine's host name (and its short form),
your home directory (`~`), amateur radio callsigns (a pattern: one or two letters, or a digit and a letter, then a
digit, then two or three letters; `N0CALL` and `N0TST` are kept), six-character grid squares (`FN31pr` form), and the
words in `redact_words`, with `<user>`, `<host>`, `<callsign>`, `<grid>` and `<redacted>`. Names under three
characters are not replaced. It cannot find what it was not told, so it will miss an employer name, a token or a
private repository unless you list the word, and the pattern can hit lookalikes (`E2EE`). It does not look for
secrets. The saved file is NOT redacted: it holds whatever the command printed, so keep the directory private. The
command inherits your environment (`gh` needs its token); it is the allow list, not a filter, that keeps untrusted
commands out.

## Measuring

Per the epic, claim no saving without a measured row: run the same command bare and through `safo-digest` and compare
the bytes that reach the context (`wc -c` of the digest against the saved file's size, which the header prints as
`bytes=`), then add the row to the token-savings ledger.

Tests: `tests/test_digest.py` (real subprocesses: large output, binary bytes, escape sequences, a hung child with a
grandchild, non-zero exit, symlinks, permissions, allow list, redaction).
