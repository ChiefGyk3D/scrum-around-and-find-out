# safo-threads

`safo-threads` lists the open review threads of a pull request and answers them from a file: a reply by REST, a
resolve by one GraphQL mutation per thread. It is a separate entry point (like `safo-ship`), not a `safo` subcommand,
so the dispatch guard's `TOP_LEVEL_COMMANDS` is untouched. It never reads or prints a token: `gh` holds the
credential.

## list

```
safo-threads list OWNER/NAME PR
```

Prints the unresolved, current threads grouped by file, one line per thread: the first comment's id, `file:line`, the
author and the first 200 characters of the body. Resolved and outdated threads are dropped. Whitespace in the body
becomes a space and every control or format character is written out as an escape through the output module, so a comment
cannot start a workflow command or move the cursor.

## apply

```
safo-threads apply OWNER/NAME PR DISPOSITIONS.json
```

The file is a JSON list; each row is exactly `comment_id` (the id `list` printed), `action` and, unless the action is
`skip`, `body` (a `skip` row must not have one):

```json
[
  {"comment_id": 1001, "action": "reply_resolve", "body": "Fixed in the next commit."},
  {"comment_id": 1002, "action": "reply", "body": "Keeping this on purpose; see the note in the docs."},
  {"comment_id": 1003, "action": "skip"}
]
```

- `reply` posts the body as a reply (`POST repos/OWNER/NAME/pulls/PR/comments/ID/replies`).
- `reply_resolve` posts the reply, then resolves that thread with one `resolveReviewThread` mutation.
- `skip` does nothing.

### What is refused, before any write

The file is read as bounded JSON (at most 256 KiB, a regular file only, no symlink, no FIFO; duplicate keys, `NaN` and
deep nesting refused). It is refused, exit 3, when it is not a non-empty list of at most 200 rows, a row has another key,
a `comment_id` is not a positive integer or is repeated, an `action` is unknown, a body is empty, over 2000
characters, holds a NUL or a lone surrogate, or is given on a `skip` row, or a `comment_id` is not an unresolved, current thread of that pull request (the same set `list` shows,
looked up with one GraphQL query of 50 threads a page, at most 20 pages). A bad row anywhere means nothing is written.

### After the first write

Writes run one at a time. The first failure stops the run and prints how many were done. A reply is never retried (a
POST of unknown outcome could double-post), and a thread is resolved only after its reply was accepted. If the reply
posted but the resolve did not (the answer must say `isResolved` is true), the error says so: resolve that thread by
hand or put it in a new file as `skip` later.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | done |
| 2 | usage: bad repository name or number |
| 3 | the dispositions file is refused; nothing was written |
| 4 | a read from GitHub failed, or `gh` is missing; nothing was written |
| 5 | a write failed; earlier writes in the run stand and are printed |

Each `gh` call has a 60 second timeout, stdin closed and no shell. The error line for a failed call carries the exit
code only, never `gh`'s own output, which can echo request text. Tests: `tests/test_threads.py`, against a fake `gh`.
