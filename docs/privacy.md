# Privacy check

`tests/test_privacy.py` scans everything public (`docs/`, `examples/`, `README.md` and `agents.yaml`) for what must
never be published: private and link-local addresses, MAC addresses, hostnames, machine serials, home-directory paths, file URLs, e-mail addresses,
callsign-shaped tokens and grid squares. The placeholders `N0CALL`, `N0TST` and `FN31pr` are allowed. CI runs these
generic patterns.

## Your own terms

Some terms cannot be written into a public repository at all, even as a pattern: an employer's name, a callsign, a grid
square, real hostnames, serial numbers. Keep them in a file **outside** the repository, one regular expression per line
(blank lines and lines starting with `#` are ignored), and point the test at it:

```bash
install -m 600 /dev/null ~/.config/safo/privacy-terms.txt   # then edit it
SAFO_PRIVACY_EXTRA_FILE=$HOME/.config/safo/privacy-terms.txt make check; echo "exit=$?"
```

The test applies your terms to the same files. A failure prints the file, the line and the category only, never the
matched text, so a log or a pasted failure does not repeat the term.

## Before publishing the generated profile files

`examples/harness/` holds files generated from the profiles in `agents.yaml` ([Agent profiles](profiles.md)). The generic
patterns catch a home path or an e-mail address in them. They cannot catch a private handle, an employer term or a
single-label internal hostname, so a release that publishes `examples/harness/` runs `SAFO_PRIVACY_EXTRA_FILE=... make
check` first, or an equivalent scan backed by a secret. Generated examples use placeholders only (`example.com`, `N0CALL`).

## Keeping the file out of Git

- The test refuses a file inside the repository and stops with an error.
- `.gitignore` excludes `privacy-terms*` and `*.privacy-terms` in case one is copied in anyway.
- Keep the file mode at `600`, and do not put it in a dotfiles repository, a backup you publish, or a CI secret.
- CI cannot run your terms (that would mean putting them in a secret). The check with your terms is a local one: run it
  before you push.
