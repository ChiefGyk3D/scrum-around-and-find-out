# Changelog

## Unreleased

- Guard: a dedicated entry point, `safo-guard` (and `python -m safo.guard`), so the hook never parses subcommands
  (#189). It reads only `--agents` and `--agents-local`, ignores every other word, and always computes the verdict.
- `safo hooks install` writes the new hook command and migrates an existing `safo hooks guard` line on a rerun.
  `safo hooks status` reports the installed form (new, legacy, mixed, absent) and takes `--settings`.
- Lines `safo hooks guard ...` already installed keep the frozen legacy routing. Re-installing the live hook is a
  separate, explicit step after the release.
