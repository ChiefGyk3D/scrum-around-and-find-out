# Boards

Project boards for the SIEM group and the whole portfolio, defined as code. Each file is one GitHub Project (v2) owned by the maintainer's user account. No GitHub App can write a user-owned project, so these are kept current from the maintainer's own `gh` login, not from CI.

| File | Project | What it tracks |
|---|---|---|
| `siem-stack.board.yaml` | SIEM Stack | `pfsense-siem-stack`, `siem-docker-stack`, `jumpcloud-wazuh-bridge`, `mother-ticker`, `netpulse` |
| `siem-and-cah.board.yaml` | SIEM and CAH | the five above plus `Clouds-Against-Humanity` |
| `all-projects.board.yaml` | All Projects | every tracked repository, grouped by project, for scanning |

Run from a directory that does not contain your `gh` binary (see issue 41):

```bash
safo --board boards/siem-stack.board.yaml validate                      # offline check
safo --board boards/siem-stack.board.yaml --gh-user YOUR_LOGIN reconcile # add missing cards
safo --board boards/siem-stack.board.yaml --gh-user YOUR_LOGIN audit     # compare live board and file
```

`bootstrap` cannot rewrite the built-in Status field on a populated board. On a new, empty project the Status options can be set once through the API; the bootstrap output lists the other settings no API can set (view grouping, roadmap date fields, project workflows).

Design: `docs/superpowers/specs/2026-10-22-siem-wiki-and-boards-design.md`, section 11.
