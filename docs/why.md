# Why

One maintainer with evenings and weekends, a dozen repositories, and a team of AI agents: a Claude lead with Claude
subagents, OpenAI Codex, and GitHub Copilot's coding agent. Agents multiply output. Without a lead, review gates and one
place to see the work, they multiply unverified churn instead.

## The board is that one place

A GitHub Project is where the maintainer looks to answer three questions: what is being worked on, by whom (which agent),
and what is waiting on a person. That only works if the board is **complete** (every open issue and pull request of every
repository is on it), **current** (Done means closed or merged, with the date), and **cheap to keep that way** (nobody drags
cards).

## What safo is for

- **Board as code.** `board.yaml` names the fields, options, iterations and views. `safo bootstrap` creates what is missing
  and refuses to edit what exists, because the API call that edits options wipes every item's value.
- **An Action that keeps it current.** `sync` reacts to one issue or pull request event; `reconcile` repairs what an event
  missed, on a schedule; `audit` tells you when the live board and the file disagree.
- **A playbook.** Roles, routing, handoff and limits for a lead, its subagents and the other agents, each with a rule the
  [lessons](lessons.md) earned.

## What it will not do

It does not run agents. It does not host anything: the Action runs in your workflow with your App's key. It does not touch
fields it was not told about, and it never reopens a card.

## The shape of a good week

The maintainer decides and merges. The lead breaks work into cards, sets the Agent field, hands each task out with a brief,
and checks the result with a fresh reviewer. CI green is the bar for a merge; the board shows the rest.
