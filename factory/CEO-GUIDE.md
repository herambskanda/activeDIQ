---
title: CEO Guide — running the activeDIQ factory
date: 2026-10-02
updated: 2026-10-02
status: review
owner: heramb
---

# CEO Guide — running the activeDIQ factory

One page. Everything else is the factory's job.

## Start and stop

```bash
cd ~/skenzeriq/activeDIQ
factory/bin/factory up        # starts the board and the dispatcher in the background
open http://127.0.0.1:4747    # the Factory Board
factory/bin/factory down      # stops both; running workers hand off cleanly
```

**Pause** (stop starting new work) and **Resume** are buttons on the board.

## Your daily loop (five minutes)

1. Open the board. The **Needs you** panel is the only thing you must look at.
2. Answer the decisions there. Each has 2–4 options, a recommendation, and a preview when taste
   is involved. Advisory decisions apply their default after 72 hours if you ignore them.
3. Glance at **Running now** and the milestone bar. Read the digest if you want the story.
4. When a milestone is demo-ready, watch the demo on the **Demos** tab, then press Love it / OK /
   Change it and say why. That is your acceptance.

## Talking to the factory

Run `claude` in this folder. You are talking to the **Factory Director**. Speak plainly —
"add bulk import from CSV", "the user list feels slow", "prepare a proposal for a partner" — and it
turns that into tickets, decisions or proposals, and tells you the ID.

| Command | Does |
| --- | --- |
| `/factory` | Status in six lines |
| `/decide` | Walks you through pending decisions in the terminal |
| `/demo` | Runs the latest milestone demo with you |
| `/ceo-feedback <text>` | Records feedback on whatever you were looking at |
| `/factory-up` · `/factory-down` | Start/stop from inside Claude |

## What you will and will not be asked

**Asked:** scope and ambition, brand and taste (UI, video, docs), pricing and partner commitments,
strategic forks, money/accounts/legal, anything leaving the building, demo acceptance.
**Never asked:** libraries, refactors, test strategy, ticket breakdowns, internal naming. The
factory decides those, logs them, and shows the notable ones as **notices** you can veto.

At most three questions are open at once. The factory learns your preferences from every answer,
so the same kind of question gets rarer.

## Safety rails you can rely on

- Opus thinks (medium/high), Sonnet builds (high/extra-high); the hardest problems escalate to
  Opus extra-high/max only through a logged ladder. No session exceeds a 300k-token working
  context — it hands off cleanly instead.
- Workers never push code anywhere, never commit secrets, never force anything; every code change
  is reviewed and QA'd before it is merged — locally.
- Nothing goes to a partner without your explicit yes.

## Where to look

| You want | Look at |
| --- | --- |
| What we are up against | `knowledge/business/strategy/executive-summary.md` (also in the board's Library) |
| How the factory works | `factory/OPERATING-MODEL.md` |
| Which agents are working right now, on which model, effort and context, and who is handing off to whom | the board's **Agents** tab (`http://127.0.0.1:4747/#agents`) |
| What we decided and why | `knowledge/memory/decisions-log.md` and the board's Decisions tab |
| What the factory knows about your taste | `knowledge/memory/ceo-preferences.md` |
