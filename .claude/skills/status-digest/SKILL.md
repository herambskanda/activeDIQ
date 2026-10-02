---
name: status-digest
description: Write the daily board digest (5 lines + factory/reports/digest-YYYY-MM-DD.md) and the weekly review from factory state — facts only, no invented progress. Use for digest meta tickets, /digest, or the weekly review.
---

# Status digest

The CEO reads the digest in ten seconds and decides whether to look closer. Every word is a
fact you can point to in the state. If something is not in the state, it did not happen.

## Gather facts — the only sources

```bash
factory/bin/factory digest --json                 # today's machine summary (primary source)
factory/bin/factory status --json
factory/bin/factory ticket list --status blocked --json
factory/bin/factory decision list --status pending --json
factory/bin/factory milestone list --json
```

Read the ticket notes only for items you will mention. Nothing goes in from memory, from earlier
conversation, or from what "should" have happened.

## Daily — the five lines

```
Shipped: T-0041 safe DN builder, T-0043 bulk-job contract (2 done today)
In progress: T-0044 bulk engine (review), T-0046 users screen (in progress, 2nd attempt)
At risk: M1 — T-0044 rejected twice in review (clone-and-adapt); escalated to principal-engineer
Needs you: D-0009 table density (advisory, defaults Sat 18:00) · A-0002 approve lab VM spend
Next: bulk create endpoints, lab E2E harness
```

- Exactly these five labels, in this order, one line each, ≤ 110 characters per line.
- IDs, then a few plain words. Counts where they help. No adjectives, no "great progress".
- An empty line says so: "Shipped: nothing today". Never pad or omit.
- **At risk** has a real reason: a ticket stuck or rejected twice, a blocker older than 24 h,
  a milestone behind its target, rate-limit backoffs, a cost spike, or a decision overdue
  against the work it blocks.
- **Needs you** lists every pending directional and advisory decision and open action item,
  oldest first, with the advisory default time. If there are none: "Needs you: nothing".

## Daily — the file

`factory/reports/digest-YYYY-MM-DD.md`, using knowledge-base frontmatter (`title date updated
status: accepted owner: project-manager`), then:

```markdown
# Digest — 2026-10-02

<the five lines>

## Shipped
- T-0041 Safe DN builder: <the ticket's two-line summary>.

## In progress
- T-0044 Bulk engine: review, attempt 2. <one line from the latest note>

## At risk
- <risk> · <evidence: ticket, note, date> · <mitigation under way or "director triaging">

## Needs the CEO
- D-0009 <title>: <kind>, blocks <tickets>, default <when>.

## Numbers
Runs today <n> / cap <cap> · tickets done <n> · ready <n> · blocked <n> · cost $<n>
```

Reference tickets by bare ID (`T-0041`). Keep each section short: the CEO opens the
file only to look closer.

## Weekly review

`factory/reports/weekly-YYYY-Www.md` (ISO week). Same rules, these sections:

1. **Milestone progress**: for each active milestone, done/total tickets, what is demo-able
   now, and the forecast against the target, with the reason.
2. **Shipped this week**: grouped by epic, with ticket IDs.
3. **Risks**: the risk register, each with an owner and a mitigation. Cover new, changed and
   closed risks.
4. **Decided on your behalf**: every `notice` this week, its ADR link, and whether it was
   acknowledged or vetoed.
5. **CEO decisions**: answered and pending, and how each answer was applied.
6. **Next week**: the 3–5 outcomes planned, and the tickets behind them.
7. **Factory health**: runs, cost, escalations, rejects per stage, rate-limit backoffs.

The board line for the weekly review is five lines in the same shape as the daily one, with
"this week" in place of "today".

## Finish

Commit the report file by path (`docs(reports): digest 2026-10-02 (T-…)`), then advance the
digest ticket with the five lines as the note.
