---
name: triage-blocked-on-another-ticket
description: Triage heuristic when a blocked ticket waits on another ticket. Unblocking returns it to in_progress, which skips depends_on gating.
metadata:
  type: feedback
---

When a blocked ticket only waits for another ticket to finish (for example T-0031 waiting on T-0127 in 2026-10), do not `ticket unblock` it yet.

**Why:** `unblockTicket` puts the ticket back in its `blocked_from` stage, usually in_progress. `claimBlockers` only gates the ready → in_progress claim, so the dispatcher would relaunch the owner straight away, they would hit the same wall and block again.

**How to apply:**
- Run `ticket set <blocked> depends_on=<blocker>` so the link shows on the board.
- Raise the blocker's priority if it is small and the queue ahead of it is long.
- Make sure the blocker's AC says it unblocks the waiting ticket.
- Leave a note on both tickets.

Re-triage is throttled by `triaged_at` and `blocked_retriage_hours`, so leaving the ticket blocked does not cause triage spam.
- Walk the whole chain down to its root. A blocker sitting in backlog never runs (T-1077 → T-1044/T-0987 → T-0916, 2026-11-01), so ready every link and raise the root's priority.
- `ticket ready` refuses a ticket with no acceptance criteria, and no CLI command adds AC later. Cancel it and re-create it with `--ac` (T-1044 → T-1151), then point the waiting ticket's depends_on at the new ID.
