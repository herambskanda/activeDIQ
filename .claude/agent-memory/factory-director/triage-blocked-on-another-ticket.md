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
- When every blocker is done, walk the data path the AC needs before unblocking. Grep for a production caller of each writer the path relies on. T-1077 (2026-11-01): the 503 was fixed, but inventory.Ingester had no caller and no sync module had ever been ticketed. Unblocking would have meant a real server with 0 rows. Instead, file a planning ticket (T-1188) and log a milestone-risk notice (D-0017).
- **`done` is not merged.** `claimBlockers` counts `done` as met, but the pre-merge gate merges one ticket at a time. After the overnight pause on 2026-11-02 there were 26 done-unmerged branches. Before you unblock a ticket because its blocker is done, run `git merge-base --is-ancestor factory/<blocker> main`. If the blocker is not on main yet, keep the ticket blocked and say so in its note (T-0765 waited on T-1245). The systemic fix is T-1266.
- Workers file follow-up bugs into backlog with no AC (T-1247, T-1248, T-1235 on 2026-11-01). Check for duplicates against done tickets first, then re-create the rest with AC as ready.
- When the blocker is done-unmerged, measure the merge queue, not just the one branch: last `Merge T-` on main and how many done branches are ahead. On 2026-11-02 (T-1295) 41 waited and nothing had merged for 26 h. A fix to the queue waits in that same queue, so its ticket must say how it gets merged (dry-run `factory premerge` plus a manual --no-ff merge, T-0975 precedent).
