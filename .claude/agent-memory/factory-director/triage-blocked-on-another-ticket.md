---
name: triage-blocked-on-another-ticket
description: Triage heuristic when a blocked ticket waits on another ticket. Unblocking returns it to in_progress, which skips depends_on gating.
metadata:
  type: feedback
---

**Done-not-merged blocker: `ticket unblock T-… --to-ready --by factory-director --note "…"` (T-1400).** It parks the ticket in `ready` with no stage role; the claim gate (T-1266) holds it until `factory/<blocker>` is on main, then the dispatcher claims it. Never leave such a ticket blocked or plain-unblock it.

When a blocked ticket waits for another ticket that is not yet done (for example T-0031 waiting on T-0127 in 2026-10), do not `ticket unblock` it yet.

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
- A "director merges this by hand" note on a done ticket is not a plan. Nothing picks it up until a ticket exists. On 2026-11-02, T-1296/T-1297/T-1266 sat done and unmerged with only that note, and the gate kept working in ID order. File a P0 director meta ticket to land them (T-1312) the same triage the fix is filed.
- Re-read each blocker's AC for IDs of cancelled tickets ("with T-1180 fixed" in T-1303 after T-1180 → T-1314/T-1335). Then note the real meaning on the blocker and add the replacement to its depends_on. When a sweep or benchmark ticket measures a plan, it depends on every open ticket that changes that plan, so it measures the final shape once (T-1303 → T-1335, T-1345, 2026-11-02).
- Read the merge-gate failure text, not just merge-base. `grep '"kind":"dispatcher"' factory/state/events/<day>.jsonl | grep merge` and `merge_gate` in dispatcher.json. On 2026-11-02 (T-1377) the train holding all four M1 deps failed with "baseline run on main timed out": the baseline is cached per full main sha, so each memory commit to main costs a fresh ~2 h `make -k ci` under load, after the head run. Fix: T-1378. Until it lands, batch director memory commits into one per session.
- At every triage of a done-unmerged block, list the done tickets in `merge_queue.waiting` that touch `factory/lib/premerge.mjs` or the dispatcher. T-1377 filed the gate fix T-1378 but no landing ticket, so at 21:07Z on 2026-11-02 four gate fixes (T-1378, T-0696, T-1336, T-1353) sat in the queue they fix. Land them all in one director meta ticket (T-1385).
