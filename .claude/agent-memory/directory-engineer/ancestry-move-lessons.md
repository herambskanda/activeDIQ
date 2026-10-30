---
name: ancestry-move-lessons
description: inventory ancestry rewrite / ancestry_complete (T-0948) — CTE FOR UPDATE trap, derive-not-trust, chain order
metadata:
  type: project
---

- `WITH old AS (SELECT … FOR UPDATE), ins AS (INSERT … ON CONFLICT DO UPDATE …)` loses `old` rows: FOR UPDATE skips a row the same statement updates, so "was it moved" read false. Read the old row without FOR UPDATE.
- `ancestry` is nearest parent first; descendant new chain = `d.ancestry[1:array_position(d.ancestry, moved)] || moved.ancestry`.
- `ancestry_complete` is derived in the upsert from the DB (NC head / parent = nc_guid / parent complete + chain match), never from the Observation. A partial chain stays incomplete until the child is observed again with the whole chain (check, not derive).
- Rewrite is by `ancestry @>` (scan until B3's GIN); completeness repair walks `parent_guid` (index 0059). Only run the rewrite for an existing row whose parent/chain changed, or initial syncs go O(n²).
- Test forests: build the parent row (`f.at`) before `f.subtree`, or the chains lack the upper hops.
- Fault injection for "fails part-way": an owner-created BEFORE UPDATE trigger that raises for one descendant guid (`d.ExecOwner`).
