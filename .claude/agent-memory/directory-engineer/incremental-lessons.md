---
name: incremental-lessons
description: T-1198 IncrementalCycle traps — Reconcile moves the fencing token, whole FeedCookie stored, deferFinish, dn gap in patch path
metadata:
  type: project
---

- `Reconcile` re-leases every partition and bumps the stored fencing token: re-take your own lease before the finish tx or it is ErrFenced.
- Store the whole marshalled `FeedCookie` (provider_kind, issuer, format version), not only provider_state.
- `readJob.deferFinish` leaves pass and cursor alone so establish can reconcile and then complete in one tx.
- `PassMarker` already exists in job.go; new ports are separate Engine fields because `memCursors` only implements `Cursors`.
- Two `each()` test envs have different tenant/connection ids: normalise dumps before comparing; pipe failing dumps through `cut -c1-300 | head`.
- T-0988 wired descendant dn rewrite only into Populate; the patch path (inventory/patch.go) leaves children's dn stale (T-2039).
- A `NeedsRead` batch writes RequireResync in the same tx instead of Advance: no crash window. No lab test yet (T-2041).
**Why/How to apply:** read before touching sync cycles or the finish transaction.
