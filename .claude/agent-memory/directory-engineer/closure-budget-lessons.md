---
name: closure-budget-lessons
description: T-0961 closure fan-out budget — measure at the declared budget, statement timeout is 30 s, chunk by rows
metadata:
  type: project
---

A budget you declare must be measured AT that size, not only a scaled-down copy: the first version (chunking by group count) passed
scaled tests and then hit the store's 30 s `statement_timeout` on PG16 at 480k rows. Chunk INSERTs by estimated rows (`closureChunkRows`).

**Why:** security review found K x N closure growth; the fix was a per-group/per-connection row budget with `over_budget` marker rows.
**How to apply:** any derived-table refresh needs a size bound, a measured worst-case batch time (closure refresh at 480k rows: 14-16 s),
and tests that lower the budget through an `export_test.go` setter. A migration comment line without `--` breaks the whole migration (syntax error at the first word).
A 30k-user populate + 25 containers measurement costs ~4-5 min per PG version; run it in the background.
