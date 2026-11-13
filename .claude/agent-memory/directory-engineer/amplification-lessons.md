---
name: amplification-lessons
description: T-1528 TM-D32 gaps — PSO applies cap (migration 0077), ancestry rewrite budget, test runtime traps
metadata:
  type: project
---

- Over-budget PSO applies cannot be narrowed to the affected users (the dropped edges are unknown), so resInner answers Unknown for every eligible account of the PSO's NC. Marker is set from the directory's value count (`SetPSOAppliesRead`), never from history.
- Ancestry over budget: flag-only `ancestry_complete=false` UPDATE (`AND ancestry_complete` makes a repeat move write nothing); skip `repairCompleteness` or it walks what the budget refused.
- New enum reason in a dataset needs an `enumLabels` entry, or the registry fails with "invalid or duplicate value".
- resInner at 128-deep ring costs ~28 ms/user (5.6 s for 200 users): T-1073 is the real fix, not a depth cap.
- Inventory package test suite exceeds the 10 min default `go test` timeout when run with other packages: use `-timeout 60m` alone. The 10,000-edge dirty test takes ~50 s per PG version (one statement per edge).
