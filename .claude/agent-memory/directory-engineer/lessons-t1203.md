---
name: t1203-schema-lessons
description: T-1203 — DefaultSchema sync-list coverage, unmerged dependency handling, lab-up failure mode
metadata:
  type: project
---

- Test for "closed list ⊆ DefaultSchema" lives in `internal/connector/ad/schema_sync_test.go` and uses `newOffline().checkAttrs(names,false)` — no lab needed.
- New DefaultSchema entries are name-only (no OID) when the OID isn't verifiable in-repo; an OID-form descriptor then fails closed (same as dNSHostName).
- T-1189 was done-but-unmerged (merge queue stall); I merged `factory/T-1189` into the branch (additive, 4 commits) instead of blocking.
- `make lab-up` can fail with "all predefined address pools have been fully subnetted" when exited per-worktree labs pile up; pruning them is devops' call, not mine.
