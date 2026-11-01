---
name: closure-decision-lessons
description: T-0961 second security rework — budgeted derived data must be decided from the current graph, not from held state
metadata:
  type: project
---

A budget that admits only the *recomputed* groups into "budget minus held rows" is history-dependent: fill the budget first, then a
small privileged group loses its room. Decide over ALL live groups on every refresh (privileged RIDs first, then smallest estimate,
then GUID), evict held groups that no longer fit to a marker, expand left-out groups that now fit.

**Why:** security review proved Domain Admins could read "too large to list" the moment an attacker joined it.
**How to apply:** any "keep what's held, fit the rest" cache/budget needs a from-scratch oracle test after EVERY refresh
(`DecideClosure` in export_test.go vs stored markers). The decision's reads (live groups, nesting edges, link counts) are O(groups), not budgeted.

Third review: a "decide over all groups" step must itself be O(V+E) — building each group's reach set to estimate cost K x W (18.6 s, 9.3 GB at
16k attacker writes). Use a memoised upper bound over SCCs (iterative Tarjan, saturating); diamonds over-count and only turn a group Unknown.
Assert the work bound in a test (time + `runtime.MemStats.TotalAlloc`), not just log it. Tier-0 RIDs also include 521, 526, 527.
