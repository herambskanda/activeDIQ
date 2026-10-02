---
name: ia-task-paths-from-costed-catalogue
description: How to prove IA paths meet task-time budgets without drift, and a Tier-0 trap when writing privileged-group states
metadata:
  type: feedback
---

Compose every task path from a costed catalogue of IA elements (click, type, step-up, wait) in a script, and parse the budgets from `klm.py` with `ast` so the IA doc and the benchmark cannot drift. See `knowledge/product/design-system/information-architecture/ia-paths.py`.

**Why:** T-0009 needed 20/20 paths within the T-0008 budgets; a hand-counted table would have gone stale on the first benchmark edit.
**How to apply:** any IA or flow doc that claims "within budget" ships a checker that prints PASS/FAIL per task and the totals.

Before writing any privileged-group state, check TM-D2 and DM-35.I5: v1 never writes Tier 0 (Domain Admins and every C2 member). Do not design approval flows for adding to Domain Admins, and do not write "deleted by X" for native changes (DM-18.I3). T-0008 had these wrong; see [[me-demo-benchmarking]] and ticket T-0131.
