---
name: review-check-ceo-answers-vs-draft-time
description: ADR/spec review checks — CEO answers landed mid-draft, consistency with every answered D-id, RLS bypasses in tenancy fitness checks, customer-visible calls missing from the notice
metadata:
  type: feedback
---

When reviewing an ADR or spec, compare the claim/draft time on the ticket with `decision list --json` answer timestamps. A draft started before a CEO answer landed will cite the fork as "open" and miss the strongest constraint.

**Why:** On T-0002 (ADR-0001, 2026-10-02), the architect claimed at 02:18 UTC, but D-0002 (deployment) was answered at 02:23. The ADR called "Windows-only vs cross-platform" an open CEO fork and used it to argue against .NET, and the draft CEO notice repeated the stale framing. It took a reject round-trip to fix.

**How to apply:**
- On every ADR/spec review, grep the draft for "CEO fork", "ADR-0002" and "pre-empt", and check each against answered D-ids.
- Also check the fitness-function wording against the testing-playbook conventions; `//go:build` tags collided.
- Rewrite the ratification notice yourself; don't trust the author's draft notice framing.
- Check against **every** answered D-id, not only the ones the ticket lists. On T-0003 (ADR-0002), the ticket listed D-0002/D-0003. But D-0001 puts Entra in v1, and the per-profile credential column covered AD only.
- On tenancy ADRs, check that the RLS checks close these bypasses: unique *indexes* (they are not in pg_constraint), FKs (FK checks bypass RLS), matviews, and global tables read inside tenant transactions.
- A support-matrix row that closes an open research question (e.g. the minimum DC OS) is customer-visible and belongs in the notice list.
- On a rework, check that the new rules cost no parity. On T-0003, the reworked rule 9 added 'no Entra admin-role rights'. That cut ADM-168, which showed up only after grepping the parity matrix for the family. Put the cut in the notice, and note it on the plan ticket.
- On a rework, grep sibling docs still in flight for any identifier the rework renamed. ADR-0002's rework renamed WithTenant to WithTenantTx while safe-primitives was being aligned to the old name.

Related: [[adr-ratification-flow]]
