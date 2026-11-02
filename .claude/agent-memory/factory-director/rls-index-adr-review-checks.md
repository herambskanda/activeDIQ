---
name: rls-index-adr-review-checks
description: Review checks for an ADR that adds an index/table under FORCE RLS — run the specified DDL, "no read" proofs must count removed rows, float bounds vs pg's float4 maths, migration backfill under FORCE
metadata:
  type: feedback
---

When an ADR specifies DDL (triggers, policies, indexes) under FORCE RLS, have the DDL actually run on PG16 and PG18 before ratifying. The prose can describe DDL that PostgreSQL refuses.

**Why:** T-1314 (ADR-0011 rev 3, 2026-11-02) read cleanly, but a security-architect consult that built the shape found two must-fixes. (1) The trigger "statement-level with transition tables, AFTER UPDATE OF key" cannot be created: PostgreSQL refuses transition tables on triggers with column lists or more than one event, and UPDATE OF key also missed key_kind changes. (2) The rule-16 proof "Actual Rows equal with tenant B full and empty" was unsound. RLS filters B's rows *below* the Actual Rows count, so a Seq Scan that reads both tenants still passes.

**How to apply:**
- Ask the consult to build the shape in throwaway containers as a non-superuser owner plus a runtime role. It finds more than reading does.
- Any "reads nothing of tenant B" proof must count rows examined: actual × loops + Rows Removed by Filter + Rows Removed by Index Recheck, and heap blocks.
- Migration backfill as the owner under FORCE silently sees 0 rows. The ticket must name the mechanism (the 0021/0047 NO FORCE window, or a per-tenant job) and assert the counts.
- A candidate bound restating pg_trgm's GIN rule (`ntrue/nkeys >= t`, float4) as `ceil(t*n)` in double tightens it at some thresholds (t=0.56, n=25 → 15 vs 14). Check it with python struct float4.
- A build ticket that edits a fitness tool must depend on the fitness ticket being *merged*, not just done (T-1126 was done but unmerged).

Related: [[search-adr-review-checks]], [[review-check-ceo-answers-vs-draft-time]]
