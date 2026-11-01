---
name: search-index-lessons
description: T-1095 search index — pg_trgm under RLS, fuzzy threshold, bind-typing traps, test fixtures for FORCE RLS tables
metadata:
  type: project
---

- pg_trgm `%`, `<%`, `%>` are NOT leakproof: on a FORCE-RLS table the planner never uses the trigram GIN for the app role (proved: owner with RLS disabled uses it). Fuzzy probe = filtered scan of the tenant's rows (~0.45 s / 195k). T-1180 decides the fix; `Test_search_plan_uses_the_indexes` pins it. `enable_seqscan=off` does not help.
- 'Pryia Ramn' vs 'Priya Raman' word_similarity = 0.333, so ADR threshold 0.5 finds nothing; 0.3 used (nearest unrelated 0.294). A transposition costs ~4 trigrams.
- Cyrillic, Greek, CJK, diacritic Latin all match under pg_trgm on the bundled pg16/pg18 images (C.UTF-8).
- Unused bound params fail with "could not determine data type of parameter $n" (42P18): bind lazily (W+1 is bound only when a probe uses it). `$1 = ''` then `$1::uuid` also fails: cast `$1::text` first.
- FORCE RLS applies to the owner too: `ExecOwner("DELETE ...")` on a tenant table removes nothing. Use `e.exec(e.a, ...)` (tenant tx). The app role has DELETE on inventory_search_keys.
- fitness-tenancy T5: no `set_config` text and no pgx import outside internal/platform/store (tests included). Settings go in reportsql; test EXPLAIN uses default exec mode; owner conn uses `SET app.tenant_id = '<uuid>'`.
- `cases.Fold` upper-cases Cherokee: NormName ends with strings.ToLower (ADR deviation) for idempotence.
- Ranking `nm` is lower(display_name) COLLATE "C", not the normalised key (deviation: avoids a per-hit key lookup).
- Map iteration order leaked into SQL text (fuzzy kind list): always iterate searchkey.AllKinds.
- Test helper names taken in package inventory_test: oid, guids, pop, rpID, hGUID, hUser, explain/catalog now mine.
- Pre-existing red on main at 398b0e6c1 (not T-1095): RP1 vet in datasets_groups.go:146,148 (viaPathSQL/findingSQL); TestOnlyPermittedFilesImportTenantref (modules/reports/handlers.go).
- Plan-shape tests: the planner's natural pick depends on LIMIT and flat `<%` estimates; prove index *eligibility* in a rolled-back owner txn (drop other indexes + pkey constraint, disable RLS), not by hoping.
- Names are PREFIX-class keys (with a "whole" rank bonus); only identifiers (sam/upn/guid/…) are EXACT. Write oracle queries accordingly.
- Plan-shape tests need realistic table sizes: on a ~100-row key table the planner picks Seq/Bitmap scans. Add ~20k filler directory_objects + keys, ANALYZE, then assert (Bitmap child nodes have no Relation Name; count on Index Scan nodes by CTE via "Subplan Name").
- SE3/SE5 live in search_scope_test.go / search_bounded_test.go (ticket-assigned, not T-1126). Hidden rows of a SHARED name also count in the fuzzy class, so equality-at-W-10 queries must not fuzzy-match the hidden keys more than W.
- Prefix probes carry ORDER BY k.key LIMIT W+1 so the ordered index range scan is the cheapest plan on any table size.
- Security F1: W (ceiling) is Searcher-construction config (`inventory.WithCeiling`, validated 1..MaxSearchCeiling), never a SearchRequest field: a per-request W lets a scoped caller spell hidden names via refine on/off. Tests needing small W build a second Searcher (`e.searcherW`).
- fitness-reports RP7 'lock-entry-removed' goes red when main has moved ahead of the branch (not the diff); judge it against `git diff main...HEAD`.
