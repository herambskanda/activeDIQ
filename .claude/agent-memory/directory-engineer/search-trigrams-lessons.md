---
name: search-trigrams-lessons
description: T-1335 trigram posting table — statement-trigger rules, plan-flip and cold-run traps in rows/blocks proofs, test-fixture traps, fitness rules
metadata:
  type: project
---

- **Statement triggers + transition tables**: one event per trigger, no column list; three triggers share one SECURITY INVOKER function with `SET search_path` and schema-qualified `show_trgm`. A migration line `-- after:` runs VACUUM outside the transaction (storetest/pgharness call `migrations.After`).
- **Backfill under FORCE RLS builds 0 rows silently** for the owner with no tenant set: use the 0021/0047 NO FORCE window and assert the count against `show_trgm` over the keys.
- **Rows/blocks proofs (AC5)**: (1) measure the SECOND run — the first in a session reads ~3 blocks more (cold metapage/catalog); (2) sum blocks over index-scan nodes only — the planner flips Bitmap Heap Scan ↔ Index Only Scan as the other tenants grow, +3 allowance on a form flip; (3) Heap Fetches count as rows: VACUUM twice AND retry while >0 (an autovacuum worker holds xmin back); (4) JSON `Actual Rows` is a rounded per-loop average before PG18, so test "the loop ran" with loops, not rows; (5) EXPLAIN JSON removed counts are per loop.
- **Table size steers the plan**: on a 2k-row directory_objects PG18 Seq Scans the hits join; add 20k filler rows (as SE5 does). At the default W=10000 PG18 hash-joins directory_objects whatever you do (T-1345). Plan/AC5 tests run W=100.
- **Fixtures**: `fillRange` names (40 syllables) repeat every ~1,600 objects — at 50k a typo query matches dozens of keys; the md5-translate `probeName` keeps matches at 2-4. Fitness-tenancy T5 bans `SET ...`/`set_config` text AND a pgx import in tests: use `storetest.Database.OwnerForTenant` (start-up parameter).
- **Fitness-search rules for the table** are in tools/fitness/search/trgmcheck.go (sync-function shape, tenant-led indexes, opclass dropped); the backfill INSERT is the only other place `show_trgm` is allowed.
- The T-1102 `probe_pg_test.go` was never committed; the AC6 probe is `Test_search_probe_50k` (opt-in `ACTIVEDIQ_SEARCH_PROBE=1`).
