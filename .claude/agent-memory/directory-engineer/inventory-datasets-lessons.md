---
name: inventory-datasets-lessons
description: T-0958 inventory.users/computers lessons — test harness traps (pgx import ban, tenant role cannot DELETE, future as-of), RP11 per-dataset subtest shape
metadata:
  type: project
---

- Test packages under internal/directory may not import pgx (FF-SP1): a recording `store.Tx` wrapper is impossible. Use `reportsql.Query.Statement()` (added in T-0958) for compiled-SQL assertions.
- The tenant app role has no DELETE on inventory_* tables and the owner role sees no rows under FORCE RLS: simulate "row absent" with an edge to a PSO that has no `inventory_psos` row, or a second NC with no domain-policy row.
- `Populate` refuses an as-of > now+5m: seed with a base date in the past (hBase 2026-05-01, now = base+100d).
- RP11 binding is PerDataset: subtests must be `Test_dataset_reveals_nothing_outside_scope/<dataset id>` directly under the test; wrap `storetest.EachVersion` inside the subtest, not around it.
- A MaskAnchor `Identity` column is already NULL outside scope, so mutating the `{in_scope.pso}` guard in `policy_source` does not fail RP11 (defence in depth); the positive control (PSO in scope shows its name) is what proves the mask is not blanket.
- The filetime codec refuses stored maxPwdAge 0, so it stays "not read" (Unknown) even though AD treats 0 as never.
- Unrelated reds seen on the full run (not from T-0958): limiter burst on pg18, syslog apihost permission catalogue, agenthost closure allow-list, fitness/api A7 (encoding/json v1 in platform/report, node ajv).
- Reasons for Unknown (review fix): `<state>_reason` are Derived enum columns fed by the same resInner CTE row (`why` = status-2 cause); a missing domain row is `domain_policy_not_read`, not `pso_set_not_read`. Don't COALESCE `eligible` to false: NULL must fail closed to unresolved. RP8 hand-written `want8.why` + reference `derive` both carry reasons.
- RP11 DN rule (T-1063): in-scope objects keep real DNs naming sentinel parent OUs; `leaks(res, ownDN)` allows the sentinel only in the `dn` cell equal to the row's own DN; `checkNoLeaks` mutates a copy of the real result (extra column, copied dn, foreign dn) and requires leaks to catch it. B6 datasets must pass an ownDN map too.
- T-0961 (groups/closure): fresh bulk loads have NO planner statistics and the app role cannot ANALYZE (skipped silently). Closure refresh took 40 s and counts 8-14 s until `e.d.ExecOwner(ctx, "ANALYZE")` ran; then 6 s and 60-95 ms. Always ANALYZE as owner in scale tests, and read EXPLAIN (ANALYZE) via `tx.Query(...).Scan(&string)` in a scratch test before blaming the query.
- sqlconst/RP1 trip on helpers: `report.SQL(x)` inside a helper that takes `string` is rejected, and `tx.Query(ctx, sqlParam)` too. Helpers take `report.Fragment`; row scanners take `(rows, err)` so the call site stays `scan(tx.Query(ctx, `const`, ...))`. Check with `go build -o $SCRATCH/vettool ./tools/vettool && go vet -vettool=$SCRATCH/vettool ./internal/directory/inventory/` (`make fitness-safeprim` is red on main by an unused import under the lab tag).
- `group_members` has two own-object DN columns (group_dn, member_dn); RP11 uses `leaksWhere(res, allowed)` with a per-row allowance instead of `leaks(res, ownDN)`.
- Parallel branches collide on migration numbers: main renumbered 0061 notify -> 0062 while I held 0062; merge main early and `ls migrations`.

- Review T-0961 round 2: a depth cap must flag-and-continue, never fail Populate (a deep group chain would freeze the whole connection's sync = DoS). Mutation-check every predicate a count relies on (delete it, a test must go red); cycle edges must be asserted on `inventory.groups` counts, not only on `group_members` rows. Main takes migration numbers fast: re-check `ls migrations` after each merge.

- T-0961 security review: a DN is only unique per forest, so any DN-string join to another object must also match `connection_id` (and `state`). An RP11 world for that needs a second connection with `hStructure` populated, or the copy's `ancestry_complete` is false and it is never in scope (the test then passes vacuously: always mutation-check). New tables need `tablekind.Declare` (fitness-domain-keys REG) and, if a CHECK limits a text column, a `probeValues` entry in `store/exempt/registry.json` (fitness-tenancy T4). Docker was available this time: both fitness targets run locally (~3 min each); their remaining reds were main's (T-1089).
