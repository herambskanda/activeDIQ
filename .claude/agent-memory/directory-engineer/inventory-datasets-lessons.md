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
