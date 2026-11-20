---
name: object-changes-lessons
description: T-1109 change history — recorded inside upsertObjectSQL, baseline rule, dataset anchoring, pre-existing red
metadata:
  type: project
---

- Changes are written by a data-modifying CTE (`chg`) inside `upsertObjectSQL` (objects.go), diffing `old` vs the params; param numbers are positional ($15 lockout, $22 observed, $25 state, $38 record, $39 noise) — recount if columns are added.
- No history until the connection has a row in `nc_sync_passes` with `last_pass_at` (first pass = baseline). Tests must call `e.pass(t, c, hDom, at)` between baseline and change.
- Dataset rows anchor on the object's CURRENT `directory_objects` row (RowAnchor `obj`), so deleted/moved-out objects vanish from scoped runs; snapshot name/dn live on the change row.
- Pre-existing red on main: tools/fitness api (reverifyStepUp policy), audit/keycustody (duplicate 0072/0073 migration numbers).
