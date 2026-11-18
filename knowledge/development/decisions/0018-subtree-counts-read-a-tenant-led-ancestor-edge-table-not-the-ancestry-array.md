---
title: "ADR-0018: Subtree counts read a tenant-led ancestor edge table (inventory_ancestors), not the ancestry array"
date: 2026-11-18
updated: 2026-11-18
status: proposed
owner: heramb
author: solution-architect
kind: technical
ticket: T-2293
fitness: fitness-inventory AN1–AN4 (to be built by the follow-up tickets); not in CI, so not `accepted`
---

# ADR-0018: Subtree counts read a tenant-led ancestor edge table, not the ancestry array

**Status:** proposed. Needs security-architect's review of the guard and RLS impact (T-2293 asks for
it), then factory-director's ratification. `accepted` when AN1–AN4 run green in `make ci`.
**Kind:** technical · **Ticket:** T-2293 (found by T-2026, same mechanism as T-1335 / ADR-0011 rule 5a)

## Context

`ou-01` ("Organizational units", dataset `inventory.ous`) shows five subtree counts per OU. Each is a
correlated subselect, `datasets_groups.go` `subtreeCount`:
`SELECT count(*) FROM {rel.sub} WHERE sub.connection_id = {t}.connection_id AND sub.ancestry @> ARRAY[{t}.object_guid] AND sub.state = 'live'`.

T-2026 measured, at 25k objects with `ADIQ_SCALE_FULL=1`: `ou-01/all` 8.8 s, `/empty` 16.1 s, `/bound`
about 20 s against a 20 s bound. The plan is 101 OUs x 5-6 SubPlans, each a Seq Scan of
`directory_objects`. The GIN `directory_objects_by_ancestry` (0061) is never used: array `@>` is not
leakproof, `directory_objects` is FORCE RLS, so the planner will not push the operator below the
policy qual (lessons 2026-11-02, T-1102/T-1335). T-2026 confirmed it with `enable_seqscan=off`: still
a tenant-only bitmap scan. So "add an index" is not available; the shape of the data or of the SQL
has to change.

Constraints that bind any answer:

- Scope trimming (ADR-0011 / reports contract §3.3) happens on `{rel.sub}`, a `FilterAnchor` over
  `directory_objects`. A count must count only descendants the caller may read, so every counted
  object still has to pass through the scoped anchor. Any answer that counts without that join is
  a scope leak (an OU name next to a count of objects the caller cannot see).
- The `fragCheck` allowlist (`reportsql/fragcheck.go`) is the guard that stops a dataset fragment
  reading an unscoped table. Widening it is a reviewed change plus a test.
- `ancestry` is nearest-parent-first, capped at 128 entries (0033 CHECK); a chain that would
  exceed it is stored as `'{}'` with `ancestry_complete = false`, which is "unknown, out of scope".
  `rewriteDescendants` (`objects.go`) updates it for a moved OU. Tombstoned rows keep their last
  ancestry; the count filters `state = 'live'`.

## Options considered

### A. Edge table `inventory_ancestors`, maintained by statement-level triggers, read as a `RelEdge`

`inventory_ancestors (tenant_id, connection_id, ancestor_guid, object_guid)`, primary key
`(tenant_id, connection_id, ancestor_guid, object_guid)`, FORCE RLS on `tenant_id` exactly as
`inventory_search_trigrams` (0074). One row per (object, element of its `ancestry`). Triggers on
`directory_objects` (AFTER INSERT, DELETE, UPDATE with transition tables; three triggers, because
PostgreSQL refuses transition tables on a multi-event trigger) keep it equal to the array for every
writer. The dataset declares it as `Rel{ID: "anc", Kind: RelEdge, Table: "inventory_ancestors",
Project: idents("connection_id", "ancestor_guid", "object_guid")}` and the count becomes
`SELECT count(*) FROM {rel.anc} JOIN {rel.sub} ON sub.object_guid = anc.object_guid AND sub.connection_id = anc.connection_id WHERE anc.ancestor_guid = {t}.object_guid AND anc.connection_id = {t}.connection_id AND sub.state = 'live' AND sub.kind ...`.

- **Plan.** The probe is `tenant_id = policy qual` (always usable) plus equality on
  `connection_id, ancestor_guid`: an Index Only Scan of the primary key per OU, `=` being leakproof.
  The join into the scoped `sub` is a lookup by `(tenant_id, connection_id, object_guid)`, the
  `directory_objects` primary key. Work is the sum of subtree sizes (objects x average depth), not
  OUs x objects. Estimate at 25k objects, 101 OUs, depth about 4-6: 100-150k edge rows, 25k-150k PK
  lookups per column, which is milliseconds to low hundreds of ms per column. **[UNVERIFIED]** this
  is a model, no PostgreSQL ran in this spike; the follow-up ticket measures it against the 20 s
  bound and the AN3 plan check.
- **Write amplification.** One edge row per ancestor per object: x depth on insert and delete (a
  25k-object sync adds 100-150k narrow rows, 3 uuid + tenant, about 40 MB of heap and index at
  250k edges **[UNVERIFIED]**). A move of an OU rewrites `ancestry` of its whole subtree
  (`rewriteDescendants` does this already, one UPDATE), and the trigger deletes and re-inserts only
  the changed edges: a move of a subtree of n at depth d costs about n x d edge writes, on a path
  that already rewrites n rows. Ordinary attribute updates leave `ancestry` unchanged and the
  trigger compares old to new, so they write nothing (as 0074 does for unchanged keys).
- **Guard surface.** None added. `RelEdge` and its "GUID, int, bool, time and enum projection,
  never text" rule exist for `links` and `inventory_group_members`. No new word enters `fragCheck`:
  the count uses `count`, `join`, `on`, which are already allowed. The table has no scope column;
  it carries no identity beyond GUIDs, and a count is produced only by joining the scoped `sub`.
- **RLS safety.** Tenant-led table, same policy shape as 0074/0068. The edge table reveals, to
  someone who could read it unscoped, which object lies under which OU. It is `rel`, never an
  anchor, so the compiler never offers it unjoined to scope: the fitness check AN2 forbids a count
  that reads `{rel.anc}` without a join to a `FilterAnchor`/`RowAnchor` of `directory_objects`.
  The runtime role has SELECT, INSERT, DELETE only (no UPDATE, no TRUNCATE; TRUNCATE ignores RLS).
- **Other readers.** `descendantsDNSQL` (`descendant_dn.go`) and `rewriteDescendants` use the same
  non-leakproof `ancestry @>` today and are the same seq scan; they can adopt the edge table later
  (a ticket below), which A makes possible and B does not.

### B. One-pass aggregate fragment (`unnest` + `GROUP BY` + keyed lookup)

An uncorrelated aggregate per column: `SELECT a, count(*) FROM {rel.sub}, unnest(sub.ancestry) a GROUP BY a`, looked up per OU. One scan of the scoped `sub` instead of 101.

- **Plan.** One seq scan of the tenant is fine, but the lookup is the problem. As scalar column
  fragments the aggregate is either correlated (the planner pushes the `a = {t}.object_guid` qual
  below `GROUP BY` and re-scans per OU, the current cost with one scan instead of five at best), or
  it must be reduced to a map (`jsonb_object_agg`) and indexed by a non-literal key. Cost with a real
  one-pass is about one scan x depth, quick. **[UNVERIFIED]** not measured. A column fragment cannot
  declare a top-level CTE, and a CTE inside a correlated subplan is re-run per outer row, so the
  one-pass only holds if the dataset grows a new shape (a joined derived table in `Base`), which is
  a change to the dataset model, not just the allowlist.
- **Write amplification.** None. Nothing new is stored.
- **Guard surface.** The widest of the two. It needs `unnest` (a set-returning function that reads
  an array column), `group`, `jsonb_object_agg` and a non-literal JSON key operator, which the guard
  refuses on purpose ("JSON key operator must be followed by a string literal"). Allowing a
  non-literal key lookup opens `->`/`->>` with a computed key for every dataset, and an aggregate
  that spans all `sub` rows is exactly the shape in which a missing scope join leaks counts of
  hidden objects. The guard's job is to refuse that class by word, and B makes the words legal.
- **RLS safety.** No new table, nothing new to leak at rest. But RLS is bypassed in spirit by every
  fragment that aggregates a whole relation, and the check has to prove a scoped input each time.
- **Other readers.** Does not help `descendantsDNSQL` or `rewriteDescendants`, which stay seq scans.

### Rejected

- **Add or reshape an index on `ancestry`** (GIN, `gin__int_ops`, B-tree on an array): rejected,
  all are blocked by the same leakproof rule (ADR-0011, lessons 2026-11-02). A leakproof function
  wrapper would need a superuser `ALTER FUNCTION ... LEAKPROOF`, which we do not run on a customer's
  PostgreSQL and which is itself a security claim we would own.
- **Materialised view or per-OU counter columns on `directory_objects`:** rejected. A counter is
  not scope-aware (the count has to be of readable objects, so it cannot be stored per OU), and a
  per-OU maintained count turns every object insert into a hot-row update of its ancestors.
- **Recursive CTE over `parent_guid`:** rejected, `parent_guid` has no tenant-led index for the
  walk and the allowlist needs `recursive` plus a join on the base table per level.

## Decision

**Option A.** `inventory_ancestors` is a derived edge table, keyed tenant-first, maintained by
statement-level triggers on `directory_objects` in the pattern of 0074, and declared in a dataset as
a `RelEdge`. A subtree count is the count of `{rel.anc}` rows for the OU joined to the scoped
`{rel.sub}`. No word is added to `fragCheck`.

**Rules**

1. **One writer path.** Edges are derived from `directory_objects.ancestry` only, by the triggers;
   no code inserts into `inventory_ancestors` (the runtime role has no INSERT grant path other than
   the trigger function's own statements; if the function is SECURITY INVOKER as in 0074 the role
   keeps INSERT/DELETE and AN1 checks callers).
2. **Equal to the array.** For every `directory_objects` row, the set of `ancestor_guid` of its
   edges equals the elements of `ancestry`; a row with `ancestry = '{}'` has none.
3. **Never counted unscoped.** A fragment that reads `{rel.anc}` must join a scoped anchor of
   `directory_objects` on `object_guid` (and `connection_id`); no count is taken from the edge table
   alone.
4. **Plan.** The count's plan contains no Seq Scan of `directory_objects` or `inventory_ancestors`
   at scale (index-scan nodes only, the loops-not-rows rule of lessons 2026-11-02).
5. **Projection is GUIDs only** (RelEdge rule). The table holds no text and no scope.

## Consequences

- One migration (table, policy, grants, three triggers, backfill with the 0074 FORCE window, VACUUM
  after), one dataset change (`ou-01` and the other `subtreeCount` consumers), one fitness job.
- Storage: about depth x objects narrow rows per tenant. Sync-time cost of a bulk insert is
  multiplied by depth. We accept it: ancestry changes are rare and bulk inserts are batched.
- The 128-entry cap bounds a row's edges at 128; a truncated chain gets no edges, matching
  "unknown, out of scope".
- Drift risk (trigger and array disagree) is the cost of any derived table; AN1 checks it
  against random writes, and a `REINDEX`-style rebuild statement is part of the migration.
- A later ADR may switch `descendantsDNSQL` and `rewriteDescendants` to the edge table.
- If measurement in the follow-up shows A misses the 20 s bound or the plan check, this ADR is
  revisited before T-2026 merges; B is not the fallback without a dataset-model change.

## Fitness function

Job `fitness-inventory`, built by the follow-up tickets. `accepted` only when all four run green in
`make ci`:

- **AN1 (integration, PostgreSQL).** Property test: after random sequences of insert, delete, move
  (parent change with `rewriteDescendants`), tombstone and a truncated chain, the edge set equals
  `unnest(ancestry)` of every row, for two tenants, and one tenant's writes change none of the
  other's edges. Also a static check that nothing outside the migration inserts into
  `inventory_ancestors`.
- **AN2 (static).** In `internal/directory/inventory/**`, every fragment that names `{rel.anc}`
  also names a scoped `{rel.<anchor>}` of `directory_objects`; an unscoped `{rel.anc}`-only count
  fails the build. `fragCheck`'s allowlist is unchanged: a golden test of `fragFunctions`,
  `fragKeywords` and the JSON-operator rule fails if `unnest`, `group` or `jsonb_object_agg` is added
  (it is the guard against sliding into B).
- **AN3 (plan, `make test-scale`).** `ou-01` at 25k objects: no `Seq Scan` on `directory_objects`
  or `inventory_ancestors` in `EXPLAIN (ANALYZE, BUFFERS)` (second run, VACUUMed, loops not rows),
  and `ou-01/all`, `/empty`, `/bound` each inside the batch-2 bound. Extends
  `Test_reports_library_batch2_at_scale`.
- **AN4 (isolation).** Rows and blocks read for tenant A's `ou-01` are equal with tenant B at 1x
  and 10x, by the ADR-0011 rule 16 formula (rows exactly, blocks within one B-tree level per loop).

## Follow-ups

Created with this ADR: the migration and triggers (backend-engineer), the dataset change and
T-2026 re-scope, the fitness job (devops-engineer), the security-architect review, and the
architecture-map entry. Candidate later ticket: move `descendantsDNSQL` / `rewriteDescendants` to the
edge table.
