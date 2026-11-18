---
title: "Security review: ADR-0018 inventory_ancestors edge table"
date: 2026-11-18
updated: 2026-11-18
status: draft
owner: heramb
author: security-architect
kind: technical
ticket: T-2294
---

# Security review: ADR-0018 `inventory_ancestors` (RLS, scope join, guard unchanged)

**Verdict: confirm Option A, with amendments to rules 1, 3, 5 and AN2 (below).** Rules 2 and 4 are confirmed as written.
Method: read-only review of the ADR against `migrations/0033`, `0074`, `0068`, `report/dataset.go` (`Rel`),
`reportsql/compile.go` `relation()` and `datasets_groups.go` `subtreeCount`. No PostgreSQL ran in this review, so
every claim about runtime behaviour is from reading code. AN1–AN4 must prove them.

## What I verified

- **Scope equivalence.** `relation()` builds a `FilterAnchor` as `(SELECT … WHERE <scope>)`, but a `Rel` as an
  unscoped `(SELECT cols FROM table [WHERE])`. The edge table therefore gets its tenant limit from RLS only,
  and its scope limit only from the join to `sub`. Under rule 2 the proposed count equals the current count
  (`sub.ancestry @> {t}.object_guid`, scoped `sub`, `state='live'`), including `'{}'` for incomplete chains. So no
  new disclosure *if* the join is present.
- **Guard.** `fragCheck` does not enforce "a `{rel.anc}` read is joined to a scoped anchor". It only requires
  that tables enter through `{rel.x}`. Rule 3 as written is policy, not a guard. See finding 1.
- **RLS shape.** The 0074 policy (`USING` and `WITH CHECK` on `tenant_id`, FORCE, UPDATE/TRUNCATE revoked) is the
  right template. `directory_objects` PK is `(tenant_id, connection_id, object_guid)`, so `object_guid` alone is
  not a key (finding 2).

## Findings and amendments

1. **High (rule 3 / AN2): scope join is unenforced by the guard.** `{rel.anc}` is an unscoped subselect. A future
   fragment that counts `{rel.anc}` alone, or selects `anc.ancestor_guid`, passes `fragCheck` and returns counts or
   GUIDs of objects the caller may not read. Amend: enforcement moves into `reportsql.NewRegistry`/`fragCheck` as a
   build-time **structural** rule (fail registration), not only a grep test: any fragment naming a Rel that has
   `RequiresScopedJoin` must also name a `FilterAnchor`/`RowAnchor` joined on `object_guid` **and** `connection_id`.
   Declare the flag on the Rel. This tightens the guard (no allowlist word is added), so "guard unchanged" holds.
   Test: registry test where a dataset with an `anc`-only count is refused; a count with the join is accepted.
2. **Medium (rule 3): join key.** Joining on `object_guid` alone could count an object of another connection with
   the same GUID. Required join: `sub.connection_id = anc.connection_id AND sub.object_guid = anc.object_guid`, and
   `anc.connection_id = {t}.connection_id` (the ADR text has all three; make them the check, not an example).
   Test: two connections of one tenant with a shared object GUID, counts unchanged.
3. **Medium (rule 5 / AN2): projection leaks ancestor GUIDs.** `ancestor_guid` of an object can be an OU above the
   caller's scope root. Counts are safe; any output column or sort/filter on `anc.*` is not. Amend rule 5: `anc` columns
   may appear only in `WHERE`/`ON` and inside `count(*)`; never in a select list, `ORDER BY` or `GROUP BY`. AN2 checks
   this. Test: fragment selecting `anc.ancestor_guid` is refused.
4. **Medium (rule 1): writer path and derived-data integrity.** SECURITY INVOKER (as in 0074, kept: PG 18 cascades run
   as the queuing role, and FORCE still binds an owner) means the runtime role keeps INSERT/DELETE on the table, so any
   code with a SQL-injection or a bug can forge edges. This corrupts counts but cannot widen a read (finding 1 keeps
   the scoped join). Amend rule 1: (a) trigger function schema-qualifies everything with
   `SET search_path = pg_catalog, public`, takes `tenant_id` **from the source row**, never from `current_setting`;
   (b) `REVOKE UPDATE, TRUNCATE`; `REVOKE ALL … FROM PUBLIC`; EXECUTE on the function not granted to the runtime role;
   (c) AN1's static check covers Go and SQL outside the migration and the trigger function, including `COPY`.
   Accepted residual risk: edge forgery by a compromised app role changes counts only; AN1 plus a rebuild statement
   detect and repair it.
5. **Medium (rule 2): tenant or connection reassignment.** The UPDATE trigger must treat a change of
   `(tenant_id, connection_id, ancestry)` as a change (0074 compares `tenant_id` too). Tenant re-assignment is
   blocked by `WITH CHECK`, but a connection change is not. Test in AN1: update `connection_id`, edges follow.
6. **Low (offboarding / retention).** The table holds object identity relationships per tenant. Tenant deletion and
   connection removal must remove its rows (FK to `tenants` has no cascade, as in 0074). Add it to the tenant-purge test
   and the "every tenant-led table has FORCE RLS and a policy" check that `search_trigrams_migration_test.go`
   follows. It is derived: excluded from exports and backups-as-evidence, rebuilt on restore.
7. **Low (migration).** The backfill lifts FORCE on `directory_objects` and the edge table for one statement. That is
   the 0021/0047/0074 precedent and acceptable only inside the single migration transaction with `tenant_id` copied
   from the source row. Test: after migration, two-tenant fixture, each tenant sees only its own edges; FORCE is on.
8. **Info: DoS.** Edge rows are bounded at 128 per object, so a hostile directory (a 128-deep chain repeated 1M
   times) gives 128x amplification on insert. Acceptable; AN3's scale run should include a deep-chain case.

## Amended rules (for the ADR)

1. One writer path: triggers only; trigger function as in finding 4; no other code or SQL writes the table.
2. Equal to the array, including on `connection_id` change; unchanged (confirmed).
3. Never counted unscoped, **enforced at registration** (finding 1) with the full join key (finding 2).
4. Plan: unchanged (confirmed). AN3 stays [UNVERIFIED] until measured.
5. GUIDs only, **and used only in WHERE/ON/count** (finding 3).

**AN2 amended:** a registry-level structural check plus the golden test of `fragFunctions`/`fragKeywords`. The
golden test is good: it stops the slide into Option B. Option B's word set (`unnest`, group, computed JSON key) is a
guard widening I would **reject** in review without a threat model of its own.

## Residual risk

Edge forgery by a compromised app role (integrity of counts only). Metadata at rest: the table lists which object sits
under which OU, no names, tenant-isolated by FORCE RLS.

## For the T-2293 successor / implementing tickets

Findings 1–3 belong to the dataset/guard ticket (T-2026 re-scope); 4–7 to the migration ticket (T-2295); AN1/AN2
changes to the fitness ticket (T-2296). ADR-0018 can move to ratification with these amendments applied.
