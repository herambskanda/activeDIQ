---
title: "ADR-0010: A report run's result is stored as rows in PostgreSQL; exports are blobs serialised from those rows"
date: 2026-10-30
updated: 2026-11-01
status: ratified
ratified_on: 2026-10-30
ratified_by: factory-director
decision: D-0015
owner: heramb
author: solution-architect
kind: technical
ticket: T-0865
fitness: fitness-reports RP3, RP4, RP5 (T-0873; not yet in CI, so not `accepted`)
---

# ADR-0010: A report run's result is stored as rows in PostgreSQL; exports are blobs serialised from those rows

**Status:** ratified 2026-10-30 by factory-director (T-0865 re-review of rework 53d5eee4e). The
fields and the notice D-0015 were recorded on 2026-11-01 (T-1145). `accepted` when `fitness-reports`
RP3–RP5 run green in CI (T-0873; T-0968 confirms).
**Kind:** technical (no CEO fork: no change to price, packaging, deployment or platform strategy).
**Deciders:** solution-architect · **Ticket:** T-0865 · **Parity / scope refs:** ADM-099, ADM-100,
ADM-101; reports-2a FR-11, FR-12, FR-17, FR-20; DM-72.
**Builds on:** ADR-0001 rule 3 (PostgreSQL is the only stateful service), ADR-0002 (tenancy: RLS +
`FORCE`, tenant-led keys), ADR-0003 rule 6 (table ownership), safe-primitives P5 rule 9 (no
materialized views over tenant tables), blueprint §12 ("Blobs" through `platform/blob`).

## Context

The locked 2a reports spec ([reports-2a §8.1](../../product/specs/reports-2a.md)) defines a **run**
as one execution over one frozen set of inputs:

- paging and sorting read **the same run's stored result** and never re-execute against newer data;
- the header's `as_of`, row count and digest belong to that run;
- export and scheduled delivery **serialise that run's stored result**, so the file, the About
  block and the digest equal what the admin saw;
- results expire (7 days by default) and an expired result is re-run, never served as current.

FR-12 adds that paging, sorting and totals are server-side and "total counts MUST not load every
row". Row caps go up to 1,000,000 stored rows per run (§8.3).

DM-72 names a `result_blob`, which assumes blob storage. Blob storage meets "frozen" but not
"server-side sort without loading every row". That conflict makes this an ADR rather than a module
detail. The choice also decides how the 1M-row cap, retention and the tenancy rules apply.

## Decision

We will store each run's result **as rows in a PostgreSQL table owned by `modules/reports`**, and
keep **export artefacts** (CSV, XLSX, later PDF and HTML) as **blobs** in `platform/blob`, produced
only by serialising those rows.

Rules:

1. **Result table.** `report_run_rows (tenant_id, run_id, row_key, ordinal, cells, sort_keys)`,
   with primary key `(tenant_id, run_id, row_key)`, a unique `(tenant_id, run_id, ordinal)`
   (deferrable, so a per-DC run can renumber before it finishes) and a foreign key to
   `report_runs`. RLS with `FORCE` and the one fail-closed policy shape (P5 rule 10). It is not
   partitioned at 2a.
   - `cells` is a JSON array of typed cells in the run's column order, using the `report.Cell`
     encoding (modules/reports.md §6.2).
   - `sort_keys` is a JSON object, column ID → order-preserving text.
   - `ordinal` is the run order: the definition's sort, with `row_key` as the last tie-break.
2. **Written only while the run is `running`; read only once it has `succeeded`.**
   - The run path reads the dataset through one server-side cursor (`reportsql.Exec`). One cursor
     is one snapshot, so every row and every hidden-row count come from the same data. No isolation
     level above the default is needed.
   - It inserts the rows batch by batch in the same transaction. For an ordinary report it flips
     the run to `succeeded` in the same commit.
   - A per-DC report commits its candidate rows with the run still `running`, fills the per-DC
     cells in short transactions, and flips to `succeeded` last (modules/reports.md §6.5).
   - A trigger refuses an insert or update of rows whose run is not `running`, and a delete unless
     the run is `failed`, `cancelled` or `expired`.
   - Page queries join `report_runs` on `state = 'succeeded'`, so a reader never sees a partial
     result, and nothing changes a row of a succeeded run.
   - A stored run is read only by its runner, and only while the runner's current read-scope
     fingerprint equals the one the rows were trimmed with (modules/reports.md §6.6). Stored rows
     are one account's view, never a shared cache.
   - A job retry that finds its run `running` fails it as `interrupted` and deletes its rows; it
     never resumes into the same run (modules/reports.md §6.3).
3. **Pages are static SQL.** Paging and re-sorting a stored result are sqlc queries over
   `report_run_rows`. They order by `ordinal`, or by `sort_keys->>@column COLLATE "C"` with two
   static variants (ascending and descending), then by `ordinal`. The column key is a bound
   parameter (SQL-16). The total is `report_runs.row_count` and is never a `COUNT(*)`. **No dynamic
   SQL reads stored results.**
4. **Exports serialise stored rows only.** The export job streams `report_run_rows` in `ordinal`
   order into a P7 encoder (`platform/export`) and puts the bytes in `platform/blob` under a
   tenant-prefixed key, with an expiry equal to the run's. Export and delivery code never compiles
   or runs a dataset query (fitness RP3). The digest is computed once, when the run succeeds, from
   the stored rows (the canonical form of reports-2a §8.3, implemented in `platform/export`). The
   About block carries that digest.
5. **Expiry.** `report_runs.expires_at = finished_at + retention`. Retention is 7 days at 2a. A
   tenant setting of 1–30 days is a later configuration Action (modules/reports.md §11).
   - A scheduled job flips expired runs to `expired` and deletes their rows in batches.
   - Reading a page of an expired run returns `ErrRunExpired`, and the API answers 410.
   - Exporting an expired run creates a new run first and says so.
   - Artefact blobs carry the same expiry, so `blob.Sweep` removes them.
6. **No other result store.** No materialized view, no temporary table, no session-held cursor or
   exported snapshot, and no second engine holds a result.

## Alternatives considered

| Alternative | What it would buy us | Why not (for now) |
| --- | --- | --- |
| **Result as a blob** (JSON Lines or a columnar file in `platform/blob`), as DM-72's `result_blob` assumed | The database stays small. Retention is just `blob.Sweep`. Export is close to a copy | A re-sort must read and sort the whole file on every request, which fails FR-12. Paging needs a side index we would have to build and keep consistent. The S3 adapter adds latency to every page. Rows and the run record could not commit together, so a crash could leave a run `succeeded` with a missing or partial blob |
| **Re-execute on every page** (store only the parameters) | No result storage at all | Breaks the frozen-run rule: page 2 could come from newer data than page 1, and the header's count, `as_of` and digest would not describe what the admin sees. The spec rejects it explicitly |
| **Hold a snapshot** (`pg_export_snapshot`, a `WITH HOLD` cursor or a temporary table per run) | Exact frozen reads with no copy | These are tied to one session or transaction. We use pooled connections and tenant-scoped transactions (P5 rule 11). They do not survive a restart, and a held snapshot pins the vacuum horizon for hours |
| **Materialized view per run** | Database-native and indexable | Banned over tenant tables (P5 rule 9): RLS does not apply to a materialized view. It also needs DDL from the runtime role |
| **Partition `report_run_rows` by expiry day** and drop partitions | Retention with no delete or vacuum cost | Creating and dropping partitions is DDL. Only migrations hold the owner role (ADR-0002), and no runtime maintenance path exists. We revisit this under "Revisit when" |

## Consequences

**Positive**
- Paging, re-sorting and totals are cheap, server-side and exact for the run on screen (FR-11,
  FR-12).
- Rows, row count, digest and state commit together, so a run is all-or-nothing.
- Tenancy needs nothing new: the result table is an ordinary RLS + `FORCE` tenant table, checked by
  `fitness-tenancy` like every other.
- Export, delivery links and the API's "recompute the digest" read one source, so every format of
  a run carries the same digest (AC-50).
- There is no second storage engine to install, back up or secure (ADR-0001 rule 3).

**Negative**
- **Database volume.** A 1M-row run with roughly 600 bytes per row is about 0.6 GB until it expires.
  Mitigations:
  - the stored-row cap (1,000,000) and the per-tenant concurrency cap (4 report jobs);
  - the 7-day retention;
  - a 60-second reuse window for an identical request (modules/reports.md §6.1).

  Customers with large domains will see the database grow, and the sizing guide must say so.
- **Delete-driven retention** leaves vacuum work after each expiry batch.
- **Long run transactions.** A large run holds one transaction with an open cursor while it
  copies the rows, which holds back the vacuum horizon during that time.
- Sorting a stored result by a column scans the run's rows: there is no per-column index.
  p95 is measured on the scale tier (reports-2a Q4). The budget is `[PROPOSED]` 3 s for 1M rows.
- Sort order for text is the casefolded byte order (`COLLATE "C"` over the sort key), not a locale
  collation.

**Follow-on work**
- T-0873: `fitness-reports` RP3–RP5 (this ADR's fitness function).
- The run-path build ticket (modules/reports.md §12, row B4; ADR-0010 reaches `accepted` through row B14) creates `report_runs`,
  `report_run_rows`, the retention job and the page queries.
- T-0874: update the architecture map, and amend DM-72 to say `result` (rows) and `exports[]`
  (blobs) in place of `result_blob`.

**Revisit when**
- the scale tier shows `report_run_rows` vacuum or bloat above budget, or sort p95 above budget
  (then partition by expiry day with a platform maintenance path, or add a per-column rank table);
- or a customer's retention needs exceed 30 days.

Either case calls for a superseding ADR.

## Fitness function

Job `fitness-reports` (`tools/fitness/reports`, T-0873). This ADR is `accepted` only when all three
of the following checks run green in `make ci`:

- **RP3 (static).** Under `internal/modules/reports/**`, only package `internal/modules/reports/run`
  may call `reportsql.Compile`, `reportsql.CompileCount` or `reportsql.Exec`. Export, delivery and
  page code therefore cannot re-query a dataset (rule 4).
- **RP4 (integration, PostgreSQL).** `Test_expired_run_is_not_served`:
  - a page read of an expired run fails with `ErrRunExpired`;
  - an export request for it creates a new run;
  - the retention job leaves no `report_run_rows` for it;
  - a `succeeded` run has a non-null `expires_at` (the table's `CHECK` refuses one without it);
  - the row trigger refuses an insert into, or an update of, `report_run_rows` once the run is
    `succeeded`, and refuses a delete while it is `succeeded` (rule 2);
  - the state trigger refuses every state edge not listed in modules/reports.md §6.2.
- **RP5 (integration).** `Test_export_digest_equals_run_digest`: the digest stored on the run equals
  the digest recomputed from the rows through the API, the digest in the XLSX About block, and the
  digest recomputed from the CSV after parsing it back (reports-2a AC-50).

`fitness-tenancy` (ADR-0002) already covers RLS, `FORCE` and the tenant-led keys of both tables.
