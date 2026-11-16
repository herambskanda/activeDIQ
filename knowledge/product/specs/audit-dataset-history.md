---
title: "Spec: activeDIQ audit-trail dataset (`history.audit_events`) for the report builder (ADM-097)"
date: 2026-11-14
updated: 2026-11-14
status: draft
owner: heramb
author: product-manager
ticket: T-2103
epic: E-010
milestone: M2c
parity: [ADM-097, ADM-137, ADM-138, ADM-114]
scope: proposed
sources_last_checked: 2026-11-14
---

# Spec: activeDIQ audit-trail dataset for the report builder

Unblocks the "activeDIQ audit" source of [reports-2c-builder.md](reports-2c-builder.md) §5.1
(FR-RB-04, AC-RB-05). It defines one registered dataset over our own audit trail (DM-80).
It adds no report screen and changes no audit guarantee.

## 1. Problem and user

- **Who and which job.** The auditor and the AD admin who must answer "who did what through
  activeDIQ, to what, when, and did it work", as a repeatable, schedulable report. The help desk
  lead needs the same, trimmed to the places they manage. Today the builder cannot name the audit
  trail as a source, so the only route is the audit viewer, which is not exportable or schedulable
  the way a report is.
- **Cost today.** The chained store `audit_event` keeps the envelope as one canonical binary blob
  (`envelope bytea`) beside four plain columns (`seq`, `at`, `event_id`, `kind`)
  (`migrations/0008_audit_chain.sql`). SQL cannot filter by actor, target, outcome or operation,
  so no report can use the table as it stands. Personal values (names, client address) are held
  by reference and erasable (ADR-0005 rule 11, rule 12), so a naive copy of them would defeat
  erasure.
- **ManageEngine.** Only the parity-matrix rows below are claimed. Anything about how ManageEngine
  stores or reports its audit data is not researched here and is not claimed (a research ticket
  is filed in §10 if wanted).

## 2. Parity baseline

| ID | Feature (matrix) | Covered by this spec |
| --- | --- | --- |
| ADM-097 | Custom report builder ([matrix](../../business/competitive-analysis/feature-parity-matrix.md)) | The audit source becomes pickable, filterable and exportable like any other source |
| ADM-138 | Admin audit report (par) | Rows for every admin action, with actor, target, outcome and time |
| ADM-137 | Help-desk audit report (enh) | Same dataset, filtered by actor kind and scope; delegated runners see only their places (§5) |
| ADM-114 | History and audit (par) | Automation and operation rows carry `operation_id` and `via` |

ADM-139 (technician logons, named in DM-80) has no row in the matrix. It is not claimed. Sign-in
events are in the dataset because they are audit events, but a sign-in report is not specified
here (`market-analyst` to add the ID if wanted).

## 3. Enhancements (v1 unless marked)

1. **EH-1 Exact freshness.** The audit chain is gapless (`seq` has no gaps, ADR-0005 rule 11),
   so the run header can say "complete through event N, M seconds behind the live trail", not a
   vague "synced X minutes ago". Source: reports-2a E1 (every run states how fresh its data is)
   and the matrix leapfrog on report customisation (matrix line 478). v1.
2. **EH-2 Every row links to its operation.** `operation_id`, `item_index` and `plan_hash` let an
   auditor open the full plan, approval and undo trail of the change. v1.
3. **EH-3 Erasure-aware.** Names that were erased under a privacy request read `[erased]` in
   every later run, and are never copied into a table that erasure cannot reach. v1. This is a
   constraint we hold, not a ManageEngine comparison.

## 4. Experience target

Set with `product-designer` at design time; this spec fixes the rules:
- "Actions by actor" (AC-RB-05) is built from the empty builder to a first preview within the
  2c builder's task-time budget (reports-2c-builder.md §5). The admin never types an event kind
  string: the `kind` picker lists the registry's labels grouped by family (`kind_family`).
- Every audit run states its watermark in plain words (§7). The admin never has to infer whether
  yesterday's change is in the report.

## 5. The dataset

**ID** `history.audit_events`. Registered by the `history` module through `Registrar.Dataset`
(EP-8, reports.md §3.1). **RowKey** `(tenant, seq)`: one row per chained event. Cardinality is one
row per event, never per change item.

### 5.1 Why a projection table

`audit_event` cannot be the base relation (§1), and only `platform/audit` may reference it in SQL.
`history` therefore owns a **read projection**, `history_audit_events` (tenant table, forced RLS,
declared in `tablekind`; written only by the projector job below). It is derived, never an
authority: the chain is. It can be dropped and rebuilt from `audit_event` at any time.

**Projector.** A `history.audit.project` job per tenant, under a lease, reads `audit_event` rows
with `seq` greater than its stored watermark, decodes each envelope with `audit.ParseEnvelope`,
and inserts the row and advances the watermark in one transaction. It never writes the chain. It
resolves no personal value (§5.4).

### 5.2 Columns

"Source" is the `audit_event` column or the `chain.Envelope` field (`internal/platform/audit/chain/chain.go`)
the projector copies. Types are the report engine's `ValueType` (reports.md §3.1).
Filter operators follow reports-2c-builder.md AC-RB-04 by type.

| Column ID | Type | Filter / sort | Source (table.field → projection) | Notes |
| --- | --- | --- | --- | --- |
| `event_seq` | Int | Eq, Lt, Le, Gt, Ge / sort | `audit_event.seq` | RowKey part; default sort descending |
| `event_id` | Text | Eq / – | `audit_event.event_id` | Stable id; for support and SIEM correlation |
| `at` | Time | all time ops and presets / sort | `audit_event.at` | UTC, microseconds |
| `kind` | Text | Eq, In, Prefix / sort | `audit_event.kind` | Dotted registry name, for example `operation.step.verified` |
| `kind_family` | Text | Eq, In / sort | first dotted segment of `kind` | Picker grouping (`operation`, `authn`, `authz`, `connection`, …) |
| `kind_version` | Int | Eq / – | Envelope `KindVersion` | |
| `outcome` | Enum | Eq, Ne, In / sort | Envelope `Outcome` | `success`, `failure`, `denied` |
| `reason` | Text | Eq, In, Present, Absent / – | Envelope `Reason` | Machine reason code only, never free text |
| `actor_id` | Text | Eq, In / sort | Envelope `Requester.ID` | Pseudonymous principal id, never a name |
| `actor_kind` | Enum | Eq, In / sort | Envelope `Requester.Kind` | `human`, `api_token`, `automation`, `system` |
| `via` | TextList | Contains / – | Envelope `Via[]` as `<kind>:<id>` | Token, automation policy or approver chain |
| `actor_name` | Text | – / – | **not stored**; resolved after the query (§5.4) | Display only |
| `component` | Text | Eq, In / – | Envelope `Component` | |
| `connection_id` | GUID | Eq / – | Envelope `Connection` | Empty for our own store |
| `target_guid` | GUID | Eq, In / – | Envelope `TargetGUID` | `objectGUID` or the store row key |
| `target_class` | Text | Eq, In / sort | Envelope `TargetClass` | |
| `target_name` | Text | – / – | **not stored**; resolved after the query (§5.4) | Display snapshot as it read at the time |
| `operation_id` | Text | Eq / – | Envelope `Operation` | |
| `item_index`, `step_index` | Int | – / – | Envelope `Item`, `Step` (only if `HasStep`) | Null when the event has no step |
| `plan_hash` | Text | Eq / – | Envelope `PlanHash` | |
| `changed_attributes` | TextList | Contains / – | attribute names of Envelope `Changes[]` | Names only, never values (a secret attribute shows its name, never a value) |
| `change_count` | Int | Eq, Gt, Ge / sort | count of Envelope `Changes[]` | |

Not columns at v1, by decision: `details` (typed per kind, so no stable column set), client
address and any change value (personal, §5.4). `details` can become columns per kind later with a
new `_v2` suffix, as in reports.md §3.3 (d).

### 5.3 Scope column: how a row is trimmed to what the runner may see

Every projected row also holds the engine's six scope columns, so the dataset can use the 2a
scope machinery unchanged (reports.md §3.1 `Anchor`, §4.3): `connection_id`, `nc_guid`,
`object_guid`, `parent_guid`, `ancestry` (`uuid[]`, nearest parent first, GIN-indexed),
`ancestry_complete` (bool NOT NULL). Plus one new column, **`scope_class`** (enum, NOT NULL):

| `scope_class` | Events | Who sees the row |
| --- | --- | --- |
| `directory` | the target is a directory object (AD or Entra) known to `directory_objects` | A runner whose delegation scope covers the object (`RowAnchor` on the six columns), and who holds `audit.read` |
| `store` | the target is our own configuration (RBAC, settings, connection, schedule) | Only a runner whose `audit.read` is **tenant-wide** |
| `tenant` | no target (sign-in, checkpoint, retention, key events) | Only a runner whose `audit.read` is tenant-wide |

**How it is populated.** For a `directory` event the projector reads the target's scope columns
from `directory_objects` for `(connection, TargetGUID)` and copies them. For an Entra target the
columns are whatever `directory_objects` holds for it, the same ones the Entra datasets use
(reports-entra-objects.md), so AU and tenant roots work as in 2a. If the object is not found
(deleted, purged, or created after the last sync), the row is stored with `ancestry_complete =
false`, and `ancestry` from the envelope's `Parent` when present. The engine treats an incomplete
row fail-closed as in reports-2a §4.5. A completion pass retries those rows for 15 minutes
(the number is a decision for `reporting-engineer` to confirm against the sync interval); a row
still incomplete after that stays incomplete, so it is visible to tenant-wide readers only.
`scope_class` is set by the projector from `TargetClass` and `Connection`, never from a filter
the runner supplies.

**Decisions.**
- Ancestry is read at projection time, within about a minute of the event, not at event time.
  For a move, the row therefore shows under the **new** location. A delegated admin scoped only
  to the source OU does not see the move. Fail closed; the header says "activity is shown for
  the places you can read", as for change history (reports.md §14 decision 13). Whether to show a
  move to both sides is Q1.
- A runner with no `audit.read` does not get the source: it is **hidden, not greyed** (2c §5.1
  rule). "My activity" (own entries only, IA) is a separate screen and is not a report source at v1.

### 5.4 Personal values

The chained envelope holds names, display snapshots, client address and change values as
`PersonalRef`s (rule 12). The projection copies **none** of them. `actor_name` and `target_name`
are filled after the query, per displayed page and per export row, through `personal.Resolve`
(and the account directory for the actor's current name), like the engine's `PerDC` columns
("filled after the query, never SQL"). Consequences, all required:
- they cannot be filtered or sorted, only shown. Filtering is by `actor_id`, `target_guid` and
  `target_class`;
- a value whose rows were erased shows `[erased]` (`Resolve` already does this), also in a
  **stored** run read after the erasure, so a stored run keeps the reference, not the text (Q2
  asks `solution-architect` to confirm against reports ADR-0010's stored result);
- an export already downloaded before an erasure is outside our reach, and the export "About"
  block says the names were resolved at the run time (docs-writer states it in the guide).

### 5.5 Platform matrix

| Platform | Contribution | Notes |
| --- | --- | --- |
| On-prem AD, any functional level | Events whose target is an AD object | The data is our own; no AD read at report time. The projector reads `directory_objects` (already synced), not the DC |
| Entra ID | Events whose target is an Entra object | Scope columns as the Entra datasets |
| Hybrid | Both, one row per event | A hybrid correlated object keeps the target of the event; no merging |
| Windows Server versions for a DC-side component | **Not applicable.** No DC-side component | Stated so it is a decision, not an omission |
| Deployment | Self-hosted and SaaS-ready | One chain and one projection per tenant; RLS on the projection; no cross-tenant read |

## 6. Security and audit

- **Privilege.** Reads one tenant's projection under forced RLS. Needs no directory privilege.
  The source needs `audit.read` (§5.3) in addition to `reports.run`. This is a new dataset-level
  gate; the 2a engine has no such field (Q3).
- **Our own audit.** A run on this dataset is audited like any run (`reports.run.*`, with dataset
  id, definition id and version, never row values; reports-2a §8.6). A denied attempt is audited.
  Running an audit report appends an event after the watermark of that run, so it is never in its
  own result and cannot loop. The projector appends **no** event per row. It appends one
  `history.projection.rebuilt` event for a rebuild (actor, `seq` range, count).
- **Retention and holds.** When `audit.Purger` deletes a partition (rule 11), the projection rows
  with `seq` at or below the purge boundary are deleted in the same maintenance step. A legal hold
  that suspends the purge keeps them. The dataset never shows an event the chain no longer holds.
- **`security-architect` must look at:** the scope trimming of `store` and `tenant` events, that the
  projection holds no personal value, the post-query resolution path, and the incomplete-ancestry
  rule. Build tickets are tagged `security-sensitive`.

## 7. Freshness guarantee

The dataset's freshness source is its projection watermark (a new `FreshnessSource`; the current
three are `FreshNCWatermark`, `FreshPolicyRead`, `FreshPerDC`, so this needs an engine amendment,
Q3). The guarantee has four parts:

1. **Lag bound.** For a tenant at or under 100 audited commits per second, 99% of events are
   projected within **60 seconds of commit**, and none is later than 5 minutes unless the job is
   down. The projector sustains at least 1,000 events per second when catching up. These are
   targets to be measured in the load test of the build ticket (`[UNVERIFIED]` until then; the
   audit chain's own budget is 200–1,000 commits/s, ADR-0005 rule 11).
2. **Exact label.** A run records `watermark_seq` (highest projected `seq`) and `head_seq` (the
   chain head read in the same transaction). The header reads "complete through event N, at
   <time>" when equal, else "N events behind (up to <time>)". `as_of` is the `at` of event
   `watermark_seq`. A run never claims more than it has.
3. **Delay is visible.** If the oldest unprojected event is older than 5 minutes, the label turns
   to "delayed" and the preview, run and export About block say so; a schedule still runs and
   carries the label. A paused projector raises the `history_projection_lag` metric and an alert.
4. **Stable runs.** A run's rows are fixed at its `watermark_seq`. Paging and export of that run
   do not move when later events arrive (reports-2a run rules).

Backfill and rebuild: after a rebuild or first install, the dataset reports "building: through
event N of M" and no run claims completeness until the watermark equals the head.

## 8. Acceptance criteria

AC-AD-01 (columns)
Given the registered dataset `history.audit_events`
When `GET` the dataset in the registry API
Then it lists exactly the columns of §5.2 with the types given, and no column for a personal value,
  a change value, `details` or the client address
Evidence: contract test `audit_dataset_columns_match_spec`; fitness check that the projection
  schema has no text column fed from a `PersonalRef`

AC-AD-02 (matches the trail)
Given a lab where 20 admin actions have been recorded and the projector has caught up
When the builder runs "Actions by actor" (`actor_id`, `kind`, `at`; `at` in the last 7 days)
Then there are rows exactly for the chain's events in that window that the runner may see, with the
  same `seq`, `kind`, `at` and `actor_id` as `audit_event`
Evidence: UI recording; test `builder_audit_source_matches_trail` (the 2c AC-RB-05 test)

AC-AD-03 (scope: directory)
Given technician A delegated to OU "Sales" and technician B delegated to OU "HR", both with
  `audit.read`, and events for objects in each OU
When each runs the same report
Then A sees only events on objects under Sales and B only those under HR, and neither sees `store` or
  `tenant` events
Evidence: test `audit_scope_directory_trim`; UI recording

AC-AD-04 (scope: tenant-wide and store)
Given a runner with tenant-wide `audit.read`
When they filter `scope_class` = `store`
Then they see the RBAC, settings and connection events, and a delegated runner running the same
  definition sees zero rows and an unchanged count line
Evidence: test `audit_scope_store_tenantwide_only`

AC-AD-05 (no permission, no source)
Given an admin with `reports.run` and without `audit.read`
When they open the builder's source list
Then "activeDIQ audit" is absent (not disabled), and a direct API call to run a definition on it
  returns 403 and an audited denial
Evidence: UI; contract test

AC-AD-06 (incomplete ancestry fails closed)
Given an event whose target is not yet in `directory_objects` (created and audited before the sync)
When a delegated runner runs the report
Then the row is not shown to them, a tenant-wide reader sees it, and after the sync and the
  completion pass the delegated runner in scope sees it
Evidence: test `audit_incomplete_ancestry_fail_closed`

AC-AD-07 (freshness label, caught up)
Given the projector has projected every event
When a run completes
Then the header shows "complete through event N", `watermark_seq` equals `head_seq`, and `as_of` is
  the time of event N
Evidence: UI; test `audit_freshness_label_caught_up`

AC-AD-08 (freshness label, behind and delayed)
Given the projector is paused and 40 events are appended over 6 minutes
When a run completes
Then the header shows "40 events behind" and "delayed", the 40 events are not in the rows, and the
  export About block carries the same label; after the projector resumes, a new run shows no
  events behind
Evidence: UI; test `audit_freshness_label_behind`

AC-AD-09 (lag bound)
Given a load of 100 audited commits per second for 10 minutes on one tenant
When the lag of each event (projected time minus commit time) is measured
Then at least 99% are within 60 seconds and none exceeds 5 minutes
Evidence: load-test output committed with the build ticket

AC-AD-10 (large trail and bulk operation)
Given a tenant with 10 million events and a 100,000-object bulk operation that appends about 200,000
  events within minutes
When a delegated runner opens a report filtered by `at` in the last hour, and another by `operation_id`
Then the first preview returns its first 50 rows with the count within the 2c preview budget, the
  operation report returns exactly the operation's events, and the projector catches up within 5
  minutes of the operation's end, with the label "behind" in the meantime
Evidence: test on a 10M-row fixture; UI recording

AC-AD-11 (erasure)
Given an event whose target's name and actor's client address were stored as personal values, and
  those values are then erased
When the report is run again and a stored run created before the erasure is opened
Then `target_name` reads "[erased]" in both, the projection table holds no copy of the name, and the
  event's `seq`, `kind` and `outcome` are unchanged
Evidence: test `audit_dataset_erasure`; a query over `history_audit_events` finding no name

AC-AD-12 (retention and rebuild)
Given the retention purge deletes the partition up to `seq` S, and, in another case, a legal hold
  blocks it
When the dataset is read afterwards
Then, in the first case, no row with `seq` ≤ S remains; in the second, rows are retained; and after
  dropping and rebuilding the projection from `audit_event`, the rows equal the earlier ones
Evidence: test `audit_projection_purge_and_rebuild`

AC-AD-13 (empty and error cases)
Given a tenant with no events other than genesis, and, separately, a run while the projection table is
  unavailable
When the report is run
Then the first shows "0 rows" with the freshness label and no error; the second fails with a stable
  reason code and the audit event of the failed run, never partial rows and never driver text
Evidence: UI; test

AC-AD-14 (group-scoped runner)
Given a runner whose delegation root is a group with 1,600 members
When they run the report
Then the rows match the engine's live closure for that group (the 2a rule), with no row for an object
  that left the group, and the run is not truncated at 1,500
Evidence: test `audit_scope_group_1600`

## 9. Out of scope

- DC audit events, sign-in and logon reports (ADA-101, ADM-139), M3 or a later spec.
- `details` as columns, client address, change values, and filtering on names.
- "My activity" as a report source (own entries only).
- Cross-tenant audit reports. Anything about ManageEngine's audit storage (not researched).
- Any change to the chain, its hash, checkpoints or export. The projection is not evidence.

## 10. Open questions and hand-offs

- **Q1 (security-architect, product-designer):** show a move to readers of the source location too
  (a second `scope` row per move)? Default here: new location only, fail closed.
- **Q2 (solution-architect):** do stored run rows (`report_run_rows`) keep the personal reference and
  resolve at read, as §5.4 requires? If ADR-0010's stored result holds resolved text, an amendment is
  needed before this ships.
- **Q3 (solution-architect):** engine amendments needed: a `FreshnessSource` for the projection
  watermark, a dataset-level required permission (`audit.read`) and the `scope_class` rule. Filed as a
  hand-off; this spec does not decide the engine.
- **Q4 (reporting-engineer):** confirm the 15-minute completion pass against the sync interval, and the
  60-second target (§7) against the audit chain's throughput in the T-0088 load test.
- Build tickets (for `project-manager`): the projection table and projector job; dataset registration
  and scope; the freshness source and dataset permission; purge integration; the load test (AC-AD-09,
  AC-AD-10). Tag `security-sensitive`. They block 2c AC-RB-05 only; the rest of the builder ships
  without them (2c §5.1 hides the source).
