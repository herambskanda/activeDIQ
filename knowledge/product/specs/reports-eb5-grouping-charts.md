---
title: "Spec: Report builder grouping, charts and sharing (EB-5, ADM-097)"
date: 2026-11-14
updated: 2026-11-14
status: draft
owner: heramb
author: product-manager
ticket: T-2104
epic: E-010
milestone: M2c
parity: [ADM-097, ADM-100, ADM-101]
scope: proposed
sources_last_checked: 2026-11-14
---

# Spec: Report builder grouping, charts and sharing (EB-5)

> An admin turns "all users" into "users per department, by account state" in one step, sees it as
> a chart or a table, and sends it to a colleague who sees only what their own scope allows.

Extends [reports-2c-builder.md](reports-2c-builder.md) §3 (EB-5, deferred) and §11. It inherits run, scope,
freshness, export, schedule, permission and audit rules from [reports-2a.md](reports-2a.md) §8 and
changes none. Requirement prefix `GC-` (`FR-GC-nn`, `AC-GC-nn`). Reviewed by `solution-architect`
(compiler amendment, §3). Dashboards and widgets (ADM-103) stay out; a chart is a view of a run, so
the widget contract ([home-report-widgets.md](home-report-widgets.md) §3.1) can adopt it later.

## 1. Problem and user

**Users.** The AD admin answering "how many accounts per department are stale?"; the auditor who
needs a count per group type or per month for a committee; the manager who receives the result and
never opens the builder.

**Cost today in ManageEngine.** Report customisation is the #2 complaint (about 17 reviews, X2),
including "currently, it's limited with old school bar charts, and having more interactive reports
with a better graphical user interface would be beneficial"
([customer voice X2](../../business/market-research/manageengine-ad-customer-voice-and-security.md) :149,
PeerSpot, 2025-09-16). The research lists the leapfrog as "bulk sharing, scheduling UX and
interactive charts" (same file :429). What ME's builder offers for grouping or charting is **not in
the research**: `[UNVERIFIED]`. Research ticket requested (§10, Q5); the targets below are absolute
until it returns.

## 2. Parity baseline

| ID | ME capability (matrix) | activeDIQ here | Status |
| --- | --- | --- | --- |
| ADM-097 | Custom report builder; copy, share and delegate ([ME research :524](../../business/market-research/manageengine-admanager-plus.md)) | Grouping on a custom report; sharing of a finished report (§6) on top of 2c §6 definition sharing | Parity plus enhancement |
| ADM-100 | Export | Chart and grouped table export under 2a §8.3 (§6.3) | Parity (2a) |
| ADM-101 | Scheduling | A grouped report schedules like any report (§6.4) | Parity (2a) |
| ADM-103 | Dashboard widgets | Not here | Later slice |

Whether ME ADManager Plus can group results or draw charts in *custom* reports is unknown
`[UNVERIFIED]`; no parity claim is made for grouping itself, only for the rows above.

## 3. Grouping (acceptance 1)

### 3.1 The node

A definition may carry **one optional grouping step** after the filter and before sort. The amendment
to [reports.md §3.2](../../development/architecture/modules/reports.md) (which says "no aggregate or
grouping node at 2a") adds a closed `Group` node, so the type never names anything that does not exist.
Proposed shape for `solution-architect` to confirm (Q1):

| Part | Rule |
| --- | --- |
| **Inputs** | Rows of the one source after filters **and after scope trimming** (DM-71.I1, LF-39) |
| **Group keys** | 1 or 2 registered columns of type enum, flag, string, GUID, or date. A date key takes a **bucket**: day, week, month, quarter, year. Max **2 keys** `[PROPOSED]` |
| **Measures** | `count` (always present), `count_distinct(column)`, `min`, `max` (date, number), `sum`, `avg` (number columns only). Up to **4 measures** `[PROPOSED]`. The operator list per column type is closed, as 2c §5.2 |
| **Missing values** | A row with no value for a key forms its own group labelled "(none)". Never dropped, never merged |
| **Group filter** | Optional "keep groups where measure op value" (Eq…Ge on a measure). This is a typed filter on the output, not a query text |
| **Order** | One sort key: a group key or a measure, plus the stable tie-break |
| **Limits** | Output **≤ 1,000 groups** `[PROPOSED]`; beyond that, the run keeps the top 1,000 by the sort and says "1,000 of N groups" naming N. Top-N cut-offs are never silent |

No group key or measure can name a secret attribute, an unregistered column or a free expression
(2c FR-RB-02). Group keys over a multi-valued attribute are **not offered** (a row would count
twice); the picker says why.

### 3.2 Output shape

A grouped run stores a result with: one column per group key (display name, typed), one column per
measure (typed), `_group_size` (the count, always), and for 2-key groupings one row per key pair.
Header carries `as_of`, freshness label, definition id, version, SHA-256, and the **after-trim**
`object_count` (objects counted), `group_count` and `groups_shown` (reports-2a §8.1 run rules).
A grouped result is paged and sorted from the stored run like any run, exports as a table, and its
rows are **groups, not objects**. Totals equal the sum of group counts; a "(none)" row is included.

### 3.3 Small groups

Scope trimming happens before grouping, so a group never counts an object the runner cannot see.
The 2a disclosure rule for aggregate columns (reports.md §3.3 :346) applies unchanged: a measure
must not differ from the same measure computed with out-of-scope objects deleted. No extra suppression
of small groups is applied, because the runner may already list those objects in the ungrouped report.

### 3.4 Drill-through

Clicking a group (a bar, a slice or a row) opens the **ungrouped report with that group's key values
as added filters**, in a new run, count equal to the group's count at the same data age (the
discrepancy case is "data changed since": the screen says so). This is the one navigation from
chart to rows, so a chart is never a dead end.

### 3.5 Builder experience

Grouping is a panel in the builder beside columns and filters ("Group by"), a picker by display name
showing type, never text. Preview (2c §5.3) shows the grouped result, first 50 groups, within the
same 300 ms debounce and rate limits. Columns and grouping are exclusive views: ungrouped columns
are kept in the definition and return when grouping is removed; nothing is lost.

## 4. Charts (acceptance 2)

### 4.1 Supported chart types (v1)

| Type | Needs | Notes |
| --- | --- | --- |
| **Bar** (horizontal and vertical) | 1 key, 1 measure | Default for 1 key; horizontal when labels are long |
| **Stacked bar** | 2 keys, 1 measure | Second key is the stack; > 8 stack values collapse into "Other" (labelled, drill-through lists them) |
| **Line** | 1 date key (bucketed), 1 or 2 measures | Missing buckets are drawn as gaps, never interpolated |
| **Donut** | 1 key, count, ≤ 8 groups | Offered only when ≤ 8 groups; otherwise not offered, with the reason |
| **Table** | any grouping | Always available and the **fallback** |

Not v1: scatter, heat map, gauge, 3-D, secondary axes, free colour. Every chart has a **"View as table"** toggle
showing the identical numbers (accessibility and trust). The type is offered by the data shape: the
picker never lists a chart the result cannot draw. A suggested type is pre-selected from the shape.

### 4.2 Attaching a chart to a grouped result

1. A chart is an optional `chart` part **of the definition** (type, key and measure bindings, title,
   sort), saved with it and versioned with it (2c §5.4). It is **not** a separate object.
2. Only a definition with a grouping step can carry a chart. Removing the grouping removes the chart
   after a confirmation naming it.
3. In the builder, after "Group by" is set, a "Chart" tab shows the suggested chart with live preview.
   The admin picks type and which key and measure bind to which axis; axes, colours and number
   formats come from the design system (no free-form styling).
4. A definition carries one chart at v1.
5. A chart reads the run's **stored result only**; it never queries. It shows the freshness label, the
   "as of" and the after-trim counts as the table does.
6. Chart values are rendered only through the design-system encoders (labels from the directory are
   untrusted text: HTML and formula characters are encoded as 2a §9).
7. Shipped reports may later carry charts by the same mechanism; that is not in this spec.

### 4.3 Experience target

Set with `product-designer` (proposals until signed off). Absolute, as the ME comparison is `[UNVERIFIED]`:

- From an existing report to a chart of "count per department": **≤ 5 interactions and ≤ 30 s** on the
  100k-user lab.
- The admin never chooses an axis format, colour or aggregation by text; defaults are right for the data.
- States shown: empty (no groups), loading, error with reason, > 1,000 groups (cut-off message), a single
  group, all values "(none)", stale run, `scope_changed`.

## 5. Platform matrix

| Part | AD on-prem (WS2016-2025) | Entra cloud-only | Hybrid | Console | REST API | PowerShell | `windows` | `linux-oci` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Grouping (FR-GC-01…08) | ✓ | ✓ if reports-entra-objects shipped, else hidden | ◐ AD and Entra separate sources, no cross-source group | ✓ | ✓ | ◐ follows API | ✓ | ✓ |
| Chart (FR-GC-09…14) | ✓ | ✓ same | ◐ | ✓ | ✓ definition and data; the image is console/export | ◐ | ✓ | ✓ |
| Sharing (FR-GC-15…) | ✓ | ✓ | ✓ | ✓ | ✓ | ◐ | ✓ | ✓ |

No DC-side component. Derived states needing policy remain `[LAB: Windows]` as in 2a §10. Server-side
chart-image rendering (for PDF and mail) must run **identically on both profiles**; a renderer that only
works on one OS is a defect (Q3).

## 6. Sharing a finished report (acceptance 3)

Three distinct things share, and the spec keeps them apart:

| What | Who | Rule |
| --- | --- | --- |
| **A. The definition** (grouping and chart included) | Named users or roles, **view** or **edit** | As 2c §6: sharing never shares data; each runner sees only their own scope; revocation next request. Edit requires `reports.build` |
| **B. A link to a run or a view** | Any signed-in user with `reports.run` | The link carries definition, version, preset, scope narrowing and chart state in the URL (2a). Opening it **runs or reuses the viewer's own run** under the viewer's scope. No link exposes another user's run, rows or counts. An unauthorised viewer gets the same "not found" as for a missing report |
| **C. The result** (export or scheduled delivery) | Recipients as 2a §8.3–8.4 | Serialises **the owner's stored run**; recipients receive what the owner can see (the schedule sheet says so). Needs `reports.export`; external recipients need the allowed-domain confirmation and fresh MFA (2a §8.4, step-up) |

### 6.1 Recipients and permissions

- **Link (B):** recipient = any account holding `reports.run` and a scope that reaches the dataset;
  a recipient with no such right gets a clear "you do not have access to this report" (no data, no counts).
- **Definition (A):** recipients named as users or roles (not free addresses).
- **Result (C):** account recipients and e-mail recipients per 2a §8.4; the sheet states, per recipient
  type, whether they get the owner's view (attachment, link-to-stored-run) or their own (link B).
- A recipient's "Run now" on a link (B) is the one place the numbers may differ from what the sender
  saw; the screen states "numbers reflect your access".

### 6.2 Link vs export

| Need | Use |
| --- | --- |
| "Look at this live, in your own view" | Link (B), defaults to the most useful default for a colleague who can sign in |
| "Here is the data as I saw it, to people outside or to a file" | Export or schedule (C): CSV and XLSX of the grouped table, PDF and HTML including the **chart image and the table**, PNG of the chart alone |
| "Put it on my home page" | Not here; widget contract later |

### 6.3 Export of a chart

All formats serialise the **run's stored result** and carry the About block (definition, version,
SHA-256, `as_of`, freshness label, counts, scope narrowing). A PNG carries a footer with the same
facts so a pasted chart is traceable. Caps, encoders and formula safety are 2a §8.3 unchanged.

### 6.4 Schedule

A grouped report schedules and delivers exactly as 2a §8.4, including notify-only-if-data (a grouped
run with zero groups counts as no data). The delivery email shows the table, with the chart as an
image only if the renderer is on both profiles (Q3); otherwise an attachment.

## 7. Security and audit

- **Privileges.** Inventory read only. No directory write, no new directory right.
- **Permissions.** Grouping and chart editing under `reports.build` (2c §9); running and exporting under
  `reports.run` and `reports.export`. No new permission.
- **New abuse cases for `security-architect`** (build tickets tagged `security-sensitive`): (a) a shared
  definition that groups by a column to reveal a count the runner should not see (answer: trim before
  grouping, §3.3; column gating is registry-owned, 2c Q2); (b) a link (B) used to expose someone else's
  run (answer: no run id in the link, server selects the caller's run); (c) a chart image leaking through
  an externally delivered mail (answer: same step-up and domain rules as an attachment); (d) denial of
  service with 2 keys of high cardinality (answer: 1,000-group cap, key cardinality is evaluated at
  save and refused above `[PROPOSED]` 100,000 distinct values, with preview rate limits); (e) group
  labels carrying markup or formula text (answer: encoders, 2a §9).
- **Safe primitives.** SQL only through `store/reportsql` with registry identifiers and bound arguments.
  The `Group` node is compiled from typed fields; no string formatting.
- **Audit.** Events (actor, definition id, version, never values): grouping added or changed, chart
  attached or removed, link generated *only if* the product records link creation (it does not at v1;
  links are URLs), definition shared or unshared (2c), export of a grouped report (2a §8.6).

## 8. Out of scope

| Item | Goes to |
| --- | --- |
| Dashboards and widgets showing the chart (ADM-103) | Later slice; adopt via home-report-widgets §3.1 |
| Cross-source grouping, joins, computed expressions | Not planned |
| Pivot tables, calculated measures, secondary axes, scatter/heat maps | Not planned at v1 |
| Chart on shipped reports | After 2c, by the same `chart` part |
| Per-recipient scope re-run on scheduled delivery | 2a decision stands (owner's view) |
| Public (unauthenticated) links | Not planned |
| Management actions on a group | 2b (ADM-098) |

## 9. Functional requirements

| ID | Requirement | Parity |
| --- | --- | --- |
| FR-GC-01 | A definition MUST be able to carry one `Group` step with 1 or 2 registered group keys and up to 4 typed measures; no query text is accepted | ADM-097 |
| FR-GC-02 | Rows MUST be grouped after filter and scope trimming; group counts MUST equal the after-trim object counts | DM-71.I1 |
| FR-GC-03 | Date keys MUST take a bucket of day, week, month, quarter or year; measures MUST be restricted by column type | enhancement |
| FR-GC-04 | Missing values MUST form a "(none)" group; no row may be dropped | enhancement |
| FR-GC-05 | Output MUST be ≤ 1,000 groups; a cut-off MUST be announced as "1,000 of N groups" | enhancement |
| FR-GC-06 | The run header MUST carry object_count, group_count and groups_shown | 2a §8.1 |
| FR-GC-07 | A multi-valued column MUST NOT be offered as a group key | enhancement |
| FR-GC-08 | A group MUST drill through to the ungrouped report filtered by the group's key values | EB-5 |
| FR-GC-09 | A definition with a grouping MUST be able to carry one chart (bar, stacked bar, line, donut, table) bound to its keys and measures | EB-5 |
| FR-GC-10 | The product MUST offer only chart types the grouped result can draw, and MUST pre-select a suggested type | EB-5 |
| FR-GC-11 | Every chart MUST offer a table view with the identical numbers and a text description for assistive technology | accessibility |
| FR-GC-12 | A chart MUST read the stored run only and MUST show freshness, as-of and after-trim counts | LF-39 |
| FR-GC-13 | Chart labels MUST be encoded; no label may carry executable markup | 2a §9 |
| FR-GC-14 | Removing a grouping MUST remove its chart after confirmation naming it, and MUST NOT lose the ungrouped columns | enhancement |
| FR-GC-15 | A link to a report MUST carry no run id and MUST run or reuse the viewer's own run under the viewer's scope | DM-71.I1 |
| FR-GC-16 | A viewer without `reports.run` MUST get the same response as for a non-existent report | TM-TB3 |
| FR-GC-17 | Export and schedule of a grouped report MUST serialise the stored run, and MUST carry the About block and, for PDF, HTML and PNG, the chart | ADM-100, ADM-101 |
| FR-GC-18 | External delivery of a chart MUST follow the 2a step-up and allowed-domain rules unchanged | 2a §8.4 |
| FR-GC-19 | Chart rendering for export MUST give the same result on `windows` and `linux-oci` | platform |
| FR-GC-20 | Grouping and chart changes MUST create a new definition version and be audited with no values | X7 |

## 10. Acceptance criteria

"100k lab" = a seeded directory of 100,000 users; "1,600 group" = a group of 1,600 members.

```
AC-GC-01 (ticket acceptance 1; FR-GC-01, FR-GC-02, FR-GC-04)
Given Users source, 100k lab, 1,000 users with no department, runner scoped to one OU of 20,000 users
When the admin groups by department with measure count
Then every group's count sums to 20,000 (including "(none)"), no group counts a user outside the OU,
  and the header shows object_count 20,000 and the group_count
Evidence: API output; test group_counts_after_trim

AC-GC-02 (FR-GC-03)
Given the Users source and the "created" date column
When the admin groups by created, bucket month, and measure max(pwdLastSet)
Then one row per month with users appears, months with none are absent, and `sum` is not offered
  on a date column
Evidence: UI; test group_date_bucket_and_measure_types

AC-GC-03 (FR-GC-05)
Given a grouping that yields 3,000 groups
When it runs
Then 1,000 groups are returned, ordered by the sort, and the screen says "1,000 of 3,000 groups"
Evidence: UI; test group_cutoff_announced

AC-GC-04 (FR-GC-07)
Given the Groups source
When the admin opens the group-key list
Then the member list column is absent and the picker states "multi-valued"
Evidence: UI recording

AC-GC-05 (FR-GC-08)
Given a grouped report where "Finance" has 412 users
When the admin clicks the Finance bar
Then the ungrouped report opens with filter department = Finance, 412 rows, and a note if data changed
Evidence: UI recording; count equality

AC-GC-06 (ticket acceptance 2; FR-GC-09, FR-GC-10)
Given a grouping by department with count
When the admin opens the Chart tab
Then a bar chart is suggested, line is not offered (no date key), donut is not offered above 8 groups
  with the reason shown, and choosing bar then saving stores the chart in the definition version
Evidence: UI; API definition JSON

AC-GC-07 (FR-GC-11, FR-GC-13)
Given a chart whose label is a department named "<img src=x onerror=alert(1)>"
When it renders and is toggled to table
Then the label displays as text in both views, no script runs, and the numbers are identical
Evidence: browser test; axe scan

AC-GC-08 (FR-GC-12)
Given a grouped run from three hours ago
When the chart is shown
Then freshness label, as-of and counts equal the run header, and changing the chart type issues no
  new run and no directory query
Evidence: API log

AC-GC-09 (FR-GC-14)
Given a definition with a grouping and a chart
When the admin removes the grouping
Then a confirmation names the chart, and after accepting, the ungrouped columns return unchanged
Evidence: UI recording

AC-GC-10 (ticket acceptance 3; FR-GC-15, FR-GC-16)
Given user A with a wide scope and user B with a narrower one, both holding reports.run, and a link
  from A to a grouped report
When B opens the link
Then B sees the report run under B's scope, with B's counts and "numbers reflect your access", and no
  data or run of A; a user without reports.run gets the same response as for an id that does not exist
Evidence: API test link_runs_viewer_scope; response bytes compared

AC-GC-11 (FR-GC-17)
Given a finished grouped report with a bar chart
When the owner exports PDF, CSV and PNG
Then the PDF shows chart and table, the CSV the grouped table, the PNG chart and footer, all with the
  same run digest and as-of
Evidence: exported files; digest check

AC-GC-12 (FR-GC-18)
Given a schedule delivering a chart to an address outside the allowed domains
When the owner saves it
Then fresh MFA and a confirmation are required exactly as for any 2a schedule
Evidence: UI; API test

AC-GC-13 (FR-GC-19)
Given the same grouped report on the `windows` and `linux-oci` profiles
When PDF and PNG are exported from identical data
Then the images match within a pixel tolerance the architect sets
Evidence: CI image comparison

AC-GC-14 (FR-GC-06, empty/error)
Given a filter that matches no objects
When the report runs
Then the screen shows "No groups", counts 0, a chart empty state, and exports a valid empty file
Evidence: UI; export

AC-GC-15 (4.3)
Given a user with reports.build on the 100k lab
When they open an existing report and make "count per department" as a bar chart
Then it takes ≤ 5 interactions and ≤ 30 s
Evidence: timed recording

AC-GC-16 (FR-GC-20; audit)
Given a grouping and chart added then removed
When the audit trail is read
Then each change is an event with actor, definition id and version and no row values
Evidence: audit API
```

## 11. Open questions and hand-offs

- **Q1 (solution-architect):** confirm the `Group` node and the 1,000-group, 2-key and 4-measure limits; confirm
  `sum` and `avg` need column-level `Numeric` flags in the registry.
- **Q2 (reporting-engineer):** is key cardinality available at save time (§7 d)? If not, drop that check and rely
  on the cap and preview limits.
- **Q3 (solution-architect, devops-engineer):** chart-image rendering for PDF, PNG and mail on both profiles, and
  the licence of any renderer (licence register, rule 9).
- **Q4 (product-designer):** sign off the experience targets and the donut limit.
- **Q5 (market-analyst, research ticket):** what ME offers for grouping and charts in custom reports, with task
  clicks. Until then no parity claim for grouping.
- **Directional (for factory-director):** none new. The cut of EB-5 from 2c (2c spec Q4) is already in the
  open question there; this spec delivers the deferred slice and does not widen the scope.
