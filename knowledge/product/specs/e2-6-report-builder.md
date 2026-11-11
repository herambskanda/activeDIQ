---
title: "Spec: E2.6 report builder (checkpoint 2c; ADM-097 and its neighbours)"
date: 2026-11-11
updated: 2026-11-11
status: draft
revision: 2
owner: heramb
author: product-manager
reviewer: solution-architect
security-sensitive: true
ticket: off-board (m2c-plan)
epic: E-012
milestone: M2
parity: [ADM-096, ADM-097, ADM-098, ADM-099, ADM-100, ADM-101, ADM-102]
scope: locked
sources_last_checked: 2026-11-11
---

# Spec: E2.6 report builder

> An admin or an auditor builds a report of their own in one screen: picks what to report on, ticks
> the columns, adds conditions from pick-lists, groups and totals if they want a chart, sees real
> rows before saving, then saves, shares, schedules or acts on the rows. They never write a filter,
> a query or an attribute name, and what they build can never show anyone an object, a value, a
> count or an ordering outside that person's delegated scope.

This is the builder half of E2.6. The epic starts at checkpoint 2a with the library, export and
scheduling ([m2-plan](../../business/scoping/m2-plan.md) row E2.6); the **builder** is its checkpoint
**2c "Hybrid and import"** part ([roadmap-skeleton](../../business/scoping/roadmap-skeleton.md), row 2c:
"E2.6 (builder)"). ENH-05 is one of the CEO's five signature enhancements
([v1-scope-options](../../business/scoping/v1-scope-options.md);
[ENH-05](../../business/strategy/enhancement-catalog.md)). The spec inherits every rule of
[reports-2a](reports-2a.md) and [reports-2-second-slice](reports-2-second-slice.md) that it does not
change (library, run, scope, freshness, export, schedule, permissions, audit: FR-01 to FR-32, FR-S01 to
FR-S12) and adds the model, screens and rules for reports **users define**. DC audit-event reports are M3.

**Planning document** (CEO decision 2026-11-10, [decisions-log](../../memory/decisions-log.md)): no board,
ticket ID, lab or Entra tenant. Follow-ups are `FB-n` (one table, §17); what only a lab or tenant can
settle is `[LAB]` or `[DISCOVERY]`; what the research does not state is `[UNVERIFIED]`. ME behaviour comes
only from the [parity matrix](../../business/competitive-analysis/feature-parity-matrix.md) and the
[ADMP research](../../business/market-research/manageengine-admanager-plus.md); the ME custom-report page is
cited by the matrix but its detail is not in the research, so ME's builder beyond the matrix row is
`[UNVERIFIED]` until FB-1. Siblings: `e2-7-hybrid-provisioning.md` (owns Entra sync and datasets, §7) and
[e2-11-migration-importer.md](e2-11-migration-importer.md) (owns import classes, §11). Round 2 answers the
architecture and security rejections (§24).

## 1. Problem and users

ME's custom report is built from "an LDAP filter or raw LDAP query", filtering "on database fields", a
column picker "including custom attributes", attached management actions, categories, and
copy/share/delegate (matrix ADM-097). Report customisation limits are the #2 complaint theme, about 17
reviews: "custom reporting is somewhat limited", "old school bar charts", reports that "overflow from the
container" ([ENH-05](../../business/strategy/enhancement-catalog.md) quoting
[customer voice X2](../../business/market-research/manageengine-ad-customer-voice-and-security.md)). A
custom LDAP report builder is an RFP checklist item
([research §7a](../../business/market-research/manageengine-admanager-plus.md)). So a switcher's own custom
reports must come across (§11), and a builder that only matches ME's raw-filter model would carry ME's
problem (admins who do not know LDAP cannot use it) into our product.

| Persona | Job (what the 2a/second-slice library cannot do) |
| --- | --- |
| AD admin | When the library has no report for my question ("enabled users in OU X with no manager and a title containing Contractor"), I want to build it once, so I can rerun, schedule and act on it. The library is fixed (reports-2a FR-03) |
| Compliance auditor | When a control asks for evidence in its own shape, I want columns, filters, grouping and a chart I choose, so I can hand over one saved, scheduled report. No grouping or totals today |
| IT manager | When I need a monthly count by department or OU, I want a grouped report with a chart that mails itself, so I can see a trend without an admin. No aggregates or charts today |
| Help-desk technician | When my lead shares a report, I want to run it and, if my role allows, act on the rows, inside my own OUs only |
| Security/SOC analyst | When I hunt (privileged accounts with old passwords, stale service-like accounts), I want to save and schedule the hunt |

Which custom reports matter most is `[DISCOVERY]` (no partner discovery has returned); the importer (§11)
reads the customer's real custom reports and re-weights the registered column list.

## 2. Which parity rows are in the 2c slice

Rows from the matrix, ADM-083 to ADM-103 (importance · stance · size · priority as the matrix states).

| ID | ME feature (edition) | Matrix | In 2c? | Where / why |
| --- | --- | --- | --- | --- |
| **ADM-097** | Custom report builder (edition not stated) | must · leapfrog · L · P1 | **In, core** | §5 to §10 |
| **ADM-096** | Report from CSV (Std+Pro) | should · parity · S · P1 | **In, first to cut** | FR-B17: GUID and DN lists need no new primitive; other identifiers need FB-6b |
| **ADM-098** | Act on report results (Std+Pro) | must · enhance · S · P1 | **In for builder reports** | FR-B16. The grid's bulk bar is the 2b spec's (reports-2a §11); this adds shortcuts, the run-bound selection contract and grouped-row drill-down |
| **ADM-099** | Scope and filters (Std+Pro) | must · parity · S · P1 | **Inherited** | reports-2a FR-06, FR-07; the builder adds user conditions |
| **ADM-100** | Export (Std+Pro) | must · parity · S · P1 | **Inherited** | reports-2a FR-16 to FR-22. CSVDE, password protection, logo stay T-1017 |
| **ADM-101** | Scheduled reports (Pro) | must · enhance · M · P1 | **Inherited**, plus version pinning | FR-B14 |
| **ADM-102** | Report-level delegation (edition not stated) | should · parity · S · P1 | **Partial** | FR-B11, FR-B12: a "Custom" category a role can allow, plus sharing. The per-report role editor is the delegation epic's |
| ADM-103 | Custom-report dashboard widgets | could · parity · S · P1 | **Out** | No dashboard surface in 2c. A saved report gets a stable ID and chart definition so a widget can bind later (FB-9) |
| ADM-093 | Compliance report sets | must · enhance · M · P1 | **Out** | "Later E-012 slice" (reports-2a §11): content work with legal weight (ENH-15) |
| ADM-083 to 092 | Prebuilt library | various | **Out** (2a, second slice) | The builder **clones** them (FR-B10) |
| ADM-094 | Microsoft 365 reports (P4) | should · parity · M · P4 | **Out as content**; the builder reads the Entra datasets **E2.7 registers** (§7) | No Entra dataset is defined here |
| ADM-095 | Google Workspace reports | could · defer | **Out** | Matrix: defer |
| ADA-101 | ADAP custom, aggregate, profile reports (P2) | must · enhance · M | **Partial** | Grouping/aggregates over directory and activeDIQ-audit data; DC events are M3. Matrix: "Same builder as ADM-097" |

## 3. ManageEngine parity baseline for ADM-097

| ME capability (matrix ADM-097, research §K) | activeDIQ | Same / differs |
| --- | --- | --- |
| LDAP filter or raw LDAP query | A typed condition tree over registered columns (§5). **No filter or query text is accepted by any builder screen or API** | **Differs** (D2). An ME filter arrives through the importer, parsed once and classed (§11) |
| Filter on "database fields (e.g., bad-password count, days since password set)" | Registered **derived columns** (reports-2a §6.4), filterable like any column | Same capability, no syntax |
| Column picker "including custom attributes" | Picker over registered columns; extra attributes join through the sync set (FR-B03) | Same, with a stated sync delay |
| Attach management actions | Saved shortcuts that start an ADR-0005 Operation with preview and undo (FR-B16) | Same, safer path |
| Categories; copy, share, delegate | Category "Custom" plus labels; clone, share to accounts, roles or tenant, run under the **runner's** scope | Same; sharing never shares data |
| Advanced scheduler for custom reports | The 2a scheduler for any saved report, in every tier | Same / better (§4) |
| How ME runs it (cache or live LDAP), operator set, condition limit | `[UNVERIFIED]` | FB-1 |

## 4. What we do better than ADMP (all v1; each tied to a sourced pain)

| # | Enhancement | Measurable claim | Source of the weakness |
| --- | --- | --- | --- |
| E-B1 | **No syntax, live preview** | 3 conditions built, previewed and saved with **0 typed filter strings**; the preview (rows plus match count) completes within the §14 budget before Save. ME baseline `[UNVERIFIED]` (FB-2) | Raw LDAP filter in ADM-097 (matrix); customisation limits #2, about 17 reviews (X2) |
| E-B2 | **Grouping, totals, interactive charts from the same stored rows** | "Count by <field>" with a bar chart in **≤ 6 interactions**; chart numbers equal the stored group rows (AC-B20) | "old school bar charts", "somewhat limited" (X2 via ENH-05) |
| E-B3 | **Act on the rows with preview and undo** | Select, choose Action, see the per-object diff, confirm; undoable from its audit record (ADR-0005) | ME rollback needs the per-user Backup add-on (research §7c, ADM-153) |
| E-B4 | **Scheduling for custom reports in every tier** | A schedule for any saved report with no edition flag (AC-B24) | ME scheduled reports are Pro only (matrix ADM-101) |
| E-B5 | **A migrated custom report lands editable, with a diff** | Fidelity row `exact`, `changed` (with diff), `manual` or `not supported`; target share set by E2.11 against lab ADMP 8043 | ME has no template export; its backup is a proprietary `.ezip` (research, Resolved gaps) |

Not claimed: fresher data than ME (its cache syncs every 10 minutes, research §7c, W6). Ours state `as_of`
on every view and export (reports-2a FR-08): honesty, not speed.

## 5. The model: a typed, allow-listed grammar (the answer to domain-model Q5)

Q5 asked how admin filters map onto inventory datasets versus a live scoped search. Answer: **the builder
never queries a directory and never accepts query text**. A custom report is data: a stored
`CustomDefinition` (FB-3a; not the shipped library type of reports module §3.4) with `origin` custom,
cloned or imported, one dataset, columns, a condition tree, sorts, optional grouping and parameters. It
runs through the same `Resolve` → `reportsql.Compile` → `report_run_rows` path as a shipped report
(ADR-0010).

**Source.** One registered dataset: `inventory.users`, `.computers`, `.groups`, `.group_members`, `.ous`,
`.contacts`, the second slice's `object_changes`, `policies`, `printers`, and the §7 sources. No joins in
v1: related facts (manager's name, member counts, "group outside your scope") are registered columns over
compiler-scoped anchors (reports module §3.3).

**Fields.** A registered `Column`: ID, label, type (`text`, `int`, `bool`, `time`, `enum`, `guid`, `text
list`), accepted operators, sortable, `groupable`, `aggregatable`, a freshness source and an optional
**read permission** (FB-3a). The picker is built from the registry, searchable, with a description and a
"from the last sync" or "computed now" tag. A field the runner may not read is not offered and, if a saved
report uses it, is refused (FR-B12). A secret attribute is never a field (D8, X4). Attributes beyond the 2a
columns join through FR-B03; the second slice's first list (e-mail, employee ID, department, title, company,
telephone, mobile, [§5.5](reports-2-second-slice.md)) is what the examples here use.

**Conditions.** A tree of `And` / `Or` / `Not` over `Cmp{field, operator, value-or-parameter}` within the
limits of §9, using reports module §3.2's closed operators:

| Field type | Operators offered (only those the column registers) |
| --- | --- |
| text | is, is not, is one of, contains, starts with, has a value, is empty |
| int | =, ≠, <, ≤, >, ≥, is one of, has a value, is empty |
| bool | is |
| time | before, after (absolute); within the last N days; older than N days; within the next N days; has a value; is empty |
| enum | is, is not, is one of (values from the column's enum, never typed) |
| guid (manager, group, OU, subject) | is, is not, is one of, has a value, is empty; values from a picker (§9 L5) |
| text list (for example SPN) | has a value, is empty, contains an element equal to |

Values are typed constructors (`TextV`, `IntV`, `TimeV`, `EnumV`, `GUIDV`); NUL or invalid UTF-8 is
refused; `contains` and `starts with` become bound `LikePattern` values (P5 rule 4), never SQL. Relative-time
operators take whole days and honour a column floor (30 days on replicated logon, reports-2a §6.4). A
`GUIDV` is stored as a GUID **without a label** (FR-B29). **Not in v1:** column-to-column comparison,
arithmetic, formulas, regular expressions, functions; a "computed" column is a dataset owner's reviewed
fragment, not an admin's text.

**Grouping and totals (needs FB-3a).** Up to 3 **group keys** (enum, bool, text, guid-with-label, or `time`
bucketed by day, week, month, quarter, year). Bucket boundaries use the time zone recorded on the run
(interactive: the runner's profile zone; schedule fire: the schedule's stored zone), and the zone is part
of the query hash. Up to 8 **aggregates**: `count`, `count distinct <field>`, `min`/`max` (time, int),
`sum`/`avg` (int). An optional **minimum group size** (on `count`), Top N (≤ 1,000) and a **grand total over
all matching in-scope rows**, not the groups shown (the table says "k of n groups shown" when a minimum or
Top N hides some). Over 10,000 groups is refused, naming the cause and the fix. Three rules make it safe:

1. **Post-scope, post-mask.** Scope and masking apply before any group, aggregate, sort, Top N or chart
   bucket, in the same statement. Group keys, aggregate inputs, `count distinct`, sort keys and chart buckets
   operate on the **masked cell value the runner would see**, never the raw value (FR-B28). Masked identities
   (a manager, group or policy outside scope) are one value, "(outside your scope)": one bucket per
   column. A guid-with-label key takes its label from the masked related column. An OU key is the row's own
   container; ancestors are named only from the row's own `dn` (reports module DN disclosure rule). A column
   on a `MaskAnchor` or `Via` is `groupable` only on its masked rendering.
2. **Unknown stays Unknown.** An aggregate over a group holding any Unknown input cell (registry
   `UnknownWhen`: another object's hidden time or size) is Unknown, shown "Unknown", never computed from the
   raw value. The minimum applies to `count` only, which is always known.
3. **Refusals are post-scope.** The 10,000-group check, the "1,000+" flag and every error class are evaluated
   on in-scope, masked rows, so none is a one-bit oracle on hidden objects.

**Match count.** The run's cursor statement returns the match count beside the stored rows (`count(*) OVER
()` with `LIMIT cap+1`) and stores it as a typed run field (FB-3b); the total row of a grouped result comes
from the same statement (grouping sets). No path issues a separate count statement (ADR-0010 rule 3).

**How it compiles (rule 5).**
1. The console builds a JSON `ReportAst` of registry IDs, enum IDs, GUIDs and typed values. The OpenAPI
   schema has **no string member interpreted as query, filter, expression or SQL** (fitness RP-B1), save the
   one allow-listed intake below.
2. `Resolve` refuses an unknown column, an operator the column does not accept, a missing parameter, a value
   under a floor, anything over a §9 limit, and **re-authorises every `GUIDV` and parameter default for the
   runner** (FR-B29). Errors are `ValidationError{Code, Path}` and never echo a value or name an object.
3. `reportsql.Compile` renders SQL from pre-quoted registry identifiers, fixed keywords and numbered `$n`
   arguments. The runner's `ReadScope`, from `rbac.ReadScopes.For` only, is rendered into the `WHERE` by
   `planScope`/`scopeSQL` before any condition, group, sort or limit; the admin's narrowing is AND-ed on top.
4. Rows are stored as `report_run_rows`. Pages, sorts, chart data, exports, the digest and deliveries read
   them and never re-query.

**The only two places text from outside the grammar enters; neither reaches a directory or database as
text.** (1) The **E2.11 file intake**: an uploaded ADMP file whose LDAP filter is parsed once by the
admin-filter parser (safe-primitives P1: strict RFC 4515, whole input consumed, canonical re-rendering) into
this tree or classed (§11); the text is kept only as inert, escaped evidence. RP-B1 allow-lists this one
operation by name. (2) The importer's **sync-set suggestion** carries an attribute name taken from a hostile
file. The Action's input is not that text but a reference to an `attributeSchema` entry in the connection's
live schema, resolved server-side: a name matching no entry is refused, a match passes the schema-driven
`SecretAttrs` predicate (safe-primitives §3.7, LF-38), and the Action shows its preview (FR-B03).

## 6. The build flow

One page, `/reports/builder` (IA §3, "Builder 2c"), preview always on screen. Patterns: single page with a
left rail of steps, data table, side sheet. Rows are the units for `product-designer` (FB-7).

| # | Admin does | System shows | Pattern |
| --- | --- | --- | --- |
| 1 | Presses `/`, types "new report", opens Reports › Builder, or clones from any report's menu | Source picker: only datasets the admin can read, each with `as_of` and a description. A clone arrives filled | Search overlay; card list |
| 2 | Picks a source | Default columns and the preview at once. Header: scope applied, freshness, "n rows match, in your scope" (the preview's match count) | Data table |
| 3 | Adds/removes **fields** by search, drags order, sets sort | Preview refreshes in place (debounced ≥ 500 ms `[PROPOSED]`); an unreadable field is absent, not greyed | Column chooser |
| 4 | Adds **conditions**: field, operator, value (pickers for dates, enums, OUs, groups, managers) | Header count and rows update per edit; each condition has Remove; `And`/`Or` are indented blocks. No per-condition counts (one count per preview, §9) | Filter builder |
| 5 | Optionally **groups and totals**: keys, aggregates, minimum, Top N, chart (bar; line for time buckets) | Group table with chart above, both from the same stored rows; "Show rows" starts a detail run | Grouped table, chart |
| 6 | Reads the **preview** | Up to 1,000 stored rows, match count or "1,000+", `as_of`, Unknown notes, any refused item with its reason | Preview run (§9) |
| 7 | **Saves** (name, description, labels) | `reports.definition.create` Action inline: diff, then version 1 published, opened in My reports | Sheet; ADR-0005 rule 10 |
| 8 | **Share**, **Schedule**, **Export**, **Act** | 2a schedule sheet (external-recipient confirmation); sharing sheet; bulk bar (FR-B16) | Side sheets |

**The admin never has to:** write or paste a filter or query; know an attribute's LDAP name or whether it is
synced; pick a domain before seeing data; click Generate; guess whether a number is scoped.

**Unhappy paths (each is an AC):** no `reports.build` (entry absent; by URL 403); no readable source (empty
state, not error); a connection never synced ("Not synced yet: <connection>", others run); a field or picked
value that became unreadable (§8); too many groups; over the row cap; preview superseded; stale connection;
10k and 100k sources; a group with more than 1,500 members.

## 7. Data sources at 2c, and which wait

| Source | Datasets | At 2c | Depends on |
| --- | --- | --- | --- |
| On-prem AD objects | `inventory.users`, `.computers`, `.groups`, `.group_members`, `.ous`, `.contacts` (reports-2a D1 to D3) | **Yes** | 2a |
| AD history, policies, printers | `inventory.object_changes`, `.policies`, `.printers` (second slice) | **Yes, each when its batch has shipped**; an unshipped one is not listed | second slice |
| AD extra attributes | Registered `JSONAttr` columns for attributes in a connection's sync set (FR-B03) | **Yes** | FB-8 |
| activeDIQ's own audit trail (**not** DC security events, which are M3) | `audit.events` (DM-70), **restricted columns**: time, kind, outcome, operation reference, target kind, actor kind. **No actor or target display name, no `details`, no personal value** (DM-80.I4: display snapshots are erasable and must not be copied into stored rows) | **Yes if `platform/audit` registers it before the 2c build**; otherwise the next slice. Not a blocker | FB-5 |
| Entra users, groups, licence assignments | Datasets that **E2.7 registers**: it owns Graph delta sync into inventory and the dataset names, columns and correlation columns (E2.7 §7.6 "Entra inventory sync and report datasets", FR-36 to FR-38; FB-11). **This spec defines none** | **Gated.** A source appears only when E2.7 has registered it **and** the scope evaluator renders the Entra roots (`entra_tenant`, `administrative_unit`, `group_members`). Until then reports-2a §8.1 applies: such a scope grants nothing and the empty state names the reason | E2.7; **FB-4**, the Entra scope-root dependency shared with E2.7 (E-011 / T-1131, ADR-0011 rule 9) |
| One person across AD and Entra | Only columns E2.7 registers showing the **matched** correlation (DM-20.I4); never a cross-dataset join | Only if E2.7 defines them | E2.7 |
| Entra devices | Not a dataset unless E2.7 syncs them | No | E2.7 |
| Per-DC values (USR-04, PWD-03), SYS-03 | Not stored datasets (reports-2a §6.5) | **No**, library-only | later |
| DC security events; file servers, Exchange, GPO, NTFS | | **No** | M3; E3.6, M5, E-008 |

`audit.events` visibility (FB-5 builds it): readable only with the audit-read permission; events with no
directory target (sign-in, RBAC, settings) need **tenant-wide** audit-read; a target-bearing event shows to a
scoped audit reader only when every target is in their read scope.

## 8. Ownership, lifecycle, sharing and RBAC

**Ownership and lifecycle.** The creator owns a custom report: a `report_definitions` row (owner
`modules/reports`) with immutable **versions**. One model (DM-71 `draft → published → archived`):
- **Editing state lives in the browser.** Previews store *run rows*, never a definition. Nothing is stored
  before Save.
- **Save publishes version n+1.** A run records `definition_id`, version and SHA-256 (reports module §3.6);
  a preview records the AST hash instead (FB-3b); a schedule pins its version.
- **A server-side `draft` exists only for an applied import** (§11.3): private, unshared, unschedulable.
- **No hard delete in v1** (DM-71 has none): `archive` hides, `restore` returns it to `published`; runs expire
  by retention. Origin: `custom`, `cloned` (source ID and version), `imported`. Shipped definitions stay
  immutable (DM-71.I2).
- Every write is an EP-3 Action (ADR-0005 rule 10): `reports.definition.create | update | share | unshare |
  archive | restore | reassign`, each with preview diff, audit and undo; undoing an update publishes a new
  version equal to the previous one.

**Permissions** (proposed IDs for `api-engineer`; the first three exist from 2a):

| Permission | Allows |
| --- | --- |
| `reports.run`, `reports.export`, `reports.schedule` | As reports-2a §8.5; unchanged for custom reports |
| `reports.build` | Create, edit and clone own custom reports; run previews |
| `reports.share` | Share own reports with accounts, roles or the tenant; `edit` access needs it too |
| `reports.manage_all` | See **metadata** of any custom report (name, owner, dataset, description, labels, versions, share targets, counts of columns and conditions); archive or reassign it. **Never opens rows or files, and never shows condition values or picked-object labels** |

**Sharing.** Default private. Targets: accounts, roles, or "everyone with `reports.run`". *Run* (open, run,
export, schedule their own) or *Edit* (create a version; the editor becomes a co-owner in the audit). A
recipient always runs the report **under their own scope and permissions**; sharing never shares data
(DM-71.I1, LF-39, reports-2a decision 5). A URL carries no data. A role target means whoever holds the role at
open. Unsharing takes effect on the next open; stored runs the recipient already made expire normally.

**What a recipient may and may not see (FR-B12, FR-B29).**
- A dataset they cannot read: the report is absent from lists and search; by ID, 404.
- A **display column** whose field they cannot read: omitted, header "2 columns not available to you".
- A **condition, sort, group key or aggregate** on such a field: the run is **refused** (`column_not_permitted`,
  field only). Dropping it would change the meaning; honouring it would let presence or order reveal the value.
- A **picked value** (`GUIDV`, parameter default) they cannot read: the run is refused (`value_not_permitted`,
  condition *path*, no object named). The editor shows "(object outside your scope)". Labels resolve at display
  under the **viewer's** scope, so a recipient never sees the owner's GUIDs or labels.
- An **Edit-level** sharee's save is validated against the **editor's** permissions.
- A **schedule fire** re-applies both refusals under the owner's *current* permissions and fails closed:
  delivery fails with a reason; no condition or column is dropped.
- Scope kinds the evaluator does not support grant nothing; the empty state names the reason.
- Whether a role's attribute allowlist (DM-34) constrains **read** as well as write is `[UNVERIFIED]` (FB-3d).
  Until settled the builder trusts dataset permission plus the registry's per-field read permission.

Text values the owner typed (for example "Finance") are the owner's disclosure and a recipient can read
them: an accepted residual (§16).

**Category delegation (ADM-102, partial).** All custom reports are in category "Custom"; a role's *report
categories* constraint (DM-34) can allow or deny it. Per-report restrictions are done with sharing.

**Orphans.** If the owner is disabled or deleted, schedules pause (2a rule); `reports.manage_all` can reassign
or archive; reassigning pauses schedules until the new owner resumes them after seeing the recipients
(reports-2a §8.4).

**A new version and a live schedule.** A schedule runs the version it pinned. Moving it to a newer version is
a `reports.schedule.update` Action whose preview shows the **column and condition diff** (labels under the
owner's scope) and repeats the external-recipient confirmation, so a newer version cannot widen what recipients
get without the owner's visible act (TM-TB15-T2).

## 9. Preview, runs, caps and the large-directory cases

**Preview is a run** of the unsaved `ReportAst`, `class = preview` (FB-3b), through the same `Resolve`,
`Compile`, scope and `report_run_rows`: at most 1,000 stored rows, retention 1 hour, superseded (expired) by a
newer preview from the same account. ADR-0010 writes rows while `running` and reads once `succeeded`, so a
preview is complete or absent. It has its **own statement timeout** (10 s `[PROPOSED]`, against the run's
15 minutes) and caps. If the windowed count cannot finish, the preview is re-issued **once** rows-only
(`LIMIT 1001`, no count) and the header says "1,000+"; if that also times out the preview fails as "too
heavy". A page and its count never come from different statements.

**Limits** (refuse and explain, never truncate; run numbers inherit reports-2a §8.3). `Resolve` enforces
this one table:

| Limit | Value |
| --- | --- |
| Columns · condition terms · depth · sort keys | 64 · 32 · 8 · 4 |
| `is one of` values (also the ADM-096 list size) | 1,000 |
| Group keys · aggregates · Top N · groups | 3 · 8 · 1,000 · 10,000 `[PROPOSED]` |
| Rows stored per run, CSV/XLSX · PDF · HTML | 1,000,000 · 5,000 · 20,000 |
| Custom definitions per tenant · per account | 2,000 · 200 `[PROPOSED]` |
| Versions kept | all; latest 20 shown `[PROPOSED]` |
| Previews: running per account · per tenant · rate | 1 (a newer one supersedes) · 2 · 30 per minute per account `[PROPOSED]`; apart from the 4-job cap for scheduled runs |
| Statement time | run: P5 SQL-22; preview: 10 s `[PROPOSED]`. A timeout is a typed failure, "too heavy", never a partial result |

**Aggregates, sort and exports can never leak scope** (FR-B30's property test covers all of it):
- **L1** Scope and masks come before any group, aggregate, sort or limit, so every group, count, minimum,
  sum or chart bar uses in-scope, masked values only (LF-39, §5 rules 1 to 3).
- **L2** A count of *other* objects (members, children) is a registered `Count` column over a masked anchor
  (RP11); there is no free aggregate over a related object.
- **L3** Sort keys are limited to readable fields, and stored `sort_keys` come from the same masked values.
- **L4** `Top N` applies after sort over scoped rows, so it does not depend on how many hidden rows exist.
- **L5** Guid pickers list only objects the runner can read **under `reports.run`**, the scope the report runs
  under (FB-6a; today ADR-0011 rule 10 fixes search to `directory.read`, so this is not yet true). Whatever a
  picker offers, `Resolve` re-authorises the value at every run (L6), so a picker can never put an unreadable
  value into a result; until FB-6a ships the picker shows only what `directory.read` already shows that account
  in global search (residual, §16). An unreadable GUID sent to the API answers "not found", as a nonexistent one.
- **L6** Every `GUIDV` and parameter default is re-authorised at every `Resolve` (run, preview, drill-down,
  schedule fire, comparator, validate-only).
- **L7** Groups and total come from **one statement**; a total can never disagree with its groups.
- **L8** Exports serialise stored rows only, with the 2a encoders, caps and digest; a group row's `row_key` is
  the canonical hash of its key values (FB-3b).

## 10. Act on results (ADM-098) through the ADR-0005 pipeline

The grid's bulk bar and first Actions are the 2b spec's. The builder adds the following and changes nothing in
the pipeline.

1. **Eligibility.** The dataset declares an *action subject* (object kind and the GUID column(s) identifying
   it; FB-3a) and the rows are objects or edges. Grouped rows are not actionable: "Show rows" starts a **new
   detail run by the actor**, then acts.
2. **Selection contract (never raw GUIDs).** The API takes `{run_id, row_keys[] | all_matching}`. The server
   re-derives the targets: it reads the selected rows from `report_run_rows` of that run and takes each row's
   subject identity through the dataset's `ActionSubject`. The run must be the actor's own, `succeeded` and
   unexpired (else 410, "run again") and pass the scope-fingerprint check of DM-72.I5 (else 409, "Your access
   changed since this run"). `all_matching` means every row of that run, bound to its stored `row_count`; a
   different count is refused. A row whose identity cell is masked or Unknown is not a target and is counted as
   skipped. A request carrying GUIDs is refused (400).
3. **Start.** One Operation, origin `report_results`, records `run_id`, the run digest and `as_of`. The bar
   offers only catalogue Actions that accept the subject kind and that the account may plan. A saved report can
   carry **shortcuts** (`attached_actions`, DM-71) shown first; a shortcut is not a grant or an automation.
4. **The pipeline decides, not the report.** Plan re-checks authorisation live per target at Plan and again at
   Apply (ADR-0005 rule 7, DM-35), fails closed on `unknown`, skips `tier0` (DM-35.I5), and lists a target that
   moved out of scope, changed or vanished as "n of m targets changed since the report ran", with reasons and
   the run's `as_of`.
5. **Limits and gates.** `max_batch` and `csv_allowed` apply (above the limit Plan refuses and says how many);
   workflow gate and step-up as for any Operation; preview diff, per-item results, verify and undo are the
   pipeline's.
6. **No unattended acting.** A schedule delivers a report; it never starts an Action (ADM-104, 2d).
7. **Audit.** The run, the Operation and each item link by ID; the run's event records row count and digest,
   the Operation's records the targets; no values.

## 11. How a migrated ADMP custom report lands (with E2.11)

[E2.11](e2-11-migration-importer.md) owns intake, hostile-file limits, classification, the fidelity report and
proposal-then-apply. This spec defines only the target grammar and what the builder offers. The four classes
are E2.11's: `exact`, `changed`, `manual`, `not supported`.

1. **Proposal.** A custom-report proposal (E2.11 §6.2) carries a `ReportAst` of this schema with
   `ast_version`, the ADMP name and category, and the source in a fidelity row. No effect until applied (TM-D21).
2. **Filter conversion.** E2.11 §6.5 says a filter becomes the typed tree or `not supported`; this spec refines
   that, compatibly, with the classes below (FB-10: E2.11 AC-12 cites this list). The importer maps each ADMP
   attribute to a registered column by LDAP display name.
   - `exact`: every attribute, operator and **object class** maps with the same meaning. Example:
     `(&(objectCategory=person)(objectClass=user)(department=Finance))` to Users, `department is Finance`
     (the users dataset is exactly that class pair).
   - `changed` (with diff): same intent, different representation or a narrower result. Examples: the bit test
     `(userAccountControl:1.2.840.113556.1.4.803:=2)` becomes the registered *enabled* column; `memberOf` becomes
     the direct-membership column; `(objectCategory=person)` alone becomes Users and no longer matches contacts.
   - `manual`: a valid attribute that is not registered (one click, "Add `<attribute>` to the sync set",
     FR-B03, then conversion re-runs; no value is guessed), **and any script-bearing content**, kept as inert
     escaped text with no code path (E2.11 §6.5, AC-11).
   - `not supported`: a matching rule or construct with no registered equivalent, raw SQL, a secret attribute,
     a cross-dataset reference. Reported, never dropped silently.
3. **Apply.** An Action needing `reports.build` **and step-up** (E2.11 §6.3), by an admin, never the importer's
   identity. The report lands as a server-side **`draft`** (§8): private to the applier, unshared, unscheduled,
   with a banner "Imported from ADMP: n items changed, m need review" and the diff. The applier may open it and
   run **previews** (their own scope); nobody else sees it, and it cannot be shared, scheduled, exported or
   run in full. **Save** publishes version 1.
4. **Never imported:** script bodies, raw SQL, credentials (E2.11 §6.4). ADMP's attached tasks are not carried
   over, by this spec's own rule: an Action binding is a privilege decision, so the admin re-attaches a
   shortcut by hand (§10).
5. **Schedules** land **disabled**, recipients shown, external ones flagged (E2.11 §6.6, TM-TB18-T9), with
   owner `manageengine` so they **cannot run** until the step-up switch of E2.11 §6.8; enabling is then the 2a
   schedule Action with its confirmation.
6. **Exposed to the importer:** (a) the `ReportAst` schema and a stable version; (b) a **validate-only** call
   with per-path errors and class reasons, writing nothing; (c) the attribute-to-column map; (d) a run API for
   the parallel-run comparator (advisory, Plan-only, E2.11 §6.8). All go through `Resolve` (RP-B2).
7. **Fidelity bar.** The share converting `exact` or `changed` on lab ADMP 8043 is E2.11's acceptance number.
   `[LAB]` fixtures come from the trial install (FB-2).

## 12. Differences from ME chosen on purpose

| # | Difference | Why |
| --- | --- | --- |
| D1 | One dataset per report, no joins | A join in a user-built query is a way around per-anchor scope. Revisit with FB-3c |
| D2 | No raw LDAP or SQL, no paste-to-convert box | Rule 5. The importer is the only parser |
| D3 | No user-defined computed column or formula | Computed columns are reviewed fragments (reports module §3.3) |
| D4 | A shared report runs under the recipient's scope and re-authorises every picked value | Sharing never shares data |
| D5 | A filter/sort on a field, or a picked value, the runner cannot read refuses the run | Silent dropping changes meaning; honouring leaks |
| D6 | An unsynced attribute reads "Not synced yet", never "empty" | Unknown is not none (reports-2a §6.4) |
| D7 | Minimum schedule interval 1 hour; no save-to-path; no mail-body | Unchanged from 2a (§11) |

## 13. Experience target (with `product-designer`, FB-7)

Counted by [top-admin-tasks-benchmark](top-admin-tasks-benchmark.md) §1.2 (interactions / typed fields /
screens). It has no custom-report task, so **ME baselines are `[UNVERIFIED]`**, measured on the ADMP trial lab
(FB-2) as rows T21 to T25. Targets `[PROPOSED]`:

| Task | Target |
| --- | --- |
| T21 Build and save "enabled users in an OU, no manager, with name/title/department" (3 conditions, 4 columns) | **≤ 14 interactions / ≤ 2 typed fields (name, OU search) / 1 screen**, preview visible throughout |
| T22 Clone a library report, add one column and one condition, save | ≤ 7 / ≤ 1 / 2 |
| T23 "Count by department" as a bar chart, from a saved source | ≤ 6 / 0 / 1 |
| T24 Share a saved report with a role | ≤ 4 / 0 / 1 |
| T25 Select all matching rows of a saved report and start "Disable" through to the Plan preview | ≤ 5 / 0 / 2 (step-up extra) |

Every step is reachable by keyboard; the picker opens on `/` inside the builder.

## 14. Performance budgets

`[PROPOSED]`, for `reporting-engineer` to calibrate on the scale tier (B13 pattern).

| Operation | 10,000 objects | 100,000 objects |
| --- | --- | --- |
| Source list, field picker, operator list | ≤ 200 ms | ≤ 200 ms (registry, independent of data) |
| Guid value picker (manager, group, OU) | ≤ 200 ms | ≤ 200 ms (ADR-0011 rule 14 class) |
| Preview complete: stored rows (≤ 1,000) and match count (≤ 5 conditions) | ≤ 2 s p95 | ≤ 5 s p95 |
| Grouped preview (3 keys, 8 aggregates, total row) | ≤ 2 s p95 | ≤ 5 s p95 |
| Full run, stored rows ≤ 100k | ≤ 3 s | ≤ 15 s |
| Re-sort, page, change chart type (stored rows) | ≤ 500 ms | ≤ 500 ms |
| Drill-down from a group | as a preview | as a preview |
| `group_members`, group with 6,000 members: first page | ≤ 5 s | ≤ 5 s (reports-2a §5) |

A group with more than 1,500 members: the edge dataset contributes every edge (reports-2a FR-15, FR-S07);
a builder report on it is tested at 6,000.

## 15. States and exact messages

| State | Message / behaviour |
| --- | --- |
| No `reports.build` | Builder entry absent; Library, My reports, Shared with me still shown if `reports.run` |
| No readable source | "Your role covers no directory objects. Ask an administrator to grant a scope." Zero rows, not an error |
| Empty result | "No users match in your scope, as of 09:41, 3 domains." Each condition offered for removal |
| Loading | Skeleton rows and "Previewing…" with cancel; a newer edit cancels the previous preview (the old one is discarded silently) |
| Preview truncated | "At least 1,000 users match. The saved report stores up to 1,000,000." |
| Stale or never synced | Banner as reports-2a §8.2; the builder still works on other connections |
| Unsynced attribute | Cell "Not synced yet" and a header count; a filter on it says "n users not yet read" |
| Unreadable field | "You can't use <field> in a condition." (run refused); display column omitted with "2 columns not available to you" |
| Unreadable picked value | "A value in this report is outside your scope." with the condition path; the editor shows "(object outside your scope)" |
| Unknown aggregate | Cell "Unknown", tooltip "Depends on objects outside your scope" |
| Too many groups | "This grouping would make more than 10,000 groups. Pick a coarser field, for example month instead of day." |
| Over the cap | "This report has 1.4 million rows. The stored result allows 1,000,000. Narrow the conditions." |
| Too heavy | "This report took too long and was stopped. Narrow the scope or the conditions." No partial rows |
| Too many previews | "Too many previews. Wait a moment." |
| Failure; imported, unreviewed; scope changed | Typed reason and Retry; banner of §11.3; 409 "Your access changed since this run. Run again." (reports module §6.6) |

## 16. Security and audit

- **Directory rights.** Inventory read only; no new directory right, no directory write. Adding an attribute
  to a sync set widens what the connector **reads**, so it is a connection setting changed by an Action with the
  connection's rights check; the attribute comes from the live schema, and a secret or confidential one is
  refused by the schema-driven `SecretAttrs` set (safe-primitives §3.7, LF-38). Entra reads come with E2.7's
  Graph permissions.
- **Tier-0.** Reports may list Tier-0 objects (reports-2a §9); acting on them is blocked by the pipeline
  (DM-35.I5).
- **Safe primitives.** Report SQL only from `store/reportsql` with registry identifiers and bound arguments
  (FF-SP4, SP-P5); LIKE only through `LikePattern`; scope only from `rbac.ReadScopes.For`; GUIDs and DNs only
  through pickers or the `dn` package; export bytes only from the P7 encoders. Titles, descriptions and labels
  are attacker-controlled text and go through the formula, HTML and file-name encoders everywhere (console,
  About block, e-mail subject, attachment name). No user-defined column labels in v1.
- **Abuse cases.** (1) A technician builds a report to see objects, values, counts or ordering outside scope:
  AC-B08, B09, B38, B40. (2) A shared report with a picked value the recipient cannot read: AC-B13, B39.
  (3) A schedule on a broad report to an outside address, or a version swap: AC-B25, B45. (4) A hostile value or
  title: AC-B27. (5) Probing and denial of service: AC-B19. (6) A secret read through "custom attributes",
  including a hostile importer suggestion: AC-B05, B43. (7) A forged selection or a stale or foreign run used to
  act: AC-B41. (8) A hostile ADMP file: AC-B28 and E2.11's limits.
- **Audit (our own).** One event per item, never values: actor, definition and version (a preview, its AST
  hash), scope summary, row count and digest. Every "filters hash" and "query hash" is an **HMAC under a
  per-tenant salt** (as `digest_salt`, DM-24.I5), so low-entropy filter values cannot be brute-forced by audit
  readers. Definition events: created, updated, shared, unshared, archived, restored, reassigned, cloned,
  imported; run, export, download and schedule events as reports-2a §8.6. **A preview is one light
  `reports.preview.run` event per preview run**, listing field, operator, group-key and aggregate IDs and the
  HMAC. Events are chained at commit (ADR-0005 rule 11, DM-80.I1), so there is no roll-up and no ADR-0005
  amendment; the per-account rate (§9) bounds chain volume. FB-5 registers the kind.
- **Residuals accepted.** Owner-typed text values are readable by anyone the report is shared with. Until
  FB-6a ships, a picker offers what `directory.read` shows the account in global search. A statement timeout
  reveals only tenant data volume, not objects.
- **Tags.** `security-sensitive` on every build ticket for: the `reportsql` grouping change, the definition
  store and sharing, the selection contract and act-on-results hand-off, the `audit.events` dataset, the
  per-field read permission and the sync-set widening.

## 17. Follow-ups this spec needs (one table; the project-manager maps `FB-n` to ticket IDs)

| # | Follow-up | Owner | Clears |
| --- | --- | --- | --- |
| FB-1 | Research: ME custom-report mechanics (operators, condition limit, cache or live, "database fields", delegate, advanced scheduler) | `market-analyst` | Q1 |
| FB-2 | ADMP trial lab: baselines T21 to T25 and custom-report fixtures for the importer | `product-designer`, `market-analyst` | Q2, §11.7 |
| FB-3a | **[modules/reports.md](../../development/architecture/modules/reports.md) amendment** (§3.2 anticipates it): stored `CustomDefinition` (table, owner, origin, `ast_version`, versions, shares) and how `Resolve` takes it; `Custom` category and ID namespace; group-key, aggregate, minimum, total nodes; `groupable`/`aggregatable` flags and Unknown propagation; `ActionSubject`; per-field read permission; validate-only entry | `solution-architect`, `reporting-engineer` | R-M2, B-B1 |
| FB-3b | **New ADR extending or superseding ADR-0010** (technical, director-ratified; ADR-0010 is accepted and not edited): (1) match count in the run's one cursor statement as a typed run field, no separate `CompileCount`; (2) run class `preview`: 1 h retention, supersede-expiry (the `succeeded → expired` edge exists), own caps; (3) group and total rows: `row_key` = canonical hash of key values, a row-kind marker for the total row, digest and export coverage, totals in the same statement (grouping sets), no snapshot option; (4) a run of an unsaved definition: AST hash and typed AST instead of definition ID, version and hash. RP3 to RP5 stay green | `solution-architect` | R-B1, R-M1 |
| FB-3c | Security review of the grouping renderer; fitness **RP-B1** (no free-text member except the one allow-listed intake), **RP-B2** (run, preview, drill-down, validate-only, comparator all through `Resolve`), **RP-B3** (non-interference property test, FR-B30) | `security-architect` | B-B1, B-M1, B-m1 |
| FB-3d | Domain model: DM-71 (`cloned`, `imported`, `ast_version`, grouping in `ast`, server-side `draft` for imports, no delete); DM-72 (run class, AST hash, match count, time zone); DM-34 allowlist read/write meaning; Q5 answered by §5 | `ad-expert`, `backend-engineer` | R-M7, Q4 |
| FB-4 | **Entra scope roots**: renderer for `entra_tenant`, `administrative_unit`, `group_members` (m2-plan E-011, T-1131). **Shared with E2.7** and ADR-0011 rule 9; both specs cite it | `backend-engineer` (delegation) | X-2 |
| FB-5 | `platform/audit`: register `audit.events` with the §7 columns and visibility; an erasure ruling before any personal column; register the `reports.preview.run` kind (EP-7) | `security-architect`, audit owner | R-M3, R-M4 |
| FB-6a | **ADR-0011 amendment** (ratified, so an amendment): `inventory.Search` takes a caller-named permission so a picker is trimmed under `reports.run`, with an SE3-style test. Replaces the unproven "no amendment" claim | `solution-architect` | R-M5 |
| FB-6b | ADM-096 exact batch resolver `inventory.ResolveIdentifiers` (≤ 1,000 values, one statement through `scopeSQL`; GUID and DN; DNs via the `dn` package; never `CompileSearch` or trigram). Without it FR-B17 stays GUID/DN | `solution-architect` | B-m2 |
| FB-7 | Design: builder, group table with chart, share sheet, Plan hand-off | `product-designer` | Q3 |
| FB-8 | Sync-set additions spec: who may add which attribute, permissions, backfill, freshness label | `product-manager`, `directory-engineer` | Q9 |
| FB-9 | Dashboard widget binding to a saved report (ADM-103) | later | §2 |
| FB-10 | E2.11 one-line cross-reference: AC-12 cites e2-6 §11.2 as the target grammar; confirm §6.3 step-up and §6.8 lock as used here | E2.11 owner | X-3 |
| FB-11 | **Done in E2.7 round 2:** §7.6 "Entra inventory sync and report datasets" (FR-36 to FR-38, AC-43) covers Graph delta sync, the three datasets, columns, correlation columns and root kinds. E2.6 only consumes | E2.7 author | X-1 |
| FB-12 | Migration `-- write-class` lines: `report_definitions`, `report_shares`, `report_definition_actions` are `config` (ADR-0005 rule 10, a widening decision); not an O3 `system` writer. No ADR-0005 amendment | `backend-engineer` | R-m10 |

## 18. Platform matrix

`✓` supported · `◐` partial as stated · `✗` not in this slice, with the follow-up · `n/a`. The builder is
server-side and reads inventory: **no DC-side or Windows-native component is added**, so no Windows Server
version of an added component applies. Managed DCs are Windows Server 2016 to 2025 (ADR-0002). No new
functional-level requirement (derived columns keep reports-2a §10's note). `windows` and `linux-oci` behave
identically (ADR-0002 rule 1); the Windows-profile GA gate is reports-2a §10. 2c is demoed on the profile
m2-plan names.

| FR group | AD on-prem WS2016 to 2025 | Entra cloud-only | Hybrid synced objects | Samba AD (CI lab) | Console | REST API | PowerShell module | `windows` | `linux-oci` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| B01 to B07 model, fields, conditions, sort | ✓ | ✗ → FB-4, FB-11 | ◐ AD side now; Entra when E2.7 registers | ✓ | ✓ | ✓ | ◐ follows the API, no cmdlet spec | ✓ | ✓ |
| B03 custom attributes | ✓ any attribute the connector reads | ✗ → E2.7 | ◐ AD attributes only | ✓ plain LDAP | ✓ | ✓ | ◐ | ✓ | ✓ |
| B06, B15, B28 grouping, totals, charts, masked values | ✓ | ✗ → same | ◐ AD side | ✓ | ✓ | ✓ | ◐ | ✓ | ✓ |
| B08 to B10 preview, save, versions, clone | ✓ | ✗ → same | ◐ AD side | ✓ | ✓ | ✓ | ◐ | ✓ | ✓ |
| B11 to B13, B29, B30 sharing, scope, non-interference | ✓ AD scope kinds of 2a; others grant nothing | ✗ → FB-4 | ◐ | ✓ | ✓ | ✓ | ◐ | ✓ | ✓ |
| B14 run, export, schedule reuse | ✓ | ✗ → same | ◐ | ✓ | ✓ | ✓ | ◐ | ✓ | ✓ |
| B16 act on results | ✓ Actions that exist then (2b set) | ✗ → E2.7 Actions | ◐ AD Actions; cloud with E2.7 | ◐ writes testable on Samba as in 2b; Windows-only effects `[LAB: Windows]` | ✓ | ✓ | ◐ | ✓ | ✓ |
| B17 report from list | ✓ GUID, DN; more with FB-6b | ✗ → same | ◐ | ✓ | ✓ | ✓ | ◐ | ✓ | ✓ |
| B18 migrated ADMP reports | ✓ (E2.11 matrix) | ◐ AD-only constructs `not supported`, never dropped | ◐ | ✓ file tests; ADMP DB tests need the lab `[LAB]` | ✓ | ✓ | ◐ | ✓ | ✓ |
| B19 to B24, B27 search, states, limits, audit, budgets, API, encoding | ✓ | ◐ for sources E2.7 registers; none before | ◐ | ✓ | ✓ | ✓ | ◐ | ✓ | ✓ |
| B25 Entra gating | n/a | ◐ source appears after E2.7 registers it and FB-4 ships | ◐ same | n/a | ✓ | ✓ | ◐ | ✓ | ✓ |
| B26 `audit.events` source | ✓ activeDIQ's own data | ✓ own data, independent of the Entra tenant | ✓ | ✓ | ✓ | ✓ | ◐ | ✓ | ✓ |

Samba results prove the plumbing and the LDAP-readable truth; what only a real Windows DC settles stays
`[LAB: Windows]` and is reported separately.

## 19. Functional requirements

Each FR names a parity ID or `enhancement`. Cite as `e2-6-report-builder#FR-B07`. MUST/SHOULD/MAY as RFC 2119.

| ID | Requirement | Parity |
| --- | --- | --- |
| FR-B01 | The builder MUST list only registered datasets whose data the user may read, each with `as_of` and freshness, and MUST NOT reveal the existence of a dataset or report the user cannot read | ADM-097 |
| FR-B02 | A field MUST be a registered column chosen from a picker. No builder screen or API operation of this spec MAY accept an attribute name, column name, expression, or filter, query or SQL text as free text; the only text-bearing operation is the allow-listed E2.11 file intake (§5). A secret attribute MUST NOT be a field | ADM-097 |
| FR-B03 | An admin with the connection permission MUST be able to add a directory attribute to the connection's sync set (an Action with preview). The input MUST be a reference to an `attributeSchema` entry of the live schema (a name matching none is refused); the Action MUST refuse a secret or confidential attribute by the schema-driven `SecretAttrs` set; an importer suggestion MUST use this Action. Until a full sync completes the cell MUST read "Not synced yet", never empty | ADM-097 |
| FR-B04 | Conditions MUST be a tree of And/Or/Not over `Cmp` with only the operators the column registers, typed values and named parameters, within §9's limits; relative-time operators MUST honour column floors | ADM-097, ADM-099 |
| FR-B05 | Every custom run (full, preview, drill-down, validate-only, importer comparator) MUST go through `Resolve` and `reportsql.Compile`. The OpenAPI schema MUST contain no free-text query, filter, expression or SQL member except the one allow-listed intake, and the server MUST NOT accept LDAP filter text or SQL from a builder client | DM-71.I3, rule 5 |
| FR-B06 | The builder MUST support up to 3 group keys, 8 aggregates (`count`, `count distinct`, `min`, `max`, `sum`, `avg`), a minimum group size, Top N and a grand total over all matching rows, all computed after scope and masking with groups and total in one statement, and refused above 10,000 groups with a reason | ADM-097, ADA-101 (partial) |
| FR-B07 | Columns (≤ 64), their order and a sort (≤ 4 keys on readable fields) MUST be user-set; column order MUST be the export and digest order | ADM-097, ADM-099 |
| FR-B08 | The preview MUST be a flagged run of the unsaved definition (≤ 1,000 stored rows, 1-hour retention, superseded by the account's next) whose match count MUST come from the same statement as its rows; "1,000+" MUST appear only after the rows-only fallback. It MUST obey the §9 preview caps (1 running per account, 2 per tenant, 30 per minute, 10 s timeout) and MUST NOT show a half-filled page | enhancement (E-B1) |
| FR-B09 | A save MUST publish an immutable version through a `reports.definition.*` Action with preview diff, audit and undo (a new version equal to the previous). The browser MUST hold editing state; a server-side `draft` MUST exist only for an applied import; there MUST be no hard delete. Runs MUST record definition ID, version and hash (a preview, its AST hash); a schedule MUST pin its version | ADM-097, ADM-101 |
| FR-B10 | Any report, shipped or custom, MUST be cloneable to a new custom report with the source recorded; shipped definitions MUST stay immutable | ADM-097 |
| FR-B11 | A report MUST default private. It MAY be shared with accounts, roles or the tenant at *Run* or *Edit* level by a holder of `reports.share`. A recipient MUST run it under their own scope and permissions; an Edit-level save MUST be validated against the editor's permissions; unsharing MUST take effect on the next open | ADM-097, ADM-102 |
| FR-B12 | A condition, sort, group key or aggregate on a field the runner may not read MUST refuse the run (`column_not_permitted`); a display column MUST be omitted with a count; an unreadable dataset MUST answer 404. A schedule fire MUST apply this under the owner's current permissions and fail closed, dropping nothing | ADM-102, DM-71.I1 |
| FR-B13 | The runner's scope MUST be rendered inside the query before any condition, group, sort or limit; counts, group sizes, totals, charts, pages and exports MUST be computed after trimming. An unsupported scope kind MUST grant nothing and the empty state MUST name the reason | ADM-099, LF-39 |
| FR-B14 | Custom reports MUST use the run, freshness, export, schedule, permission and audit rules of reports-2a FR-06 to FR-32 unchanged. Moving a schedule to a newer version MUST show the column/condition diff and repeat the external-recipient confirmation | ADM-099, 100, 101 |
| FR-B15 | A grouped result MUST offer a bar chart (a line chart for a time-bucketed key) drawn from the stored group rows, with accessible values (table toggle, labels); charts MUST NOT trigger a query | enhancement (E-B2) |
| FR-B16 | A selection MUST be `{run_id, row_keys[] or all_matching}` and MUST NOT accept GUIDs. The server MUST re-derive targets from the stored rows of an own, unexpired run whose scope fingerprint still matches (else 410/409), start one Operation with origin `report_results` recording run ID and digest; Plan MUST re-check authorisation live per target, report changed targets, and obey `max_batch`, gates, step-up and undo. A grouped row MUST act only through a new detail run. A schedule MUST NOT start an Action | ADM-098 |
| FR-B17 | A user MAY supply a list (paste or CSV, ≤ 1,000 identifiers, ≤ 256 KiB, UTF-8) of GUIDs or DNs (more kinds with FB-6b) resolved **exactly** under the runner's scope, never by fuzzy or trigram matching; unresolved values MUST be counted as one bucket "not found in your scope" | ADM-096 |
| FR-B18 | The builder MUST accept an importer proposal of this schema, expose the validate-only call and the attribute-to-column map, and on a step-up apply land a private, unshared, unscheduled `draft` with a review banner (previewable by the applier only; version 1 on Save). It MUST classify with §11.2's classes, land imported schedules disabled with owner `manageengine`, and NOT import attached actions or script text | ADM-097, E2.11 |
| FR-B19 | A shared or own custom report MUST be findable by name in `/` search under Reports, trimmed by permission, and listed under My reports and Shared with me | enhancement |
| FR-B20 | Every builder screen MUST show the empty, error, loading, stale, partial and over-cap states of §15 with no fake data and no control that does nothing | house rule 6 |
| FR-B21 | The limits of §9 MUST be enforced and MUST refuse and explain, never truncate | TM-TB15-T8 |
| FR-B22 | Definition, share, preview, run, export and schedule events MUST be audited as §16 (one event per preview run, HMAC hashes), with no values | TM-TB15-T6 |
| FR-B23 | The budgets of §14 MUST be met on the scale tier | enhancement |
| FR-B24 | Every behaviour MUST be an OpenAPI operation first with one `x-permission`, and the console MUST use only the generated client | ADR-0004 |
| FR-B25 | A source from E2.7 MUST appear only when E2.7 has registered it and the scope renderer supports its root kinds; this spec MUST define no Entra dataset | ADM-097 |
| FR-B26 | If `platform/audit` registers `audit.events`, the builder MUST expose it with §7's restricted columns (no display name, no `details`), only to holders of audit-read, with §7's scoping | ENH-05 |
| FR-B27 | Report titles, descriptions and labels MUST be encoded wherever they are rendered, exported or mailed | TM-TB15-T1 |
| FR-B28 | Group keys, aggregate inputs, `count distinct`, sort keys and chart buckets MUST be computed over the masked cell value the runner would see; masked identities MUST form one bucket per column; an aggregate over any Unknown cell MUST be Unknown; group-cardinality and error decisions MUST be evaluated post-scope | ADM-097, LF-39 |
| FR-B29 | A definition MUST store GUIDs without labels. Every `GUIDV` and parameter default MUST be re-authorised for the runner at every `Resolve`; an unreadable one MUST refuse the run (`value_not_permitted`, condition path only). Labels MUST resolve under the viewer's scope; `reports.manage_all` metadata MUST contain no condition value or picked-object label | ADM-102, DM-71.I1, LF-36 |
| FR-B30 | A runner's output (rows, counts, totals, sort order, group keys, chart buckets, export bytes, and the error or refusal class and its timing class) MUST be identical across worlds that differ only in objects and attributes outside their scope | ADM-097, LF-39 |

## 20. Acceptance criteria

Ground truth is a computed value over the lab seed (Samba AD) unless stated; `[LAB: Windows]` items are
reported separately until run. **No AC claims a match with ManageEngine's output.** Evidence names the artefact
`qa-verifier` produces; 100k and 10k seeds are the reports-2a scale-tier seeds. The table after the list traces
every FR to its ACs.

```
AC-B01 (FR-B01)
Given an account with reports.build and read scope over domain A only, and datasets users, groups and audit.events registered
When the source picker opens
Then it lists users and groups with as_of, and not audit.events or any dataset the account cannot read
Evidence: API test list_sources_by_permission; screenshot
AC-B02 (FR-B02, FR-B05)
Given the OpenAPI document and the console
When the schema is linted and every builder input inspected
Then no member accepts query, filter, expression or SQL text except the one allow-listed E2.11 intake operation, a request carrying such a member elsewhere is refused (400, unknown member), and no input accepts an attribute name
Evidence: fitness RP-B1 green (allow-list is exactly one operation); API test hostile_members_refused; UI input inventory
AC-B03 (FR-B02)
Given the field picker for users
When the admin searches "mgr" and "pass"
Then registered fields with matching labels are listed with type and freshness tag, and no secret attribute appears
Evidence: API test picker_lists_registered_only; registry boot test (secret JSONAttr key refused)
AC-B04 (FR-B03)
Given an admin adds the schema attribute "extensionAttribute3" to a connection's sync set through the Action
When the preview is confirmed and before the next full sync completes
Then the field is listed with the right type, existing users show "Not synced yet" (not blank), a condition on it states "n users not yet read", and after the sync values equal an LDAP read of the lab
Evidence: lab test sync_set_addition; screenshots of both states; LDAP ground truth
AC-B05 (FR-B03)
Given attempts to add msFVE-RecoveryPassword, a LAPS password attribute, unicodePwd, and a seeded custom attribute with only searchFlags 0x200
When the Action is planned
Then each is refused with the reason "secret attribute" and nothing is read or stored
Evidence: Action plan test secret_attribute_refused (4 attributes, schema-driven set)
AC-B06 (FR-B04, FR-B05)
Given conditions: department is one of ["Finance","R&D)(uid=*"], displayName contains "*)(cn=*", displayName contains "50%_\", and password last set older than 90 days
When the report runs
Then the hostile strings are data (% _ \ match literally, LDAP metacharacters match nothing, no error beyond "no match"), the run SQL holds only numbered arguments for them, and the result equals an independent query on the seed
Evidence: injection test builder_hostile_values; captured compiled statement (arguments, not text); ground truth
AC-B07 (FR-B04)
Given a text column that registers only [is, contains, has a value] and a request using "starts with"
When the definition is validated
Then Resolve refuses it with code operator_not_allowed and Path, echoing no value
Evidence: unit test resolve_operator_per_column
AC-B08 (FR-B06, FR-B13)
Given a technician scoped to OU=Sales (5,000 users), an admin with the whole domain (100,000 users), and the same saved report "Users by department" with count
When each runs it
Then the technician's groups and counts sum to 5,000 and contain no department without a user in OU=Sales; the admin's sum to 100,000
Evidence: lab test grouped_counts_equal_scope_oracle; two screenshots
AC-B09 (FR-B13, FR-B06)
Given the technician above and an out-of-scope user in OU=HR with title "CFO" and the newest replicated logon in the domain
When the technician runs title = "CFO", then Top 10 by replicated logon descending, then a report grouped by title
Then the first returns 0 rows and the same text as any non-matching value, the second holds only in-scope users and the same ten rows however many hidden users have newer logons, and the third has no "CFO" group
Evidence: lab test side_channel_matrix; oracle comparison over AuthorizeRead
AC-B10 (FR-B12, FR-B11)
Given a report shared Run-level with a technician whose role cannot read "employeeID", with employeeID as a display column, a second report filtering on it and a third sorting by it
When the technician opens the three, and an Edit-level sharee without that permission tries to save a version using it
Then the first runs with the column omitted and header "1 column not available to you"; the second and third are refused with column_not_permitted naming employeeID, with no row, count or hint; the save is refused
Evidence: API tests column_not_permitted_matrix (3), edit_save_checks_editor; screenshots
AC-B11 (FR-B09)
Given a saved report at version 1 with a schedule
When the owner saves an edit
Then version 2 exists, version 1 is unchanged and runnable, runs record the version used, the schedule still runs version 1, and the Action preview diff listed the change
Evidence: API test versions_immutable_schedule_pinned; audit events with versions
AC-B12 (FR-B09)
Given version 2 of a report
When the owner undoes the update from the audit record
Then version 3 equals version 1's definition and no version is deleted
Evidence: Action undo test report_definition_undo
AC-B13 (FR-B11)
Given a report shared Run-level from an admin (whole domain) to a technician (OU=Sales)
When the technician opens it, copies the URL to the admin, and the admin opens it
Then the technician's rows are in-scope only, the admin sees the admin's rows, neither URL carried data, and unsharing makes the report disappear for the technician on the next open
Evidence: API test share_runs_under_recipient_scope; two run records with different scope_applied
AC-B14 (FR-B10)
Given library report USR-03 and the clone action
When the admin clones it
Then a custom report with origin cloned, the source ID and version, the same columns and conditions exists; USR-03 and its file hash are unchanged
Evidence: RP7 unchanged; API test clone_keeps_source
AC-B15 (FR-B08, FR-B23)
Given 100,000 users and a builder session editing a condition three times in 5 seconds
When the edits settle
Then only the last preview is readable, earlier ones are expired, each stored at most 1,000 rows, the match count is exact and from the same statement as the rows (the statement log shows one cursor statement per preview, no separate count), and the preview completes within the §14 budget
Evidence: scale-tier test preview_supersede (p50/p95); report_run_rows row counts; statement log
AC-B16 (FR-B08, FR-B21)
Given the same source and a preview whose windowed count does not finish within the 10 s preview timeout
When the timeout fires
Then the preview is re-issued once rows-only and shows "1,000+" with its rows and no estimated number; if that also times out it fails as "too heavy" with no rows
Evidence: fault-injection tests count_timeout_fallback, preview_timeout_too_heavy
AC-B17 (FR-B06)
Given 100,000 users in 2,000 departments and a report grouped by department with count and max(replicated logon)
When it runs
Then it has 2,000 group rows, each count and max equals an independent query, the grand total equals 100,000 and the sum of group counts, and groups and total come from one statement (a concurrent writer test)
Evidence: lab test group_totals_one_statement; statement log
AC-B18 (FR-B06, FR-B21)
Given a group key with more than 10,000 distinct in-scope values
When the report runs
Then it fails with the "too many groups" message naming the field and a coarser choice, and stores no rows
Evidence: API test group_cardinality_refused
AC-B19 (FR-B21, FR-B08)
Given 5 concurrent previews from 3 accounts of one tenant (one account sending a second while its first runs), a 31st preview in a minute from one account, and a scheduled run due
When all run
Then at most 2 previews execute per tenant, the account's first is superseded by its second, the 31st is refused "Too many previews", the scheduled run starts on time, and a statement over its timeout fails as "too heavy" with no partial rows
Evidence: job-cap tests preview_cap, preview_rate; timeout test
AC-B20 (FR-B15)
Given a report grouped by month with count, a bar chart and a line chart
When the admin changes chart type and exports the table
Then no new run is created, the chart values equal the stored group rows, the table toggle shows the same numbers, and the export's digest equals the run's digest
Evidence: network log (no query); RP5 digest test; axe check on the chart
AC-B21 (FR-B16)
Given a saved report "Enabled users inactive 180 days" with 50 rows, the Action "Disable user", and an account that may disable users in its scope
When the account selects all 50 and chooses the Action
Then one Operation with origin report_results records the run ID and digest, its 50 targets were derived from the stored rows, the Plan shows a per-object diff and as_of, an out-of-scope or tier0 target is listed as refused with the reason, and after confirm and step-up the Operation is undoable from its audit record
Evidence: Operation test report_results_plan_apply_undo; Plan screenshots
AC-B22 (FR-B16)
Given 3 of the 50 rows changed after the run (one moved out of scope, one already disabled, one deleted)
When the Plan is created
Then it states "3 of 50 targets changed since the report ran" with each reason, plans the other 47, and authorises live again at Apply
Evidence: lab test plan_recheck_changed_targets
AC-B23 (FR-B16)
Given a role with max_batch 20 and a selection of 50
When the Action is chosen
Then Plan refuses with "this role allows 20 at a time; 50 selected", and a schedule on the same report starts no Operation
Evidence: Plan test max_batch_refused; schedule test no_action_from_schedule
AC-B24 (FR-B14, FR-B24)
Given a custom report and an account holding reports.schedule
When the account picks Monthly 1st 08:00 and an internal recipient
Then the schedule is created through the Action with a preview and appears under Schedules, with no edition or tier flag in the request
Evidence: API test custom_report_schedule; screenshot
AC-B25 (FR-B14)
Given a schedule on version 1 with an external recipient, and a new version that adds three columns
When the owner moves the schedule to the new version
Then the Action preview shows the three added columns and repeats the external-recipient confirmation, the confirmed address is in the audit event, and each fire still runs under the owner's scope
Evidence: Action test schedule_version_update_diff
AC-B26 (FR-B17)
Given a CSV of 1,000 GUIDs and DNs (900 in scope, 60 outside, 40 nonexistent), a CSV of 1,001, and a list holding a near-miss name
When the first is used as "Match list" and the others submitted
Then the first resolves 900 objects and reports "100 not found in your scope" (one bucket) equal to the seed, the second is refused before any read, and the near-miss name matches nothing (no fuzzy fallback)
Evidence: API tests match_list_buckets, match_list_cap, match_list_no_fuzzy
AC-B27 (FR-B27)
Given a report titled "=HYPERLINK(...)" with description "<script>x</script>", labels with markup, and a column value "=cmd|' /C calc'!A0"
When it is listed, opened, exported (CSV, XLSX, PDF, HTML) and mailed
Then every place shows inert text, spreadsheet cells are neutralised, the file name comes from the download-header encoder, and the e-mail subject is encoded
Evidence: encoder corpus test builder_hostile_titles; screenshot of each format
AC-B28 (FR-B18)
Given an E2.11 proposal set: the filter (&(objectCategory=person)(objectClass=user)(department=Finance)), one with the UAC bit test, one with a nested-group matching rule, one with a secret attribute, one with raw SQL, one with a script
When they are validated and applied
Then they classify exact, changed (with diff), not supported, not supported, not supported and manual, none is applied silently, the script and secret rows carry only inert escaped text, and validate-only wrote nothing
Evidence: importer test custom_report_classes; fidelity row export
AC-B29 (FR-B18)
Given an imported report with an ADMP schedule and an external recipient
When the report is applied
Then the schedule is disabled, the recipient flagged external, owner manageengine, it refuses to run, and cannot be enabled without the step-up switch and the Action's confirmation
Evidence: E2.11 tests with TM-TB18-T9 and §6.8 assertions
AC-B30 (FR-B25)
Given E2.7 has not registered an Entra dataset, and then has
When the source picker opens in each state
Then the first state lists no Entra source; the second lists it only for an account whose scope can be rendered (entra_tenant, administrative_unit or group_members), and an account with an unsupported scope kind sees the empty state naming the reason; the reports registry defines no Entra dataset itself
Evidence: API test entra_source_gating; screenshot of the reason; registry test no_entra_dataset_in_reports
AC-B31 (FR-B26)
Given audit.events registered, a technician with directory scope only, an auditor with scoped audit-read, and an auditor with tenant-wide audit-read
When each opens the source picker and runs the source
Then the technician sees no audit source; the scoped auditor sees only events whose every target is in scope and none without a directory target; the tenant-wide auditor sees all; no run holds a display name, a details field or a personal value
Evidence: API test audit_source_columns_and_scope; stored-row scan for display names
AC-B32 (FR-B19)
Given a custom report "Contractors without manager" shared with a technician
When the technician searches "contractors" in /
Then it appears under Reports with "Shared by <owner>"; an unshared account does not see it
Evidence: search API test; screenshot
AC-B33 (FR-B20)
Given each builder screen
When shown empty, loading, stale, failed, over the cap, with an unreadable value, and at 100,000 rows
Then each state matches §15, every control works, and no number is placeholder text
Evidence: screenshots of each state; click-through log by qa-verifier
AC-B34 (FR-B13, FR-B23)
Given 10,000 and 100,000 users, a group of 6,000 members and a builder report on group_members
When the report runs
Then the group contributes all 6,000 edges, the first page appears within the §14 budget, and the count equals the LDAP ground truth
Evidence: scale-tier timings; LDAP ground truth
AC-B35 (FR-B22)
Given a session with 12 previews in 8 minutes, one save, one share, one export
When the audit trail is read
Then there are 12 reports.preview.run events (each with an HMAC filter hash and field, operator and group-key IDs, no values) plus one each for create, share and export, none carrying values, and the hash chain verifies
Evidence: audit query test; chain verification
AC-B36 (FR-B07)
Given a request with 65 columns, one with 5 sort keys, and a saved report with columns reordered
When each is validated, run and exported
Then the first two are refused naming the limit, and the export column order and digest order equal the saved column order
Evidence: API tests columns_sort_limits, column_order_is_export_order
AC-B37 (FR-B24)
Given the OpenAPI document and the console source
When the contract lint and generated-client check run
Then every builder operation has exactly one x-permission, and the console has no hand-written HTTP call
Evidence: contract lint builder_x_permission; ADR-0004 client fitness green
AC-B38 (FR-B28)
Given a technician scoped to OU=Sales (40 users) whose users have 7 managers (3 in scope, 4 in OU=HR), and reports grouped by manager with count, with count distinct manager, with max of the manager's replicated logon, and grouped by OU path
When the technician runs each
Then the first has 4 buckets (3 named managers and one "(manager outside your scope)"), count distinct is 4 not 7, max is Unknown for any group whose manager is out of scope and never a hidden value, and OU keys name only each user's own container
Evidence: tests group_by_masked_column_single_bucket, count_distinct_masked_related, aggregate_over_unknown_is_unknown, ou_key_own_container
AC-B39 (FR-B29)
Given an admin's report "Reports of manager = <HR director>" shared Run-level to a Sales technician who cannot read the HR director, a technician-owned schedule on it, and an account with reports.manage_all
When the technician opens the condition editor, runs, previews, drills down, the schedule fires, and the manage_all account reads the metadata
Then the editor shows "(object outside your scope)", each run and the fire are refused value_not_permitted with the condition path and no object name or row, and the metadata shows no condition value or label
Evidence: tests shared_guid_value_unreadable_refused, shared_definition_label_masked, manage_all_metadata_labels_masked, schedule_fire_guid_value_rechecked
AC-B40 (FR-B30)
Given a seeded property test drawing reports from the full grammar (every registered column, conditions, up to 3 group keys, aggregates, minimum, Top N, sorts, parameters, GUIDV) over pairs of worlds that differ only in out-of-scope objects, their attributes, and in-scope objects' links to out-of-scope objects (link existence constant)
When each report runs as an own run, a shared run by a lower-scoped recipient, a preview, a drill-down and a schedule fire, and is exported
Then rows, counts, totals, sort order, group keys, chart buckets, export bytes and the error or refusal class and timing class are identical across each pair, the oracle equality over AuthorizeRead also holds, and the deliberately failing fixtures (a raw-GUID group key, a pre-scope cardinality check) are caught
Evidence: rp_b3_noninterference (seeded, PostgreSQL, in CI) with its two failing-fixture runs
AC-B41 (FR-B16)
Given an actor with a stored 50-row run, another account's run, an expired run, a run whose scope fingerprint changed, and a grouped result
When the actor posts raw GUIDs, then {run_id, row_keys} for each run, then all_matching with a wrong count, then acts on a grouped row
Then the GUIDs are refused (400), the foreign run is refused, the expired run answers 410, the changed fingerprint 409, the wrong count is refused, the grouped row acts only through a new detail run by the actor, and the Operation records the run ID and digest
Evidence: tests act_selection_rejects_raw_guids, act_on_foreign_run_refused, act_on_expired_410, act_after_scope_change_409, all_matching_bound_to_row_count, drilldown_is_new_run_by_actor
AC-B42 (FR-B23)
Given the 10,000 and 100,000 seeds
When the picker, a grouped preview (3 keys, 8 aggregates, total row), a 100k-row full run, a re-sort and a chart change are timed
Then each meets its §14 row at p95
Evidence: scale-tier timings table (p50/p95) against §14
AC-B43 (FR-B03, FR-B05)
Given importer suggestions naming "x)(cn=*", an attribute absent from the schema, and a real secret attribute
When each is submitted to the sync-set Action
Then the first two are refused "not in schema" with no directory or SQL string built from the text, the third is refused as secret, and the hostile text appears only escaped in the fidelity row
Evidence: tests sync_set_suggestion_hostile_name, sync_set_suggestion_unknown_attr; FF-SP1 green
AC-B44 (FR-B09, FR-B18)
Given an applied import and a published report
When the applier previews the draft, another account opens it by ID, the applier tries to share, schedule and export it and then saves it, and the owner archives and restores the published report and looks for a delete
Then the draft previews for the applier only, the other account gets 404, share, schedule and export are refused until Save, Save publishes version 1, archive and restore keep every version, and no delete operation exists in the API or console
Evidence: tests import_draft_lifecycle, archive_restore_keeps_versions; OpenAPI has no delete operation
AC-B45 (FR-B12, FR-B14)
Given a schedule pinned to a version that groups by a field the owner has since lost permission to read
When the schedule fires
Then delivery fails with a reason naming the field, no partial or reduced report is sent, and the audit event records the refusal
Evidence: test schedule_fire_fails_closed
```

| FR | AC | FR | AC | FR | AC |
| --- | --- | --- | --- | --- | --- |
| B01 | B01 | B11 | B10, B13 | B21 | B16, B18, B19 |
| B02 | B02, B03 | B12 | B10, B45 | B22 | B35 |
| B03 | B04, B05, B43 | B13 | B08, B09, B34 | B23 | B15, B34, B42 |
| B04 | B06, B07 | B14 | B24, B25, B45 | B24 | B24, B37 |
| B05 | B02, B06, B43 | B15 | B20 | B25 | B30 |
| B06 | B08, B09, B17, B18 | B16 | B21, B22, B23, B41 | B26 | B31 |
| B07 | B36 | B17 | B26 | B27 | B27 |
| B08 | B15, B16, B19 | B18 | B28, B29, B44 | B28 | B38 |
| B09 | B11, B12, B44 | B19 | B32 | B29 | B39 |
| B10 | B14 | B20 | B33 | B30 | B40 |

## 21. Out of scope

| Item | Goes to |
| --- | --- |
| Reports over DC security events | M3 (event pipeline) |
| Compliance report sets (ADM-093); dashboard widgets (ADM-103) | Later E-012 slice; FB-9 |
| CSVDE, password-protected export, logo; mail-body and save-to-path delivery | reports-2a §11 / T-1017; mail-body later; save-to-path never |
| Joins; column-to-column comparison; formulas; regular expressions; hard delete of definitions | Later, with a security review (D1, D3); delete needs a DM-71 change |
| A box that accepts an LDAP filter or SQL, including "paste to convert" | Never in the builder (D2) |
| Per-DC fields (USR-04, PWD-03, SYS-03) as builder fields; Entra devices | Library only; E2.7 |
| Automatic Actions from a schedule | Automation, 2d |
| Old/new value diffs in change reports | Later (second slice §4.1.3) |
| Public or cross-tenant share links, embedding; natural-language building (ENH-20); Exchange, M365 content packs, GPO, NTFS, Google | Not planned; not in the set of 5; their milestones |

## 22. Open questions

Closed in round 2: Q6 (Entra datasets belong to E2.7, FB-11) and Q8 (new ADR, FB-3b). Numbers are kept.

| # | Question | Owner | Blocks |
| --- | --- | --- | --- |
| Q1 | What do ME's custom reports support: operators, condition count, cache or live LDAP, "database fields", "delegate", the advanced scheduler | `market-analyst` (FB-1) | §3's final parity table only |
| Q2 | ME baselines for T21 to T25 | `product-designer` (FB-2) | Claims in §4 |
| Q3 | Design of the builder, group table with chart, share sheet, Plan hand-off | `product-designer` (FB-7) | Screens |
| Q4 | Does the role attribute allowlist (DM-34) constrain **read**? | `solution-architect`, `ad-expert` (FB-3d) | FR-B12 build |
| Q5 | `audit.events`: erasure rule if a personal column is ever added; confirm §7's visibility | `security-architect` (FB-5) | FR-B26 |
| Q7 | Does the 2b bulk bar and first Actions set land before 2c? If not, FR-B16 reduces to builder reports and the bar moves into 2c | `project-manager` | FR-B16 sequencing |
| Q9 | Sync-set additions: who may add which attribute, permissions, backfill, freshness label | `product-manager`, `directory-engineer` (FB-8) | FR-B03 build |
| Q10 | Budgets of §14 and limits of §9 | `reporting-engineer` | Calibration only |
| Q11 | **CEO-directional (conditional):** cut order if 2c capacity forces a cut. Recommendation: ADM-096 first, then charts (E-B2) as a fast-follow, then the audit source; the rest is core to ADM-097. File with `ceo-decisions` only if a cut is forced | `factory-director` | Nothing now |

No question blocks the spec from review. Q11 is the only CEO item and is filed only if needed.

## 23. Hand-offs

- `solution-architect`: FB-3a, FB-3b (new ADR), FB-6a, FB-6b; confirm the in-statement count, grouped statement
  and `ActionSubject` fit the closed AST. `security-architect`: tag list in §16; FB-3c, FB-5.
- `reporting-engineer`: Q10, chart data contract, stored-row group keys, Unknown propagation.
  `product-designer`: FB-7, T21 to T25. `market-analyst`: FB-1. `project-manager`: tickets at merge, Q7.
- E2.7 owner: FB-11 and FB-4. E2.11 owner: FB-10. §7 and §11 are the interfaces; neither spec is redefined here.

## 24. Review response (round 2)

Reviews: [architecture](reviews/2026-11-11-m2c-architecture-review.md) (R-, X-) and
[security](reviews/2026-11-11-m2c-security-review.md) (B-). `R-m1..11` and `R-n1..4` are the architecture
minors and nits in order; `B-m1..5` and `B-n1` are the security B.4 items in order. Everything is taken
unless stated.

| Finding | Response |
| --- | --- |
| R-B1 | Match count in the run's one statement (§5, §9, FR-B08); no `CompileCount` path; per-condition counts and picker row counts dropped (§6, FR-B01); "1,000+" only after the rows-only fallback; FB-3b |
| R-M1 | ADR-0010 left alone; FB-3b is a new extending/superseding ADR (count, preview class, group/total rows, unsaved-AST run); snapshot option dropped |
| R-M2 | FB-3a: `CustomDefinition`, `Resolve`, category, ID namespace, nodes, `ActionSubject`, read permission |
| R-M3 | No roll-up: one `reports.preview.run` event per preview run, chained at commit; no ADR-0005 amendment; rate limit bounds volume (§16, AC-B35) |
| R-M4 | `audit.events` is the own-audit source, not DC events (§7, §21); display-name columns dropped; visibility rules; FB-5 |
| R-M5 | The ADR-0011 claim was unproven: now FB-6a, an interim residual and `Resolve` re-authorisation (§9 L5, L6, §16) |
| R-M6 | True `exact` example, `changed` examples, scripts `manual`, raw SQL `not supported`, matching E2.11 (§11.2, AC-B28) |
| R-M7 | One lifecycle: browser editing state, Save publishes, server `draft` only for imports, no delete, apply needs step-up (§8, §11.3, FR-B09, AC-B44) |
| R-m1 to R-m4 | FR-B07 to AC-B36, FR-B24 to AC-B37, FR-B23 to AC-B15/B34/B42; AC-B19 traces FR-B21/B08 with the preview caps in FR-B08; AC-B08 traces FR-B06; AC-B09 uses its Given and replicated logon replaces `lastLogon` (AC-B09, B17); LIKE metacharacters in AC-B06 |
| R-m5, R-m6, R-m7 | One FB table (§17), no unlettered "FB-3"; one limits table (§9) used by `Resolve` (§5); preview timeout 10 s `[PROPOSED]` named in AC-B16 |
| R-m8, R-m9 | Label from the masked column and time zone in the query hash (§5, AC-B38, AC-B40); GUID and DN default, FB-6b extension (FR-B17, AC-B26) |
| R-m10, R-m11 | `-- write-class` line, FB-12; ownership lock in §11.5 and AC-B29, and the E2.11 §6.4 citation for attached tasks removed (§11.4) |
| R-n1 to R-n4 | Frontmatter `reviewer`, `security-sensitive`; header explains E2.6 at 2a versus 2c; matrix rows for FR-B19 to B25, B27 and the new FRs; "independent of the Entra tenant" (§18) |
| X-1, X-2 | E2.7 owns Graph sync and registers the Entra datasets, E2.6 defines none (§7, FR-B25, FB-11, AC-B30; Q6 closed). FB-4 is the shared scope-root follow-up (E-011 / T-1131, ADR-0011 rule 9) that both specs list |
| X-3 | Scripts `manual`; apply is step-up; ownership lock; FB-10 for E2.11's cross-reference (§11) |
| B-B1 | Post-mask rule, one masked bucket, Unknown propagation, `groupable`/`aggregatable`, OU key rule (§5, FR-B28, AC-B38) |
| B-B2 | GUIDs without labels, re-authorisation at every `Resolve`, viewer-scope labels, `value_not_permitted`, metadata limits, owner-typed text as a stated residual (§8, §9 L6, §16, FR-B29, AC-B39) |
| B-M1 | RP-B3 replaced by the non-interference property test with failing fixtures (FB-3c, FR-B30, AC-B40); RP-B2 widened |
| B-M2 | `{run_id, row_keys[] or all_matching}`, derivation from stored rows, 409/410, new drill-down run (§10, FR-B16, AC-B41) |
| B-m1 | RP-B1 allow-lists the E2.11 intake only; sync-set input is a schema reference; carve-outs stated (§5, FR-B02, FR-B03, AC-B43) |
| B-m2 | Exact resolver only, DNs via the `dn` package, no fuzzy (FR-B17, FB-6b, AC-B26) |
| B-m3 | Taken except the roll-up: the security review accepted aggregation, but the architecture review and ruling 7 rule it out, so one event per preview. Visibility rules, HMAC hashes and ID-only listing taken (§7, §16) |
| B-m4, B-m5, B-n1 | Edit-level save and schedule-fire checks fail closed (§8, AC-B10, AC-B45); per-account preview cap of 1 (§9, AC-B19); grand total over all matching rows with "k of n groups shown" (§5) |
| B.1, B.2 rulings | Accepted as stated; residuals in §16 |

## Sources

- Parity rows ADM-083 to ADM-103, ADA-101: [feature-parity-matrix](../../business/competitive-analysis/feature-parity-matrix.md) and its [CSV](../../business/competitive-analysis/feature-parity-matrix.csv).
- ME custom report row and the help page the matrix cites: [ADMP custom reports help](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-custom-reports.html) (cited by the research; contents beyond the matrix row not read, `[UNVERIFIED]`); research [§K](../../business/market-research/manageengine-admanager-plus.md), §7a, §7c, W6, Resolved gaps.
- Pain: [customer voice X2](../../business/market-research/manageengine-ad-customer-voice-and-security.md); [ENH-05](../../business/strategy/enhancement-catalog.md).
- Scope: [v1-scope-options](../../business/scoping/v1-scope-options.md), [roadmap-skeleton](../../business/scoping/roadmap-skeleton.md), [m2-plan](../../business/scoping/m2-plan.md), [decisions-log](../../memory/decisions-log.md).
- Constraints: [ADR-0010](../../development/decisions/0010-report-results-stored-as-rows-in-postgres.md) (accepted, unchanged), [ADR-0011 rev 3](../../development/decisions/0011-universal-search-over-inventory-pg-trgm-one-scope-renderer.md), [ADR-0005](../../development/decisions/0005-operation-pipeline-and-audit-trail.md), [modules/reports.md](../../development/architecture/modules/reports.md), [safe-primitives](../../development/architecture/safe-primitives.md) (P1, P5, §3.7), [threat-model](../../development/architecture/threat-model.md), [reports-schedules-security-review](../../development/architecture/reports-schedules-security-review.md), [domain-model](../../development/domain/domain-model.md) (DM-20, DM-24, DM-33 to DM-36, DM-70 to DM-73, DM-80, Q5).
- Siblings: [reports-2a](reports-2a.md), [reports-2-second-slice](reports-2-second-slice.md), [e2-11-migration-importer](e2-11-migration-importer.md), `e2-7-hybrid-provisioning.md`.
- Reviews answered: [architecture](reviews/2026-11-11-m2c-architecture-review.md), [security](reviews/2026-11-11-m2c-security-review.md).

## Changelog

- 2026-11-11: first draft, off-board (`m2c-plan`).
- 2026-11-11: round 2, answering both rejecting reviews (§24): in-statement match count and a new extending ADR in
  place of an ADR-0010 amendment; post-mask grouping; re-authorised picked values; non-interference test;
  run-bound selection contract; free-text carve-outs; Entra datasets left to E2.7 with the shared scope-root
  dependency; E2.11 classes; one lifecycle, limits table and follow-up table; FR-B28 to B30 and AC-B36 to B45
  added, every FR traced to an AC.
