---
title: "Spec: Custom report builder at 2c: columns, filters, sources, clone, LDAP-filter import (ADM-097)"
date: 2026-11-14
updated: 2026-11-14
status: draft
owner: heramb
author: product-manager
ticket: T-2059
epic: E-010
milestone: M2c
parity: [ADM-097, ADM-099]
scope: proposed
sources_last_checked: 2026-11-14
---

# Spec: Custom report builder at 2c

> An admin builds a report of their own in a few minutes without writing a query, sees the first
> rows while they build, starts from any shipped report or from a ManageEngine LDAP filter they
> already have, and is told in plain words which part of a filter we cannot run instead of getting
> a silent approximation.

It is the 2c spec that [reports-2a.md](reports-2a.md) §6.1 rule 1 and §11 defer, and it answers
domain-model Q5 (`knowledge/development/domain/domain-model.md` :2173). It inherits run, scope,
freshness, export, schedule, permission and audit rules from reports-2a (§8) and changes none of
them. Entra datasets come from [reports-entra-objects.md](reports-entra-objects.md). Reviewed by
`solution-architect`; `security-architect` and `ad-expert` consults are requested in §12.
Prefix `RB-` is used for requirements (`FR-RB-nn`) and criteria (`AC-RB-nn`) so they do not collide
with 2a's `FR-nn` and `AC-nn`.

## 1. Problem and user

**Users.** The AD admin who needs "all enabled users in OU X whose password is older than 180 days
and who have no manager"; the auditor who needs a repeatable variant of a shipped report; the
migrating admin who has ManageEngine custom reports defined as LDAP filters.

**Cost today in ManageEngine.** The ADM-097 builder takes an LDAP filter or raw LDAP query, can
filter on database fields (bad-password count, days since password set), has a column picker with
custom attributes, can attach management actions, and supports copy, share and delegate
([ME help](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-custom-reports.html);
matrix row ADM-097 in [feature-parity-matrix.md](../../business/competitive-analysis/feature-parity-matrix.md) :247).
Report customisation limits are the #2 complaint, about 17 reviews: "The canned reports are great,
but the custom reporting is somewhat limited" and "if you create a large amount of custom reports,
they can overflow from the container"
([customer voice X2](../../business/market-research/manageengine-ad-customer-voice-and-security.md) :149).
A customer migrating must carry these reports over, and the migration playbook says to translate
them into the typed filter model and reject what cannot be parsed safely
([playbook](../../business/service/manageengine-migration-playbook.md) :134).

Frequency and ME click or second counts for the builder are not in the research: `[UNVERIFIED]`;
research ticket T-2070 (§12).

## 2. Parity baseline

| ID | ME capability (source: ME research :524) | activeDIQ at 2c | Status |
| --- | --- | --- | --- |
| ADM-097 | LDAP filter or raw LDAP query | Typed filter builder; LDAP-filter **import** into a typed AST (§7). No raw query, ever | Parity of outcome, different mechanism |
| ADM-097 | Filter on database fields (bad-password count, days since password set) | Registered, typed, derived columns are filterable (§5.2) | Parity |
| ADM-097 | Column picker incl. custom attributes | Column picker over **registered** attributes (§5.1). An attribute not in the registry cannot be a column | Parity with a deliberate limit |
| ADM-097 | Attach management actions | **2b** (ADM-098). The definition model keeps `attached_actions` empty at 2c | Deferred, stated |
| ADM-097 | Categories | Custom categories, folder-like, per tenant (§6) | Parity |
| ADM-097 | Copy, share, delegate | Clone, share definition read-only or editable, and `reports.build` permission (§6, §9) | Parity |
| ADM-099 | Scope and filters: domains, OU scope, period presets, result filters, add/remove columns | Already in 2a FR-06; the builder reuses it unchanged | Parity (2a) |
| ADM-103 | Custom reports as dashboard widgets | Out of scope (dashboards) | Not at 2c |
| MIG-05 | Report crosswalk | Import path in §7 and crosswalk rules in §10 | In scope |

## 3. Enhancements

Each is tied to X2 above. **V1 = ships at 2c.**

| ID | Enhancement | Pain it answers | V1 |
| --- | --- | --- | --- |
| EB-1 | **Live preview**: the first 50 rows, count and freshness label update as the admin edits, trimmed to the builder's own scope | "limited" customisation; admins build blind then run | Yes |
| EB-2 | **Import with a clause-by-clause result**: each clause of an LDAP filter shown as mapped (with the typed filter it became) or rejected (with the reason) | Migration cannot proceed if a filter is silently altered | Yes |
| EB-3 | **Clone with upgrade notice**: a clone remembers the shipped report and version it came from; when a newer shipped version exists the report says so and offers a side-by-side diff. It never changes the clone by itself | Shipped reports are immutable (DM-71.I2); clones must not rot silently | Yes |
| EB-4 | **Folders that do not overflow**: categories are searchable, paged, and a search shows owner and last-run | "overflow from the container" | Yes |
| EB-5 | **Grouping and a bar or table chart of a grouped report, shareable** | "old school bar charts" (X2, PeerSpot) | **No: P2.** Needs a compiler amendment (reports.md §3.2: no aggregate or grouping node at 2a). Charts and dashboards are a later slice |

## 4. Experience target

Set with `product-designer` (targets are proposals until
it signs them off). The ME comparison is `[UNVERIFIED]` until the research ticket returns, so the
absolute targets below are the gate:

- From "New report" to first rows on screen: **≤ 60 s and ≤ 8 interactions** for a report of one
  source, three filters and six columns, on the 100k-user lab.
- Import a ManageEngine LDAP filter: paste, see the result, **≤ 3 interactions** to a saved report.
- Clone a shipped report and add one column: **≤ 4 interactions**.
- The admin never writes an LDAP filter, SQL or attribute names by hand: attributes are picked by
  display name from a searchable list that shows the type; values are typed controls (date picker,
  flag toggle, user picker). The paste box in §7 is the only text input that accepts filter syntax,
  and it is an import, not an editor.
- Every state shows: empty source (no rows), loading, error with typed reason, 100k+ rows (preview
  says "50 of 112,400 rows"), saved-but-stale, and a rejected import.

## 5. The builder

### 5.1 Sources and columns

A report has **exactly one source** (reports-2a FR-05: an AST over one registered dataset). No joins
at 2c; a column from a related object is available only if the dataset registers it (for example
manager display name on `inventory.users`).

| Source | Datasets | Available at 2c | Notes |
| --- | --- | --- | --- |
| Directory (AD) | `inventory.users`, `computers`, `groups`, `group_members`, `ous`, `contacts` (reports-2a §7 D1–D3) | Yes | |
| Entra | `inventory.entra_users`, `entra_groups`, `entra_contacts` (reports-entra-objects.md) | Yes, if the Entra spec has shipped; otherwise the source is hidden, not greyed | Sign-in and Entra audit-log sources are not in that spec (`[UNVERIFIED]` licence needs there) |
| activeDIQ audit | a dataset of our own audit trail, registered by the `history` module | **Conditional**: needs the audit dataset spec (T-2071, §12). If it has not shipped, the source is hidden and AC-RB-05 is not claimed | Only our own actions. DC audit events are M3 and out of scope |

Columns: only registry columns (reports-2a §6.1 rule 5). Secret attributes are never in a dataset
(D8, LF-38), so no column and no filter can name one. The picker groups columns (Identity,
Account state, Dates, Group and OU, Policy-derived), shows type, and marks derived columns
("computed at run time"). Defaults: the source's identity column, name and `observed_at` are
pre-selected; the admin adds, removes and reorders the rest.

Limits (all `[PROPOSED]`, narrower than the engine's so the UI never offers a state the engine
refuses): **40 columns**, **1 sort key** (plus the stable tie-break), name 120 characters,
description 1,000.

### 5.2 Filters

The filter is a **typed AST** of the compiler's closed operator vocabulary
(modules/reports.md §3.2): `Eq, Ne, Lt, Le, Gt, Ge, In, Present, Absent, Contains, Prefix,
WithinLastDays, OlderThanDays, WithinNextDays`, combined with AND, OR and NOT.

- Operators offered per column depend on its type (string, number, date, flag, enum, GUID).
  Offering an operator the type does not support is impossible, not an error.
- Flag columns (decoded `userAccountControl` bits, group type) are toggles, never numbers.
- Date columns offer relative presets (last 30 days, older than 90 days) as well as absolute dates.
- Derived "database field" filters (days since password set, bad-password count where the dataset
  carries it, locked out, password expired) are ordinary typed columns and filter as such.
- Groups of conditions can nest to depth **4** (`[PROPOSED]`), **40 conditions** in total, `In`
  up to **1,000** values (the engine cap), each string value up to 1,024 characters.
- **NOT and nested AND/OR are a compiler amendment** if the 2a vocabulary does not already carry
  group nodes: requested of `solution-architect` (§12 Q1). Until it lands, the builder offers `Ne`
  and `Absent` and AND-only groups, and AC-RB-12 is not claimed.
- Scope: the builder's domain, OU and period controls are 2a's (FR-06), stored as part of the
  definition's **default** scope; the runner's authority always applies on top (DM-71.I1).

### 5.3 Preview

Preview is a run in the sense of reports-2a §8.1, capped at 50 rows and tagged "Preview", with the
same freshness label and after-trim counts (LF-39). A preview is not retained as a run. It is
debounced (300 ms) and cancels the previous preview. Previews are rate-limited per user
(`[PROPOSED]` 30 per minute) and count against the tenant's 4-concurrent-report-jobs limit
(ADR-0010).

### 5.4 Saving

A definition has `origin` = `custom`, `version`, `dataset`, `ast`, `category`, `owner`,
`shared_with`, lifecycle `draft → published → archived` (DM-71). Saving a published definition
publishes a new version; every run records the definition version and its SHA-256 (reports.md
§3.6). Tenant limit: **500 custom definitions** (`[PROPOSED]`); 50 versions retained per definition.
A definition that fails validation cannot be saved as published, only as draft.

## 6. Clone, share, categories

**Clone (DM-71.I2).**
1. Any user with `reports.run` on a shipped or custom report and `reports.build` can clone it.
2. The clone is a **draft** `origin: custom` owned by the cloner, named "Copy of <name>", with
   the source definition id, version and SHA recorded. It carries the AST, columns, default
   scope and preset filters; it does **not** carry "Also known as" names (they belong to the
   shipped report), schedules, shares or run history.
3. A clone of a clone records its direct parent and the root shipped report.
4. The shipped definition is never modified; the cloner needs no right on it beyond `reports.run`.
5. When a newer version of the shipped source ships, the clone shows "Based on <name> v3, v4
   available" with a diff of columns and filters. Nothing is applied automatically. If the
   source was deprecated the clone shows that and continues to run.
6. A clone whose source column was removed from the registry by a dataset change is marked
   **needs attention** and refuses to publish or run until the column is replaced; it never
   silently drops a column or filter.

**Share.** A definition can be shared with named users or roles as **view** (run it) or **edit**.
Sharing a definition never shares data: each runner sees only what their own scope allows
(DM-71.I1). A recipient with no `reports.run` sees nothing. Revoking removes access at the next
request. Only the owner or `reports.build.manage_all` can delete; deleting a definition used by a
schedule is refused with the list of schedules.

**Categories.** The six shipped categories are fixed. Custom definitions live in custom
categories (flat, 100 per tenant, `[PROPOSED]`), visible in the library next to shipped reports and
searchable by name, description and owner.

## 7. LDAP-filter import (MIG-05, ADM-097)

Import turns an RFC 4515 filter text, pasted or read by the migration importer from the ME
database ([e2-11-migration-importer.md](e2-11-migration-importer.md) :67), into a typed AST. It
never stores the text as something to execute (DM-71.I3, FR-05).

**Pipeline.** Parse with the safe-primitive `ldapfilter` package (`ParseAdminFilter`, schema
allowlist, 64 KiB, depth 32, 512 nodes; safe-primitives.md §3) → select the dataset → map each
clause onto a registered column and a vocabulary operator → validate against the builder limits in
§5 → show the result. Nothing is persisted until the admin saves, and a filter with any
unmapped clause **cannot be saved at all** (AC-RB-07). No fallback runs a live directory search.

**Answer to domain-model Q5.** Admin LDAP filters map onto **inventory datasets**, not live scoped
search. Reasons: a run's rows, counts and trimming are guaranteed by the one scope renderer and
ADR-0010's stored result; a live search would bypass freshness labelling and per-run storage and
would make a 100k-user report depend on DC load. The cost, stated to the admin: results are as
fresh as the last sync, and attributes not in the registry cannot be filtered.

**Dataset selection.** The `objectClass` / `objectCategory` conjunct at the top level picks the
dataset: `user`/`person` → users, `computer` → computers, `group` → groups, `contact` → contacts,
`organizationalUnit` → OUs. `(&(objectCategory=person)(objectClass=user))` is the usual ME form
and resolves to users. If absent, the admin picks the dataset (one choice). If two conflict, or
the class names no dataset, the import is rejected naming the clause.

**Mapping table (v1).**

| LDAP clause | Maps to | Notes |
| --- | --- | --- |
| `(attr=value)` | `Eq` | Value typed by the column; a value that does not parse as the type is rejected naming the clause |
| `(attr=*)` / `(!(attr=*))` | `Present` / `Absent` | |
| `(attr=pre*)` / `(attr=*mid*)` | `Prefix` / `Contains` | |
| `(attr>=v)` / `(attr<=v)` | `Ge` / `Le` | Time attributes: GeneralizedTime and FILETIME are converted to a typed date |
| `(!(…))`, `(&…)`, `(|…)` | NOT, AND, OR | Subject to §5.2 limits and Q1 |
| `userAccountControl:1.2.840.113556.1.4.803:=N` (and `:804:`) | The decoded flag column(s) for each bit of N | A bit with no registered flag column rejects the clause naming the bit |
| `sAMAccountName`, `mail`, `department`, `title`, `whenCreated`, `lastLogonTimestamp`, `pwdLastSet`, `accountExpires`, `lockoutTime` … | Registered columns | Whatever the registry carries (reports-2a §7); anything else is "attribute not in the dataset" |

**Rejected, always naming the clause** (`[PROPOSED]` set, reviewed by `ad-expert`):

| Clause | Reason shown |
| --- | --- |
| Attribute not in the dataset registry (including custom schema attributes and constructed ones) | "`extensionAttribute3` is not available in this dataset" |
| Secret attribute (`unicodePwd`, `userPassword` …) | "refused: secret attribute" |
| Extended match other than 803/804, including `:dn:` and any other OID | "unsupported matching rule `<oid>`" |
| `1.2.840.113556.1.4.1941` (transitive membership) | "transitive membership is not supported in imported filters; use the effective-members column of the Groups reports" |
| Equality or substring on a DN-syntax attribute (`memberOf`, `manager`, `distinguishedName`) | "DN-valued filters are not supported; use the group or manager picker" |
| Approximate match `~=` | "approximate match is not supported" |
| Substring with a final-only or multi-part pattern (`*suffix`, `a*b*c`) | "pattern shape not supported" |
| Empty assertion, unbalanced parenthesis, invalid escape, over-limit size, depth or nodes | The parser's typed error with the position |
| A value naming an object the importer's caller cannot read (the `ldapfilter` `Caller` check) | "value refers to an object you cannot read" (and nothing about whether it exists) |

**Result view.** A table of clauses: original text, mapped typed filter or the reason, and a badge
(Mapped / Rejected). If every clause is mapped, "Save as report" is enabled, and the admin chooses
name, category and columns (default columns of the dataset) and a preview shows. If any is
rejected, the whole import is blocked and **no definition, draft or otherwise, is created**; the
admin can fix the filter text or build the report from the builder. A partial import is never
offered, since a partial filter returns the wrong rows.

**Import from the migration importer (MIG-05).** The same pipeline runs per ME custom report.
Output is the fidelity report row (MIG-03): exact / changed / not supported, with the clause
reason. Mapped reports land as **drafts** owned by the importing admin, never published or
scheduled automatically (cf. TM-TB18-T9). The crosswalk records the ME report name so the library
shows it as "Also known as" on the imported report. ME's column picker choices are imported
only where each column is in the registry; others are listed as dropped in the fidelity report
and the report is marked "changed".

## 8. Platform matrix

| FR group | AD on-prem (WS2016–2025 DCs) | Entra cloud-only | Hybrid synced | Console | REST API | PowerShell | `windows` | `linux-oci` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Build, columns, filters, preview, save (FR-RB-01…12) | ✓ | ✓ if reports-entra-objects shipped, else hidden | ◐ AD and Entra are separate sources, no cross-source join | ✓ | ✓ | ◐ follows the API, no cmdlet spec at 2c | ✓ | ✓ |
| Audit source (FR-RB-04) | ✓ | ✓ activeDIQ's own audit only | ✓ | ✓ | ✓ | ◐ | ✓ | ✓ |
| Clone, share, categories (FR-RB-13…18) | ✓ | ✓ | ✓ | ✓ | ✓ | ◐ | ✓ | ✓ |
| Filter import (FR-RB-19…27) | ✓ | n/a: LDAP filters apply to AD objects. An Entra filter (OData `$filter`) import is not offered | ◐ AD side only | ✓ | ✓ | ◐ | ✓ | ✓ |
| Run, export, schedule of a custom report | as reports-2a §10 | as 2a | as 2a | ✓ | ✓ | ◐ | ✓ | ✓ |

No DC-side component is added: nothing here needs a Windows Server version beyond reports-2a's
inventory sync. The builder is pure server and console code, so it adds no Windows-only behaviour
and neither profile lags. Samba lab proves the import and builder against synced data; derived
states that depend on policy `[LAB: Windows]` as in reports-2a §10.

## 9. Security and audit

- **Privileges.** The builder reads inventory only; it needs no new directory right. It writes
  definitions to our own store, never to a directory.
- **Permissions** (proposed registry IDs, X6): `reports.build` (create, edit, clone and delete
  own definitions, import filters), `reports.build.manage_all` (list, reassign, delete any
  definition; never opens another user's run rows). `reports.run` is still required to run.
- **Threat model.** The existing rows TM-TB3-T4 (filter and DN injection), TM-TB1-T8 (scope
  trimming) and TM-TB15 apply. New abuse cases for `security-architect` to add: a shared
  definition used to widen another user's view (answer: scope is the runner's, DM-71.I1); a
  crafted filter for denial of service (answer: limits in §5 and §7, preview rate limit);
  enumeration through the import error "object you cannot read" (answer: the same message for
  non-existent and unreadable); a definition name or description carrying HTML or a formula
  (answer: encoders on every cell and label, as 2a §9); a builder-created report used to exfiltrate
  an attribute the user cannot read as a column (answer: column visibility is a registry property,
  and scope trims rows, so a column that is sensitive must be gated by a permission in the registry:
  **Q2**).
- **Safe primitives.** SQL only through `store/reportsql` with registry identifiers and bound
  arguments (FF-SP4). Filter parsing only through `ldapfilter`. No string formatting of any
  filter, DN or SQL.
- **Our audit trail.** One event per item, recording actor, definition id and version, never
  values: definition created, edited, published, archived, deleted, cloned (with source id and
  version), shared and unshared (with the principal), imported (with counts of mapped and rejected
  clauses and a hash of the filter text, **never the text** since it may carry values), import
  rejected (with the clause kinds), ownership reassigned. Runs, exports and schedules of custom
  reports are audited as in reports-2a §8.6.
- **`security-sensitive`** for build tickets: definition store and sharing (scope of who sees what),
  the import mapper, the preview endpoint, and any column added to the registry that exposes a
  user-readable attribute.

## 10. ManageEngine crosswalk for MIG-05

| ME artefact | activeDIQ result | Source |
| --- | --- | --- |
| Custom report defined by an LDAP filter | Draft custom report via §7, or "not supported" row naming the clause | [playbook](../../business/service/manageengine-migration-playbook.md) :134 |
| Custom report defined by a raw LDAP query | As above; non-filter parts (base, scope, attributes) map to the domain/OU scope and columns where registered | `[UNVERIFIED]` how ME stores raw queries: needs the DB schema research |
| Column picker with custom attributes | Imported only for registered columns; others dropped and listed | ME research :524 |
| Filters on database fields | Mapped to the matching derived column if one exists; else not supported | ME research :524 |
| Attached management actions | Not imported (2b), listed in the fidelity report | ME research :524 |
| Categories, share and delegate settings | Category recreated; shares **not** imported (principals do not map); owner = importing admin | assumed; `[UNVERIFIED]` ME export format |
| Prebuilt report names | Unchanged: 2a presets and crosswalk | reports-2a §6.1 rule 2 |

The ME database is the only known source for custom reports (e2-11-migration-importer.md :67), and
the format is `[UNVERIFIED]`. The import pipeline takes a text filter, so it works from a paste
regardless of the importer.

## 11. Out of scope

| Item | Goes to |
| --- | --- |
| Attach management actions to results (ADM-098) | 2b |
| Dashboards and widgets (ADM-103), grouping and charts (EB-5) | Later slice; T-2072 |
| DC audit-event sources and reports (ADA-101) | M3 |
| Joins across datasets, computed expressions, raw SQL, raw LDAP query execution | Not planned |
| Report-category delegation (ADM-102) | 2b / grooming |
| Import of Entra OData filters | Not planned |
| Report from CSV (ADM-096) | Later E-012 slice |
| Live directory search as a report source | Not planned (Q5 answer, §7) |

## 12. Open questions and hand-offs

- **Q1 (solution-architect), ANSWERED 2026-11-14:** yes. The 2a `report.Expr` is a sealed union of `And`, `Or`, `Not` and `Cmp` (reports.md §3.6/Definition block: And/Or ≤ 32 terms, depth ≤ 8), so no compiler amendment is needed for NOT or nesting. FR-RB-12, AC-RB-12 and the NOT row of §7 are claimed at 2c; the §5.2 limits (depth 4, 40 conditions) sit inside the engine's. The amendment reports.md §3.2 foresees is only for grouping (EB-5, T-2072). Note: with DN-valued clauses always rejected, the "object you cannot read" path in §7 and AC-RB-25 is only reachable if DN support is added later; today both inputs get the same DN-valued rejection.
- **Q2 (security-architect, ad-expert):** which registry columns need a read permission beyond
  `reports.run` (for example `pwdLastSet`, `lockoutTime`, `lastLogonTimestamp` are widely visible in
  AD; confirm none are sensitive). The default decision here: none is gated, since reports-2a
  already lists them.
- **Q3 (ad-expert):** confirm the rejected-clause set and the 803/804 flag mapping; confirm the
  `objectCategory`/`objectClass` dataset selection rules against AD's class hierarchy
  (`objectCategory=person` also matches contacts in AD `[UNVERIFIED]`).
- **Q4 (directional, not asked of the CEO yet):** EB-5 grouping and charts are deferred from 2c,
  though the parity matrix describes the leapfrog as including interactive charts. This is a scope
  cut; `factory-director` to decide whether it needs a CEO decision at M2c grooming.
- **Follow-ups filed:** research ticket for ME builder task-time and the raw-query storage format
  (`market-analyst`, T-2070); spec ticket T-2071 for the activeDIQ audit-trail dataset (needed for §5.1); T-2072 for grouping and charts.

## 13. Functional requirements

| ID | Requirement | Parity |
| --- | --- | --- |
| FR-RB-01 | A user with `reports.build` MUST be able to create a report by choosing one source, columns, filters, sort, scope defaults, name and category, without entering any query text | ADM-097 |
| FR-RB-02 | A column MUST exist in the dataset registry; the builder MUST NOT offer, and the API MUST refuse, any other column or any attribute marked secret | ADM-097, D8 |
| FR-RB-03 | Filters MUST be typed ASTs over the closed operator vocabulary; operators MUST be restricted by column type; no API accepts filter text except the import endpoint | FR-05, DM-71.I3 |
| FR-RB-04 | Sources MUST be limited to registered datasets of directory, Entra and activeDIQ audit; a source whose dataset is not shipped MUST be hidden | ENH-05 |
| FR-RB-05 | Limits of §5 (40 columns, 40 conditions, depth 4, `In` ≤ 1,000, name 120) MUST be enforced by UI and API with a typed error naming the limit | enhancement |
| FR-RB-06 | The builder MUST show a preview of ≤ 50 rows with after-trim count and freshness label, cancelling superseded previews | EB-1 |
| FR-RB-07 | Saving MUST create a new definition version; every run MUST record definition id, version and SHA-256 | X7 |
| FR-RB-08 | A definition that fails validation MUST NOT publish, and MUST name the invalid column or filter | enhancement |
| FR-RB-09 | Results MUST be trimmed to the runner's authority regardless of owner or sharing | DM-71.I1 |
| FR-RB-10 | Custom reports MUST export, schedule and run under reports-2a §8 rules with no exemptions (caps, encoders, step-up for external delivery) | ADM-100, ADM-101 |
| FR-RB-11 | The tenant limit of 500 custom definitions and 50 versions per definition MUST be enforced with a typed error | enhancement |
| FR-RB-12 | Filters MUST support NOT and nested groups once Q1 is resolved | ADM-097 |
| FR-RB-13 | Clone MUST create a draft owned by the cloner with source id, version and SHA recorded, and MUST NOT copy Also-known-as names, schedules, shares or runs | DM-71.I2 |
| FR-RB-14 | Shipped definitions MUST never change as a result of a clone, share or edit of a clone | FR-03 |
| FR-RB-15 | A clone MUST show a newer-version notice and a diff and MUST NOT apply changes automatically | EB-3 |
| FR-RB-16 | A clone or custom definition referencing a column no longer in the registry MUST be marked needs-attention and MUST NOT run or publish | enhancement |
| FR-RB-17 | Sharing MUST be per principal with view or edit; revocation MUST apply on the next request; deleting a scheduled definition MUST be refused | ADM-097 |
| FR-RB-18 | Custom categories MUST be searchable and paged | EB-4 |
| FR-RB-19 | Import MUST parse text only through `ldapfilter`, MUST select the dataset per §7, and MUST map every clause or reject | MIG-05 |
| FR-RB-20 | If any clause is rejected, import MUST store nothing and MUST name each rejected clause with its reason | MIG-05 |
| FR-RB-21 | The result view MUST show each clause, its typed mapping or reason | EB-2 |
| FR-RB-22 | Import MUST map `userAccountControl` 803/804 matches to decoded flag columns bit by bit, rejecting unmapped bits | ADM-097 |
| FR-RB-23 | Import MUST reject extended matches other than 803/804, transitive membership, DN-valued clauses, approximate match, unsupported substring shapes, unregistered and secret attributes | MIG-05 |
| FR-RB-24 | Import MUST never run a live directory search and MUST never store filter text as executable | DM-71.I3 |
| FR-RB-25 | An import error for an unreadable referenced object MUST be identical to that for a non-existent one | TM-TB3-T4 |
| FR-RB-26 | Migration-importer output MUST be drafts, never published or scheduled, with the fidelity row per report | MIG-03, MIG-05 |
| FR-RB-27 | The import audit event MUST carry counts and a hash of the filter text and never the text | TM-TB15 |
| FR-RB-28 | `reports.build` and `reports.build.manage_all` MUST exist and be enforced on UI and API; `x-permission` on every endpoint | ADR-0004 |

## 14. Acceptance criteria

Evidence names are what `qa-verifier` produces. "Lab" is the CI AD lab; the 100k lab is a seeded
directory of 100,000 users and a group of 1,600 members.

```
AC-RB-01 (T-2059 acceptance 1; FR-RB-01, FR-RB-04)
Given a user with reports.build and a synced directory
When they pick source "Users", add columns name, department, pwdLastSet, add filter
  "department = Finance" and "password older than 180 days", and save as "Stale Finance"
Then the report appears in their category, runs, and every row has department Finance and a
  pwdLastSet older than 180 days, and no text query was entered
Evidence: UI recording; test builder_create_typed_report; API output

AC-RB-02 (FR-RB-02)
Given the Users dataset
When a client POSTs a definition with column "unicodePwd" or "extensionAttribute3" that is not
  in the registry
Then the API returns 422 naming the column and nothing is stored
Evidence: API test builder_unregistered_column_rejected

AC-RB-03 (FR-RB-03)
Given any definition endpoint
When a request carries a filter as a text string in place of an AST
Then it is refused with 422 and nothing is stored
Evidence: contract test; fitness check that only the import endpoint accepts filter text

AC-RB-04 (FR-RB-03)
Given a date column and a string column
When the admin opens the operator list for each
Then the date column offers Eq, Ne, Lt, Le, Gt, Ge, Present, Absent and the relative presets, the
  string column offers Eq, Ne, In, Present, Absent, Contains, Prefix, and neither offers the other's
Evidence: UI recording; test operators_by_type

AC-RB-05 (FR-RB-04; claimed only if the audit dataset has shipped)
Given the activeDIQ audit source and a lab with 20 recorded admin actions
When the admin builds "Actions by actor" with columns actor, action, time and filter time in the
  last 7 days
Then the rows match the audit trail for the same window, trimmed to what the runner may see
Evidence: UI; test builder_audit_source_matches_trail

AC-RB-06 (FR-RB-04)
Given a deployment with no Entra connection or no Entra dataset shipped
When the admin opens the source list
Then Entra is not shown, and no empty or disabled placeholder appears
Evidence: UI recording

AC-RB-07 (T-2059 acceptance 2; FR-RB-19, FR-RB-20, FR-RB-23)
Given the LDAP filter "(&(objectCategory=person)(objectClass=user)(extensionAttribute3=X)(department=Finance))"
When it is imported
Then the import is rejected, the result names the clause "(extensionAttribute3=X)" and the reason
  "attribute not in this dataset", no definition (draft or published) is created, and the clause
  list is still shown for the clauses that would have mapped
Evidence: UI; API output; test import_unsupported_clause_rejected_nothing_stored asserting a row count of zero in the definitions table before and after

AC-RB-08 (FR-RB-23)
Given each of: "(memberOf:1.2.840.113556.1.4.1941:=CN=A,DC=x)", "(manager=CN=B,DC=x)", "(cn~=smith)",
  "(cn=*smith)", "(cn:dn:=x)", "(unicodePwd=*)"
When each is imported
Then each is rejected with the reason of the §7 table, naming the clause, storing nothing
Evidence: table-driven test import_rejection_reasons

AC-RB-09 (FR-RB-19, FR-RB-21)
Given "(&(objectCategory=person)(objectClass=user)(department=Finance)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
When imported
Then the dataset is Users; clauses map to Eq on department and to "account is not disabled" on the
  decoded flag; the result view shows each clause with its mapping; saving creates a draft whose run
  returns exactly the enabled users of department Finance in the lab
Evidence: UI; test import_uac_bitwise_maps_flag; lab comparison with an LDAP search of the same filter on Samba

AC-RB-10 (FR-RB-22)
Given "(userAccountControl:1.2.840.113556.1.4.803:=8388608)" where that bit has no registered flag column
When imported
Then it is rejected naming the clause and the bit
Evidence: test import_unregistered_bit

AC-RB-11 (FR-RB-19)
Given "(department=Finance)" with no objectClass clause
When imported
Then the admin is asked to choose the dataset once, and the choice is shown in the result before
  save; with "(&(objectClass=user)(objectClass=computer))" the import is rejected naming the conflict
Evidence: UI; test import_dataset_selection

AC-RB-12 (FR-RB-12; claimed after Q1)
Given a filter "A AND (B OR NOT C)" built in the UI and the same as imported text
When both are saved and run
Then both ASTs are equal, and the rows are those that match the expression in the lab
Evidence: test builder_and_import_ast_equal

AC-RB-13 (FR-RB-05)
Given a definition with 41 columns, or 41 conditions, or depth 5, or an In list of 1,001
When saved
Then each is refused with a typed error naming the limit and its value
Evidence: boundary tests at 40/41, 40/41, 4/5, 1000/1001

AC-RB-14 (FR-RB-19, FR-RB-20)
Given a filter of 70 KiB, or one nested 33 levels, or with an unbalanced parenthesis
When imported
Then it is rejected with the parser's typed error and position, within 1 second, with nothing stored
Evidence: tests import_oversize, import_depth, import_malformed

AC-RB-15 (FR-RB-06)
Given the 100k-user lab and a report on Users with no filter
When the admin edits a filter
Then the preview shows 50 rows, the text "50 of N rows" with N the after-trim count, the freshness
  label, and appears in under 2 seconds at the 95th percentile (`[PROPOSED]`); a second edit within
  300 ms cancels the first preview
Evidence: perf test builder_preview_100k; UI recording

AC-RB-16 (FR-RB-09)
Given a custom report shared by owner A (whole forest) with user B whose scope is OU Sales
When B runs it
Then B's rows, count and "checked n objects" cover only OU Sales; A's run still covers the forest
Evidence: test shared_report_trimmed_to_runner; API output of both runs

AC-RB-17 (FR-RB-13, FR-RB-14)
Given a shipped report "Inactive users" v1
When a user with reports.build clones it and adds a column
Then a draft "Copy of Inactive users" exists owned by the user with the source id, v1 and SHA
  recorded; the shipped definition's version and SHA are unchanged (library/LOCK fitness passes);
  the copy has no Also-known-as names, shares or schedules
Evidence: test clone_records_source_shipped_unchanged; API output

AC-RB-18 (FR-RB-15)
Given the clone from AC-RB-17 and a shipped v2 that adds a column
When the owner opens the clone
Then it shows "Based on Inactive users v1, v2 available" with a diff, and the clone's AST is
  unchanged until the owner applies the diff
Evidence: UI; test clone_upgrade_notice_no_autoapply

AC-RB-19 (FR-RB-16)
Given a custom report whose column was removed from the registry
When the owner runs or publishes it
Then the action is refused with "needs attention: column X no longer available" and the report
  neither drops the column nor returns rows
Evidence: test definition_column_removed_needs_attention

AC-RB-20 (FR-RB-17)
Given a definition used by schedule S
When its owner deletes it
Then it is refused and S is listed; after S is deleted the delete succeeds
Evidence: test delete_definition_blocked_by_schedule

AC-RB-21 (FR-RB-17)
Given a definition shared "view" with B
When the owner revokes the share and B reloads the library
Then the report is not listed for B and a direct API run by B returns 404
Evidence: test share_revoke_effective_next_request

AC-RB-22 (FR-RB-28)
Given a user with reports.run but not reports.build
When they call create, edit, clone or import
Then each returns 403 and the UI shows none of those controls
Evidence: API test; UI recording

AC-RB-23 (FR-RB-10)
Given a custom report returning 1,000,001 rows
When it runs
Then the run is refused with the stored-row cap explanation as for shipped reports (reports-2a AC-24);
  with 5,000 rows it exports to CSV where a cell "=cmd|' /C calc'!A0" in the lab data is neutralised
Evidence: tests builder_cap_enforced, builder_export_formula_encoded

AC-RB-24 (FR-RB-26)
Given a migration batch with 10 ME custom reports, 7 mappable and 3 not
When the importer runs
Then 7 drafts exist, none published or scheduled, 3 rows in the fidelity report name the
  rejected clause and no definition exists for them
Evidence: test mig05_batch_drafts_only; fidelity report output

AC-RB-25 (FR-RB-25)
Given an import with "(manager=CN=Existing,…)" for an object the caller cannot read, and another
  for a non-existent object
When both are imported
Then the responses are byte-identical apart from the clause echo
Evidence: test import_no_existence_oracle

AC-RB-26 (FR-RB-27)
Given an import with "(department=Secret Project)"
When the audit trail is read
Then the event shows counts and a hash of the text and neither "Secret Project" nor the text
Evidence: test import_audit_no_values

AC-RB-27 (empty state)
Given a source with zero rows in scope
When the admin builds and previews a report
Then the preview shows "0 rows" with the freshness label and the reason scope or filter if it
  applies, not a blank screen
Evidence: UI recording

AC-RB-28 (error state)
Given the store is unavailable during a preview or save
When the admin acts
Then the UI shows a typed error with retry, and no partial definition is stored
Evidence: fault-injection test builder_store_failure_atomic

AC-RB-29 (large directory)
Given the 100k lab and a group of 1,600 members
When the admin builds a Group-members report filtered on that group and runs it
Then the run returns all 1,600 rows, none missing or duplicated, with after-trim counts
Evidence: test builder_group_over_1500

AC-RB-30 (platform)
Given the linux-oci and windows profiles
When AC-RB-01, 07, 09, 17 run on each
Then results are identical
Evidence: CI matrix output (windows profile when its adapters reach GA)

AC-RB-31 (experience)
Given the 100k lab and a user new to the builder
When timed on the task of §4 (one source, three filters, six columns)
Then the task completes in ≤ 60 s and ≤ 8 interactions; the import completes in ≤ 3 interactions
Evidence: qa-verifier timed recordings, 3 runs
```

## Sources

[ME custom reports help](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-custom-reports.html)
(as quoted in the ME research :524; not re-read on this ticket). Internal sources are linked
inline. The `ldapfilter` behaviour is from `knowledge/development/architecture/safe-primitives.md`
§3 and the package; ADR-0010 (accepted) and ADR-0011 (ratified) constrain the result store and scope.
Everything about AD behaviour not cited is for `ad-expert` to verify (Q3).

## Changelog

- 2026-11-14 · created (T-2059)
