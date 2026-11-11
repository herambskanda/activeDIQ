---
title: "Spec: E2.7a Entra inventory sync and report datasets (split out of E2.7, checkpoint 2c slice)"
date: 2026-11-11
updated: 2026-11-11
status: draft
owner: heramb
author: product-manager
prd: none (the E-013 PRD is not written; this spec is the contract for the checkpoint 2c slice)
ticket: off-board (m2c-plan)
epic: E-013
milestone: M2
parity: [I360-003, ADM-169, ADM-094]
scope: locked
sources_last_checked: 2026-11-11
reviewer: solution-architect
second_reviewer: security-architect
security-sensitive: true
revision: 1
parent: knowledge/product/specs/e2-7-hybrid-provisioning.md
---

# Spec: E2.7a Entra inventory sync and report datasets

> activeDIQ keeps an inventory of the connected tenant's users, groups, licence SKUs and licence
> assignments, up to date by Graph delta, and registers three Entra datasets that the report builder
> reads. Correlation between an AD object and an Entra object can only change through this sync
> (DM-20.I5), so the hybrid create in [E2.7](e2-7-hybrid-provisioning.md) depends on it.

Split from E2.7 §7.6 in round 3 (architecture review, "Length"; director ruling 7). **FR-36…FR-38 and
AC-42, AC-43 keep their numbers**; E2.7 and [E2.6](e2-6-report-builder.md) cite them here. Planned
off-board (CEO decision 2026-11-10): documents only. No Entra tenant exists yet (A-0026), so every
Microsoft behaviour is sourced inline or tagged `[UNVERIFIED — lab]`. Tenant connection, certificate and
permission families are E2.7 §7.1; this spec adds no permission (it reads with the Read family, FR-04).

Binding sources: [connector contract](../../development/architecture/connector-contract.md) §6.6,
[domain model](../../development/domain/domain-model.md) DM-16 (I9), DM-20 (I4, I5), DM-70,
[ADR-0011](../../development/decisions/0011-universal-search-over-inventory-pg-trgm-one-scope-renderer.md) rule 9,
[safe-primitives-odata](../../development/architecture/safe-primitives-odata.md) (P8, V12),
[threat model](../../development/architecture/threat-model.md) §6.6.

## 1. Problem, user, parity

- **Why.** Without sync, "is this Entra user the same identity as that AD user" cannot be answered, and
  ADMP's cloud actions "work only on users synced by DirSync" with no explanation (ADM-169, W15;
  [ADMP research](../../business/market-research/manageengine-admanager-plus.md)). Matrix I360-003 (must,
  parity, P1) had no requirement behind it before E2.7.
- **Users.** AD admin / help-desk technician (reads the source-of-authority badge); compliance auditor and
  IT manager (read the datasets through E2.6); the hybrid flow (consumes correlation).
- **Parity** ([matrix](../../business/competitive-analysis/feature-parity-matrix.csv)): I360-003 **in** (Graph
  delta of users, groups, licence assignments); ADM-169 **in, minimal** (SOA and correlation columns);
  ADM-094 **input only** (E2.6 builds the reports). No new IDs.
- **Enhancement.** The correlation columns and reason (E3 in E2.7): 0 clicks to see why a cloud user is
  not "AD authored".

## 2. Platform matrix

`[LAB-E]` = Entra sandbox (D-0001). Datasets and Entra scopes also depend on E-011 / T-1131 (§6); until it
lands the cells that need those roots read ✗ → E-011. Samba cannot exercise Entra.

| FR | windows | linux-oci | saas | Entra Connect | Cloud Sync | Entra-only tenant | Samba AD half | Console | REST API |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| FR-36…37 Entra sync, targeted re-sync | ✓ | ✓ | ✗ not shipped (ADR-0002 saas profile) | ✓ | ✓ | ✓ | n/a | ✓ | ✓ |
| FR-38 Entra datasets | ✓ | ✓ | ✗ | ✓ | ◐ correlation columns stay `candidate` until OQ-F3 | ◐ correlation columns empty | n/a | ✓ | ✓ |

National clouds and air-gapped installs: not in 2c (E2.7 §5). PowerShell module: n/a (M3, FD-07).

## 3. Functional requirements

| ID | Requirement | Parity / enh |
| --- | --- | --- |
| FR-36 | The system MUST sync Entra **users, groups, subscribed SKUs and per-user licence assignments** into inventory (connector contract §6.6; DM-16 Entra rows; `ancestry_complete` is false for Entra rows). Users and groups use Graph delta ([user delta](https://learn.microsoft.com/en-us/graph/api/user-delta?view=graph-rest-1.0), [group delta](https://learn.microsoft.com/en-us/graph/api/group-delta?view=graph-rest-1.0)) with the property list selected in the initial request (query parameters other than the tokens must be given up front, user delta page). User properties: `id`, `userPrincipalName`, `displayName`, `accountEnabled`, `usageLocation`, `assignedLicenses`, `onPremisesSyncEnabled`, `onPremisesImmutableId`, `onPremisesSecurityIdentifier`, `onPremisesDomainName`, `onPremisesLastSyncDateTime`, `onPremisesSyncBehavior` (beta; when unreadable, DM-20.I4(a) alone decides). Group properties: `id`, `displayName`, `securityEnabled`, `groupTypes`, `membershipRule` presence, `isAssignableToRole`, `onPremisesSyncEnabled`, `onPremisesSecurityIdentifier`, `assignedLicenses` `[UNVERIFIED — lab]`. **Delta does not track `licenseAssignmentStates`** ([user delta note](https://learn.microsoft.com/en-us/graph/api/user-delta?view=graph-rest-1.0)), so licence-assignment state is read per user on a targeted re-sync, for users whose `assignedLicenses` changed, and by a scheduled reconcile (default daily `[PROPOSED]`, paged). Sync sets `cloud_seen_at` when it sees a user or group cloud-only or cloud-managed (DM-16.I9). A lost or expired delta token causes a full resync `[UNVERIFIED — lab]`. Not synced in 2c: devices, group member lists or counts, service-plan detail. **Link and token binding (A2-m7):** `@odata.deltaLink` and `@odata.nextLink` are stored per connection and followed only after the P8 host pin; each access token's `tid` is checked against the connection's `directory_identity` on **every acquisition**, not only at EV2; a delta page from another tenant or host is refused. | I360-003, ADM-169 |
| FR-37 | The system MUST support a **targeted re-sync** of one user or group by object `id` or, for users, by anchor (DM-20.I5), through the P8 `Eq`/`Str` builders. It MUST refresh the object and its licence-assignment state and re-evaluate the correlation gate. It is the only thing "Check now" (E2.7 FR-19), the FR-15 lookup and the FR-16 pre-write read do before they *read* the stored result. It follows the Graph throttling rules (E2.7 FR-27). **Budget (A2-m3):** re-syncs are capped per request (one per 30 s, E2.7 FR-40), **per account and per tenant** `[PROPOSED]: 6 and 30 per minute`, and the write path has priority: when the tenant is throttled, re-syncs queue behind pending cloud writes. | I360-003, E2 |
| FR-38 | The system MUST register these datasets, declared by `directory/inventory` (DM-70), as the Entra sources that E2.6 reads (E2.6 FR-B25 cites this spec; E2.6 does not define them). **Boot rule (H2-m3):** the dataset registry MUST refuse a dataset whose declared root kinds the scope renderer does not render (E-011 / T-1131); the refusal is a startup outcome, not a merge-order convention. Columns that reach another object are flagged related-object so E2.6's masking, grouping and aggregation rules apply unchanged; no cross-dataset join. **AD-derived columns (A2-m1):** correlation state, `candidate_reason` and the AD-derived part of the SOA badge are facts about AD objects. They are flagged related-object and masked for a runner without read on the AD side; synced / cloud stays visible, because it is an Entra fact (`onPremisesSyncEnabled`). | I360-003, ADM-169, ADM-094 (input only) |

| Dataset | Columns (typed; ID = Entra object `id`) | Scope roots needed |
| --- | --- | --- |
| `inventory.entra_users` | object id, UPN, display name, enabled, usage location, sync enabled, last sync time, **source-of-authority** (AD / Cloud / Candidate / Broken; AD-derived part masked per FR-38), correlation state*, `candidate_reason`*, `ad_object`* (related-object reference to the AD object, only for a `matched` correlation), licence count, created | `entra_tenant`, `administrative_unit`, `group_members` (Entra); an AD scope with `include_correlated` for matched rows |
| `inventory.entra_groups` | object id, display name, security enabled, membership kind (assigned / dynamic), role-assignable, source (AD-synced / cloud / cloud-managed), carries a licence, `ad_object`* (matched by SID, DM-20.I1b), created | same |
| `inventory.entra_licence_assignments` | one row per user × SKU: user id, SKU id, SKU part number, SKU friendly name, assignment kind (direct / via group), assigning group (related-object), state, error, observed time | same |

\* related-object column, masked without AD-side read. `onPremisesImmutableId`, mail and proxy addresses are
not exposed as columns in 2c. A dataset is readable only under its scope: a runner sees the rows their scope
reaches, and the SOA badge is derived, never edited.

## 4. Security considerations (tag all build tickets `security-sensitive`)

- **Privileges:** reads only (E2.7 FR-04 Read family); nothing here writes to Entra. Application-only.
- **Takeover signal.** Sync is what sets `cloud_seen_at` (DM-16.I9) and feeds the takeover gate
  (DM-20.I4(g)). `cloud_seen_at` is protected by the inventory trigger (`blueprint.md`, T-0431). A foreign
  delta page, a foreign host or a token for another tenant would let an attacker move correlation, hence the
  FR-36 binding.
- **Disclosure.** Masking per FR-38; `onPremisesImmutableId` never a column; a runner never learns that an
  out-of-scope AD object carries an anchor.
- **Safe primitives (rule 5).** OData only through P8 (`Eq`, `Str`, `Key(GUID)`); no URL or `$filter`
  literal outside the home packages; `@odata.nextLink` only after the host pin (P8 V12).
- **Scale.** Paged delta; the licence-state reconcile is paged; the dataset reads are paged by E2.6; a 100,000-user
  tenant is never held in memory.

## 5. Acceptance criteria

Tiers as in E2.7 §11: **F** fake Graph, **E** Entra sandbox `[LAB-E]`.

| ID | FR | Given / When / Then | Tier | Evidence |
| --- | --- | --- | --- | --- |
| AC-42 | 36, 37 | **Given** a tenant with users, groups and licence assignments **when** sync runs **then** inventory holds them with the FR-36 properties; a delta round applies only changes; a changed licence assignment appears after the targeted re-sync or the reconcile although delta does not track `licenseAssignmentStates`; a lost delta token triggers a full resync; Check now refreshes one object and re-evaluates the correlation without writing to Entra. | F, E | Sync tests; request log |
| AC-43 | 38 | **Given** the three datasets **when** the scope renderer lacks the Entra root kinds **then** the registry refuses each at Boot and E2.6 shows its "not available" state; **when** it supports them **then** each is registered with the FR-38 columns, related-object columns are flagged, `onPremisesImmutableId` is not exposed, and a runner sees only rows their scope reaches. | F | `dataset_registry_refuses_unrendered_root`; registry test; scope test (E-011) |
| AC-55 | 36 | **Given** a delta page or `nextLink` on a foreign host, or an access token whose `tid` differs from the connection's `directory_identity` **when** sync runs **then** the page or token is refused, nothing is stored and the connection reports the finding. | F | `delta_link_foreign_host_refused`, `token_tid_mismatch_refused` |
| AC-56 | 37 | **Given** one account pressing Check now across many requests, and a tenant under write load **when** the per-account or per-tenant cap is reached **then** further re-syncs are refused with the cap named, and pending cloud writes run before queued re-syncs. | F | `check_now_account_cap`, `check_now_tenant_cap`, `writes_have_priority_over_resync` |
| AC-57 | 38 | **Given** a runner whose scope is `entra_tenant` only **when** they read `inventory.entra_users` **then** correlation state, `candidate_reason` and `ad_object` are masked, synced / cloud stays visible, and no out-of-scope AD object is disclosed. | F | `entra_only_runner_sees_no_ad_derived_reason` |

## 6. Dependencies, out of scope, open questions

- **Dependency.** E-011 / T-1131: the `entra_tenant`, `administrative_unit` and `group_members` evaluators
  and the E2.6 reports renderer (E2.6 FB-4). Shared with E2.7 FR-30, FR-32, FR-33 and E2.6 AC-B30.
- **Out of scope.** Entra devices, group member lists and counts, service-plan detail (later); report
  *content* (E2.6 / M5); writes to Entra (E2.7).
- **Open.** OQ-F3 (Cloud Sync SID, E2.7 §13); OQ-F4 (delta returns `onPremisesImmutableId`,
  `assignedLicenses` and group `assignedLicenses` as selected; delta-token loss behaviour); OQ-F6 (reconcile
  cadence). No directional question.

## Sources

Microsoft Learn: [user delta](https://learn.microsoft.com/en-us/graph/api/user-delta?view=graph-rest-1.0) (read in full 2026-11-11: properties selected up front; `licenseAssignmentStates` not tracked) · [group delta](https://learn.microsoft.com/en-us/graph/api/group-delta?view=graph-rest-1.0) (permission from TM §6.6, page not re-read). Repo research cited inline; ME behaviour only from the ADMP research file and the parity matrix.

## Changelog

- 2026-11-11 · product-manager · revision 1: split out of E2.7 §7.6 (round 3, architecture review "Length"). FR-36…38 and AC-42/43 keep their numbers. Added: link and token binding (A2-m7, AC-55), re-sync budget and write priority (A2-m3, AC-56), Boot rule for datasets (H2-m3, AC-43), masking of AD-derived columns (A2-m1, AC-57).
