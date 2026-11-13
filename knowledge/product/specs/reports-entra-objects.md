---
title: "Spec: Entra object reports for the hybrid slice (ADM-094 basics)"
date: 2026-11-06
updated: 2026-11-06
status: draft
owner: heramb
author: product-manager
ticket: T-1018
epic: E-002
milestone: M2a
parity: [ADM-094]
scope: proposed
sources_last_checked: 2026-11-06
---

# Spec: Entra object reports for the hybrid slice (ADM-094 basics)

> An admin opens "Cloud users", "Guests" or "Groups without owner" from the same search box as every
> AD report, sees the Entra data with its age stated, sees which rows are the cloud copy of an AD
> account, and only ever sees the tenant objects their delegation reaches.

Follow-up 5 of [reports-2a.md](reports-2a.md) §12. It extends the 2a report engine to **Entra
objects held in inventory** (DM-16). It does **not** cover Exchange Online, sign-in, MFA or licence
reports; §7 says why and what unlocks each. Reviewed by `solution-architect`.

## 1. Problem and user

The ADMP Microsoft 365 report set is about 91 reports (ADM-094, see
[ADMP research](../../business/market-research/manageengine-admanager-plus.md)), and the Entra part
is where a hybrid admin lives for joiner/leaver audits: cloud-only accounts, guests, users with no
manager, groups with no owner, orphaned or expired passwords. Pain, all sourced:

- **Cloud needs another product / console.** "Cloud requires another product" (≈11 reviews,
  [customer voice X5](../../business/market-research/manageengine-ad-customer-voice-and-security.md));
  ADMP's M365 tab is a separate app (matrix differentiator 7,
  [feature-parity-matrix.md](../../business/competitive-analysis/feature-parity-matrix.md)).
- **Stale and slow.** Some ME Entra reports say they "may take up to six hours to update" and need
  Azure AD Premium
  ([ME Entra reports help](https://www.manageengine.com/products/ad-manager/help/office365/reports/azure-active-directory-reports.html),
  Users Last Logon, Inactive Users, read 2026-11-06). The product does not state data age on screen.
- **Report UX** is the #2 complaint theme (X2; see reports-2a §1).

| Persona | Job | Frequency |
| --- | --- | --- |
| Hybrid AD/Entra admin | List cloud-only and guest accounts, and synced accounts with no AD counterpart, to find orphans | Monthly review, ad hoc |
| Auditor | Group ownership and membership of the tenant, as a file | Quarterly access review |
| Help-desk technician delegated one tenant slice | See only the users and groups they are allowed to see | Daily |

## 2. Parity baseline

The matrix has **one** ID for this area, ADM-094. It cannot say which ME report is covered, so
this spec uses **activeDIQ report IDs** (`ENT-…`, same style as `USR-…` in 2a) in §5, and asks
`market-analyst` to split ADM-094 into per-category IDs (§11 Q5). No parity ID is invented here.

ME names below are exact from the
[ME Entra reports help](https://www.manageengine.com/products/ad-manager/help/office365/reports/azure-active-directory-reports.html)
(read 2026-11-06). ME's help still uses "Azure AD" and "Office 365" naming.
**Edition is Std+Pro** (matrix). Entra credential and permissions follow
[ADR-0002](../../development/decisions/0002-deployment-model.md) rules 3 and 8 (customer's own app
registration, certificate auth, read permissions only for reports).

The ME Entra help page names 64 reports; this spec covers **36** of them through 17 presets (§5) and defers the rest with
a reason (§7).

## 3. Enhancements

Each is tied to a sourced pain. All three are v1 for this slice.

| # | Enhancement | ME baseline | Target |
| --- | --- | --- | --- |
| E1 | **Freshness of the Entra copy is stated per tenant**, with the same labels as AD (reports-2a §8.2). A tenant never synced, or with a failed delta pass, is named, not silently empty | ME states up to six hours for some reports and nothing on the report itself | Every Entra run shows `Synced hh:mm` or `Stale: last sync n h ago (<tenant>)` |
| E2 | **Hybrid-aware by default.** Every user and group row shows `Source` (Cloud only / Synced from AD / Cloud-managed) and, for synced rows, the AD counterpart and its correlation state (DM-20). One filter "no AD counterpart" replaces ME's "Exclude Active AD users" step | ME splits Cloud Users and Synced Users into separate reports and has no counterpart link (customer voice X5) | Orphan check in one report, one filter |
| E3 | **A report that cannot be answered says so.** A report whose input needs a licence, a permission or data we do not store shows the reason and the fix, never an empty grid or a zero | ME's Inactive Users and Users Last Logon require Azure AD Premium; the page states it in help text only | Zero reports show `0 rows` for an input that was not read |

Not promised: charts, cross-tenant roll-ups, act-on-results (2b), report builder (2c).

## 4. Experience target

Same budgets as reports-2a §5, no new screens:

| Task | Budget | Target time |
| --- | --- | --- |
| Open an Entra report with results: `/`, type the name or the ME name, Enter | 3 interactions / 1 typed field / 2 screens | ≤ 6 s |
| Find synced accounts with no AD counterpart | open + one filter = 5 / 1 / 2 | ≤ 12 s |
| Export or schedule | As 2a (T19 6 / 1 / 2, T20 7 / 2 / 3) | As 2a |

The admin never has to pick a "tenant account" before seeing data (all permitted tenants are the
default, as with domains in 2a), nor choose between "Cloud Users" and "Synced Users" reports to
answer one question. Task-time values for these rows are `[PROPOSED]` pending `product-designer`
measurement (not benchmarked yet; the 2a benchmark has no Entra task).

## 5. The Entra report slice

Report IDs are ours. Datasets: `inventory.entra_users`, `inventory.entra_groups`,
`inventory.entra_contacts` (derived from DM-16 rows of the `entra_tenant` connection; §6 lists the
columns each needs). "ME names" are the exact ME names the preset answers.

| ID | Report (preset) | ME names answered | Input from DM-16 | State |
| --- | --- | --- | --- | --- |
| ENT-USR-01 | All users (filter: Source, Enabled, Type = Member/Guest) | "Office 365 Users", "Cloud Users", "Synced Users", "Guest Users" | `object_class`, `enabled`, `userType`, `onPremisesSyncEnabled`, `cloud_seen_at` | v1 |
| ENT-USR-02 | Synced users with no AD counterpart | none (E2) | Correlation (DM-20) state | v1 |
| ENT-USR-03 | Users by manager (filter: has / no manager; all managers) | "All Managers", "Users With Managers", "Users Without Managers" | `manager` link | v1 |
| ENT-USR-04 | Users with empty attributes (pick attributes, all/any) | "User with Empty Attributes" | typed synced attribute set | v1 |
| ENT-USR-05 | Users sharing an attribute value | "Users with Same Attribute Values" | typed synced attribute set | v1 |
| ENT-USR-06 | Recently created / modified users (period) | "Recently Created Users", "Recently Modified Users" | `when_created`, `when_changed` | v1 |
| ENT-USR-07 | Deleted users (state `deleted`; period) | "Deleted Users", "Recently Deleted Users" | `state`, deleted-items observation | v1 |
| ENT-USR-08 | Users with / without photo | "Users with Photo", "Users without Photo" | photo present flag | ◐ needs a presence flag, not the image (§6) |
| ENT-USR-09 | Password never expires | "Never Expiring Passwords" | `passwordPolicies` | v1 |
| ENT-USR-10 | Password last changed / unchanged for n days | "Password Changed Users", "Password Unchanged Users" | `lastPasswordChangeDateTime` | v1 |
| ENT-USR-11 | Password expired / expiring soon | "Password Expired Users", "Soon To Expire Passwords" | `lastPasswordChangeDateTime` + tenant password-expiry setting | ◐ tenant setting must be read; else Unknown (E3) |
| ENT-USR-12 | Users with provisioning errors | "Users with DirSync Provisioning Error", "Users with Validation Error" | `onPremisesProvisioningErrors` | ◐ |
| ENT-GRP-01 | All groups (filter: Security / Microsoft 365 / Mail-enabled / Dynamic; Source) | "All Office 365 Groups Report", "Office 365 Security Groups Report", "Office 365 Distribution Groups Report", "Office 365 Dynamic Distribution Groups Report" | `groupTypes`, `securityEnabled`, `mailEnabled`, `membershipRule` | v1 |
| ENT-GRP-02 | Group members (pick groups; direct or transitive, with path) | "Office 365 Group Members Report", "Office 365 Dynamic Distribution Group Members Report" | DM-17 edges | v1 |
| ENT-GRP-03 | Groups with / without owner | "Groups with Owner", "Groups without Owner" | owner links | v1 |
| ENT-GRP-04 | Group size | "Group Size" | DM-17 edges (count) | v1 |
| ENT-CTC-01 | Contacts (filter: mail-enabled; period for new/modified/deleted) | "Contact List", "Mail Contacts", "New Contacts", "Modified Contacts", "Deleted Contacts" | `orgContact` rows | v1 |

That is 17 presets answering 36 of the 64 ME names on the help page (recount at review; the ME-name column is the authority). The other 28 are in §7.

Rules inherited unchanged from 2a: run model (§8.1), exports (§8.3), schedules (§8.4), permissions
(§8.5), audit trail (§8.6). Dataset columns are shown with the Source/AD-counterpart columns from E2.

## 6. Data and freshness

**Inventory columns.** DM-16 holds the Entra row, its `cloud_seen_at` (I9) and the synced attribute
set. Before build, `directory-engineer` confirms the following are in the Entra synced set and adds
the missing ones (ticket §11): `userType`, `accountEnabled`, `passwordPolicies`,
`lastPasswordChangeDateTime`, `createdDateTime`, `onPremisesSyncEnabled`,
`onPremisesProvisioningErrors`, manager and owner links, `groupTypes`, `membershipRule`,
a photo-present flag, deleted-items observation.
Secrets (DM-16.I3) and photos are never stored.

**Freshness.** Entra rows carry `observed_at`. The 2a labels (§8.2) apply with the tenant as the
unit: `as_of` is the oldest watermark of the covered NCs **and** tenants. Entra has no DCs, so the
"Read from n of m DCs" label never appears. A report reading both AD and Entra shows both ages.
`[PROPOSED]` staleness threshold: 2 h for Entra, set with P1's per-connection watermark.

**Entra permissions.** Report reads use the tenant's app registration, read-only application
permissions (`User.Read.All`, `Group.Read.All`, `Directory.Read.All`-class; exact list is T-0007's)
`[UNVERIFIED]`. If the permission is missing, the affected reports show `missing.entra_permission`
(DM-35 finding family) with the permission name, not an empty list.

## 7. Out of this slice, and what unlocks each

| ME names / area | Why not now | Goes to |
| --- | --- | --- |
| Licensed / Unlicensed users, License Details | Licence assignment is not in inventory (DM-16 carries none). Needs `assignedLicenses` and SKU catalogue | follow-up spec after the licence build (ADM-161 in M5) |
| MFA Enabled / Disabled, MFA Status | Needs authentication-method reads (a separate, sensitive permission) | follow-up, security review first |
| Users Last Logon, Inactive Users, Never logged on, logon activity, Recent Logon Failure | Sign-in data needs Entra ID P1 or P2 and an audit-log permission `[UNVERIFIED]` ([search found sign-in logs need P1](https://practical365.com/entra-id-sign-ins/); `signInActivity` itself not confirmed). ME also states the Premium need | follow-up; E3 rule applies |
| Exchange Online users and mailboxes, OWA, mailbox security | EXO needs the PowerShell sidecar (v1-scope row, M5) | M5, [v1-scope-options.md](../../business/scoping/v1-scope-options.md) |
| Contacts Audit Log, Contacts Activity, Inactive Contacts | Need audit/mail-flow logs | later |
| Last User Activity by Service / Date, User Created Objects | Audit-log based | later |
| Azure Locked / Unlocked Users | Entra has no admin-visible lockout flag in inventory `[UNVERIFIED]` | later, ask `ad-expert` |
| Report from CSV (ADM-096), builder (ADM-097), act on results (ADM-098) | Own specs | per 2a §11 |

## 8. Platform matrix

`✓` supported · `◐` partial as stated · `✗` not in this slice, with where it goes · `n/a`. Reports
are server-side and identical on `windows` and `linux-oci` (ADR-0002 rule 1).

| Capability | AD on-prem only (no Entra connection) | Entra-only tenant | Hybrid (confirmed HybridLink) | GCC / sovereign clouds | `windows` | `linux-oci` | Console | REST API | PowerShell module |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ENT-USR / GRP / CTC reports | n/a (reports hidden, no empty tabs) | ✓ | ✓ | ✗ → decision needed: DM-10 does not name national clouds `[UNVERIFIED]` | ✓ | ✓ | ✓ | ✓ | ◐ follows API |
| Source and AD-counterpart columns (E2) | n/a | ◐ every row is Cloud only, columns hidden | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ◐ |
| ENT-USR-02 orphans | n/a | ✗ no AD to compare, report hidden | ✓ needs a `confirmed` link (DM-21.I2) | ✗ | ✓ | ✓ | ✓ | ✓ | ◐ |
| Export, schedule | n/a | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ◐ |
| Windows Server | no DC-side component: n/a |  |  |  |  |  |  |  |  |

Entra credential per profile follows ADR-0002 rule 3 (including `saas`, which is not v1). The
**delegation prerequisite** (T-1131) applies to every cell: until it lands, nobody but an assignment
that expresses tenant access reaches Entra rows; reports fail closed (§9).

## 9. Security and audit

- **Scope.** 2a read scopes are AD-only, so Entra rows are unreachable by every admin until
  T-1131 defines the Entra root kinds (`entra_tenant`, `administrative_unit`, and the `group_members` interaction). **This spec
  does not ship before T-1131.** Reports fail closed on any root kind they do not understand
  (2a §8.1) and the empty state names the reason.
- **Read-only.** Reports need no write permission in Entra. The app registration holds no privileged
  role permission (ADR-0002 rule 9).
- **Our audit trail** records each run, export and schedule (2a §8.6) with the tenant ID in
  `scope_applied`. Recipients of a scheduled Entra report get the stored artefact under 2a's
  external-recipient rules (TM-D30).
- **PII.** Guest users carry external e-mail addresses; exports carry them. `security-architect`
  reviews: guest e-mails in a delivery to an external recipient, deleted-user rows, and what the
  About block states. Build tickets are tagged `security-sensitive`.
- **Tier-0.** `tier0` rows (DM-16.I8) are shown read-only like any other; no action exists.

## 10. Acceptance criteria

Each is verifiable by `qa-verifier` through the UI or API. IDs are `AC-ENT-n`.

1. **Cloud-only list.** Given a tenant with 3 cloud-only and 5 synced users, When an admin opens ENT-USR-01 with Source = Cloud only, Then exactly the 3 rows show, each with Source `Cloud only` and no AD counterpart.
2. **Orphan filter.** Given 5 synced users, 4 with a confirmed correlation and 1 whose AD object was deleted, When ENT-USR-02 runs, Then exactly the 1 row shows with its AD counterpart empty and correlation state shown.
3. **Link not confirmed.** Given a HybridLink in `proposed`, When ENT-USR-02 runs, Then the report states the link is unconfirmed and shows no rows as orphans.
4. **No Entra connection.** Given the tenant has only AD, When the admin searches "cloud users", Then no Entra report is offered and no empty Entra report appears.
5. **Delegation trims.** Given an admin whose assignments reach one administrative unit (once T-1131 exists), When they run ENT-USR-01, Then counts, totals and "checked n objects" equal only rows in that unit and none outside.
6. **Fail closed before T-1131 / unknown root kind.** Given a role whose scope has a root kind the reports do not understand, When it runs an Entra report, Then zero rows show and the empty state names the unsupported scope kind, not "no data".
7. **Freshness fresh.** Given the tenant's last delta pass 20 minutes ago, When any ENT report opens, Then the header shows `Synced hh:mm` and `as_of` equals that watermark.
8. **Freshness stale.** Given the last successful pass was 3 h ago, When a report runs, Then it runs with `Stale: last sync 3 h ago (<tenant>)`, and an export and a scheduled delivery carry the same label.
9. **Never synced.** Given a tenant connection with no completed first sync, When a report covers it with an AD domain, Then the AD rows show and the tenant is listed as `skipped (not synced yet)`.
10. **Missing permission.** Given the app registration lacks the group-read permission, When ENT-GRP-01 runs, Then it shows `missing.entra_permission` naming the permission and no `0 rows`.
11. **Input not read.** Given the tenant password-expiry setting was not read, When ENT-USR-11 runs, Then every row shows `Unknown (input missing)` and the report never claims "not expired".
12. **Group members with path.** Given group G1 contains group G2 which contains user U, When ENT-GRP-02 runs for G1 transitive, Then U appears with path `G1 > G2`; with direct only, U does not appear.
13. **Large group.** Given a group with 1,800 members, When ENT-GRP-02 runs, Then all 1,800 rows are present across pages with the correct count, and an export has 1,800 data rows.
14. **No owner.** Given 10 groups, 3 without an owner, When ENT-GRP-03 filters "without owner", Then exactly those 3 show.
15. **Large directory.** Given a tenant with 100,000 users, When ENT-USR-01 opens, Then the first 50 rows show within 2 s at p95 and the full count within 5 s `[PROPOSED]` (calibrated by `reporting-engineer`).
16. **Deleted users.** Given a user deleted 5 days ago and recoverable, When ENT-USR-07 runs with period 7 days, Then that user shows with its deleted time; with period 1 day it does not.
17. **ME name search.** Given the admin types "Groups without Owner", When they press Enter, Then ENT-GRP-03 opens with that filter applied.
18. **Guest export.** Given 4 guest users, When ENT-USR-01 (Type = Guest) is exported to CSV, Then the file has 4 data rows and an About block with generator, time, freshness label and scope, and a cell beginning `=` is neutralised as in 2a §8.3.
19. **Schedule.** Given an Entra report, When a schedule is created from the screen to an external recipient, Then the 2a external-recipient confirmation and MFA step apply and the delivery history records the tenant.
20. **Audit.** Given any run, export or schedule of an Entra report, Then our audit trail has an entry naming the runner, report ID, tenant and row count, and none contains cell values.
21. **Read-only.** Given the app registration has only read permissions, When any ENT report runs, Then no Graph write call is made (verified in the connector call log).
22. **Deferred reports are honest.** Given the admin searches "licensed users", Then the result states the licence report is not available yet and why, and does not return a different report silently.

## 11. Open questions and follow-ups

| # | Question | Owner | Blocks |
| --- | --- | --- | --- |
| Q1 | Entra read-scope root kind(s) | solution-architect, T-1131 | **All build** |
| Q2 | Does the Entra synced set already carry every column in §6? | directory-engineer | Build start |
| Q3 | National-cloud (GCC/sovereign) support: in or out of v1 | ceo-decisions candidate: scope; not asked yet, no demand sourced | Matrix row only |
| Q4 | Sign-in, MFA and licence reports: which permission and Entra licence tier are needed | research, `market-analyst` + `ad-expert` | §7 follow-ups |
| Q5 | Split ADM-094 in the matrix into per-category IDs | market-analyst | Traceability |

No question here is directional for the CEO today. Q3 would become one only if a customer needs
a sovereign cloud.

Filed as `backlog`: T-1689 (research, Q4 and Q5), T-1690 (inventory attribute check, Q2);
licence and sign-in report specs follow once T-1689 answers.

## Sources

[ME Entra reports help](https://www.manageengine.com/products/ad-manager/help/office365/reports/azure-active-directory-reports.html) (read 2026-11-06) ·
[ADMP research](../../business/market-research/manageengine-admanager-plus.md) ·
[customer voice](../../business/market-research/manageengine-ad-customer-voice-and-security.md) ·
[parity matrix](../../business/competitive-analysis/feature-parity-matrix.md) ·
[reports-2a](reports-2a.md) · [domain model](../../development/domain/domain-model.md) DM-16, DM-20, DM-21, DM-35 ·
[ADR-0002](../../development/decisions/0002-deployment-model.md) ·
[practical365 on sign-in logs](https://practical365.com/entra-id-sign-ins/).

## Changelog

- 2026-11-06 · created (T-1018)
