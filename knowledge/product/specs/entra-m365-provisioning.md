---
title: "Spec: Entra / M365 provisioning via Graph — onboarding, bulk users, licences, account actions, groups, hybrid view"
date: 2026-11-14
updated: 2026-11-14
status: draft
owner: heramb
author: product-manager
ticket: T-2058
epic: E-008
milestone: M2c
parity: [ADM-009, ADM-027, ADM-131, ADM-159, ADM-160, ADM-161, ADM-162, ADM-164, ADM-169, M365-005, M365-007, I360-003]
scope: proposed
sources_last_checked: 2026-11-14
---

# Spec: Entra / M365 provisioning via Graph

> An admin connects an Entra tenant in one guided flow, then creates, licenses, changes and groups
> cloud users from the same console and the same preview-and-undo pipeline as AD. Every Entra object
> shows who authors it (AD or Entra). Edits Graph would refuse are refused **before** the request,
> with the reason and the place where the edit does work.

Reviewed by `solution-architect`; security-sensitive (`security-architect` second review). Build
tickets for E-008 are cut from this file by `project-manager`. Out of scope: the Exchange Online
helper (E-020), M365 reports (see [reports-entra-objects.md](reports-entra-objects.md)).

## 1. Problem and user

| Persona | Job | Frequency |
| --- | --- | --- |
| Hybrid AD/Entra admin | Onboard a tenant once; create or change cloud users and guests; assign or swap licences; run block/reset/restore | Onboarding once per tenant; users and licences daily |
| Help-desk technician (delegated) | Licence and account actions on one slice of users | Daily |
| Joiner/leaver owner | The cloud half of a joiner or leaver, in the same flow as the AD half | ≈33 joiners and leavers per 1,000 staff per month ([benchmark T07, T09](top-admin-tasks-benchmark.md)) |

What it costs in ManageEngine today (all sourced):

- **Cloud is another product.** "Only covers domain on premises, cloud requires another product" (≈11 reviews, [customer voice X5](../../business/market-research/manageengine-ad-customer-voice-and-security.md)). ADMP's M365 module is an embedded app with its own layout and still says "Azure Active Directory" ([ADMP research W8](../../business/market-research/manageengine-admanager-plus.md)).
- **Slow.** Assigning a licence is 12 interactions and ≈26 s in the M365 tab ([benchmark T14](top-admin-tasks-benchmark.md)); a joiner with licence is 13 interactions, 26.7 s (T07).
- **Hybrid is half-handled.** ME's orchestration cloud actions "work only on users synced by DirSync" ([ADMP research W15](../../business/market-research/manageengine-admanager-plus.md)); the licence page filters by AD domain/OU, and the cited help shows no per-attribute authority `[UNVERIFIED — absence not confirmed, §15 Q5]` ([ADM-169 row](../../business/competitive-analysis/feature-parity-matrix.csv)).

## 2. Parity baseline

IDs from the [parity matrix](../../business/competitive-analysis/feature-parity-matrix.md); ME behaviour from [ADMP research §3.Q](../../business/market-research/manageengine-admanager-plus.md) (ME help pages linked there). Edition: Std+Pro for all rows. Class = matrix class.

| ID | ME behaviour (research) | Class | v1 | Covered by |
| --- | --- | --- | --- | --- |
| ADM-159 | Global-admin consent creates the app, or manual registration; several tenants; many-to-many domain↔tenant links ([ME help](https://www.manageengine.com/products/ad-manager/help/directory-application-settings/microsoft-365-tenant-configuration.html)) | enhance | yes | FR-01…FR-09 |
| I360-003 | Entra sync via Graph app, consent or manual (Identity360, same capability as ADM-159) | parity | yes | FR-01…FR-09; delta read FR-10 |
| ADM-009 | Create M365 account without an AD user | parity | yes (P2 in matrix, pulled into M2 by FD-03) | FR-11 |
| ADM-160 | Bulk create/modify, cloud-only and synced users; bulk guest creation | parity | yes (FD-03) | FR-11…FR-14 |
| ADM-027 | M365 at creation: licences and service plans, groups, roles, Exchange alias, litigation hold, archive, quotas, protocols | enhance | **partly**: licences, service plans, groups. Roles, Exchange alias, litigation hold, archive, quotas, protocols are out (§12) | FR-15 |
| ADM-161 / M365-005 | Add, replace, remove licences; group-based licence changes; CSV by ObjectId or UPN; filter by AD domain or OU | parity | yes | FR-16…FR-22 |
| ADM-162 | Reset password, block/unblock, delete, hard delete, restore; change UPN or domain; set manager; revoke refresh tokens | parity | yes | FR-23…FR-28 |
| ADM-164 / M365-007 | M365, distribution, mail-enabled security, dynamic distribution groups; security-group changes; templates | parity | **partly**: M365 and security groups. Distribution and mail-enabled security groups are read-only in Graph (Exchange only, [groups overview](https://learn.microsoft.com/en-us/graph/api/resources/groups-overview?view=graph-rest-1.0)), so they are shown and not changed (E-020) | FR-29…FR-32 |
| ADM-131 | Delegation of cloud tasks (cloud scope of the same RBAC model) | parity | yes | FR-33 |
| ADM-169 | Remote mailboxes; filter cloud users by AD domain or OU; cloud actions only on DirSync users | leapfrog | **partly**: source-of-authority view yes; remote mailboxes out (Exchange, E-020) | FR-34…FR-41 |

M365-004 (bulk lifecycle) is "same capability as ADM-160" in the matrix and is covered by ADM-160.

## 3. Enhancements

| # | Enhancement | Pain it answers | v1 |
| --- | --- | --- | --- |
| E1 | **One flow and one preview/undo pipeline for AD and Entra** (ADR-0005). A joiner creates the AD user, the cloud licence and groups in one operation | X5 "cloud requires another product"; W8 iframe app | yes |
| E2 | **Source-of-authority-aware hybrid view** with pre-flight refusal and "edit in AD instead" (§7) | W15, ADM-169 matrix leapfrog | yes |
| E3 | **Licence plan with conflict check before any write**: shortfall of seats, missing usage location, overlapping SKUs, direct vs group-inherited (§6) | the 12-interaction licence flow (T14); silent failures [UNVERIFIED — no sourced ME complaint; the target is the T14 task time] | yes |
| E4 | **Guided onboarding with certificate auth and a least-privilege checklist**: the permission set is derived from the features the admin switches on; extras are refused (TM-D5, D-0007) | matrix ADM-159 enhancement column | yes |
| E5 | **Attestation-expiry alert and audit-log-gap staleness rule** shown in connection health (§8) | m2-plan §1 carry-over for E-013/E-008 | yes |

Not v1: transferring source of authority (`User-OnPremisesSyncBehavior.ReadWrite.All` is on the deny list, TM-D5), licence reclamation by inactivity (needs sign-in activity, Entra P1/P2, [UNVERIFIED — a report, not provisioning]).

## 4. Experience target

Measured against the [top-admin-tasks benchmark](top-admin-tasks-benchmark.md) (interactions = clicks + typed fields; ME numbers are its measured ones). `product-designer` confirms flows; QA measures.

| Task | ME today | Target |
| --- | --- | --- |
| T14 Assign one licence to a found user | 12 interactions, ≈26 s (M365 tab) | **≤ 6 interactions, ≤ 19 s** (benchmark target) |
| T07 Joiner with licence and groups (AD + cloud in one operation) | 13 interactions, 26.7 s | **≤ 6 interactions, ≤ 18 s** (benchmark target) |
| T09 Leaver, cloud half included (block, revoke sessions, remove licence) | 17 interactions, 31.3 s | **≤ 17 s** (benchmark target) |
| Onboard a tenant (consent path) | not benchmarked `[UNVERIFIED]` | ≤ 8 interactions and ≤ 5 min from "Add tenant" to the first synced users; **0** values copied by hand in the consent path |
| Swap licence SKU for 500 users from a CSV | per-user CSV by ObjectId or UPN ([ME help](https://www.manageengine.com/products/ad-manager/help/office365/management/license-management.html)) | one upload, one preview showing seat shortfall and every skip with its reason, one confirm; ≤ 8 interactions |

The admin never has to: write an OData `$filter` or a Graph URL; look up a SKU GUID or service-plan GUID; know whether a user is synced before choosing a tool; copy a client secret (there is none; certificate only); open a second console for cloud work.

## 5. Onboarding an Entra tenant (ADM-159, I360-003)

**Path A — guided consent (default).** Admin enters nothing but the tenant name or domain. The server shows the permission checklist derived from the features switched on (§9), then sends the admin to Microsoft's consent page. Consent is performed by a Global Administrator signing in at Microsoft; activeDIQ never sees that admin's credentials or token beyond the consent callback. The customer's own app registration holds a **certificate** credential (ADR-0002 rules 3, 8); no client secret exists, no Entra directory role is held (TM-O1).

**Path B — manual registration** for customers who forbid automatic app creation: the product shows copy-ready steps, the certificate (public part) to upload, the permission list, and accepts tenant ID and application ID. The private key never leaves the server's credential store. Which of A or B the platform can ship first (does path A require a multi-tenant activeDIQ app, which a self-hosted product does not have?) is open: §13 Q1.

Verification (reuses the ad-forest-connection pattern, [spec](ad-forest-connection.md) §7): identity (tenant ID fixed at first verification, DM-10.I1/I2), certificate auth works, **granted permissions read back and compared** with the allow list and deny list (TM-D5, D-0007), Tier-0 guard reads (§9). Refusals are named; **a failure that is not a pass is never shown as one**.

Many-to-many links: a **HybridLink** (DM-21) says which AD domain syncs to which tenant. The wizard proposes links found from correlations; they stay `proposed` until an admin holding `connections.hybrid_link.confirm` over **both** sides confirms (DM-21.I2).

## 6. Licence model (ADM-161, M365-005)

Objects shown to the admin, read from Graph into inventory:

- **SKU** (`GET /subscribedSkus`): friendly name, purchased/assigned/available seats, capability status. The admin picks by name; the GUID is never typed.
- **Service plans** inside a SKU, individually switchable on (`disabledPlans` on assign, [assignLicense](https://learn.microsoft.com/en-us/graph/api/user-assignlicense?view=graph-rest-1.0)).
- **Assignment source** per user per SKU: **direct** (assigned on the user) or **inherited from group(s)**. A SKU can be both. The user's licence panel shows each source with a link to the group. Group-based licensing needs paid Entra ID `[UNVERIFIED — Microsoft requirement, confirm at onboarding in a tenant without P1; the product must read capability, not assume it]`.

**Operations** (each an Action through ADR-0005; Plan shows the diff, seat check and conflicts; Apply calls `assignLicense` for users or groups):

| Operation | Behaviour |
| --- | --- |
| Add | Adds SKU(s) with the chosen service plans. Plan refuses an item with no usage location set **and offers to set it in the same operation** (a licence cannot be assigned without one `[UNVERIFIED — Microsoft documents this on the licensing-problems page, not on assignLicense; confirm in lab]`) |
| Remove | Removes **direct** assignment only. If the same SKU is also inherited from a group, Plan says so: "Still licensed through group *X*" and does not claim the licence was removed |
| Replace (A→B) | One Plan with two effects: add B, remove A, in the one `assignLicense` call (it takes both lists, [ref](https://learn.microsoft.com/en-us/graph/api/user-assignlicense?view=graph-rest-1.0)), so the user is never briefly unlicensed |
| Group licence change | Add/remove a SKU on a group (`POST /groups/{id}/assignLicense`). Plan shows the member count that will gain or lose it. Group-licence errors are read back after Apply and listed per user |

**Conflicts Plan detects before writing:** not enough seats (shows the shortfall and the first *n* users who would succeed — the admin chooses to proceed with *n* or stop); no usage location; the SKU is already direct (no-op, shown as skipped); removal blocked by group inheritance; target is Entra `tier0` (refused, §9); target synced from AD and the operation is allowed in cloud (licences are a cloud property, so synced users are valid targets).

**Bulk.** Pick users by search, by an existing report/list, by **AD domain or OU** (through confirmed correlations only, ADM-161), by group, or by CSV keyed on ObjectId **or** UPN (parity). Throttling (`429` with `Retry-After`) is waited out by the pipeline ([ADR-0005 rule on Graph throttling](../../development/decisions/0005-operation-pipeline-and-audit-trail.md)); the admin sees progress, never a failed item for being throttled.

## 7. Source of authority and the hybrid view (ADM-169, ADM-160)

Every Entra user and group row carries an **Authority** badge, derived from `onPremisesSyncEnabled` and the correlation state (DM-20):

| State | Meaning | Edits |
| --- | --- | --- |
| **Cloud** | Created in Entra, `onPremisesSyncEnabled` null/false | All Graph-writable properties in §10 |
| **Synced from AD** (correlated, `matched`) | Authored by the AD object; the cloud copy is read-only for the on-prem-sourced properties | Cloud-owned properties (licences, usage location, group membership of cloud groups, sessions, block `[UNVERIFIED — lab, see §10]`); AD-owned properties are refused with the hybrid message and an **Edit in AD** action when the admin's scope reaches the AD object |
| **Synced, no AD match** | Marked synced but no correlated AD object: orphan | Same refusal; message says no AD object was found |
| **Cloud-authored after SOA transfer** (user SOA GA Jan 2026, [matrix LAND §7.1#6](../../business/competitive-analysis/feature-parity-matrix.md)) | Customer moved authority to Entra | Treated as Cloud. v1 **shows** the state and does **not** transfer it (permission is deny-listed) |

**The refusal.** Graph treats some properties of a synced user as read-only: "For an `onPremisesSyncEnabled` user, the source of authority for this set of properties is the on-premises and is read-only" (`onPremisesExtensionAttributes`, [user update](https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0)); the page says more generally that for synced users the ability to update certain properties "is additionally determined by the source of authority and whether synchronization is enabled". Microsoft's list of synced attributes is the sourced basis for our table (`soa v1`): [attributes synchronized](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-sync-attributes-synchronized). The exact per-property result and Graph's error code per property are `[UNVERIFIED — lab, needs a synced user in a sandbox tenant (T-0075)]`; until verified, **the table fails closed: any property on the on-prem-sourced list is refused**.

The hybrid message, verbatim in intent: **"`<property>` of `<user>` is authored by Active Directory (`<domain>`). Entra will not accept this change, and a sync would overwrite it. Change it on the AD account — [Edit in AD] (needs rights on the AD object) — and it will reach Entra at the next sync."** If the admin has no reach on the AD object: "Ask an AD administrator" and no button. Bulk and CSV: a refused row is reported, never skipped silently, and the preview counts refusals per reason.

**Edit in AD** is an AD write on a synced user, which flows to Entra through Connect and so is checked by the same property guard on the AD path (threat model TM-D25 rule 7f). It runs through the AD write Actions of E-008 ([objects module](../../development/architecture/modules/objects.md)), not a new path.

**Hybrid filters (parity ADM-169/161):** filter cloud users by AD domain and OU, by authority state, by "synced but no AD match", by "AD user with no cloud account".

**Remote mailboxes** (ADM-169 row part): out, §12.

## 8. DM-10.I7: attestation expiry alert and audit-log-gap staleness rule

Base rule is in [DM-10.I7](../../development/domain/domain-model.md): `takeover_protection` is `attested` only while both sync flags were true, `attested_at` is younger than `attestation_max_age` (default 90 days), and no demotion signal has arrived. Any other state makes every correlation in the tenant `candidate`, and so removes the hybrid view's "Synced from AD (matched)" state and the on-prem-sourced messages degrade to "authority unconfirmed". This section adds the **user-visible alert and the gap rule** carried by [m2-plan §1](../../business/scoping/m2-plan.md).

1. **Expiry alert.** 14 days before `attested_at + attestation_max_age`, health warns (already DM-10.I7(c)); this spec adds **delivery**: a notification to every holder of `connections.takeover.attest` over the tenant, repeated at 7, 3 and 1 days, then a banner on the Cloud users list and the hybrid view while `stale`. The alert says what happens at expiry in plain terms: "At expiry, cloud users stop showing as matched to AD and Edit-in-AD links are withheld."
2. **Audit-log-gap rule.** With `AuditLog.Read.All` the monitor reads `directoryAudits` to catch a change to the tenant sync features after `attested_at` (DM-10.I7(d)). A gap is time the log was not read. Microsoft retains Entra audit logs **7 days (Free) or 30 days (P1/P2)** ([data retention](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention)). **Rule (proposed values, ratification by `solution-architect` with `security-architect`):**
   - The monitor records the end time of each *complete, successful* read.
   - If now − last complete read > **24 h**, health shows **change monitoring degraded** (warning).
   - If now − last complete read > **6 days** (the 7-day Free window minus a day, because the tenant's edition is not assumed), or the permission was removed after having been present, state becomes **`stale`** until the next complete read covers the gap **and** a new attestation is made. Fail closed: we cannot prove no sync-feature change happened.
   - Without `AuditLog.Read.All` the gap rule does not run; age is the only trigger and health says change monitoring is off (DM-10.I7(d)).
3. **Visible consequence.** The Cloud users list and the connection page show: state, last complete read, next expiry date, and a one-click **Re-attest** (starts the delegated Global Administrator flow, step-up required).

## 9. Permissions and write-path scope (Graph least privilege)

Allow list and deny list are decided in [threat model §6.6 (TM-D5)](../../development/architecture/threat-model.md) and [graph-data-permissions-policy.md](../../development/decisions/graph-data-permissions-policy.md) (D-0007); this table assigns each capability its permission from them. The app holds **no directory role**; permissions are granted **only for features the admin switched on**. `[lab]` = TM-D5 marks it unverified; the build ticket must close it in the Entra lab (T-0075) and fail closed until then.

| Capability (parity) | Graph call | Application permission |
| --- | --- | --- |
| Tenant facts (ADM-159) | `GET /organization` | `Organization.Read.All` |
| Read SKUs (ADM-161, M365-005) | `GET /subscribedSkus` | `LicenseAssignment.Read.All` |
| Assign/remove licences, users and groups (ADM-161, M365-005) | `POST …/assignLicense` | `LicenseAssignment.ReadWrite.All` ([user](https://learn.microsoft.com/en-us/graph/api/user-assignlicense?view=graph-rest-1.0)) |
| Create cloud users (ADM-009, 160, 027) | `POST /users` | `User.Create` |
| Invite guests (ADM-160) | `POST /invitations` | `User.Invite.All` |
| Update properties, UPN (ADM-160, 162) | `PATCH /users/{id}` | `User.ReadUpdate.All` (UPN coverage `[lab]`) |
| Reset password (ADM-162) | `PATCH` `passwordProfile` | `User-PasswordProfile.ReadWrite.All`; whether app-only also needs a role is contradictory on Microsoft's page `[lab]` |
| Block/unblock (ADM-162) | `PATCH` `accountEnabled` | `User.EnableDisableAccount.All` + `User.Read.All` |
| Soft delete; set/remove manager (ADM-162) | `DELETE /users/{id}`; `/manager/$ref` | `User.ReadWrite.All`, the only documented one; granted **only if these features are on** `[lab: whether User.DeleteRestore.All suffices]` |
| Hard delete, restore (ADM-162) | `/directory/deletedItems/{id}` | `User.DeleteRestore.All` |
| Revoke sessions (ADM-162) | `POST …/revokeSignInSessions` | `User.RevokeSessions.All` |
| Create groups (ADM-164, M365-007) | `POST /groups` | `Group.Create` |
| Update, delete groups; owners | `PATCH`/`DELETE`, `owners/$ref` | `Group.ReadWrite.All` in practice (also reads M365 group conversations; accepted, feature-gated) |
| Group membership | `members/$ref` | `GroupMember.ReadWrite.All` |
| Hybrid view and delta (ADM-169, I360-003) | `GET /users`, `/users/delta`, `/groups/delta` | `User.Read.All`; `GroupMember.Read.All` |
| Tier-0 guard (required for any write feature) | memberOf, role assignments, PIM-for-Groups schedules | `Directory.Read.All`, `RoleManagement.Read.Directory`, `PrivilegedEligibilitySchedule.Read.AzureADGroup`, `PrivilegedAssignmentSchedule.Read.AzureADGroup` |
| Change monitor (optional, recommended) | `GET /auditLogs/directoryAudits` | `AuditLog.Read.All` |
| Attestation | `GET /directory/onPremisesSynchronization` | **delegated** `OnPremDirectorySynchronization.Read.All` inside a Global Administrator's sign-in; no app-only form |

Refused at onboarding (EV3, D-0007 and TM-D5 deny list): `Directory.ReadWrite.All`, role-management writes, `Application.ReadWrite.*`, `UserAuthenticationMethod.ReadWrite.All`, `User-OnPremisesSyncBehavior.ReadWrite.All` and the rest. **A write feature whose permission is missing is greyed with the missing permission named; no feature is silently disabled.**

**Tier-0 guard (TM-D2, TM-D25).** Writes to Entra `tier0` objects (holders of any directory role, role-assignable groups and their members/owners, hybrid-control accounts, objects correlated to AD `tier0`, customer-designated break-glass accounts) are **refused with the reason**. If the guard's reads fail, **every Entra write is refused** (fail closed; TM Q: "refuse every Entra write").

## 10. Functional requirements

Each FR is observable in the UI or API. "Pipeline" = Plan → gate → Apply → Verify → audit, undo as a new operation ([ADR-0005](../../development/decisions/0005-operation-pipeline-and-audit-trail.md)).

**Onboarding (ADM-159, I360-003)**

- FR-01 The system MUST create an Entra connection by guided consent (Path A) or manual registration (Path B), with certificate authentication only. It MUST NOT accept or store a client secret.
- FR-02 It MUST fix the tenant ID at first verification and refuse a second connection to the same tenant (DM-10.I1/I2).
- FR-03 It MUST read the service principal's granted application roles and compare them with the allow and deny lists, showing missing, excess and denied permissions by name.
- FR-04 It MUST refuse activation when a deny-list permission is granted; the override is the existing audited TM-D1 override with a permanent banner.
- FR-05 It MUST show a feature switch per capability family (read/hybrid view, licences, users, account actions, groups), and the permission set MUST be derived from the switches.
- FR-06 It MUST support several tenants and many-to-many HybridLinks, proposed from correlations and confirmed only by a holder of `connections.hybrid_link.confirm` over both sides (DM-21).
- FR-07 It MUST require the Tier-0 guard reads whenever any write feature is on; if they cannot be read, writes stay off and the page says which read failed.
- FR-08 It MUST show first-sync progress as counts, with no fake percentage, and search over the synced part labelled incomplete (as the AD connection does).
- FR-09 It MUST show the takeover-protection state, last attestation, next expiry and the §8 alerts on the connection page.
- FR-10 Entra inventory MUST update by delta (`/users/delta`, `/groups/delta`) and every cloud list MUST show the age of its data.

**Users (ADM-009, ADM-160, ADM-027)**

- FR-11 It MUST create a cloud-only user (no AD user) from a form, a template or CSV. Required inputs are the Graph minimum (UPN, display name, mail nickname, password-or-generated); the form MUST offer verified domains of the tenant only.
- FR-12 Bulk create/modify via CSV MUST accept UPN or ObjectId as key, map columns by name with a preview, and report every row's outcome: created, modified, skipped (with reason), refused (with reason), failed (with Graph cause). Partial failure MUST NOT roll back successful rows silently; the report offers **Undo successful rows**.
- FR-13 It MUST create guest users in bulk through invitations, showing the invitation state per row.
- FR-14 Modifying a **synced** user MUST apply the §7 refusal per property, before any request is sent.
- FR-15 The AD create-user flow MUST include an optional cloud step (licences with service plans, cloud groups) for each HybridLink-confirmed tenant of the user's domain (DM-21.I1). It is one operation: the Plan shows the AD and cloud steps, and a cloud failure leaves the AD user created and reports exactly which cloud steps did not run, with a one-click retry of those steps.

**Licences (ADM-161, M365-005)** — see §6.

- FR-16 It MUST list SKUs with friendly names, seats purchased/assigned/available and service plans.
- FR-17 It MUST show per user the licences with their source (direct / group name), and per SKU the assigned users and groups.
- FR-18 Add, remove and replace MUST run the §6 conflict check in Plan and show seat shortfall before Apply.
- FR-19 It MUST support group-based licence changes and show the affected member count in Plan.
- FR-20 Bulk selection MUST accept search, list, group, AD domain/OU (via confirmed correlations) and CSV by ObjectId or UPN.
- FR-21 After Apply, Verify MUST read the user back and report any licence in an error state (including group-licence errors) per user.
- FR-22 Removal of a directly assigned SKU that is also group-inherited MUST say the user keeps the licence through the group.

**Account actions (ADM-162)**

- FR-23 It MUST reset a password (generated or chosen; the secret is shown once and never stored or logged, ADR-0005 rule 9), force change at next sign-in by default, and declare the step **Irreversible** in Plan.
- FR-24 It MUST block/unblock (`accountEnabled`) and revoke sign-in sessions, individually and in bulk, as separate or combined steps. A leaver preset is "block + revoke sessions + remove direct licences" in one operation.
- FR-25 It MUST soft-delete a user, list deleted users, and restore within Microsoft's window; **hard delete is Irreversible**, step-up, and shown as such in Plan.
- FR-26 It MUST change UPN and primary domain, with Plan warning that sign-in names change.
- FR-27 It MUST set and remove manager (a manager must exist in the same tenant).
- FR-28 For **synced** users the actions that are cloud-owned MUST work; a synced user's soft-delete, UPN change and password reset that Graph or sync would refuse or overwrite MUST be refused with the §7 message `[UNVERIFIED — per-action behaviour needs the lab; fail closed]`.

**Groups (ADM-164, M365-007)**

- FR-29 It MUST create, edit, delete M365 groups and security groups; set owners; add/remove members including in bulk from CSV.
- FR-30 It MUST show distribution lists, mail-enabled security groups and dynamic distribution groups read-only with the line "Managed in Exchange Online; not editable here in this release".
- FR-31 It MUST create and edit dynamic membership rules from a rule builder, never from raw rule syntax. The Tier-0 guard rule for rule properties (TM-D25 rule 7) applies, and a refused rule shows which closure it would reach.
- FR-32 For synced groups it MUST refuse member changes Graph refuses and point to the AD group (§7). Groups with more than 1,500 members MUST list and edit by page, never by loading all members.

**Delegation (ADM-131)**

- FR-33 Cloud actions MUST be permissions in the same RBAC model with `entra_tenant` roots and group/AD-domain scopes (DM-35). It MUST NOT use Entra administrative units (the permission is deny-listed). The technician sees only the users their scope reaches; an out-of-scope or `tier0` target answers as "not found or not permitted", not as a different error.

**Hybrid view (ADM-169)**

- FR-34 It MUST show the Authority badge (§7) on every cloud user and group row and detail page.
- FR-35 It MUST provide the hybrid filters of §7.
- FR-36 It MUST show, on a correlated user, the AD and cloud values side by side for the synced properties, and mark which side authors each.
- FR-37 It MUST refuse a write to an on-prem-sourced property of a synced user before sending it, with the §7 message (the Graph error is the backstop and is mapped to the same message).
- FR-38 **Edit in AD** MUST be shown only if the admin's scope reaches the correlated AD object and the correlation is `matched` (DM-20.I4); otherwise the message omits the button and says why.
- FR-39 It MUST implement the §8 expiry alerts and gap rule, and show state, last complete read and next expiry.
- FR-40 When `takeover_protection` is not `attested`, authority-dependent features MUST say "authority unconfirmed" and offer Re-attest, not hide data.
- FR-41 No part of the hybrid view may transfer source of authority in v1.

## 11. Platform matrix

A blank cell is a decision; each is stated.

| Case | v1 | Notes |
| --- | --- | --- |
| **Cloud-only user/group** (no on-prem source) | Full | All FRs |
| **Synced user** from Entra Connect Sync | Cloud-owned properties and actions only; on-prem-sourced properties refused (§7) | Graph behaviour per property `[UNVERIFIED — lab]`; fail closed |
| **Synced user** from Entra Cloud Sync | Same as Connect | Same table. Whether Cloud Sync's SOA set differs `[UNVERIFIED]`: lab |
| **Authority moved to Entra** (user/group SOA) | Treated as cloud; state shown; no transfer | GA dates per matrix LAND §7.1#6 |
| **On-prem AD** functional levels | n/a to Graph; Edit-in-AD uses the AD write path | AD levels per [ad-forest-connection](ad-forest-connection.md) |
| **Hybrid (AD + Entra, HybridLink confirmed)** | Full incl. hybrid view and joiner flow (FR-15) | Needs `matched` correlation for Edit-in-AD and AD/OU filters |
| **Entra only (no AD connection)** | Full except AD/OU filters and Edit-in-AD | |
| **Windows Server versions for a DC-side component** | **None.** Graph only, no Windows (FEAS §1.9 per [matrix ADM-027 note](../../business/competitive-analysis/feature-parity-matrix.csv)) | |
| **Server host** | Both profiles (windows, linux-oci) | Same code, no Windows dependency |
| **Tenant editions** Free / P1 / P2 | Provisioning works on all; group-based licensing, dynamic groups and `signInActivity` need P1/P2 | `[UNVERIFIED — confirm the P1 requirements at onboarding; the product reads capability from the tenant and greys what is missing, naming the licence]` |
| **Sovereign clouds** (US Gov L4/L5, China/21Vianet) | **Not in v1** (global service only) | `assignLicense` is available in them ([ref](https://learn.microsoft.com/en-us/graph/api/user-assignlicense?view=graph-rest-1.0)), so the cost is endpoints and a lab, not API; backlog ticket filed, §15 Q4 |
| **Multi-tenant (MSP)** | Several tenants per activeDIQ tenant; scope is per Entra root | |

## 12. Out of scope

- Exchange Online helper: mailboxes, aliases, litigation hold, archive, quotas, protocols, remote mailboxes, distribution and mail-enabled security group *changes* (E-020, M5; PowerShell sidecar per FEAS §1.9). The ADM-027 row's Exchange parts and ADM-169's remote-mailbox part wait for it.
- M365 reports, sign-in/MFA/licence-usage reports (see [reports-entra-objects.md](reports-entra-objects.md) §7).
- Roles and Conditional Access (ADM-168 is out of v1, ADR-0002 rule 9, D-0007); Teams (ADM-167); per-user MFA (ADM-163).
- Source-of-authority transfer; Entra administrative units; guest lifecycle governance.
- Google Workspace (ADM-171…173).
- Sovereign clouds.

## 13. Security and audit

- **Tag build tickets `security-sensitive`**; `security-architect` reviews: the permission table and its gating (§9), consent and certificate flow (FR-01), password reset secret handling (FR-23), the `soa v1` table (fail-closed), the Edit-in-AD path (TM-D25 rule 7f), and the gap rule.
- **Our own audit trail** (ADR-0005): every write is an Operation with initiator, approver, target `connection_id` + object ID, per-step diff (before → after), reversibility class and the Graph request ID; passwords and invitation URLs are never recorded (secret inputs, rule 9); personal values are held outside the hashed form (X11). Also audited: tenant connect/disconnect, permission read-backs, deny-list override, link confirm, attestation start/callback, feature-switch changes.
- **Graph writes are only reachable through Actions**; the only write path is `internal/directory/graphwrite` (TM-F-BACKING), with OData filters and keys built by the safe renderer (P8, TM-TB7-T14): an admin-supplied UPN can never widen a lookup, and the write uses the object's `id` from a lookup that returned exactly one object.
- **Throttling and idempotency:** retry honours `Retry-After`; a retried step is checked against the read-back before re-applying (ADR-0005); the Graph read-after-write delay is `[UNVERIFIED]` (T-0051, lab).

## 14. Acceptance criteria

Each is verifiable by `qa-verifier` against the running product (or API) with evidence: a screenshot, the API response, the audit event. "Lab" = the Entra sandbox tenant (T-0075) and a Samba/Windows AD with Connect, or Graph test doubles for the unit tier.

**Onboarding**

- AC-01 *Given* an Entra tenant with no connection, *When* a Global Administrator completes Path A, *Then* the connection verifies, shows tenant ID, granted-vs-required permissions, and syncs; no client secret field exists anywhere in the UI or API. *Evidence:* screenshots; API schema has no secret property.
- AC-02 *Given* the registration carries `Directory.ReadWrite.All`, *When* the admin presses Verify, *Then* activation is refused naming that permission; the TM-D1 override needs step-up and leaves a permanent banner and an audit event.
- AC-03 *Given* the admin switches on Licences only, *When* the checklist shows, *Then* only the licence-related permissions plus the Tier-0 guard reads are requested, and group-write permissions are absent.
- AC-04 *Given* the Tier-0 guard reads fail (permission revoked), *When* any Entra write is planned, *Then* it is refused with "guard could not read `<what>`" and nothing is sent to Graph.
- AC-05 *Given* a domain and a tenant with a `proposed` HybridLink, *When* an admin who holds the permission over only one side confirms, *Then* it is refused; with both, it is confirmed and audited.
- AC-06 *Given* a tenant with 100,000 users, *When* the first sync runs, *Then* the page shows counts and elapsed time, search works labelled incomplete, and no percentage is shown.

**Users and bulk**

- AC-07 *Given* the tenant's verified domains, *When* the admin creates a cloud-only user, *Then* the user exists in Entra with the licences chosen, the UPN domain list offered only verified domains, and the audit event shows the diff.
- AC-08 *Given* a CSV of 1,000 rows with 10 invalid UPNs, 5 duplicates and 3 synced users whose `extensionAttribute1` is in the file, *When* previewed and confirmed, *Then* the report shows 982 created or modified, 10 refused invalid, 5 skipped duplicate and 3 refused with the hybrid message; no row is lost.
- AC-09 *Given* a bulk run that fails on row 400 (Graph error), *When* it ends, *Then* completed rows are kept, the failed rows list the Graph cause, and **Undo successful rows** is offered.
- AC-10 *Given* a bulk guest invitation CSV, *When* run, *Then* each row shows its invitation state.
- AC-11 *Given* an AD create-user with a confirmed HybridLink and a licence chosen, *When* the cloud step fails (no seats), *Then* the AD user exists, the result names the cloud steps not run and "Retry cloud steps" works once seats exist.
- AC-12 *Given* ADM-009's flow used from the same screen, *When* "no AD account" is chosen, *Then* only a cloud user is created and no AD write is planned.

**Licences**

- AC-13 *Given* a user with usage location unset and a SKU chosen, *When* planned, *Then* Plan refuses the item for usage location and offers to set it; accepting sets it then assigns.
- AC-14 *Given* 100 seats are free and 500 users are selected, *When* planned, *Then* Plan shows "400 short", lets the admin proceed with the first 100 or stop, and Apply never sends the 400.
- AC-15 *Given* a user holds SKU A directly and B through group G, *When* the admin removes B directly, *Then* Plan says "Still licensed through G" and the verified result shows B still present.
- AC-16 *Given* Replace A→B, *When* applied, *Then* a single Graph call carries both lists and the user is never observed without both A and B-or-A.
- AC-17 *Given* a group licence change on a group of 5,000 members, *When* planned, *Then* the member count is shown, and after Apply the per-user error states (if any) are listed.
- AC-18 *Given* a CSV by ObjectId and a CSV by UPN, *When* each is uploaded, *Then* both resolve and the preview shows the same users; an unknown key is listed, not dropped.
- AC-19 *Given* a licence filter "AD domain `X`, OU `Y`", *When* applied with a `matched` correlation set, *Then* exactly the users correlated to objects under that OU are selected; with the takeover state `stale`, the filter says "authority unconfirmed" and selects none.
- AC-20 *Given* the experience target, *When* QA performs T14 and T07 on the demo data, *Then* each is within the §4 targets, measured per the benchmark method.

**Account actions**

- AC-21 *Given* a cloud user, *When* an admin resets the password, *Then* the secret is displayed once, is absent from the audit event, logs and API reads, and Plan labelled the step Irreversible.
- AC-22 *Given* a leaver preset on 20 users, *When* run, *Then* each is blocked, sessions are revoked and direct licences removed; Verify shows `accountEnabled=false` and sessions revoked; one throttled item is retried without failing.
- AC-23 *Given* a soft-deleted user, *When* restored in the window, *Then* the user returns with the licences Graph restores; *When* hard-deleted, *Then* step-up was required and there is no undo.
- AC-24 *Given* UPN change, *When* planned, *Then* Plan warns sign-in names change and the audit event holds old and new.
- AC-25 *Given* a user that holds a directory role, *When* any write is planned, *Then* it is refused as `tier0` with the reason and no Graph request is sent.
- AC-26 *Given* a delegated technician whose scope covers a 200-user group, *When* they open a user outside it, *Then* it answers "not found or not permitted" and no write is possible.

**Groups**

- AC-27 *Given* an M365 group, *When* created, edited, an owner added and 3,000 members added from CSV, *Then* each is an Operation with a preview, and a group over 1,500 members lists by page.
- AC-28 *Given* a distribution list, *When* opened, *Then* it is read-only with the Exchange line and no editable control is a dead button.
- AC-29 *Given* a dynamic rule touching a property in a Tier-0 closure, *When* saved, *Then* it is refused and names the closure.
- AC-30 *Given* an empty tenant, *When* Groups opens, *Then* an empty state with **Create group** shows, not a blank table.

**Hybrid view and refusal (acceptance 2 of the ticket)**

- AC-31 *Given* a synced user correlated `matched` to an AD user, *When* the admin edits `extensionAttribute1` (or `department`, once the lab confirms it is on-prem-sourced) in the cloud form, *Then* **no Graph request is sent**, the field shows the §7 message with the AD domain and the **Edit in AD** button, and the audit event records a refusal of kind `authority_refused` with the property and reason.
- AC-32 *Given* the same edit when the admin's scope does not reach the AD object, *Then* the message appears with no button and says an AD administrator must change it.
- AC-33 *Given* the admin follows **Edit in AD** and saves, *When* the next sync runs, *Then* the hybrid view shows the AD and cloud values side by side and equal, and the AD write was checked by the Tier-0 property guard (a rule-reaching property is refused).
- AC-34 *Given* the same edit arrives from CSV or API, *Then* the row is refused with the same reason code; **the Graph error, if ever reached, maps to the same message**.
- AC-35 *Given* a synced user with no AD match, *Then* the badge reads "Synced, no AD match" and the refusal message says no AD object was found.
- AC-36 *Given* a user whose SOA was moved to Entra, *Then* the badge reads Cloud, edits are allowed, and no control moves authority.
- AC-37 *Given* the connection is `attested` with expiry in 14 days, *Then* health warns and every holder of `connections.takeover.attest` is notified; at 7, 3, 1 days again; at expiry, correlations become `candidate`, the banner shows and Re-attest works.
- AC-38 *Given* `AuditLog.Read.All` is granted and the monitor has no complete read for 25 h, *Then* health shows "change monitoring degraded"; at 6 days 1 h, state is `stale`; a complete read alone does **not** return it to `attested`, a new attestation does.
- AC-39 *Given* `AuditLog.Read.All` is revoked after being present, *Then* state becomes `stale` and health says why; *Given* it was never granted, *Then* health says "change monitoring is off" and only age applies.
- AC-40 *Given* a synced user in the lab, *When* each property in the `soa v1` table is edited, *Then* the recorded outcome (accepted/refused) matches the table, and a drift test fails when it does not. *Evidence:* lab log (this closes the `[UNVERIFIED — lab]` items).

## 15. Open questions

Directional ones become decisions via `ceo-decisions`; the rest are answered by the owner named.

1. **Path A consent needs an application that is the customer's own registration or a multi-tenant app that activeDIQ publishes.** A self-hosted product has no publisher app; "Global-admin consent creates the app automatically" (ME) implies the vendor's. Does v1 ship Path A as a **scripted registration** (the product shows a one-click Microsoft consent for a template, or a copy-ready `az`/PowerShell script) and call that guided? *Owner:* `solution-architect` with `security-architect`; becomes a CEO decision only if it implies activeDIQ publishes a multi-tenant app (leaving the building, commercial).
2. Gap-rule values (24 h degraded, 6 days stale) are proposals. *Owner:* `solution-architect` with `security-architect`.
3. Per-property `soa v1` results, Cloud Sync differences and usage-location and group-licence error behaviour: lab T-0075 (the CEO deferred the sandbox tenant until after M1; AC-40 cannot pass before it exists).
4. Sovereign clouds: PM decision is **not in v1**; a backlog ticket records the demand-driven follow-up (§11).
5. `market-analyst`: confirm in research whether ME's hybrid screen exposes authority per attribute (we state it does not on the strength of ADM-169's row; nothing in the cited help shows it either way `[UNVERIFIED]`) and whether ME's CSV licence import handles seat shortfall.

## Sources

[ADMP research](../../business/market-research/manageengine-admanager-plus.md) · [customer voice](../../business/market-research/manageengine-ad-customer-voice-and-security.md) · [parity matrix](../../business/competitive-analysis/feature-parity-matrix.md) · [v1 scope options](../../business/scoping/v1-scope-options.md) · [m2-plan](../../business/scoping/m2-plan.md) · [threat model §6.6, §6.8, §6.9](../../development/architecture/threat-model.md) · [domain model DM-10, DM-20, DM-21](../../development/domain/domain-model.md) · [ADR-0005](../../development/decisions/0005-operation-pipeline-and-audit-trail.md) · [Graph permission policy](../../development/decisions/graph-data-permissions-policy.md) · [top-admin-tasks-benchmark](top-admin-tasks-benchmark.md) · Microsoft Learn: [update user](https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0), [assignLicense](https://learn.microsoft.com/en-us/graph/api/user-assignlicense?view=graph-rest-1.0), [attributes synchronized](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-sync-attributes-synchronized), [Entra data retention](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention) (read 2026-11-14).
