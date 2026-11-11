---
title: "Spec: E2.7 Hybrid via Graph — Entra tenant connection, Entra inventory sync, and one flow that creates an AD user with a Microsoft 365 licence and groups (checkpoint 2c slice)"
date: 2026-11-11
updated: 2026-11-11
status: draft
owner: heramb
author: product-manager
prd: none (the E-013 PRD is not written; this spec is the contract for the checkpoint 2c slice)
ticket: off-board (m2c-plan)
epic: E-013
milestone: M2
parity: [ADM-159, ADM-027, ADM-161, ADM-164, ADM-169, ADM-131, M365-005, M365-007, I360-003, ADM-162, ADM-160, ADM-009]
scope: locked
sources_last_checked: 2026-11-11
reviewer: solution-architect
second_reviewer: security-architect
security-sensitive: true
revision: 2
---

# Spec: E2.7 Hybrid via Graph (checkpoint 2c slice)

> An admin connects an Entra tenant with a least-privilege, certificate-authenticated app and then
> creates a hybrid user in **one** flow: one preview that shows the AD half and the cloud half, one
> approval, and a status that says plainly what is done, what is waiting for Microsoft's sync and
> why. The default path needs no profile-write permission in Entra. The cloud half never touches an
> object activeDIQ cannot prove it created.

Planned off-board on the second machine (CEO decision 2026-11-10, `knowledge/memory/decisions-log.md`):
documents only, no product code, no ticket IDs. Attach board IDs at merge. **No Entra tenant exists
yet** (action A-0026, deferred until M1 acceptance), so every Microsoft behaviour below is sourced
inline or tagged `[UNVERIFIED]` (needs the Entra sandbox, D-0001) or `[DISCOVERY]` (needs a pilot).
Round 2 (2026-11-11) answers the architecture and security reviews of the same date; §15 maps every
finding to its change.

Binding sources: [ADR-0005](../../development/decisions/0005-operation-pipeline-and-audit-trail.md)
**plus the amendment named in §14.1** (this spec is not buildable on ADR-0005 alone),
[ADR-0002](../../development/decisions/0002-deployment-model.md) rules 3, 7, 8, 9,
[domain model](../../development/domain/domain-model.md) DM-10 (I7, I9–I11), DM-16 (I9), DM-20, DM-21, DM-35, DM-40…42, DM-50, DM-70,
[threat model](../../development/architecture/threat-model.md) §6.6 (TM-D5), §6.8–6.9, TM-D1, TM-D2, TM-D17, TM-D19, TM-D23, TM-D25,
[safe-primitives-odata](../../development/architecture/safe-primitives-odata.md) (P8),
[connector contract](../../development/architecture/connector-contract.md) §6.6, §8,
[forest connection spec](ad-forest-connection.md) (the AD half's connection; its §14 hands the Entra
connection and attestation to this spec), [M2 plan](../../business/scoping/m2-plan.md).

## 1. Problem and user

Hybrid is the normal case for the migrating customer: "Most ADMP customers run hybrid"
([ADMP research §7a](../../business/market-research/manageengine-admanager-plus.md)). In ADManager
Plus the cloud half lives in a separate app: the M365 tab is an embedded Ember app with its own
navigation, and the research records a ~26 s render and ~64 action links in the demo
([ADMP research §4.1–4.2, W8](../../business/market-research/manageengine-admanager-plus.md);
single-session, indicative). Reviewers say "cloud requires another product" (~11 reviews, X5,
[customer voice](../../business/market-research/manageengine-ad-customer-voice-and-security.md)).
ADMP's orchestration cloud actions "work only on users synced by DirSync" (ADM-169, W15), and the
research does not say what happens before the user has synced `[UNVERIFIED]`.

- **AD admin / help-desk technician** creates joiners daily to weekly. *When a new hire starts, I want
  the AD account, the M365 licence and the right groups created from one form, so I can hand over a
  working identity without opening a second tool.* Source: ADM-027 baseline.
- **AD admin (once per tenant)** connects the tenant (ADM-159, I360-003). *When I connect Microsoft 365,
  I want to know the app can do licences and groups and nothing else, so I can approve it with the
  security team.* Source: ADR-0002 rules 7–9; TM-D1.
- **Security / SOC analyst.** *When a hybrid user is provisioned, I want proof the cloud half touched
  only the object we created.* Source: TM-D17 (takeover through hard/soft match).
- **IT manager / auditor.** One audit record across AD and Entra. **End user:** no interaction in 2c.

What it costs today in ManageEngine: a second surface, a separate M365 service account for bulk MFA and
Teams policy ([ADMP research §2.3](../../business/market-research/manageengine-admanager-plus.md)),
and no documented handling of the sync gap `[UNVERIFIED]`.

**The technical fact that shapes the spec.** An AD user created by activeDIQ does not exist in Entra
until the customer's sync client copies it. Entra Connect Sync runs a cycle every 30 minutes by default;
a delta cycle is started with `Start-ADSyncSyncCycle -PolicyType Delta` on the sync server
([scheduler](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sync-feature-scheduler)).
Cloud Sync is described as every two minutes, but Microsoft's pages disagree (the FAQ says roughly 10 to
20 minutes for user provisioning)
([what is Cloud Sync](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/what-is-cloud-sync),
[how it works](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/concept-how-it-works),
[FAQ](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/reference-cloud-sync-faq)).
The licence and the cloud groups can only be applied after that copy exists **and** activeDIQ has proved
it is the same identity (DM-20.I4).

## 2. Parity baseline and the 2c slice

IDs are from [feature-parity-matrix.csv](../../business/competitive-analysis/feature-parity-matrix.csv)
(checked row by row, 2026-11-11). "Stance" is the matrix's. No new IDs invented.

| ID | ME feature (edition) | Matrix: must / stance / phase | 2c slice | Reason |
| --- | --- | --- | --- | --- |
| ADM-159 | Tenant onboarding: consent creates the app, or manual registration; several tenants; many-to-many domain-tenant links | must / enhance / P1 | **In** | Prerequisite of the demo. Ours: certificate auth, least-privilege scopes, no service account (FR-01…08, FR-39) |
| I360-003 | Entra ID sync via Graph app (Pro, Ent) | must / parity / P1 | **In: Graph delta sync of users, groups and licence assignments into inventory (FR-36…38)** | Matrix note. Correlation can only change through sync (DM-20.I5), so the flow depends on it. Devices and group member lists are not synced in 2c |
| ADM-027 | M365 at creation: licences and service plans, groups, roles, Exchange alias, litigation hold, archive, quotas, protocols | must / enhance / P1 | **In, narrowed:** licence (**default: membership of a licensed group**; direct SKU assignment and usage location are opt-in), groups. **Deferred:** roles (ADR-0002 rule 7, ADM-168 out of v1), Exchange alias, litigation hold, archive, quotas, protocols (EXO needs the PowerShell sidecar, v1-scope §3.6, M5) | The demo sentence is licence and groups |
| ADM-161 | Licence management: add, replace, remove; group-based changes; CSV by ObjectId or UPN; filter by AD domain or OU | must / parity / P1 | **In, single and small multi-select** (≤ 50): direct add, replace, remove (opt-in family) and licensed-group membership. **Deferred to slice 2c-b:** CSV, assigning a licence *to a group*, filter by OU | CSV rides the bulk engine (E2.3, 2b); group licence writes are a separate guard case (TM-D25 7e) |
| M365-005 | Bulk assign/remove M365 licences | must / parity / P1 | **Same as ADM-161** | Matrix note |
| ADM-164 | Groups: M365, distribution, mail-enabled security, dynamic distribution; security-group changes; templates | must / parity / P1 | **In, membership only** of security and M365 groups, as the Entra arm of the existing `objects` group-membership Actions (blueprint: ADM-164 is `objects` on the Entra provider). **Deferred:** group create/edit, distribution and dynamic-distribution groups (Exchange-owned), templates | Membership is what the flow needs |
| M365-007 | Groups (M365 Manager Plus) | must / parity / P1 | **Same as ADM-164** | Matrix note |
| ADM-169 | Hybrid handling: remote mailboxes; filter cloud users by AD domain or OU; cloud actions only for DirSync users | must / leapfrog / P1 | **In, minimal:** per-user source-of-authority badge, correlation state and reason (FR-30). **Deferred:** remote mailbox (ADM-070, Exchange helper, FD-04), "filter cloud users by OU" list view (E2.5/E2.6 consume `include_correlated`) | The view is the leapfrog; the list filter needs the scope evaluator |
| ADM-131 | M365/Google delegation (Pro) | should / parity / P1 | **Partial:** enforcement only (FR-33). **Deferred:** the cloud role and scope editor UI (E2.5) | One RBAC model; UI belongs to the delegation spec |
| ADM-162 | Account actions: reset password, block/unblock, delete, hard delete, restore, UPN, manager, revoke tokens | must / parity / P1 | **Deferred to slice 2c-b** | Not in the demo sentence. Needs `User.ReadWrite.All`-class rights for some actions (TM §6.6), so it is its own security review |
| ADM-160 | Bulk create/modify, cloud-only and synced; guests | should / parity / P2 | **Deferred** (post-2c) | Matrix P2; needs E2.3 bulk engine |
| ADM-009 | Cloud-only accounts (no AD user) | should / parity / P2 | **Deferred** (post-2c); cloud-only users are **read-only** with SOA "Cloud" (FR-30) | Matrix P2. Not requesting `User.Create` in 2c is least privilege (FR-04) |

**Cloud-only users:** not created in 2c. The Actions, the `entra_tenant` scope and the Plan/verify path are
the same, so slice 2c-b adds them without a new architecture.

**Scope impact of round 2 (director rulings 3 and 5).**
- **Group-based licensing does not move between slices.** Licensing a user by membership of a licensed
  group was already in 2c (FR-26, as an alternative). It is now the **default**, because it needs only
  `GroupMember.ReadWrite.All` and neither `LicenseAssignment.ReadWrite.All` nor `User.ReadUpdate.All`.
  What stays in 2c-b is assigning a licence *to a group*. The 2c demo promise ("one flow creates an AD
  user with an M365 licence and groups") is met on the default path. Preconditions, stated in the wizard:
  the tenant already has a licensed cloud group, and the hire's location equals the tenant location,
  because a user with no usage location inherits the tenant's location under group-based licensing
  ([group licences](https://learn.microsoft.com/en-us/microsoft-365/admin/manage/manage-group-licenses?view=o365-worldwide);
  Microsoft's own advice for multi-location tenants is to set the location during user creation, which is
  why that is an opt-in family, not a dead end). A customer without a licensed group, or with hires in
  several countries, enables the opt-in families knowingly (E4).
- **E2.7 gains Entra delta sync and the Entra report datasets** (FR-36…38): one more build slice (sync,
  dataset registration). No new parity ID; I360-003 was already "In" and had no requirement behind it.

## 3. Enhancements (each tied to a sourced pain; all in the 2c slice unless marked)

| # | Enhancement | Pain / source | Measurable claim | Proof |
| --- | --- | --- | --- | --- |
| E1 | **One flow, one console, one preview** for AD + Entra (matrix ADM-027 enhance) | ADMP's M365 tab is a separate iframe app (W8); "cloud requires another product" (X5, ~11 reviews) | Hybrid create with licence and 2 groups: 1 form, 1 preview, 1 approval, 0 context switches. ME baseline: separate app, `[UNVERIFIED]` interaction count; to be timed in the M2 baseline task set | AC-12, task timing |
| E2 | **Honest sync-gap status** (our design guard; no comparative claim, ME's behaviour is undocumented) | Silent failure while the cloud object does not exist | At every moment the status names the waiting step, last-check time, expected interval and next check | AC-16, AC-25 |
| E3 | **Source-of-authority badge** (matrix ADM-169 leapfrog) | ADMP cloud actions only for DirSync users; no documented explanation for others | Every hybrid or cloud user shows AD / Cloud / Candidate with the reason (`candidate_reason`) in 1 glance, 0 clicks | AC-37 |
| E4 | **Least-privilege tenant connection: no service account, no directory role, and no profile-write permission on the default path** (matrix ADM-159 enhance) | ADMP still needs a separate M365 service account for bulk MFA and Teams ([§2.3](../../business/market-research/manageengine-admanager-plus.md)). `User.ReadUpdate.All` is tenant-wide profile write, and Microsoft documents no narrower permission for the sensitive user properties (security review A-M2) | Default permission set = reads + `GroupMember.ReadWrite.All`. Direct licensing and usage location are separate opt-in families, each with breadth text. A deny-list permission, a directory role or an unexpired secret refuses activation, and no acknowledgement overrides it | AC-02, AC-03, AC-04 |
| E5 | **Preview and undo cover the cloud half**; irreversible and lossy steps flagged before execution (ENH-04, D-0004) | Roadmap exit criterion 5 | Every non-reversible step is labelled in the preview, API response and approval | AC-12, AC-34 |
| E6 | **No script path** (DM-40.I4) | ADMP 8043 fixed remote code execution through CSV input with embedded PowerShell in the M365 tab ([ADMP research release table](../../business/market-research/manageengine-admanager-plus.md)) | Zero free-form script verbs reachable from any hybrid input; fitness checks FF-SP2/graph-url-assembly | AC-45 |

Cut on purpose: any "faster than ADManager Plus" claim. ME's time-to-licence is not documented. A research
ticket for `market-analyst` should time ADMP's M365-at-creation flow in the lab (see §14.7).

## 4. Experience target (to be confirmed with `product-designer`)

| Task | ME baseline | Target |
| --- | --- | --- |
| Connect an Entra tenant (first time) | Consent creates the app, or manual registration ([matrix ADM-159](../../business/competitive-analysis/feature-parity-matrix.csv)); time `[UNVERIFIED]` | ≤ 4 screens, ≤ 15 min including the customer's own portal steps `[EST]`. We cannot match one-click consent: a vendor-owned multi-tenant app was rejected in ADR-0002 (one key would open every tenant). The wizard supplies a copy-ready script and streams the check results |
| Create a hybrid user with licence + 2 groups | Separate M365 app `[UNVERIFIED]` count | Form → Preview → Approve → done in ≤ 3 interactions after the form is filled; the template pre-fills licence group, other groups |
| Know why the licence is not there yet | Not documented | 0 clicks: status is on the user page and the request row |

The admin never writes an OData filter, a SKU GUID or a group object ID: licence groups and SKUs show
friendly names and available counts, groups resolve from a picker, usage location (opt-in) is a country list.

## 5. Platform matrix

Legend: **Dec** = a decision, not an omission. `[LAB-E]` = needs the Entra sandbox (D-0001, A-0026,
T-0183 bootstrap) and, for sync behaviour, Entra Connect on the Windows lab (D-0003, "G9").

| Dimension | Decision |
| --- | --- |
| Deployment profiles | `windows` and `linux-oci` identical: the Entra connector is embedded and only needs outbound HTTPS to Microsoft (ADR-0002, DM §10). `saas`: composed and CI-tested, not shipped; the cell holds the Entra certificate (ADR-0002 rule 3). Air-gapped installs have no Entra connection (ADR-0002) |
| Directory topologies | **On-prem AD only:** no Entra features (not this spec). **Entra only (no AD):** connection, sync, licence and group membership on Entra-scope objects work; the hybrid create is n/a. **Hybrid:** the 2c target |
| Sync client | **Entra Connect Sync:** the 2c demo target (30-min default cycle). **Cloud Sync:** ◐ supported by design; its `onPremisesSecurityIdentifier` population for users is `[UNVERIFIED]` (domain-model Q8, DM-20.I4(c)); until the lab confirms, a Cloud Sync user stays `candidate` (`sid_mismatch`) and the cloud half holds. Not claimed at 2c |
| Source anchor | Binary anchors only (`objectGUID`, `ms-DS-ConsistencyGuid`). A link declared with a string anchor (for example `employeeID`) blocks the hybrid create at Plan (`anchor_attr_unsupported`); it is Dec, not an omission |
| Entra clouds | Global service only. National clouds (US Gov, China operated by 21Vianet) are Dec: ✗ not in 2c (endpoints and consent differ) `[DISCOVERY]` |
| Windows Server versions | No DC-side or Windows-host component in this spec. The AD half uses the AD connector and is bound by the forest-connection matrix (managed DCs WS2016–2025). A customer-run Windows helper on the sync server is **not** built (OQ-C1) |
| Lab tiers | **F** fake Graph (CI, decisions-log: T-0067 "runs on fake Graph first") · **E** Entra sandbox tenant `[LAB-E]` · **H** E + Entra Connect on the Windows lab with AD `[LAB-E]` · **S** Samba AD (AD half only) |

Per-requirement matrix (✓ full · ◐ partial · ✗ not delivered, reason · n/a):

| FR | windows | linux-oci | saas | Entra Connect | Cloud Sync | Entra-only tenant | Samba AD half | Console | REST API |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| FR-01…08, 39 tenant connection, rotation | ✓ | ✓ | ✗ not shipped (ADR-0002 saas profile) | ✓ | ✓ | ✓ | n/a | ✓ | ✓ |
| FR-09…12 plan and preview | ✓ | ✓ | ✗ | ✓ | ✓ | ◐ no AD half; cloud steps only | ✓ | ✓ | ✓ |
| FR-13…21, 40 continuation and wait | ✓ | ✓ | ✗ | ✓ `[LAB-E]` | ◐ `sid_mismatch` risk `[UNVERIFIED]` | n/a | ✓ AD half only | ✓ | ✓ |
| FR-22…29 cloud steps | ✓ | ✓ | ✗ | ✓ `[LAB-E]` | ◐ as above | ✓ | n/a | ✓ | ✓ |
| FR-30 SOA view | ✓ | ✓ | ✗ | ✓ | ◐ | ✓ ("Cloud" only) | n/a | ✓ | ✓ |
| FR-31…33 licence, groups, authority | ✓ | ✓ | ✗ | ✓ | ◐ | ✓ | n/a | ✓ | ✓ |
| FR-34…35 audit, errors | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

Datasets and Entra scopes also depend on E-011 / T-1131 (§14.6); until it lands, the cells that need
those roots read ✗ → E-011, not ✓. PowerShell module: n/a (M3, FD-07). Samba cannot exercise Entra; the
AD half runs on Samba and the cloud half on fake Graph (F) in CI, so **no 2c cloud claim is made from
Samba alone**.

## 6. Flows

### Flow A: connect an Entra tenant (once)

| # | Admin does | System shows | Pattern |
| --- | --- | --- | --- |
| 1 | **Add Microsoft 365 tenant** (step-up) | Empty state offers one action. Explains: customer's own app registration, certificate auth, no admin role | Wizard |
| 2 | Chooses the families to enable | *Read directory* (always), *Group membership* (on by default; also carries the licensed-group path), *Licences, direct* (off), *Usage location* (off; text: "lets this app edit profile properties of every non-admin user"), *Change monitoring* (recommended once a hybrid link exists). Each lists the exact Graph application permissions (FR-04) with a Microsoft doc link | Checklist |
| 3 | Copies the script or follows the portal steps; the wizard shows the **public** certificate generated by activeDIQ (private key stays sealed, ADR-0002 rule 8) | Tenant ID and app ID inputs (no secret input exists) | Wizard step |
| 4 | An Entra role-holder grants admin consent in their own portal (activeDIQ never receives that token) | Link and exact permission list to compare | |
| 5 | **Verify** | Progress per check EV1…EV5 (DM-24 "Checks"), each Pass / Warn / Fail / Could not verify | Progress checklist |
| 6 | **Activate** | Connection `active`. Health shows `takeover_protection: unattested` with the fix (FR-06) | Connection page |
| 7 | **Declare the hybrid link** (which AD domain syncs into this tenant, which sync client, which source anchor) | A *declared* link is created `confirmed` by a holder of `connections.hybrid_link.confirm` over both sides (DM-21.I2). A link *discovered* from correlations stays `proposed` until confirmed | Dialog |

Rotation (FR-39) is a second wizard from the connection page: new certificate, customer adds it, verify,
cut over, customer removes the old one, verify.

### Flow B: the one flow (the 2c demo)

| # | Admin does | System shows |
| --- | --- | --- |
| 1 | **New user**, picks the published template "Employee (hybrid)" | One form: names, OU, licensed group (friendly name, available units), other cloud groups; AD groups are in the same picker with a "synced to Entra" tag. With the opt-in families on, a licence (SKU, optional disabled service plans) and a usage-location country list also appear |
| 2 | **Preview** | One diff with **AD steps** (create user, AD groups, set password) and **Cloud steps** (add to licensed group, add to groups) labelled "runs after Entra receives the user". Badges: **Irreversible** on the password set; "uses 1 of N units"; "inherits tenant location XX". Everything knowable before the AD write has already been checked here (FR-10): a refusal blocks the whole request and nothing is written |
| 3 | **Approve** | If the tenant setting "approval for irreversible changes" holds the request (ADR-0005 rule 8 kernel hold), the approver needs a fresh step-up; step-up for a `StepUp` Action is a separate rule and is shown separately. The approval names what it covers on the cloud side (FR-17 table) |
| 4 | Watches the request | AD half runs. Status: `AD user created ✓ · waiting for Entra to receive jdoe · last checked 14:02 · Entra Connect typically syncs every 30 min · next check 14:03 · cloud steps valid until 14:00 tomorrow`. Actions: **Check now**, **How to sync now** (FR-19), **Cancel cloud steps**, **Undo** |
| 5 | (nothing) | Entra object appears; correlation `matched`; live re-checks pass (FR-16); group adds apply; each step verified (the licence arrives through the group and is verified from `licenseAssignmentStates`). Request `succeeded` |
| 6 | Opens the user | Hybrid user page: AD attributes, Entra licence and groups, SOA badge "Authored in AD", correlation `matched`, request history |

### Unhappy paths
No permission, family off, tenant not attested, group `tier0`, no available units, missing usage location
on the direct path: the request is refused at **Plan** with the reason, the field and the fix, and **no AD
write happens** (FR-10); each offers "continue without the cloud steps". After the AD write: tenant
attestation lapses, correlation not `matched`, authority lost, throttled, Graph unreachable, expiry
(FR-16…21) leave the AD user in place, show the per-step list, and offer **Undo**. Sync late: "late"
banner with causes. 10k results: pickers are searchable and paged. Empty states: no tenants, no licensed
groups or SKUs, no hybrid link.

## 7. Functional requirements

MUST / SHOULD / MAY. "enh" = enhancement E# in §3. Numbers are never reordered; new requirements in round 2
are FR-36…FR-40 and sit in their natural section.

### 7.1 Tenant connection (ADM-159, I360-003)

| ID | Requirement | Parity / enh |
| --- | --- | --- |
| FR-01 | The system MUST connect one Entra tenant per Entra connection (DM-10 `entra_tenant`) using the customer's own app registration with certificate credentials generated by activeDIQ; the private key MUST stay sealed under the tenant key and MUST NOT be shown or returned; the console and API MUST NOT accept a client secret (ADR-0002 rules 3, 8). | ADM-159, I360-003, E4 |
| FR-02 | Several tenants MAY be connected (many-to-many domain-tenant links via DM-21), each with its own credential and binding. | ADM-159 |
| FR-03 | Verification MUST run EV1 (token), EV2 (tenant identity = `directory_identity`, fixed at first verification, DM-10.I1), EV3 (over-privilege), EV4 (read and enabled-write sufficiency), EV5 (excess, warn only) (connector contract §8.4, DM-24). EV3 MUST fail on any TM §6.6 deny-list permission, any directory role (active or eligible) and any unexpired password credential. **For an Entra connection in 2c an EV3 failure MUST NOT be acknowledgeable** (DM-24 allows a DM-25 acknowledgement; the stricter rule is a DM-24 follow-up, §14.3). A rotation's pending certificate is not an "extra key" (FR-39). | ADM-159, E4 |
| FR-04 | The 2c application-permission set is closed and grouped in **families**. **Read (always):** `User.Read.All` ([user delta](https://learn.microsoft.com/en-us/graph/api/user-delta?view=graph-rest-1.0)), `GroupMember.Read.All` (group delta, TM §6.6), SKU reads via `LicenseAssignment.Read.All` or `Organization.Read.All`, and the tier-0 guard reads `Directory.Read.All`, `RoleManagement.Read.Directory` and the two PIM-for-Groups reads. **Group membership (on by default):** `GroupMember.ReadWrite.All` ([add members](https://learn.microsoft.com/en-us/graph/api/group-post-members?view=graph-rest-1.0): least privileged for a user member); it carries the licensed-group path (FR-26). **Licences, direct (opt-in):** `LicenseAssignment.ReadWrite.All` ([assignLicense](https://learn.microsoft.com/en-us/graph/api/user-assignlicense?view=graph-rest-1.0)). **Usage location (opt-in, off by default):** `User.ReadUpdate.All` ([update user](https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0): least privileged for `PATCH /users/{id}`; `usageLocation` is not among the page's listed exceptions, so the documentation covers it, confirm in lab G3). Its EV5 text MUST say the grant is tenant-wide profile write and that Microsoft documents no property-specific permission for `onPremisesImmutableId` or `userPrincipalName` (confirm in lab G3 extended, OQ-F4). **Change monitoring (recommended whenever a HybridLink exists, FR-06):** `AuditLog.Read.All`; optional `Policy.Read.ConditionalAccess` (TM-D25 rule 9). The system MUST NOT request `User.ReadWrite.All`, `Directory.ReadWrite.All`, `User.Create`, `Group.ReadWrite.All` or `Synchronization.ReadWrite.All` (deny list). EV5 MUST NOT flag `AuditLog.Read.All` as excess while a HybridLink exists. A permission an *enabled* family needs and the app lacks MUST disable that family with the permission named (EV4 warn for writes, block for reads). | ADM-159, E4 |
| FR-05 | Every Graph call MUST be application-only. Delegated Graph calls are limited to the one attestation read (FR-06). Rationale: delegated licence and group writes would run as the signed-in admin and need Entra roles ([assignLicense roles](https://learn.microsoft.com/en-us/graph/api/user-assignlicense?view=graph-rest-1.0): License Administrator, User Administrator…), which ADR-0002 rule 7 keeps out of the product. | E4 |
| FR-06 | The Entra connection MUST implement the takeover-protection attestation exactly as DM-10.I7 defines (start with `connections.takeover.attest` + step-up; a Global Administrator signs in once, read-only, `OnPremDirectorySynchronization.Read.All`; the server reads both flags, checks `tid`, discards the token; state computed, never stored; 90-day max age; 14-day warning). Health MUST say what the state blocks: "every cloud step of a hybrid request holds". **Without `AuditLog.Read.All` health MUST show "change monitoring off"**: age is then the only demotion trigger (DM-10.I7(d)), so a flag flip during a wait is invisible for up to 90 days (residual TM-R11, accepted). | ADM-169 (gate), E3 |
| FR-07 | Activation MUST follow DM-10.I9/I11: a qualifying verification ≤ 15 min old; the write gate MUST close every Entra write while V7/EV3 is not `pass` and re-open only on a pass. | ADM-159 |
| FR-08 | A HybridLink (DM-21) MUST carry `sync_client` (`entra_connect` or `cloud_sync`), `expected_sync_interval` (defaults 30 min for Connect and 20 min for Cloud Sync `[PROPOSED]`, the FAQ's 10–20 min; admin-adjustable; used **only** for wait messages, never for correctness) and `source_anchor_attr` (binary anchors only in 2c, platform matrix). Declaring or confirming it MUST need `connections.hybrid_link.confirm` over both sides (DM-21.I2). | ADM-159 |
| FR-39 | **Certificate rotation and expiry.** The system MUST rotate the Entra certificate without downtime: generate the new key sealed under the tenant key; the customer adds the public certificate; Verify recognises the pending thumbprint as ours (SHA-1 of `key`, TM lab G7) and does not report it as an extra key (EV3/EV5); cut over; the customer removes the old certificate; Verify confirms exactly one key; the old private key is deleted once its thumbprint is gone. Health MUST show the certificate's age and expiry and warn 30 days before expiry `[PROPOSED]`. | ADM-159, E4 |

### 7.2 Plan and preview of the hybrid create (ADM-027, ADM-161, ADM-164)

| ID | Requirement | Parity / enh |
| --- | --- | --- |
| FR-09 | A template with `provider = hybrid` (DM-50) MUST define AD steps and **cloud steps** (licensed-group membership by default; with the opt-in families also direct licence SKUs with optional disabled service plans and a usage location; other cloud group memberships). One request MUST be one Operation, one audited unit, with one preview and one approval, planned as a **coupled item group** of an AD item and a cloud item (§14.1 item 1). No template field and no AD step of a hybrid request MAY write `ms-DS-ConsistencyGuid` or `onPremisesImmutableId`; Plan refuses with `consistency_guid_write_refused`. | ADM-027, E1 |
| FR-10 | **Everything that can be known before the AD write MUST be checked at Plan, for the whole coupled group.** A refusal of any one check blocks every item of the request; Plan never writes (ADR-0005 rule 1), so the operation ends `plan_failed` and **no AD write happens**. The checks: (a) a direct-licence step exists and `usageLocation` is absent or not a two-letter ISO 3166 code (Microsoft requires it for licensed users, [user resource](https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0)); (b) a usage location is set while that family is off; (c) a needed permission family is off or missing (`connection_rights_unverified`); (d) direct licence with 0 available units (FR-11); (e) the group classifications and the §8.9 property guard (FR-25); (f) the tier-0 guard for the user and every group, including its PIM reads (FR-16); (g) tenant takeover protection not `attested` (`tenant_takeover_open`); (h) the Plan-time authority rule of FR-33; (i) the link's source anchor unsupported. Each block offers "continue without the cloud steps", which re-plans the request as AD-only. Whether sync writes `usageLocation` from AD is `[UNVERIFIED]`; the flow never relies on it. | ADM-027 |
| FR-11 | Plan MUST read live availability and show `available / total` for a direct SKU, and for the licensed group's SKU. A direct-licence step with 0 available units MUST be `blocked` (`no_available_units`). Availability is a live fact re-read at Apply; the step fails `insufficient_licences` **only if no unit is available at Apply** (a drop from 5 to 4 does not fail it). The licensed-group path MUST show a warning, not a block, because a shortage surfaces later as an error on the user ([group licensing problems](https://learn.microsoft.com/en-us/entra/identity/users/licensing-groups-resolve-problems)). | ADM-161, ADM-027 |
| FR-12 | The preview MUST classify every step `Reversible`, `Lossy` or `Irreversible` with the reason (ADR-0005 rule 1, ENH-04). Defaults: AD create user Reversible; **set initial password Irreversible**; set usage location Reversible; group-member add Reversible; assign licence Reversible, **its inverse (remove) Lossy** because removal can remove access to or data in the services the licence grants `[UNVERIFIED]` service by service. **The undo of an AD create of a synced user is Lossy** and its preview names the effects on the other system: sync will soft-delete the Entra user (restorable 30 days, DM-16), release its licences and drop its group memberships. The password value MUST NOT appear in the plan, plan hash, audit event or API response (a secret-input flag only). | E5 |
| FR-13 | The system MUST NOT create the Entra user for a hybrid request. Creating a cloud object first would invite the soft/hard-match takeover that DM-20.I4(f) exists to prevent. The only source of the Entra object is the customer's sync. | ADM-169 |

### 7.3 Continuation: waiting for the sync

The product behaviour is fixed here. The mechanism is the **ADR-0005 amendment of §14.1** (a gate step with
a `waiting` state, coupled items, outcome names inside the closed result sets, Resume as a new Operation).

| ID | Requirement | Parity / enh |
| --- | --- | --- |
| FR-14 | When the AD item is `succeeded`, the cloud item's gate step MUST enter `waiting` with the identity to wait for: `ad_ref` = the `objectGUID` **returned by our own create** (never re-read later) and the anchor derived from it (base64 of `objectGUID`). The AD-verify read MUST also read `ms-DS-ConsistencyGuid`: absent or equal to `objectGUID` is normal; any other value MUST hold the cloud half as `anchor_tampered` and raise a `high` alert to `tenant-owner`. The same moment fixes `approval_valid_until` = AD verify + 24 h and records the activation digest of FR-17. | E2, security |
| FR-15 | The system MUST look for the Entra object **only by anchor** (`onPremisesImmutableId` equal to the anchor, a supported `$filter` property per the [user resource](https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0)), through the typed OData builder (`Eq` on a constant property with a `Str` value; never UPN, name or mail; P8, `graph.Client.Unique`), as a targeted re-sync (FR-37). Zero matches → keep waiting. More than one → hold `ambiguous_anchor`. **Exactly one match whose object is cloud-only or cloud-managed** (`onPremisesSyncEnabled` not `true`, or `isCloudManaged`) is the shape of a hard-match staging attempt: the system MUST set `cloud_seen_at` (DM-16.I9, through the targeted re-sync), hold `anchor_on_cloud_object`, and raise a `high` alert to `tenant-owner`; it MUST NOT keep waiting silently. Every poll that reads such an object feeds DM-16.I9. The I1a anchor lookup behind the `matched` check MUST fail closed: when any AD connection with a HybridLink to the tenant cannot be read, the result is `ambiguous_anchor`. | ADM-169 |
| FR-16 | Cloud steps MUST run only when **all** hold, each re-read live **immediately before each write**: (1) the correlation is `matched` (DM-20.I4 (a)–(g)) **and is the right one**: `ad_ref` = the recorded `objectGUID`, `entra_ref` = the found object `id`, and the object's anchor equals the recorded anchor; (2) the tier-0 guard on the user and on every group (TM §6.4 E1–E5, TM-D25 rules 1–7), because the new user can become tier-0 during the wait (DM-20.I7); a failed PIM read holds every cloud step (`pim_read_failed`, TM-D25 rule 4); (3) tenant takeover protection is `attested` (DM-20.I4(f), `tenant_takeover_open`) and no re-confirmation is due (`reconfirm_required`); (4) the activation digest still matches (FR-17); (5) the authority of the initiator chain **and of each approver** (FR-33). Any other state holds the cloud half with the first failing reason. The continuation MUST NEVER fall through to FR-32's `candidate` path: a hybrid request whose correlation is not `matched` holds, whatever scope the initiator has. Verify runs ADR-0005 rule 7's `tier0_after_write` for Entra steps. The Entra UPN observed at Apply MUST be shown in the status and the audit when it differs from the planned UPN (identity is the anchor, so no re-approval). | ADM-169, E3 |
| FR-17 | **Unattended continuation.** The cloud half MAY run without a second approval only when the activation digest binds all of the following; a deviation has the stated effect (**refuse**: the cloud half ends, never re-approvable onto another identity; **hold**: the gate stays `waiting`, the new diff is shown, and it resolves only by Resume with a fresh approval of the new diff; **deny**: authority was lost, the cloud half ends). | E1, E5, security |

| Bound element | Value | If it differs at Apply |
| --- | --- | --- |
| Tenant | Entra connection ID and its `directory_identity` (tenant ID, DM-10.I1) | refuse |
| Identity | `ad_ref` = the `objectGUID` returned by our own create; `anchor_attr` + `anchor_value` derived from it; match = anchor | refuse |
| Usage location | the ISO 3166 value (opt-in family only) | hold `replan_changed` |
| Licences | the exact licensed-group IDs, or the exact `skuId` set with each exact `disabledPlans` set, **add-only** (`removeLicenses` empty for a create) | hold `replan_changed` |
| Groups | the exact group object IDs, each with the classification it had at approval (cloud-mastered, not dynamic, not role-assignable, not `tier0`, not in a designated closure) | hold if one is added or reclassified; refuse if one became `tier0` |
| Actors | initiator chain, approval IDs, approvers | deny if any is no longer valid (FR-33) |
| Expiry | `approval_valid_until` = AD verify + 24 h. Fixed: Check now, "late" and polling never extend it | the wait ends (FR-18) |

A narrowing (a step now `already_applied`) never needs re-approval. A scope or permission loss **denies**;
it does not ask for re-approval. Availability is FR-11's, not this table's. The plan hash binds the
*reference* to the AD create's result and everything in the table that is known at Plan; the
`objectGUID`, anchor and `approval_valid_until` do not exist until the AD write, so they enter the
**activation digest** (SHA-256 over plan hash, `objectGUID`, anchor, tenant ID, `approval_valid_until`)
that the cloud steps' tokens bind to (§14.1 item 5). Security-architect to confirm this two-stage binding.

| ID | Requirement | Parity / enh |
| --- | --- | --- |
| FR-18 | The status MUST name the waiting step, last check time, next check time and `expected_sync_interval` at all times. It is **late** after 3 × interval, with a banner naming the causes: sync client stopped, user outside sync scope, OU filtering, takeover protection `[PROPOSED]`, **and "change monitoring off" when `AuditLog.Read.All` is absent**. The wait **ends at `approval_valid_until`**: the cloud item is `cancelled` and the Operation `partially_succeeded` with `cloud_reason = cloud_expired`; the AD user is never rolled back by expiry. **Resume** is a **new Operation** (origin `console`, linked by `request_id`) planned against live state; it is not a transition out of a terminal state. Resume **before** `approval_valid_until` with an identical activation digest keeps the original approvals (same hash, ADR-0005 rule 8); Resume **after** it always needs a new approval (and step-up if a step is Irreversible: the cloud half has none), so a 24-hour approval can never be re-armed open-endedly. | E2 |
| FR-19 | The system MUST NOT trigger a sync itself in 2c: starting a Connect delta cycle needs code on the sync server (`Start-ADSyncSyncCycle -PolicyType Delta`, [scheduler](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sync-feature-scheduler)); Cloud Sync's per-object on-demand provisioning is a Graph synchronization-job action ([device sync](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/device-sync)) whose permission (`Synchronization.ReadWrite.All`) is on the TM §6.6 deny list `[UNVERIFIED]` for the exact action name. **How to sync now** MUST show the copy-ready command or portal path for the customer's sync client; **Check now** MUST request a targeted re-sync (FR-37) and then *read* the correlation. | E2 |
| FR-20 | **Cancel cloud steps** MUST end the cloud item (`cancelled`, `cloud_reason = cloud_cancelled`), leave the AD user, and be audited. **Undo** while waiting MUST cancel the continuation first, then plan the AD undo. | E5 |
| FR-21 | Terminal outcomes MUST never read as plain success unless every step is `verified`, and MUST use only the closed Operation results (ADR-0005 rule 3) plus a `cloud_reason` field. Display labels such as "AD done, cloud expired" are derived from the pair; they are not states. See the table below. Each outcome MUST list which steps ran, which did not (`not_run`) and the next admin action; **AD undo is offered whenever the AD item is `succeeded`**. | E5 |

| Situation | Operation result | `cloud_reason` | Items |
| --- | --- | --- | --- |
| Any Plan-time block (FR-10) | `plan_failed` | n/a | none run; no AD write |
| Cancelled before the AD write | `cancelled` | n/a | both `cancelled` |
| AD item failed | `failed` | n/a | cloud item `cancelled` (not started) |
| AD done; every cloud step verified | `succeeded` | n/a | both `succeeded` |
| AD done; a cloud step `failed` or `verify_failed` | `partially_succeeded` | `cloud_step_failed` | per-step list |
| AD done; the wait reached `approval_valid_until` | `partially_succeeded` | `cloud_expired` | cloud item `cancelled` |
| AD done; admin cancelled the cloud steps | `partially_succeeded` | `cloud_cancelled` | cloud item `cancelled` |
| AD done; identity refused or authority lost (FR-16, FR-17) | `partially_succeeded` | `cloud_denied` | cloud item `cancelled` |
| AD done; cloud steps waiting or held | not terminal: the Operation stays `running` | n/a | cloud item `running`, gate step `waiting` with a `wait_reason` |

| ID | Requirement | Parity / enh |
| --- | --- | --- |
| FR-40 | **Request controls and their authority.** *Check now* is a read, rate-limited per request `[PROPOSED]` (one per 30 s), open to anyone who can read the request. *Cancel cloud steps*, *Undo* and *Resume* are audited Actions; each MUST need its Action's permission over the request's scope, evaluated by the Plan-time authority rule of FR-33 (and re-checked at Apply), and Resume additionally an approval where FR-18 requires one. Permission names `[PROPOSED]`; DM-33 registry follow-up. | ADM-169 |

### 7.4 Cloud steps (ADM-027, ADM-161, ADM-164)

| ID | Requirement | Parity / enh |
| --- | --- | --- |
| FR-22 | **Direct licence assign/replace/remove (opt-in family)** MUST use `POST /users/{id}/assignLicense` addressed by the object `id`, never by UPN (X3); `removeLicenses` MUST always be sent (it is required, may be empty). Before writing, the connector MUST read the user's `assignedLicenses`; a present SKU is `already_applied`. Service-plan toggles are `disabledPlans` on the add. A replace is one call (add + remove) so the user is never unlicensed in between. A timeout after the request was sent MUST be resolved by reading the target before any retry; if the target cannot be read the step ends `outcome_unknown`, is never retried automatically, and is resolved by Check now or Resume. | ADM-161, M365-005 |
| FR-23 | **Group membership** MUST be the Entra arm of the existing `objects` group-membership Actions (no per-provider clone), using `POST /groups/{id}/members/$ref` after a direct membership test; Graph returns `400` when the object is already a member ([add members](https://learn.microsoft.com/en-us/graph/api/group-post-members?view=graph-rest-1.0)), so an existing member is `already_applied`, not an error. Bulk adds MAY use up to 20 per request (same page); 2c needs one. The `outcome_unknown` rule of FR-22 applies. | ADM-164, M365-007 |
| FR-24 | Groups mastered on-premises (`onPremisesSyncEnabled = true`) MUST NOT be changed through Graph. Plan MUST route such a group to an **AD** membership step in the AD item (membership of an AD-mastered group is an AD attribute, DM-20.I3) and show it as "synced to Entra". Graph cannot update members of AD-synced groups ([group SOA](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-group-source-of-authority-configure); exact Graph error `[UNVERIFIED — lab]`). A group whose SOA was moved to the cloud (`isCloudManaged`) is treated as a cloud group. | ADM-164 |
| FR-25 | **Every cloud step MUST pass the connector contract §8.9 property guard with its `PropertyWrite`** (TM-D25 rule 7): a licence write (and membership of a group that carries a licence) is refused when the dynamic-group closure holds `assignedPlans`, `mail` or `proxyAddresses`; a `usageLocation` write is checked as the dynamic-rule property it commonly is; a membership write is guarded as a potential licence write. Plan MUST block, with the reason, any group step whose target is: dynamic-membership (members are rule-derived, `[UNVERIFIED]`: confirm in lab), **any `tier0` group** per TM §6.4 E1–E5 and TM-D25 rules 1–7 (role-assignable, privileged-role holders, groups that are PIM-eligible members of a role-assignable group, customer-designated Conditional-Access-excluded groups), or inside a designated dynamic-group closure where `GROUP_MEMBERSHIP` is refused (§8.9). | ADM-164, security |
| FR-26 | The **licensed-group path (the default)**: membership of a cloud group that carries the licence, added directly (group-based licensing does not support nested groups: only first-level members are licensed, [group licences](https://learn.microsoft.com/en-us/microsoft-365/admin/manage/manage-group-licenses?view=o365-worldwide)). Verify for it MUST read `licenseAssignmentStates` for the SKU (`assignedByGroup`, state, error; [licenseAssignmentState](https://learn.microsoft.com/en-us/graph/api/resources/licenseassignmentstate), enum values `[UNVERIFIED — lab]`) because Microsoft processes group licensing asynchronously and it can take long under load (same page). A state with an error (for example not enough licences, usage location not allowed) MUST end the step `verify_failed` with the error shown. Plan shows "inherits tenant location XX" when the user has no usage location. Assigning a licence *to a group* is deferred (2c-b). | ADM-161, E4 |
| FR-27 | Throttling: a `429` MUST keep the step `applying` and retry after the `Retry-After` value (exponential backoff if absent), never immediately; at most four concurrent writes per tenant (ADR-0005; [throttling](https://learn.microsoft.com/en-us/graph/throttling)). A `$batch` MUST NOT be used for writes in 2c (throttled members are not retried automatically, same page). | all |
| FR-28 | Eventual consistency: a `400 "The source resource object or one of the objects being referenced don't exist"` immediately after an object was created or changed MUST be retried inside a bounded window (default 2 minutes `[PROPOSED]`) before the step fails ([add members note](https://learn.microsoft.com/en-us/graph/api/group-post-members?view=graph-rest-1.0), [eventual consistency](https://devblogs.microsoft.com/identity/designing-for-eventual-consistency-for-microsoft-entra/)). With the usage-location family on, the value MUST be read back before the direct licence call; an `assignLicense` `400` right after a successful `usageLocation` write is retried in the same window (reported by practitioners, `[UNVERIFIED]`). | all |
| FR-29 | Each cloud step MUST be verified by a read-back inside the per-provider verify window: the group `members` test passes; `licenseAssignmentStates` per FR-26 (or `assignedLicenses` contains the SKU on the direct path); `usageLocation` equals the planned value. A window that elapses without the after-state is `verify_failed` `read_back_mismatch` (ADR-0005). | E5 |

### 7.5 Source of authority, licence management, authority, audit

| ID | Requirement | Parity / enh |
| --- | --- | --- |
| FR-30 | Every user page, search row and request MUST show a source-of-authority badge derived from the correlation: **AD** (`matched`), **Cloud** (cloud-only or `isCloudManaged`), **Candidate** (with `candidate_reason` and its fix), or **Broken**. The badge MUST also state, for a hybrid user, which attributes are edited where (AD-mastered attributes go to AD, licences to Graph; DM-20.I3). No create control exists for cloud-only users in 2c (absent, not disabled). Showing Entra objects in search needs E-011 / T-1131 (§14.6). | ADM-169, ADM-009 (read), E3 |
| FR-31 | From any user with an Entra object in the admin's scope, the admin MUST be able to add or remove licensed-group membership and cloud group membership, and, with the opt-in family, add, replace or remove a direct licence, through the same preview/approve/verify/undo pipeline, for up to 50 users per operation in 2c (the 51st is refused at Plan with the limit named). CSV and larger batches are slice 2c-b. | ADM-161, ADM-164, M365-005, M365-007 |
| FR-32 | Actions on a **`candidate`** or `broken` correlation (not part of a hybrid create) MUST be limited to what the admin's Entra-root scope allows on an Entra object, and MUST never route to AD (DM-20.I3). | ADM-169 |
| FR-33 | Authorisation MUST be the DM-36 model. Permissions: `m365.licence.assign`, `m365.licence.remove` (blueprint `m365` module); group membership uses the permission(s) of the existing group-membership family (`GroupMembershipPermissions`, rbac module), and usage location the Entra arm of `objects.user.update` limited to the key `usageLocation`; names `[PROPOSED]`, DM-33 registry follow-up. **Plan, for a cloud item whose Entra object does not exist yet:** the initiator, and the approver where the gate holds the request, MUST hold the permission over the tenant's `entra_tenant` root, **or** over the planned AD parent OU with `include_correlated` (DM-35.I6), else the request is blocked `scope_denied`. **Apply, against the resolved object:** the system MUST re-check the initiator chain **and each approver** (account active; still holds `operation.approve` over the resolved Entra object through `entra_tenant`, an administrative unit, Entra `group_members`, or an AD scope with `include_correlated` through the `matched` correlation; separation-of-duties checks still pass). A scope, role or account lost while waiting MUST deny the steps (`approver_scope_denied` / `scope_denied`). No cloud permission is ever granted by a technician-supplied template (DM-50.I3). Depends on E-011 (§14.6). | ADM-131 |
| FR-34 | Audit (DM-80): `operation.*` events per ADR-0005 rule 11 (`operation.completed` carries `cloud_reason`) plus `hybrid.awaiting_sync.started`, `.correlation.matched`, `.late`, `.held`, `.expired`, `.cancelled`, `.resumed`, `connection.attested`, `connection.certificate.rotated` and the connection events of the forest spec. Each cloud-step event MUST carry the AD `objectGUID`, the Entra object `id`, the anchor, the correlation ID, state and `eligibility_class`, the attestation ID and age, the approval IDs and `plan_hash`, the activation digest, and that the executor was the continuation acting for the initiator chain. No password, token, certificate or SKU secret appears in any event. The initial password is stored only sealed in `operation_secret` (ADR-0005 rule 9, 72-hour TTL) and deleted when the AD step records; the cloud half holds no secret. | all |
| FR-35 | Errors MUST map to the closed set below, each shown with cause and next action. Never "something went wrong". | all |

| Phase | Codes |
| --- | --- |
| Plan (block) | `no_available_units`, `usage_location_missing`, `usage_location_family_off`, `connection_rights_unverified`, `scope_denied`, `tier0_refused`, `group_not_writable(<why>)`, `tenant_takeover_open`, `anchor_attr_unsupported`, `consistency_guid_write_refused` |
| Apply (hold, deny, refuse) | `not_matched(<reason>)`, `ambiguous_anchor`, `anchor_on_cloud_object`, `anchor_tampered`, `replan_changed`, `approver_scope_denied`, `scope_denied`, `pim_read_failed`, `tenant_takeover_open`, `reconfirm_required` |
| Apply (step outcome) | `throttled`, `replication_pending`, `insufficient_licences`, `read_back_mismatch`, `licence_state_error(<error>)`, `outcome_unknown`, `tier0_after_write`, `cloud_expired` |

## 8. Pipeline fit (ADR-0005)

What this spec uses **unchanged**: Plan is read-only; `plan_hash` over steps, diffs, reversibility and
secret-input flags (rule 9); one approval (rule 8, SoD, step-up for Irreversible); a step token per claimed
step (rule 2); read-then-write idempotency and `already_applied` (rule 4); the `tier0` guard and
`tier0_after_write` (rule 7); verify windows and 429 handling (four concurrent writes per tenant); undo as
a new Operation in reverse order, planned against live state.

What it **cannot** do on ADR-0005 as ratified, and which the amendment of §14.1 supplies: a wait or gate
step (rule 3 has no wait and no `running → planning` edge); items that block or run as a group (rule 1
makes the item the unit of blocking); a request outcome for "AD done, cloud refused" inside the closed
result sets (rule 3); Resume (nothing leaves a terminal state); a target that does not exist at Plan
(rule 1 defines "to be created" only for an AD parent and RDN, rule 7 has no Plan-time authority for it,
rule 9 hashes every item's target); `plan_valid_until` (1 h) being shorter than a sync cycle; and
`outcome_unknown` for a non-password step (a Graph timeout after send).

## 9. Data and API impact

- **Graph resources:** `users/{id}` (read; `assignLicense`; PATCH `usageLocation`), `users/delta`, `groups/delta`, `subscribedSkus` (read), `groups/{id}` and `members/$ref`, `users/{id}/licenseAssignmentStates` (read), `organization` (verified domains, tenant location; read). All URLs through the P8 builders (`graph.Client.Unique`, `Key(GUID)`); no `$filter`/`$search` literal outside the home package; `@odata.nextLink` followed only after the host pin (P8 V12).
- **Actions:** group membership = Entra arm of the existing `objects` group-membership Actions; usage location = Entra arm of `objects.user.update`, allow-listed to the single key `usageLocation` (TM-D28 B2/B4/B8); licence = `m365.licence.assign` / `m365.licence.remove`. **No `m365.group.member.*` and no `m365.user.usage_location.set`** (round 1 drafted them; superseded).
- **New persisted entities (domain-model follow-ups):** a **HybridRequest / continuation** record (gate state, recorded anchor, activation digest, `approval_valid_until`, wait deadlines, `wait_reason`); **LicenceSku** inventory (SKU id, friendly name, service plans, prepaid/consumed units, observed time) — DM-16 has no licence concept beyond "Entra-only attributes (licences)"; Entra inventory rows and delta cursors (§7.6); DM-21 attributes `sync_client`, `expected_sync_interval`, `source_anchor_attr`; DM-50 `usage_location` field and the deferred cloud step group.
- **Connector contract:** Entra rows of the EP-11 `(ProviderKind, WriteKind)` table with a `PropertyWrite` per kind (§8.9) for licence assignment, group membership add/remove and usage-location update (`WriteKind` has no Entra kind today, §8.1), with touched-set rule, conformance cases and a `Describe` entry; a retryable "target not yet visible" error (today `OBJECT_NOT_FOUND` is never retried); an ambiguous-outcome signal for Graph writes.
- **Events:** FR-34. **API operations (for the 2c OpenAPI spec):** connect/verify/activate/attest/rotate tenant; declare/confirm hybrid link; list SKUs and licensed groups; plan/approve hybrid create; read request status; check-now; cancel cloud steps; resume; licence and group operations on a user; Entra dataset registration. Verification, sync and waits are jobs, not requests.
- **Scale:** SKU list and group pickers are searched server-side and paged; a group with > 1,500 members (and 50k) is never enumerated to test membership; Entra sync is paged delta and the licence-state reconcile is paged.

## 10. Security considerations (tag all build tickets `security-sensitive`)

- **Privileges.** Entra: only FR-04's permissions, application-only, no directory role (EV3 refuses, no acknowledgement). Default grant = reads + `GroupMember.ReadWrite.All`. Direct licensing and usage location are opt-in; `User.ReadUpdate.All` is tenant-wide profile write and is probably able to write `onPremisesImmutableId` and the UPN of non-admin users `[UNVERIFIED — lab G3 extended]`, which is why it is off by default (residual to be added to TM §6.6). AD: none new in this spec; the AD half's rights belong to E2.2/forest connection. `security-architect` re-reviews FR-03…FR-07, FR-13…FR-17, FR-24, FR-25, FR-33, FR-39 and §14.1.
- **Tier 0.** Entra `tier0` (TM §6.4 E1–E5 and the TM-D25 reach closure) is outside every write scope (DM-35.I5). A new hybrid user is never `tier0` at creation, but may become so during the wait (a protected-group addition): the guard re-runs before each write (FR-16). A correlation never brings a `tier0` object into reach (DM-20.I7).
- **The central abuse case: licensing or grouping an object we did not create.** Vectors and defences: *soft match* (pre-staged UPN) — anchor-only lookup, attested soft-match blocking, writes by object `id`; *hard match* (pre-staged `onPremisesImmutableId` equal to the new GUID, readable by any domain user once the AD half commits, TM §6.8) — attested hard-match blocking plus FR-15's `anchor_on_cloud_object` hold, `cloud_seen_at` and alert, so DM-20.I4(g) fires; *anchor collision / stamped `ms-DS-ConsistencyGuid`* — anchor = our created `objectGUID`, `anchor_tampered` hold, Plan refuses the write, `ad_ref` binding, fail-closed I1a lookup; *flag flip in the wait window* — change monitoring (FR-06) and (g); residuals TM-R11, TM-R12 and the E4 admin who can write the anchor. An Entra-scoped admin acting on a `candidate` object is accepted by design (FR-32) and is unreachable from the continuation (FR-16).
- **Unattended continuation.** Bounded by the FR-17 table: bound descriptor, 24-hour fixed `approval_valid_until`, live re-check of initiator **and each approver**, no fall-through, Resume after expiry needs a new approval. This applies security ruling A.1 verbatim except the two-stage hash noted under FR-17.
- **Safe primitives (rule 5).** OData through P8 only (`Eq`, `Str`, `Key(GUID)`; `MaxString`, `MaxIn`, `MaxAnd`, `MaxURL` limits); no Graph URL assembled outside `internal/directory/graphwrite`/home packages (FF-SP2/3: `graph-url-assembly`, `odata-key-shape`); JSON bodies from typed structs; objects addressed by `id` after `Unique`. The usage-location Action emits only the constant key `usageLocation`. Egress: one client, resolved IP, no private ranges (TM-TB9-T1); Graph host pin.
- **Credentials.** Certificate private key sealed, never returned, deleted when the connection is removed or the old key's thumbprint is gone after rotation (FR-39). An expired or extra credential on the app is a finding (EV5/EV3). A stolen certificate is a TM §6.6 residual (`addKey` mitigations).
- **Audit.** FR-34; links the AD and Entra halves by one request ID so an auditor reads one chain.
- **Lab.** Lab credentials never committed; the Entra sandbox bootstrap writes gitignored files only (D-0001 decision).

## 11. Acceptance criteria

Lab tiers per §5: **F** fake Graph, **E** Entra sandbox, **H** E + Entra Connect on the Windows lab, **S** Samba. Evidence is test output, a recorded Graph request log, or a screenshot of the named state. `qa-verifier` re-runs each against the running product. `[LAB-E]` items cannot be proved from this machine and are the 2c demo proof. Test names in backticks are the proposed evidence names.

| ID | FR | Given / When / Then | Tier | Evidence |
| --- | --- | --- | --- | --- |
| AC-01 | 01, 03, 07 | **Given** an admin with the connection permission and fresh MFA and a correctly consented app **when** they Verify **then** EV1…EV5 pass, the tenant ID becomes the fixed identity, and Activate leads to `active` with `takeover_protection: unattested` shown; no client-secret input exists in console or API. | E | Screenshot of the checklist; verification row; API schema |
| AC-02 | 03 | **Given** an app that holds `Directory.ReadWrite.All`, or an eligible directory role, or an unexpired client secret **when** verified **then** activation is refused naming each finding, no Entra write is possible, and no acknowledgement control exists. | F, E | `ev3_refuses_deny_list`; screenshot |
| AC-03 | 04 | **Given** an app lacking `GroupMember.ReadWrite.All` (or, with the direct family on, `LicenseAssignment.ReadWrite.All`) **when** verified **then** reads work, that family is shown disabled naming the permission, and a template step of that family plans `blocked` (`connection_rights_unverified`) with no AD write. | F | Test; screenshot |
| AC-04 | 04, 05 | **Given** a new connection with default choices **when** its consent list is generated **then** it holds only the Read and Group-membership permissions and none of `User.ReadUpdate.All`, `LicenseAssignment.ReadWrite.All`; **given** the Usage-location family is enabled **then** the EV5 text names tenant-wide profile write; and every recorded Graph call is application-only except the one attestation read. | F | `ev5_warns_user_readupdate_breadth`; request-log token types |
| AC-05 | 02 | **Given** two tenants connected to the same forest **when** a hybrid request names tenant B **then** only tenant B's credential, binding and attestation are used and tenant A receives no call. | F | Request log |
| AC-06 | 06, 10 | **Given** a tenant whose attestation is absent, stale (> 90 days) or open **when** the admin previews a hybrid create **then** the request is `plan_failed` with `tenant_takeover_open`, no AD write occurs, and "continue without the cloud steps" re-plans it AD-only; the attestation read discards its token and the 14-day warning appears. | F, E | Test asserts zero AD changes; token-discard test |
| AC-07 | 06, 16 | **Given** the attestation lapses while a request waits **when** the cloud half evaluates **then** it holds `tenant_takeover_open`, the AD half stays done, and zero Graph writes occur. | F | Request log |
| AC-08 | 07 | **Given** an active connection **when** EV3 starts failing **then** every Entra write is refused until a passing verification re-opens the gate. | F | Test |
| AC-09 | 08 | **Given** an admin holding the hybrid-link privilege over only one side **when** they declare or confirm a link **then** it is refused naming the missing side; a declared link is created `confirmed`, a discovered one `proposed`; a link with a string source anchor makes the hybrid create `plan_failed` (`anchor_attr_unsupported`). | F | Tests |
| AC-10 | 39 | **Given** an active certificate **when** the admin rotates **then** the pending thumbprint is not flagged as an extra key, Entra calls never fail during cutover, after the customer removes the old certificate Verify confirms one key and the old private key is deleted, and an expiry warning shows 30 days out. | F, E | `certificate_rotation_no_downtime`, `pending_thumbprint_not_flagged_extra`, `expiry_warning` |
| AC-11 | 04, 06, 18 | **Given** a HybridLink and no `AuditLog.Read.All` **when** health is read **then** it shows "change monitoring off" and the late-banner causes include it; **given** the permission is present **then** EV5 does not flag it as excess. | F | `hybrid_link_without_auditlog_shows_monitoring_off`, `ev5_does_not_flag_auditlog_with_hybrid_link` |
| AC-12 | 09, 12, 17, 26, 29 | **Given** an attested tenant, a confirmed link, template "Employee (hybrid)" with a licensed cloud group (default family set only), 1 cloud group and 1 AD-synced group **when** the admin previews, approves and the sync runs **then** the preview shows AD and cloud steps with the password Irreversible and the unit count; the AD user exists; after sync the Entra user is a direct member of the licensed group and `licenseAssignmentStates` shows the SKU assigned by that group in a non-error state, is a member of the cloud group, and the AD-synced group membership came through AD; no `User.ReadUpdate.All` or `LicenseAssignment.ReadWrite.All` call occurred; the request is `succeeded` with ≤ 3 interactions after the form. | H `[LAB-E]` (F in CI) | Recorded Graph reads; AD read; screenshots of preview and final state; task timing |
| AC-13 | 09, 10, 22, 28, 29 | **Given** the Licences-direct and Usage-location families on, a direct SKU with a disabled-plan set and usage location `GB` **when** the same flow runs **then** `usageLocation = GB` is read back before `assignLicense`, `assignedLicenses` contains the SKU, and the request is `succeeded`. | H `[LAB-E]` (F in CI) | Recorded Graph reads |
| AC-14 | 10 | **Given** each Plan-time check of FR-10 (a)…(i) in turn (direct licence without usage location; usage location with the family off; family missing; 0 units; `tier0`/dynamic group; PIM read failure; unattested; scope not covering the tenant root or planned parent; string anchor) **when** the admin previews **then** the request is `plan_failed` naming the check, the field and the fix, **no AD change occurs**, and "continue without the cloud steps" works. | F, S | Parametrised test asserts zero AD changes |
| AC-15 | 11 | **Given** 0 available units of a direct SKU **when** previewing **then** the step is `blocked` (`no_available_units`); **given** availability falls from 5 to 4 between approval and apply **then** the step succeeds; **given** it falls to 0 **then** the step fails `insufficient_licences`, the AD user remains and the request is `partially_succeeded` (`cloud_step_failed`). | F, E | Tests; request log |
| AC-16 | 13, 14, 18, 19 | **Given** the AD half is done and the Entra object does not exist **when** the admin opens the request **then** it shows `waiting for Entra`, last and next check, the expected interval and the fixed `approval_valid_until`, with **Check now**, **How to sync now**, **Cancel cloud steps**; after 3 × interval it also shows "late" with causes; no Entra user was ever created by the product. | F (clock faked), H | Screenshots at T+0 and T+3×interval; request log shows no `POST /users` |
| AC-17 | 15 | **Given** a cloud user pre-created with the new user's UPN and a different anchor, takeover blocking on **when** the cloud half evaluates **then** it finds no anchor match, writes nothing to that object, and keeps waiting. | F, E | Request log: no write to the foreign object id |
| AC-18 | 15 | **Given** a pre-staged cloud-only user carrying the new user's anchor **when** the poll reads it **then** `cloud_seen_at` is set, the request holds `anchor_on_cloud_object`, a `high` alert reaches `tenant-owner`, and zero writes occur; **given** two objects carry the anchor **then** it holds `ambiguous_anchor`. | F | `prestaged_cloud_object_with_anchor_holds_and_alerts`, `anchor_mismatch_holds` |
| AC-19 | 09, 14 | **Given** a template that writes `ms-DS-ConsistencyGuid` **when** previewing **then** Plan refuses (`consistency_guid_write_refused`); **given** another writer stamps a different value on the new user before AD verify **then** the cloud half holds `anchor_tampered` with an alert and the recorded anchor stays the created `objectGUID`. | F, S | `consistency_guid_stamped_holds` |
| AC-20 | 16 | **Given** the found Entra object is `matched` to a different AD object than the one we created, or its anchor differs from the recorded anchor **when** evaluated **then** the cloud half holds with zero Graph writes. | F | `correlation_adref_must_equal_created_guid` |
| AC-21 | 15 | **Given** one AD connection with a HybridLink to the tenant cannot be read **when** the anchor lookup runs **then** the result is `ambiguous_anchor` and nothing is written. | F | `anchor_lookup_unknown_forest_fails_closed` |
| AC-22 | 17 | **Given** a changed tenant, anchor, licence set, disabled-plan set, group set, group classification or usage location **when** the activation digest is recomputed **then** it differs, with the stated effect (refuse or hold). | F | `approval_binds_deferred_target` (table-driven over the FR-17 rows) |
| AC-23 | 17 | **Given** the cloud-half diff at Apply differs from the approved one in SKU, group or classification **when** the Entra object matches **then** the cloud half holds `replan_changed`, zero Graph writes occur, the new diff is shown, and with no workflow matching the initiator can re-submit through Resume; **given** the diff is equal **then** the steps run without a second approval. | F | Tests |
| AC-24 | 17, 33 | **Given** an approver whose scope never reached the Entra tenant **when** the cloud half evaluates **then** the steps are held or denied `approver_scope_denied` and nothing is written; **given** the approver is disabled while the request waits **then** the steps are denied. | F | `approver_scope_rechecked_on_cloud_target`, `approver_disabled_while_waiting` |
| AC-25 | 18, 20 | **Given** a request waiting until `approval_valid_until` **when** the window ends **then** the result is `partially_succeeded` with `cloud_expired`, the AD user is unchanged and Check now has not extended the window; **when** Resume is pressed **then** a new Operation is planned against live state and needs a new approval; with an approval inside the window and an identical digest the original approval carries. | F (clock faked) | `resume_after_expiry_requires_new_approval` |
| AC-26 | 16, 32 | **Given** a hybrid request whose correlation is `candidate` **and** an initiator with an `entra_tenant` scope **when** the cloud half evaluates **then** it holds and never takes the FR-32 path. | F | `candidate_never_falls_through_to_entra_scope_path` |
| AC-27 | 16, 25 | **Given** a cloud group that is a PIM-eligible member of a role-assignable group, a customer-designated group, a new user that became `tier0` during the wait, or a failed PIM read **when** evaluated **then** the step is refused or the whole cloud half held, and a post-write `tier0` finding yields `tier0_after_write`. | F | `group_in_pim_closure_refused`, `designated_group_refused`, `user_became_tier0_while_waiting_refused`, `pim_read_failure_holds_cloud_half` |
| AC-28 | 25 | **Given** a dynamic-membership group, a role-assignable group, a group inside a dynamic-group closure, or a licence write or `usageLocation` write whose closure holds a guarded property **when** previewing **then** the step is `blocked` with the reason. | F | Test per case |
| AC-29 | 27 | **Given** fake Graph returns `429` with `Retry-After: 10` **when** a cloud step applies **then** it stays `applying`, retries no earlier than 10 s, never writes twice, and at most four writes are in flight for the tenant. | F | `graph_429_retry_after` |
| AC-30 | 28 | **Given** the group add returns the replication `400` right after the user match **when** retried **then** it succeeds inside the 2-minute window; if the window ends the step fails `replication_pending` and Resume works. | F | Test; screenshot |
| AC-31 | 21 | **Given** the licensed-group add succeeds and a second group add is refused **when** the request ends **then** the result is `partially_succeeded` with `cloud_step_failed`, the per-step list shows `verified` and `failed`, and Undo offers the applied steps and the AD undo. | F | Test; screenshot |
| AC-32 | 24 | **Given** the admin picks a group with `onPremisesSyncEnabled = true` **when** previewing **then** it appears as an AD step and no Graph write to that group is ever sent. | F | Request log |
| AC-33 | 22, 23 | **Given** a completed request **when** it is re-run **then** every step is `already_applied` / `no_change` and Graph receives no write; **given** a write times out after send **then** the target is read before any retry, and an unreadable target yields `outcome_unknown` with no automatic retry. | F, E | Request log; `graph_timeout_reads_before_retry` |
| AC-34 | 12, 20, 21 | **Given** a `succeeded` request **when** the admin undoes it **then** the preview lists cloud removals first and then the AD delete classed **Lossy** with the sync soft-delete, licence release and membership effects named; **given** the request is waiting **then** undo cancels the continuation and deletes the AD user. | F, H | Previews; recorded order |
| AC-35 | 20, 40 | **Given** a waiting request **when** the admin cancels the cloud steps **then** the AD user remains, no cloud write is made, the result is `partially_succeeded` / `cloud_cancelled`, and the audit shows who and when; **given** a user without the cancel permission **then** the control is refused with the permission named. | F | Test; audit read |
| AC-36 | 33 | **Given** a technician without the needed permission, or whose scope is removed while the request waits **when** the cloud half runs **then** it is denied at Plan or at the live Apply re-check with the permission or scope named, and the result is `cloud_denied`. | F | Test; denial audit event |
| AC-37 | 30 | **Given** a synced user, a cloud-only user, a candidate and a broken correlation **when** the admin opens each **then** the badge reads AD, Cloud, Candidate (with reason and fix), Broken; a differing observed UPN is shown; and no "create cloud-only user" control exists. | F, E | Screenshots (four states) |
| AC-38 | 31 | **Given** 50 existing users selected **when** the admin adds them to a cloud group (and, with the family on, a direct licence) **then** one preview/approval covers all and each is verified; a 51st is refused at Plan naming the limit. | F | Tests |
| AC-39 | 34 | **Given** any hybrid request **when** the audit chain is read **then** AD and Entra steps share the request ID, each cloud-step event carries the evidence fields of FR-34, and a search for the initial password, certificate bytes and tokens finds nothing in any event, log, plan or API response. | F | Canary test (TM-F-SECRETOUT style) |
| AC-40 | 23, 36 | **Given** a tenant with 100,000 users and a group with > 1,500 members **when** previewing a membership add **then** the page responds without enumerating members and shows a membership test result. | F (synthetic) | Request log shows no member paging |
| AC-41 | 35 | **Given** each code in the FR-35 table is provoked **when** the UI and API render it **then** it shows cause and next action, and no response carries a generic error. | F | Per-code test |
| AC-44 | 09, 11, 26, 30 | **Given** no tenants, no licensed groups or SKUs, Graph unreachable, or the connection `suspended` **when** the admin opens the screens **then** each shows its named empty or error state, every control works or is absent, and no number is invented. | F, E | Screenshots; QA control sweep |
| AC-45 | 09 | **Given** a fitness run **when** CI executes **then** no Graph URL or OData option is built outside the home packages, no script verb is reachable from a hybrid input, and the usage-location Action emits only the key `usageLocation`. | CI | FF-SP2/3 output; `usage_location_action_emits_only_usageLocation` |
| AC-46 | 26, 29 | **Given** the licensed-group path and `licenseAssignmentStates` reports an error for the SKU (for example not enough licences or usage location not allowed) **when** verify reads it **then** the step ends `verify_failed` showing the error and the request is `partially_succeeded`. | F | Test |

## 12. Out of scope (with destination)

Cloud-only user create (ADM-009) and bulk M365 (ADM-160): post-2c. CSV licence management, assigning a
licence to a group, OU filter, account actions (ADM-162): slice 2c-b. Roles and Conditional Access
(ADM-168, ADR-0002 rule 7): not in v1. Exchange Online features, remote mailbox, Teams (ADM-165…167, 070,
026): M5 / FD-04 helper. M365 report *content* (ADM-094, M365-001…): E2.6/M5 (this spec registers the
datasets only). MFA settings and TAP (ADM-163, M365-008): P4. M365 delegation editor UI (E2.5). Workflow
approval (E2.8); HR-driven hybrid joiners (E2.9, will reuse these Actions). Entra devices and group member
lists in inventory: later. Setting usage location from AD (`msExchUsageLocation`): not relied on (OQ-F9).
National clouds; air-gapped Entra. A Windows helper on the sync server. Guest/B2B users.

## 13. Open questions

| # | Question | Tag | Owner | Blocks / default |
| --- | --- | --- | --- | --- |
| OQ-C1 | Should the product ever ship a customer-run helper on the Entra Connect server to start a delta cycle (a new Windows component on a Tier-0 host, FD-11)? | **CEO-directional (scope), dormant** | factory-director → CEO | Nothing in 2c. **Recommendation: no.** v1 offers guided "How to sync now" plus targeted re-check (FR-19). File a decision only if a pilot asks. No new CEO question arises from round 2 |
| ~~OQ-F1~~ | Closed by proposal: the mechanism is the §14.1 amendment (gate step, coupled items, outcomes, Resume, deferred-target hash, `plan_valid_until`) | factory | solution-architect → factory-director ratifies | Build tickets wait for ratification |
| ~~OQ-F2~~ | **Closed** by the security ruling, applied as FR-14…FR-18 and the FR-17 table. One residual for `security-architect`: the two-stage binding (plan hash plus activation digest) | factory | security-architect | AC-22 |
| OQ-F3 | Does Cloud Sync populate `onPremisesSecurityIdentifier` for users (DM Q8)? Which sync client does the pilot use? | factory | test-engineer (T-0051 lab), `[DISCOVERY]` | Cloud Sync claim |
| OQ-F4 | Lab G3 extended: can `User.ReadUpdate.All` write `onPremisesImmutableId` and the UPN of a non-admin user? Exact Graph errors for AD-synced group writes, dynamic groups, `assignLicense` after `usageLocation`; read-after-write lag; `licenseAssignmentStates` enum; do `users/delta` and `groups/delta` return `onPremisesImmutableId`, `assignedLicenses` and group `assignedLicenses` as selected | factory | directory-engineer on the sandbox | FR-04, 10, 24, 25, 28, 36 |
| OQ-F5 | Where does a usage-location default come from for the opt-in family (template field, tenant default, AD `c`/`co` mapping)? PM default: template field, no inference; the default path inherits the tenant location | factory | product-manager + product-designer | FR-10 |
| OQ-F6 | Verify-window length, retry bounds, wait/late/expiry defaults (30 min / 3× / 24 h), reconcile cadence | factory | backend-engineer + lab | FR-18, 28, 29, 36 |
| OQ-F7 | Does ADMP wait, retry or trigger a sync for a freshly created user (undocumented)? | factory | `market-analyst` research ticket (to file on the server) | Comparative claims only |
| OQ-F8 | What does a user with no usage location actually inherit under group-based licensing: confirm `organization` country letter code equals the tenant location the page means | factory | directory-engineer on the sandbox | FR-26, Flow B |
| OQ-F9 | Does `msExchUsageLocation` flow to `usageLocation` through sync (an AD-side way to set the location with no Graph write)? | factory | directory-engineer (Connect lab) | Optional; not relied on |

## 14. Follow-ups (outside this diff; for the server board)

### 14.1 ADR-0005 amendment (technical, director-ratified)

### 14.2 ADR-0004 rule 14 amendment

Operation-level routes for multi-family Operations: status, check-now (read), cancel cloud steps, Resume as
a new Operation, and undo of an Operation that spans `objects.user.*`, the Entra group-membership arm and
`m365.licence.*` (rule 14 defines one undo pair per Action family).

### 14.3 Domain model (`ad-expert` + `backend-engineer`)

HybridRequest / continuation entity; DM-41/42 coupled group, gate step, `cloud_reason`; LicenceSku
inventory; DM-21 `sync_client`, `expected_sync_interval`, `source_anchor_attr`; DM-50 deferred cloud steps
and `usage_location`; DM-33 permissions (`m365.*`, Resume/Cancel); DM-24 EV check list for 2c (EV4 "enabled
write families") and **EV3 not acknowledgeable for an Entra connection**; DM-16 Entra `assignedLicenses`,
`usageLocation`, group flags; DM-80 `hybrid.*` kinds; DM-70 the three Entra datasets (§7.6).

### 14.4 Connector contract

Entra `WriteKind`s (licence, group membership, usage-location update) with `PropertyWrite` and touched-set
rules; retryable not-visible error; ambiguous-outcome signal; targeted re-sync by id and by anchor.

### 14.5 Threat model and security

TM §6.6 row and residual for `User.ReadUpdate.All` breadth; TM-F-HYBRID extended with the wait-window
cases (AC-17…AC-21); **P1 `bug`, `security-sensitive`, `directory-engineer`: add `ms-DS-ConsistencyGuid`
to `guarded-v1` under `map_credential`** (TM §6.9a; it decides which cloud identity an AD object becomes);
lab G3 extended (OQ-F4).

### 14.6 Cross-spec dependencies

**Shared dependency with E2.6: Entra scope roots, m2-plan E-011 "DM-35 Entra roots and
`include_correlated`" / T-1131** (the `entra_tenant`, `administrative_unit` and `group_members` evaluators,
and the reports renderer FB-4). E2.7's FR-30, FR-32, FR-33, FR-38 and the ACs that use those scopes
(AC-24, AC-26, AC-36, AC-43) depend on it. E2.6 cites §7.6 for its datasets and closes its Q6 and FR-B25
against it (an E2.6 edit, not made here). E2.11 is not affected.

### 14.7 Tickets (server board)

`market-analyst`: ADMP M365-at-creation timing and sync-gap behaviour (OQ-F7). `product-designer`: hybrid
flow, wait-state previews, opt-in family wording. The 2c OpenAPI slice. The Entra sandbox bootstrap and
Connect lab (T-0183, T-0075, T-0441, already in the decisions log). Build slices to be cut by
`project-manager`: connection and rotation; Entra sync and datasets; hybrid plan and continuation; cloud
steps; SOA view.

## Sources

Microsoft Learn: [assignLicense](https://learn.microsoft.com/en-us/graph/api/user-assignlicense?view=graph-rest-1.0) · [update user](https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0) · [user resource](https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0) · [create user](https://learn.microsoft.com/en-us/graph/api/user-post-users?view=graph-rest-1.0) · [add group members](https://learn.microsoft.com/en-us/graph/api/group-post-members?view=graph-rest-1.0) · [user delta](https://learn.microsoft.com/en-us/graph/api/user-delta?view=graph-rest-1.0) · [group delta](https://learn.microsoft.com/en-us/graph/api/group-delta?view=graph-rest-1.0) · [throttling](https://learn.microsoft.com/en-us/graph/throttling) · [Entra Connect scheduler](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sync-feature-scheduler) · [Cloud Sync overview](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/what-is-cloud-sync), [how it works](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/concept-how-it-works), [FAQ](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/reference-cloud-sync-faq), [device sync (on-demand provisioning)](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/device-sync) · [group licensing problems](https://learn.microsoft.com/en-us/entra/identity/users/licensing-groups-resolve-problems) · [M365 group licences](https://learn.microsoft.com/en-us/microsoft-365/admin/manage/manage-group-licenses?view=o365-worldwide) · [group source of authority](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-group-source-of-authority-configure) · [designing for eventual consistency](https://devblogs.microsoft.com/identity/designing-for-eventual-consistency-for-microsoft-entra/) · [licenseAssignmentState](https://learn.microsoft.com/en-us/graph/api/resources/licenseassignmentstate) (enum `[UNVERIFIED]`) (group delta: permission from TM §6.6, page not re-read).

Pages read in full 2026-11-11: assignLicense, create user, add members, throttling (round 1); **M365 group licences and user delta (round 2: tenant-location inheritance, no nested-group support, slow processing under load, and "changes to `licenseAssignmentStates` are currently not tracked" in user delta)**. Update user: permission table and `usageLocation` description only; the security review read it in full. Cloud Sync, licensing problems, group SOA, scheduler and group delta claims come from search-result summaries or the threat model, not full reads. Repo research is cited inline; ME behaviour comes only from the ADMP and customer-voice research files and the parity matrix.

## Changelog

- 2026-11-11 · product-manager · first draft for the 2c plan (off-board).
- 2026-11-11 · product-manager · round 2: answers the architecture and security rejects. Default licence path is membership of a licensed group, usage location and direct licensing become opt-in families; Plan-time all-or-nothing checks and `cloud_reason` outcomes (H-B1); bound, time-boxed unattended continuation with approver re-check (A-B1); hard-match hold-and-alert and `ad_ref` rule (A-B2); `AuditLog.Read.All`, certificate rotation, tier-0 at Apply; Entra delta sync and the three Entra datasets (X-1, X-2); ADR-0005 amendment list (§14.1); OQ-F1/F2 closed; ACs now trace to FRs (46).
