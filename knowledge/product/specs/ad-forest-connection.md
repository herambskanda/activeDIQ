---
title: "Spec: AD forest connection — onboarding, rights check, sync health"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: heramb
author: product-manager
prd: none (the E-018 platform PRD is not written; this spec is the contract for checkpoint 2a key S5)
epic: E-018
milestone: M2
parity: [ADM-212, I360-002]
scope: locked
ticket: T-0068
reviewer: solution-architect
---

# Spec: AD forest connection — onboarding, rights check, sync health

> An admin connects an AD forest with a least-privilege identity in a few minutes, activeDIQ
> proves the identity is neither too powerful nor too weak before it activates, and from then on
> the console says plainly how fresh its data is and why it is not, and never calls it "live".

Scope lock: v1 replaces ADManager Plus first (D-0001), the connection is parity row ADM-212 and
AD sync is I360-002 (both `must`, P1 in the [parity matrix](../../business/competitive-analysis/feature-parity-matrix.md)).
The least-privilege half of ENH-08 (verification, not the delegation-plan wizard) is in v1 per
[v1-scope-options](../../business/scoping/v1-scope-options.md) D-0004 row.
Binding sources: [domain model](../../development/domain/domain-model.md) DM-10…DM-15, DM-19;
[threat model](../../development/architecture/threat-model.md) §6.1–6.5, TM-D1, TM-D2, TM-D10, §7.4;
[connector contract](../../development/architecture/connector-contract.md) §4;
[ADR-0002](../../development/decisions/0002-deployment-model.md) rules 3, 7, 8, 9;
[ADR-0005](../../development/decisions/0005-operation-pipeline-and-audit-trail.md) rule 5.

## 1. Problem

Before an admin can search, report or change anything, the product has to be connected to the
directory, and that connection is the most dangerous object it holds: its identity reaches every
account in the forest. ManageEngine's path is "use a Domain Admins account"; the least-privilege
alternative is a manual Delegation-of-Control procedure documented in a PDF, operation by
operation ([ADMP research §2.3](../../business/market-research/manageengine-admanager-plus.md),
[ME permissions guide](https://download.manageengine.com/products/ad-manager/permissions-required-for-the-ad-account-configured-in-admanager-plus.pdf)).
Setup is one of ADMP's praised strengths (25 of 59 sampled reviews mention ease of use or setup;
[customer voice §3](../../business/market-research/manageengine-ad-customer-voice-and-security.md)),
so we must not trade that ease for safety: the safe path has to be as quick as the unsafe one.
Once connected, the research does not show how an admin tells how current the data is
([ADM-212](https://www.manageengine.com/products/ad-manager/help/directory-application-settings/connecting-to-a-domain.html)
describes discovery, DC priority and LDAPS, with no freshness or rights verdict). `[UNVERIFIED]`
for the freshness half until the ME baseline research ticket (§15) lands.

## 2. Personas and jobs to be done

| Persona | Job | Source |
| --- | --- | --- |
| AD admin | When I install activeDIQ, I want to connect my forest with a service identity that is not Domain Admin, so I can find and report on objects today and know the product is not a new Tier-0 path. | Customer voice: delegation without DC access is the main value in 8 of 59 reviews; threat model TM-D1 |
| AD admin | When a sync looks wrong, I want to see which DC, which check, since when and what to do, so I fix the cause and do not guess. | Threat model §6.5; connector contract §4 health |
| Security / SOC analyst | When I review the product before approving it, I want proof the connection holds only delegated rights, and a record of every override. | ADR-0002 rule 9; TM-D1 |
| Compliance auditor | When I cite a report, I want its "as of" time and whether the sync was healthy then. | Blueprint §12 freshness rule |
| IT manager | When I decide whether to trust what the console shows, I want one status per forest (current, behind, stale, paused), not a log. | This spec §8 |
| Help-desk technician | When I look up a user, I want to know if the record may be old. (Reads the freshness label; configures nothing.) | §8 |

## 3. ManageEngine parity

| Parity ID | What ME does (edition) | Source | Our answer |
| --- | --- | --- | --- |
| ADM-212 Domain connection settings | Discovers and prioritises DCs; "DC sort intelligence" picks the fastest; LDAPS; custom LDAP attributes (n/s edition) | [ME help](https://www.manageengine.com/products/ad-manager/help/directory-application-settings/connecting-to-a-domain.html), matrix row | FR-01…FR-04, FR-23, FR-24: DC discovery and priority, always-secure transport (not optional), additional synced attributes |
| I360-002 AD sync via agent | Syncs users, groups and members on a schedule or on demand (Pro, Ent) | [ME help](https://www.manageengine.com/identity-360/help/admin-guide/universal-directory/directory-services-integration/directory-management.html) | FR-25…FR-27: scheduled and on-demand sync. The embedded connector does the work in v1, so there is no agent to install |
| MIG-12 = ENH-08 least-privilege service identity (the matrix cites ADM-135 for it) | ADM-135 is ME's *native AD security roles*, which write ACL-based delegation into AD. Our research documents no verdict on the service account's own rights (absence not confirmed, `[UNVERIFIED]`). Its setup advice is Domain Admin or a manual guide (not a numbered ME feature) | [ADM-135 help](https://www.manageengine.com/products/ad-manager/help/managing_security_roles/pre-defined_security_roles.html), ADMP research §2.3, [matrix enhancement 15](../../business/competitive-analysis/feature-parity-matrix.md) | The verification half only (FR-10…FR-16). The delegation-plan wizard is a separate spec (§15, T-0166) |

Not covered here (parity rows with their own specs): ADM-133 per-OU DC preference (delegation),
ADM-210 HA, ADM-213 diagnostics beyond the connection's own health, ADM-159 M365 tenant (E2.7).

## 4. What we do better

| Claim (measurable) | ME baseline | Target | Proof |
| --- | --- | --- | --- |
| **E1 (v1)** A refused identity names each finding: the object, the right or group, and the fix. | ME recommends Domain Admins and offers a manual PDF ([§1](#1-problem)); a verdict is not documented `[UNVERIFIED]` | Every refusal in §7 carries ≥ 1 finding with object, right and fix. Zero refusals read "insufficient permissions" | AC-14…AC-20 |
| **E2 (v1)** Honest freshness: every directory view says "as of <time>"; the word "live" never describes directory data. | ME baseline `[UNVERIFIED]` (research ticket T-0164) | AC-37, AC-38; checked on every console screen that shows directory data | QA screenshots |
| **E3 (v1)** No surprise full resync: when a DC change forces one, the admin sees it coming with cause and duration estimate. | `[UNVERIFIED]` | AC-34 | QA |
| **E4 (v1)** The safe path is as quick as the unsafe one: forest name → identity reference → first search result. | `[UNVERIFIED]` ME steps and seconds (research ticket T-0164); setup is a praised strength | **Draft budget, to be confirmed by product-designer, T-0165:** ≤ 3 typed inputs (forest or DC name, credential reference, nothing else), ≤ 5 screens, verification ≤ 60 s on a 2-DC lab, first search result ≤ 2 min after clicking Activate on the 5k-object lab | AC-39 |

Cut: a "connection score" number. A score hides the finding; findings are the product.

## 5. UX flows

Patterns come from the design system once T-0043 lands; names here are the intended pattern.

### Flow A — Connect a forest (primary)

| # | Admin does | System shows | Pattern |
| --- | --- | --- | --- |
| 1 | Chooses **Add forest**, completes step-up MFA (TM-D16: connection and credential changes need fresh MFA) | Empty state on the Connections page offers exactly one action: Add forest | Page empty state → wizard |
| 2 | Types the forest DNS name or one DC name | Locator result: forest root resolved, DCs found per site, **forest root GUID and SID** shown as the identity (FR-02). If the name was a child domain: "This is a child domain of `<forest>`. activeDIQ connects whole forests. Continue with `<forest>`?" | Wizard step, inline resolution |
| 3 | Picks the credential. **Windows profile:** the server's gMSA (default). **linux-oci:** the keytab reference | A short "prepare the service account" panel with copy-ready commands for this profile, the account name filled in, and no password in any command (FR-07). The page never accepts a pasted secret | Wizard step |
| 4 | Presses **Verify** | Progress checklist (§7), one row per check with Pass / Warn / Fail / Could not verify, running in order, each with elapsed time | Progress checklist |
| 5 | Reads the result. Pass: a summary of forest, domains (all domain NCs preselected as managed), DCs, rights verdict, capabilities | Primary button **Activate and start first sync**; secondary **Edit**. On refusal: Flow B | Summary card |
| 6 | Presses **Activate** | The connection becomes `active` (if the verification is older than 15 min it re-verifies inline first, FR-17); the first sync starts and the page shows objects synced so far and elapsed time (FR-26). Search works on what has synced, labelled incomplete (FR-29) | Connection page |

### Flow B — A refused connection (over- or under-privileged)

| # | Admin does | System shows |
| --- | --- | --- |
| 1 | Reads the refusal banner | Headline states the blocking reason in one sentence, then a findings table (check, object, right or group, severity, what to do). Example text in §7 |
| 2 | Fixes it in AD (removes a group membership, delegates a read right, fixes the clock) | Nothing changes until they act |
| 3 | Presses **Verify again** | Only checks that failed re-run first; the rest re-run after. Inputs are kept (FR-09) |
| 4 | (Over-privilege only) Chooses **Activate anyway** | Platform-scope permission and step-up required; typed acknowledgement "activeDIQ will be Tier 0 in this forest" (FR-13). Not offered for under-privilege, for "could not verify" or for a failed bind |

### Flow C — Suspend and resume
Connection page → **Suspend** (optional reason) → state `suspended`, banner "Suspended by `<name>` on `<time>` — sync and changes are stopped; data is as of `<time>`". **Resume** re-verifies, then resumes sync. A cursor that is still valid continues; otherwise a resync is scheduled with cause shown.

### Flow D — Read sync health
Connections list shows one status per forest (§8.1). Connection page → **Health** tab: connection checks, DC table, per-domain sync freshness, timeline of the last 30 days. Every row states when it was last checked.

### Flow E — Change the credential
Connection page → **Change credential** (step-up). The new identity is verified against the same forest identity (DM-10.I1); only on a pass is it swapped in. A failure leaves the old credential in use and says so.

### Flow F — Remove a forest
**Remove forest** → impact summary (objects held, report schedules and delegation scopes that use it, operations in flight) → type the forest name → step-up → state `decommissioning`; its data disappears from search and reports at once; the entry becomes `removed` when the purge ends.

### Unhappy paths (all specified in §6–§8)
No permission → page reads a role-trimmed view (FR-30), never an empty error. DC unreachable or slow (> 5 s) → per-DC row with cause; the others carry on. Identity disabled or password changed after activation → `Authentication rejected`. 100k objects → counts, no fake percentage. Empty state (no connections) → one **Add forest** action.

## 6. Lifecycle: every transition has a visible behaviour

States are persisted lifecycle states of DM-10. Health (reachable, degraded, behind) is observed and is **never** a lifecycle state (domain model, lifecycle notation).

| # | Transition | Trigger | What the admin sees | What is recorded | AC |
| --- | --- | --- | --- | --- | --- |
| L1 | — → `draft` | Add forest, first save of name and credential reference | Connection listed as **Draft — not verified**, no data, no sync | Audit `connection.created` (step-up) | AC-01 |
| L2 | `draft → verifying` | **Verify** | Progress checklist (§7). Edit and Remove disabled while it runs | Audit `connection.verification.started` | AC-02 |
| L3 | `verifying → draft` (every verification ends here) | The run ends. A pass sets `verified_at` and the connection shows **Verified — ready to activate** (still `draft`). A blocking check that fails, or Could-not-verify, shows the refusal | Banner and findings (§7). Inputs kept. No sync started, no inventory written | Audit `connection.verification.completed` with verdict, a findings digest and per-finding object GUIDs; a `ConnectionVerification` record (§11) | AC-03, AC-14…AC-20 |
| L4 | `draft → active` | Admin presses **Activate** with a passing verification at most 15 min old (FR-17), or with a Tier-0 override (FR-13). If the verification is older, or there is none, activation runs `draft → verifying → active` inline and proceeds only on a pass | Connections list shows **Active — initial sync running** | Audit `connection.activated`: who, verification id and result, binding, managed domains | AC-04, AC-05 |
| L5 | `active → suspended` | **Suspend** | Banner as Flow C; Search and reports still show data labelled "as of `<last cycle>` — connection suspended"; change actions disabled with reason "Connection suspended". Sync cursor state shows `paused` | Audit `connection.suspended` with reason | AC-06 |
| L6 | `suspended → active` | **Resume** | A re-verification **job** runs while the connection stays `suspended` and shows "Resuming — verifying". On pass, the state becomes `active` and sync resumes. On failure it **stays suspended** with the findings | Audit `connection.resumed` | AC-07, AC-08 |
| L7 | `suspended → decommissioning`, `active → decommissioning` (both direct) | **Remove forest** after typed confirmation | Impact summary; data hidden from search and reports immediately; status **Removing** | Audit `connection.removal.started` with the impact counts | AC-09 |
| L8 | `decommissioning → removed` | Inventory purge and reference clean-up complete | Entry under **Removed forests** with removal time and a link to the audit events. A purge that fails stays `decommissioning` with the error and a **Retry** | Audit `connection.removed`; earlier audit events are retained (X10, DM-10.I5) | AC-10, AC-11 |
| L9 | `draft → discarded` (terminal) | **Discard draft** | Gone from the list and from search. The row is kept but hidden, so audit references still resolve | Audit `connection.draft.discarded` | AC-12 |
| L10 | `draft → active`, blocked | A second connection with the same forest identity (DM-10.I2) is verified or activated | "This forest is already connected as `<name>`" with a link; no second draft | none beyond the refusal | AC-13 |
| L11 | Re-verification of an `active` or `suspended` connection (scheduled, **Check now**, credential change, resume) | Scheduled run, button, or Flow E | A job. The lifecycle state **does not change**; the result moves the derived status (§8.1) and the Health tab | Audit `connection.verification.completed` with the kind | AC-45 |

Lifecycle decisions in this section were taken in the T-0068 review and are recorded in the domain model by T-0168 (OQ-5).

Companion states that users see:

| Entity | Transition | Visible behaviour | AC |
| --- | --- | --- | --- |
| DM-19 SyncCursor | `initial_sync → incremental` | Domain shows **Current** with "as of" time | AC-33 |
| DM-19 | `incremental → resync_required` | Cause line (§8.3), warning on affected search results about deletions (FR-28), resync starts on its own unless the cause needs the admin | AC-34, AC-35 |
| DM-19 | `resync_required → incremental` | Cause cleared, timeline entry | AC-35 |
| DM-19 | `→ paused` (connection suspended) | **Paused (suspended)**; never "Behind" | AC-06 |
| DM-11 credential | `pending → active`, `active → rotated` (Change credential), `→ revoked` (Remove) | Credential card shows kind, principal name, state, **no secret value ever** (DM-11.I1) | AC-21, AC-22 |
| DM-13 binding | `embedded` binding exists while `active` (DM-10.I3) | Read-only line "Served by: embedded connector". Remote connectors are out of scope (§14) | AC-04 |

## 7. Onboarding verification and refusals

Checks run in this order. Each ends **Pass**, **Warn** (shown, does not block), **Fail** (blocks) or **Could not verify** (blocks when marked ◆: the answer decides a security verdict, so it fails closed). The check technique belongs to T-0053 and the connector contract; this spec fixes what the admin sees and when the connection may activate.

| # | Check | Blocks activation? | Notes |
| --- | --- | --- | --- |
| V1 | **Locate.** The DC locator by SRV record and an LDAP ping, plus an anonymous rootDSE read per DC ([DC locator](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/dc-locator), [rootDSE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/96f7b086-1ca3-4764-9a08-33f8f7a543db)) | Fail if no DC answers | SRV records are a hint; the DC list is rebuilt from the configuration NC in V6 |
| V2 | **Clock.** Skew from rootDSE `currentTime` against the server clock at the round-trip midpoint | Fail ≥ 4 min; Warn ≥ 1 min | Kerberos tolerates 5 min by default ([policy](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/maximum-tolerance-for-computer-clock-synchronization)); the configured tolerance may differ and is `[UNVERIFIED]` readable. Works before Kerberos does |
| V3 | **Transport.** TLS (LDAPS or StartTLS) with full certificate validation | Fail | No "ignore certificate" option exists. An untrusted chain shows the chain and the fix (FR-05) |
| V4 | **Authenticate.** Kerberos only, signed and sealed or TLS with a channel-binding token, never NTLM (TM-D10, DM-10.I4) | Fail | The failure names the DC and the LDAP result (§7.2). It does not weaken the bind to find out why |
| V5 | **Identity.** Forest root domain NC GUID from the root crossRef `nCName` (extended DN), cross-checked with the root domain SID (DM-10 key attributes) | Fail on mismatch or duplicate (L10) | Identity comes from the GUIDs, never from the typed name |
| V6 | **Topology.** Domains (crossRefs with `systemFlags` bits 0x1 and 0x2, `Enabled` not FALSE), DCs (`nTDSDSA`: GC, RODC, site, `dsa_guid`, `invocation_id`), forest deletion settings read, never assumed (DM-10.I6; [crossRef](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8877f323-90ec-4460-9ae9-c3dfb6be2e61)) | Fail if the configuration NC is unreadable | A DC in the configuration NC that does not answer is listed with its error, never dropped (connector contract §4) |
| V7 | **Over-privilege ◆** TM §6.5 steps 1–3 and 5: membership of the Tier-0 set (C1, C13 and designated groups), write or control rights on any `tier0` object, delegation configuration of the identity itself | Fail (overridable, FR-13) | **Forest-wide:** membership and rights are evaluated across every domain of the forest, including universal and enterprise Tier-0 groups (Enterprise Admins, Schema Admins) held in another domain, and foreign-security-principal edges. If a domain or global catalog needed for the answer cannot be reached, the result is Could not verify, never a pass. Evaluated from the directory at check time (TM §6.5), never from the process's own Kerberos ticket or token, which can miss a recent change ([ad-expert consult](#sources)). The technique belongs to T-0053 |
| V8 | **Read sufficiency.** The identity can read what v1 features need: R1 and R2 of TM §6.3 on every domain NC it will manage, and a change-feed prime succeeds | Fail (not overridable) | Under-privilege |
| V9 | **Excess in managed OUs.** TM §6.5 step 4: GenericAll, GenericWrite, WRITE_DAC, WRITE_OWNER, Delete-Tree, never-delegate list | Warn, with fix | Blocks only when it lands on a `tier0` object, which V7 already catches |

### 7.1 The capability panel
After V8 the page lists what activeDIQ **can** and **cannot** do in this forest, per feature family shipped in the running build: read and report, change tracking, and each write family once it ships. A write family shows `Rights present`, `Rights missing` with the exact list, or `Excess rights` with the list. Rows are information, not buttons. Families that are not in the build do not appear, so the page never pre-announces. Missing write rights never block activation: the family stays off until its rights verify.

### 7.2 Refusal and failure messages

Messages are specified so that QA can assert the text pattern. `<…>` is data. Every message ends with a next action and none contains a secret.

| ID | When | Headline (verbatim pattern) | Findings and fix |
| --- | --- | --- | --- |
| M-OVER-1 | V7: member of a Tier-0 group, directly or nested | **Not activated: `<identity>` can administer your forest.** It is a member of `<group>` (through `<path>`). activeDIQ is built never to hold these rights. | Group, path from identity to group, "Remove `<identity>` from `<group>`, then Verify again." |
| M-OVER-2 | V7: write or control right on a Tier-0 object | **Not activated: `<identity>` can change `<object>`.** | Object, the right found (write property, create child, write DACL…), where it is inherited from when known, fix |
| M-OVER-3 | V7: delegation configured on the identity | **Not activated: `<identity>` is trusted for delegation.** | Which setting (constrained delegation target, unconstrained, resource-based), fix |
| M-OVER-4 | Override active | Permanent banner on every page of the connection: **activeDIQ is Tier 0 in this forest.** `<who>` acknowledged `<n>` findings on `<date>`. | Links to the findings and **Verify again** |
| M-UNDER-1 | V8: a domain NC cannot be read | **Not activated: `<identity>` cannot read `<domain>`.** activeDIQ needs read access to manage it. | Domain, what failed (bind, search, attribute), "Grant read access or untick this domain and verify again." |
| M-UNDER-2 | V8: change feed prime fails | **Not activated: change tracking does not work for `<domain>`.** | The DC, the LDAP result, whether it is rights or a DC condition |
| M-UNDER-3 | Read denied for a required attribute set | **`<identity>` cannot read `<attribute set>`**; the features that need it are off. (Warn, not a refusal, for non-core sets) | List per attribute set |
| M-NOVERIFY | V7 ◆ cannot be decided | **Not activated: activeDIQ could not verify `<n>` objects.** Without proof the identity is not over-privileged we do not activate. | Per object: not readable, domain unreachable, or ACL not returned, and what grants the read |
| M-BIND-SIGN | DC rejects the bind: signing required (LDAP result 8, [signing](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server)) | **`<DC>` rejected the connection: strong authentication required.** | The DC; "We always sign. If this persists, check the account and the Kerberos setup." We cannot read which DC setting is in force (it is a DC registry value) and do not retry weaker |
| M-BIND-CBT | DC rejects: channel binding (result 49, data `80090346`, secondary sources) | **`<DC>` rejected the channel-binding token.** | The DC and the likely causes (certificate or load balancer terminating TLS) |
| M-AUTH | KDC refuses the identity (`KDC_ERR_PREAUTH_FAILED` 0x18, or no password available for the gMSA) | **The domain controller rejected the identity.** Profile-specific cause line: **keytab (linux-oci, or another forest):** the keytab does not match the account's current password, or the account is disabled, locked or expired. **gMSA (windows):** the account is disabled, this host is not in the account's `PrincipalsAllowedToRetrieveManagedPassword`, or the forest has no KDS root key. | **keytab:** check the account state first, then regenerate the keytab. **gMSA:** check the account is enabled, add this host to the allowed principals, confirm a KDS root key exists. The KDC gives the same error for the keytab cases ([event 4771](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771)); the gMSA causes are `[UNVERIFIED — lab]` until T-0123/T-0124 |
| M-TLS | V3 chain untrusted or name mismatch | **Certificate from `<DC>` is not trusted.** | Chain shown with issuer; "Add the issuing CA to the activeDIQ trust store" (FR-05) |
| M-SKEW | V2 | **Clock differs from `<DC>` by `<n>` minutes.** Kerberos fails above 5 minutes by default. | Fix time sync on the activeDIQ host |
| M-NODC | V1 | **No domain controller answered for `<name>`.** | Per name tried: DNS result, port, error, last attempt time |

## 8. Sync health and freshness

### 8.1 Rules
1. **Data as of.** For each domain, `data_as_of` is the commit time of the last sync cycle that completed (DM-19.I1). It is not the time of the last change. A directory with no changes has a fresh `data_as_of` and an old "last change seen".
2. **Never "live".** The words "live" and "real-time" never describe directory data in any activeDIQ screen, report header or export. A re-read from a DC at Plan time is described as "re-read from `<DC>` at `<time>`". (Blueprint §12: "a report says how fresh its data is, never live when it is not.")
3. **Freshness label** from age = now − `data_as_of`, with the sync interval *I* (default 5 min, FR-25):

   | Label | Rule | Meaning |
   | --- | --- | --- |
   | **Current** | age ≤ 2·*I* | Normal; there may still be changes not yet read |
   | **Behind** | 2·*I* < age ≤ 12·*I* | A cycle was missed or is slow; data is older than expected |
   | **Stale** | age > 12·*I*, or sync failing > 1 h | Do not trust for decisions; a banner appears on search and reports |
   | **Initial sync** | no complete cycle yet | Results are incomplete (FR-29) |
   | **Resync needed** | `resync_required` | Data is as of the last cycle; deletions made since may still show (DM-19.I3) |
   | **Paused** | connection suspended | Data is frozen on purpose |

   *I* and these multipliers are product defaults pending the T-0065 latency budget (OQ-6).
4. **Connection status** (one word per forest on the list): **Healthy** (all checks pass, all domains Current), **Degraded** (some DC down, or Behind, or Warn findings), **Needs attention** (Stale, a failed check, over-privilege, authentication rejected), **Unavailable** (no DC reachable), **Suspended**, **Draft**, **Removing**. The status is a derived label, not a lifecycle state, and it lists the worst cause beside it.
5. Each check and each DC row shows when it was last checked. A health value is greyed with "not checked since `<time>`", never shown as still passing, when it is older than **2× its own schedule**: connectivity, clock and per-DC rows 2× the sync interval *I*; rights checks (V7–V9) 2× 24 h (or 2× the tenant's shorter setting). A rights row from 3 hours ago is therefore not greyed.

### 8.2 The Health tab
- **Connection checks:** V1–V5 and V7–V8 results from the latest run, with next scheduled run. Rights checks (V7, V8, V9) run at least every 24 h, after every credential change and on **Check now**; the 24 h is a ceiling a tenant can shorten, never lengthen. Connectivity and clock checks run every cycle.
- **DC table:** per DC, its site, GC/RODC, reachable, last seen, clock skew, `invocation_id` change flag, and the last error. Admin actions: **Exclude** and **Priority** (FR-04). An RODC is listed and is never a write target (DM-15.I2).
- **Per-domain sync:** state (DM-19), `data_as_of`, last change seen, last full sync, objects held, and the issuing DC for the cookie.
- **Timeline:** state and verdict changes for the last 30 days (FR-31).
- **Credential card:** kind, principal, state, and the last time the credential authenticated.

### 8.3 Failure and resync causes

Each cause has: what the admin reads, what activeDIQ does by itself, what the admin can do, and the effect on the data.

| ID | Cause | Admin reads | activeDIQ does | Admin can | Data effect |
| --- | --- | --- | --- | --- | --- |
| H1 | One DC unreachable | **Degraded.** `<DC>` unreachable since `<time>`: `<cause>` | Uses another DC. If `<DC>` is the cookie's issuing DC, waits for the grace period (default 15 min) before switching and resyncing (DM-19.I4) | Exclude the DC | None while the grace holds; then see H3 |
| H2 | All DCs unreachable | **Unavailable.** Per DC cause and last attempt | Retries with backoff; sync and any change are refused with "no domain controller reachable" | Fix network, DNS or firewall | Data kept, labelled with its age; label moves Behind → Stale |
| H3 | DC changed under the cookie (DM-19.I4) | **Resync needed:** the sync moved from `<DC1>` to `<DC2>`. A full resync will run at `<time>`, about `<estimate>` (last full sync: `<duration>`) | Runs the resync, reconciling forest-wide by GUID so missed deletions are caught (DM-19.I3) | **Resync now**, or wait | As of last cycle until done |
| H4 | `invocation_id` changed (DC restored or cloned: VM-GenerationID) | **Resync needed:** `<DC>` was restored or reset | As H3. Cursor keyed on `(dsa_guid, invocation_id)` is discarded (DM-15.I5) | — | As H3 |
| H5 | `highestCommittedUSN` below the stored value with the same `invocation_id` (USN rollback, [guidance](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/detect-and-recover-from-usn-rollback)) | **Needs attention.** `<DC>` is in an unsupported state; activeDIQ will not read from it | Excludes it from use, resyncs from another DC | Fix the DC | As H3 |
| H6 | Cookie rejected (`0000203D`) | **Resync needed:** the DC rejected our position | Full resync | — | As H3 |
| H7 | Authentication rejected after activation | **Needs attention.** M-AUTH text | Retries at the next cycle with backoff, stops hammering after 5 failures to avoid locking the account | Fix the account or keytab, **Check now** | As of last cycle; Stale after 12·*I* |
| H8 | TLS certificate changed or untrusted | M-TLS | Retries; other DCs carry on | Trust the CA | As above |
| H9 | Clock skew over tolerance | M-SKEW | Retries | Fix time | As above |
| H10 | Rights drift: identity became over-privileged (V7) | **Needs attention: `<identity>` now has Tier-0 rights.** M-OVER text | Reads and sync continue; **changes are blocked** until V7 passes (fail closed). Audit `connection.rights.verdict_changed` | Remove the rights, or suspend | None on reads |
| H11 | Rights drift: read lost on a domain | M-UNDER-1 | That domain's sync fails (H7 pattern) and shows its own cause | Fix rights | That domain only |
| H12 | A domain NC disappears from the configuration NC | **Domain `<name>` was removed from the forest.** | Marks the NC `gone` (DM-14), keeps its objects until the admin confirms | Confirm removal, or investigate | Its objects flagged |
| H13 | Schema changed (fingerprint) | Info line in the timeline | Re-reads the schema, then continues | — | None |
| H14 | Forest deletion settings changed (Recycle Bin, tombstone lifetime) | Info line | Re-reads (DM-10.I6) | — | None |

### 8.4 Required readings of a cycle
`data_as_of`, `last_change_at`, objects read, objects changed, DC used, duration, and result (complete, partial with the domain that failed, failed with the cause). A **partial** cycle never moves `data_as_of` of the domain that failed.

## 9. Functional requirements

| ID | Requirement | Parity / enhancement |
| --- | --- | --- |
| FR-01 | The system MUST create an AD forest connection from a forest DNS name **or** one DC name, resolve the forest, and display forest root GUID and SID as the connection's identity. | ADM-212 |
| FR-02 | The system MUST fix `directory_identity` at first verification and refuse any later credential change that resolves to a different forest (DM-10.I1), and refuse a second connection to the same forest (DM-10.I2), however the name was typed. | ADM-212 |
| FR-03 | The system MUST discover all domains and DCs from the configuration NC, show each DC's site, GC and RODC flags, and list DCs that do not answer with their error. It MUST NOT drop any silently. | ADM-212 |
| FR-04 | The system MUST pick DCs automatically (same site first, healthy, lowest latency) and MUST let an admin **exclude** a DC and set **priority** order. Writes pin one DC per naming context for an operation (ADR-0005 rule 5). The admin's DC choices are audited. | ADM-212 |
| FR-05 | The system MUST validate every DC certificate and MUST NOT offer any option to skip validation. It MUST let an admin with the connection permission add a CA certificate to a tenant trust store (step-up, audited, public certificate only). | ADM-212, DM-10.I4 |
| FR-06 | The system MUST authenticate with Kerberos only, MUST sign and seal or use TLS with a channel-binding token on every bind, and MUST NOT fall back to NTLM or a weaker bind for any reason, including to diagnose a failure (DM-10.I4, TM-D10). | ADM-212, enhancement (ENH-08 posture) |
| FR-07 | The credential step MUST offer: on `windows`, the server's gMSA; on `linux-oci`, an AES-only keytab by file reference. It MUST NOT accept a secret value through the console or API (DM-11.I1, I2). It SHOULD show copy-ready commands to prepare the account for the chosen profile, with no secret in them and tested on the lab. | ADM-212, ENH-08 |
| FR-08 | The credential record MUST show kind, principal, state and last successful use. It MUST NOT show or return any secret, key bytes or keytab content. | DM-11.I1 |
| FR-09 | **Verify** MUST run V1–V9 in order and show progress per check. A failed run MUST leave the inputs, write no inventory and start no sync, and a re-run MUST keep inputs. | ADM-212 |
| FR-10 | V7 MUST refuse activation if the identity is, transitively, a member of any Tier-0 group, holds a write or control right on any `tier0` object, or has delegation configured (TM-D1, TM-F-RIGHTS). Membership MUST be evaluated at check time and forest-wide, including universal and enterprise Tier-0 groups held in another domain, foreign-security-principal edges, and groups with more than 1,500 members. If a domain or global catalog needed to decide cannot be reached, the result MUST be Could not verify (FR-11), never a pass. | enhancement (ENH-08) |
| FR-11 | V7 MUST distinguish "no rights" from "could not compute". An absent or empty answer MUST be accepted as "no rights" only when a control in the same session proves that the directory computes that answer; otherwise the result is Could not verify, which blocks activation. | enhancement |
| FR-12 | V8 MUST refuse activation if the identity cannot read the R1 and R2 set (TM §6.3) on a domain the admin intends to manage, and MUST NOT allow an override for it. | ADM-212 |
| FR-13 | An admin with the platform-scope Tier-0-override permission MAY activate despite V7 findings after step-up and a typed acknowledgement. The override records the fingerprints of the findings shown (§11); a *new* finding is any fingerprint not in that set, and needs a new acknowledgement. It MUST NOT apply to V8, to Could not verify, or to a failed bind. | TM-D1 |
| FR-14 | While an override is in force the console MUST show on every page of that connection "activeDIQ is Tier 0 in this forest", and Health MUST show the same. The banner MUST clear only when a verification passes with no V7 findings. | TM-D1 |
| FR-15 | Every refusal and failure MUST use a message from §7.2 with its findings, each naming the object, the right or group and the fix. A message MUST NOT contain a secret and MUST NOT read only "insufficient permissions". | enhancement (E1) |
| FR-16 | Detailed findings (they enumerate Tier-0 exposure) MUST need the verify permission to view. Other viewers see the verdict and the count only. | security |
| FR-17 | Activation MUST require a passing verification at most 15 minutes old; otherwise it MUST run `draft → verifying → active` inline and proceed only on a pass. Every verification MUST end in `draft` (a pass records `verified_at`). Re-verification of an `active` or `suspended` connection MUST be a job and MUST NOT change the lifecycle state (L11). | DM-10 |
| FR-18 | `suspended` MUST stop sync and changes immediately for unclaimed work, let claimed steps finish or fail per ADR-0005, and show Suspending until they drain. | DM-10 |
| FR-19 | **Resume** MUST re-verify as a job while the connection stays `suspended`, and MUST stay suspended with findings if any blocking check fails. | DM-10 |
| FR-20 | **Remove** (from `active` or `suspended`) MUST show an impact summary, require the typed forest name and step-up, hide the connection's data from search and reports at once, and end in `removed` only after purge. It MUST NOT delete audit events (DM-10.I5). A failed purge MUST stay visible with **Retry**. | DM-10 |
| FR-21 | **Change credential** MUST verify the new identity against the same forest identity and swap atomically only on pass; a failure MUST keep the old credential and say so. | DM-11 |
| FR-22 | The connection MUST be editable only through audited settings changes: display name, managed domains, DC choices, sync interval, extra attributes, trust store. Each is an audit event with before and after. | ADM-212 |
| FR-23 | The system SHOULD let an admin add attributes to the synced set from a schema-aware picker, MUST refuse attributes the schema marks secret (`SECRET_ATTRIBUTE`, connector contract §4) with the reason, and MUST state the effect on sync volume. | ADM-212 (custom LDAP attributes) |
| FR-24 | The managed set of domains MUST default to all discovered domain NCs the identity can read, and the admin MAY untick any (DM-14.I1). Configuration and schema NCs are never offered. | ADM-212 |
| FR-25 | Sync MUST run on a schedule (default every 5 minutes, adjustable 1–60 minutes) and on demand via **Sync now**. At most one cycle per domain runs at a time, and the button shows the running state. | I360-002 |
| FR-26 | During initial sync the page MUST show objects synced so far and elapsed time, and MUST NOT show a percentage unless it has a basis. | I360-002 |
| FR-27 | An admin with the sync permission MUST be able to request a full resync with a confirmation stating the last full sync's duration. | I360-002 |
| FR-28 | When a domain is Resync needed, any search or report that includes it MUST carry "deletions made since `<time>` may still appear". | DM-19.I3, E2 |
| FR-29 | While a domain has no complete cycle, any search or report that includes it MUST carry "incomplete: initial sync running" in the UI **and** in any export. | E2 |
| FR-30 | A viewer without the connection permission MUST see the connection's name, status and `data_as_of`, and nothing else. | security |
| FR-31 | The Health tab SHOULD keep a 30-day timeline of status, verdict and resync-cause changes. | enhancement |
| FR-32 | Freshness MUST be computed per §8.1 and shown as an explicit "as of" time wherever directory data appears. The words "live" and "real-time" MUST NOT describe directory data. | E2 |
| FR-33 | After 5 consecutive authentication failures the system MUST stop retrying until the next scheduled check or **Check now**, so it cannot lock the identity's account. | security |
| FR-34 | When the cookie's issuing DC is lost, the system MUST wait for the grace period (default 15 minutes) before switching and, when a resync is forced, MUST show the cause, scheduled time and duration estimate beforehand. | E3 |
| FR-35 | The system MUST block change operations while V7 fails on an active connection and MUST keep reading and syncing. | TM-D1, TM-D2 |
| FR-36 | **Discard draft** MUST end the connection in the terminal state `discarded`: hidden from every list and search, never reactivated, with its row kept so audit references resolve. It MUST be offered only from `draft`. | DM-10 |

## 10. Platform matrix

Columns: **windows** and **linux-oci** are the v1 deployment profiles (ADR-0002); **saas** is composed and CI-tested but not shipped; **DC 2016–19** and **DC 2022–25** are managed DCs (WS2016–WS2025 supported, ADR-0002 rule 8; WS2012 R2 is not); **Samba** is the CI lab, an oracle for most checks and not a customer target; Entra and hybrid are out of scope here.
`✓` full · `◐` partial · `✗` not delivered (reason, ticket) · `n/a` not applicable.

Legend for recurring cells: **S** = `✗ not shipped in v1 (ADR-0002); AD credentials stay on a remote connector (DM-11.I2) → T-0167`; **E** = `n/a: Entra tenants are E2.7`; **H** = `n/a: HybridLink is a separate spec`; **P** = `n/a: PowerShell module is M3 (FD-07)`; **W** = `◐ proven on Windows lab only (T-0051, T-0156); Samba can false-pass`.

| FR | windows | linux-oci | saas | DC 2016–19 | DC 2022–25 | Samba | Entra | Hybrid | Console | REST API | PS module |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| FR-01 | ✓ | ✓ | S | ✓ | ✓ | ✓ | E | H | ✓ | ✓ | P |
| FR-02 | ✓ | ✓ | S | ✓ | ✓ | ✓ | E | H | ✓ | ✓ | P |
| FR-03 | ✓ | ✓ | S | ✓ | ✓ | ◐ child-domain support in Samba `[UNVERIFIED]` (m2-plan decision 11) | E | H | ✓ | ✓ | P |
| FR-04 | ✓ | ✓ | S | ✓ | ✓ | ◐ 2-DC tier (T-0049) | E | H | ✓ | ✓ | P |
| FR-05 | ✓ | ✓ | S | ✓ | ✓ | ✓ | E | H | ✓ | ✓ | P |
| FR-06 | ✓ | ✓ | S | ✓ | ✓ enforced by default on new WS2025 forests | ✓ | E | H | n/a | n/a | P |
| FR-07 | ✓ gMSA for the host's forest. ◐ other forests need keytab (OQ-3) | ✓ keytab. ✗ gMSA retrieval `[LAB]` → OQ-4 | S | ✓ | ✓ | ✓ keytab | E | H | ✓ | ✓ | P |
| FR-08 | ✓ | ✓ | S | n/a | n/a | n/a | E | H | ✓ | ✓ | P |
| FR-09 | ✓ | ✓ | S | ✓ | ✓ | ◐ see FR-10, 11 | E | H | ✓ | ✓ | P |
| FR-10 | ✓ | ✓ | S | W (child-domain case: no lab has one, `[LAB-GAP]` → AC-47) | W (same) | ◐ constructed attributes behave the same in source, runtime `[LAB]`; single domain, cross-domain membership untestable | E | H | ✓ | ✓ | P |
| FR-11 | ✓ | ✓ | S | W | W | W | E | H | ✓ | ✓ | P |
| FR-12 | ✓ | ✓ | S | ✓ | ✓ | ✓ | E | H | ✓ | ✓ | P |
| FR-13 | ✓ | ✓ | S | ✓ | ✓ | ✓ | E | H | ✓ | ✓ | P |
| FR-14 | ✓ | ✓ | S | n/a | n/a | n/a | E | H | ✓ | ✓ | P |
| FR-15 | ✓ | ✓ | S | ✓ | ✓ | ✓ | E | H | ✓ | ✓ | P |
| FR-16 | ✓ | ✓ | S | n/a | n/a | n/a | E | H | ✓ | ✓ | P |
| FR-17 | ✓ | ✓ | S | n/a | n/a | n/a | E | H | ✓ | ✓ | P |
| FR-18 | ✓ | ✓ | S | n/a | n/a | n/a | E | H | ✓ | ✓ | P |
| FR-19 | ✓ | ✓ | S | ✓ | ✓ | ✓ | E | H | ✓ | ✓ | P |
| FR-20 | ✓ | ✓ | S | n/a | n/a | n/a | E | H | ✓ | ✓ | P |
| FR-21 | ✓ | ✓ | S | ✓ | ✓ | ✓ | E | H | ✓ | ✓ | P |
| FR-22 | ✓ | ✓ | S | n/a | n/a | n/a | E | H | ✓ | ✓ | P |
| FR-23 | ✓ | ✓ | S | ✓ | ✓ | ✓ | E | H | ✓ | ✓ | P |
| FR-24 | ✓ | ✓ | S | ✓ | ✓ | ◐ single-domain lab; T-0120 adds two forests, not a child domain | E | H | ✓ | ✓ | P |
| FR-25 | ✓ | ✓ | S | ✓ | ✓ | ✓ | E | H | ✓ | ✓ | P |
| FR-26 | ✓ | ✓ | S | ✓ | ✓ | ✓ | E | H | ✓ | ✓ | P |
| FR-27 | ✓ | ✓ | S | ✓ | ✓ | ✓ | E | H | ✓ | ✓ | P |
| FR-28 | ✓ | ✓ | S | n/a | n/a | n/a | E | H | ✓ | ✓ | P |
| FR-29 | ✓ | ✓ | S | n/a | n/a | n/a | E | H | ✓ | ✓ | P |
| FR-30 | ✓ | ✓ | S | n/a | n/a | n/a | E | H | ✓ | ✓ | P |
| FR-31 | ✓ | ✓ | S | n/a | n/a | n/a | E | H | ✓ | ✓ | P |
| FR-32 | ✓ | ✓ | S | n/a | n/a | n/a | E | H | ✓ | ✓ | P |
| FR-33 | ✓ | ✓ | S | ✓ | ✓ | ✓ | E | H | n/a | n/a | P |
| FR-34 | ✓ | ✓ | S | W: restore and USN-rollback causes (H4, H5) need Windows DCs | W | ◐ H3, H6 only | E | H | ✓ | ✓ | P |
| FR-35 | ✓ | ✓ | S | ✓ | ✓ | ✓ | E | H | ✓ | ✓ | P |
| FR-36 | ✓ | ✓ | S | n/a | n/a | n/a | E | H | ✓ | ✓ | P |

Windows-profile gaps (gMSA source T-0124, SSPI adapter T-0123, service host T-0126) close before M2 exit, not at checkpoint 2a (m2-plan decision 9). Until then the 2a demo runs on `linux-oci`, and every `windows` ✓ above is "specified, not yet demonstrable".

## 11. Data and API impact

- **Directory read:** rootDSE (`rootDomainNamingContext`, `configurationNamingContext`, `dsServiceName`, `currentTime`, `forestFunctionality`, `highestCommittedUSN`, `isGlobalCatalogReady`); `CN=Partitions` crossRefs (`nCName` as extended DN, `systemFlags`, `Enabled`); `nTDSDSA` and server objects; for V7 `tokenGroups` or `member` + `primaryGroupID`, `allowedAttributesEffective`, `allowedChildClassesEffective`, `sDRightsEffective`, `nTSecurityDescriptor` (DACL, SD-flags control, never SACL); on the identity `msDS-AllowedToDelegateTo`, `userAccountControl` delegation bits and DC RBCD attributes. **Constructed attributes are requested explicitly and from a DC of the object's domain on 389/636, never the Global Catalog** ([allowedAttributesEffective](https://learn.microsoft.com/en-us/windows/win32/adschema/a-allowedattributeseffective)). **Nothing is written to the directory.**
- **Persisted (existing):** DM-10 Connection (lifecycle amended: every verification ends in `draft`; `draft → discarded` terminal and hidden; `active → decommissioning` direct), DM-11 credential metadata, DM-13 binding, DM-14, DM-15, DM-19.
- **Persisted (new, decided in the T-0068 review, recorded by T-0168):**
  - **`ConnectionVerification`**, append-only: one row per run with kind (onboarding, resume, credential_change, scheduled, manual), start and end, verdict (pass, refused, could_not_verify, failed), and **Finding** rows `{check V1…V9, object GUID, right or group GUID, code, severity, fingerprint}`. It stores GUIDs, SIDs and codes only; display names are resolved at read time, so X11 needs nothing extra. Retention is a tenant record class defaulting to audit retention; `security-architect` confirms the access restriction and retention in its review.
  - **`Tier0Override`** `{acknowledged_by, at, acknowledged finding fingerprints, cleared_at, cleared_by_verification}`. A *new finding* is the set difference of fingerprints. It is not a column on DM-10.
  - **Health and cycle history:** a 30-day rolling window (FR-31).
  - A tenant **trust store** for CA certificates, and the health fields per cycle (§8.4).
- **Audit events (DM-80):** `connection.created`, `.verification.started`, `.verification.completed` (verdict, findings digest), `.activated`, `.suspended`, `.resumed`, `.credential.changed`, `.settings.changed`, `.tier0_override.acknowledged`, `.tier0_override.cleared`, `.rights.verdict_changed`, `.resync.requested`, `.removal.started`, `.removed`, `.draft.discarded`, `trust_store.changed`. Personal display values follow X11.
- **API (for T-0069):** create/edit/discard draft; verify (job, polled); activate; suspend; resume; credential change; remove; sync now; full resync; list and get connections with status and `data_as_of`; health (checks, DCs, per-domain sync, timeline); findings (restricted); DC exclude and priority; trust store. Verification and resync are jobs, not requests.
- **Scale:** verification cost is bounded by the Tier-0 set and the managed OU count, not directory size. A forest of 100k objects and a Domain Admins group of more than 1,500 members are both in the acceptance set.

## 12. Security considerations

- **Privileges the identity needs (TM §6.3):** read set R1 and R2 only for checkpoint 2a. No Get-Changes or Get-Changes-All (DCSync), no write rights. Write families add their own rights when they ship, each a security-architect trigger (TM §14, RT-4).
- **Tier-0 impact:** the connection is where the product could become Tier 0. V7 refuses that by default, the override is audited and visible forever, and TM-D2's connector-side guard still refuses writes to `tier0` objects even when the override is on.
- **Safe primitives:** DNs, filters and SD reads built with the typed primitives only (rule 5); the forest name typed by the admin is parsed as a DNS name, never concatenated into a filter or DN.
- **Credentials:** gMSA and keytab hold no secret in the database (DM-11.I2). The keytab path is a reference on the server host and MUST be readable only by the service identity. Nothing returns a secret (TM-TB2).
- **Abuse cases:** (1) an admin points the server at an attacker host to coerce authentication: targets come from the discovered DC list and the typed name goes only to DNS and the locator; no NTLM exists to coerce (TM-D10). (2) A findings view is reconnaissance: restricted by FR-16. (3) A malicious or confused admin loops failed binds to lock the account: FR-33. (4) Override abuse: step-up, platform scope, typed acknowledgement, permanent banner, audit.
- **Our own audit trail** records every state change and setting change in §11 with who, when, before and after.
- **`security-sensitive`:** yes. Build tickets T-0093, T-0119, T-0053 and T-0080 carry the tag. `security-architect` should read §7, FR-11, FR-13, FR-16 and OQ-2.

## 13. Acceptance criteria

Lab tiers: **S** Samba single DC, **2dc** two DCs (T-0049), **MF** two forests (T-0120), **W** Windows lab (T-0051, T-0123).

```
AC-01  (L1)
Given an admin with the connection permission and fresh MFA
When they add a forest by DNS name
Then a connection is listed as "Draft — not verified" with no objects and no sync, and an audit event connection.created exists with their identity
Evidence: API response and console screenshot of the list; audit query (S)

AC-02  (L2)
Given a draft
When Verify is pressed
Then the checklist shows V1…V9 in order, each with a state and elapsed time, and Edit and Remove are disabled until it ends
Evidence: console recording of the run; the disabled controls (S)

AC-03  (L3)
Given a verification with one failing blocking check
When it ends
Then the connection is back to draft, inputs are kept, zero inventory rows exist for it, no sync cursor exists, and the findings are shown
Evidence: SQL count of inventory and cursor rows = 0; screenshot (S)

AC-04  (L4, DM-13)
Given a passing verification
When Activate is pressed
Then the state is active, exactly one embedded binding is shown read-only, the first sync starts, and an audit event connection.activated records who, the verification result and the managed domains
Evidence: API get-connection; audit event; screenshot (S)

AC-05  (L4, FR-17)
Given a verification that passed 20 minutes ago
When Activate is pressed
Then the state goes draft → verifying → active, verification re-runs inline first, and activation proceeds only if it passes again; if it fails the state is draft with the findings
Evidence: audit shows two verification.completed events before activated; state sequence in the API (S)

AC-06  (L5, DM-19 paused)
Given an active connection with a running sync
When Suspend is pressed
Then no new cycle starts, the cursor shows paused, the banner names who and when, a search for a known user returns it labelled "as of <time> — connection suspended", and any change action is disabled with the reason
Evidence: screenshots; cursor state in API (S)

AC-07  (L6)
Given a suspended connection whose identity is still valid
When Resume is pressed
Then re-verification runs, the connection is active, and sync resumes from the cursor when valid or schedules a resync with its cause shown
Evidence: audit connection.resumed; health timeline (S)

AC-08  (L6)
Given a suspended connection whose identity was added to Domain Admins meanwhile
When Resume is pressed
Then it stays suspended and shows M-OVER-1 with the group and path
Evidence: screenshot of the message; state in API (S, W)

AC-09  (L7)
Given an active connection with two report schedules and 5,000 objects
When Remove is pressed
Then the impact summary lists 5,000 objects and two schedules, the typed forest name and step-up are required, the state is decommissioning, and a search no longer returns its objects
Evidence: screenshot; search API returns none (S)

AC-10  (L8)
Given a decommissioning connection
When the purge ends
Then the state is removed, the entry appears under Removed forests, and every earlier audit event for it is still readable
Evidence: audit query before and after; count unchanged (S)

AC-11  (L8)
Given a purge that fails
Then the state stays decommissioning, the error and a Retry are shown, and Retry completes it
Evidence: fault injection on the purge job; screenshots (S)

AC-12  (L9)
Given a draft
When Discard draft is pressed
Then its state is discarded, it disappears from the list and from search, the row is still resolvable from an audit event reference, and an audit event records the discard; Discard is not offered on an active connection
Evidence: list, API get by id, audit (S)

AC-13  (L10, FR-02)
Given a connected forest
When the same forest is added by a child-domain name or by another of its DCs
Then no second draft is created and the message names the existing connection
Evidence: API error type and screenshot (MF: same names in two different forests must both be accepted)

AC-14  (M-OVER-1)
Given an identity in Domain Admins
When Verify runs
Then V7 fails, the headline reads "Not activated: <identity> can administer your forest", the finding names Domain Admins, and Activate is not offered
Evidence: screenshot; verification record (S, W)

AC-15  (M-OVER-1, nested, large)
Given an identity nested in Backup Operators through two groups and a Domain Admins group with 2,000 members
When Verify runs
Then it is refused with the full path, and the 2,000-member group does not make the check time out or truncate
Evidence: finding shows the path; run duration recorded (S with seeded groups)

AC-16  (M-OVER-2)
Given an identity with write access to the Domain Controllers OU, and one with write property on a protected group's member attribute
When Verify runs
Then each is refused with M-OVER-2 naming the object and the right
Evidence: TM-F-RIGHTS lab cases (S, W)

AC-17  (M-OVER-3)
Given an identity with constrained delegation to ldap/<DC>
When Verify runs
Then it is refused with M-OVER-3 naming the delegation target
Evidence: TM-F-RIGHTS lab case (S, W)

AC-18  (M-UNDER-1, FR-12)
Given an identity that can bind but cannot read the domain NC
When Verify runs
Then V8 fails with M-UNDER-1, no override is offered, and ticking off that domain and verifying again passes if the remaining domains are readable
Evidence: screenshot; override control absent in the DOM (S)

AC-19  (M-NOVERIFY, FR-11)
Given a DC that returns no effective-rights attributes at all
When Verify runs
Then the result is Could not verify for those objects, the connection is not activated, and no override is offered
Evidence: connector fault injection removing the constructed attributes (S)

AC-20  (FR-10)
Given an identity added to Domain Admins 10 minutes before the check, with a Kerberos ticket issued before that
When Verify runs
Then it is still refused, because membership was evaluated at check time
Evidence: lab sequence with timestamps (W)

AC-21  (DM-11)
Given an active connection
When the credential card is viewed through the console, the API and a database dump of the connection tables
Then no secret value, keytab content or key bytes appear in any of them
Evidence: grep across API responses and dumps for the seeded secret (S)

AC-22  (FR-21)
Given an active connection
When Change credential is used with an identity from another forest, then with a valid one, then with a failing one
Then the first is refused as a different forest, the second is swapped atomically and the old credential state is rotated, and the third leaves the old credential in use with a message saying so
Evidence: audit events and API state (MF)

AC-23  (M-BIND-SIGN)
Given a DC that requires signing and a client forced to send an unsigned bind (test double)
When Verify runs
Then the message is M-BIND-SIGN with the DC named, and no weaker bind is attempted
Evidence: protocol capture shows no unsigned or NTLM bind (S, W)

AC-24  (FR-06)
Given DCs with signing required and channel binding "Always", and NTLM blocked domain-wide
When Verify and a sync cycle run
Then both succeed with no directory service events 2887, 3039, 3074 or 3075 attributable to the identity
Evidence: DC event log export (W)

AC-25  (M-AUTH)
Given a keytab whose account password was reset after the keytab was made
When Verify runs
Then the message is M-AUTH; and when the account is later disabled on an active connection, health shows M-AUTH within 2 intervals
Evidence: screenshots; timeline entry (S)

AC-26  (M-TLS, FR-05)
Given a DC certificate from a CA the host does not trust
When Verify runs
Then M-TLS shows the chain, no skip option exists, and after a CA certificate is added to the trust store the check passes
Evidence: DOM check for absence of any skip control; audit trust_store.changed (S)

AC-27  (M-SKEW)
Given the activeDIQ host clock 6 minutes ahead of the DC
When Verify runs
Then V2 fails with M-SKEW showing 6 minutes; at 2 minutes it warns and does not block
Evidence: screenshots (S)

AC-28  (M-NODC)
Given all DCs unreachable
When Verify runs
Then M-NODC lists each DC with its cause, and an active connection shows Unavailable with the last attempt time
Evidence: closed-port lab; screenshot (S)

AC-29  (FR-13, FR-14)
Given an over-privileged identity and a user holding the Tier-0-override permission with fresh MFA
When they choose Activate anyway and type the acknowledgement
Then the connection is active, every page of it shows "activeDIQ is Tier 0 in this forest", an audit event records who, when and the findings, and a user without the permission is not offered the control
Evidence: screenshots of two users; audit (S)

AC-30  (FR-14)
Given an active connection under override
When the identity is fixed and Verify passes
Then the banner clears and tier0_override.cleared is audited
Evidence: screenshot; audit (S)

AC-31  (FR-13)
Given an override in force
When a new finding appears (the identity gains another Tier-0 right)
Then health shows Needs attention, changes remain blocked, the new finding (a fingerprint not in the acknowledged set) needs its own acknowledgement, and the already-acknowledged findings do not ask again
Evidence: screenshots (S)

AC-32  (H10, FR-35)
Given an active connection whose identity becomes over-privileged
When the next rights check runs
Then health shows Needs attention with M-OVER text, sync continues, any change action is refused with the reason, and connection.rights.verdict_changed is audited
Evidence: screenshots; audit; a refused change attempt (S)

AC-33  (DM-19 initial_sync → incremental, FR-26)
Given a forest of 100,000 objects
When the first sync runs
Then the page shows objects synced so far and elapsed time updating, no percentage, Initial sync as the label, and Current once a cycle completes
Evidence: screenshots at three moments on the 100k-object scale tier (the 250k tier is a stretch run, not the criterion)

AC-34  (H3, FR-34)
Given a two-DC forest where the cookie's issuing DC is stopped
When 15 minutes pass
Then health shows the cause, the scheduled resync time and a duration estimate before the resync starts
Evidence: 2dc lab; timeline entries (2dc)

AC-34b  (H1, FR-34)
Given the same forest and the issuing DC stopped for 10 minutes only
When the DC returns
Then no resync runs, the DC row clears, and the timeline shows the outage
Evidence: 2dc lab; no resync job, timeline entry (2dc)

AC-35  (H3, H6, DM-19.I3)
Given a user deleted while the cookie was stale
When the resync completes
Then the user shows deleted in inventory, and the "deletions may still appear" notice has cleared
Evidence: before and after search (2dc)

AC-36  (H4, H5)
Given a DC restored from a snapshot (new invocation id), and one with a USN rollback
When the next cycle runs
Then H4 and H5 are shown with their causes, the rolled-back DC is not read from, and a resync runs from another DC
Evidence: Windows lab (W; Samba cannot reproduce)

AC-37  (FR-32, E2)
Given every console screen and export that shows directory data
When they are inspected
Then each shows an "as of" time and none uses the words "live" or "real-time" for directory data
Evidence: automated text scan of the web build and export templates, plus a screenshot sweep

AC-38  (§8.1 labels)
Given a sync interval of 5 minutes
When the last complete cycle is 9, 30 and 90 minutes old
Then the label reads Current, Behind and Stale respectively, and the data_as_of value equals the last complete cycle's commit time, not the last change time
Evidence: clock-controlled test; screenshots (S)

AC-39  (E4)
Given the fresh install and a 2-DC lab with 5,000 objects
When a tester completes Flow A with a least-privilege identity
Then the run has ≤ 3 typed inputs, ≤ 5 screens, verification ≤ 60 s and a search result ≤ 2 min after Activate (values to be confirmed by the design ticket)
Evidence: timed recording

AC-40  (partial cycle, §8.4)
Given two domains where one fails mid-cycle
When the cycle ends
Then the failed domain's data_as_of does not move, the other's does, and the health row names the failed domain and cause
Evidence: fault injection (MF or 2dc)

AC-41  (FR-30, FR-16)
Given a user without the connection permission and a user with it but without the verify permission
When each opens the connection page
Then the first sees name, status and data_as_of only, and the second sees the verdict and counts but not the findings table
Evidence: two screenshots; API responses (S)

AC-42  (FR-33)
Given an active connection whose keytab is invalid
When 6 cycles are due
Then at most 5 authentication attempts reach the DC before retries pause, and the account is not locked
Evidence: DC bad-password count (S)

AC-43  (FR-23)
Given the attribute picker
When a secret-flagged attribute is selected
Then it is refused with the reason and cannot be added
Evidence: screenshot; API error type (S)

AC-44  (FR-04)
Given a 2-DC forest
When one DC is excluded and the priority order is changed
Then no cycle or write pin uses the excluded DC, the order is honoured when both are healthy, and both changes are audited
Evidence: connector log of DC used; audit (2dc)

AC-45  (L11, FR-17)
Given an active connection and a suspended one
When a scheduled rights check, Check now, or a credential change runs verification on each
Then the lifecycle state of each is unchanged while it runs and after it ends, the Health tab shows the run, and a refused result moves the derived status to Needs attention, not the lifecycle state
Evidence: API state read before, during and after; screenshots (S)

AC-46  (§8.1 rule 5)
Given a sync interval of 5 minutes, a rights check last run 3 hours ago (schedule 24 h) and a connectivity check last run 14 minutes ago
When the Health tab is opened, then again with the rights check 49 hours old and the connectivity check 9 minutes old
Then at first the rights row is not greyed and the connectivity row is greyed "not checked since <time>"; at second the rights row is greyed and the connectivity row is not
Evidence: clock-controlled test; screenshots (S)

AC-47  (V7 forest-wide, FR-10)
Given a forest with a child domain and an identity from the child domain that is a member of Enterprise Admins in the root domain
When Verify runs
Then it is refused with M-OVER-1 naming Enterprise Admins and the path; and if the root domain's DCs are unreachable the result is Could not verify, never a pass
Evidence: Windows lab with a child domain (W, [LAB-GAP]: no Samba or MF tier has a child domain; lab ticket T-0169); until then verified by connector unit tests on recorded directory responses

AC-48  (M-AUTH, gMSA)
Given the windows profile and a gMSA whose host is not in PrincipalsAllowedToRetrieveManagedPassword
When Verify runs
Then the message is M-AUTH with the gMSA cause line (account disabled, host not allowed, no KDS root key) and the gMSA fix, and not the keytab wording
Evidence: screenshot of the message (W)

AC-49  (FR-36)
Given a draft and an active connection
When the admin opens each
Then Discard draft is offered on the draft only, and a discarded id never appears in a list or search but still resolves from the audit event
Evidence: DOM check; API (S)
```

## 14. Out of scope

- **Remote connector enrollment and bindings** (DM-12, DM-13 beyond embedded; ADM-210 redundancy). T-0167. The SaaS profile depends on it.
- **Entra tenant connection and the takeover attestation** (DM-10.I7). E2.7.
- **The delegation-plan wizard** that generates and applies ACLs (ENH-08 second half, TM-D3). Separate spec, T-0166.
- **Per-OU preferred DCs** (ADM-133). Delegation spec (E-011).
- **HybridLink** between an AD and an Entra connection (DM-21).
- **Writing any directory object.** This spec writes nothing to the directory.
- **Password-based AD credential** (`ad_password`, DM-11). Not offered in 2a. OQ-7.
- **SSO sign-in to the console, SIEM export of health.** Their own epics.

## 15. Open questions and tickets

| # | Question | Owner | Blocks | Decision |
| --- | --- | --- | --- | --- |
| OQ-1 | Tier-0 override acknowledgement storage. | solution-architect | T-0119 | **Decided (T-0068 review):** new entity `Tier0Override` with finding fingerprints (§11); recorded in T-0168 |
| OQ-2 | Where findings, verification results and health history live, retention, X11. | solution-architect, security-architect | T-0093, T-0119 | **Decided (review):** append-only `ConnectionVerification` with Finding rows (GUIDs, SIDs, codes only), retention a tenant record class defaulting to audit retention, health history 30 days (§11). `security-architect` confirms the restriction and retention |
| OQ-3 | `windows` profile and a forest the host is not joined to or does not trust: a gMSA cannot span forests. Is a keytab credential allowed on `windows`? Spec assumes yes (DM-11 allows `keytab_ref` on any profile). | directory-engineer, security-architect | T-0124, multi-forest on windows | open; PM default: keytab |
| OQ-4 | gMSA retrieval on Linux is `[LAB]`; if it proves out, the linux-oci credential step gains a second option. | directory-engineer | none (keytab ships) | open |
| OQ-5 | DM-10 has no `draft → discarded`; where does re-verification sit? | solution-architect | T-0119 | **Decided (review):** §6 L3, L4, L7, L9, L11; recorded in T-0168 |
| OQ-6 | Defaults *I* = 5 min, grace = 15 min, 12·*I* stale line, and the effect on DCs at 100k objects. | directory-engineer (T-0065, T-0092) | AC-34, AC-38 | open; PM default stands until T-0065 gives a budget |
| OQ-7 | Should an `ad_password` fallback exist at all? PM recommendation: not in 2a; revisit at M2 exit with evidence from migrating customers. Customer-visible packaging, so the director decides whether it needs the CEO. | factory-director | none for 2a | open |
| OQ-8 | May the change feed use an RODC? Not found in the consult. | ad-expert, directory-engineer | H1 priority rules | open |
| OQ-9 | Whether the configuration NC is readable by an unprivileged identity by default is not stated in the consulted sources; a refusal at V6 would make onboarding impossible. | ad-expert (T-0051) | V6 | open, `[UNVERIFIED]` |
| OQ-10 | Whether `sDRightsEffective` returns 0 or is absent for a non-administrator. FR-11 is written to be safe either way. | ad-expert (T-0051) | T-0053 | open, `[UNVERIFIED]` |
| OQ-11 | Whether an *unprivileged* identity gets an unhidden entry for every Tier-0 object. M-NOVERIFY fails closed. If it proves common, the spec needs a documented way to grant list rights, not an override. | security-architect, T-0053 | AC-19 | open |

Added in revision 2 (review fixes): OQ-12 — **a lab with a child domain** is needed to prove forest-wide V7 (AC-47); owner devops-engineer, ticket T-0169, backlog; until then AC-47 is covered by recorded-response unit tests and is marked `[LAB-GAP]`.

Tickets filed from this spec (backlog): T-0164 `research` ME onboarding baseline (market-analyst), T-0165 `design` onboarding and health flows with the task-time budget (product-designer), T-0166 `spec` least-privilege delegation-plan wizard, T-0167 `spec` remote-connector variant.

## Sources

Product: [ME ADM-212 help](https://www.manageengine.com/products/ad-manager/help/directory-application-settings/connecting-to-a-domain.html) · [ME permissions guide](https://download.manageengine.com/products/ad-manager/permissions-required-for-the-ad-account-configured-in-admanager-plus.pdf) · [ME I360 directory help](https://www.manageengine.com/identity-360/help/admin-guide/universal-directory/directory-services-integration/directory-management.html) · repo research files cited inline.

AD behaviour (ad-expert consult, 2026-10-02, documentation only, nothing run on a lab): [DC locator](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/dc-locator) · [anonymous rootDSE](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/anonymous-ldap-operations-active-directory-disabled) · [rootDSE attributes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/96f7b086-1ca3-4764-9a08-33f8f7a543db) · [crossRef](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8877f323-90ec-4460-9ae9-c3dfb6be2e61) · [hidden values read as nonexistent](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e6685d31-5d87-42d0-8a5f-e55d337f47cd) · [constructed attributes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c16a23d1-6847-4b25-9f6b-f09fc29e8627) · [allowedAttributesEffective](https://learn.microsoft.com/en-us/windows/win32/adschema/a-allowedattributeseffective) · [LDAP signing and channel binding](https://support.microsoft.com/en-us/topic/2020-2023-and-2024-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a) · [LDAP signing errors](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server) · [clock tolerance](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/maximum-tolerance-for-computer-clock-synchronization) · [event 4771](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771) · [DirSync control](https://learn.microsoft.com/en-us/windows/win32/ad/polling-for-changes-using-the-dirsync-control) · [USN rollback](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/detect-and-recover-from-usn-rollback). Result 49 with data `80090346` for a bad channel-binding token comes from a vendor knowledge-base article and is secondary; the same applies to "channel binding covers SASL binds over TLS, not simple binds" (both `[UNVERIFIED — lab]`).

Consult facts tagged `[UNVERIFIED]` here: that an Authenticated User can read the configuration NC (OQ-9), that membership added within the ticket lifetime is missing from a cached ticket's token (design inference, drives FR-10's "evaluated at check time"), that the Kerberos tolerance configured in a domain is readable by the identity, and that `msDS-KeyVersionNumber` is readable by the connector.

## Changelog

- 2026-10-02 · revision 2 after solution-architect review (T-0068): staleness per check cadence (§8.1 rule 5, AC-46); V7 forest-wide with Could-not-verify on unreachable domains (V7, FR-10, AC-47); V7 method wording per TM §6.5; M-AUTH gMSA wording (AC-48); "Live checklist" renamed "Progress checklist"; lifecycle amended per OQ-5 (L3, L4, L7, L9, new L11, FR-17, FR-19, FR-36, AC-45, AC-49); `Tier0Override` and `ConnectionVerification` folded in (§11, OQ-1, OQ-2); AC-33 and AC-34 nits fixed.
- 2026-10-02 · created (T-0068). Covers DM-10 L1–L10, DM-11, DM-13, DM-19 transitions, TM-D1 refusal messages, and sync freshness without "live".
