---
title: ManageEngine → activeDIQ Migration Playbook
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: heramb
---

# ManageEngine → activeDIQ Migration Playbook

**Audience:** skenzeriq customer success, solutions engineering, product. **Internal.** Parts may
be adapted for partner-facing material, but only after CEO approval (`ceo-decisions`, category 6)
and after the messaging rules in [CV §6.3] are applied. That means no adjectives about
ManageEngine, and no claims tagged `[UNVERIFIED]`.

**What this is:** how a customer moves from ManageEngine's AD products (ADManager Plus, ADAudit
Plus, ADSelfService Plus, AD360, RecoveryManager Plus) to activeDIQ with minimal risk. Every
ManageEngine fact is cited to the research corpus. Durations are estimates and tagged `[EST]`.
Tooling we have to build is written as product requirements (`MIG-##`, §8).

## Source key

| Tag | Document |
|---|---|
| [ADMP] | [manageengine-admanager-plus.md](../market-research/manageengine-admanager-plus.md) |
| [ADAP] | [manageengine-adaudit-plus.md](../market-research/manageengine-adaudit-plus.md) |
| [ADSSP] | [manageengine-adselfservice-plus.md](../market-research/manageengine-adselfservice-plus.md) |
| [AD360C] | [manageengine-ad360-suite-and-commercials.md](../market-research/manageengine-ad360-suite-and-commercials.md) |
| [CV] | [manageengine-ad-customer-voice-and-security.md](../market-research/manageengine-ad-customer-voice-and-security.md) |
| [LAND] | [ad-management-market-landscape.md](../competitive-analysis/ad-management-market-landscape.md) |
| [FEAS] | [ad-technical-feasibility.md](../../development/architecture/build-feasibility/ad-technical-feasibility.md) |

---

## 1. Summary for decision-makers

1. **What makes switching expensive is configuration, not data** [LAND §7.1 #10]. Customers name
   five barriers: price, dependence on compliance reports, sunk configuration (templates,
   delegation roles, workflows), audit-history retention, and ADSSP users having to re-enroll in
   MFA and SSPR [CV Key takeaways #7, §5.2]. This playbook answers each one (§4–§5).
2. **ManageEngine documents almost no way to export configuration.**
   - The ADMP REST API v2 has no documented endpoints for templates, workflow approvals, report
     export, GPOs or backup [ADMP §2.7].
   - ADAP has no documented public API [ADAP ADA-108].
   - ADSSP's REST API is "in pipeline" [ADSSP ADSS-136].

   That leaves three routes: report exports (CSV/XLSX), reading the product databases
   read-only, or rebuilding the configuration with help. Reading the databases is
   `[UNVERIFIED feasibility]` and needs an EULA review `[TODO]` [ADAP §7a option 5; AD360C §8.2].
   **Do not promise "automatic import" to a partner until a lab install has proven it** (§9).
3. **Our build order decides the migration order.** The feasibility roadmap `[EST]` puts
   directory management, delegation, reports and a web SSPR portal (TOTP + WebAuthn) in Phase 1.
   Event-based auditing, the DC password filter and the Windows logon-screen credential provider
   come in Phase 2. macOS/Linux logon, the push app and M365/Exchange Online come in Phase 3
   [FEAS §6.3]. So **the ADMP scope moves first, ADAP second and ADSSP logon-screen/endpoint MFA
   last**. A customer can run activeDIQ next to ManageEngine products they have not yet replaced.
4. **ManageEngine stays the rollback path until hypercare ends.** Keep ManageEngine licences
   active, configuration frozen and servers running until exit criteria are met (§6). That makes
   the renewal date a planning input, and co-term credit a CEO decision [AD360C §8.1 item 4].
5. **About half of the ADSSP enrollment surface can move with zero user effort.** Email/SMS,
   AD-attribute questions, Duo/RSA/RADIUS/Entra/SAML and PIV can move. App-based TOTP, push and
   security answers almost certainly need re-enrollment, so we use progressive enrollment, not a
   big-bang drive [ADSSP §8a].

---

## 2. Principles

| # | Principle | Why |
|---|---|---|
| P1 | **Waves, never big-bang.** Move one capability at a time and one OU or user group at a time. | Tier-0 change risk; customers report updates that affected AD [CV §2.2 X10] |
| P2 | **Start read-only.** activeDIQ reads AD, reports and runs in shadow mode before it writes anything. | Builds trust; validates parity without risk |
| P3 | **One writer per job.** Every automation, schedule and notification is owned by exactly one system at any moment (MIG-14). | Prevents double execution: two leaver runs, two expiry emails |
| P4 | **Don't touch ManageEngine until exit.** No uninstalls, no licence reductions and no config edits during the parallel run, except deliberately switching off a job that has moved. | Keeps rollback cheap. Some ManageEngine wind-down actions destroy data or weaken security (§6.3) |
| P5 | **No Domain Admin.** Install with the least-privilege wizard (MIG-12); Tier-0 actions only through the optional Tier-0 connector [FEAS §0, §2.3]. | Removes the security reviewer's first objection |
| P6 | **Evidence, not assurances.** Every phase ends with an artifact: inventory, fidelity report, parity diff, sign-off. | Customers need proof of a safe migration [CV §6.2 "Safe migration"] |
| P7 | **Generic tooling.** Importers and checklists are parameterized by ManageEngine product and build, with no customer names or topologies in code. | PatchIQ lesson: one customer's topology leaked into shared code ([postmortem §11 #4](../../../../UEM/knowledge/development/legacy/patchiq-postmortem.md)); CLAUDE.md rule 8 |

---

## 3. Phases, entry and exit criteria

Durations assume one domain, a few thousand users and the ADMP + ADAP + ADSSP trio. All are
`[EST]` and must be recalibrated after the first pilot.

| Phase | Goal | Entry criteria | Key activities | Exit criteria (all required) | Duration `[EST]` |
|---|---|---|---|---|---|
| **0. Discovery** | Know exactly what the customer uses | Signed NDA; executive sponsor named; discovery questionnaire returned ([partner-discovery-questionnaire.md](../partnerships/partner-discovery-questionnaire.md)) | Workshops with the AD admin, help-desk lead, security and compliance. Run the read-only discovery scanner (MIG-01). Record ManageEngine products, editions, builds, add-ons, licence counts and **renewal/AMS dates**. Use the per-product checklists in §4 | Signed **scope sheet**: products and features in scope, mapped to ADM-/ADA-/ADSS- IDs; feature gaps flagged against activeDIQ's shipped scope; wave plan; target cutover dates **before** the ManageEngine renewal date | 1–2 weeks |
| **1. Inventory export** | Get the customer's configuration out of ManageEngine | Scope sheet signed; customer has granted access to ManageEngine consoles (read-only technician) and, if agreed, read-only DB access | Run the export pack (§4): report exports, technician inventory, schedules, screenshots of templates and workflows, enrolled-users export, optional DB extraction (MIG-02). Snapshot AD as the baseline (MIG-18) | **Inventory workbook** complete: every in-scope object has a row (template, role, workflow, automation, report, alert, policy, integration). Counts reconcile with the ManageEngine UI | 1 week |
| **2. Mapping & build** | Recreate the configuration in activeDIQ | Inventory workbook complete; activeDIQ installed in least-privilege mode (MIG-12), read-only | Import or rebuild each item. Generate the **import fidelity report** (MIG-03): exact / changed / manual / not supported. Customer reviews every "changed" and "not supported" row. Build the report crosswalk (MIG-05) | Fidelity report signed by the customer's AD lead. Every "not supported" item has a decision: workaround, defer, or keep in ManageEngine. Test plan agreed | 1–3 weeks |
| **3. Parallel run** | Prove parity with live data, with no customer-visible change | Fidelity report signed; rollback plan (§6) approved by the customer's change board | Shadow mode: activeDIQ runs reports and automations in **dry-run** and the comparator (MIG-10) diffs results against ManageEngine. A pilot group of technicians uses activeDIQ for real tasks inside a scoped OU. Audit: ADAP keeps forwarding events to activeDIQ's receiver (MIG-07). Weekly parity review | **Parity sign-off:** top reports match within agreed tolerance; dry-run automations would have produced the same changes; pilot technicians complete the agreed task list; no P1/P2 defects open; security review passed | 2–4 weeks |
| **4. Cutover** | Move ownership to activeDIQ, wave by wave | Parity sign-off; comms sent (§5.3); help desk briefed; ManageEngine licences valid ≥ 60 days past the planned cutover `[EST buffer]` | Per wave: switch job ownership (MIG-14). Disable each moved job in ManageEngine **the same hour** it is enabled in activeDIQ. Move technicians by role. For ADSSP, move users by OU via coexistence routing (MIG-10). Re-point integrations (ITSM, SIEM, SAML apps, RADIUS) | Wave checklist complete; smoke tests pass; no rollback trigger hit for 72 h after the wave (§6.2) | 1 day per wave; 2–6 waves |
| **5. Hypercare** | Stabilize | Final wave cut over | Daily check-ins in week 1, then weekly. Named engineer on call. Track help-desk tickets tagged "activeDIQ". Close out remaining enrollment (progressive) | 30 days with no rollback trigger hit; ticket volume back to baseline; customer acceptance signed | 30 days |
| **6. Decommission** | Retire ManageEngine safely | Hypercare acceptance signed | Agent removal (MIG-11). Keep the audit-history bridge (§4.2). Remove ManageEngine service accounts and credentials. Review the audit-policy and SACL GPOs ManageEngine created **before** deleting them (activeDIQ may rely on the same settings, MIG-08). Archive the inventory workbook and fidelity report | ManageEngine servers off or kept as a read-only audit viewer by documented decision. Service accounts disabled. Customer confirms non-renewal | 1–2 weeks |

**Recommended capability order** (follows [FEAS §6.3] and P2):
1. **Reporting and read-only views** (ADMP reports): lowest risk, immediate UX win.
2. **Directory management and delegation** (ADMP technicians, templates, bulk operations, workflows).
3. **Automations** (ADMP scheduled and event-driven), one at a time, each after a dry-run.
4. **Auditing** (ADAP), once activeDIQ's event pipeline has shipped (Phase 2).
5. **Self-service and MFA** (ADSSP). Web SSPR is possible from Phase 1. Logon-screen reset and
   endpoint MFA wait for the credential provider (Phase 2) and macOS/Linux agents (Phase 3).

---

## 4. What must be carried over, product by product

**Column key**
- **How it leaves ManageEngine:** only documented paths are cited. "DB" means a read-only adapter
  over the product database, `[UNVERIFIED]` until the lab test (§9).
- **Tooling:** requirement IDs from §8.

### 4.1 ADManager Plus (ADMP)

ADMP stores its configuration in bundled PostgreSQL (port 33306, localhost only) or MS SQL
[ADMP §2.1; ADM-211]. It backs up its own database monthly [ADM-158]. **Any export through the
REST API draws on the quota of 50 successful calls per technician per day** [ADM-190], so bulk
exports should use reports or the DB, not the API.

| Item | ME IDs | How it leaves ManageEngine | How it lands in activeDIQ | Tooling | Notes / risk |
|---|---|---|---|---|---|
| User-creation templates, field layout, creation rules | ADM-012–014, 016 | No documented export; REST API v2 has no template endpoints [ADMP §2.7]. DB, or screenshots plus a walkthrough | Policy-bound templates. Import from DB if feasible, otherwise a guided rebuild with side-by-side review | MIG-02, MIG-03 | ADMP template edits don't update existing users [ADMP W13]. Offer drift detection after import [ADMP §7c] |
| Modification templates and mover rules | ADM-015, 042, 058 | Same as above | Rule engine | MIG-02 | Validate in dry-run against real movers |
| Naming formats and custom functions | ADM-017, 019 | Naming formats are macro strings [ADMP W8]; custom functions are scripts | Parse macro strings into activeDIQ naming rules. Re-implement custom functions by hand, in sandboxed form | MIG-02 (macro parser) | Script components carry risk: ADMP's Custom Script component had CVE-2025-10020 [CV §5.3] |
| Duplicate-prevention rules | ADM-020 | DB or manual | Uniqueness rules (domain, forest, external DB, Entra) | MIG-02 | — |
| **Bulk CSV formats** in use by HR or scripts | ADM-010, 011 | The customer's own files: LDAP attribute headers, DN-format `memberOf`/manager, `templateName` column [ADM-011] | **Accept ADMP-format CSV unchanged**, plus smart column mapping [ADMP §7c] | MIG-04 | Lets existing HR exports and scripts keep working on day one |
| Help-desk roles, technicians, OU/group scope, group-based delegation | ADM-125–133 | Technicians report: "inventory of technicians and their permissions" [ADM-139]. Report exports are CSV/PDF/XLSX/HTML/CSVDE [ADM-100]; whether ADM-139 supports every format is `[UNVERIFIED]` | Roles with task-, attribute- and OU-scope. Group-based assignment | MIG-02, MIG-16 | Per-technician pricing leads some customers to share admin accounts [CV §5.3]. Clean up identities during migration (MIG-16) |
| "Impersonate as Admin" usage | ADM-134 | Visible in role configuration | Per-technician attribution [ADMP §7c] | — | DC logs show the service account under this mode [ADMP §2.6]. After migration, attribution in DC logs changes; tell the SOC |
| Native AD security roles (ACLs written into AD) | ADM-135 | Already in AD | Read and report; no migration needed | MIG-01 (detects them) | Leave in place. Review against Tier-0 ACL hygiene [LAND §7.1 #7b] |
| Technician-managed **privileged** accounts | — | Discovery question | Out of default scope: AdminSDHolder-protected accounts are handled only through the optional Tier-0 connector [FEAS §0] | — | **Gap to flag in Discovery** if technicians manage admin accounts through ADMP today |
| Business workflows, assigning rules, SLAs | ADM-116–123 | No API for workflow approvals [ADMP §2.7]. DB or manual | Approval workflows with manager routing | MIG-02 | **Drain in-flight requests**: freeze new requests in ADMP before the wave and finish or cancel open ones. Don't migrate open requests |
| Scheduled automations, policies, event-driven automation, orchestration templates | ADM-104–115 | API v2 lists orchestration templates and shows execution status [ADMP §2.7]; whether full definitions are exported is `[UNVERIFIED]`. The admin audit report lists configuration changes [ADM-138] | Rebuild each automation; run in **dry-run** during parallel run; move ownership one by one | MIG-02, MIG-10, MIG-14 | **Highest operational risk**: double execution, e.g. a leaver deleted twice. Custom scripts (ADM-112) are rewritten, not copied |
| Prebuilt reports in use | ADM-083–096 | Customer lists the reports in use | Report crosswalk with matching names | MIG-05 | Report parity is a day-one expectation [CV §2.1, §5.2] |
| Custom reports | ADM-097, 103 | Definitions are LDAP filters or raw queries [ADM-097]. DB or manual copy | Translate into activeDIQ's typed LDAP-filter model [FEAS §0] | MIG-05 | Reject filters that can't be parsed safely; never pass them through as strings (CLAUDE.md rule 5) |
| Scheduled reports, recipients, formats | ADM-101 | DB or screenshots | Schedules with identical recipients and formats | MIG-06 | Auditors and managers on the recipient list notice changes. Keep names and timing identical in the first cycle |
| Help-desk and admin audit history | ADM-137, 138, 206 | Report exports: CSV, PDF, XLSX or HTML [ADM-137] | Import as legacy evidence with provenance (MIG-07) | MIG-07 | Retention set in ADMP [ADM-206]; ask the customer what they must keep |
| Backup add-on snapshots | ADM-149–156 | Not migrated | activeDIQ snapshots start at the parallel run (Phase 1 scope [FEAS §6.3]) | MIG-18 | Keep ADMP backup readable until the customer's restore window has passed |
| ITSM integrations (ServiceNow, SDP, Jira and others) | ADM-191–193 | Configuration visible in console | activeDIQ connectors; re-point catalog items | MIG-13-style checklist | ServiceNow is a Store app with MID Server [ADM-191]; activeDIQ needs an equivalent before an ITSM-driven customer can cut over |
| HCM connectors, DB-driven and CSV-drop provisioning | ADM-040, 041, 194 | Configuration in console | activeDIQ HR connectors | — | Check the customer's HR system against activeDIQ's connector list in Discovery |
| Custom app framework, webhooks | ADM-110, 111, 195, 196 | Configuration in console | Signed webhooks [FEAS §4.6] | MIG-02 (inventory) | Inbound callers (ADM-111) must be re-pointed by their owners |
| Scripts and tools calling the ADMP REST API | ADM-188, 189 | Inventory via authtoken list [ADM-141] | activeDIQ API | MIG-17 (proposal) | Every token owner must be found and told |
| SIEM / syslog forwarding | ADM-198 | Configuration in console | Same format and target (syslog RFC 3164/5424) | — | Avoid breaking SOC parsers |
| Console SSO and 2FA | ADM-142, 143 | IdP configuration | New SAML app in the customer IdP | MIG-13 | — |
| Mobile app users | ADM-201–203 | — | Responsive web console first [ADMP §7b] | — | Tell mobile approvers about the change |

### 4.2 ADAudit Plus (ADAP)

ADAP keeps audit data in PostgreSQL (port 33307) or MS SQL (Professional only), plus a separate
"DataEngine" store for high-volume categories. Cold and Frozen archive tiers **cannot be
searched** until they are restored, and archives are password-protected ZIPs [ADAP §2.4, §2.5].

**Audit history: default approach.** ADAP §7a lists six bridging options. Recommend combining
the first three, with the fourth where the customer kept raw logs:

| # | Option | What it gives | Status |
|---|---|---|---|
| 1 | **Keep ADAP as a read-only viewer.** The Free edition "never expires" and allows "Reports generation from event log data collected during evaluation / license period" | Auditors can still be answered after the subscription stops | `[UNVERIFIED in practice]`: test that a lapsed subscription drops to Free with history intact. The server still needs patching [ADAP §7a] |
| 2 | **Dual-run via SIEM forwarding.** ADAP forwards syslog/CEF/Splunk HEC (every category except printer and advanced GPO) to activeDIQ's receiver [ADA-106] | Continuous history across the cutover, plus side-by-side validation | Does **not** backfill events from before the cutover |
| 3 | **Bulk export of key reports.** Scheduled reports with the "Before N days" range cover everything since install, as CSV/XLS [ADA-100] | Searchable legacy evidence in activeDIQ | Formats vary by report and are undocumented; build importers for the top ~30 [ADAP §7a] |
| 4 | **EVTX backfill** if raw Security logs were kept. ADAP imports EVT/EVTX itself [ADA-118] and ManageEngine sells this as an onboarding service [ADAP §1.4] | Rebuilds history from source | Depends on what the customer retained |
| 5 | Direct DB read | Full fidelity | `[UNVERIFIED feasibility]`; DataEngine store proprietary; `[TODO]` EULA review [ADAP §7a] |

| Item | ME IDs | How it leaves ManageEngine | How it lands in activeDIQ | Tooling | Notes / risk |
|---|---|---|---|---|---|
| Audit history and retention settings | ADA-117, 118 | Options above | Legacy evidence store, labeled with source, time range and hash | MIG-07 | Ask for the oldest data needed and any legal holds. One admin was advised to keep the old VM rather than purge [CV §5.2] |
| Alert profiles, thresholds, business hours | ADA-092–094 | Config export `[UNVERIFIED]` [ADAP §7a option 6]; screenshots plus inventory | Rebuild using the alert crosswalk | MIG-02, MIG-05 | Use the move to cut noise; customers report alert floods [CV §2.2 X11] |
| Response scripts | ADA-095 | Script files on server | Rewrite as typed actions | — | No copied scripts |
| ITSM auto-ticketing | ADA-096 | Configuration in console | activeDIQ ticketing connectors | — | Re-point at cutover, one ticket queue at a time |
| Scheduled and custom reports | ADA-100, 101 | Inventory plus screenshots | Crosswalk using report names auditors recognize [ADAP §7a] | MIG-05, MIG-06 | E.g. "Administrative User Actions", "Logon Failures", "All File or Folder Changes" [ADAP §7a] |
| Global exclusions (noise filters) | ADA-114 | Configuration in console | Exclusion rules | MIG-02 | Carry over, or alert volume jumps at cutover |
| Technician roles, 2FA/SSO | ADA-110, 111 | Configuration in console | activeDIQ RBAC (same model as ADMP roles) | MIG-02 | Merge with ADMP roles into one role model |
| Audit policy and SACL GPOs created by ADAP | ADAP §2.3, §7a option 6 | Already in AD | **Detect and reuse**; don't re-push | MIG-08 | Don't delete ADAP's GPOs at decommission without checking dependencies |
| Agents on DCs, servers, workstations | ADA-115 | — | activeDIQ DC agent / WEF | MIG-11 | Two agents on DCs during the parallel run: measure resource impact `[TODO lab]` |
| SIEM forwarding | ADA-106 | Configuration in console | Same formats, **field mappings compatible with existing SIEM parsers** [ADAP §7a] | — | Breaking SOC content is a visible failure |
| Add-ons in use (Entra, file servers, NAS vendor, File Analysis, AD backup) | ADAP §1.3 | Licence page | Check coverage per add-on | MIG-01 | NAS vendor coverage decides feasibility [ADAP §7a] |

**Discovery checklist** [ADAP §7a]: build and edition; add-ons and counts; database
(PostgreSQL or MSSQL), archive settings and size; number of custom alert profiles and scheduled
reports; SIEM targets; NAS vendors; Entra licence tier; use of AD Backup, File Analysis or Attack
Surface Analyzer; agents vs agentless; HA.

### 4.3 ADSelfService Plus (ADSSP)

ADSSP has scheduled DB backups, a server-migration utility and a DB-migration tool
[ADSS-129]. The bundled PostgreSQL is readable by the customer's DBA, but whether TOTP seeds and
FIDO public keys can be extracted is unknown [ADSSP §8a].

| Item | ME IDs | How it leaves ManageEngine | How it lands in activeDIQ | Tooling | Notes / risk |
|---|---|---|---|---|---|
| **Enrollment data** | ADSS-021–029 | See §5.1 | See §5.1 | MIG-09 | The decisive switching cost [ADSSP §0 #6] |
| Self-service policies (scope by domain/OU/group, features, authenticators, precedence) | ADSS-124 | Config export `[UNVERIFIED]`; screenshots | Policies with the same scope and precedence | MIG-02 | — |
| Password Policy Enforcer, breached-password check | ADSS-097–103 | Configuration in console | activeDIQ password filter (Phase 2 [FEAS §6.3]) | — | Running **two password filters on the same DCs** needs a lab test `[TODO]`; plan one-DC-at-a-time replacement |
| Password Sync Agent on every DC; sync targets | ADSSP §2.2; ADSS-105–108 | Configuration in console | activeDIQ DC agent and sync | MIG-11 | Each Password Sync Agent consumes ADSSP licences on native changes [ADSSP §1.4] |
| Expiry notifications | ADSS-091–094 | Configuration in console | Notification schedules | MIG-14 | Switch off in ADSSP **in the same hour** activeDIQ switches on; duplicate emails confuse users |
| Logon-screen agents (Windows, macOS, Linux) | ADSS-006–010, 132 | Deployed via console push, GPO, SCCM, Endpoint Central [ADSS-132] | activeDIQ credential provider and agents through the same tool | MIG-11 | Credential-provider coexistence untested `[TODO]` [AD360C §8.2]. Microsoft recommends always keeping a system provider available [FEAS §1.6] |
| VPN MFA via NPS extension; OWA/IIS MFA | ADSS-068–072 | Configuration on NPS/IIS | activeDIQ RADIUS service [FEAS §1.6] | — | Re-point one VPN profile at a time. Confirm MSCHAPv2/PEAP needs [FEAS App. A #7] |
| SAML/OIDC SSO apps | ADSS-073–078 | App metadata | Bulk metadata import; per-app cutover | MIG-13 | Users see a new sign-in page; announce it |
| Mobile app (push, TOTP) | ADSS-005, 030 | — | activeDIQ app via the customer's MDM (Phase 3 [FEAS §6.3]) | MIG-09 | App-bound factors can't be migrated [ADSSP §8a] |
| Reports, audit, Syslog/Splunk forwarding | ADSS-118–123 | Report exports (CSV, PDF, XLS, HTML, CSVDE) [ADSS-122] | Crosswalk; same SIEM format | MIG-05 | Auditors ask for these during migration [ADSSP §8a] |
| Help-desk-assisted reset (needs ADMP) | ADSS-116 | — | Native caller verification [ADSSP §8c L7] | — | New help-desk script needed (§5.3) |
| Portal branding | ADSS-133 | Logo, colors | activeDIQ branding settings | — | Keeps the end-user experience familiar |

### 4.4 AD360, RecoveryManager Plus, M365 Manager Plus

| Product | What to carry over | How | Notes |
|---|---|---|---|
| AD360 | Shell SSO across modules, AD360-level roles (Admin/Operator only) [AD360C §1.3, §8.3] | Nothing to export: activeDIQ has one login and one role model | The AD360 shell has its own PostgreSQL (port 33305) [AD360C Exec summary #1]. Decommission it after the last module moves |
| RecoveryManager Plus | Backup snapshots and retention (RMP-039: retention counts full backups, not days), restore points for AD, Entra, M365 [CV §5.3; AD360C §2.2] | Not migrated. Keep RMP readable until its retention window passes, or the customer accepts the risk | activeDIQ snapshots start at parallel run (MIG-18). RMP has thin customer-review evidence `[TODO]` [CV §5.3] |
| M365 Manager Plus | "Virtual tenant" delegation scopes [M365-010] | Inventory plus rebuild | Listed as a config importer target [AD360C §8.2] |

---

## 5. End-user impact and communications

### 5.1 Avoiding re-enrollment (ADSSP)

From [ADSSP §8a], ranked by user effort:

| Enrollment data | Exportable? | Approach | User effort |
|---|---|---|---|
| Email / mobile for OTP | Likely yes: the Enrolled Users report includes emails and mobile numbers; since build 6527, exports list each user's authenticators as columns | Import CSV plus AD `mail`/`mobile` | None |
| AD-attribute security questions | N/A | Recreate as configuration | None |
| Duo, RSA SecurID, RADIUS OTP, Entra MFA, external SAML IdP | N/A (held externally) | Map by `sAMAccountName`/UPN | None |
| Smart card / PIV | N/A | Configure trust anchors | None |
| Hardware TOTP tokens | DB export `[UNVERIFIED]` | Re-import the vendor seed files if the customer kept them | None if seeds kept |
| Software TOTP | `[UNVERIFIED]` | Assume re-enrollment; progressive | Low |
| Security Q&A | **Plaintext: no** (one-way hashed, MD5 or SHA-512) | Re-enroll, or hash-compatible import `[UNVERIFIED]`, or retire. NIST SP 800-63B discourages knowledge-based questions | Low, or none if retired |
| FIDO2 passkeys | `[UNVERIFIED]`; bound to the ADSSP Access-URL RP ID | Possible carry-over only if activeDIQ serves the same RP ID and the keys can be extracted (inference). Otherwise re-register | Low |
| Push, biometric, QR, ADSSP-app TOTP | No (app-bound) | Re-enroll in the activeDIQ app, rolled out via MDM | Low |

**Strategy, in order:**
1. **Bootstrap on day one** with migrated email/SMS and AD-attribute questions, so no user is
   ever stranded without a way to reset.
2. **Coexistence by OU.** ADSSP keeps serving users who haven't moved yet (MIG-10).
3. **Progressive enrollment.** Prompt for a passkey or app at the next successful sign-in,
   instead of the desktop-blocking HTA prompt ADSSP uses [ADSS-022, ADSSP W15]. Set a grace
   period and show enrollment progress per OU in the migration cockpit (MIG-15).
4. **Graph import** of Entra-registered phone methods where the customer uses Entra MFA
   `[UNVERIFIED feasibility per tenant]`.
5. **Retire security questions** where the customer agrees, citing NIST SP 800-63B.

**Don'ts during coexistence:**
- **Don't change the ADSSP Access URL.** It changes the RP ID and disenrolls every FIDO user
  [ADSSP §2.3].
- **Don't reclaim ADSSP licences with "Restrict Users"**: it deletes the user's enrollment data
  [ADSSP §1.4 #5] and removes the fallback.
- **Don't cut the ADSSP licence count** below active users while ADSSP still enforces endpoint
  MFA. Over the limit, "MFA is simply skipped for those extra users" (fail-open) [ADSSP §1.4 #4].

### 5.2 Who notices what

| Group | What changes | When |
|---|---|---|
| Technicians / help desk | New console, new role names, new mobile approach | ADMP waves (§3 Phase 4) |
| Approvers (managers) | New approval emails and links | Workflow cutover |
| Auditors / report recipients | New sender and layout; same report names in the first cycle | Scheduled-report cutover |
| SOC | New syslog source; attribution in DC logs changes (ADM-134) | Audit cutover |
| End users | New reset portal, new logon-screen link, possibly one enrollment prompt, new SSO page | ADSSP waves |
| Endpoint team | Agent rollout and removal | Before ADSSP and ADAP waves |

### 5.3 Communications timeline (per ADSSP wave; shorter versions for technician waves)

| When | Audience | Message | Owner |
|---|---|---|---|
| T-30 days | Help desk | Training, new reset and caller-verification script, FAQ, escalation path | skenzeriq CS + customer help-desk lead |
| T-14 | Wave users | What's changing, why (one sentence), what they need to do (often nothing), date | Customer internal comms (we supply drafts) |
| T-3 | Wave users | Reminder; new portal URL; how to get help | Customer internal comms |
| T-0 | Wave users | "It's live": link, 3-step guide, help-desk number | Customer internal comms |
| T+3 | Non-enrolled users in wave | Gentle enrollment prompt (progressive) | activeDIQ in-product + comms |
| T+14 | Sponsor | Wave report: enrollment rate, tickets, incidents | skenzeriq CS |

Help-desk vishing is a top attack vector [LAND Key findings #4]. Attackers may exploit migration
emails, so **every user message says the help desk will never ask for a password or MFA code**,
and caller verification goes live before the first wave.

---

## 6. Risks and rollback

### 6.1 Risk register

| # | Risk | Likelihood `[EST]` | Impact | Mitigation |
|---|---|---|---|---|
| R1 | Configuration can't be extracted from ManageEngine (no API, DB unreadable or barred by EULA) | Medium | High: manual rebuild, longer Phase 2 | Lab proof before promising (§9); guided rebuild with fidelity report; scope rebuild effort in Discovery |
| R2 | Double execution: an automation, schedule or notification runs in both systems | Medium | High (e.g. a user deleted twice, duplicate emails) | One-writer rule (P3, MIG-14); same-hour switch-off; dry-run first |
| R3 | Report mismatch noticed by auditors | Medium | High (trust) | Crosswalk with identical names; comparator diff; first cycle sent from both systems with a note |
| R4 | Audit-history gap at cutover | Low (with option 2) | High (compliance) | SIEM forwarding dual run from the start of Phase 3; ADAP read-only viewer |
| R5 | Users locked out during ADSSP waves | Medium | High | Day-one bootstrap factors; OU waves; help desk briefed; rollback per OU |
| R6 | Two credential providers or password filters conflict on an endpoint or DC | Unknown `[TODO lab]` | High (logon failures; an LSASS crash reboots the DC [FEAS §1.7]) | Lab test before any pilot; replace one DC or endpoint ring at a time; keep the Microsoft system provider |
| R7 | ManageEngine licence lapses mid-migration | Medium if renewal is near | High (no rollback; ADAP Free stops collecting fresh data after 30 days [ADAP §1.2]; expired ADMP may drop to Free, 100 objects `[UNVERIFIED]` [ADMP §1.5 #9]) | Plan cutover ≥ 60 days before renewal `[EST]`; ADMP licences must be renewed ≥ 10 days before expiry [ADMP §1.5 #9]; co-term or short extension (CEO decision) |
| R8 | Shared technician accounts make role mapping impossible | Medium [CV §5.3] | Medium | MIG-16; customer names an owner for each shared login before Phase 2 |
| R9 | Hidden API consumers break (ITSM, scripts) | Medium | Medium | Authtoken inventory [ADM-141]; contact each owner; MIG-17 evaluated |
| R10 | activeDIQ lacks a feature the customer uses (gap found late) | Medium | High | Discovery maps features to IDs; signed scope sheet; "keep in ManageEngine" is a valid interim decision |
| R11 | Fail-open MFA during wind-down | Low if rules followed | High (security) | §5.1 "Don'ts" |
| R12 | Privileged accounts were managed through ADMP; activeDIQ excludes them by default | Medium | Medium | Flag in Discovery; Tier-0 connector or native tools [FEAS §0] |

### 6.2 Rollback

**Rollback is possible at every phase, because ManageEngine is left running and unchanged
until Phase 6** (P4).

| Phase | Rollback action | Time to roll back `[EST]` |
|---|---|---|
| 0–2 | Stop. Uninstall activeDIQ. Nothing in AD changed (read-only) | Hours |
| 3 | Stop the pilot technicians using activeDIQ. Use the activeDIQ change log to undo pilot changes, if wanted | Hours |
| 4 (per wave) | Re-enable the moved jobs in ManageEngine and disable them in activeDIQ (MIG-14 swaps owner). Move technicians back. ADSSP: route the OU back to ADSSP (MIG-10); users still have their ADSSP enrollment because nothing was deleted (§5.1) | < 1 hour per wave |
| 5 | Same as Phase 4, across all waves | < 1 day |
| 6 | Not cheap: ManageEngine has been retired. Exiting Phase 5 is therefore a formal sign-off | — |

**Rollback triggers** (agreed in Phase 2, reviewed by the customer's change board):
- Any unintended AD change caused by activeDIQ.
- A report or audit gap that an auditor or the SOC cannot accept.
- Logon or reset failures above an agreed threshold in a wave.
- A P1 defect without a fix or workaround within the agreed time.
- The customer's sponsor calls it.

---

## 7. RACI

R = responsible, A = accountable, C = consulted, I = informed.

| Activity | skenzeriq migration lead | skenzeriq solutions eng. | skenzeriq product/eng. | skenzeriq CEO / account | Customer sponsor | Customer AD/identity lead | Customer help-desk lead | Customer security / CISO | Customer compliance / audit | Customer endpoint team | Customer comms |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Discovery workshops and scope sheet | A | R | C | I | C | R | C | C | C | I | — |
| Commercials, renewal alignment, co-term | C | — | — | A/R | R | I | — | — | — | — | — |
| Security review of activeDIQ | C | R | R | I | I | C | — | A | C | — | — |
| Least-privilege install and service accounts | C | R | C | — | I | A | — | C | — | — | — |
| Inventory export from ManageEngine | A | R | — | — | I | R | C | — | — | — | — |
| Import / rebuild and fidelity report | A | R | C | — | I | C | — | — | — | — | — |
| Fidelity report sign-off | R | C | — | — | I | A | C | C | C | — | — |
| Report crosswalk and parity check | R | R | C | — | I | C | — | — | A | — | — |
| Parallel run and parity sign-off | R | R | C | I | I | A | C | C | C | — | — |
| Rollback plan and change-board approval | R | C | — | — | I | A | C | C | — | — | — |
| Agent rollout and removal | C | C | C | — | — | C | — | C | — | A/R | — |
| End-user communications | C | C | — | — | I | C | C | — | — | — | A/R |
| Help-desk training and scripts | R | C | — | — | — | C | A | C | — | — | C |
| Cutover waves | R | R | C | I | I | A | C | I | I | C | I |
| Hypercare | A/R | R | R (fixes) | I | I | C | C | I | — | — | — |
| Decommission ManageEngine | C | C | — | — | A | R | — | C | C | R | — |
| Defects and gap requests into the backlog | R | C | A | I | — | C | — | — | — | — | — |

---

## 8. Product requirements: switching tooling

These are **proposed requirement IDs local to this playbook** (`MIG-##`). Map them into the
feature-parity matrix and tickets when those exist. Priority follows [ADSSP §8a]: **P0** =
needed at cutover for pilot accounts, **P1** = within the first renewal cycle. The corpus already
backs "Migration in a box" as a wedge [CV §6.1 #7], the "ME migration kit" as P0 [LAND §7.1 #10]
and switching-cost reducers as "build these, not just sell them" [AD360C §8.2].

| ID | Requirement | Covers (ME IDs) | Priority | Acceptance (draft) | Depends on / open |
|---|---|---|---|---|---|
| MIG-01 | **Read-only discovery scanner**: domains, OUs, object counts, enabled users, native AD delegation ACLs, ADAP-created audit GPOs, privileged accounts in scope. Outputs a scope and sizing sheet | ADM-135; ADAP §2.3 | P0 | Runs with read-only rights; no writes; report in < 30 min for 10k objects `[EST]` | Could double as the free posture scan door-opener [LAND §7.1 #9] |
| MIG-02 | **ManageEngine configuration adapters**, versioned per product and build: ADMP templates, rules, naming formats, roles, workflows, automations, custom reports; ADAP alert profiles, schedules, exclusions, roles; ADSSP policies; M365MP virtual tenants. Inputs: documented report exports first, read-only DB second | ADM-012–020, 097, 101, 104–133; ADA-092–101, 110, 114; ADSS-124; M365-010 | P0 (ADMP) / P1 (ADAP, ADSSP) | Imports a lab ADMP build 8043 configuration with every item classified in MIG-03 | **Lab install + schema study + EULA review** `[TODO]`; adapter contract keeps importers generic (P7) |
| MIG-03 | **Import fidelity report**: per item, exact / changed (with diff) / manual / not supported; exportable PDF/CSV for customer sign-off | All of MIG-02 | P0 | Every inventory row appears exactly once; the customer can sign it | Also a sales proof point [CV §6.2] |
| MIG-04 | **ADMP-compatible CSV import**: LDAP headers, DN-format `memberOf`/manager, `templateName` column; plus smart mapping and row-level preview | ADM-010, 011 | P0 | A customer's unmodified ADMP CSV creates the same users in dry-run | CSV/XLSX output escaping [FEAS §2.7] |
| MIG-05 | **Report crosswalk and parity pack**: ManageEngine report name → activeDIQ report, with matching names for auditor-known reports; side-by-side diff | ADM-083–097; ADA-098–101; ADSS-118–122 | P0 for the customer's top reports | For each pilot customer's top 20 reports, the diff is within the agreed tolerance | Needs a report-name inventory from Discovery |
| MIG-06 | **Scheduled-report importer**: frequency, recipients, formats, delivery mode | ADM-101; ADA-100; ADSS-122 | P0 | Schedules recreated identically; first run matches | — |
| MIG-07 | **Audit-history bridge**: syslog/CEF/Splunk HEC receiver for ADAP forwarding; CSV importers for the top ~30 ADAP reports; EVTX import; a legacy-evidence view with provenance (source, range, hash) | ADA-106, 117, 118; ADM-137 | P0 (receiver) / P1 (importers, EVTX) | Events forwarded by ADAP are searchable in activeDIQ within minutes; imported evidence is labeled as imported | Event pipeline is Phase 2 [FEAS §6.3] |
| MIG-08 | **Audit-policy detect and reuse**: read existing audit policy and SACLs; report gaps; don't re-push what exists | ADAP §2.3, §7a | P1 | No duplicate audit GPOs created on a domain where ADAP ran | — |
| MIG-09 | **Enrollment migration kit**: import the ADSSP Enrolled Users export; AD-attribute bootstrap; external-factor mapping; hardware TOTP seed import; optional hash-compatible Q&A `[UNVERIFIED]`; Graph import of Entra phone methods `[UNVERIFIED]`; progressive enrollment | ADSS-021–029 | **P0** | In a pilot OU, every user has at least one working reset factor on day one without user action | Lab check of ADSSP build 7001 schema `[TODO]` [ADSSP §9] |
| MIG-10 | **Coexistence routing and parallel-run comparator**: route users or OUs to ADSSP or activeDIQ; run automations and reports in dry-run and diff against ManageEngine results | ADM-104–115; ADSS-001–010 | P0 | Comparator flags every divergence in a seeded test; routing switch per OU in < 5 min `[EST]` | Coexistence of logon agents `[TODO lab]` |
| MIG-11 | **Agent swap kit**: MSI/GPO/Intune/SCCM packages; ManageEngine agent removal checklists (ADAP agents, ADSSP login agent and Password Sync Agent, RMP DC agent) | ADA-115; ADSS-132; ADSSP §2.2 | P1 | Documented, tested removal for each agent type | [AD360C §8.2] |
| MIG-12 | **Least-privilege setup wizard**: generate, apply and verify the ACLs each enabled feature needs; gMSA where possible | ADMP §2.3 | P0 | Install completes with no Domain Admin membership | [ADMP §7c; FEAS §2.3] |
| MIG-13 | **SSO and integration re-point**: bulk SAML metadata import; ITSM, SIEM and RADIUS re-point checklists | ADSS-073–078; ADM-142, 143, 191–198 | P1 | 10 SAML apps re-pointed in one session `[EST]` | [AD360C §8.2] |
| MIG-14 | **Job ownership lock**: every automation, schedule and notification has one owner (ManageEngine or activeDIQ); a switch flips it and records who did it and when | ADM-101, 104–108; ADA-100; ADSS-091 | P0 | activeDIQ refuses to run a job whose owner is ManageEngine | Supports P3 and rollback |
| MIG-15 | **Migration cockpit** in the admin UI: phase checklist, wave status, fidelity results, enrollment progress, rollback state | — | P1 | Customer sponsor can read status without a call | Must show real data only (CLAUDE.md rule 6) |
| MIG-16 | **Technician identity cleanup assistant**: find technician logins used by several people; map each to named people before roles are created | ADM-125–139 | P1 | Every migrated role assignment is to a named person or group | [CV §5.3] |
| MIG-17 | **ADMP REST compatibility shim** for the most-used v1/v2 endpoints, so scripts and ITSM keep working during transition | ADM-188, 189 | Proposal, evaluate | — | Legal and feasibility review `[TODO]`; may not be worth it |
| MIG-18 | **Baseline AD snapshot and rollback point** taken before the parallel run | — | P0 | Attribute-level restore of any pilot change | Phase 1 snapshots [FEAS §6.3] |

---

## 9. Open items before the first pilot

- `[TODO]` **Lab installs** of ADMP 8043, ADAP (current build) and ADSSP 7001. Study the DB
  schemas for templates, roles, workflows, alert profiles and enrollment (TOTP seeds, FIDO keys,
  Q&A hash format). Prove or kill MIG-02 and MIG-09 [ADSSP §9; ADAP Open gaps].
- `[TODO]` **EULA/legal review** of reading ManageEngine databases on the customer's behalf
  [ADAP §7a option 5].
- `[TODO]` Confirm the ADAP Free-edition read-only viewer behavior after a subscription lapses
  [ADAP Open gaps].
- `[TODO]` Lab-test credential-provider and password-filter coexistence (ADSSP and activeDIQ on
  the same endpoint or DC) [AD360C §8.2].
- `[TODO]` Confirm whether ADAP and ADSSP can export configuration natively [ADAP §7a; ADSSP §8a].
- `[TODO]` Calibrate every `[EST]` duration after pilot 1.
