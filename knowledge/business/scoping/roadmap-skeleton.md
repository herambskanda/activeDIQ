---
title: Roadmap skeleton (M1–M5)
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: heramb
---

# Roadmap skeleton: M1–M5

This is the milestone skeleton for the direction set by the CEO on 2026-10-02 (D-0001…D-0004).
The v1 feature set and the factory decisions behind it (FD-##) are in
[v1-scope-options.md](v1-scope-options.md). That file is the scope lock; this one sequences it.

Milestone IDs match the Factory Board:
- **M1 "Foundation & direction"** (current, active);
- **M2 "Core management parity — pilot-ready"**;
- **M3–M5**: the later phases. Their names below are **factory proposals**; the CEO may rename them.

**Legend**
- `[CEO-PENDING Qn]` = waits on open question *n* in v1-scope-options §8.
- `[CEO-FORK]` = a later strategic decision. The CEO does not need to answer it now; it is needed
  before that milestone's scope lock.
- `[DISCOVERY]` = settled by partner discovery answers; a factory decision.
- **Estimate** = analyst judgement (method in v1-scope-options §3.8). Sizes are factory-weeks
  (fw) at an `[ASSUMPTION]` of 10 FEAS engineer-weeks per factory-week. They are re-baselined
  after ~4 build weeks.
- Epic labels (`E2.3` etc.) are local to this file. The Board assigns ticket IDs.
- Demo criteria are proposals. In pilots, the partner sets the thresholds (PILOT "Success
  criteria").

**Sources.** The same key as v1-scope-options.md:
- [MATRIX](../competitive-analysis/feature-parity-matrix.md)
- [STRAT](../strategy/product-strategy.md)
- [ENH](../strategy/enhancement-catalog.md)
- [ADM](../market-research/manageengine-admanager-plus.md)
- [ADA](../market-research/manageengine-adaudit-plus.md)
- [ADSS](../market-research/manageengine-adselfservice-plus.md)
- [CV](../market-research/manageengine-ad-customer-voice-and-security.md)
- [LAND](../competitive-analysis/ad-management-market-landscape.md)
- [FEAS](../../development/architecture/build-feasibility/ad-technical-feasibility.md)
- [MIG](../service/manageengine-migration-playbook.md)
- [PILOT](../service/pilot-offer-outline.md)

---

## 0. At a glance

| Milestone | Phase | Goal the CEO judges in the demo | ME product replaceable at exit | Size (Estimate) | Blocked by |
|---|---|---|---|---|---|
| **M1 Foundation & direction** *(active)* | Phase 0 | "The architecture is decided, the lab is real, the product has a look, and we know what our partners use" | — | 8–10 fw | Q1 (discovery), Q5 (spend/legal) |
| **M2 Core management parity — pilot-ready** | P1 + ADMP P2 pulls | "A partner's AD team can do its ADManager Plus work in activeDIQ, faster, with preview and undo, and could switch ADMP off" | **ADManager Plus** (conditions: v1-scope §4) | 25–40 fw | Q2, Q3, Q4 before the first pilot |
| M3 *Change auditing & closed loop* (proposed name) | P2 (rest) | "Any change to AD or Entra, made anywhere, is seen, attributed and can be undone, and ADAP's history comes with us" | **ADAudit Plus** (except NAS, P4 tail) | ≈ 25–45 fw | DC-agent acceptance `[DISCOVERY]`; agent module contract (D-0003) |
| M4 *Self-service & MFA* (proposed name) | P3 | "Users fix their own passwords from the logon screen, nobody re-enrolls, and native password changes obey our policy" | **ADSelfService Plus** (except P4 items) | ≈ 30–50 fw | LSA signing lead time; IdP fork `[CEO-FORK]` |
| M5 *Recovery, Exchange & breadth* (proposed name) | P4 | "The long tail our partners actually use is covered, and the last ME product goes" | RMP, M365MP, ERP, then the AD360 shell | ≈ 25–50 fw, trimmed by discovery | SaaS/MSP timing `[CEO-FORK]` |

Phase mapping (FD-09): M2 = matrix P1 plus the pulls in v1-scope §6; M3 = rest of P2; M4 = P3;
M5 = P4.

Row counts per milestone (must / should / could), from the CSV:

| | M2 | M3 | M4 | M5 |
|---|---|---|---|---|
| Rows | 142 (103 / 37 / 2), plus 3 conditional | 130 (55 / 71 / 4) | 120 (60 / 55 / 5) | 171 (2 / 60 / 109) |
| Windows-native rows · XL rows | 0 · 0 | 44 · 0 | 19 · 7 | 51 · 3 |

---

## M1 — Foundation & direction *(active)*

**Goal (demo).** The CEO sees four things:
1. the binding architecture decisions;
2. a **walking skeleton**: the real UI calls the real API, which reads a real lab DC under WS2025
   hardening with no Domain Admin;
3. the activeDIQ design direction on the skenzeriq design system;
4. what the first partners actually run.

**Epics**

| Epic | Content | Source |
|---|---|---|
| E1.1 ADRs | Ratify **ADR-0001 technology stack** (status `proposed`, ticket T-0002). Also: a **deployment-profiles ADR** (Windows installer + Linux/Docker, one update path, `tenant_id` + RLS from migration 1, per D-0002); tenancy/RBAC; safe primitives + lint rules; job engine phases; directory connector and LDAP security; release train and signing (ENH-07); extension points; **platform-agent module contract** (D-0003: drafted in M1, ratified before M3, agreed with the UEM owners) | FEAS §4.3, §4.5, §4.6, §6.1; CLAUDE.md rule 4 |
| E1.2 Lab | Samba 4 compose for CI. A Terraform/Packer Azure lab with WS2016–WS2025 DCs (`[CEO-PENDING Q5]` spend). An Entra/M365 test tenant. A golden-fixture recorder. A Windows CI runner | FEAS §5.3–5.7 |
| E1.3 ME lab installs | ADMP build 8043 first, then ADAP and ADSSP. Study the export and DB formats for the importers. Counsel review is `[CEO-PENDING Q5]` | MIG §9 |
| E1.4 v1-gating spikes (**exit gates**, FD-10) | (a) LDAP bind under signing + CBT "Always" on WS2025 and Samba with no 2887/3039/3074 events. (b) Graph + EXO cert-auth smoke test from a Linux container. (c) Effective-permissions golden tests for ENH-08. (d) Windows LAPS decryption from Linux `[UNVERIFIED]` | FEAS §6.2, §6.3 Phase 0, §1.1 |
| E1.5 Later long-pole spikes (**started, not gating M1**) | Password filter in audit mode; credential provider V2; event ingest at 5k eps synthetic; GPO parsing of 50 real GPOs. **Microsoft LSA plug-in signing enrolment in week 1** `[CEO-PENDING Q5]` | FEAS §6.2 |
| E1.6 Foundation skeletons | Tenant + RBAC core, safe-primitive library, directory connector, job engine (dry-run/diff/approve/execute/verify), event-pipeline skeleton, public API + OpenAPI codegen | FEAS §6.1 #1–5, #7 |
| E1.7 Design direction | activeDIQ on the skenzeriq tokens. A task-first console concept (ENH-01). Interaction budgets for the top-20 admin and help-desk tasks. The help-desk reset + caller-verification flow (ENH-09). A Storybook prototype; fixtures are allowed only in Storybook and tests (factory/OPERATING-MODEL.md quality rules) | STRAT §11, §13 Q7; `../design-system/README.md` |
| E1.8 UX baseline | Time 10 common tasks on the lab ADMP 8043 install. This is the "before" for every later demo, and it re-measures ADM §4.2's indicative page weights `[TODO]` | CV §6.2; ADM §4.2 |
| E1.9 Partner discovery | Send the [discovery questionnaire](../partnerships/partner-discovery-questionnaire.md) to the named accounts `[CEO-PENDING Q1]`. File profiles in `partnerships/`. Re-weight the v1 must rows from real usage | MATRIX research gap #1; STRAT §10.1 |
| E1.10 Security programme start | Threat model v0, SBOM in CI, disclosure policy draft (ENH-10). Choose the pentest vendor `[CEO-PENDING Q4]` | CV §6.2; FEAS §6.3 |

**Main parity IDs.** No parity features ship in M1. The foundations underpin ADM-003/004 (search
and explorer, in the skeleton), ADM-212 (domain connection) and I360-002 (AD sync).

**Demo criteria**
1. ADR-0001 and the deployment ADR are `ratified`, and each has a fitness function defined.
2. In the walking skeleton, typing a name in the real UI finds the real user on a WS2025 lab DC
   with LDAP signing and CBT enforced. The service account has no Domain Admin membership.
3. E1.4 gates are green, or each has an explicit fallback decision (FEAS §6.3 Phase-0 exit rule).
4. A clickable design-direction prototype exists for the console and the help-desk reset flow,
   with interaction budgets stated. The CEO accepts or redirects the look.
5. The ADMP baseline task timings are recorded.
6. Discovery is back from at least one account `[CEO-PENDING Q1]`, and v1-scope-options moves to
   `review`.

---

## M2 — Core management parity — pilot-ready

**Goal (demo).** A partner's AD team can do its ADManager Plus work in activeDIQ:
- faster, measured against the M1 baseline;
- with every change previewed and undoable;
- across AD and Entra/M365.

At exit, a partner could switch ADMP off, under the conditions in v1-scope §4.

**Epics**

| Epic | Content | Main parity IDs | ENH / MIG |
|---|---|---|---|
| E2.1 Console and search | Task-first console, universal search with inline actions, command palette, AD Explorer, dashboard, localization framework | ADM-001–004, 007 | ENH-01 |
| E2.2 Directory objects | Users, groups, computers, contacts, OUs; BitLocker/LAPS; restore deleted users; GPO links and scope | ADM-008, 016, 020–025, 033, 038, 048–051, 055–062, 073, 077 | — |
| E2.3 Bulk, CSV and templates | Bulk create/modify, smart CSV import (ADMP format accepted), creation and modification templates, rules, naming formats | ADM-010–015, 017, 018, 034, 037 | ENH-14 (via ADM-011); MIG-04 |
| E2.4 Preview, undo and history | Diff before every write; undo from the audit record; snapshot foundation; object change history (activeDIQ changes + DirSync deltas, without "who" for native changes) | ADM-005, 033, 034, 098 | ENH-04; MIG-18 |
| E2.5 Delegation and help desk | RBAC with OU/group/site scopes, cross-domain; help-desk roles; per-technician attribution; reset console with caller verification | ADM-125–136; I360-020 | ENH-09 |
| E2.6 Reports | Prebuilt library, compliance sets, builder, scheduling, export, act-on-results, report delegation | ADM-083–087, 089, 092, 093, 096–103 | ENH-05; MIG-05, MIG-06 |
| E2.7 Hybrid via Graph | Tenant onboarding, M365 at creation, cloud-only accounts, bulk M365, licences, account actions, groups, source-of-authority view | ADM-009, 027, 131, 159–162, 164, 169; M365-005, 007; I360-003 | — |
| E2.8 Workflow and approvals | Request → review → approve → execute; roles; assigning rules; SLAs; manager approvers | ADM-116–121 | — |
| E2.9 Automation and JML | Scheduled automation, policies, controlled automation; HR/DB/CSV joiners; movers; leaver disable/delete policies; offboarding blocks (except NTFS); expiry reminders; cleanup | ADM-039–045, 047, 104–107, 114, 146–148; ADSS-091 | MIG-14 |
| E2.10 Integrations and API | Unmetered public REST API; ServiceNow; ServiceDesk Plus; SIEM forwarding; notifications; mail/SMS | ADM-188–192, 198, 204, 205 | (ENH-11 API half) |
| E2.11 Migration kit (ADMP) | Discovery scanner; ADMP adapters; fidelity report; parallel-run comparator; technician identity cleanup | — | ENH-02; MIG-01–03, 10, 16 |
| E2.12 Platform and updates | Windows installer + Linux/Docker profiles (D-0002); HA; signed staged automatic updates with rollback; product DB backup; diagnostics; retention/privacy | ADM-158, 206, 207, 209, 210, 213; RMP-046 | ENH-07 |
| E2.13 Tier-0 proof | Console SSO and mandatory admin MFA; login hardening; hardening score; least-privilege wizard; trust center; external pentest | ADM-141–145, 208, 212; ADA-111, 116; ADSS-126 | ENH-08 (MIG-12), ENH-10 |
| E2.14 *(conditional)* Exchange helper | PowerShell-remoting helper for Exchange at creation and remote mailboxes. Built only if a pilot has on-prem or hybrid Exchange (FD-04) | ADM-026, 070 | — |

**Internal demo checkpoints.** M2 is the largest milestone, so the CEO judges it at four
checkpoints before the exit demo. The order is reads before writes; the job engine before bulk;
importers after the features they import into (ENH-02 dependency).

| Checkpoint | Demo the CEO judges | Epics |
|---|---|---|
| **2a Find and report** | Search any object across domains and see its history. Run the partner's most-used ADMP reports and export or schedule them | E2.1, E2.6 (library, export, scheduling), E2.4 (history) |
| **2b Manage safely** | Create, modify and bulk-change with preview and undo. Help-desk reset + unlock in ≤3 interactions, with caller verification, by a technician with no AD rights | E2.2–E2.5, E2.13 (console security) |
| **2c Hybrid and import** | One flow creates an AD user with M365 licence and groups. A lab ADMP 8043 configuration is imported, with a fidelity report. Report builder. **Candidate first-pilot start** `[CEO-PENDING Q3]` after a pentest of this build | E2.6 (builder), E2.7, E2.11 |
| **2d Automate and approve** | A workflow with manager approval; an HR-driven joiner; a leaver policy with preview; a ServiceNow ticket executing a change; job-ownership switch from ADMP to activeDIQ | E2.8–E2.10, MIG-14 |
| **Exit: pilot-ready** | Everything below | E2.12, E2.13, (E2.14) |

**Exit demo criteria**
1. **POC #1**: 20-user bulk onboarding with approval in under 5 minutes (LAND §6, STRAT §10.2).
2. **POC #3**: a verified-caller reset by a tier-1 agent with no AD rights; the verification is
   in the audit trail.
3. **POC #4, directory scope**: an auditor question about directory state or activeDIQ-made
   changes is answered in under 1 minute. The audit-event version is M3.
4. Reset + unlock in ≤3 interactions (ADM §7c). The M1 baseline task set is timed in activeDIQ
   and compared task by task with ADMP 8043.
5. A bulk modification is undone and the prior values are restored. Attributes that cannot be
   reverted are flagged **before** execution.
6. The lab ADMP 8043 configuration is imported, and every item is classified in the fidelity
   report (MIG-02/03 acceptance).
7. Install completes with no Domain Admin membership (MIG-12 acceptance).
8. On both the Windows and the Docker profile, an update applies automatically, and a
   deliberately bad update rolls back. Both also work with HA enabled.
9. FEAS Phase-1 exit: runs against WS2016–WS2025 with signing/CBT enforced, and the external
   pentest is passed.
10. No dead buttons and no fake data: QA clicks every control (CLAUDE.md rule 6).

**Pending decisions in M2**
- Q1 settles E2.14 and the ADMP + ADSSP handling (v1-scope §4 #2).
- Q2 (pricing and pilot commercials) and Q4 (security-evidence budget) are needed before any pilot
  offer goes out.
- Q3 decides whether the pilot starts at 2c or at exit.

---

## M3 — *Change auditing & closed loop* (proposed name)

**Goal (demo).** A change made in ADUC, PowerShell or the Entra portal shows up in activeDIQ with
who, what and before/after. A Tier-0 change is reverted from the alert. The partner's ADAP history
is searchable in activeDIQ. A partner can switch ADAudit Plus off.

**Epics**
- **E3.1 DC event collection** as a module of the shared platform agent (D-0003; FEAS §6.1 #6),
  or agentless WEF where customers refuse DC agents `[DISCOVERY]` (FEAS App. A #2). Sustains
  ≈3k events/s per collector (FEAS §6.2).
- **E3.2 Change attribution ("who")** and AD change auditing with old/new values in every tier.
- **E3.3 Entra sign-in and directory auditing**, hybrid correlation, long retention.
- **E3.4 Logon, lockout and privileged monitoring.** Includes the lockout analyzer, which is the
  basis for ENH-13 (a candidate, not committed).
- **E3.5 Alerts, response, audit reports, compliance packs, archive tiers, SIEM, EVTX import.**
- **E3.6 File-server agent**: file auditing, NTFS management and reports, the ADM-045 NTFS block.
- **E3.7 AD backup, Backup Explorer, quick recovery and rollback** (RMP AD rows).
- **E3.8 Remaining ADMP P2**: event-driven automation, webhooks and scripts, dynamic and time-bound
  groups, GPMC-format GPO reports, other ITSM/HCM connectors, risk assessment.
- **E3.9 Migration kit (ADAP)**: history bridge (ENH-06; MIG-07, MIG-08), ADAP adapters (MIG-02),
  agent swap kit (MIG-11).
- **E3.10 Sequenced enhancements** (D-0004): ENH-11 (webhooks, PowerShell module, read-only MCP),
  then ENH-22 (detect → attribute → revert), plus ENH-12 investigation-first audit UX.

**Main parity IDs**
- ADA-001–010, 012, 013, 021, 023–028, 037, 038, 041, 042, 046, 047, 049, 054, 055, 057, 063,
  072, 092–102, 106, 110, 114, 115, 117–119;
- ADM-026/070 (if not in M2), 045 (NTFS block), 052, 053, 078–082, 090, 091, 108–113, 149–153,
  174, 176, 193–195;
- RMP P2 rows.

**Demo criteria**
1. **POC #2**: a malicious Tier-0 change is detected and reverted (LAND §6).
2. **POC #5**: object restore plus a recovery plan.
3. **POC #4, full**: an auditor query over audit events is answered in under 1 minute.
4. Events forwarded by ADAP are searchable within minutes, and imported evidence is labelled as
   imported (MIG-07 acceptance).
5. 3k events/s sustained per collector (FEAS Phase-2 exit).
6. No duplicate audit GPOs on a domain where ADAP ran (MIG-08).

**Pending decisions**
- DC-agent acceptance per account `[DISCOVERY]`.
- Ratify the agent module contract with the UEM owners (D-0003).
- NAS auditing (ADA-058/059) is pulled forward only if a pilot needs it `[DISCOVERY]`.

---

## M4 — *Self-service & MFA* (proposed name)

**Goal (demo).** A user resets a forgotten password from the Windows logon screen. Pilot users
have a working reset factor on day one without enrolling. A password set natively in ADUC is
rejected by our policy. A partner can switch ADSelfService Plus off.

**Epics**
- **E4.1 Web SSPR portal**: reset, unlock, change, mobile browser, Entra SSPR.
- **E4.2 Enrollment and carry-over** (ENH-03; MIG-09). Progressive enrollment, OU-by-OU
  coexistence with ADSSP.
- **E4.3 Authenticators and MFA policy**: TOTP, FIDO2, email/SMS, push, Duo/RSA/RADIUS.
- **E4.4 Password filter GA**: native-change enforcement, breached-password ban (ENH-27 offline
  corpus is a candidate). Gated by **LSA plug-in signing** (FEAS §6.2).
- **E4.5 Credential provider GA**: logon-screen reset and unlock, endpoint MFA (logon, RDP, UAC,
  offline), cached-credential update. Expert human review of AI-written LSASS/LogonUI code
  (STRAT R4).
- **E4.6 RADIUS/VPN MFA** (ENH-24 candidate; MSCHAPv2 caveat, FEAS App. A #7).
- **E4.7 Native self-service approvals and help-desk-assisted reset** (ADSS-115/116 = ADM-124).
  This removes the ADMP dependency that ADSSP has (ADSS W9).
- **E4.8 SSO/IdP**, to the depth ADSSP switchers use `[CEO-FORK: build an IdP or integrate]`
  (MATRIX research gap #2; STRAT §8).
- **E4.9 macOS/Linux login** (XL; FEAS App. A #8).
- **E4.10 ENH-20 guard-railed AI operator**, after USP-2 is proven at a pilot (ENH §3.3). Its
  posture is `[CEO-FORK]` (STRAT §13 Q5).

**Main parity IDs.** The 56 ADSS P3 must rows, including:
- ADSS-001–004, 006, 009–011, 014, 016, 017;
- ADSS-021, 023–025, 027–029, 031–036, 038, 040, 043, 046–048;
- ADSS-051, 053–055, 058–061, 068, 069;
- ADSS-097, 098, 100–103, 116, 118–120, 122–125, 128, 132;
- I360-013–015, 019.

**Demo criteria**
1. In a pilot OU, every user has a working reset factor on day one without user action (MIG-09
   acceptance; PILOT criterion 7).
2. The filter is signed and loads under RunAsPPL, and the credential provider passes a red-team
   exercise (FEAS Phase-2 exit).
3. A verified-caller reset uses push to an enrolled device, which upgrades the ENH-09 factors.
4. No MFA is skipped when over a licence limit or during an outage (STRAT §7.2 #3).

**Pending decisions**
- `[CEO-FORK]` IdP build vs integrate, and AI posture.
- The LSA signing lead time (enrolment started in M1, Q5).

---

## M5 — *Recovery, Exchange & breadth* (proposed name)

**Goal (demo).** The remaining features the partners actually use are covered, so they can
switch off the last ME products (RMP, M365MP, ERP) and the AD360 shell.

**Epics**
- **E5.1 Entra, M365, Exchange and DNS recovery** (RMP P4 rows).
- **E5.2 Exchange on-prem and Exchange Online mailbox management**, M365 and Exchange reports,
  Teams. Uses the .NET/PowerShell sidecar (FEAS §0, §1.9).
- **E5.3 GPO editing** (XL; FEAS §6.2).
- **E5.4 Governance**: access certification and entitlements (ADM-177–180); ENH-26 SoD is a
  candidate.
- **E5.5 Long tail, re-triaged per lead**: Google Workspace, NAS auditing, mobile, AD migration,
  deferred rows.
- **E5.6 SaaS profile launch and MSP** `[CEO-FORK]`. D-0002 says self-hosted first; the core has
  been SaaS-ready since M1.
- **E5.7 Convergence with the common skenzeriq core** (D-0003, "later").

**Main parity IDs**
- ADM-054, 063–069, 071, 072, 074–076, 088, 094, 165–168, 175, 177–180;
- ADA-058, 059 and the ADA P4 rows;
- RMP P4 rows; ERP-001–013; M365 P4 rows.

**Demo criteria**
1. FEAS Phase-3 exit: parity of at least 90% of the features customers actually use, measured as
   the share of discovery-weighted must rows that are done (MATRIX "Exit gate").
2. Each pilot account has switched off every ME product it planned to retire (STRAT §1 north-star
   metric).

---

## Cross-milestone threads

| Thread | Rule |
|---|---|
| Security evidence | A pentest at every milestone exit that adds attack surface (proposal). SBOM per release. Same-day advisories (ENH-10). Never characterize ME's CVEs (CV §6.3) |
| UX benchmark | Every milestone demo re-times the M1 task set against the ME baseline. "Easy" is never claimed without a number (STRAT §7.2 #5) |
| Migration kit | Grows by one ME product per milestone: ADMP in M2, ADAP in M3, ADSSP in M4 (ENH-02/06/03; MIG §8) |
| Matrix upkeep | Each milestone scope lock updates `phase` in the CSV for the rows it pulls or pushes, and logs the reason (MATRIX "How the matrix feeds tickets") |
| Partner names | Only in `knowledge/business/partnerships/` (CLAUDE.md rule 8) |

## Decision calendar

| Decision | Owner | Needed by | Affects |
|---|---|---|---|
| Q1 pilot accounts + ME footprint | CEO | Early M1 | E1.9, E2.14, ADMP + ADSSP handling, NAS pull-forward, evidence-pack regulator |
| Q5 M1 spend and legal (code signing, LSA enrolment, Azure lab, counsel) | CEO | M1 week 1 | E1.2, E1.3, E1.5, E2.12 |
| Q4 security-evidence investment | CEO | Mid-M2 (to book the pentest) | E2.13, pilot entry gate |
| Q3 pilot start at 2c or at M2 exit | CEO | Before checkpoint 2c | First pilot date |
| Q2 pricing and pilot commercials | CEO | Before any pilot offer leaves the building | PILOT, conversion terms |
| IdP build vs integrate | CEO `[CEO-FORK]` | Before the M4 scope lock | E4.8 |
| AI posture for ENH-20 | CEO `[CEO-FORK]` | Before the M4 scope lock | E4.10 |
| SaaS launch timing; MSP channel | CEO `[CEO-FORK]` | Before the M5 scope lock | E5.6 |
| DC-agent vs WEF per account | Factory `[DISCOVERY]` | Before the M3 scope lock | E3.1 |
| Exchange helper in M2 | Factory `[DISCOVERY]` (FD-04) | Checkpoint 2b | E2.14 |
