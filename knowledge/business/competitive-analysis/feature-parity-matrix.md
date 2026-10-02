---
title: Feature-parity matrix — ManageEngine AD suite vs activeDIQ
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: heramb
---

# Feature-parity matrix — ManageEngine AD suite vs activeDIQ

This file is the readable view of `feature-parity-matrix.csv` (same folder). The CSV has one row for
each of the **578 ManageEngine features** in the research inventories, keyed by the
research IDs. It records what a switching customer needs from activeDIQ, how we answer each feature
and when we build it. It is a **draft**: every judgment here comes from the draft research corpus
dated 2026-10-02 and should be re-checked against discovery with the CEO's warm accounts before
scope is locked.

The CSV has no YAML frontmatter because a header block would make it invalid CSV. This file's
frontmatter (title, dates, status, owner) governs both files. Change them together.

## Key conclusions

1. **220 of 578 features are "must"** for a switching customer. Parity is a large build, and most of
   it is plain parity (347 parity rows). We differentiate through 90 enhance rows and 55 leapfrog
   rows, not by skipping features.
2. **The leapfrog is mostly experience and architecture, not new features.** The strongest evidence
   is the UI and navigation, the #1 complaint (≈28 of ~152 coded reviews, CV doc §2.2 X1). Next come
   report customization (≈17, X2) and manual upgrades (≈16, X3). Then the AD360 seams: one console,
   one login, one RBAC model and one update (AD360 doc §8.3).
3. **Switching cost, not feature count, decides the deal.** The biggest switching levers have no
   ManageEngine feature ID: config importers, the ADAudit Plus history bridge, ADSelfService Plus
   enrollment migration and the agent swap kit. They are tracked separately (see "Requirements with
   no ManageEngine ID").
4. **The long poles are Windows-native**: the DC password filter (LSA signing), the credential
   provider, DC event collection at scale, GPO settings parsing and the effective-permissions
   engine (FEAS doc §6.2). They gate P2 and P3, so their spikes start in Phase 0. P1 has no
   Windows-resident dependency at all.
5. **Two strategic forks change the matrix.** Whether to build an IdP/SSO (LAND doc §7.2 says
   don't; ADSS doc §8a lists SSO as P1), and the deployment model (the stack/deployment ADR is
   pending). Both are CEO decisions (see "Research gaps").

## How to read it

**Sources** (all under `knowledge/`). Short names are used in the `evidence` column:

| Short name | File |
|---|---|
| ADM doc | `business/market-research/manageengine-admanager-plus.md` (ADM-001…213) |
| ADA doc | `business/market-research/manageengine-adaudit-plus.md` (ADA-001…120) |
| ADSS doc | `business/market-research/manageengine-adselfservice-plus.md` (ADSS-001…138) |
| AD360 doc | `business/market-research/manageengine-ad360-suite-and-commercials.md` (RMP-001…047 in §2.2, M365-001…019 in §3.1, ERP-001…017 in §3.2, I360-001…024 in §1.5) |
| CV doc | `business/market-research/manageengine-ad-customer-voice-and-security.md` |
| LAND doc | `business/competitive-analysis/ad-management-market-landscape.md` |
| FEAS doc | `development/architecture/build-feasibility/ad-technical-feasibility.md` |

In the evidence column, `W#` is a numbered weakness in that product doc and `L#` is an ADSS doc
leapfrog item. `§7a`/`§7b`/`§7c` (ADSS: `§8a`/`§8b`) are the parity-vs-leapfrog sections. `X#` is a
CV doc pain theme.

**Scope note.** There are no `AD360-###` IDs in the corpus. AD360 is an integration shell over
separately installed products (AD360 doc §1.3). The AD360-family inventory that does carry IDs is
**Identity360 (`I360-###`, AD360 doc §1.5)**, ManageEngine's SaaS track, so those 24 rows are
included. Most of them duplicate an ADM or ADSS row and say so in `notes`. The AD360 shell's own
capabilities (SSO between modules, central technicians, unified reports) are covered by the
architecture leapfrogs below, not by rows.

**Columns.**

| Column | Meaning |
|---|---|
| `id` … `me_edition` | Copied from the research inventory. Descriptions and editions keep the source's `[UNVERIFIED]` tags. `n/s` = vendor does not say. |
| `importance` | **must**: table stakes for a switching customer (daily use, core workflow, or repeatedly cited in reviews or in a research doc's table-stakes list) · **should** · **could** · **wont** |
| `stance` | **parity** · **enhance** (parity plus a concrete improvement) · **leapfrog** (a materially better approach) · **defer** (parked; re-triage per lead) · **skip** (reason in `notes`) |
| `enhancement` | ≤ 15 words, for enhance/leapfrog only. These are *our proposals*, not ManageEngine facts. |
| `complexity` | S/M/L/XL. Taken from FEAS doc §1 where the evidence column cites `FEAS doc §1.x`; otherwise an **analyst estimate**. `-` = not applicable. |
| `windows_native` | **Y** if the feature needs a Windows-resident component (DC agent, password filter, credential provider, file-server agent, GPMC/Exchange PowerShell helper, IIS module). macOS/Linux-native agents are **N**, with a note. |
| `phase` | **P1** core management, reporting and delegation (pilot-ready parity) · **P2** workflows, automation and change auditing · **P3** self-service password, MFA and SSO · **P4** recovery, M365/Exchange and advanced security · `-` for skip rows. Defer rows are parked in P4. |
| `notes` | Reasons, dependencies, duplicates ("Same capability as …: build once"), and `[TODO]`/`[UNVERIFIED]` carried from the source. |

**Importance and phase are independent.** "Must" means a customer cannot retire that ManageEngine
product without it. Phase is build order. For example, SSPR rows are "must" but P3.

**Where phase deviates from the phase labels, and why** (dependency and customer value):

- **Entra/M365 identity basics are pulled into P1**: tenant onboarding, licences, groups, account
  actions and M365 at creation (ADM-027, 159, 161, 162, 164, 169; M365-005, 007; I360-003). Hybrid
  provisioning is day-one for switchers (ADM doc §7a; CV doc X5). It needs only Graph, with no
  Windows component (FEAS doc §1.9). Exchange Online mailbox work stays in P4 because it needs the
  PowerShell sidecar (FEAS doc §1.9).
- **Entra sign-in and directory auditing are pulled into P2** (ADA-046, 047, 049, 054), because ADA
  doc §7a treats them as table stakes for hybrid estates.
- **AD snapshots, attribute revert and AD rollback are in P2, not P4** (ADM-149–153, ADA-022/090/091,
  most AD rows of RMP). DirSync snapshots are foundation work anyway (FEAS doc §6.3 Phase 1). The
  closed loop of detect, diff and revert is a top wedge (ADA doc §7c#1; LAND doc §7.1#4). P4 keeps
  Entra, M365 and DNS recovery.
- **The detection catalogue v1 (ADA-080) and posture checks (ADM-174) are in P2.** They ride on the
  P2 event pipeline and on LDAP-only checks respectively (FEAS doc §1.5.2, §6.3).
- **Password and account expiry notifications are in P2** (ADM-047, ADSS-091–096). They are cheap and
  a hygiene feature (ADSS doc §8a).
- **Hybrid remote mailbox (ADM-026, ADM-070) is in P2** with joiner/leaver automation (ADM doc §7a).
- **Two "must" rows remain in P4**: NetApp and Dell/EMC NAS auditing (ADA-058, ADA-059). ADA doc §7a
  makes them must only for leads that run those NAS, so confirm per lead and pull them forward if a
  pilot account needs them.
- **Timing differs from FEAS doc §6.3.** That roadmap puts the SSPR web portal in its Phase 1, and
  the password filter and credential provider in its Phase 2. The matrix keeps them in P3 to match
  the CEO-facing phase labels. The web portal (ADSS-001–004) can move earlier at low cost.
  Whichever ordering wins, the long-pole spikes start in Phase 0.

## Totals

**Product × importance**

| Product | must | should | could | wont | Total |
|---|---|---|---|---|---|
| ADManager Plus (ADM) | 88 | 77 | 46 | 2 | 213 |
| ADAudit Plus (ADA) | 54 | 33 | 28 | 5 | 120 |
| ADSelfService Plus (ADSS) | 60 | 59 | 19 | 0 | 138 |
| RecoveryManager Plus (RMP) | 5 | 25 | 16 | 1 | 47 |
| M365 Manager Plus (M365) | 3 | 11 | 5 | 0 | 19 |
| Exchange Reporter Plus (ERP) | 2 | 6 | 6 | 3 | 17 |
| Identity360 (AD360 Cloud) (I360) | 8 | 12 | 2 | 2 | 24 |
| **Total** | 220 | 223 | 122 | 13 | **578** |

**Product × stance**

| Product | parity | enhance | leapfrog | defer | skip | Total |
|---|---|---|---|---|---|---|
| ADManager Plus (ADM) | 124 | 44 | 20 | 23 | 2 | 213 |
| ADAudit Plus (ADA) | 62 | 22 | 14 | 17 | 5 | 120 |
| ADSelfService Plus (ADSS) | 95 | 20 | 12 | 11 | 0 | 138 |
| RecoveryManager Plus (RMP) | 25 | 2 | 8 | 9 | 3 | 47 |
| M365 Manager Plus (M365) | 13 | 2 | 0 | 4 | 0 | 19 |
| Exchange Reporter Plus (ERP) | 9 | 0 | 0 | 5 | 3 | 17 |
| Identity360 (AD360 Cloud) (I360) | 19 | 0 | 1 | 2 | 2 | 24 |
| **Total** | 347 | 90 | 55 | 71 | 15 | **578** |

**Product × phase**

| Product | P1 | P2 | P3 | P4 | n/a (skip) | Total |
|---|---|---|---|---|---|---|
| ADManager Plus (ADM) | 96 | 61 | 2 | 52 | 2 | 213 |
| ADAudit Plus (ADA) | 3 | 62 | 0 | 50 | 5 | 120 |
| ADSelfService Plus (ADSS) | 4 | 6 | 108 | 20 | 0 | 138 |
| RecoveryManager Plus (RMP) | 4 | 20 | 0 | 20 | 3 | 47 |
| M365 Manager Plus (M365) | 3 | 3 | 0 | 13 | 0 | 19 |
| Exchange Reporter Plus (ERP) | 2 | 0 | 0 | 12 | 3 | 17 |
| Identity360 (AD360 Cloud) (I360) | 5 | 3 | 10 | 4 | 2 | 24 |
| **Total** | 117 | 155 | 120 | 171 | 15 | **578** |

**Phase × importance**

| Phase | must | should | could | wont | Total |
|---|---|---|---|---|---|
| P1 | 83 | 32 | 2 | 0 | 117 |
| P2 | 75 | 76 | 4 | 0 | 155 |
| P3 | 60 | 55 | 5 | 0 | 120 |
| P4 | 2 | 60 | 109 | 0 | 171 |
| n/a (skip) | 0 | 0 | 2 | 13 | 15 |
| **Total** | 220 | 223 | 122 | 13 | **578** |

**Phase × stance**

| Phase | parity | enhance | leapfrog | defer | skip | Total |
|---|---|---|---|---|---|---|
| P1 | 75 | 25 | 17 | 0 | 0 | 117 |
| P2 | 95 | 36 | 24 | 0 | 0 | 155 |
| P3 | 92 | 19 | 9 | 0 | 0 | 120 |
| P4 | 85 | 10 | 5 | 71 | 0 | 171 |
| n/a (skip) | 0 | 0 | 0 | 0 | 15 | 15 |
| **Total** | 347 | 90 | 55 | 71 | 15 | **578** |

**Phase × windows_native**

| Phase | Y | N | Total |
|---|---|---|---|
| P1 | 0 | 117 | 117 |
| P2 | 44 | 111 | 155 |
| P3 | 21 | 99 | 120 |
| P4 | 52 | 119 | 171 |
| n/a (skip) | 9 | 6 | 15 |
| **Total** | 126 | 452 | **578** |

**Reading the totals.**
- P1 (117 rows, 83 must) is the ADManager Plus core plus Entra basics: enough to pilot as an ADMP
  replacement. **It needs no Windows-resident component**: everything runs over LDAP, SMB and
  Graph (FEAS doc §1.1, §1.9), so a pilot does not wait on the long poles.
- P2 (155 rows, 75 must) is the heaviest phase. It is where the event pipeline, workflows and
  automation all land, and most of its Windows-native work is the DC agent.
- P3 (120 rows, 60 must) is almost all ADSelfService Plus.
- P4 (171 rows) is mostly should/could, plus the 71 deferred rows.
- 51 rows are duplicates across ManageEngine SKUs ("Same capability as …"). The real build surface
  is therefore smaller than 578. The duplication is the SKU sprawl that AD360 doc §4.7 documents.

## Must list per product

220 rows. Stance abbreviations: par = parity, enh = enhance, lea = leapfrog. Win = windows_native.
Full descriptions, enhancements and evidence are in the CSV.

### ADManager Plus — 88 must rows

| ID | Feature | Stance | Cx | Win | Phase |
|---|---|---|---|---|---|
| ADM-001 | Tabbed web console | lea | M | N | P1 |
| ADM-003 | Global object search | lea | M | N | P1 |
| ADM-004 | AD Explorer | enh | M | N | P1 |
| ADM-005 | Object change history | lea | M | N | P1 |
| ADM-008 | Create single user | enh | M | N | P1 |
| ADM-010 | Bulk user creation wizard | enh | M | N | P1 |
| ADM-011 | CSV import (create/modify) | lea | M | N | P1 |
| ADM-012 | User creation templates | enh | M | N | P1 |
| ADM-013 | Creation rules | par | M | N | P1 |
| ADM-015 | User modification templates | par | M | N | P1 |
| ADM-016 | Copy user attributes | par | S | N | P1 |
| ADM-017 | Naming formats | enh | S | N | P1 |
| ADM-018 | Advanced (conditional) naming | par | S | N | P1 |
| ADM-020 | Duplicate prevention | par | S | N | P1 |
| ADM-021 | Random password policy | par | S | N | P1 |
| ADM-022 | Password options | enh | S | N | P1 |
| ADM-023 | Home and profile folders | par | M | N | P1 |
| ADM-024 | Account controls | par | S | N | P1 |
| ADM-026 | Exchange at creation | par | L | Y | P2 |
| ADM-027 | M365 at creation | enh | M | N | P1 |
| ADM-033 | Modify single user | enh | M | N | P1 |
| ADM-034 | Bulk user modification | enh | M | N | P1 |
| ADM-038 | Restore deleted users | par | M | N | P1 |
| ADM-039 | HR-driven joiners | enh | L | N | P2 |
| ADM-041 | CSV-drop provisioning | par | S | N | P2 |
| ADM-042 | Movers | enh | M | N | P2 |
| ADM-043 | Disable policy (leaver preset) | enh | M | N | P2 |
| ADM-044 | Delete policy | par | M | N | P2 |
| ADM-045 | Offboarding orchestration blocks | par | L | Y | P2 |
| ADM-047 | Password-expiry reminders | par | S | N | P2 |
| ADM-048 | Group create, modify, delete | par | M | N | P1 |
| ADM-050 | Membership management | par | M | N | P1 |
| ADM-055 | Create computers | par | M | N | P1 |
| ADM-056 | Bulk computer modification | par | M | N | P1 |
| ADM-057 | Reset and restore | par | S | N | P1 |
| ADM-060 | BitLocker and LAPS | par | M | N | P1 |
| ADM-070 | Remote mailbox (hybrid) | par | M | Y | P2 |
| ADM-083 | Prebuilt report library | enh | L | N | P1 |
| ADM-084 | User reports (35) | enh | M | N | P1 |
| ADM-085 | Password reports (8) | par | S | N | P1 |
| ADM-086 | Group reports (16) | par | M | N | P1 |
| ADM-087 | Computer reports (18) | par | S | N | P1 |
| ADM-093 | Compliance report sets | enh | M | N | P1 |
| ADM-097 | Custom report builder | lea | L | N | P1 |
| ADM-098 | Act on report results | enh | S | N | P1 |
| ADM-099 | Scope and filters | par | S | N | P1 |
| ADM-100 | Export | par | S | N | P1 |
| ADM-101 | Scheduled reports | enh | M | N | P1 |
| ADM-104 | Scheduled automation | par | M | N | P2 |
| ADM-105 | Automation policies | par | M | N | P2 |
| ADM-107 | Automatable tasks | par | M | N | P2 |
| ADM-114 | History and audit | par | S | N | P2 |
| ADM-116 | Business workflows | enh | L | N | P2 |
| ADM-117 | Workflow technicians and requester roles | par | M | N | P2 |
| ADM-118 | Assigning rules | par | M | N | P2 |
| ADM-120 | Requests tab | par | M | N | P2 |
| ADM-121 | Managers as reviewers/approvers | par | S | N | P2 |
| ADM-125 | Help-desk roles | enh | L | N | P1 |
| ADM-126 | Built-in technicians and roles | par | S | N | P1 |
| ADM-127 | OU-based delegation | par | M | N | P1 |
| ADM-128 | Group-based delegation | par | M | N | P1 |
| ADM-129 | Include/exclude groups | par | S | N | P1 |
| ADM-130 | Cross- and multi-domain delegation | par | M | N | P1 |
| ADM-134 | Impersonate as Admin | lea | M | N | P1 |
| ADM-136 | Help Desk Reset Password Console | lea | S | N | P1 |
| ADM-137 | Help-desk audit report | enh | M | N | P1 |
| ADM-138 | Admin audit report | par | S | N | P1 |
| ADM-142 | Console 2FA | enh | M | N | P1 |
| ADM-143 | Console SSO | par | M | N | P1 |
| ADM-145 | Login hardening | enh | S | N | P1 |
| ADM-146 | Clean up from reports | par | S | N | P1 |
| ADM-147 | Automated cleanup policy | par | M | N | P2 |
| ADM-148 | Other stale objects | par | M | N | P1 |
| ADM-159 | Tenant onboarding | enh | S | N | P1 |
| ADM-161 | License management | par | M | N | P1 |
| ADM-162 | Account actions | par | S | N | P1 |
| ADM-164 | Groups | par | M | N | P1 |
| ADM-169 | Hybrid handling | lea | M | N | P1 |
| ADM-188 | REST API v1 | lea | M | N | P1 |
| ADM-189 | REST API v2 | par | M | N | P1 |
| ADM-191 | ServiceNow | par | M | N | P2 |
| ADM-192 | ServiceDesk Plus | par | M | N | P2 |
| ADM-198 | SIEM and log forwarding | enh | M | N | P2 |
| ADM-204 | Notifications | par | S | N | P1 |
| ADM-205 | Mail, SMS and proxy | enh | S | N | P1 |
| ADM-209 | Automatic hotfixes | lea | L | N | P1 |
| ADM-210 | High availability and load balancing | lea | L | N | P1 |
| ADM-212 | Domain connection settings | enh | M | N | P1 |

### ADAudit Plus — 54 must rows

| ID | Feature | Stance | Cx | Win | Phase |
|---|---|---|---|---|---|
| ADA-001 | User management auditing | enh | L | Y | P2 |
| ADA-002 | Group & membership auditing | enh | L | Y | P2 |
| ADA-003 | Computer management auditing | par | M | Y | P2 |
| ADA-004 | OU management auditing | par | M | Y | P2 |
| ADA-005 | GPO object auditing | par | M | Y | P2 |
| ADA-006 | GPO setting-level changes | enh | L | Y | P2 |
| ADA-007 | All-attribute tracking with old/new values | enh | M | Y | P2 |
| ADA-008 | AD permission (ACL) change auditing | enh | L | Y | P2 |
| ADA-009 | Schema, configuration & contacts | par | M | Y | P2 |
| ADA-010 | DNS auditing | par | M | Y | P2 |
| ADA-012 | Admin / help-desk activity trail | par | M | Y | P2 |
| ADA-013 | User-based consolidated audit trail | lea | M | Y | P2 |
| ADA-021 | Domain policy change auditing | par | S | Y | P2 |
| ADA-023 | Domain logon activity | par | L | Y | P2 |
| ADA-024 | Logon failure analysis | par | M | Y | P2 |
| ADA-025 | Logon history, currently logged-on users, logon duration | par | M | Y | P2 |
| ADA-026 | Local logon/logoff on servers and workstations | par | L | Y | P2 |
| ADA-027 | RDP / Terminal Services / RD Gateway | par | M | Y | P2 |
| ADA-028 | RADIUS / NPS logons | par | M | Y | P2 |
| ADA-037 | Lockout reports and default alert | par | M | Y | P2 |
| ADA-038 | Account Lockout Analyzer (root cause) | lea | L | Y | P2 |
| ADA-041 | Password change/reset auditing | par | M | Y | P2 |
| ADA-042 | Privileged group monitoring | enh | M | Y | P2 |
| ADA-046 | Sign-in auditing | par | M | N | P2 |
| ADA-047 | Directory change auditing | enh | M | N | P2 |
| ADA-049 | Hybrid correlation | lea | M | N | P2 |
| ADA-054 | Long-term retention of cloud logs | par | M | N | P2 |
| ADA-055 | Windows file server auditing | par | L | Y | P2 |
| ADA-057 | NTFS and share permission changes | par | M | Y | P2 |
| ADA-058 | NetApp | par | L | N | P4 |
| ADA-059 | Dell / EMC | par | L | N | P4 |
| ADA-063 | Server-, user-, share- and profile-based file reports | par | M | Y | P2 |
| ADA-072 | Local accounts and groups | par | M | Y | P2 |
| ADA-092 | Alert profiles | enh | M | N | P2 |
| ADA-093 | Thresholds, business hours, filters, throttling | par | S | N | P2 |
| ADA-094 | Email and SMS delivery | enh | S | N | P2 |
| ADA-095 | Script execution | enh | M | N | P2 |
| ADA-096 | ITSM auto-ticketing | par | M | N | P2 |
| ADA-097 | Product health notifications | lea | M | Y | P2 |
| ADA-098 | Prebuilt reports | lea | L | N | P2 |
| ADA-099 | Compliance report packs | enh | M | N | P2 |
| ADA-100 | Scheduled reports | par | S | N | P2 |
| ADA-101 | Custom, aggregate and profile reports | enh | M | N | P2 |
| ADA-102 | Report search and archive global search | enh | L | N | P2 |
| ADA-106 | SIEM forwarding | enh | M | N | P2 |
| ADA-110 | Technician delegation | enh | M | N | P2 |
| ADA-111 | 2FA and SSO | par | M | N | P1 |
| ADA-112 | Technician audit trail | par | S | N | P1 |
| ADA-114 | Global exclusions (noise filters) | par | S | N | P2 |
| ADA-115 | Agent management | enh | M | Y | P2 |
| ADA-116 | Hardening and misc | lea | S | N | P1 |
| ADA-117 | Archive tiers and retention | lea | L | N | P2 |
| ADA-118 | EVT/EVTX import | par | M | N | P2 |
| ADA-119 | HA and DR | lea | L | N | P2 |

### ADSelfService Plus — 60 must rows

| ID | Feature | Stance | Cx | Win | Phase |
|---|---|---|---|---|---|
| ADSS-001 | Web-portal password reset | enh | M | N | P3 |
| ADSS-002 | Web-portal account unlock | par | S | N | P3 |
| ADSS-003 | Web-based password change | par | S | N | P3 |
| ADSS-004 | Mobile-browser portal | par | S | N | P3 |
| ADSS-006 | Windows logon-screen reset/unlock | enh | XL | Y | P3 |
| ADSS-009 | Cached-credential update over VPN | par | L | Y | P3 |
| ADSS-010 | Cached-credential update without VPN | enh | L | Y | P3 |
| ADSS-011 | Microsoft Entra ID SSPR | lea | M | N | P3 |
| ADSS-014 | Block user after failed verification | par | S | N | P3 |
| ADSS-016 | Anti-enumeration "mock MFA" | par | S | N | P3 |
| ADSS-017 | Action notifications | par | S | N | P3 |
| ADSS-021 | User self-enrollment | enh | M | N | P3 |
| ADSS-023 | Forced enrollment at portal login | par | S | N | P3 |
| ADSS-024 | Enrollment reminders | par | S | N | P3 |
| ADSS-025 | Bulk import from CSV | lea | M | N | P3 |
| ADSS-027 | Pre-populated profile data | par | S | N | P3 |
| ADSS-028 | Enrollment reports and export | par | S | N | P3 |
| ADSS-029 | MFA backup codes | par | S | N | P3 |
| ADSS-031 | Security questions & answers | enh | S | N | P3 |
| ADSS-032 | AD security questions | par | S | N | P3 |
| ADSS-033 | Email verification code | par | S | N | P3 |
| ADSS-034 | SMS verification code | enh | S | N | P3 |
| ADSS-035 | Google Authenticator | par | S | N | P3 |
| ADSS-036 | Microsoft Authenticator | par | S | N | P3 |
| ADSS-038 | Custom TOTP (hardware or software token) | par | S | N | P3 |
| ADSS-040 | Push notification | enh | L | N | P3 |
| ADSS-043 | FIDO2 passkeys | enh | M | N | P3 |
| ADSS-046 | Duo Security | par | M | N | P3 |
| ADSS-047 | RSA SecurID | par | M | N | P3 |
| ADSS-048 | RADIUS authentication | par | M | N | P3 |
| ADSS-051 | Factor policy | par | M | N | P3 |
| ADSS-053 | TOTP replay hardening | par | S | N | P3 |
| ADSS-054 | Windows workstation logon MFA | par | XL | Y | P3 |
| ADSS-055 | Windows Server logon MFA | par | XL | Y | P3 |
| ADSS-058 | RDP MFA (server and client side) | par | L | Y | P3 |
| ADSS-059 | UAC elevation MFA | par | L | Y | P3 |
| ADSS-060 | Workstation unlock MFA | par | M | Y | P3 |
| ADSS-061 | Offline MFA | enh | L | Y | P3 |
| ADSS-068 | RADIUS MFA via NPS extension | lea | M | N | P3 |
| ADSS-069 | Two prompt modes | par | M | N | P3 |
| ADSS-091 | Password-expiry reminders | par | S | N | P2 |
| ADSS-092 | Account-expiry reminders | par | S | N | P2 |
| ADSS-093 | Manager notifications | par | S | N | P2 |
| ADSS-097 | Custom complexity rules | par | S | N | P3 |
| ADSS-098 | Pattern/dictionary rules | par | S | N | P3 |
| ADSS-100 | Breached-password ban (Have I Been Pwned) | enh | M | N | P3 |
| ADSS-101 | Enforcement on native changes | par | XL | Y | P3 |
| ADSS-102 | Live strength meter and rule display | par | S | N | P3 |
| ADSS-103 | Policy scoping | par | S | N | P3 |
| ADSS-116 | Help-desk-assisted reset/unlock | lea | M | N | P3 |
| ADSS-118 | AD reports | par | S | N | P3 |
| ADSS-119 | Self-service audit | par | S | N | P3 |
| ADSS-120 | MFA reports | par | S | N | P3 |
| ADSS-122 | Export and schedule | par | S | N | P3 |
| ADSS-123 | Log forwarding | par | S | N | P3 |
| ADSS-124 | Policy engine | enh | M | N | P3 |
| ADSS-125 | Technician delegation | lea | S | N | P3 |
| ADSS-126 | Admin-portal controls | par | S | N | P1 |
| ADSS-128 | HA failover / load balancing / reverse proxy | lea | L | N | P3 |
| ADSS-132 | Login-agent deployment and customization | enh | M | Y | P3 |

### RecoveryManager Plus — 5 must rows

| ID | Feature | Stance | Cx | Win | Phase |
|---|---|---|---|---|---|
| RMP-040 | Compression and encryption | par | S | N | P2 |
| RMP-042 | Technician roles | par | S | N | P1 |
| RMP-043 | Audit trail and SIEM | par | S | N | P1 |
| RMP-044 | Login and authentication | par | S | N | P1 |
| RMP-046 | Self-maintenance | lea | S | N | P1 |

### M365 Manager Plus — 3 must rows

| ID | Feature | Stance | Cx | Win | Phase |
|---|---|---|---|---|---|
| M365-005 | Licence management | par | M | N | P1 |
| M365-007 | Groups | par | M | N | P1 |
| M365-018 | Product access security | par | S | N | P1 |

### Exchange Reporter Plus — 2 must rows

| ID | Feature | Stance | Cx | Win | Phase |
|---|---|---|---|---|---|
| ERP-014 | Technician RBAC | par | S | N | P1 |
| ERP-017 | Hardening | par | S | N | P1 |

### Identity360 (AD360 Cloud) — 8 must rows

| ID | Feature | Stance | Cx | Win | Phase |
|---|---|---|---|---|---|
| I360-002 | AD sync via agent | lea | M | N | P1 |
| I360-003 | Entra ID sync | par | M | N | P1 |
| I360-004 | Smart templates | par | M | N | P1 |
| I360-013 | Remote-access MFA | par | M | N | P3 |
| I360-014 | MFA for RDP | par | L | Y | P3 |
| I360-015 | Offline MFA | par | L | Y | P3 |
| I360-019 | 12 authenticator types | par | M | N | P3 |
| I360-020 | Help-desk delegation | par | S | N | P1 |

### Requirements with no ManageEngine ID (must, tracked outside the CSV)

These come from the research but are not ManageEngine features, so they have no ID. Track them as
activeDIQ requirements in `knowledge/business/scoping/`. **Do not mint ADM/ADA/… IDs for them.**

| Requirement | Why | Evidence |
|---|---|---|
| Multi-domain and multi-forest support | Enterprise baseline; also an ADMP licensing pain point | ADM doc §7a, §2.9 |
| Config importers: ADMP templates, naming formats, roles, workflows and automations; ADAP alert profiles and schedules; ADSSP policies | Sunk configuration is a top switching barrier | CV doc §5.2, §5.3; AD360 doc §8.2; ADM doc §7c |
| ADAudit Plus history bridge: syslog/CEF receiver, CSV importers for the top ~30 compliance reports, EVTX backfill, report crosswalk, reuse of the existing audit policy | Customers will not discard years of audit history | ADA doc §7a "Historical audit data"; CV doc §5.2 |
| ADSelfService Plus enrollment migration, OU-by-OU coexistence and progressive enrollment | Re-enrollment is the decisive ADSSP switching cost | ADSS doc §0 #6, §8a; CV doc §5.2 |
| Agent swap kit: remove ADAP, ADSSP and RMP agents; deploy ours via MSI/GPO | Logon agents must be redeployed on every endpoint | AD360 doc §8.2; CV doc §5.2 |
| Least-privilege service identity: no Domain Admin, gMSA where possible | ADSSP and ADMP guidance asks for Domain Admin | ADSS doc W6; ADM doc §7c; FEAS doc §2.3 |

## Top 25 enhance/leapfrog opportunities

Ranked by strength of evidence × value to a switching customer × how well we can prove it in a
demo. Rows that solve the same problem are grouped. The enhancements are proposals.

| # | Opportunity | Matrix rows | Rationale (evidence) |
|---|---|---|---|
| 1 | **Task-first console**: command palette, universal search that runs actions, single-page flows | ADM-001, ADM-003, ADM-004 | UI/navigation is the #1 complaint, at ≈28 of ~152 coded reviews (CV doc X1). ADMP shows ~64 action links on one landing page and the demo's Create User page weighed 10.4 MB (ADM doc W8). This is the CEO's "far easier to use" test, and it can be measured with task timings (CV doc §6.2) |
| 2 | **Upgrades that just happen**: automatic, signed, zero-downtime, with rollback | ADM-209, RMP-046, ADA-115 | Manual, multi-step upgrades rank #3 at ≈16 reviews, some of which report failed upgrades (CV doc X3). This is wedge #1 in CV doc §6.1. ADMP hotfixes are unavailable under HA (ADM doc W1) |
| 3 | **Visual report builder** with interactive charts, sharing and scheduling | ADM-097, ADA-101, ADA-104 | Report customization limits rank #2 at ≈17 reviews (CV doc X2) |
| 4 | **Report parity pack plus investigation-first views**: crosswalk of ME report names that auditors recognize | ADM-083, ADA-098, ADA-013 | Canned compliance reports are why customers stay (CV doc key takeaway 2). ADAP has ~1,000 report entries in its nav (ADA doc W12). Auditors know specific ADAP report names (ADA doc §7a) |
| 5 | **Change → diff → one-click revert**, natively and in every tier | ADM-005, ADM-150, ADM-151, ADA-022, RMP-006/008/009 | ME splits who-changed (ADAP), restore (RMP or a paid add-on) and approve (ADMP) across products (AD360 doc §8.3; ADA doc §7c#1). Semperis and Cayosoft sell this as a premium (LAND doc §7.1#4) |
| 6 | **Preview, then undo** for every bulk change and every offboarding | ADM-033, ADM-034, ADM-043, ADM-098, ADM-153 | ADMP rollback needs the per-user Backup add-on, and no single offboarding preview is documented (ADM doc §7c) |
| 7 | **One hybrid console, aware of source of authority** | ADM-169, ADM-027, ADA-047, ADA-049, ADSS-011 | "Cloud requires another product" (CV doc X5, ≈11). ADMP's M365 tab is a separate iframe app (ADM doc W8). ADSSP's Entra support is new and partial (ADSS doc W19). Group/user SOA reached GA in 2025–26 (LAND doc §7.1#6) |
| 8 | **ADSSP enrollment migration kit plus progressive enrollment** | ADSS-025, ADSS-021, ADSS-027, ADSS-031 | About half the enrollment surface migrates with zero user effort (ADSS doc §8a). ADSSP's HTA popup blocks the desktop (W15) |
| 9 | **Smart CSV import**: auto-map columns, names instead of DNs, row-level preview | ADM-011 | ADMP requires LDAP attribute headers and DN syntax (ADM doc W8, §7c) |
| 10 | **Help-desk caller verification** built into reset and unlock | ADSS-116, ADM-136 | Help-desk vishing is the #2 initial vector at 11% (LAND doc key finding 4, §7.1#7). ADSSP needs ADManager Plus for assisted reset (ADSS doc W9) |
| 11 | **Searchable history across all storage tiers** with multi-year retention | ADA-102, ADA-117 | ADAP Cold/Frozen archives must be restored before they can be queried (ADA doc W8). Audit-history retention is a switching barrier (CV doc §5.2) |
| 12 | **Guard-railed AI agent**: preview, approval, rollback, plus an MCP server | ADM-181 | Zia covers 4 actions and needs the customer's Azure OpenAI key (ADM doc W11). AI is table stakes, but rollback-native agentic AD is an open lane (LAND doc key finding 2, §7.1#3) |
| 13 | **Per-technician attribution** in AD's own logs | ADM-134 | Under "Impersonate as Admin", DC logs show the service account. CVE-2025-11670 is tied to this mode (ADM doc W4) |
| 14 | **Secure by default**: no default credentials, HTTPS only, mandatory admin MFA | ADM-142, ADM-145, ADM-208, ADSS-127, ADA-116 | ADMP: admin/admin, HTTP 8080, 2FA skippable by the built-in admin (ADM doc W3). ADSSP has similar defaults (ADSS doc W17). Buyers will vet a Tier-0 tool (CV doc §6.2). State our facts; never disparage |
| 15 | **Least-privilege setup wizard** (never Domain Admin) | ADM-135 | ADMP recommends Domain Admin or a manual guide (ADM doc §7c). ADSSP's guide asks for Domain Admin (ADSS doc W6) |
| 16 | **Lockout root cause with a one-click fix** | ADA-038 | Lockout depth is a named reason customers look elsewhere (CV doc §5.1). ADSSP documents no lockout root-cause tooling (ADSS doc W16, L8) |
| 17 | **Automation triggered by any AD change**, including ADUC and PowerShell | ADM-108, ADM-042 | ADMP's documented triggers fire on ADMP actions only (ADM doc W10; to be confirmed, see gaps) |
| 18 | **Unmetered, OpenAPI-first API** with webhooks and an event stream | ADM-188, ADM-190, ADA-108, ADSS-136 | ADMP allows 50 calls per technician per day, then US$1 per extra call/day (ADM doc key takeaway 3). ADAP has no documented public API (ADA doc W13). ADSSP lists a REST API as "in pipeline" (ADSS doc W8) |
| 19 | **No edition gating on audit depth**: old/new values, GPO diffs and ACL diffs in every tier | ADA-001, ADA-006, ADA-007, ADA-008 | These are Pro-only in ADAP (ADA doc §3.1, W10, §7c#3) |
| 20 | **Low-noise alerting**: correlated, deduplicated, tunable | ADA-092, ADA-081 | Reviewers report inboxes "flooded" (CV doc X11). ADAP fixed several false positives only in build 9000 (ADA doc W7) |
| 21 | **One RBAC model, no per-technician licensing** | ADM-125, ADSS-125, ADA-110 | Per-technician pricing leads some customers to share admin accounts (CV doc §5.3, §6.1#6). ADSSP has two roles (W7). AD360 roles are per component (AD360 doc §1.3) |
| 22 | **Built-in RADIUS server** (no Windows NPS) | ADSS-068 | ADSSP VPN MFA requires an NPS extension (ADSS doc W11, L13). Note the MSCHAPv2 caveat (FEAS doc App A Q7) |
| 23 | **Offline breached-password corpus** | ADSS-100 | ADSSP's HIBP check is online-only (ADSS doc W13). Matters for air-gapped and regulated buyers |
| 24 | **Control-mapped evidence packs**, including NIS2 and DORA | ADM-093, ADA-099 | ADMP documents no ISO 27001, NIST, CMMC or NIS2 mappings (ADM doc W14). No ADAP NIS2/DORA page was found (ADA doc §7c#8). DORA six-monthly reviews and PCI 7.2.4 are RFP checkboxes (LAND doc key finding 6) |
| 25 | **HA included and multi-site by design** | ADM-210, ADA-119, ADSS-128 | ADMP HA needs the same subnet (ADM doc W1). ADAP HA needs manual SQL steps (ADA doc W2). ADSSP HA is a $395 add-on (ADSS doc W5, §3.13) |

Close runners-up: policy-bound templates with drift detection (ADM-012; ADM doc W13); continuous
audit-policy health (ADA-097); SoD checks at request time (ADM-116; ADM doc W14); the policy
simulator (ADSS-124); posture checks as a free-scan door-opener (ADM-174; LAND doc §7.1#9).

**Don't overclaim.** ADSS-067 (passwordless OS logon, SSH/sudo MFA) is a leapfrog over ADSSP only.
Identity360 already lists desktop passwordless and sudo/SSH MFA (I360-012, I360-016). The same
caution applies to AD360 doc §8.4 generally: compare against current ManageEngine builds, with dates.

## Windows-native dependency list (long poles)

126 rows need a Windows-resident component (9 of them are skip rows). Grouped by component:

| Component | Rows (must rows in bold) | Phase | Why it is long (FEAS doc) |
|---|---|---|---|
| **Password-filter DLL in LSASS on every writable DC** | **ADSS-101**, ADSS-105, ADSS-108, ADSS-106, ADSS-107 | P3 (spike in Phase 0) | XL. Under LSA protection every LSA plug-in must be Microsoft-signed through the LSA file-signing service; review lead time unknown. An LSASS crash reboots the DC; no debugger under PPL. Start enrolment in week 1 (§1.7, §6.2, App A Q3) |
| **Credential provider in LogonUI** (logon, unlock, change, PLAP, RDP) | **ADSS-006, 009, 010, 054, 055, 058, 059, 060, 061, 132**; ADSS-022, 062–067; **I360-014, 015**; I360-012, 016, 017 | P3 (spike in Phase 0) | XL. COM as SYSTEM, x64 + ARM64, offline/VPN cases. ManageEngine shipped SYSTEM-level bugs exactly here (§1.6, §6.2). Coexistence with the ADSSP agent during migration is [TODO] (AD360 doc App A) |
| **DC/server event-collection agent** (or WEF) | **ADA-001–010, 012, 013, 021, 023–028, 037, 038, 041, 042, 072, 097, 115**; ADA-011, 014, 073, 080, 113 and the P4 audit long tail | P2 | L. ≈3,000 events/s per collector; no gap signal when a log wraps; an agent on a DC is Tier 0. Whether customers accept a DC agent at all is open (§1.5, §6.2, App A Q2) |
| **File-server agent** (effective access, bulk NTFS, file auditing) | **ADM-045, ADA-055, 057, 063**; ADM-078, 079, 081, 082, 091; ADA-056, 062, 064, 065 | P2 / P4 | L. Must match Windows access-check semantics exactly; file auditing is the highest-volume source (§1.4, §1.5, §6.2) |
| **Windows helper: GPMC/GroupPolicy module** | ADM-072, ADM-074, ADM-090 | P2 / P4 | XL for settings editing. Many CSE formats; one bad write breaks policy on thousands of machines (§1.3, §6.2) |
| **Windows helper: Exchange Server PowerShell remoting** | **ADM-026, ADM-070**; ADM-054, 063–069, 071; ERP-001–003, 008, 013 | P2 / P4 | Scope depends on each lead's on-prem Exchange footprint (FEAS doc App A Q6) |
| **IIS module on Exchange/IIS hosts** | ADSS-071, ADSS-072 | P4 | Declining as customers move to Exchange Online (ADSS doc §8a) |
| **Workstation/endpoint agent** (shared skenzeriq agent) | **ADA-026** (workstation part); ADA-035, 053, 066–071, 075, 076, 079, 085 | P2 / P4 | Must honour "one agent process per endpoint", with module contract agreed with the UEM owners (FEAS doc §6.1#6, App A Q4) |
| Skipped (no build) | ADA-034, 036, 077, 078; RMP-020, 021; ERP-005, 011, 012 | – | Reasons in notes |

Not Windows, but native and long: macOS login (ADSS-007, 056; XL, Platform SSO vs authorization
plug-in, FEAS doc App A Q8) and Linux PAM (ADSS-008, 057).

## Research gaps that could change the matrix

Items most likely to flip importance, stance or phase come first.

1. **What the warm accounts actually run** [TODO]: products, editions, add-ons, technician counts,
   NAS vendors, on-prem Exchange, Entra licence tier, enabled authenticators, SIEM targets. ADA doc
   §7a and ADSS doc §8a give discovery checklists. This is the single biggest swing factor for
   must/should. (Account names belong only in `business/partnerships/`.)
2. **CEO fork: build an IdP/SSO or integrate?** [TODO]. LAND doc §7.2 says don't build an IdP. ADSS
   doc §8a lists SSO as P1 and FEAS doc §6.3 plans an OIDC/SAML IdP. This affects ADSS-073–086,
   137, 138 and I360-009/017.
3. **Deployment model** (SaaS, self-hosted or both): the stack/deployment ADR is pending (CLAUDE.md).
   It changes the shape of ADM-158, 209, 210, 211 and ADSS-128, and whether customers accept
   outbound connectors near DCs (FEAS doc App A Q5).
4. **ADSSP database contents** [TODO]: TOTP seeds, FIDO2 public keys and the security-answer hash
   format (ADSS doc §9). These set the scope of ADSS-025/031 and how much re-enrollment customers
   face.
5. **ManageEngine config and audit export formats** [TODO]: ADMP, ADAP, ADSSP and M365MP (AD360 doc
   App A; ADA doc open gaps). Also whether a lapsed ADAP subscription drops to a Free read-only
   viewer with history intact [UNVERIFIED in practice] (ADA doc §7a). These decide the importer and
   history-bridge effort.
6. **DC-side acceptance and signing**: will customers accept a DC agent and a password-filter DLL
   (FEAS doc App A Q2)? What are the LSA plug-in signing requirements and lead time (Q3)? If the
   answer is no or slow, ADSS-101/108 and much of ADA move.
7. **ADMP behaviours to confirm** [TODO]: whether event automation triggers on changes made outside
   ADMP (affects the ADM-108 leapfrog claim), and edition placement for every `n/s` row (ADM doc
   open items). Also re-measure page weight on build 8043.
8. **Customer voice is thin for RMP and AD360** [TODO] (CV doc open gaps). RMP rows are
   should/could on low evidence. G2, TrustRadius and Gartner pages were blocked for several products
   (ADM, ADA and CV docs).
9. **Credential-provider coexistence with the ADSSP agent** [TODO] (AD360 doc App A). If they can't
   coexist, OU-by-OU migration (ADSS doc §8a) needs another plan.
10. **MSCHAPv2/PEAP need** (FEAS doc App A Q7). It decides whether the built-in RADIUS leapfrog
    (ADSS-068) also needs NPS or Netlogon pass-through.
11. **Password sync vs Entra password hash sync** (FEAS doc App A Q10). This affects ADSS-105.
12. **Smaller gaps**: the ADSSP full SSO catalogue and SCIM app list, and end-user portal languages
    (ADSS doc §9); ADAP build 9000 module licensing and UI (ADA doc open gaps); minimum supported DC
    OS (FEAS doc App A Q1); decrypting Windows LAPS from Linux [UNVERIFIED] (FEAS doc §1.1, affects
    ADM-060).

## How the matrix feeds tickets

- **IDs are the contract.** Every PRD, spec and ticket that implements ManageEngine-equivalent
  behaviour lists the IDs it covers, e.g. `parity: ADM-084, ADM-085, ADSS-118`. Never renumber. New
  ManageEngine features get an ID in their research doc first, then a row here.
- **Scoping reads the matrix.** A milestone scope lock in `business/scoping/` selects rows by
  `phase` and `importance`, and records any row it pulls forward or pushes back, with the reason.
  Update the row's `phase` in the same change.
- **Duplicates close together.** Rows whose notes say "Same capability as X" are built once. The
  ticket cites all the IDs, so parity is counted per ManageEngine product.
- **Acceptance criteria come from the row.** Parity means the `description` behaviour works against
  a real DC. Enhance/leapfrog adds the `enhancement`. Windows-native rows (`windows_native = Y`) need
  Windows-runner tests, because Samba does not emulate event logs, GPO client processing or WS2025
  hardening (FEAS doc §5.2).
- **No dead buttons.** A UI entry point for a row ships only when that row's capability works end
  to end (CLAUDE.md rule 6; the PatchIQ postmortem §11 records stub pages and fabricated dashboard
  data as root causes).
- **Exit gate.** FEAS doc §6.3 sets the breadth exit criterion as parity ≥ 90% of the features
  customers actually use. Measure it as the share of `must` rows (re-weighted by discovery) whose
  tickets are done.
- **Keep it true.** When research changes, update the CSV, regenerate the totals and must tables
  here, bump `updated`, and log the reason. The matrix is `draft` until a human reads it end to end.
