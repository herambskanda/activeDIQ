---
title: v1 scope options and scope lock (ADManager Plus first)
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: heramb
---

# v1 scope options and scope lock

On 2026-10-02 the CEO made four directional decisions (D-0001…D-0004 on the Factory Board).
This file does two things:
- §2 briefly records the three scope options that were considered.
- §3–§7 lock the v1 scope for the chosen direction.

Only the questions in §8 still need the CEO. The factory has decided everything else and logged
it in §6.

**Conventions**
- **Estimate** = analyst arithmetic or judgement, not a measurement.
- `[ASSUMPTION]` = not stated by the CEO and not sourced.
- `[UNVERIFIED]` and `[TODO]` tags are carried over from the source documents.
- `[DISCOVERY]` = settled by partner discovery answers. The factory decides these; the CEO does not.
- Feature IDs (`ADM-###` etc.) are the research IDs. Counts come from
  `feature-parity-matrix.csv` as of 2026-10-02.
- Partner names never appear here (CLAUDE.md rule 8).

**Source key.** Citations use the format `KEY §section`.

| Key | Document |
|---|---|
| MATRIX | [feature-parity-matrix.md](../competitive-analysis/feature-parity-matrix.md) + `.csv` |
| STRAT | [product-strategy.md](../strategy/product-strategy.md) |
| ENH | [enhancement-catalog.md](../strategy/enhancement-catalog.md) |
| EXEC | [executive-summary.md](../strategy/executive-summary.md) |
| ADM | [ADManager Plus](../market-research/manageengine-admanager-plus.md) |
| ADA | [ADAudit Plus](../market-research/manageengine-adaudit-plus.md) |
| ADSS | [ADSelfService Plus](../market-research/manageengine-adselfservice-plus.md) |
| SUITE | [AD360 & commercials](../market-research/manageengine-ad360-suite-and-commercials.md) |
| CV | [customer voice & security](../market-research/manageengine-ad-customer-voice-and-security.md) |
| LAND | [market landscape](../competitive-analysis/ad-management-market-landscape.md) |
| FEAS | [technical feasibility](../../development/architecture/build-feasibility/ad-technical-feasibility.md) |
| MIG | [migration playbook](../service/manageengine-migration-playbook.md) (`MIG-##` requirements, §8) |
| PILOT | [pilot offer outline](../service/pilot-offer-outline.md) |

Companion: [roadmap-skeleton.md](roadmap-skeleton.md) (M1–M5).

---

## 0. Key conclusions

1. **v1 is "the ADManager Plus replacement release".** It covers **all 88 ADMP must rows** and
   33 of the 77 ADMP should rows, plus Graph-based Entra ID/M365 provisioning. Including duplicate
   rows that other ManageEngine (ME) SKUs carry, that is **106 must and 37 should rows** of the
   matrix's 220/223 (§3.2). v1 is delivered at the exit of **M2 "Core management parity —
   pilot-ready"**.
2. **v1 needs no Windows-resident component** (no DC agent, password filter or credential
   provider) (MATRIX "Reading the totals"). Three Windows-native ADMP must rows are conditional
   (§3.3). All the XL long poles are in M3–M5. The v1 long poles are protocol-level: LDAP
   signing and channel binding from Go, the effective-permissions check behind the
   least-privilege wizard, and the config importers (§3.7).
3. **To retire ADMP, v1 needs ADMP's workflow, automation and joiner/mover/leaver rows, not just
   the matrix's P1.** ADM §7a lists them as day-one needs. We therefore pull **24 rows** from P2
   into v1 (19 must, 5 should) (§6 FD-02, FD-03). This makes M2 the largest milestone, so it
   ships through four internal demo checkpoints (roadmap §M2).
4. **Day-one retirement is conditional on the partner's ME footprint** (§4–§5).
   - Best fit: an ADMP-centric account, especially one on ADMP **Standard**. Standard excludes
     workflow, automation, and group, OU and contact management (ADM key takeaway 3), so v1
     covers more than it uses.
   - Watch out for ADMP + ADSSP. ADSSP's approval workflow and help-desk-assisted reset
     **require ADMP** (ADSS W9; ADSS-115/116). Switching ADMP off can break those flows until M4.
   - On-prem Exchange, NTFS management and the ADMP Backup add-on also block a day-one switch.
5. **Size: about 33–50 factory-weeks to v1, M1 included** (**Estimate**, §3.8). This rests on an
   unmeasured factory throughput, so it must be re-baselined after the first build weeks.
   Options B and C would be about 2× and 3× that.
6. **Five questions remain for the CEO** (§8): pilot accounts and their ME footprint, pricing and
   pilot commercials, whether a pilot may start before M2 exit, security-evidence budget, and M1
   external spend/legal (code signing, Microsoft LSA-signing enrolment, counsel review of ME
   data access).

## 1. What the CEO decided and what it means for scope

| ID | Decision (2026-10-02) | Consequence for v1 scope |
|---|---|---|
| D-0001 | **ADManager Plus first**, with Graph-based Entra ID/M365 provisioning pulled into v1 (STRAT §13 Q1) | v1 = every ADMP must row (§3), plus the Graph rows. Exchange Online mailbox work is *not* Graph-only: it needs the PowerShell sidecar (FEAS §1.9), so it stays in M5 (§3.6) |
| D-0002 | **Self-hosted first**: Windows installer + Linux/Docker. The codebase is SaaS-ready (multi-tenant core) from the first migration | Two install profiles in v1, both on one update path (ENH-07; FEAS §4.3). `tenant_id` + RLS from migration 1 (FEAS §4.5, §6.1 #1). The SaaS profile is not in v1 |
| D-0003 | **Standalone now**, on UEM principles, the house stack and the skenzeriq design system. Shared endpoint agent via module contracts; converge on a common core later | v1 has no agent (§0 #2). The platform-agent module contract is drafted in M1 and must be ratified before M3 (FEAS §6.1 #6). The UI uses the skenzeriq tokens (`../design-system/README.md`) |
| D-0004 | **The set of 5**: ENH-01, ENH-04, ENH-07, ENH-05, ENH-09. Plus the baseline switch enablers and Tier-0 proof (ENH §3.1). ENH-11, ENH-22, ENH-20 come after | All five ship in v1 (§3.5). Of the baseline, ENH-02 (ADMP importers), ENH-08 and ENH-10 are in v1. ENH-03 and ENH-06 are not, because ADSSP and ADAP are not v1 products (ENH §3.1) |

## 2. Options considered (for the record)

Counts are matrix rows (must / should) covered, including duplicate rows that other SKUs carry.
Sizes are **Estimates** derived in §3.8.

| | **A. Management parity first** *(chosen, D-0001)* | **B. Management + change-auditing core** | **C. Full-suite parity** |
|---|---|---|---|
| Products / modules | ADMP core: directory management, bulk, templates, delegation/help desk, reports + builder, workflow, automation, JML, ITSM/API. Graph-based Entra/M365 provisioning | A + ADAP core (DC/Entra auditing, alerts, retention, file-server auditing), AD snapshots and rollback, the rest of ADMP's P2 | B + ADSSP (SSPR, MFA, logon-screen reset, password filter, SSO) |
| Matrix rows (must / should) | **106 / 37** (ADMP 88/33) | 158 / 108 (all P1 + P2) | 220 / 163 (P1–P3 + the 2 P4 musts) |
| Enhancements | Set of 5 + ENH-02 (ADMP) + ENH-08 + ENH-10 | + ENH-06 history bridge, ENH-11, ENH-22, ENH-12 | + ENH-03 enrollment, ENH-24 RADIUS, ENH-18 (partly) |
| Windows-native rows | 3, all conditional; no XL | 44 rows: DC agent, file-server agent, GPMC/Exchange helpers | 63 rows, 7 XL (password filter, credential provider, macOS logon) |
| Row-sum engineer-weeks, deduplicated (FEAS bands) | ≈ 230–620 | ≈ 550–1,500 | ≈ 890–2,280 |
| Rough size to release | **≈ 33–50 factory-weeks** | ≈ 60–95 | ≈ 90–145, plus an unknown LSA-signing lead time |
| Main risks | Too thin for ADAP/ADSSP-heavy accounts. The "one console" story is partial while ME products remain | DC-agent acceptance (FEAS App. A #2); ≈3k events/s per collector (FEAS §6.2); pilot date slips by ~6+ months | LSA signing lead time unknown (FEAS §6.2). Credential provider is where ME shipped SYSTEM-level bugs. No pilot for well over a year |
| Retire from ME on day one | ADMP, under the conditions in §4 | ADMP + ADAP (except NAS auditing ADA-058/059 and the P4 audit long tail) | ADMP + ADAP + ADSSP (except P4 items) |
| Fits partners who run | ADMP, alone or as the main product | ADMP + ADAP | Full AD360 stack |

**Why A (the strategy team's recommendation, now decided).**
- ADMP is the most-reviewed and most-inherited product (CV §1.1, §3.2 #5).
- A avoids the Windows-native long poles (STRAT R2).
- Preview/undo and the task-first console are most visible in ADMP work (STRAT §13 Q1).
- B and C delay the first switch by the duration of one or two FEAS phases (FEAS §6.3) and stake
  the pilot on DC-side acceptance and Microsoft signing.

## 3. v1 scope lock

### 3.1 Definition

**v1 = everything a switching ADMP customer needs on day one** (ADM §7a), built to the matrix's
acceptance rule: parity means the row's `description` works against a real DC, and enhance/leapfrog
rows add the `enhancement` (MATRIX "How the matrix feeds tickets").

**The selection rule** (MATRIX: "A milestone scope lock selects rows by phase and importance, and
records any row it pulls forward"):
1. every matrix row with `phase = P1` (117 rows);
2. plus every ADMP `must` row in P2 (22). 19 go into M2; the 3 Windows-native rows are
   conditional (§3.3);
3. plus 5 P2 `should` rows: 3 that ADM §7a lists as day-one (ADM-040, 106, 119) and 2 that are
   Graph provisioning under D-0001 (ADM-009, 160);
4. plus ADSS-091, a duplicate of ADM-047 that is built once.

v1 is 145 rows: 106 must, 37 should, 2 could. 142 of them are unconditionally in M2.

### 3.2 Coverage counts (from the CSV)

| Product | must in v1 / total must | should in v1 / total should | Note |
|---|---|---|---|
| ADManager Plus (ADM) | **88 / 88** | 33 / 77 | 3 must rows are conditional (§3.3) |
| ADAudit Plus (ADA) | 3 / 54 | 0 / 33 | Console 2FA/SSO, technician audit, hardening. These are platform rows; **ADAP is not replaceable in v1** |
| ADSelfService Plus (ADSS) | 2 / 60 | 3 / 59 | Admin-portal controls, expiry reminders, platform hygiene. **ADSSP is not replaceable in v1** |
| RecoveryManager Plus (RMP) | 4 / 5 | 0 / 25 | Technician roles, audit/SIEM, login, self-maintenance (platform rows) |
| M365 Manager Plus (M365) | 3 / 3 | 0 / 11 | Licences, groups, access security |
| Exchange Reporter Plus (ERP) | 2 / 2 | 0 / 6 | Technician RBAC, hardening (platform rows) |
| Identity360 (I360) | 4 / 8 | 1 / 12 | AD sync, Entra sync, smart templates, help-desk delegation, REST API |
| **Total** | **106 / 220** | **37 / 223** | Most non-ADM rows are "Same capability as …" duplicates, built once |

### 3.3 The v1 feature set by module (ADManager Plus)

**Bold** = must. `^` = pulled forward from P2 (reason in §6). Everything else is P1 in the matrix.
Stance, complexity and enhancement text for every row are in the CSV.

| Module | Rows in v1 |
|---|---|
| Console (6) | **ADM-001** tabbed console → task-first console · ADM-002 dashboard · **ADM-003** global search · **ADM-004** AD Explorer · **ADM-005** object change history · ADM-007 localization |
| Users (23) | **ADM-008** create · ADM-009^ cloud-only accounts · **ADM-010** bulk create · **ADM-011** CSV import · **ADM-012** creation templates · **ADM-013** creation rules · ADM-014 template bulk-edit · **ADM-015** modification templates · **ADM-016** copy attributes · **ADM-017** naming formats · **ADM-018** conditional naming · **ADM-020** duplicate prevention · **ADM-021** random passwords · **ADM-022** password options · **ADM-023** home/profile folders · **ADM-024** account controls · ADM-025 Kerberos AES flags · **ADM-026^** Exchange at creation *(conditional)* · **ADM-027** M365 at creation · **ADM-033** modify · **ADM-034** bulk modify · ADM-037 attribute lists · **ADM-038** restore deleted users |
| Lifecycle (8) | **ADM-039^** HR-driven joiners · ADM-040^ database-driven provisioning · **ADM-041^** CSV-drop provisioning · **ADM-042^** movers · **ADM-043^** disable (leaver) policy · **ADM-044^** delete policy · **ADM-045^** offboarding orchestration blocks *(NTFS block in M3)* · **ADM-047^** password-expiry reminders |
| Groups (4) | **ADM-048** group lifecycle · ADM-049 templates · **ADM-050** membership (nested, cross-domain) · ADM-051 copy attributes |
| Computers (6) | **ADM-055** create · **ADM-056** bulk modify · **ADM-057** reset/restore · ADM-058 templates · ADM-059 domain-join permissions · **ADM-060** BitLocker and LAPS |
| Contacts, OUs (2) | ADM-061 contact lifecycle · ADM-062 OU lifecycle |
| Exchange (1) | **ADM-070^** remote mailbox (hybrid) *(conditional)* |
| GPO (2) | ADM-073 link management · ADM-077 scope and delegation |
| Reports (16) | **ADM-083** prebuilt library · **ADM-084** user · **ADM-085** password · **ADM-086** group · **ADM-087** computer · ADM-089 contact/OU · ADM-092 other · **ADM-093** compliance sets · ADM-096 report from CSV · **ADM-097** custom builder · **ADM-098** act on results · **ADM-099** scope/filters · **ADM-100** export · **ADM-101** scheduling · ADM-102 report delegation · ADM-103 dashboard widgets |
| Automation (5) | **ADM-104^** scheduled · **ADM-105^** policies · ADM-106^ controlled automation · **ADM-107^** automatable tasks · **ADM-114^** history and audit |
| Workflow (6) | **ADM-116^** business workflows · **ADM-117^** technician/requester roles · **ADM-118^** assigning rules · ADM-119^ SLAs · **ADM-120^** requests tab · **ADM-121^** managers as approvers |
| Delegation and help desk (12) | **ADM-125** help-desk roles · **ADM-126** built-in roles · **ADM-127** OU delegation · **ADM-128** group delegation · **ADM-129** include/exclude · **ADM-130** cross-domain · ADM-131 M365 delegation · ADM-132 technician templates · ADM-133 site delegation · **ADM-134** per-technician attribution · ADM-135 native AD security roles · **ADM-136** help-desk reset console (+ ENH-09) |
| Audit of our own actions (3) | **ADM-137** help-desk audit · **ADM-138** admin audit · ADM-139 technician logons |
| Console access (4) | ADM-141 auth tokens · **ADM-142** console 2FA · **ADM-143** console SSO · **ADM-145** login hardening |
| Cleanup (3) | **ADM-146** clean up from reports · **ADM-147^** automated cleanup policy · **ADM-148** other stale objects |
| Entra ID / M365 via Graph (6) | **ADM-159** tenant onboarding · ADM-160^ bulk create/modify · **ADM-161** licences · **ADM-162** account actions · **ADM-164** groups · **ADM-169** hybrid handling (source-of-authority-aware view) |
| API and integrations (6) | **ADM-188** REST API · **ADM-189** REST v2 (same API) · ADM-190 unmetered · **ADM-191^** ServiceNow · **ADM-192^** ServiceDesk Plus · **ADM-198^** SIEM forwarding |
| Admin and platform (10) | ADM-158 product DB backup · **ADM-204** notifications · **ADM-205** mail/SMS/proxy · ADM-206 retention · ADM-207 privacy · ADM-208 hardening score · **ADM-209** automatic updates · **ADM-210** HA · **ADM-212** domain connection (LDAPS, signing, CBT) · ADM-213 diagnostics |

**Closed by the same build** (non-ADM rows; MATRIX notes "Same capability as …"):
- ADA-111, ADA-112, ADA-116;
- ADSS-091, ADSS-126, ADSS-127, ADSS-129, ADSS-131;
- RMP-042, RMP-043, RMP-044, RMP-046;
- M365-005, M365-007, M365-018;
- ERP-014, ERP-017;
- I360-002, I360-003, I360-004, I360-020, I360-022.

**The three conditional Windows-native ADMP must rows**

| Row | Why it is conditional | v1 handling (factory decision FD-04) |
|---|---|---|
| ADM-026 Exchange at creation | On-prem Exchange needs Windows PowerShell remoting (FEAS App. A #6) | Build the Exchange helper in M2 **only if** a pilot account has on-prem or hybrid Exchange `[DISCOVERY]`. Otherwise it goes in M3 |
| ADM-070 Remote mailbox (hybrid) | Same helper. The matrix calls it the "hybrid-critical piece of on-prem Exchange" | As ADM-026 |
| ADM-045 Offboarding orchestration blocks | NTFS clean-up on large trees needs the file-server agent (FEAS §1.4) | Licence, group, OU and mailbox blocks ship in M2. The NTFS block ships with the file-server agent in M3 |

### 3.4 v1 requirements with no ME feature ID

These come from MATRIX "Requirements with no ManageEngine ID" and MIG §8. They are must for v1.

| Requirement | IDs | v1 scope |
|---|---|---|
| Multi-domain and multi-forest support | ADM §7a, §2.9 | In M2 |
| ADMP configuration import | MIG-01 discovery scanner · MIG-02 (ADMP adapters only) · MIG-03 fidelity report · MIG-04 ADMP-format CSV · MIG-05 report crosswalk · MIG-06 scheduled-report importer | In M2. Inputs: documented exports first, read-only DB second. The formats are `[UNVERIFIED]` and EULA review is `[TODO]` (MIG §9) |
| Parallel run and cutover control | MIG-10 comparator (ADMP half) · MIG-14 job-ownership lock · MIG-16 technician identity cleanup | In M2. MIG-14 is what lets a partner flip each job from ADMP to activeDIQ |
| Least-privilege service identity (no Domain Admin) | MIG-12 = ENH-08 | In M2 |
| Baseline AD snapshot and rollback point | MIG-18 | In M2 (snapshot foundation, FEAS §6.3 Phase 1) |
| ADMP REST compatibility shim | MIG-17 | **Not in v1.** MIG marks it "proposal, evaluate" with legal review `[TODO]` |

### 3.5 Enhancements in v1

| ENH | What v1 ships | Where the scope stops | Main rows |
|---|---|---|---|
| **ENH-01** Task-first console (set of 5) | Universal search that runs actions inline, a command palette and single-page flows. Each top task gets an interaction budget, e.g. reset + unlock in ≤3 interactions (ADM §7c) | Ongoing work: every later milestone extends it to its own surfaces | ADM-001, 003, 004 |
| **ENH-04** Preview + undo (set of 5) | Every write goes through dry-run → diff → approve → execute → verify (FEAS §6.1 #4). Any change made **through activeDIQ** can be undone from its audit record, in every tier. Changes that cannot be reverted, such as passwords, are flagged before execution (ENH-04 risk) | Detecting and reverting changes made **outside** activeDIQ is ENH-22 (M3). The full backup product (ADM-149–153) is M3 | ADM-005, 033, 034, 043, 098; MIG-18 |
| **ENH-05** Report builder (set of 5) | Canned-report parity for ADMP's library, a builder over directory, Entra and activeDIQ-audit data, scheduling, CSV/PDF/XLSX export, act-on-results, and the ME report crosswalk | Reports over DC audit **events** come with the M3 event pipeline (ENH-05 dependency) | ADM-083–101; MIG-05, MIG-06 |
| **ENH-07** Automatic updates (set of 5) | One signed, staged release train with automatic rollback on health-check failure, for both D-0002 profiles. Customer-controlled timing windows (ENH-07 risk). Updates also work under HA, which ADMP's hotfixes do not (ADM W1) | Agents join the train when agents exist (M3) | ADM-209, ADM-213, RMP-046 |
| **ENH-09** Help-desk caller verification (set of 5) | Before a tier-1 technician with no AD rights can reset or unlock, the caller proves identity with an OTP. The verification is audited with the reset (POC #3, LAND §6). v1 factors: one-time codes to email or mobile numbers **already held** in AD or HR data (the zero-touch factors in ADSS §8a, via ENH-03), plus a minimal end-user TOTP enrollment page. The console shows which factor was used | Push verification needs the mobile app (M4). Full SSPR enrollment is ENH-03 (M4). **This deviates from the ADM-136 note** ("caller verification needs P3 authenticators"). FD-05 gives the reason | ADM-136, ADM-137 |
| ENH-02 Migration kit (baseline, ADMP part) | §3.4 | ADAP and ADSSP adapters come with M3 and M4 | MIG-01–06, 10, 14, 16 |
| ENH-08 Least-privilege wizard (baseline) | For each enabled feature: generate the ACLs and gMSA setup, apply with approval, verify (FEAS §2.3) | Full verification needs the effective-permissions engine, a long pole (FEAS §6.2). See §3.7 #2 and FD-08 | ADM-135; MIG-12 |
| ENH-10 Tier-0 trust center (baseline) | Threat model, SBOM per release, disclosure policy, same-day advisories, pentest summary (CV §6.2) | Certification status depends on §8 Q4 | — |

**Included because the parity row's stance already carries it.** These are not extra choices.
- ENH-14 smart CSV import, through ADM-011 (leapfrog).
- An unmetered public REST API, through ADM-188 and ADM-190. This is the API half of ENH-11.
  Webhooks, the PowerShell module and the MCP server follow in M3 (D-0004 sequencing).
- A source-of-authority-aware hybrid view, through ADM-169. The hybrid health-check door-opener
  (ENH-17/19) is not in v1.
- An AD + M365 leaver preview, which falls out of ENH-04 + ADM-043. The cross-system ENH-16 claim
  (file servers, Google) is **not** made for v1.

**Not in v1:**
- ENH-11 webhooks/MCP, ENH-22 and ENH-20 (sequenced after, D-0004);
- ENH-03 and ENH-06 (their products are not in v1);
- ENH-13 (needs DC events);
- everything else in ENH §2.

### 3.6 Explicitly not in v1 (ADManager Plus rows that stay on ME for now)

These are all should/could rows. Milestone placement follows the matrix phase (P2→M3, P3→M4,
P4→M5).

| Area | Rows | Lands in | Why it waits |
|---|---|---|---|
| On-prem Exchange mailbox management and reports | ADM-054, 063–069, 071, 088 | M5 | Windows/PowerShell helper (FEAS App. A #6). ADM §7a lists ADM-088 in its report row, but the matrix grades it should/P4 |
| Exchange Online mailboxes, Teams, M365 canned reports, M365 MFA settings | ADM-028, 163, 165–168, 094 | M5 | EXO needs the PowerShell sidecar (FEAS §1.9). ADM §7a lists ADM-163, but the matrix grades it could. Pull ADM-094 forward if a pilot depends on it `[DISCOVERY]` |
| File servers / NTFS management and reports | ADM-078–082, 091 | M3 | File-server agent; effective-permissions engine (FEAS §6.2) |
| GPO reports in GPMC format; GPO editing | ADM-090 (M3); ADM-072, 074–076 (M5) | M3 / M5 | GPMC helper; GPO editing is XL (FEAS §6.2) |
| AD backup, Backup Explorer, quick recovery, rollback | ADM-149–153 | M3 | A paid add-on in ADMP (ADM §7b). v1 undo covers activeDIQ-made changes |
| Event-driven automation, webhooks, custom scripts and functions, macros, orchestration templates | ADM-019, 032, 108–113 | M3 | ADM-108's leapfrog needs change attribution (MATRIX top-25 #17) |
| Dynamic and time-bound groups; delayed-task queue; extra workflow rows | ADM-052, 053, 036, 122, 123 | M3 | Should rows. Pull forward if a pilot uses them `[DISCOVERY]` |
| Other ITSM, HCM connectors, custom app framework | ADM-193–195 | M3 | Should rows. ServiceNow and ServiceDesk Plus are in v1 |
| Governance (risk assessment, privileged entities, certifications, entitlements) | ADM-174–180 | M3 / M5 | GRC add-on, Pro only (ADM §3.S) |
| Zia AI and ML features | ADM-181–184 | With ENH-20, after USP-2 is proven at a pilot (ENH §3.3) | D-0004 |
| ADSSP approvals routed through ADMP | ADM-124 (= ADSS-115) | M4 | Arrives with ADSSP replacement (§4) |
| Google Workspace, AD migration, mobile apps, Power BI, marketplace, DB options | ADM-029, 095, 155, 171–173, 185–187, 197, 199–203, 211 | M5 (defer) | ADM §7b |
| Remaining could rows | ADM-035, 046, 115 (M3); ADM-031, 140, 144, 154, 156, 170, 196 (M5) | M3 / M5 | Low switching impact (MATRIX importance) |
| Skype/Lync; "backup without the add-on" | ADM-030, 157 | Never | Skip rows (MATRIX) |

**Also not in v1: managing Tier-0 / AdminSDHolder-protected accounts.** These are out of scope
for the main server. They are reached only through an optional, separately deployed Tier-0
connector (FEAS §0), and PILOT excludes them too. Partners keep native tools for those accounts.

### 3.7 Long poles and technical risks inside v1

| # | Item | Why it matters | Mitigation and owner milestone |
|---|---|---|---|
| 1 | **LDAP signing + channel binding from Go on Linux** | WS2025 DCs require signing/sealing; go-ldap has no CBT or sign/seal on Linux. Every v1 feature depends on this (FEAS §0, §6.2) | Own GSSAPI adapter, LDAPS. A **Phase-0 gate in M1**: bind under signing + CBT "Always" with no 2887/3039/3074 events |
| 2 | **Effective-permissions check** for ENH-08 verification | It must match Windows access-check semantics exactly (FEAS §6.2) | A spike in M1 with golden tests against Windows "Effective Access". FD-08 is the fallback |
| 3 | **Windows LAPS decryption from Linux** `[UNVERIFIED]` | ADM-060 is must (FEAS §1.1) | A spike in M1. If it fails, decryption runs on the Windows-installer profile or a helper (factory decision at the gate) |
| 4 | **ADMP config import** | Formats `[UNVERIFIED]`; EULA review `[TODO]` (MIG §9) | ADMP 8043 lab install in M1. PILOT already allows "guided rebuild" if import is not proven. Counsel review is §8 Q5 |
| 5 | **HA + automatic updates under HA** | ADM-209 and ADM-210 are L-complexity must rows | Designed in the deployment ADR (M1); proven in the M2 exit demo |
| 6 | **External pentest gate** | FEAS Phase-1 exit; PILOT precondition | Scheduled before the first pilot (§8 Q3–Q4) |
| 7 | *(conditional)* **Exchange PowerShell helper** | ADM-026/070 | Only if discovery shows on-prem or hybrid Exchange (FD-04) |

**Started in M1 although not needed for v1.** Microsoft's LSA plug-in file-signing enrolment
"in week 1" (FEAS §6.2). Its lead time gates the M4 password filter. The CEO must approve it
(§8 Q5).

### 3.8 Size estimate and reasoning (all figures are Estimates)

**Method.** No factory throughput has been measured yet, so two independent anchors are used.
1. **Row arithmetic.** Each v1 must/should row gets its FEAS complexity band (S ≤2, M 2–6,
   L 6–16, XL 16–24 engineer-weeks; FEAS §6, MATRIX `complexity`), with duplicate rows counted
   once. Result for M2's rows: **≈ 227–616 engineer-weeks**. Add v1 enhancement work that no row
   carries (ENH-02 L, ENH-04 L, ENH-08 L, ENH-09 M, ENH-10 S–M ≈ 21–60). M2 total ≈ **250–680
   engineer-weeks**.
   - This overcounts work that shares engines (report engine, job engine).
   - It undercounts integration, Windows-lab testing and pentest remediation.
2. **FEAS calendar anchor.** Phase 0 is ~8 weeks and Phase 1 is ~4–6 months (FEAS §6.3), so
   ≈25–34 weeks for a scope that is close to M2 but not identical. FEAS Phase 1 also has the SSPR
   web portal and GPO backup. It lacks workflow, automation, JML and ITSM, which add 19 must rows
   (≈41–116 engineer-weeks by row arithmetic).

**Conversion** `[ASSUMPTION]`. Planning uses **1 factory-week ≈ 10 FEAS engineer-weeks**. The
dispatcher today runs at most 2 workers in parallel, with a cap of 60 runs a day
(`factory/config.json`). Replace this ratio with measured throughput after the first ~4 weeks of
M1 build tickets.

| | Row arithmetic at 10 ew/fw | FEAS calendar anchor | **Planning range** | At 5 / 20 ew/fw (sensitivity) |
|---|---|---|---|---|
| M1 Foundation & direction | — | ≈ 8 weeks (Phase 0) | **8–10 fw** | — |
| M2 = v1 | 25–68 fw | ≈ 21–38 weeks (Phase 1 + the ADMP P2 slice) | **25–40 fw** | 50–136 / 13–34 |
| **To v1 (M1 + M2)** | | | **≈ 33–50 fw** | |
| Option B (+M3 scope) | +33–91 fw | + Phase 2: ~17–26 weeks | ≈ 60–95 fw | |
| Option C (+M4 scope) | +33–74 fw | + parts of Phases 2–3 | ≈ 90–145 fw, plus LSA-signing lead time | |

## 4. What a partner can retire on day one, and what stays on ME

**At M2 exit, a partner can switch ADManager Plus off if all of these hold** `[DISCOVERY]` per
account:
1. They do not depend on the rows in §3.6, chiefly:
   - on-prem Exchange mailbox management;
   - NTFS/file-server management;
   - the ADMP Backup or GRC add-ons;
   - EXO mailbox management or the canned M365 reports;
   - Google Workspace;
   - dynamic or time-bound groups.
2. **If they also run ADSSP**, they do not use ADSSP's approval workflow or help-desk-assisted
   reset. Both require ADMP (ADSS W9; ADSS-115, ADSS-116). activeDIQ's help-desk console with
   ENH-09 replaces the technician side of assisted reset. It does not take over ADSSP-originated
   approval requests until M4.
3. If they have on-prem or hybrid Exchange, the Exchange helper was built in M2 (FD-04).
4. Their Tier-0 accounts are administered with native tools (§3.6).

The switch itself runs through the parallel run and the job-ownership lock (MIG-10, MIG-14). The
first pilot is a parallel run with dry-run automations and no decommissioning (PILOT "Scope").
Switching ADMP off is the next step, after the go/no-go readout.

| ME product | At M2 exit (v1) | Replaceable at | Bridge meanwhile |
|---|---|---|---|
| ADManager Plus | **Retireable**, under the conditions above | M2. Residual rows in M3 and M5 | MIG-10, MIG-14 parallel run |
| ADAudit Plus | Stays. activeDIQ audits only its own actions (ADM-137/138). "Who" for native changes needs the M3 event pipeline (ADM-005 note) | M3 (NAS auditing ADA-058/059 in M5 unless pulled forward `[DISCOVERY]`) | ADAP keeps running; ENH-06 history bridge arrives in M3 |
| ADSelfService Plus | Stays. Note the ADMP dependency in condition 2 | M4 | MIG-09 enrollment kit arrives in M4 |
| RecoveryManager Plus | Stays | AD object recovery in M3; Entra, M365 and Exchange recovery in M5 | v1 undo covers activeDIQ-made changes |
| M365 Manager Plus | Stays for mailboxes and reports. Licence, group and account basics overlap v1 | M5 | — |
| Exchange Reporter Plus | Stays | M5 | — |
| AD360 shell | Cannot be retired while any component remains (SUITE §1.3) | After the last component | — |

## 5. Which partner situations v1 fits

The CEO knows which ME products each warm account runs. Read the fit from that.

| If the partner runs… | Fit for the first v1 pilot | What they can switch off at M2 exit | Watch-outs |
|---|---|---|---|
| **ADMP Standard** only | **Strongest.** Standard excludes group/OU/contact management, scheduling, OU delegation, workflow and automation (ADM key takeaway 3), so v1 covers more than it uses | ADMP | On-prem Exchange (FD-04) |
| **ADMP Professional** (± its M365 tab) only | **Strong** | ADMP, if none of the §4 blockers apply | Backup add-on (ADM-149–153 → M3); GRC add-on (→ M3/M5); NTFS management (→ M3) |
| **ADMP + ADAP** | **Good.** A visible switch, but two consoles until M3 | ADMP | ADAP history stays in ADAP until ENH-06 (M3) |
| **ADMP + ADSSP** | **Conditional** | ADMP only if ADSSP approvals and assisted reset are unused (§4 #2). Otherwise nothing until M4 | ADSS W9. Confirm in discovery before promising a switch |
| **AD360 / three or more products** | **Good relationship target, weaker first switch.** Only one of several products goes. The "one console" claim (USP-1) stays partial until M3/M4 | ADMP | Time each later retirement to that product's renewal (STRAT §10.4) |
| **ADAP-only or ADSSP-only** | **Poor for v1.** Nothing to switch off | Nothing | Revisit at M3/M4 |
| **Heavy on-prem Exchange** (any of the above) | **Conditional** | ADMP only once the Exchange helper ships | Mailbox management rows wait for M5 |

The draft ICP prefers accounts running **two or more** ME products (STRAT §3.1). v1 switches off
one. The best first pilot is therefore an ADMP-centric account that also runs ADAP, not one built
around ADSSP. This is the selection guidance for §8 Q1.

## 6. Factory decisions taken in this scope lock (decide-and-note)

| ID | Decision | Reason |
|---|---|---|
| FD-01 | v1 = all 88 ADMP must rows; delivered at M2 exit | D-0001. "Must" means a customer cannot retire the product without it (MATRIX "Importance and phase are independent") |
| FD-02 | Pull the 19 non-Windows ADMP must rows from P2 into M2: ADM-039, 041–044, 047, 104, 105, 107, 114, 116–118, 120, 121, 147, 191, 192, 198 | ADM §7a lists leaver policy, scheduled automation, workflow and ITSM as day-one needs |
| FD-03 | Pull five P2 should rows into M2: ADM-040, 106, 119 (named in ADM §7a ranges 039–041, 104–106, 116–119) and ADM-009, 160 (Graph provisioning) | ADM §7a; D-0001 |
| FD-04 | ADM-026/070 go into M2 only if discovery shows on-prem or hybrid Exchange. ADM-045's NTFS block goes into M3 | FEAS App. A #6, §1.4. Keeps v1 free of Windows-resident components unless a pilot needs one |
| FD-05 | ENH-09 ships in v1 with OTP to existing contact data plus TOTP. Push comes in M4. The full SSPR portal (ADSS-001–004) is not in v1 | D-0004 puts ENH-09 in v1, and ENH-09 lists OTP/TOTP as Phase 1. D-0001 keeps ADSSP out of v1. The portal is the cheapest later pull-forward (MATRIX "Timing differs"). If a named pilot makes it a condition, it goes back to the CEO as a scope decision |
| FD-06 | Snapshot infrastructure (MIG-18) is in M2 as the foundation for undo. The backup product rows (ADM-149–153) stay in M3 | FEAS §6.3 Phase 1; MATRIX "AD snapshots … in P2" |
| FD-07 | The unmetered REST API ships in v1 as parity (ADM-188–190). Webhooks, the PowerShell module and MCP (ENH-11) come in M3 | FEAS §6.1 #7 (API first). D-0004 sequences ENH-11 after the set of 5 |
| FD-08 | ENH-08 verification: if the effective-permissions spike is green in M1, v1 verifies effective access. If not, v1 verifies only the ACEs it generated and says so in the UI | FEAS §6.2 long pole; no claims beyond evidence (CV §6.3) |
| FD-09 | Milestone ↔ phase mapping: M2 = P1 + the pulls above; M3 = rest of P2; M4 = P3; M5 = P4 | CEO's Board naming; MATRIX phases |
| FD-10 | Phase-0 spikes that v1 depends on (§3.7 #1–3) are M1 exit gates. The later long-pole spikes (password filter, credential provider, event ingest, GPO parsing) start in M1 but only gate their own milestone's scope lock | FEAS §6.2–6.3; keeps M1 short |
| FD-11 | No Tier-0 connector in v1 | FEAS §0; PILOT excludes Tier-0 writes |

## 7. Risks to this scope lock

| Risk | Effect | Response |
|---|---|---|
| Discovery shows that partners rely on rows we deferred: Exchange, NTFS, backup add-on, dynamic groups | Day-one retirement slips for that account | Pull individual rows forward as factory decisions with a logged reason. Escalate to the CEO only if the v1 date moves materially |
| Every warm account runs ADMP + ADSSP with approvals in use | No account can switch ADMP off at M2 | Reorder M4 items (ADSS-115/116 native approvals) into a late-M2 slice, which is a scope change for the CEO. Decide after §8 Q1 |
| M2 is long, so the CEO sees too little for too long | Feedback loop breaks | Four internal demo checkpoints (roadmap §M2), each judged by the CEO |
| The factory-throughput assumption is wrong by 2× | Dates move by 2× either way (§3.8 sensitivity) | Re-baseline after ~4 build weeks in M1 |
| ME config import proves infeasible (MIG §9) | ENH-02 becomes "guided rebuild" | PILOT already allows that wording. Fidelity report is still produced |
| ADAP 9000's UI redesign narrows the UX gap (STRAT R7) | ENH-01 wins smaller | Benchmark against current ME builds; do not assert |

## 8. Open questions for the CEO (only these)

1. **Pilot accounts.** Which two warm accounts go first (STRAT §13 Q6)? For each, please tell us:
   - which ME products and editions it runs (ADMP Standard or Pro, ADAP, ADSSP, AD360);
   - whether it has on-prem or hybrid Exchange;
   - whether its ADSSP approvals or help-desk-assisted reset are in use;
   - its renewal or AMS date;
   - its regulator.

   This settles FD-04, the ADMP + ADSSP question in §4, any NAS pull-forward, and the first
   evidence-pack regulator (STRAT §13 Q9). Names go only in `knowledge/business/partnerships/`.
2. **Pricing model and pilot commercials.** P-A/P-B/P-C ± P-D (STRAT §9, §13 Q3), plus the pilot
   fee and conversion terms (PILOT "Commercials"). We need this before any pilot offer leaves the
   building.
3. **Pilot timing.** May the first parallel-run pilot start at M2 checkpoint 2c? At that point
   P1 scope, import and a pentest of that build are done, automations run dry-run only and nothing
   is decommissioned, which matches PILOT's scope. The alternative is to start only at M2 exit.
   *Recommendation: 2c.* PILOT's scope is already Phase-1 scope, and starting there lets the
   8-week pilot overlap the end of M2. The cost is a second, smaller pentest at M2 exit.
4. **Security-evidence investment before the first pilot.** Pentest only, or pentest + SOC 2
   Type II readiness (STRAT §13 Q8; recommendation: pentest + SOC 2 readiness)? Costs are
   `[TODO]`.
5. **M1 external spend and legal sign-off**, all needed in M1:
   - Code-signing (EV) certificate and Microsoft Partner Center / LSA plug-in file-signing
     enrolment (FEAS §6.2, App. A #3). Code signing is needed for the v1 Windows installer and
     signed updates. LSA signing gates the M4 password filter.
   - Azure Windows lab, ≈$71–89/month with auto-shutdown or ≈$168–229/month running 24×7
     (FEAS §0).
   - Counsel review of reading ME exports and databases on a customer's behalf (MIG §9; ADA §7a).

Everything else in this file is a factory decision (§6). The factory will log it and revisit it
from discovery data.

## 9. Follow-ups (factory)

- **Matrix sync.** In `feature-parity-matrix.csv`, set `phase` to P1 for the 24 rows pulled in
  §6 FD-02/FD-03 and for ADSS-091 (a duplicate of ADM-047). Do the same for ADM-026/070 if FD-04
  pulls them. Then regenerate the totals, as the matrix requires ("update the
  row's `phase` in the same change"). That file is owned by another workstream and is not edited
  here; open a ticket.
- Add FD-01…FD-11 to `knowledge/memory/decisions-log.md` (memory skill).
- Move this file to `review` after discovery re-weights the must rows (MATRIX research gap #1).
