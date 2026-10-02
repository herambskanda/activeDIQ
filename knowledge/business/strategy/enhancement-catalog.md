---
title: activeDIQ Enhancement Catalog (beyond parity)
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: heramb
---

# activeDIQ Enhancement Catalog

This catalog lists 28 candidate enhancements **beyond parity** with ManageEngine's AD suite. It
ranks them and offers three "signature sets" for the CEO to choose from. Parity (what a switching
customer needs on day one) is defined in the research files: ADM §7a, ADA §7a and ADSS §8a.

- The strategic frame is in [product-strategy.md](product-strategy.md).
- The competitor picture is in [executive-summary.md](executive-summary.md).
- **Status.** Draft. IDs `ENH-##` are stable once this file reaches `review`. Rank order may change.

**Source key** (cite format: `KEY §section`):
[CV](../market-research/manageengine-ad-customer-voice-and-security.md) ·
[ADM](../market-research/manageengine-admanager-plus.md) ·
[ADA](../market-research/manageengine-adaudit-plus.md) ·
[ADSS](../market-research/manageengine-adselfservice-plus.md) ·
[SUITE](../market-research/manageengine-ad360-suite-and-commercials.md) ·
[LAND](../competitive-analysis/ad-management-market-landscape.md) ·
[FEAS](../../development/architecture/build-feasibility/ad-technical-feasibility.md)

## 1. How the ranking works

Every item gets four scores from 1 to 3. **All scores are Estimates (analyst judgement).**

| Score | 3 | 2 | 1 |
|---|---|---|---|
| **E: evidence** | Several sourced customer-voice or gap signals (e.g., a CV pain theme ≥ ≈10 mentions) | One sourced gap or a moderate signal | Inference or a single source |
| **D: differentiation vs ManageEngine** | ME lacks it, or it requires a second ME product | ME has a partial or add-on version | ME has a comparable capability |
| **S: switching impact** for warm ME accounts | It removes a switching barrier or meets a CEO switching condition directly | It helps a buying persona | Nice to have |
| **F: feasibility** | S or M | L | XL, or research risk |

- **Rank** is by total (max 12). Ties are broken by S, then E, then strategic fit.
- **Complexity** uses the FEAS scale: S ≤2 engineer-weeks; M 2–6; L 6–16; XL >16 or research risk.
- **Phase** refers to FEAS §6.3:
  - Phase 1 is the ADManager core MVP.
  - Phase 2 adds audit and password security.
  - Phase 3 adds breadth and cloud.
- **Differentiation vs the field** is relative to the non-ME vendors in LAND §2. "Weak" means one
  or more of them already ships it.

**Two classes of item**
- **Switch enablers** (ENH-02, 03, 06). These are required for whichever ME product a pilot
  replaces. They are not optional "signature" choices.
- **Signature candidates.** Everything else.

## 2. Ranked catalog

### 2.1 Summary

| Rank | ID | Enhancement | Primary persona | vs ME | vs field | Cx | Score (E/D/S/F) |
|---|---|---|---|---|---|---|---|
| 1 | ENH-01 | Task-first console: universal search + command palette | Admin, help desk | Strong | Medium–Strong | M (ongoing) | 12 (3/3/3/3) |
| 2 | ENH-02 | ManageEngine migration kit (config importers + crosswalks) *(switch enabler)* | Admin, economic buyer | Strong | Medium | L | 11 (3/3/3/2) |
| 3 | ENH-03 | Progressive MFA/SSPR enrollment and zero-touch carry-over *(switch enabler)* | End user, help desk | Medium | Medium | M | 11 (3/2/3/3) |
| 4 | ENH-04 | Preview every change; one-click undo | Admin, security | Medium–Strong | Medium | L | 10 (3/2/3/2) |
| 5 | ENH-05 | Report builder auditors and admins both like | Compliance, admin | Medium | Medium | M–L | 10 (3/2/3/2) |
| 6 | ENH-06 | ADAudit Plus history bridge *(switch enabler)* | Compliance | Medium | Medium | M–L | 10 (3/2/3/2) |
| 7 | ENH-07 | Signed, automatic, staged updates with rollback | Admin, security | Strong | Medium | M–L | 10 (3/3/2/2) |
| 8 | ENH-08 | Least-privilege setup wizard (never Domain Admin) | Security | Strong | Medium | L | 10 (3/3/2/2) |
| 9 | ENH-09 | Help-desk caller verification inside reset/unlock | Help desk, security | Medium–Strong | Medium | M | 10 (3/2/2/3) |
| 10 | ENH-10 | Tier-0 trust center (threat model, SBOM, same-day advisories) | Security, economic buyer | Medium | Medium | S–M | 10 (3/2/2/3) |
| 11 | ENH-11 | Unmetered public API, webhooks and an MCP server | Admin, integrators | Strong | Medium | M | 10 (2/3/2/3) |
| 12 | ENH-12 | Investigation-first audit UX (timelines, diffs, NL search, every tier searchable) | Security, compliance | Medium | Medium | L | 9 (3/2/2/2) |
| 13 | ENH-13 | Lockout root cause with one-click fix in the help-desk flow | Help desk | Medium | Medium | M | 9 (2/2/2/3) |
| 14 | ENH-14 | Smart CSV/HR import (auto-map, names not DNs, row preview) | Admin | Medium–Strong | Medium | S–M | 9 (2/2/2/3) |
| 15 | ENH-15 | Control-mapped evidence packs (incl. DORA, NIS2, CERT-In) | Compliance | Medium | Medium | M | 9 (2/2/2/3) |
| 16 | ENH-16 | Unified leaver preview across AD, M365, file servers, Google | Admin, compliance | Medium | Medium | M | 9 (2/2/2/3) |
| 17 | ENH-17 | Hybrid source-of-authority awareness + hybrid health check | Admin, CIO | `[TODO]` | Medium | M (check) / L (full) | 9 (2/2/2/3) |
| 18 | ENH-18 | Consumer-grade end-user self-service | End user | Strong | Weak–Medium | L | 9 (2/3/2/2) |
| 19 | ENH-19 | Free posture + hybrid scan as a door-opener | Security, CIO | Medium | Weak | M | 9 (2/2/2/3) |
| 20 | ENH-20 | Guard-railed AI operator (plan → diff → approve → execute → undo) | Admin, help desk | Strong | Medium–Strong | L | 8 (2/3/1/2) |
| 21 | ENH-21 | Policy-bound templates with drift detection | Admin, compliance | Strong | `[UNVERIFIED]` | M | 8 (1/3/1/3) |
| 22 | ENH-22 | Detect → attribute → revert for changes made outside activeDIQ | Security | Medium | Weak–Medium | L–XL | 7 (2/2/2/1) |
| 23 | ENH-23 | Audit-readiness self-check (policy/SACL drift + guided fix) | Compliance, admin | Medium | `[UNVERIFIED]` | M | 7 (1/2/1/3) |
| 24 | ENH-24 | Built-in RADIUS service (no Windows NPS dependency) | Admin | Medium | `[UNVERIFIED]` | M | 7 (1/2/1/3) |
| 25 | ENH-25 | Low-noise alerting (incidents, suppression, feedback tuning) | Security | Weak | Weak | M–L | 6 (2/1/1/2) |
| 26 | ENH-26 | SoD / toxic-combination rules at request time | Compliance | Medium | Weak | M–L | 6 (1/2/1/2) |
| 27 | ENH-27 | Offline breached-password corpus | Security | Medium | `[UNVERIFIED]` | M (+ filter dependency) | 6 (1/2/1/2) |
| 28 | ENH-28 | Tier-0 exposure and delegation hygiene (dMSA/BadSuccessor paths, ACL drift) | Security | Weak | Weak | L–XL | 5 (2/1/1/1) |

### 2.2 Detail

#### ENH-01 · Task-first console: universal search and command palette

- **Problem and evidence.**
  - UI and navigation are the #1 complaint, at ≈28 of ~152 coded reviews (CV §2.2 X1).
  - The ADMP User Management landing page has ~64 action links. Its forms mix single-page routes
    with full-page `.do` forms. The Create User page weighed 10.4 MB and took ~20 s to load (demo,
    indicative) (ADM §4.1–4.2).
  - ADSSP settings are split across "Configuration" and "Admin" trees (ADSS §5.3).
- **Idea.**
  - One search box finds any object and offers its actions inline, e.g. "jsmith → reset + unlock".
  - A keyboard command palette.
  - Single-page flows with per-task interaction budgets, such as reset + unlock in ≤3 interactions
    (ADM §7c).
- **Persona.** AD admin and help-desk technician.
- **Differentiation.**
  - **vs ME, Strong.** ADAP 9000 shipped a redesign on 2026-09-30, which we have not seen (ADA §4.1).
  - **vs field, Medium–Strong.** Adaxes still lists a web admin console on its roadmap (LAND §7.1 #2).
- **Complexity.** M per surface, and ongoing.
- **Dependencies.**
  - A public API the UI consumes (FEAS §6.1 #7).
  - The design system.
  - Task-time benchmark scripts (CV §6.2).
- **Risk.** It is easy to claim and hard to prove. Without measured benchmarks it is an adjective.

#### ENH-02 · ManageEngine migration kit *(switch enabler)*

- **Problem and evidence.**
  - Sunk configuration is a top barrier to switching: templates, OU rules, workflows, technician
    roles and automations. Tools are often inherited (CV §5.2–5.3).
  - The landscape rates this "the single biggest lever for warm accounts" (LAND §7.1 #10).
- **Idea.**
  - Import ADMP user templates, naming formats, delegation roles and OU scopes, workflows,
    automations and scheduled reports.
  - Import ADSSP policies, and ADAP alert profiles and schedules.
  - Ship a report crosswalk (ME report → activeDIQ equivalent).
  - Produce an import-fidelity report for each customer (SUITE §8.2; ADM §7c; ADA §7a item 6).
- **Persona.** Admin; economic buyer (lower migration risk).
- **Differentiation.**
  - **vs ME, Strong.** ME will not build this for us.
  - **vs field, Medium.** Cayosoft runs a Replace-ManageEngine program; the depth of its importers
    is `[UNVERIFIED]` (LAND §2.4).
- **Complexity.** L.
- **Dependencies.**
  - Lab installs of current ME builds.
  - Export and DB formats are `[UNVERIFIED]`.
  - EULA/legal review is `[TODO]` (ADA §7a).
  - Target features (templates, RBAC, workflow) must exist first.
- **Risk.** Formats are undocumented and change between builds. Imports may be partial; the
  fidelity report must say exactly what was not migrated.

#### ENH-03 · Progressive MFA/SSPR enrollment and zero-touch carry-over *(switch enabler)*

- **Problem and evidence.**
  - Re-enrolling a workforce is a major switching cost (CV §5.2).
  - ADSSP's own lever is a non-closable HTA popup that blocks the desktop (ADSS §5.2, W15).
  - About half the enrollment surface can move with zero user effort: email/SMS, AD-attribute
    questions, Duo/RSA/RADIUS/Entra, PIV. Security answers are one-way hashed (ADSS §8a).
- **Idea.**
  - Bootstrap every user from imported email and phone, AD-attribute questions and mapped external
    factors.
  - Prompt for a passkey or app enrollment at the next successful login, not with a blocking popup.
  - Migrate OU by OU while ADSSP still runs (ADSS §8a mitigation playbook).
- **Persona.** End user; help-desk lead.
- **Differentiation.**
  - **vs ME, Medium.** It is migration-specific and better enrollment UX.
  - **vs field, Medium.**
- **Complexity.** M.
- **Dependencies.**
  - SSPR core with TOTP and WebAuthn (Phase 1).
  - In-agent enrollment needs the credential provider (Phase 2).
  - TOTP seed and FIDO export are `[UNVERIFIED]` (ADSS §8a).
- **Risk.**
  - App-based factors probably need re-enrollment.
  - Endpoint agent coexistence with ADSSP is untested `[TODO]` (SUITE §8.2).

#### ENH-04 · Preview every change; one-click undo

- **Problem and evidence.**
  - Admins describe ADMP as able to "do significant damage if in the wrong hands" (CV §3.2 #5).
  - Some reviewers report updates or bugs that affected AD (CV X10).
  - ADMP rollback needs the Backup add-on (ADM-153), and no single offboarding preview is
    documented (ADM §4.3).
- **Idea.**
  - Every write shows a diff (AD + Entra + M365 where relevant) before execution.
  - Any change made through activeDIQ can be undone from its audit record.
  - Included in every tier.
- **Persona.** Admin; security.
- **Differentiation.**
  - **vs ME, Medium–Strong.** ME has point-in-time recovery (ADMP 8030, ADAP 8710) as add-on or
    separate features (SUITE §7). It does not offer preview-before-execute in the same flow.
  - **vs field, Medium.** Semperis and Cayosoft sell rollback (LAND §7.3).
- **Complexity.** L.
- **Dependencies.**
  - The job engine with dry-run → diff → approve → execute → verify phases (FEAS §6.1 #4).
  - Snapshots and attribute-level restore (Phase 1).
- **Risk.**
  - Some changes cannot be reverted, such as passwords and certain attributes (ADA-022 notes). The
    UI must say so before execution.
  - Snapshots must exclude sensitive attributes by default (FEAS App. A #9).

#### ENH-05 · A report builder auditors and admins both like

- **Problem and evidence.**
  - Report customization and report UX are the #2 complaint, at ≈17. Examples: "custom reporting is
    somewhat limited"; "old school bar charts"; custom reports that "overflow from the container"
    (CV X2).
  - Canned compliance reports are also the top reason customers stay (CV §2.1).
- **Idea.**
  - Parity on the canned reports auditors know by name (ADA §7a).
  - A builder over the unified object and event model with interactive charts, saved views,
    sharing, scheduling, and export to CSV, PDF and XLSX.
  - "Act on results" from any report (ADM-098).
- **Persona.** Compliance; admin.
- **Differentiation.**
  - **vs ME, Medium.** ME has custom reports (ADM-097; ADA-101).
  - **vs field, Medium.**
- **Complexity.** M–L.
- **Dependencies.**
  - Typed query DSL and report engine (FEAS §4.4 flow 1).
  - Event pipeline for audit reports (Phase 2).
- **Risk.** Report-name parity takes a lot of content work. Auditor acceptance must be tested at
  pilots.

#### ENH-06 · ADAudit Plus history bridge *(switch enabler)*

- **Problem and evidence.**
  - Years of ADAP data back investigations and legal holds (CV §5.2).
  - Customers keep ME running just for retention unless history is bridged (SUITE §8.2).
- **Idea.** Five bridges (ADA §7a options 2–4, 6):
  - a syslog/CEF receiver for the dual-run period;
  - importers for the top ~30 ADAP compliance reports from scheduled CSV exports;
  - EVTX backfill;
  - a read-only legacy-archive view;
  - reuse of the existing audit policy.
- **Persona.** Compliance; security.
- **Differentiation.**
  - **vs ME, Medium.** ME sells "Historic EVT/EVTX file import" as an onboarding service (ADA §1.4).
  - **vs field, Medium.**
- **Complexity.** M–L.
- **Dependencies.**
  - Event pipeline and normalized schema (FEAS §6.1 #5).
  - ADAP report formats are per-report and undocumented (ADA §7a).
- **Risk.**
  - Partial fidelity.
  - Whether the ME Free edition keeps history readable after a lapse is `[UNVERIFIED]` (ADA §7a).

#### ENH-07 · Signed, automatic, staged updates with rollback

- **Problem and evidence.**
  - ≈16 complaints about manual or failed upgrades (CV X3).
  - Sequential service packs (ADA W5; ADSS §5.3).
  - CV ranks this the #1 wedge for evidence × ease of proof (CV §6.1).
  - Slow patching widens exposure windows (CV §4.4).
- **Idea.**
  - One release train for the server, connectors and agents.
  - Signed packages, staged rings, automatic rollback on health-check failure.
  - Signed offline bundles for air-gapped sites (FEAS §4.3).
- **Persona.** Admin; security.
- **Differentiation.**
  - **vs ME, Strong** across the suite. ADAP agents already self-upgrade (ADA §2.2).
  - **vs field, Medium.** SaaS vendors get this inherently.
- **Complexity.** M–L.
- **Dependencies.** Deployment profiles and the signing infrastructure.
- **Risk.**
  - A bad automatic update on a Tier-0 tool would have high impact. It needs rings and a fast
    rollback.
  - Some customers will require change windows, so the timing must be controllable.

#### ENH-08 · Least-privilege setup wizard (never Domain Admin)

- **Problem and evidence.**
  - ADAP's fast setup path is Domain Admin; the least-privilege path is a long manual procedure
    (ADA §4.2).
  - ADSSP's guides ask for a Domain Admin service account (ADSS W6).
  - ADMP's least-privilege path is a Delegation-of-Control PDF (ADM §4.4).
- **Idea.**
  - For each enabled feature, generate the exact ACLs and gMSA setup.
  - Apply them with approval, then **verify** them.
  - Show what activeDIQ can and cannot touch (FEAS §2.3).
- **Persona.** Security; admin.
- **Differentiation.**
  - **vs ME, Strong.**
  - **vs field, Medium.** Semperis sells Delegation Manager separately (LAND §7.1 #7b).
- **Complexity.** L.
- **Dependencies.**
  - Security-descriptor primitives (FEAS §6.1 #2).
  - Verification needs the effective-permissions engine, a long pole (FEAS §6.2).
- **Risk.** AD ACL semantics are subtle, and a wrong grant on Tier 0 is serious. It needs golden
  tests against Windows "Effective Access".

#### ENH-09 · Help-desk caller verification inside reset/unlock

- **Problem and evidence.**
  - Voice phishing is the #2 initial vector at 11% (Mandiant M-Trends 2026).
  - CISA AA23-320A describes help-desk resets and MFA transfers.
  - M&S guided c.£300m of impact (LAND §4.2).
  - In ME, approvals and help-desk-assisted reset for ADSSP require ADMP (ADSS W9).
- **Idea.**
  - Before a tier-1 agent can reset or unlock, the caller proves identity: an OTP or push to an
    enrolled factor.
  - The agent needs no AD rights.
  - The verification is audited with the reset. This is POC test #3 (LAND §6).
- **Persona.** Help-desk lead; security.
- **Differentiation.**
  - **vs ME, Medium–Strong**, because it is one product instead of two.
  - **vs field, Medium.** Specops sells Secure Service Desk (LAND §7.3).
- **Complexity.** M.
- **Dependencies.**
  - Enrollment (ENH-03).
  - RBAC.
  - OTP/TOTP in Phase 1; push needs the mobile app (Phase 3).
- **Risk.** Low technically. Adoption depends on enrollment coverage.

#### ENH-10 · Tier-0 trust center

- **Problem and evidence.**
  - Buyers will ask every vendor for an SBOM, dependency SLAs, same-day advisories with consistent
    CVSS, signed updates, no default credentials, admin MFA, a minimal unauthenticated surface and
    a pentest attestation (CV §4.4).
  - ME's fix-to-NVD median is 60 days (CV §4.3).
- **Idea.**
  - A public page and an NDA pack containing:
    - the threat model;
    - an SBOM per release;
    - the disclosure policy and bug bounty;
    - advisories published the same day as the fix;
    - a pentest summary;
    - certification status (CV §6.2).
- **Persona.** Security; economic buyer.
- **Differentiation.**
  - **vs ME, Medium.** ME has an advisory portal and a bug bounty (CV §4.3).
  - **vs field, Medium.**
- **Complexity.** S–M for engineering, plus external costs `[TODO]`.
- **Dependencies.**
  - SCA/SBOM in CI.
  - A CNA or disclosure process.
  - The external pentest gate (FEAS §6.3).
- **Risk.**
  - We will have CVEs too. Transparency must be real, not marketing (CV §6.3).
  - Never compare CVE counts.

#### ENH-11 · Unmetered public API, webhooks and an MCP server

- **Problem and evidence.**
  - The ADMP REST API is capped at 50 calls per technician per day, with paid overage. ITSM
    integrations draw from the same quota (ADM §1.5).
  - ADAP has no documented public API or webhooks (ADA W13).
  - ADSSP's REST API is "in pipeline" (ADSS W8).
  - ME lists no AD/AD360 MCP server (SUITE §7).
- **Idea.**
  - The same OpenAPI the UI uses, unmetered.
  - Signed webhooks and an event stream.
  - A PowerShell module.
  - A read-only MCP server first, with write tools behind the approval engine (LAND §7.1 #3).
- **Persona.** Admin; integrators (ITSM, HR, SOC).
- **Differentiation.**
  - **vs ME, Strong.**
  - **vs field, Medium.** Netwrix ships MCP servers (LAND §4.5).
- **Complexity.** M.
- **Dependencies.**
  - API-first core (FEAS §6.1 #7).
  - RBAC scopes applied to API tokens.
- **Risk.** The MCP and API surface becomes an attack surface. It needs the same authentication,
  scoping and audit as the UI.

#### ENH-12 · Investigation-first audit UX

- **Problem and evidence.**
  - ADAP lists about 1,000 report entries with overlapping groupings (ADA W12).
  - Cold and Frozen archives are not searchable without a restore (ADA W8).
  - Reviewers mention sluggish long-range filtering (CV X1).
- **Idea.**
  - Object and user timelines with attribute diffs.
  - Natural-language questions such as "who added anyone to Domain Admins last quarter?"
  - Every storage tier searchable.
  - Revert and approval actions directly on the timeline (ADA §7c #1–2).
- **Persona.** Security; compliance.
- **Differentiation.**
  - **vs ME, Medium, and narrowing.** ADAP 9000 shipped Activity Explorer (ADA-103).
  - **vs field, Medium.**
- **Complexity.** L.
- **Dependencies.**
  - Event pipeline and attribution (Phase 2).
  - Tiered storage.
  - ENH-04 for in-place revert.
- **Risk.** Storage cost at DC event volume (FEAS §6.2).

#### ENH-13 · Lockout root cause with one-click fix

- **Problem and evidence.**
  - A former ADAP user: "doesn't really give me enough information on account lock outs" (CV §5.1).
  - ADSSP reviewers want lockout diagnosis, and no root-cause tooling is documented (ADSS W16).
  - ADAP's Account Lockout Analyzer is Pro-only and lives in a separate product from the unlock
    action (ADA-038).
- **Idea.**
  - In the unlock screen, show the source host and process and the likely stale credential
    (service, scheduled task, mapped drive, mobile mail).
  - Offer the fix: unlock + notify, or open a task on the source.
- **Persona.** Help-desk technician.
- **Differentiation.**
  - **vs ME, Medium**, because it is integrated into the help-desk flow and included in every tier.
  - **vs field, Medium.**
- **Complexity.** M.
- **Dependencies.**
  - DC agent events (Phase 2).
  - Endpoint data from the platform agent.
- **Risk.** Root-cause accuracy across sources such as ActiveSync and IIS logs (ADA-038 notes).

#### ENH-14 · Smart CSV/HR import

- **Problem and evidence.**
  - ADMP CSV import requires LDAP attribute names as headers, and DNs for `memberOf` and manager
    (ADM §4.3, ADM-011).
  - Reviewers name HR-connector gaps (CV §5.3).
- **Idea.**
  - Auto-map column headers.
  - Accept group and manager names instead of DNs.
  - Validate row by row, and preview through ENH-04.
  - Save mappings and reuse them for scheduled HR feeds.
- **Persona.** Admin.
- **Differentiation.**
  - **vs ME, Medium–Strong.**
  - **vs field, Medium.**
- **Complexity.** S–M.
- **Dependencies.** Directory connector and ENH-04.
- **Risk.** Low. Name collisions need explicit disambiguation.

#### ENH-15 · Control-mapped evidence packs

- **Problem and evidence.**
  - No NIS2, DORA or CMMC page was found for ADAP `[UNVERIFIED absence]` (ADA-099).
  - ISO 27001, NIST 800-53, CMMC and NIS2 mappings are not documented for ADMP (ADM W14).
  - Regulation creates concrete checkboxes: DORA RTS Art. 21 and PCI 7.2.4 six-monthly reviews;
    RBI privileged MFA; CERT-In 180-day in-country logs (LAND §4.7).
- **Idea.**
  - Evidence packs keyed to control IDs: report, approver, timestamp and tamper-evident export.
  - Packs for the warm accounts' regulators first (product-strategy §13 Q9).
- **Persona.** Compliance / internal audit.
- **Differentiation.**
  - **vs ME, Medium.**
  - **vs field, Medium.**
- **Complexity.** M, and content-heavy.
- **Dependencies.**
  - ENH-05.
  - Hash-chained audit log (FEAS §6.1 #1).
- **Risk.** Control mappings carry legal weight. They need expert review before any external claim.

#### ENH-16 · Unified leaver preview

- **Problem and evidence.** ADMP offboarding is a configured policy. "A single offboarding screen
  that previews every change across AD, M365, Google Workspace and file servers is not documented"
  (ADM §4.3).
- **Idea.**
  - One leaver screen shows every change about to happen: disable, licences, groups, mailbox, OU
    move, file shares, Google.
  - Steps can be scheduled in stages and approved.
  - Any step can be undone.
- **Persona.** Admin; compliance.
- **Differentiation.**
  - **vs ME, Medium.**
  - **vs field, Medium.**
- **Complexity.** M.
- **Dependencies.**
  - ENH-04.
  - M365/Graph and Google connectors, which FEAS places in Phase 3 (see product-strategy R3).
- **Risk.** Depends on the hybrid-sequencing decision (product-strategy §13 Q1).

#### ENH-17 · Hybrid source-of-authority awareness and a hybrid health check

- **Problem and evidence.**
  - Group source-of-authority (SOA) conversion has been GA since Oct 2025, and user SOA since
    Jan 2026.
  - Connect Sync must be upgraded by **7 Apr 2027**, and Microsoft is steering customers to
    Cloud Sync (LAND §4.1).
- **Idea.**
  - Show whether each object is authored in AD or in Entra.
  - Plan SOA conversion safely, as "AD DS minimization".
  - Ship a hybrid health check now as a door-opener (LAND §7.1 #6).
- **Persona.** Admin; CIO.
- **Differentiation.**
  - **vs ME `[TODO]`.** ME's SOA handling is not covered in the research.
  - **vs field, Medium.**
- **Complexity.** M for the health check; L for full SOA-aware management.
- **Dependencies.** Graph connector.
- **Risk.**
  - Microsoft's APIs and timelines are moving.
  - The health check must not overreach into consulting.

#### ENH-18 · Consumer-grade end-user self-service

- **Problem and evidence.**
  - The ADSSP iOS app is rated 2.1/5 (75 ratings), with reviews citing slowness.
  - Push breaks when the server's bundled certificate expires.
  - Portal branding is rigid (ADSS §5.1–5.2, W14).
- **Idea.**
  - An accessible (WCAG 2.1 AA), localized self-service portal and app.
  - Number-matching push.
  - Enrollment inside the logon agent (ADSS §8c L3).
- **Persona.** End user.
- **Differentiation.**
  - **vs ME, Strong.**
  - **vs field, Weak–Medium.** IdP vendors set a high bar.
- **Complexity.** L, because of the mobile app.
- **Dependencies.**
  - Push MFA app (Phase 3).
  - Credential provider (Phase 2).
- **Risk.** Mobile apps are a long-term support burden. Standard TOTP and passkeys may be enough
  for pilots.

#### ENH-19 · Free posture and hybrid scan as a door-opener

- **Problem and evidence.**
  - Free assessment tools are the category's proven lead-generation motion (PingCastle, Purple
    Knight).
  - Netwrix tightened PingCastle licensing (LAND §7.1 #9, §2.13).
- **Idea.**
  - A free, read-only scanner covering Tier-0 hygiene, the hybrid sync posture (ENH-17) and stale
    objects.
  - Its report quantifies risk for warm accounts.
- **Persona.** Security; CIO.
- **Differentiation.**
  - **vs ME, Medium.**
  - **vs field, Weak.** Several free tools exist.
- **Complexity.** M.
- **Dependencies.**
  - Directory connector.
  - Posture queries (FEAS §1.5.2).
- **Risk.** A scanner is itself security-sensitive software that must stay read-only. It is also a
  maintenance commitment.

#### ENH-20 · Guard-railed AI operator

- **Problem and evidence.**
  - ADMP's Zia covers 4 chat actions plus reports. It needs the customer's own Azure OpenAI key and
    carries a disclaimer that responses may contain mistakes (ADM W11).
  - LAND finds no vendor shipping rollback-native agentic changes for on-prem AD (LAND §4.5, §7.1 #3).
  - ME announced Zia Agents suite-wide in May 2026 (SUITE §7).
- **Idea.**
  - A natural-language request becomes a plan and a diff preview.
  - The plan goes through RBAC-scoped approval, then executes with one-click undo.
  - The agent is itself a governed identity.
  - Provider-agnostic, with a self-hosted model option.
- **Persona.** Admin; help desk.
- **Differentiation.**
  - **vs ME, Strong today, but ME is moving.**
  - **vs field, Medium–Strong.**
- **Complexity.** L.
- **Dependencies.** ENH-04, ENH-11 and the RBAC/approval engine.
- **Risk.**
  - AI errors on Tier 0.
  - Model hosting choices for regulated customers.
  - Must never bypass preview and approval (product-strategy §8).

#### ENH-21 · Policy-bound templates with drift detection

- **Problem and evidence.** In ADMP, "changing a template does not update users already created
  from it" (ADM W13).
- **Idea.**
  - Users stay bound to their template or role.
  - Template changes propose updates to existing users through preview and approval.
  - Drift is detected and offered for correction.
- **Persona.** Admin; compliance.
- **Differentiation.**
  - **vs ME, Strong.**
  - **vs field `[UNVERIFIED]`.**
- **Complexity.** M.
- **Dependencies.** ENH-04; the template engine.
- **Risk.** Mass updates from a template edit. Requires preview and staged rollout.

#### ENH-22 · Detect → attribute → revert for changes made outside activeDIQ

- **Problem and evidence.**
  - ADMP's event-driven automation fires only on ADMP's own actions (ADM W10).
  - "Who changed it" lives in ADAP, "restore it" in RMP/ADMP/ADAP, and "approve it" in ADMP
    (SUITE §8.3).
  - Under "Impersonate as Admin", DC logs record the service account (ADM W4).
  - This is POC test #2: a malicious Tier-0 change detected and **auto-reverted** (LAND §6).
- **Idea.**
  - DirSync deltas plus DC events, correlated to "who".
  - Policy-driven auto-revert for Tier-0 objects.
  - Revert or approve directly from the alert.
- **Persona.** Security / SOC.
- **Differentiation.**
  - **vs ME, Medium.** ADAP can revert from reports (ADA-022, add-on).
  - **vs field, Weak–Medium.** Semperis and Cayosoft do this (LAND §7.3).
- **Complexity.** L–XL.
- **Dependencies.**
  - DirSync change history (Phase 1).
  - DC agent attribution (Phase 2).
  - ENH-04.
- **Risk.**
  - Attribution accuracy.
  - Auto-revert loops with legitimate tools.
  - Collection at DC scale, ≈3k events/s per collector (FEAS §6.2).

#### ENH-23 · Audit-readiness self-check

- **Problem and evidence.** ADAP emails notifications about collection failures and shares missing
  SACLs (ADA-097). LAND proposes continuous checks with guided fixes (ADA §7c #8).
- **Idea.**
  - Continuous checks on audit policy, SACLs and collection health.
  - A guided fix with preview.
  - "Audit gap" evidence for auditors.
- **Persona.** Compliance; admin.
- **Differentiation.**
  - **vs ME, Medium.**
  - **vs field `[UNVERIFIED]`.**
- **Complexity.** M.
- **Dependencies.** DC agent (Phase 2) and ENH-04.
- **Risk.** Low.

#### ENH-24 · Built-in RADIUS service

- **Problem and evidence.** ADSSP's VPN MFA requires Windows NPS plus an extension (ADSS W11).
- **Idea.**
  - A RADIUS server inside activeDIQ (FEAS §3.5 already plans one).
  - VPN MFA without an NPS dependency.
- **Persona.** Admin.
- **Differentiation.**
  - **vs ME, Medium.**
  - **vs field `[UNVERIFIED]`.**
- **Complexity.** M.
- **Dependencies.** MFA methods. MSCHAPv2/PEAP needs Netlogon pass-through or NPS (FEAS App. A #7).
- **Risk.** Protocol coverage for target VPNs is unknown.

#### ENH-25 · Low-noise alerting

- **Problem and evidence.**
  - "Your inbox will get absolutely flooded with routine notifications and false alarms" (CV X11).
  - ADAP 9000 fixed false positives in five detections and only then added whitelisting (ADA W7).
- **Idea.**
  - Correlate detections into incidents.
  - Suppression from day one.
  - Thresholds tuned from feedback.
  - Privileged context on every alert (ADA §7c #6).
- **Persona.** Security / SOC.
- **Differentiation.**
  - **vs ME, Weak.** ME added whitelisting in 9000.
  - **vs field, Weak.**
- **Complexity.** M–L.
- **Dependencies.** Event pipeline and detection rules (Phase 2).
- **Risk.** It is hard to show in a short pilot.

#### ENH-26 · SoD / toxic-combination rules

- **Problem and evidence.** ADMP documents no SoD rule engine. ME's own SoD article maps SoD to
  delegation, workflow and certification (ADM W14).
- **Idea.** Toxic-combination rules over AD/Entra groups and roles, checked at request time and
  in certifications.
- **Persona.** Compliance.
- **Differentiation.**
  - **vs ME, Medium.**
  - **vs field, Weak.** IGA vendors own this.
- **Complexity.** M–L.
- **Dependencies.** Workflow engine and access certification.
- **Risk.** Scope creep toward full IGA, which is an anti-goal (product-strategy §8).

#### ENH-27 · Offline breached-password corpus

- **Problem and evidence.** ADSSP's breached-password check (HIBP) needs outbound internet. No
  offline corpus is documented (ADSS W13).
- **Idea.**
  - A local, signed breached-password corpus, updated through the offline bundle path.
  - Enforced by the password filter.
- **Persona.** Security; air-gapped customers.
- **Differentiation.**
  - **vs ME, Medium.**
  - **vs field `[UNVERIFIED]`.** Specops sells breached-password protection (LAND §7.3).
- **Complexity.** M, on top of the password filter.
- **Dependencies.** Password filter and LSA signing, an XL long pole (FEAS §6.2).
- **Risk.** It is gated by the filter's timeline. Corpus size and licensing are `[TODO]`.

#### ENH-28 · Tier-0 exposure and delegation hygiene

- **Problem and evidence.**
  - Akamai found non-admins with dMSA (BadSuccessor) rights in 91% of the environments it examined
    (LAND §4.2).
- **Idea.**
  - A who-can-write-what view for Tier 0, with ACL drift alerts.
  - Fixes go through ENH-04.
- **Persona.** Security.
- **Differentiation.**
  - **vs ME, Weak.** ADAP 9000 ships Access Analyzer with attack paths and effective permissions,
    and ADMP has Risk Exposure Management (ADA §5; ADM §5).
  - **vs field, Weak.** BloodHound, Semperis and PingCastle cover this ground.
- **Complexity.** L–XL.
- **Dependencies.** Effective-permissions engine, a long pole (FEAS §6.2).
- **Risk.** We would be competing on detection breadth, where we said we would not fight
  (LAND §7.2).

## 3. Signature sets

### 3.1 Baseline in every option (not counted in the sets)

**Switch enablers**, for whichever ME product a pilot replaces:
- ENH-02 migration kit;
- ENH-03 enrollment carry-over (if ADSSP is in scope);
- ENH-06 history bridge (if ADAP is in scope).

**Tier-0 proof**:
- ENH-08 least-privilege wizard;
- ENH-10 trust center.

USP-4 depends on both, and the pilot entry gate needs them (product-strategy §10.2).

### 3.2 The three options

All effort figures are **Estimates**, summed from the FEAS complexity bands.

| | **Set of 3: "Easy and safe"** | **Set of 5: "Every persona wins"** | **Set of 8: "The closed loop"** |
|---|---|---|---|
| Items | ENH-01 task-first console · ENH-04 preview + undo · ENH-07 automatic updates | Set of 3 + ENH-05 report builder · ENH-09 help-desk caller verification | Set of 5 + ENH-22 detect → attribute → revert · ENH-11 open API + MCP · ENH-20 guard-railed AI operator |
| Evidence covered | UI ≈28 (X1), upgrades ≈16 (X3), fear of damage (X10) | + reports ≈17 (X2), help-desk vishing (LAND §4.2) | + native-change attribution (ADM W4, W10), API metering (ADM §1.5), AI lane (LAND §4.5) |
| Personas served | Admin, security (partly) | Admin, help desk, security, compliance, economic buyer | All, plus SOC and integrators |
| Effort | ≈ 10–38 engineer-weeks (M + L + M–L) | ≈ 14–60 engineer-weeks | ≈ 28–100+ engineer-weeks |
| FEAS phase fit | Phase 1 | Phase 1. Push-based verification waits for Phase 3; OTP works in Phase 1 | Needs Phase 2 (DC attribution) and a stable USP-2 before AI writes |
| Demo story | "Do it faster, see it first, take it back, and never run an upgrade again" | Adds "auditors get their reports their way" and "your help desk can't be talked into a reset" | Adds "any change, made anywhere, caught and undone", "your tools and agents plug in", and "ask in English, approve the diff" |
| Biggest risk | Too thin for security buyers; looks like a nicer ADMP | Report-parity content workload | Schedule. ENH-22 is L–XL; the AI story arrives before the evidence for it does |

**Why each set is shaped this way**
- **Set of 3.** These are the three most-evidenced pains that we can show in under five minutes each.
  They map directly to the CEO's conditions: easier (ENH-01), meaningful enhancement (ENH-04) and
  less operational burden (ENH-07).
- **Set of 5.** This adds the #2 complaint (reports) and the fastest-rising attack path (help-desk
  social engineering). With it, each of the five buying personas in LAND §6 has at least one
  signature item, so every stakeholder in a pilot sees something for them.
- **Set of 8.** This completes the closed loop the strategy describes in USP-1 and USP-2. It covers
  POC test #2 (auto-revert), the open-platform answer to ME's API metering, and a guard-railed AI
  operator that the landscape finds no one shipping for on-prem AD. It is the most differentiated
  set and the least certain to land on time.

### 3.3 Recommendation (for CEO decision, not decided)

**Choose the set of 5 as the signature for the pilot release.** Sequence the three set-of-8 additions
as the next milestone, in this order:
1. ENH-11, once the API exists;
2. ENH-22, once DC attribution lands;
3. ENH-20, once USP-2 has been proven at a pilot.

Reasons:
- The set of 5 is the smallest set that gives every buying persona a reason to switch.
- It stays within FEAS Phases 1–2.
- It does not stake the pilot on the XL-risk items: native-change attribution at DC scale, and AI
  writes to Tier 0.
- The set of 3 risks losing the security and compliance stakeholders, who can veto a Tier-0 tool.
- The set of 8 risks the pilot date.

**Decision needed from the CEO:**
- 3, 5 or 8;
- whether any item should be swapped in, for example ENH-13 lockout root cause if the warm accounts'
  help desks rank lockouts above caller verification.
