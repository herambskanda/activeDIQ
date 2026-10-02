---
title: activeDIQ Product Strategy
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: heramb
---

# activeDIQ Product Strategy

This is the source of record for **why** activeDIQ exists, **who** it is for and **how** it wins.
It is a draft. Nothing in it is decided until the CEO rules on the open questions in §13.

**Conventions**
- Facts are as of 2026-10-02.
- **Estimate** marks analyst arithmetic or judgement.
- `[ASSUMPTION]` marks something not stated by the CEO and not sourced.
- `[UNVERIFIED]` tags are carried over from the source documents.
- Pricing (§9) is CEO-owned. It is written as options, not decisions.

**Source key.** Citations use the format `KEY §section`.

| Key | Document |
|---|---|
| CV | [customer voice & security](../market-research/manageengine-ad-customer-voice-and-security.md) |
| ADM | [ADManager Plus](../market-research/manageengine-admanager-plus.md) |
| ADA | [ADAudit Plus](../market-research/manageengine-adaudit-plus.md) |
| ADSS | [ADSelfService Plus](../market-research/manageengine-adselfservice-plus.md) |
| SUITE | [AD360 & commercials](../market-research/manageengine-ad360-suite-and-commercials.md) |
| LAND | [market landscape](../competitive-analysis/ad-management-market-landscape.md) |
| FEAS | [technical feasibility](../../development/architecture/build-feasibility/ad-technical-feasibility.md) |
| UEM | [UEM product strategy](../../../../UEM/knowledge/business/strategy/product-strategy.md) |
| PM | [PatchIQ postmortem](../../../../UEM/knowledge/development/legacy/patchiq-postmortem.md) |
| DS | [skenzeriq design system](../../../../design-system/README.md) |

Companion documents:
- [executive-summary.md](executive-summary.md): what we are up against.
- [enhancement-catalog.md](enhancement-catalog.md): ENH-## items and the signature sets.

---

## 1. North star

> **Every identity change in a hybrid Microsoft estate is made, approved, audited and, if needed,
> undone from one place, by people who did not need a course to learn it, with a tool a CISO can
> sign off as safe for Tier 0.**

"Hybrid Microsoft estate" means AD + Entra ID + M365.

The statement turns the CEO's three switching conditions into one product property:
- **parity** on the features customers rely on;
- **meaningful enhancements**;
- **far easier to use, with a much better UI**.

The phrase "did not need a course" answers a reviewer quote: "It's almost like you need to take a
course on how to manoeuvre within it" (CV §2.2 X4).

**Proposed north-star metrics.** These are proposals for the CEO to accept or replace.

| Metric | Why this one |
|---|---|
| **ManageEngine products switched off** at pilot accounts | The outcome the warm-account strategy depends on. A customer running both products is not a switch |
| **Share of routine identity tasks done in activeDIQ** at each pilot account | Measures real adoption, not licence count |
| **Median task time vs the customer's ADMP baseline** on 10 scripted tasks | Turns "far easier" into a number (CV §6.2) |

## 2. The thesis: why we win at these customers

### 2.1 The argument

1. **The pain is real, durable and documented.** In ~152 coded reviews, the top complaints are
   UI and navigation (≈28), report customization (≈17), manual or failed upgrades (≈16) and
   cross-module seams (≈11) (CV §2.2). These complaints go back to 2021 or earlier (CV §3.2 #2) and
   still appear in vendor-solicited 2026 reviews (CV §1.1).
2. **The pain is structural, so ME cannot fix it fast.**
   - AD360 is "a launcher plus config sync plus SSO plus partial report aggregation" over seven
     separately installed, patched and databased products (SUITE §1.3).
   - ME's consolidation effort is going into Unified Log360 and the Identity360 SaaS, not into the
     AD360 shell (SUITE §7). The shell shipped one build in 2026 (SUITE §1.1).
   - A unified data model, one role model and one release train are architecture properties. They
     cannot be bolted on (inference).
3. **What keeps customers is switching cost, not loyalty.** Price is ME's top praise. Beyond price,
   customers stay because of compliance reports, sunk configuration, audit history and MFA
   re-enrollment (CV §5.2). We can neutralize each of these with product features (§6, USP-5),
   which a challenger without migration tooling cannot.
4. **The relationships are warm.** The CEO has relationships with enterprises running ME AD products
   that will switch on parity + enhancements + UX (CEO brief). That shortens the slowest part of
   enterprise sales: getting a pilot.
5. **The timing is right.**
   - Hybrid estates must touch their sync layer before Microsoft's Connect Sync deadline of
     **7 Apr 2027** (LAND §4.1).
   - 2026 brought critical ME fixes in ADAP and ADSSP, and a suite-seam SSO bug (CV §4.1).
   - Identity360 was repriced 2.6–4.5× in Aug 2026. That is a signal of what an ME-driven
     "move to cloud" could cost these customers (SUITE §1.5, §6.5).

### 2.2 What must be true (validate in discovery before scope lock)

| # | Assumption | How we test it |
|---|---|---|
| A1 | Warm accounts run ≥2 of ADMP/ADAP/ADSSP and are hybrid (AD + Entra/M365) `[ASSUMPTION]` | Discovery checklist per account (§10.1) |
| A2 | The features they *use* are a manageable subset of the ME catalogue. FEAS's Phase-3 exit criterion is "≥90% of the features customers actually use" (FEAS §6.3) | Usage survey plus a ME config export review per account |
| A3 | They will accept agents and a password-filter DLL on DCs, or agentless (WEF) collection is enough (FEAS App. A #2) | Security-team conversations during discovery |
| A4 | The deployment model we choose is acceptable to their security teams: self-hosted vs SaaS with outbound-only connectors (FEAS App. A #5) | Ask; see §13 Q2 |
| A5 | ME configuration, audit history and enrollment can be extracted. Several paths are `[UNVERIFIED]` (ADA §7a; ADSS §8a; SUITE §8.2) | Lab installs of current ME builds; legal/EULA review `[TODO]` |
| A6 | The accounts will pay at or near ME's fully loaded stack price for a better product `[ASSUMPTION]` | Pricing conversations framed as options (§9) |

If A2 or A5 fails, the thesis still holds, but the time to a first switch grows. If A4 fails for
our chosen deployment model, the product cannot be sold to that account.

## 3. ICP and personas

### 3.1 Ideal customer profile (hypothesis)

| Dimension | ICP | Evidence / reason |
|---|---|---|
| Incumbent | Runs **two or more** of ADMP, ADAP, ADSSP, or AD360 | The seam pain only exists with several products (CV X5; SUITE §8.3) |
| Directory | Hybrid: on-prem AD plus Entra ID / M365 | Most targets are hybrid (ADA §7a, our assumption); hybrid is the durable product (LAND §4.3) |
| Size | ~1,000–20,000 users `[ASSUMPTION]` | Matches the commercial scenarios in SUITE §6.3. Below ~500 users, ME's free tiers and low price dominate |
| Drivers | Compliance-driven (SOX, PCI, DORA, NIS2, RBI/CERT-In) with a security team that vets Tier-0 tools | The audit mandate is why ADMP is bought (CV §3.2 #6). Security reviews favour evidenced vendors (CV §4.4) |
| Timing | ME renewal or AMS date within 6–12 months | Renewal moments are the switching window (CV §5.4; SUITE §6.4) |
| Relationship | Warm CEO relationship | CEO brief |

**Not ICP for now:**
- cloud-only (Entra-only) organizations;
- MSPs, which are a separate go-to-market (ADM §7b);
- buyers who want full IGA (LAND §7.2);
- very small estates served by free tiers.

### 3.2 Personas

These are drawn from LAND §6. Primary research with the warm accounts is `[TODO]`.

| Persona | Role in the deal | Pain we can evidence | What wins them |
|---|---|---|---|
| **AD / systems admin** | Daily user; runs the hands-on trial | Navigation depth; CSV needs LDAP attribute names and DNs; macro-string naming formats; settings outside the UI (ADM §4; CV X1, X4) | Fast task flows; preview and undo; one console for AD + Entra + M365 |
| **Help-desk lead** | Owns ticket volume and tier-1 tooling | Lockout diagnosis gaps (CV §5.1); enrollment friction (ADSS W15); vishing risk (LAND §4.2) | Reset and unlock in a few interactions; built-in caller verification; lockout root cause |
| **Security / SOC** | Can veto | Category KEV history (CV §4); Domain Admin service accounts (ADSS W6; ADA §4.2); alert noise (CV X11) | Evidenced Tier-0 posture; least-privilege setup; SIEM streaming; change revert |
| **Compliance / audit** | Defines "done" for parity | Depends on canned reports with names auditors recognize (ADA §7a); needs "reports that cant be manipulated" (CV §5.2) | Report parity plus control-mapped evidence packs; tamper-evident audit |
| **IT manager / CIO / CISO** | Economic buyer | Licence complexity (CV X8); hidden TCO (SUITE §6.7); upgrade labour (CV X3) | One licence; migration included; 3-year TCO; reference customers |
| **End user** | Makes or breaks SSPR adoption | ADSSP iOS app at 2.1/5; an enrollment popup that blocks the desktop (ADSS §5.1–5.2) | Enrollment at next login, no blocking; a modern self-service UI |

## 4. Positioning statement

> **For** IT and security teams in mid-size and large enterprises that run ManageEngine's AD tools
> on hybrid Active Directory and Entra ID,
> **who** need to manage, audit, secure and recover identities without stitching products together,
> **activeDIQ** is a single identity-operations platform. In it, every change can be previewed,
> approved, audited and undone, from a console your help desk can use on day one.
> **Unlike** ManageEngine's AD suite, which runs as separately installed products joined by the
> AD360 launcher (SUITE §1.3),
> **we** offer one data model, one console, one role model, one licence and one automatic release,
> plus migration tooling that brings your configuration, audit history and users with you.

Rules for using this statement externally (CV §6.3):
- The "Unlike" clause states a sourced architectural fact. It must not be strengthened into
  adjectives about ME.
- Any external use of this statement is a CEO decision.

## 5. Value pillars

| Pillar | Promise | Pain it answers | Proof we owe |
|---|---|---|---|
| **1. One product, not seven** | Manage, audit, self-service and recovery for AD + Entra + M365 in one console, one role model and one licence | Separate products, logins and updates (CV X5; SUITE §1.3); the same capability sold in several SKUs (SUITE §4.7) | A live demo: the same object followed from change → audit → revert → approval without leaving the screen |
| **2. Fast for the work people do every day** | The top-20 admin and help-desk tasks in the fewest interactions, measured | UI and navigation are the #1 complaint (CV X1); ~64 links on a landing page (ADM §4.1) | Task-time benchmarks against each pilot's ADMP baseline (CV §6.2) |
| **3. Safe to give Tier-0 access** | No Domain Admin; no inbound exposure by default; signed automatic updates; typed primitives that remove injection bug classes | Category KEV history and the buyer checklist (CV §4.4); defaults such as admin/admin (ADM W3) | External pentest, SBOM, published threat model, disclosure policy (CV §6.2) |
| **4. Switch without losing anything** | Import configuration, bridge audit history, carry over enrollment, run in parallel | Switching barriers (CV §5.2–5.3) | Import fidelity report and a reference customer (CV §6.2) |

## 6. USPs

Complexity uses FEAS's scale: S ≤2 engineer-weeks; M 2–6; L 6–16; XL >16 or research risk.
"Phase" refers to FEAS §6.3. Complexity is an **Estimate**.

### USP-1: One platform, one data model, one licence

| | |
|---|---|
| **Claim** | Management, auditing, self-service and recovery for AD, Entra ID and M365 share one object model, one RBAC model, one audit trail and one licence |
| **Why the buyer cares** | Admins stop switching between consoles. Security reviews one product, not seven. Finance buys one SKU, with nothing "already paid for elsewhere" |
| **Evidence** | AD360 registers seven separately versioned products, with N+1 databases and per-component technician settings (SUITE §1.3).<br>"For reports, we have to go back to ADAudit, which is not ideal." (CV X5).<br>The inter-product SSO trust boundary produced CVE-2026-11374 (SUITE §1.3) |
| **What must be true / proof** | The core is built around the shared model from day one (FEAS §4.6, §6.1).<br>Entra/M365 coverage arrives early enough to make "one console" true in the pilot. FEAS currently schedules it for Phase 3: see §12 R3 and §13 Q1.<br>Demo: one object timeline across manage, audit and restore |
| **Cost to build** | An architecture property, not a feature. It costs discipline in the core (Phases 0–1) rather than a line item. Entra/M365 breadth is **L** (Phase 3 in FEAS) |
| **ME response** | ME is consolidating in Log360 first ("Unified Log360", June 2026). Identity360's AD-parity roadmap is undated (SUITE §7). A unified AD360 rebuild would mean reworking seven codebases (inference). **Most likely response:** a "move to Identity360" pitch and renewal discounts (inference) |

### USP-2: Every change is previewed, approved where policy says so, and undoable

| | |
|---|---|
| **Claim** | Before any write, activeDIQ shows a diff across AD, Entra and M365. Every change made through activeDIQ can be undone in one click. Changes made outside activeDIQ are detected, attributed and revertible (phased) |
| **Why the buyer cares** | It removes the fear of bulk changes on Tier 0. Admins describe ADMP as able to "do significant damage if in the wrong hands" (CV §3.2 #5), and updates or bugs have affected AD (CV X10). It also closes the audit loop of who changed what, approval and evidence |
| **Evidence** | At ME, rollback is a paid add-on or "Advanced Recovery" in several products (ADM-153; ADA-090/091; SUITE §4.7).<br>No single offboarding preview is documented (ADM §4.3).<br>ADMP's event triggers fire only on ADMP's own actions (ADM W10).<br>Semperis and Cayosoft sell rollback as a premium (LAND §7.3) |
| **What must be true / proof** | The job engine has dry-run → diff → approve → execute → verify phases (FEAS §6.1 #4).<br>Snapshots and attribute-level restore (Phase 1).<br>Attribution for native changes (Phase 2).<br>We are honest about what cannot be reverted, such as passwords and some attributes (ADA-022 notes) |
| **Cost to build** | **L** for preview + undo of own changes (Phase 1). **L–XL** for detect → attribute → revert of native changes (Phase 2) |
| **ME response** | ME already has point-in-time recovery: ADMP 8030 and ADAP 8710 (SUITE §7). It could bundle it into base editions. Our defence is **preview-before-execute and undo in the same flow, in every tier**, not rollback alone |

### USP-3: Measurably faster daily work

| | |
|---|---|
| **Claim** | The top-20 admin and help-desk tasks take fewer interactions and less time than in ADMP/ADSSP, measured at each customer. Example target: reset + unlock in ≤3 interactions (ADM §7c) |
| **Why the buyer cares** | This is the CEO's "far easier to use" condition. It means help-desk throughput and less training (CV X4) |
| **Evidence** | UI and navigation are the #1 complaint, ≈28 of ~152 (CV X1).<br>ADMP Create User page: 10.4 MB, ~20 s (demo, indicative) (ADM §4.2).<br>ADAP: 438 report entries under AD › Auditing (ADA §4.1).<br>ADSSP settings are split across two trees (ADSS §5.3).<br>Adaxes still lists a web admin console on its roadmap (LAND §7.1 #2) |
| **What must be true / proof** | Task-time benchmarks on 10 tasks from customer pilots (CV §6.2).<br>The five cross-persona POC scripts (LAND §6).<br>ME's numbers are re-measured on a local install before any external use (ADM §4.2 `[TODO]`) |
| **Cost to build** | **M** per surface, but continuous. It depends on the design system (DS) and a public API the UI consumes (FEAS §6.1 #7) |
| **ME response** | ADAP 9000 (2026-09-30) shipped a UI redesign and Activity Explorer. We have not seen it firsthand (ADA §4.1). **The window is narrowing.** UX must be benchmarked, not asserted |

### USP-4: Tier-0 security you can verify

| | |
|---|---|
| **Claim** | activeDIQ never needs Domain Admin. It has no inbound internet exposure by default, uses outbound-only agents, ships signed automatic updates and same-day advisories, and removes injection bug classes by construction |
| **Why the buyer cares** | Tools with AD write access are Tier 0 by Microsoft's model (LAND §4.9). CISA's remediation for a compromised SSPR tool included domain-wide password resets (CV §4.4). Security news triggers evaluations (CV §3.2 #3) |
| **Evidence** | 3 KEV entries in the category; 2026 critical fixes (CV §4).<br>Fix-to-NVD median of 60 days (CV §4.3).<br>Defaults: HTTP, admin/admin, admin may skip 2FA (ADM W3; ADSS W17).<br>Domain Admin recommended by default or for setup (ADA §4.2; ADSS W6) |
| **What must be true / proof** | Least-privilege design: DirSync without replication rights, and an optional separate Tier-0 connector (FEAS §0, §2.3).<br>Safe-primitive library and lint rules before the first feature (FEAS §6.1 #2).<br>External pentest as the Phase-1 exit gate (FEAS §6.3).<br>SBOM, disclosure policy, threat model (CV §6.2).<br>Rules for how we talk about this: state our facts, never characterize ME (CV §6.3) |
| **Cost to build** | Engineering cost sits in the foundation (Phase 0–1). External cost: pentest and SOC 2 / ISO 27001. Amounts are `[TODO]` |
| **ME response** | ME can and does fix fast in places (a 2-day turnaround, a bug bounty; CV §4.3). It added a Security Hardening page (ADA §5) and dropped TLS 1.0/1.1 in ADSSP 7001 (ADSS §1.1). It **can** change defaults quickly. Changing the architecture behind internet-facing portals and Struts 1 web tiers is slower (ADSS W2, inference) |

### USP-5: Switch without losing anything

| | |
|---|---|
| **Claim** | activeDIQ imports ADMP templates, roles, workflows and schedules. It bridges ADAP audit history, carries over ADSSP enrollment where possible, and runs in parallel until the customer is ready |
| **Why the buyer cares** | It removes the five switching barriers: price, compliance reports, sunk configuration, audit history and re-enrollment (CV §0 #7) |
| **Evidence** | CV §5.2–5.3; ADA §7a (history bridge options); ADSS §8a (about half the enrollment surface needs zero user effort); SUITE §8.2.<br>Cayosoft runs a Replace-ManageEngine program (LAND §2.4), so this must be **better**, not merely present |
| **What must be true / proof** | Lab installs of current ME builds to confirm export formats. TOTP seed and FIDO export are `[UNVERIFIED]` (ADSS §8a); DB access is `[UNVERIFIED]` with legal review `[TODO]` (ADA §7a).<br>Proof: an import fidelity report per pilot (CV §6.2) |
| **Cost to build** | **L** in total (ENH-02, ENH-03, ENH-06). It runs in parallel with Phase 1–2 |
| **ME response** | Renewal discounts and co-term pressure (inference). ME could also make exports harder (speculative). Our defence: importers that work from the customer's own exports and AD artefacts first, and DB access only as a fallback |

### USP-6: Updates that just happen

| | |
|---|---|
| **Claim** | Every component, including DC and endpoint agents, updates automatically. Updates are signed, staged and rollback-capable, on one release train. Air-gapped sites get signed offline bundles |
| **Why the buyer cares** | It saves upgrade labour and shrinks the window in which known-vulnerable builds keep running (CV §4.4) |
| **Evidence** | ≈16 upgrade complaints, some about failed upgrades (CV X3).<br>Sequential service packs (ADA W5; ADSS §5.3).<br>"I wish all the different modules updated together." (CV X3).<br>CV §6.1 ranks this the #1 wedge for evidence × ease of proof |
| **What must be true / proof** | Deployment profiles share one update path (FEAS §4.3).<br>Staged rings, so an update never breaks AD-facing behaviour (CV X10).<br>Measured median upgrade time and % of customers on the latest build (CV §6.2) |
| **Cost to build** | **M–L** |
| **ME response** | ADAP agents already self-upgrade (ADA §2.2), and ADMP has automatic hotfixes outside HA mode (ADM W1). ME could extend these. Removing sequential service packs across seven products is harder (inference) |

**Candidate USP-7, held back: guard-railed AI operator** (ENH-20). The landscape calls this the
open lane (LAND §4.5). It depends on USP-2 and on CEO answers to §13 Q5. Until then it is an
enhancement, not a headline USP. ME has announced Zia Agents suite-wide, but no AD MCP server is
listed (SUITE §7).

## 7. Non-negotiable product principles

### 7.1 Inherited from the UEM thesis, and where activeDIQ differs

| UEM principle (UEM §1, §4–5) | activeDIQ stance |
|---|---|
| **Deployment-shape agnostic.** One core; self-hosted, air-gapped, private cloud and SaaS as profiles | **Same.** One codebase with profiles (FEAS §4.3); a single-tenant install is one tenant row (FEAS §4.5).<br>**Differs in emphasis:** for a tool with AD write access, the write path is Tier 0. Regulated buyers will favour a self-hosted control plane (LAND §4.9). The ME research also argues for a SaaS control plane (ADSS §8c L1; ADA §7c #4). Which profile ships first is a CEO decision (§13 Q2) |
| **Extensible core.** Modules register against stable extension points; no forks | **Same.** Extension points are defined before features: directory provider, action/workflow step, event source, detection rule, authentication method, notifier (FEAS §4.6). The PatchIQ lesson applies: the interface must be the **only** on-ramp from day one (PM §11 #2) |
| **API as the product boundary.** The UI is one client | **Same.** Public API + OpenAPI before features (FEAS §6.1 #7). It also enables the unmetered API and MCP enhancement (ENH-11) |
| **UI-swappable** for white-label partners | **Differs.** activeDIQ's own UI *is* the differentiator (USP-3), so white-label is not a v1 property. The API boundary keeps it possible later at no extra cost |
| **Monetise the road.** Each checkpoint is a standalone, buyable product | **Same idea.** Each phase must displace at least one ME product completely, so a customer can switch that product off |
| **Parity is the destination, not the entry ticket** (UEM §7) | **Differs.** The CEO's brief makes parity on the features a customer *relies on* the entry ticket. Parity with the full ME catalogue is not. We scope by measured usage per pilot account (A2) |

### 7.2 activeDIQ-specific principles

1. **Tier-0 safe by construction.**
   - No Domain Admin, ever.
   - Outbound-only agents with a closed set of typed commands.
   - Security-relevant strings (LDAP filters and DNs, SQL, PowerShell, security descriptors) are
     built only with safe primitives (CLAUDE.md rule 5; FEAS §2.7).
   - This is the direct lesson of PatchIQ's recurring `fmt.Sprintf` injection bugs (PM §11 #1).
2. **Preview, approve, audit, undo.** Every write goes through the job engine's dry-run/diff/approval
   phases and leaves a hash-chained audit record (FEAS §4.4 flow 2).
3. **Never fail open.** Licence limits, outages and misconfiguration must never silently skip MFA.
   ADSSP skips endpoint MFA for users over the licence count (ADSS §1.4).
4. **No edition gating of security or audit depth.**
   - Before/after values, admin MFA and phishing-resistant factors are in every tier.
   - At ME, all three are Pro-only or gated (ADA §1.2; ADSS §1.4 #7).
5. **Measured UX.** Each top task has an interaction and time budget, checked in demos and pilots.
   "Easy" is never claimed without a number.
6. **Migration is product.** Importers, the history bridge and enrollment carry-over are built and
   tested like features, not done as services.
7. **Hybrid-first.**
   - Every object knows its source of authority (AD or Entra).
   - Every feature is designed for AD + Entra, even when it ships AD-first (LAND §4.1).
8. **No fake data, no dead buttons** (CLAUDE.md rule 6). PatchIQ shipped a dashboard of fabricated
   SLA data (PM §11 #1).
9. **No customer topology in core.** Customer-specific names and topologies stay in configuration
   and in `knowledge/business/partnerships/`. This is the PatchIQ lesson (PM §11 #4) and CLAUDE.md
   rule 8.
10. **One agent per endpoint.** Endpoint and DC agents are modules of the shared skenzeriq platform
    agent (FEAS §6.1 #6).

## 8. Anti-goals

| We will not | Why | Instead |
|---|---|---|
| Compete on sticker price | ME's price is its #1 praise and the floor is low (CV §6.1; LAND §7.2) | Total cost, one licence, migration included |
| Become a general workforce IdP / SSO platform | Okta and Entra own it (LAND §7.2) | SAML/OIDC SSO only to the depth ADSSP switchers actually use (ADSS §8a, P1). Integrate other IdPs |
| Build a SIEM/XDR | MDI, CrowdStrike and Palo Alto own the SOC (LAND §7.2) | High-fidelity AD-specific detections plus auto-revert, streamed to the customer's SIEM |
| Build full IGA (role mining, cross-app SoD) | SailPoint, Saviynt and Entra ID Governance own it (LAND §7.2) | IGA-lite: AD/Entra/M365 recertification and joiner/mover/leaver (JML), with SCIM/API hand-offs |
| Own backup storage | Commvault and Cohesity own immutability and clean rooms (LAND §7.2) | AD-aware restore orchestration and object-level UX |
| Ship employee monitoring (session video, work-hours tracking, SSL interception) | Privacy-sensitive and not identity (ADA §7b, W16) | Leave it out |
| Build every long-tail connector up front (exotic NAS, legacy password-sync targets) | Low switching impact (ADA §7b; ADSS §8b) | Add when a named lead needs one |
| Let AI change AD without preview and approval | Tier-0 risk; customers need to be able to regain control (LAND §4.5) | AI proposes; humans approve; everything is undoable (ENH-20) |
| Copy ME's report count | Hundreds of reports is a strength we must *match* for auditors (CV §6.1), not imitate as navigation | Parity for the reports auditors know, plus a flexible builder and investigation views |

## 9. Pricing and packaging hypotheses: options for the CEO

**CEO-owned. Nothing in this section is decided.**

### 9.1 Facts any model must respect

- **ME list price**, ADMP + ADAP + ADSSP (**Estimate**, SUITE §6.3):
  - **Trio:** $5.0k–$8.8k/yr at 1k users; $12.8k–$20.1k at 5k.
  - **Trio Pro with common add-ons:** $12,160 at 1k; $28,405 at 5k.
  - **ME full-stack equivalent:** $15,750 at 1k; $41,395 at 5k.
- **Perpetual customers** pay about 0.5× the subscription price per year in AMS from year 2. This
  base is the hardest to displace on price (SUITE §6.4).
- **ME's own cloud IAM**, Identity360 Pro: $7,250/yr at 1k users and $25,000 at 5k, after an
  Aug 2026 repricing of 2.6–4.5× (SUITE §6.3, §1.5).
- **Field anchors:**
  - Adaxes: $1,600 perpetual per 100 users;
  - tenfold: $0.90/identity/month;
  - Cayosoft: "no fees per administrator, CPU, node or server" (LAND §7.2, §2.4).
- **Hidden ME costs** to put in any TCO comparison: onboarding $3,495–$14,995; Windows/SQL hosts;
  HA add-ons; patching 3–7 products (SUITE §6.7).

### 9.2 Options

| Option | Shape | For | Against |
|---|---|---|---|
| **P-A. One platform, tiered, per enabled human identity** (SUITE §8.1) | Core (≈ ADMP + ADSSP), Complete (+ ADAP, RMP, M365MP equivalents), Enterprise (+ governance, endpoint MFA, long retention). No infrastructure, technician or tenant meters. Analyst corridor: Complete at ~$12/user/yr at 1k, ~$5.5–6 at 5k, ~$2–3 at 20k (**Estimate**) | Easy to compare line by line with ME. Removes ME's surprise meters (SUITE §6.6). Encourages named technician accounts (CV §3.2 #10) | Tier boundaries reintroduce some gating. Needs volume tiers for 20k+ |
| **P-B. Module SKUs mirroring ME** (Manage / Audit / Self-service) per identity, with a bundle discount | Customers buy only the modules that replace what they own | Lowest-friction swap for a customer replacing one ME product first | Recreates SKU sprawl, which is a pain we criticize (SUITE §4.7). Weakens USP-1 |
| **P-C. One flat per-identity price with volume bands** | Everything included | Simplest to quote. Strongest "one product" story | Expensive for a customer replacing only one ME product. Hard to land a first module |
| **P-D. Commercial-term add-ons to any of the above** | Perpetual/term licence for self-hosted; co-term credit for remaining ME term; migration included; 90-day free parallel run; 3-year price lock (SUITE §8.1 #4–5) | Answers ME's perpetual base and the repricing fear | Perpetual revenue recognition and support load `[TODO: finance view]` |

**What we need to learn before the CEO chooses:**
- each warm account's current ME spend and renewal date;
- whether they are on perpetual or subscription licences;
- which ME products they would retire first;
- whether procurement wants line-by-line comparability.

## 10. Go-to-market via warm relationships

Motion: **pilot → reference → expansion**. Account names live only in
`knowledge/business/partnerships/` (CLAUDE.md rule 8). Profiles there are `[TODO]`.

### 10.1 Stage 0: discovery (per account)

Collect:
- ME products, builds and editions; add-ons and counts; perpetual vs subscription; renewal or AMS dates;
- which features are actually used (A2);
- the ADAP discovery checklist: database, archive size, alert profiles, SIEM targets, NAS vendors,
  Entra licence tier, agents vs agentless, HA (ADA §7a);
- ADSSP enabled authenticators and enrollment counts (ADSS §8a);
- the security team's position on DC agents and SaaS (A3, A4).

**Door-opener:** a hybrid health check before the **7 Apr 2027** Connect Sync deadline, and a
posture scan (LAND §7.1 #6, #9; ENH-17, ENH-19).

### 10.2 Stage 1: pilot

- **Scope:** one ME product replaced end to end, plus parallel run. The recommended order is in §13 Q1.
- **Script:** the five cross-persona POC tests (LAND §6):
  1. 20-user bulk onboarding with approval in under 5 minutes.
  2. A Tier-0 change detected and reverted.
  3. A verified-caller reset by a tier-1 agent with no AD rights.
  4. An auditor query answered in under 1 minute.
  5. Object restore plus a recovery plan.

  Add the 10-task timing benchmark against the customer's ADMP (CV §6.2).
- **Entry gate:** security evidence ready **before** the pilot. Enterprise buyers will send a
  security questionnaire that references the category's KEV history (CV §5.4). This means at least
  an external pentest, threat model and SBOM (FEAS §6.3 Phase-1 exit).
- **Exit criteria** (proposal):
  - the ME product is switched off at the pilot account;
  - task-time targets are met;
  - the auditor accepts the reports;
  - no Sev-1 incidents during the parallel run.

### 10.3 Stage 2: reference

Turn each successful pilot into:
- a reference call;
- an import-fidelity report;
- a measured before/after (task time, upgrade effort, ticket deflection, using Microsoft's
  $60-vs-$2 recovery-cost estimator only as a default anchor, LAND §6).

Any external case study or datasheet is a CEO decision (CV §6.3).

### 10.4 Stage 3: expansion

- **Within the account:** retire the next ME product; a typical order is ADMP → ADSSP → ADAP →
  RMP/M365MP. Time each step to that product's renewal.
- **Across accounts:** use references with the next warm accounts.
- **Later, CEO decision:** MSP channel and partner resale. ME runs 300+ channel partners
  (SUITE §5.4); we will not match that early.

## 11. Relation to the skenzeriq portfolio

| Asset | Relation |
|---|---|
| **UEM** (sister product) | Shared conventions and thesis (UEM §1, §4–5).<br>Shared **platform agent**: one agent process per endpoint, with module contracts agreed with the UEM/PatchIQ owners (FEAS §6.1 #6, App. A #4).<br>House stack: Go / React / PostgreSQL (FEAS §0).<br>Possible later cross-sell, since both products sell to the same IT teams `[ASSUMPTION]`. Not in scope now |
| **Design system** | **Separate brand** (D-0005, 2026-10-02): activeDIQ has its own palette and identity, independent of skenzeriq. The direction is A · Ledger (D-0012, chosen from the T-0042 previews). The skenzeriq design system (DS) is a craft reference only. USP-3 depends on executing it well |
| **PatchIQ lessons** | Architecture before implementation; safe primitives; extension points as the only on-ramp; no single-customer topology in core; no fabricated UI data (PM §11; §7.2 above) |

## 12. Key risks

| # | Risk | Likelihood / impact (Estimate) | Mitigation |
|---|---|---|---|
| R1 | **Parity scope is large.** ADSSP alone has 138 features (ADSS §0). FEAS phases run to ~14–18+ months before ≥90% of used-feature parity (FEAS §6.3, **Estimate**) | High / High | Scope by measured usage per pilot (A2). Displace one ME product at a time (§13 Q1) |
| R2 | **Windows-native long poles** gate P0 ADSSP features. The password filter needs Microsoft LSA plug-in signing, with unknown lead time. The credential provider is where ME shipped SYSTEM-level bugs (FEAS §6.2) | Medium / High | Start LSA-signing enrolment in week 1 (FEAS §6.2). Lead with ADMP replacement while the long poles mature |
| R3 | **Sequencing conflict.** FEAS puts Entra/M365 in Phase 3, but ADMP switchers need M365 provisioning on day one (ADM §7a), and USP-1 claims one hybrid console | High / High | CEO decision §13 Q1: pull Graph-based Entra/M365 basics into Phase 1 |
| R4 | **Our own security incident.** One CVE in a Tier-0 product with few customers would be fatal to the thesis | Medium / Critical | Safe primitives, external pentest gate, disclosure process (USP-4). Expert human review of AI-written LSASS/LogonUI code (FEAS App. A #12) |
| R5 | **ME price response.** Renewal discounts; perpetual customers already pay about 0.5× subscription per year (SUITE §6.4) | High / Medium | Compete on TCO and migration terms (§9 P-D). Time offers to renewals |
| R6 | **Other "replace ME" vendors** (Cayosoft, Netwrix) reach the same accounts first (LAND §2.4) | Medium / Medium | Warm relationships; UX and SSPR depth (Cayosoft's SSPR is undocumented, LAND §2.4) |
| R7 | **The UX window narrows.** ADAP 9000 shipped a redesign on 2026-09-30 (ADA §5) | Medium / Medium | Benchmark rather than assert. Differentiate on unification and the closed loop, which a redesign does not deliver |
| R8 | **Migration feasibility.** Export formats, TOTP seeds and DB access are `[UNVERIFIED]`, and the EULA review is `[TODO]` | Medium / High | Lab installs now. Importers based on customer-side exports and AD artefacts first |
| R9 | **Microsoft shrinks on-prem scope.** Source-of-authority shift, Cloud Sync (LAND §4.1) | Medium / Medium | Hybrid-first and SOA-aware design; position as the bridge to Entra (ENH-17) |
| R10 | **Support expectations** of a young vendor vs ME's 24×7 for high-impact issues (SUITE §5.5) | Medium / Medium | Named support during pilots; published severity SLAs. ME publishes only acknowledgement targets |
| R11 | **Account concentration.** A pipeline of a few warm accounts | High / Medium | Each pilot must yield a reference. Free door-opener tools (ENH-19) widen the pipeline |

## 13. Open strategic questions (CEO decisions)

Each recommendation is the strategy team's and is **not decided** unless the question carries a **Decided** line. On 2026-10-02 the CEO decided Q1, Q2, Q4 and Q7, and the platform question in §11.

### Q1: v1 scope. Which ManageEngine product do we displace first?

**Decided 2026-10-02 (D-0001): (a)**, as recommended, with Entra/M365 provisioning in v1.

**Options**
- **(a) ADMP first.** Management, delegation, workflow, reports, plus web SSPR. Matches FEAS
  Phase 1.
- **(b) ADSSP first.** Self-service and MFA.
- **(c) A thin slice of all three.**

**Recommendation: (a)**, with Graph-based Entra/M365 provisioning pulled into Phase 1 (R3).
- ADMP is the most-reviewed and most-inherited product (CV §1.1, §3.2 #5). It avoids the
  Windows-native long poles (R2).
- Preview/undo (USP-2) and UX (USP-3) are most visible there.
- (b) depends on the password filter and credential provider. (c) spreads the team thin and
  switches nothing off.

### Q2: Deployment. Which profile ships first?

**Decided 2026-10-02 (D-0002): (a)**, self-hosted first and SaaS-ready (ADR-0002).

**Options**
- **(a) Self-hosted** (Windows MSI + Linux/Docker) first.
- **(b) Multi-tenant SaaS** with outbound-only connectors first.
- **(c) Both at once.**

**Recommendation: (a)**, with the codebase SaaS-ready from migration 1 (FEAS §4.5).
- Tools with AD write access are Tier 0 (LAND §4.9).
- SaaS acceptance is unconfirmed (FEAS App. A #5), and ME's customers bought on-prem.
- Confirm in discovery (A4). If the warm accounts prefer SaaS, switch to (b).

### Q3: Pricing model (§9)

**Options:** P-A, P-B or P-C, each with or without P-D terms.

**Recommendation for the CEO to test, not decided:** P-A plus P-D terms in discovery.
- P-A keeps USP-1 intact and maps line by line to ME.
- P-D answers the perpetual base and the repricing fear.

### Q4: Signature enhancement set

**Decided 2026-10-02 (D-0004): the set of 5**, as recommended.

**Options:** 3, 5 or 8 enhancements (enhancement catalog §3).

**Recommendation: the 5-set.** It covers every persona and stays inside FEAS Phases 1–2.

### Q5: AI posture

**Options**
- **(a) No AI in v1.**
- **(b) An assistant with a bring-your-own model key** (ME's Zia pattern, ADM W11).
- **(c) A guard-railed operator** (plan → diff → approve → execute → undo), provider-agnostic with
  a self-hosted model option, plus a read-only MCP server first.

**Recommendation: (c), sequenced after USP-2 exists.**
- Ship the read-only MCP and API early (ENH-11). Agentic writes come only on top of preview and undo.
- An assistant alone is parity (LAND §4.5).

### Q6: Pilot accounts and order

**Options:** the CEO names 2–3 warm accounts now, or after discovery calls.

**Recommendation:** name 2 accounts now. Prefer accounts that:
- run ADMP + at least one other ME product;
- are hybrid;
- have a renewal within 6–9 months.

Store the profiles in `knowledge/business/partnerships/`.

### Q7: Brand and UI direction

**Decided 2026-10-02 (D-0005): (c) a separate brand.** The CEO did not take the recommended (b). The palette, identity and UI style are chosen from three clickable previews (T-0042).

**Direction chosen 2026-10-02 (D-0012): A · Ledger**, the recommended option. It is light and dense, with cobalt `#0A5CB0`, IBM Plex Sans/Mono, a labelled left rail and 32 px rows. T-0043 builds the design system from it.

**Options**
- **(a) The skenzeriq design system as is.**
- **(b) An activeDIQ sub-brand on the same tokens.**
- **(c) A separate brand.**

**Recommendation: (b).** It keeps the token core (DS) and lets the product carry its own name and
icon. This is a taste call for the CEO.

### Q8: Security certification investment before the first pilot

**Options**
- **(a) External pentest only.**
- **(b) Pentest + SOC 2 Type II readiness.**
- **(c) Pentest + ISO 27001.**

**Recommendation: (b).**
- The pentest is already a Phase-1 exit criterion (FEAS §6.3).
- Starting SOC 2 readiness early shortens later security reviews (CV §6.2).
- Costs are `[TODO]`.

### Q9: First regulatory focus

**Options:** India BFSI (RBI, SEBI, CERT-In); EU (DORA, NIS2); US (SOX, PCI).

**Recommendation:** follow the warm accounts' regulators. Build evidence packs for that regulator
first (ENH-15). If the accounts are in Indian BFSI, self-hosted in-region deployment becomes a
feature (LAND §7.1 #8).
