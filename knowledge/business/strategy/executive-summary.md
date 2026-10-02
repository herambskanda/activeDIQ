---
title: "Executive summary: what we are up against"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: heramb
---

# What we are up against: ManageEngine's AD suite

For the CEO. All facts are as of 2026-10-02. Prices are US list prices before discounts. Numbers
marked **Estimate** are analyst arithmetic, not vendor figures. Internal only: nothing here leaves
the building without CEO approval.

**Source key** (cite format: `KEY §section`):
[CV](../market-research/manageengine-ad-customer-voice-and-security.md) customer voice & security ·
[ADM](../market-research/manageengine-admanager-plus.md) ADManager Plus ·
[ADA](../market-research/manageengine-adaudit-plus.md) ADAudit Plus ·
[ADSS](../market-research/manageengine-adselfservice-plus.md) ADSelfService Plus ·
[SUITE](../market-research/manageengine-ad360-suite-and-commercials.md) AD360 & commercials ·
[LAND](../competitive-analysis/ad-management-market-landscape.md) market landscape ·
[FEAS](../../development/architecture/build-feasibility/ad-technical-feasibility.md) technical feasibility

## Bottom line

- ManageEngine (ME) sells **cheap, broad, auditor-familiar** AD tools. Their price is the most-praised
  thing about them, so we cannot win on price.
- What they sell is **seven separately installed Windows/Java products**, joined by a free launcher
  (AD360). Customers' most frequent complaints are the UI, upgrades, report customization and the
  seams between products. All four come from how the products are built, so ME cannot fix them quickly.
- What keeps customers from switching is **configuration, audit history and end-user MFA
  enrollment**, not data. If migration is a product feature, the warm accounts can move.

## 1. The suite at a glance

| Product | Job | Licence meter | Entry list price (annual) | Source |
|---|---|---|---|---|
| ADManager Plus (ADMP) | AD/M365/Exchange/Google management, 200+ reports (vendor claim), workflow, automation | Domains (child domains included) + named technicians | Std $595 (1 domain + 2 techs); Pro $795 admin-only, $10,595 with 20 techs | ADM §1.3 |
| ADAudit Plus (ADAP) | AD/Entra/file/server auditing, UBA, ITDR/posture | DCs, plus 6+ add-on meters | $595 Std / $945 Pro for 2 DCs | ADA §1.3–1.4 |
| ADSelfService Plus (ADSSP) | SSPR, MFA, SSO, password sync | Users, consumed on a user's first action | $595 Std / $1,195 Pro per 500 users | ADSS §1.2–1.3 |
| RecoveryManager Plus, M365 Manager Plus, Exchange Reporter Plus, SharePoint Manager Plus | Backup; M365; Exchange; SharePoint | Per workload / user / mailbox / farm | From $345–$945 | SUITE §1.2 |
| AD360 | Launcher over the seven products: SSO, config sync, reports from 3 of them | Free shell; pay per component; **no bundle discount at list** | — | SUITE §1.3–1.4 |

- **Architecture.** Each product is its own Java/Tomcat app with PostgreSQL on Windows. Each has
  its own port, database and update cadence (ADM §2.1; ADA §2.1; SUITE §1.3).
  - Full-suite sizing guidance adds up to about 98 GB RAM on at least 4 servers (**Estimate**, SUITE §1.3).
  - The AD360 shell shipped one build in 2026 (SUITE §1.1).
  - ADMP, ADAP and ADSSP have no vendor-hosted SaaS. ME's cloud IAM is a separate product,
    Identity360 (ADM §1.6; SUITE §1.5).
- **Pricing reality.**
  - ADMP + ADAP + ADSSP at list costs **$5.0k–$8.8k/yr at 1,000 users** ($0.42–$0.73 per user per
    month), and $12.8k–$20.1k at 5,000 users (**Estimate**, SUITE §6.3).
  - A realistic Pro stack (add-ons, backup, M365) is $15,750/yr at 1k users and $41,395 at 5k (**Estimate**, SUITE §6.3).
  - Perpetual licences cost 2.5× the annual subscription, plus 20% per year in maintenance (AMS).
    Long-tenured perpetual customers therefore pay about half the subscription price each year (SUITE §6.4).
  - Hidden costs: Windows/SQL hosts, onboarding at $3,495–$14,995, and patching 3–7 products (SUITE §6.7).
- **The company.** ME is a bootstrapped division of Zoho with about **US$575M** segment revenue in
  FY25 (**Estimate**, SUITE §5.1) and 300+ channel partners (SUITE §5.2).

## 2. Where they are strong

- **Price and value.** Price is mentioned in 21 of 59 praise sections. Community posters say
  alternatives are "two to three times at least more expensive" (CV §2.1, §3.2).
- **Canned compliance reports** (SOX, HIPAA, GDPR, PCI): 25 of 59 praise sections, and the reason
  many customers stay (CV §2.1, §5.2). ADAP alone lists about 1,000 report entries (ADA §6 W12).
- **Breadth.** ME is one of very few vendors with a product in all five AD segments: admin, audit,
  SSPR/MFA, recovery and ITDR (LAND §1).
  - ADSSP has 138 inventoried features, including FIDO2 for machine logon (ADSS §0).
  - ADAP 9000 (2026-09-30) added attack-path analysis, non-human-identity auditing, CSPM/SSPM and a
    UI redesign (ADA §5).
- **Easy first install, and delegation without giving technicians Domain Admin** (CV §2.1).
- **Analyst presence.** KuppingerCole rates ME a "Market Leader" in IGA and ITDR. That is the
  market-presence axis, not product leadership (SUITE §5.3).
- **Review scores** are uniformly high: 4.0–4.8/5. Many 2026 reviews were solicited by the vendor (CV §1.1).

## 3. Where they are weak

| Area | Evidence |
|---|---|
| **UX** | The #1 complaint: ≈28 of ~152 coded reviews; reviewers' words include "clunky" and "very Windows 2000" (CV §2.2 X1).<br>ADMP demo: about 64 action links on one landing page, and a Create User page of 10.4 MB that took ~20 s to load (indicative) (ADM §4).<br>ADSSP iOS app: 2.1/5 (ADSS §5.1) |
| **Integration seams** | Separate logins and separate updates per module (CV X5).<br>AD rollback is sold in up to 5 SKUs (SUITE §4.7).<br>ADSSP approvals need ADMP (ADSS W9).<br>The ADMP M365 tab is a separate iframe app (ADM §4.1) |
| **Upgrades** | ≈16 complaints, some about failed upgrades (CV X3). Service packs must be applied in sequence (ADA W5; ADSS §5.3) |
| **Security record** | **3 CISA KEV entries**: CVE-2021-40539, CVE-2022-47966, CVE-2022-28810 ([KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)).<br>2026 critical fixes: an unauthenticated ADAP RCE (CNA 10.0), an ADSSP logon-screen RCE (CNA 9.8) and suite SSO ticket prediction (CNA 9.0).<br>Median 60 days from fix to NVD publication.<br>admin/admin first login (CV §4; ADM W3; ADSS W17).<br>Counterpoint: an active bug bounty and a 2-day fix on CVE-2022-28219 (CV §4.3) |
| **Licensing** | Named technicians push some teams to share admin accounts (CV §3.2 #10).<br>ADMP API capped at 50 calls per technician per day (ADM §1.5).<br>Before/after values are Pro-only (ADA §1.2).<br>Over the licence limit, endpoint MFA is **skipped** (ADSS §1.4) |
| **Support & docs** | ≈9 review complaints about support; it is the loudest community theme (CV X7, §3.2).<br>Only acknowledgement times are published (8 h on Classic support), with no resolution SLAs (SUITE §5.5).<br>Documentation gaps ≈12 (CV X4) |
| **Openness** | ADAP has no documented public API or webhooks (ADA W13).<br>ADSSP's REST API is "in pipeline" (ADSS W8) |

## 4. What customers say

These quotes are for internal use only. Sources are in CV §2–3.

- "The canned reports are great, but the custom reporting is somewhat limited." (Capterra, ADAP, 2026)
- "I wish all the different modules updated together." (Capterra, AD360, 2025)
- "They aren't the best products, but it's damn hard to find on premises alternatives that aren't two to three times at least more expensive." (r/sysadmin, 2022)
- "I use ADAudit by ManageEngine but am moving to netwrix auditor." (Spiceworks, 2026)

Why customers look elsewhere:
- security news reaching leadership;
- usability;
- upgrade pain;
- renewal cost;
- hybrid coverage that needs extra SKUs (CV §5.1).

Why they stay:
- price;
- compliance reports;
- sunk configuration;
- audit history;
- re-enrolling users in MFA (CV §5.2).

## 5. The wider market

- **Other vendors already run "replace ManageEngine" campaigns.**
  - Cayosoft has an explicit Replace-ManageEngine program and $22.5M of growth funding.
  - Netwrix markets against ME.
  - One Identity is separating from Quest, announced 2026-06-24 (LAND §0 #1, §2.4).
- **Microsoft is pulling object authority into Entra.** Group and user source-of-authority
  conversion are GA, and Connect Sync must be upgraded by **7 Apr 2027**. On-prem AD is being
  minimized, not retired, so the durable product is hybrid (LAND §4.1, §4.3).
- **AI assistants are table stakes.** ADMP's Zia shipped in Oct 2025 and needs the customer's own
  Azure OpenAI key. The open lane is **guard-railed** AI changes to AD: preview, approve, execute,
  roll back (LAND §4.5; ADM W11).
- **The attack pattern has shifted.** Help-desk vishing is now the #2 initial vector (11%, Mandiant
  2026), while initial access via stolen credentials is falling (LAND §4.2).
- **Regulation** creates RFP checkboxes: DORA and PCI access reviews, NIS2, RBI privileged MFA and
  CERT-In 180-day log retention (LAND §4.7).
- **Market size:** about $1–2B/yr for AD-centric tooling (**Estimate, low confidence**, LAND §5.5).
- **ME's own direction:** consolidation is going into "Unified Log360" and the Identity360 SaaS.
  Identity360 prices rose 2.6–4.5× in Aug 2026, and its AD-parity roadmap is undated (SUITE §7).

## 6. What it means for activeDIQ

1. **Win on total cost and one licence, not on sticker price.**
   - Price at or below ME's fully loaded trio.
   - Include migration, HA and MFA in the price, where ME charges for them as add-ons.
   - The pricing call itself is the CEO's (SUITE §8.1; see `product-strategy.md` §9).
2. **Migration is the product.** Customers stay because of configuration, audit history and
   enrollment. Importers, an ADAP history bridge, progressive MFA enrollment and a parallel run
   must ship with the pilot (CV §5.3; ADA §7a; ADSS §8a).
3. **Prove "far easier" with a stopwatch.** Time 10 common tasks against ADMP at every pilot
   (CV §6.2). Adjectives will not survive a security-review-driven RFP.
4. **Unification is the structural wedge**: one data model, one console, one role model, one
   release. ME's consolidation effort is going into Log360 and Identity360; the AD360 shell is in
   maintenance (SUITE §1.1, §7).
5. **A Tier-0 tool must show its security evidence before it is asked.** We will face the
   checklist in CV §4.4:
   - SBOM;
   - same-day advisories;
   - signed automatic updates;
   - no default credentials;
   - no Domain Admin;
   - an external pentest.

   State our own facts. Never characterize ME's CVEs (CV §6.3).
6. **Be hybrid from day one.** FEAS §6.3 schedules Entra/M365 for Phase 3. That conflicts with
   what ADMP switchers need on day one (ADM §7a) and with our one-console claim. This is a CEO-level
   sequencing question.
7. **Differentiate on the closed loop, not on "AI".** The loop is: detect a change → see the diff →
   undo or approve → audit trail, in one product. Guard-railed AI sits on top of that loop. An AI
   assistant on its own is parity.
