---
title: "AD Management & Identity Security Market Landscape (2026)"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: heramb
sources_last_checked: 2026-10-02
---

# AD Management & Identity Security Market Landscape (2026)

> Scope: the non-ManageEngine market and where it is heading. ManageEngine (ME) itself is covered in sibling files under `knowledge/business/market-research/manageengine-*.md`.
> Conventions: inline links are sources (accessed 2026-10-02 unless dated). `[UNVERIFIED]` = could not confirm; `[TODO]` = not reached. "Opinion"/"analysis" = analyst judgement. Vendor-sponsored statistics are flagged. **Absence wording** ("not found", "none", ○) always means "not documented in the sources reviewed as of 2026-10-02", never "does not support". **Prices** are list prices before discounts unless stated. Comparative-claim rules: `.claude/skills/competitive-intel` §4. Anything RFP-bound needs CEO approval.

## Key findings (decision-relevant)
1. **We are not the only "replace ManageEngine" story.** Cayosoft runs an explicit *Replace ManageEngine* program and covers admin, audit, rollback and instant forest recovery. Its SSPR is undocumented (§2.4). Netwrix also markets directly against ME, calling it "a collection of separate tools". Yet Netwrix needs ~6–8 products to match AD360's scope (analyst estimate), and Directory Manager advisory CVE-2025-48748 was rated CVSS 10.0 (14 May 2025) (§2.2). Quest/One Identity spreads the same scope across 10+ on-prem and SaaS products. **One Identity (Active Roles, Password Manager) announced its separation from Quest on 24 Jun 2026**, and Quest did two debt transactions in 2025, so their installed base faces vendor-transition questions (§2.1). Breadth alone will not win; **unified UX plus migration ease** will.
2. **AI is table stakes, not a differentiator.**
   - ME shipped a natural-language **"Zia" AI assistant in ADManager Plus** (Build 8030, 30 Oct 2025).
   - Microsoft **includes Security Copilot in M365 E5/E7** (rollout from 18 Nov 2025) with Entra agents.
   - The open lane is **guard-railed agentic changes to on-prem AD**: preview, approve, execute, one-click rollback (§4.5).
3. **Microsoft is moving AD object authority to the cloud.**
   - Group SOA conversion GA (Oct 2025) and user SOA GA (Jan 2026).
   - Microsoft is steering Connect Sync customers to Cloud Sync, with a forced Connect Sync upgrade by **7 Apr 2027**.
   - Entra Backup & Recovery is GA but **cloud-only**.
   - activeDIQ must be hybrid/SOA-aware. AD forest recovery remains third-party territory (§2.10, §4.1).
4. **Messaging should lead with Tier-0 blast radius, help-desk fraud and recovery, not "credentials are the #1 way in".**
   - 2026 data shows stolen-credential initial access *falling*: Mandiant 9%, Verizon 13%.
   - What is rising: help-desk vishing (#2 vector, 11%), post-compromise credential theft (52.2% of valid-account intrusions) and attacks on DCs, sync servers and backups (§4.2).
5. **ITDR and recovery are consolidating and commoditizing.**
   - Palo Alto–CyberArk (~$25B, completed Feb 2026); CrowdStrike–SGNL (~$750M, Jan 2026); Semperis–MightyID (Feb 2026).
   - Backup vendors are moving in: Commvault lists AD forest recovery at $0.75–1.25 per enabled user/month, and Cohesity resells Semperis.
   - KuppingerCole rates **ME an ITDR "Market Leader"** (Nov 2025). activeDIQ needs AD-specific ITDR depth plus auto-revert, and should integrate into the SOC rather than compete with it (§4.4, §4.8).
6. **Regulation creates concrete RFP checkboxes.**
   - Six-monthly access reviews (DORA RTS Art. 21; PCI 7.2.4).
   - MFA for privileged users (RBI, DORA, PCI).
   - 180-day in-country logs (CERT-In).
   - NIS2 enforcement (CJEU referrals Jul 2026).
   - Counter-signal: **CMMC Phase 2 was halted on 13 Jul 2026**, weakening the US defence-contractor driver (§4.7).
7. **Do not fight on list price.** The floor is low: Adaxes $1,600 perpetual per 100 users; tenfold $0.90/identity/month; Okta from $6/user/month; ME licenses by domain and technician. Win on TCO, UX, migration ease and Tier-0 security posture (§7.2).
8. **Market size (estimate, low confidence):** AD-centric tooling is ~$1–2B/yr globally, growing roughly at IAM's ~10% CAGR, with resilience and ITDR growing faster (§5.5). Third-party ITDR and MFA "market sizes" are mutually inconsistent and should not be quoted (§5.1).

## 1. Market definition & segments

**Definition used here.** Software that administers, monitors, protects and recovers **Microsoft Active Directory (AD DS)** and its hybrid extensions (Entra ID, Exchange/M365, file-server permissions), sold to IT operations, help desk, security and compliance teams. AD remains the authoritative directory for Kerberos/LDAP apps, GPO and Windows endpoints. The market is now shaped by Microsoft pulling object authority into the cloud: Group SOA conversion, described as "AD DS minimization" ([Learn](https://learn.microsoft.com/en-us/entra/identity/hybrid/concept-source-of-authority-overview)).

| # | Segment | Jobs to be done | ManageEngine product | Main non-ME alternatives (2026) | Boundary / adjacent markets |
|---|---|---|---|---|---|
| S1 | **AD administration & delegation ("IGA-lite")** | Joiner/mover/leaver provisioning, templates, bulk ops, scoped delegation, approval workflows, group lifecycle, stale-object cleanup, light access reviews | ADManager Plus | One Identity Active Roles; Softerra Adaxes; Cayosoft Administrator; Netwrix Directory Manager; tenfold; SolarWinds ARM; native ADUC/ADAC/PowerShell + Entra ID Governance with provisioning back to AD | Full IGA (SailPoint, Saviynt, One Identity Manager, Entra ID Governance) for cross-app entitlements, SoD and role mining |
| S2 | **AD auditing & change monitoring** | Who/what/when/where with before/after values, logon and lockout forensics, file-server auditing, compliance reports, alerting, UBA | ADAudit Plus | Netwrix Auditor; Quest Change Auditor; Lepide; Semperis DSP and Cayosoft Guardian (change tracking with rollback); native event logs + Sentinel | SIEM (Sentinel, Splunk, ME Log360). Data-security/DSPM for file permissions |
| S3 | **Self-service password reset / MFA** | SSPR and unlock, password-policy and breached-password enforcement, MFA for Windows logon/VPN/OWA, help-desk caller verification | ADSelfService Plus | Specops (uReset, Password Policy, Secure Service Desk); Netwrix Password Policy Enforcer; One Identity Password Manager; Adaxes self-service; Entra SSPR with writeback; Okta; JumpCloud | Workforce IdP/SSO (Okta, Entra, Ping), passwordless/passkeys |
| S4 | **AD backup & forest recovery** | Object/attribute/GPO restore, DC recovery, automated malware-free forest recovery, rehearsals | RecoveryManager Plus (see sibling file) | Semperis ADFR; Quest Recovery Manager for AD (Disaster Recovery / Forest editions); Cayosoft Guardian; Netwrix Recovery for AD; Commvault Cloud Backup & Recovery for AD ([page](https://www.commvault.com/platform/active-directory)); Cohesity "identity resilience" ([page](https://www.cohesity.com/solutions/active-directory/)). Confirmed: Cohesity sells "Cohesity Identity Resilience, powered by Semperis" (17 Sep 2025) ([PR](https://www.semperis.com/press-release/cohesity-semperis-offering-unifies-data-identity-resilience/)). | General backup/cyber-recovery platforms (Commvault, Rubrik, Cohesity, Veeam) |
| S5 | **ITDR / identity security posture (ISPM)** | AD/Entra exposure assessment, Tier-0 attack paths, real-time attack detection (DCSync, DCShadow, Golden Ticket, Kerberoasting), automated response | AD360 "UBA-driven identity threat protection"; Log360 | Microsoft Defender for Identity; Semperis DSP/Lightning; Quest Security Guardian; Netwrix ITDR stack; CrowdStrike, SentinelOne, Tenable, Silverfort, Okta ISPM (see §2.14); free: PingCastle, Purple Knight, BloodHound CE | XDR/SIEM platforms; PAM (CyberArk, now Palo Alto Networks) |

**Structural observations (analysis):**
- ME is one of the few vendors with a product in **all five segments** under one brand. The full-breadth alternatives are Quest/One Identity and Netwrix, each delivering that scope through many separately installed products, largely acquired (§2.1–2.2), and **Cayosoft**, which covers S1, S2, S4 and part of S5 but has undocumented SSPR (§2.4). Most other challengers are 1–2-segment specialists (Semperis S4/S5, Specops S3, Adaxes S1, Lepide S2, tenfold S1).
- The centre of gravity is moving from S1/S2 (operations, compliance) toward S4/S5 (resilience, security), and from on-prem-only toward hybrid AD + Entra.
- Microsoft bundles (E5: MDI and now Security Copilot; Entra ID Governance) put a price ceiling on S5 and on cloud-side S1. They leave on-prem AD workflow, rollback and recovery largely to third parties.

## 2. Competitor profiles

Format per vendor: positioning · flagship capabilities · deployment · pricing signals · target segment · vs ManageEngine (ME) · sources. "Opinion" marks analyst judgement rather than sourced fact.

### 2.1 Quest Software / One Identity
quest.com and oneidentity.com block automated fetches, so product facts below come from Internet Archive snapshots (dated) and the live Azure Marketplace catalog.

| Field | Detail |
|---|---|
| Quest ownership & finances | **Clearlake Capital** (closed 2 Feb 2022; ~$5.4B incl. debt per Wikipedia, secondary) ([Wikipedia](https://en.wikipedia.org/wiki/Quest_Software)). **CEO Tim Page** since 27 Jan 2025. **Debt restructurings:** $350M new term loans from existing lenders (30 May 2025) ([PR](https://www.prnewswire.com/news-releases/quest-software-announces-new-350-million-capital-infusion-to-accelerate-ai-innovation-and-growth-302469848.html)), then a second exchange creating a "3.5-out" loan (Aug 2025) ([PE Wire](https://privateequitywire.co.uk/clearlakes-quest-software-unveils-second-debt-restructuring/)). S&P downgraded Quest in Mar 2025, with debt >$3.5B (per trade press). **Acquired Anetac** (human, non-human and AI-agent identity observability), 17 Jun 2026 ([PR](https://www.globenewswire.com/news-release/2026/06/17/3313367/0/en/clearlake-backed-quest-software-acquires-anetac-to-advance-identity-security-for-the-agentic-ai-era.html)). Customer-count boilerplate fell from "130,000+" (May 2025) to "more than 28,000" (16 Sep 2026), unexplained `[UNVERIFIED reason]`. |
| **One Identity separation** | **24 Jun 2026:** One Identity announced it will become an **independent company with global HQ in Cork, Ireland**, focused on **IGA and PAM**. The transition "continues throughout 2026" and post-separation **ownership is undisclosed** ([ITPro](https://www.itpro.com/business/business-strategy/one-identity-spins-out-as-independent-company-relocates-global-hq-to-ireland), 26 Jun 2026). CEO **Praerit Garg** (Sep 2025; previously worked on AD at Microsoft and ran AWS directory services). As of 2026-10-02, One Identity products are still listed under Quest's Azure Marketplace publisher, so the separation is not complete. |
| Brand split (2026) | **One Identity:** Active Roles, Password Manager, Defender, Identity Manager (+On Demand), Safeguard, Starling Connect, OneLogin. **Quest:** Identity Defense (ex-Security Guardian), Identity Recovery (ex-On Demand Recovery), Recovery Manager for AD (+ Disaster Recovery Edition), Change Auditor, GPOADmin, Enterprise Reporter, Active Administrator, On Demand Audit, Security Guardian Audit, On Demand Migration, Identity Insights (Anetac), Guardian Managed Recovery, and resold BloodHound Enterprise. |

| Product | Key facts (2024–2026) | Deployment | Price signal |
|---|---|---|---|
| **Active Roles** (One Identity) | "Simple Identity Governance for Microsoft® Environments". One console across AD domains and Entra/M365 tenants; workflow and change approval; role-based delegation; attribute-based groups; change history; Synchronization Service connectors. **v8.5** (Azure listing for Windows Server 2025, 15 Jul 2026) ([Active Roles](https://www.oneidentity.com/products/active-roles/), snapshot 9 Jul 2026) | **On-prem** (Administration Service + Web Interface + SQL); BYOL VMs on Azure/AWS. **No Active Roles SaaS found** | No public price. User anecdotes: ">50 euros per identity"; "seven-figure" over two years at a 10,000+ employee org ([PeerSpot](https://www.peerspot.com/products/one-identity-active-roles-pricing), anecdotal) |
| **Change Auditor** (Quest) | Before/after auditing for AD, Entra, Exchange/EXO and file servers. Detects DCSync, DCShadow, NTDS theft and SIDHistory abuse. **Blocks** changes to critical groups and GPOs; one-click AD rollback; SIEM forwarding. SaaS companion On Demand Audit (up to 10-year retention); **Security Guardian Audit** SaaS listed 19 Dec 2025 ([CA](https://www.quest.com/products/change-auditor-for-active-directory/), snapshot 14 Jun 2026) | On-prem Windows/SQL plus SaaS | Quote |
| **Recovery Manager for AD** + **Disaster Recovery Edition** (Quest) | **"Forest Edition" no longer appears on 2026 pages; superseded by DRE** `[no formal EoL found]`. DRE: hardened Secure Storage, immutable Blob/S3 backups, malware scan before restore, clean-OS and bare-metal restore, **standby-forest provisioning (v10.4, Apr 2026)**. **Secure Replay** (private preview, Sep 2026): AI separates attacker changes from legitimate ones ([blog](https://blog.quest.com/product-post/the-disaster-recovery-trade-off-is-over-introducing-secure-replay/)). **Guardian Managed Recovery** service (Aug 2026), white-labelable. SaaS "Disaster Recovery for Identity" for on-prem AD (2025). FedRAMP High for Identity Recovery and Defense | On-prem + SaaS + managed | Quote |
| **Identity Recovery** (ex-On Demand Recovery) | SaaS Entra ID/M365 backup incl. roles, licences and CA-related objects; shared dashboard with RMAD ([page](https://www.quest.com/products/identity-recovery/entra-id-recovery), snapshot 10 Jul 2026) | SaaS | Quote |
| **GPOADmin** (Quest) | Positioned as the replacement for Microsoft **AGPM, which reaches end of life in Apr 2026 (per Quest)**. Check-out/approval workflow, version compare, **protected Tier-0 GPOs**, rollback, air-gapped repository, Intune-readiness analysis ([page](https://www.quest.com/products/gpoadmin), snapshot 30 Apr 2026) | On-prem / offline | Quote |
| **Enterprise Reporter** (Quest) | AD/Entra discovery and reporting, delegated-rights reports, "AD Modernization" report pack; Windows Server 2025 and TLS 1.3 support (May 2025) | On-prem (SQL, discovery nodes) | Quote |
| **Identity Defense** (ex-**Security Guardian**; renamed ~Apr 2026) | Tier-0 and privileged-path visibility for human and non-human identities; AD/Entra posture benchmarking; object freeze and **"Shields Up"** containment (Feb 2025); Security Copilot plugin (2024); **Agentic AI Defense** auto-isolation (Sep 2026); **Identity Insights** (Anetac) ([page](https://www.quest.com/products/identity-defense), snapshot 16 Jul 2026; [blog](https://blog.quest.com/product-post/autonomous-identity-threat-response-with-quest/)) | SaaS (Quest Security Management Platform); FedRAMP High | Azure private offers only |
| Password Manager (One Identity) | On-prem SSPR and unlock, Q&A policies, workflows, bundled cloud 2FA ([page](https://www.oneidentity.com/products/password-manager/), snapshot 16 Mar 2026). Defender and Starling 2FA status unclear `[UNVERIFIED]` | On-prem | Quote |

**Other notes:**
- **Pricing.** Every Quest identity SaaS offer on Azure Marketplace is quote-only and MACC-eligible; Active Roles is BYOL ([Azure catalog](https://catalogapi.azure.com/offers?api-version=2018-08-01-beta), accessed 2026-10-02). Vendr's third-party median across *all* Quest products is ~$14.3K/yr (Feb 2026 data) ([Vendr](https://www.vendr.com/marketplace/quest-software)).
- **Analyst coverage.** Gartner, "A Well-Run Active Directory Requires Strong Identity Controls" (8 May 2025), names Quest, Active Roles and OneLogin as example vendors (per [Quest blog](https://blog.quest.com/product-post/quest-named-as-an-example-vendor-in-the-2025-gartner-report-a-well-run-active-directory-requires-strong-identity-controls/)).

| vs ME | Detail |
|---|---|
| Strengths | Broad enterprise **forest-recovery** options: Secure Storage, standby forest, SaaS DR for on-prem AD, managed recovery, FedRAMP High. **Change blocking**, not just detection. Active Roles delegation/workflow at enterprise scale. GPO change control (GPOADmin) as AGPM sunsets. Security Copilot/Sentinel integration; Azure MACC purchasing. |
| Weaknesses | **Two companies mid-separation**: Active Roles and Password Manager move to an independent One Identity focused on IGA/PAM, with undisclosed ownership. Quest completed two debt transactions in 2025: $350M of new term loans (May) and a second exchange (Aug), following an S&P downgrade in Mar 2025 (trade press). Frequent renames. Quote-only pricing. Many Windows/SQL installs plus separate SaaS consoles (opinion). Google Workspace coverage not found. **Implication:** Active Roles and RMAD customers face roadmap and vendor-risk questions in 2026–27, a **switching window** for activeDIQ (analysis). |

### 2.2 Netwrix
| Field | Detail |
|---|---|
| Corporate | Private; **HQ Frisco, TX** ([about](https://netwrix.com/en/about/)). TA Associates majority investment (1 Oct 2020) ([TA](https://ta.com/news/netwrix-receives-majority-investment-from-ta-associates)). Centerbridge strategic investment (May 2023), when "TA Associates remains the majority shareholder" ([PR](https://netwrix.com/en/resources/news/netwrix-announces-strategic-investment-from-centerbridge-partners/)). **Conflict:** the About page now says "2023: Netwrix receives a majority investment from Centerbridge". Current control `[UNVERIFIED]`; RFP-safe wording is "privately held, backed by TA Associates and Centerbridge". **CEO Grady Summers** since 14 Oct 2024 (ex-SailPoint EVP Products) ([PR](https://netwrix.com/en/resources/news/netwrix-announces-ceo-transition/)). |
| Scale (vendor claims) | "More than 13,000 customers, including nearly 25% of the Fortune 500" (press boilerplate Oct 2025–Aug 2026). ARR grew 23× through twelve acquisitions under the prior CEO ([PR](https://netwrix.com/en/resources/news/netwrix-announces-ceo-transition/)). No revenue disclosed. Netwrix's own figures conflict, which is useful when fact-checking its RFP answers: 13,000 vs "14k+" customers; "170+", "200+" and "210+" security checks; TA vs Centerbridge as majority holder. |
| Acquisition string | Stealthbits (merger, Jan 2021), Strongpoint (Feb 2021, per Wikipedia), ANIXIS (Mar 2021), NNT (Jun 2021), PolicyPak (Oct 2021), Usercube (Aug 2022), MATESO (Sep 2022), Imanami (Nov 2022), Remediant (Dec 2022), CoSoSys (Feb 2024), **PingCastle (1 Aug 2024)** ([PingCastle PR](https://netwrix.com/en/resources/news/netwrix-acquires-pingcastle/)). **None found Jan 2025–Sep 2026.** |
| Platform | Everything now sits under **"Netwrix 1Secure"** ("Identity-first data security for enterprise AI") with Data Security and Identity Security pillars (ITDR, IGA, ISPM, PAM, Directory Security) ([platform](https://netwrix.com/en/platform/)). |

**Rename map (current ← former):**
- **Directory Manager** ← GroupID / Imanami. Renamed between 11 Feb and 14 May 2025.
- **Identity Recovery** ← Recovery for Active Directory ← StealthRECOVER.
- **Threat Manager** ← StealthDEFEND.
- **Threat Prevention** ← StealthINTERCEPT.
- **Access Analyzer** ← Enterprise Auditor ← StealthAUDIT.
- **Privilege Secure** ← SbPAM / Remediant SecureONE.
- **Identity Manager** ← Usercube.
- **Password Secure** ← MATESO Password Safe.
- **Password Policy Enforcer** and **Password Reset** ← ANIXIS.

Threat Manager and Threat Prevention remain **separate products**, grouped under the ITDR solution ([products](https://netwrix.com/en/products/)).

| Product | Key facts (2025–2026) | Deployment | Price signal |
|---|---|---|---|
| **Auditor** 10.9 (30 Jun 2026) | Change/activity auditing across AD, Entra ID, Exchange/EXO, SharePoint/SPO, OneDrive, Teams, file servers/NAS, SQL, Oracle, VMware. Point-in-time state reporting; AD and Entra inactive-user correlation; MCP server. No Google Workspace ([product](https://netwrix.com/en/products/auditor/)) | On-prem with SQL; SaaS variant on 1Secure since Mar 2026 | Essentials "starts at **$20 per enabled AD user** + cloud-only Entra ID user", 1-year minimum ([buy](https://netwrix.com/en/buy-now/)). Many per-source licensing exceptions |
| **Directory Manager** 11.1 (11 Feb 2025) | User and group lifecycle, dynamic groups, delegated management "without granting native directory rights", workflows. Covers AD, Entra ID, LDAP and **Google Workspace**. Web UI (replaced MMC) in v11. 11.1 added an **SSPR portal, help-desk portal and Windows logon-screen reset**. Computer-object and Okta management still "in-progress" (Apr 2025 community) ([product](https://netwrix.com/en/products/directory-manager/)) | **On-prem only** (IIS + Elasticsearch) | Suite or Group/User/Password modules plus ~12 add-ons; no public price |
| Directory Manager security advisories | **CVE-2025-48748**: CVSS 4.0/3.1 **10.0**; "Hard-coded Password in Netwrix Directory Manager (formerly Imanami GroupID) v10 and Earlier"; affected **10.0.7784.0 and earlier**; fix build `[TODO]`; published **14 May 2025** ([ADV-2025-013](https://community.netwrix.com/t/13945), verified). Further v11 advisories listed by Netwrix in May, Jun, Jul and Sep 2025, e.g. [ADV-2025-014](https://community.netwrix.com/t/13951); CVE IDs, scores and fix builds `[TODO]`. **ADV-2026-004**: SQL injection, CVSS 4.0 **9.4**, 17 Feb 2026 ([ADV-2026-004](https://community.netwrix.com/t/122889)); CVE ID and fix build `[TODO]` | — | — |
| **Password Policy Enforcer** 12.0 (20 Aug 2026) | Up to 256 policies, compliance templates, breached and reused password blocking, versioned breached-password database | On-prem (AD password filter) | From **$6.60 per enabled user** ([buy](https://netwrix.com/en/buy-now/)) |
| **Password Secure** | Enterprise vault: approval workflows, SSO, mobile apps | On-prem / "cloud, or hybrid" | From **$60 per enabled user** |
| **PingCastle** 4.0 (11 Aug 2026) | "170+ hybrid identity risks", 102 Entra ID indicators (Enterprise only), SCIM, audit log ([product](https://netwrix.com/en/products/pingcastle/)) | Exe; on-prem web app; inside 1Secure | Community free. Service-provider licence "Starting at **$1,000/Assesment**" (sic). Enterprise "Starting at **$30/identity/year**" ([pingcastle.com](https://pingcastle.com/services/)). See licensing changes below |
| **Identity Recovery** 3.1 (15 Jan 2026) | Rollback of AD users, GPOs and DNS; Entra ID and **Okta** object recovery; "automated AD forest recovery". Recovery for AD 2.6 EoS 15 Jul 2026 ([product](https://netwrix.com/en/products/identity-recovery-software/)) | On-prem; Entra/Okta recovery also in 1Secure | UK G-Cloud reseller listing **£7.73/user, minimum 150 users** (May 2024) |
| **Threat Manager** 3.3 (18 Aug 2026) / **Threat Prevention** 8.1 | TM: detects DCShadow, DCSync, Golden Ticket, Kerberoasting, AS-REP roasting, spraying, NTDS.dit extraction; Entra ID detections; automated response; **AI-agent identity inventory in Entra ID**. TP: **real-time blocking** of Tier-0 changes (privileged groups, DCs, GPOs), compromised-account logons and malicious certificate enrollments; "without relying on native logs" ([TM](https://netwrix.com/en/products/threat-manager/), [TP](https://netwrix.com/en/products/threat-prevention/)) | On-prem agents | Quote |
| **1Secure** (SaaS) | AD, Entra ID, Windows Server, SPO, EXO, file servers, SQL. ITDR (Jun 2025); Entra and Okta recovery (Oct 2025); repackaged as Pro Identity / Pro Data / Pro Complete with **Neo AI assistant (beta)** (23 Jun 2026); **SOC 2 Type II** (22 Sep 2026); Pax8 for MSPs ([product](https://netwrix.com/en/products/1secure/)) | Multi-tenant SaaS on Azure plus an on-prem agent | Self-service **$24 / $24 / $39 per identity/yr** (≤150 employees). Azure Marketplace: ITDR **$21–$42**, bundles **$22–$36**/user/yr ([buy 1Secure](https://netwrix.com/en/buy-now/buy-1secure/)) |
| Identity Manager (ex-Usercube) | IGA (JML, certifications, SoD, AI-assisted role modelling); Google Workspace connector. KuppingerCole IGA: Overall Leader (2024) → **Challenger (May 2026)** | SaaS or on-prem | Quote |

**PingCastle licensing after acquisition (watch-outs):**
- Enterprise moved to per-user licensing; per-domain is now "legacy".
- New 4.0 features are Enterprise-only.
- pingcastle.com says Community is "Free for personal use", which contradicts the README (internal use free, NPOSL 3.0).
- Builds carry an expiry; the README shows "End of support: 2027-08-31" ([GitHub](https://github.com/netwrix/pingcastle)).
- This tightening opens room for a **genuinely free** activeDIQ posture scan (§7.1 #9).

**AI (shipped):** MCP servers for Access Analyzer (Apr 2025, free), Auditor, Privilege Secure and Threat Manager ([PR](https://netwrix.com/en/resources/news/netwrix-introduces-agentic-ai-integration/)); AI remediation guidance in 1Secure (Apr 2025); Neo assistant (beta, Jun 2026); AI DLP for prompts (Oct 2025); AI-agent inventory (Aug 2026).

**Competitive motion vs ME:** Netwrix publishes a "ManageEngine alternative" post (9 Mar 2026) calling ME "a collection of separate tools" ([blog](https://netwrix.com/en/resources/blog/manageengine-alternative/)).

| vs ME | Detail |
|---|---|
| Strengths | Real-time **blocking** at source (Threat Prevention). Attack-specific detection with automated response. Recovery across AD, Entra ID and Okta. PingCastle mindshare ("45,000+ domains"). A SaaS offering (1Secure, SOC 2 Type II) and shipped MCP/AI features. Analyst coverage. |
| Weaknesses | **~6–8 separately installed products/consoles** to match AD360's scope (opinion, from the product list). Licensing has many dimensions: per-source exceptions, add-ons, five PingCastle editions, and two 1Secure repackagings in 13 months. **Directory Manager is on-prem only; computer-object management is listed as "in-progress" (Apr 2025); CVE-2025-48748 (CVSS 10.0) was published 14 May 2025.** An endpoint (Windows logon) MFA product is not documented on netwrix.com as of 2026-10-02 `[UNVERIFIED gap]`. M365 tenant administration (licences, mailboxes) is likewise not documented `[UNVERIFIED gap]`. Stacked per-user prices ($6.60–$60 per product) put it above ME (estimate). |

### 2.3 Semperis
| Field | Detail |
|---|---|
| Corporate | Private; Hoboken, NJ; CEO Mickey Bresman ([company](https://www.semperis.com/company/)). **CPO Alex Weinert** (ex-Microsoft VP Identity Security) joined 29 Apr 2025 ([PR](https://www.semperis.com/press-release/alex-weinert-chief-product-officer/)). Funding: $200M Series C led by KKR (May 2022) ([coverage](https://anz.peoplemattersglobal.com/news/technology/cybersecurity-firm-semperis-secures-200-mn-series-c-funding-34111)); **$125M growth financing** from J.P. Morgan and Hercules, 20 Jun 2024 ([PR](https://www.semperis.com/press-release/semperis-secures-growth-financing/)). New executives were described as having "IPO and public company experience"; no IPO filing found `[UNVERIFIED]`. |
| Scale (vendor claims) | **ARR "surpassed $100M"** (30 Jan 2025) ([PR](https://www.semperis.com/press-release/100m-arr/)). "1,200+" customers in Apr–Sep 2026 releases; "25%+ of the 100 largest U.S. companies" ([PR](https://www.semperis.com/press-release/semperis-takes-center-stage-at-black-hat-usa/)). |
| M&A / alliances | **Acquired MightyID** (Okta/Ping backup, recovery and failover), 4 Feb 2026, terms undisclosed ([PR](https://www.semperis.com/press-release/semperis-acquires-identity-resilience-provider-mightyid/)). Cohesity sells **"Cohesity Identity Resilience, powered by Semperis"** (17 Sep 2025) ([PR](https://www.semperis.com/press-release/cohesity-semperis-offering-unifies-data-identity-resilience/)). Microsoft MISA and co-sell partner; joined the Sentinel partner ecosystem 30 Sep 2025 ([PR](https://www.semperis.com/press-release/microsoft-sentinel-partner-ecosystem-strategic-ally/)). Lightning integrates with custom Security Copilot agents via the Security Store (blog 23 Jun 2026) ([blog](https://www.semperis.com/blog/semperis-microsoft-sentinel-copilot-integration/)). |
| Products | **DSP (Directory Services Protector)**: tamper-proof AD and Entra change tracking, point-in-time **auto-undo**, hundreds of IOE/IOC indicators, ML spray/brute-force detection, response rules (ServiceNow, force reset, disable the "ChangedBy" user), Sentinel/Splunk ([page](https://www.semperis.com/active-directory-security/)); Service Account Protection for NHIs (5 Aug 2025). **ADFR**: malware-free automated forest recovery, staged "Minimum Viable Company" recovery, immutable backups on Azure Blob or S3, Windows Server 2025 DC support ([page](https://www.semperis.com/active-directory-forest-recovery/)). **DRET**: SaaS Entra tenant backup and recovery (users, groups, roles, CA policies, app registrations, PIM) ([page](https://www.semperis.com/entra-id/)). **Recovery for Okta** (SaaS). **Lightning Platform**: IRP (ML attack detection) and Intelligence (SaaS posture scoring, Tier-0 attack paths, "agent identity exposures"; launched 4 Dec 2024) ([PR](https://www.semperis.com/press-release/lightning-intelligence-offering/)). **Delegation Manager for AD**: ACL delegation policy enforcement, not a help-desk console; launched 12 Jun 2024 ([page](https://www.semperis.com/solutions/delegation-manager/)). **Migrator for AD v2.0** (23 Sep 2026) ([PR](https://www.semperis.com/press-release/semperis-reimagines-active-directory-migration-from-the-ground-up/)). **Ready1**: out-of-band crisis management, 25 Apr 2025 ([PR](https://www.semperis.com/press-release/ready1-transform-cyber-crisis-response/)). Free: **Purple Knight** (AD, Entra and Okta assessment; GCC High from 21 Apr 2026) and **Forest Druid** (Tier-0 attack paths) ([Purple Knight](https://www.semperis.com/purple-knight/), [Forest Druid](https://www.semperis.com/forest-druid/)). IR services (IFIR). "Lightning Intrusion Detection" does not appear on current pages `[UNVERIFIED]`. |
| Not documented (as of 2026-10-02) | **Day-to-day AD administration, provisioning, approval workflow and SSPR/MFA are not documented** in the product list ([semperis.com](https://www.semperis.com/), [Delegation Manager](https://www.semperis.com/solutions/delegation-manager/)). No Google Workspace. |
| Deployment | Mixed. Customer-hosted (DSP, ADFR; specifics `[UNVERIFIED]`) and SaaS (DRET, Recovery for Okta, Ready1, Lightning Intelligence via an on-prem collector, no DC agents). |
| Pricing | Quote only; no public price list; licensing metric `[UNVERIFIED]`. Federal vehicles via Carahsoft (SEWP V, ITES-SW2, NASPO etc., 6 May 2026). **Estimate:** ~$100K average ARR per customer ($100M ARR ÷ ~1,000 customers; mixes dates and vendor claims; order of magnitude only). |
| Vendor research (sponsored, flag bias) | 2024 Ransomware Risk Report: ~1,000 respondents; 83% targeted in the past year; 78% paid; only 27% had AD-specific backup ([PR](https://www.semperis.com/press-release/semperis-2024-ransomware-study/)). 2025: ~1,500 organizations, 69% paid ([PR](https://www.semperis.com/press-release/2025-ransomware-study-reveals-relentless-cyberattacks-global-organizations/)). Purple Knight data: average score 61/100, down from 72 in 2023 ([PR](https://www.semperis.com/press-release/purple-knight-report/)). May 2026 (Censuswide, 1,100 organizations): 93% use or plan AI agents for password resets and VPN tasks; only 32% "very confident" they could regain control if AI exposed admin credentials ([PR](https://www.semperis.com/press-release/new-semperis-study-reveals-ais-effects-on-the-identity-attack-surface/)). |
| Target | Large enterprise and government; security, IR and identity-architecture buyers (CISO-led). |
| vs ME | **Strengths:** a leading AD forest-recovery and AD/Entra auto-undo brand (opinion); Microsoft alumni and alliances; threat-research brand; coverage beyond Microsoft (Okta, Ping). **Weaknesses:** cannot replace ADManager Plus or ADSelfService Plus; many separately sold products; opaque, premium pricing (opinion). Usually a **complement** in ME accounts, not a replacement. |

### 2.4 Cayosoft (the closest like-for-like "replace ME" challenger)
| Field | Detail |
|---|---|
| Corporate | Private; Columbus/Westerville, Ohio; founders Bob Bobel (CEO; ex-Quest and Netwrix product management) and Andrei Polevoi (CTO) ([leadership](https://www.cayosoft.com/about/leadership-team/)). **$22.5M minority growth investment from Centana Growth Partners**, 7 Mar 2024 ([PR](https://markets.financialcontent.com/postgazette/article/gnwcq-2024-3-7-cayosoft-secures-225-million-to-make-instant-active-directory-recovery-an-industry-standard)). **Acquired Petri IT Knowledgebase** (petri.com), 21 Feb 2025 ([PR](https://www.cayosoft.com/news/cayosoft-acquires-the-petri-it-knowledgebase-strengthening-its-commitment-to-the-it-professional-community/)). MISA member since Nov 2024. |
| Growth claims (vendor, mutually inconsistent) | "76% YoY ARR growth" for FY2025 and "99% average retention over 3 years" ([PR 19 Feb 2026](https://markets.financialcontent.com/postgazette/article/gnwcq-2026-2-19-cayosoft-captures-record-market-momentum-in-2025-amid-rising-demand-for-operational-resilience-and-modernization)). No customer count disclosed. Named wins: **IRS** multi-year contract (1 Jun 2025) ([PR](https://www.cayosoft.com/news/cayosoft-awarded-multi-year-contract-with-internal-revenue-service-to-manage-their-microsoft-identity-environment/)), a U.S. Department of War agency (4 Feb 2026). |
| Products | **Cayosoft Administrator**: one web console for AD, Entra ID, M365, Exchange, Teams and Intune. JML automation, HR feeds, dynamic groups, license management, role/attribute-based delegation, approvals, group attestation, reporting; an "Ask Otto – Cayosoft AI Assistant" heading appears, product status `[UNVERIFIED]` ([page](https://www.cayosoft.com/products/administrator/)). **Cayosoft Guardian** in three tiers. *Protector* is free forever (detection and change monitoring, no object limits; launched 15 Oct 2025) ([page](https://www.cayosoft.com/products/guardian/guardian-protector/)). *Audit & Restore* adds before/after change history and one-click rollback across AD, Entra, M365, Intune, Teams and Exchange Online, plus IOE/IOC/IOA detection and SIEM forwarding ([page](https://www.cayosoft.com/products/guardian/guardian-audit-restore/)). *Instant Forest Recovery* keeps a patented, continuously validated **standby forest** for cutover in "minutes" (patent 24 Sep 2024) ([page](https://www.cayosoft.com/products/guardian/guardian-active-directory-instant-forest-recovery/)). **Guardian v7.2** (17 Mar 2026) adds monitoring and rollback for **Entra Agent ID** identities ([PR](https://www.cayosoft.com/news/cayosoft-debuts-agentic-ai-identity-change-controls-and-new-incident-response-offering-at-rsa-2026/)). **Guardian SaaS** was announced 18 Nov 2025 for Q1 2026 GA, then slipped to "Q2 2026"; no GA announcement found `[UNVERIFIED]`. |
| Deployment | Guardian is agentless on a Windows Server VM (SaaS pending). The standby forest can run on VMware, Hyper-V, Azure or AWS. Administrator hosting `[UNVERIFIED]`. |
| Pricing | Quote only. 12/36/72-month subscriptions; "no fees per administrator, CPU, node or server"; dev/test included ([pricing](https://www.cayosoft.com/about/pricing/)). Licensing unit `[UNVERIFIED]`. Vendor claims "30–60% lower TCO" than Quest and Semperis. |
| **Competitive motion vs ME** | Runs a **"Replace ManageEngine" program page**. It claims to include in one line what ME spreads across ADSelfService Plus, ADAudit Plus and RecoveryManager Plus, and rates ME lifecycle workflows as "basic" and ME rollback as "limited" (vendor claims) ([page](https://www.cayosoft.com/replacement-program/replace-manageengine/)). Similar pages target Quest, Semperis, Netwrix and Imanami. |
| Research bias flag | Its 2024 and 2025 AD surveys were run by Petri, which Cayosoft has owned since Feb 2025 (e.g., "only 6% can recover AD in under an hour") ([PR](https://markets.financialcontent.com/postgazette/article/gnwcq-2024-2-15-new-survey-report-majority-of-businesses-unprepared-for-active-directory-forest-recovery)). |
| Target | "SMB to mid-enterprise" plus federal, healthcare and education. |
| vs ME | **Strengths:** closest feature-for-feature replacement (admin, delegation, audit, rollback and forest recovery in one family, including Intune and Teams); free Protector tier as lead-gen; federal references. **Weaknesses:** SSPR/MFA-at-logon scope undocumented; no Google Workspace; small funding base; no public pricing; SaaS GA unconfirmed. **Implication:** activeDIQ is not the only "replace ME" story. Differentiation must come from UX, SSPR depth, AI and price transparency, not breadth alone. |

### 2.5 Softerra Adaxes
| Field | Detail |
|---|---|
| Positioning | Self-hosted AD / Entra ID / Exchange / M365 management and automation layer: web interface for help desk and self-service, rule-based delegation, approval workflows, business rules, PowerShell scripting. |
| Recent releases | **2025.1** (27 Mar 2025): "reworked web interface", full PowerShell 7 support, improved approval-request handling. **2026.1** (29 Jan 2026): "seamless sign-in for Entra users", password self-reset on Entra-joined devices, REST API token auth. 2026.1 Update 3 (11 May 2026) published the client SDK on NuGet. ([news](https://www.adaxes.com/news.htm)) |
| Public roadmap (vote counts, undated) | Dynamic forms (1,314 votes), temporary group membership (927), **web-based admin console (825)**, Teams integration (795), Entra device management (390), choice of SSPR verification method (368), Entra administrative-unit management (260). The roadmap mentions no AI, Google Workspace, access reviews, auditing or SaaS delivery. ([roadmap](https://www.adaxes.com/info_roadmap.htm)) The admin console being on the roadmap suggests it is still a Windows client today (opinion). |
| Deployment | Self-hosted. All licenses are perpetual ([purchase](https://www.adaxes.com/purchase.htm)). |
| Pricing (public, accessed 2026-10-02) | Licensed by **enabled, non-expired user accounts across all managed domains**. Perpetual: 100 users **$1,600**; 200 $2,084.21; 400 $3,052.63; 600 $4,021.05; 800 $4,989.47; 1,000 **$5,957.89**; 1,500 $8,378.95; 2,000 **$10,800**. Annual maintenance is about 30% ($480 at 100 users, $3,240 at 2,000). 2k–10k and 10k–50k users are quoted; unlimited license above 50k users; education, government and non-profit discounts. ([purchase](https://www.adaxes.com/purchase.htm)) |
| Target | SMB to mid-enterprise; PowerShell-literate Windows teams (opinion). |
| vs ME: strengths | Deeper rules and automation engine, approval workflows and scripting extensibility than ADManager Plus (opinion, common in practitioner comparisons `[UNVERIFIED]`); transparent perpetual price list; steady release cadence (above). |
| vs ME: weaknesses | Equivalents to ADAudit Plus (DC-level change auditing), RecoveryManager Plus (backup/recovery) and ITDR are not documented on adaxes.com as of 2026-10-02. Its own logging covers operations made through Adaxes, not native DC event auditing `[UNVERIFIED]`. No Google Workspace. Admin console is not yet web-based (roadmap). |

### 2.6 Lepide
| Field | Detail |
|---|---|
| Positioning | "Data Security Platform" for "admins and security leaders": auditing, permissions analysis and threat detection across identity and data. Modules: **Lepide Auditor, Trust (permissions analysis), Detect (real-time alerts/response), Identify (data classification), Protect (permissions management), Lepide AI**. ([lepide.com](https://www.lepide.com/), accessed 2026-10-02) |
| Coverage | AD / Entra ID, Windows file servers, M365 (incl. M365 Copilot), Exchange, SharePoint, SQL Server, Nutanix, Nasuni. ([lepide.com](https://www.lepide.com/)) |
| 2025–2026 moves | **Lepide AI** launched 26 Feb 2025. Copilot security support in DSP 24.4 (20 Jan 2025). "AI-led" Lepide Protect (9 Jul 2025). Free AD Risk Assessment tool (29 Jul 2025). Free inactive-AD-account tool (18 Aug 2025). "State of Identity and Data Security 2026" report (3 Jul 2026, vendor research). ([news](https://www.lepide.com/news/)) |
| Deployment | Self-hosted `[UNVERIFIED]`. The About page's "on-prem and cloud platforms" reads as coverage, not delivery model. Founded 2005; "3 Global Offices"; ownership not disclosed ([about](https://www.lepide.com/about-us.html)). |
| Pricing | Quote only ([quote request](https://www.lepide.com/quoterequest.html)). |
| Target | Mid-market and enterprise, compliance-driven buyers. Logos shown include Deloitte, KPMG, Pfizer and NHS (vendor claim, [lepide.com](https://www.lepide.com/)). |
| vs ME: strengths | Combines ADAudit Plus-style AD auditing with file/data-access governance and classification (closer to ME's DataSecurity Plus + ADAudit Plus together). Shipped a branded AI layer early (Feb 2025). |
| vs ME: weaknesses | AD lifecycle management/delegation console, SSPR and forest recovery are not documented on lepide.com as of 2026-10-02. Corporate ownership and HQ not disclosed `[UNVERIFIED]`. |

### 2.7 SolarWinds Access Rights Manager (ARM)
| Field | Detail |
|---|---|
| Corporate | SolarWinds was taken private by **Turn/River Capital**: announced 7 Feb 2025, completed 18 Apr 2025, $18.50/share, about $4.4B, delisted from NYSE ([Wikipedia](https://en.wikipedia.org/wiki/SolarWinds), citing Cybersecurity Dive 7 Feb 2025 and Channel Insider 18 Apr 2025; secondary source). The investor-relations site now redirects to solarwinds.com. |
| Positioning / capabilities | Still sold as "Access Rights Manager" (accessed 2026-10-02). Features: AD and "Azure AD" reports, file-server and Exchange auditing, SharePoint and OneDrive/M365 permissions, automated user provisioning/onboarding, and a self-service permissions portal that delegates access decisions to data owners. 30-day trial. ([product page](https://www.solarwinds.com/access-rights-manager)) |
| Security record | **CVE-2024-28991**: critical (CVSS 9.0) deserialization RCE by an authenticated user in ARM ≤2024.3, fixed in 2024.3.1, published 12 Sep 2024 ([advisory](https://www.solarwinds.com/trust-center/security-advisories/cve-2024-28991)). Other 2024 ARM CVEs exist `[UNVERIFIED count]`. |
| Deployment | Self-hosted `[UNVERIFIED]`; the page does not state it. |
| Pricing | The page shows a "Starts at" price, but the figure was not captured `[UNVERIFIED]`. |
| vs ME | Strength: permission-centric access governance (file share/SharePoint owner delegation). Considerations: the product page still uses the pre-2023 "Azure AD" name (inference: slower content refresh). See CVE-2024-28991 above. Private-equity ownership since Apr 2025. SSPR, AD recovery and ITDR are not documented on the product page as of 2026-10-02. |

### 2.8 Specops Software
| Field | Detail |
|---|---|
| Status | specopssoft.com and outpost24.com returned HTTP 403 to automated fetches on 2026-10-02, so **everything below comes from prior knowledge and needs re-verification** `[UNVERIFIED]`. |
| Corporate | Acquired by **Outpost24** in 2023 `[UNVERIFIED]`. |
| Products | **Specops Password Policy** (AD password policy engine with Breached Password Protection), **Specops uReset** (SSPR with multi-factor identity verification and Entra ID support), **Specops Secure Service Desk** (help-desk caller identity verification before resets/unlocks), **Specops Password Auditor** (free AD password audit) `[UNVERIFIED]`. |
| Why it matters | Secure Service Desk addresses the help-desk social-engineering pattern behind several 2023–2025 intrusions (see §4.2). For ADSelfService Plus's equivalent help-desk verification capability, see the sibling file `[verify]`. |
| Pricing | Per-user subscription `[UNVERIFIED]`; figures not captured `[TODO]`. |
| vs ME | Strength: specialised password hygiene (breached-password lists) and help-desk verification `[UNVERIFIED]`. Scope: AD management, auditing and recovery are outside the documented product line `[UNVERIFIED]`. |

### 2.9 tenfold
| Field | Detail |
|---|---|
| Positioning | "No-code" IGA for the mid-market with "faster time to value": role-based access, joiner/mover/leaver automation, access reviews/recertification, separation of duties, file-level visibility (incl. M365 shared content), self-service access requests and password resets, auditing and threat detection. Plugins cover AD, file servers, M365/Entra ID, HR/ITSM/ERP, plus a generic API connector. ([tenfold](https://www.tenfold-security.com/en/), accessed 2026-10-02) |
| Deployment | **On-prem only**: "runs on-premise", "not a SaaS solution". Needs Windows Server plus SQL Server or Oracle. ([pricing](https://www.tenfold-security.com/en/tenfold-pricing/)) |
| Pricing (public) | **Essentials $0.90 / managed identity / month** (on-prem systems); **Essentials 365 $1.25** (adds Microsoft cloud); **Enterprise** custom (SAP, Workday, etc.); **Community Edition free up to 150 users**. Minimum yearly subscription is 100 users, and per-user cost "may be higher than the shown starting price". ([pricing](https://www.tenfold-security.com/en/tenfold-pricing/)) |
| Target | Mid-market, DACH-centric `[UNVERIFIED]`. |
| vs ME | Strength: purpose-built IGA (recertification, SoD, roles) at a published low price point. ADManager Plus also offers access certification, with ML recommendations since Dec 2024 ([release notes](https://www.manageengine.com/products/ad-manager/release-notes.html)); depth comparison is in the sibling file. Weakness: on-prem only; no AD forest recovery, ITDR or Google Workspace found. |

### 2.10 Microsoft native stack
| Component | State (2026) | Gap left for third parties |
|---|---|---|
| ADUC / ADAC / RSAT / PowerShell | Free, in-box. | No approval workflow, attribute-scoped delegation UI, templated provisioning, change rollback or consolidated reporting (opinion; long-standing reason the third-party category exists). |
| Entra ID P1 / P2 | List **$7.00 / $10.00** per user/month, annual ([pricing](https://www.microsoft.com/en-us/security/business/microsoft-entra-pricing), accessed 2026-10-02). Earlier list prices were $6 / $9; the effective date of the change was not verified `[UNVERIFIED]`. | Licence cost pushes non-E3/E5 mid-market buyers toward third-party SSPR/MFA (opinion). |
| Entra ID Governance / Entra Suite | Governance **$7.00** user/month add-on (requires P1 or P2). Entra Suite **$12.00** (requires P1). ([pricing](https://www.microsoft.com/en-us/security/business/microsoft-entra-pricing)) | Lifecycle workflows and access reviews are cloud-centric; on-prem AD coverage comes via provisioning back to AD (below). |
| Entra Connect Sync → **Entra Cloud Sync** | Microsoft calls Cloud Sync its "strategic direction for hybrid identity". It uses lightweight outbound-only provisioning agents and cloud-managed config, syncs every 2 minutes, handles disconnected multi-forest, and supports **cloud-to-AD group provisioning** and SOA scenarios. Doc dated 17 Feb 2025, updated 13 Mar 2026. ([Learn](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/what-is-cloud-sync)) Since Apr 2026 Microsoft is "beginning the transition from… Connect Sync to… Cloud Sync" ([what's new](https://learn.microsoft.com/en-us/entra/fundamentals/whats-new)). Connect Sync must be at **2.6.84.0+ with app-based auth by 7 Apr 2027** ([Learn](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-install-prerequisites)). | Sync is free and owned by Microsoft. Third parties add value in sync-error visibility, attribute hygiene before sync, and M&A multi-forest cleanup (opinion). |
| Group Source of Authority (SOA) conversion | Converts AD-synced groups into cloud-managed groups, which can then be provisioned back to AD DS. Lets Entra ID Governance control Kerberos/LDAP apps; Microsoft calls this "AD DS minimization". Doc dated 19 Aug 2025, updated 24 Sep 2026. ([Learn](https://learn.microsoft.com/en-us/entra/identity/hybrid/concept-source-of-authority-overview)) **Group SOA GA Oct 2025; user SOA GA Jan 2026** ([archive](https://learn.microsoft.com/en-us/entra/fundamentals/whats-new-archive)). | **Strategic threat.** Microsoft is moving the authoring point for AD objects into Entra. Any AD-management product must manage both SOAs cleanly. |
| Defender for Identity (MDI) | ITDR for on-prem AD and Entra ID, plus "other IAM solutions (for example, Okta)". Posture assessments in Secure Score, lateral-movement-path analysis, detections incl. DCShadow and Golden Ticket, remediation actions. Doc dated 23 Jul 2026. ([Learn](https://learn.microsoft.com/en-us/defender-for-identity/what-is)) Licensing: sold within the **Microsoft Defender Suite at $12.00/user/month** (annual), which requires M365 E3 or O365 E3 + EMS E3 ([product page](https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-for-identity), accessed 2026-10-02). It is also part of M365 E5 (not re-verified this pass). | Detection-centric. No change rollback, no object-level restore, no forest recovery. |
| Security Copilot Entra agents | **Conditional Access Optimization Agent** (needs Entra ID P1; runs every 24h or on demand). **Identity Risk Management Agent** (Preview). Both consume Security Compute Units (SCUs). Security Store is embedded in the Entra admin center. Doc 21 Jan 2026, updated 15 Jun 2026. ([Learn](https://learn.microsoft.com/en-us/entra/security-copilot/entra-agents)) | Cloud-only scope. No agent for on-prem AD administration found. |
| Ignite 2025 Entra wave | **Entra Agent ID** (identities for AI agents), synced passkeys and passkey profiles, self-service account recovery, Identity Risk Management agent, lifecycle workflows for inactive users (10 Nov 2025). ([Learn](https://learn.microsoft.com/en-us/entra/fundamentals/whats-new-ignite-2025)) | Raises the bar for "modern" identity UX that buyers will compare against. |
| Entra Backup and Recovery | **GA Jun 2026, cloud tenant objects only; does not cover AD** ([what's new](https://learn.microsoft.com/en-us/entra/fundamentals/whats-new)). | AD forest/DC recovery and object rollback stay with third parties. Entra-side backup becomes native to Microsoft's stack (licensing not verified `[UNVERIFIED]`), which squeezes DRET-style third-party Entra backup (opinion). |
| Entra SSPR | Cloud-only reset is included from M365 Business Standard upward. **Hybrid reset with on-prem writeback needs Entra ID P1/P2 or M365 Business Premium**; standalone M365 Basic/Standard plans do not support writeback (doc dated 4 Mar 2025, updated 13 Feb 2026) ([Learn](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-licensing)). | Users that are never synced, orgs without P1 (e.g., O365-only SKUs), and logon-screen or VPN scenarios keep third-party SSPR relevant (opinion). Many ME accounts on M365 E3/E5 already own P1, which weakens the SSPR-only pitch there. |
| Windows LAPS | Shipped in the **11 Apr 2023** Windows updates and is free. Backs up to AD or Entra ID; also manages DSRM passwords on DCs. Automatic Account Management needs Win 11 24H2+ / Windows Server 2025+. Legacy Microsoft LAPS is deprecated; Windows 10 reached end of support 14 Oct 2025. Doc dated 14 Sep 2026. ([Learn](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)) | Native management is ADUC, PowerShell and the event log. Approval-gated retrieval, cross-estate reporting and alerting are value-add opportunities (opinion). |

### 2.11 JumpCloud ("replace AD" play)
| Field | Detail |
|---|---|
| Positioning | Cloud directory plus device management. "Replace AD altogether or integrate it seamlessly with your AD instance"; "Break free of AD's restrictions with a more modern alternative." Offers AD Integration (import identities from AD) and an **AD Migration Utility** (converts domain profiles to local profiles that JumpCloud then manages, hosted on GitHub). ([modernize AD](https://jumpcloud.com/use-cases/modernize-active-directory), accessed 2026-10-02) |
| AI | **JumpCloud AI Assistant** (stated GA): natural-language queries over users, devices and apps; actions such as MFA resets and user unlocks; bulk operations via chat; human-in-the-loop approval with audit logging in Directory Insights ([page](https://jumpcloud.com/platform/jumpcloud-ai-assistant)). The sitemap also lists "agentic identity lifecycle management" and "shadow AI discovery" pages ([sitemap](https://jumpcloud.com/page-sitemap.xml)). |
| Pricing (public) | Device Management **$9**/user/mo (annual) or $11 (monthly). SSO **$11** or $13. Device Identity Management **$13** or $15. Platform tiers are quoted. À-la-carte Cloud Directory, MFA, SSO and Lifecycle Mgmt are $3–$4 each. ([pricing](https://jumpcloud.com/pricing)) |
| Target | SMB / mid-market, Mac-heavy and cloud-first orgs (opinion). |
| vs ME | Strength: removes the AD/DC estate entirely for small orgs; the AI assistant ships today. Limitation: replacing Kerberos/LDAP-dependent apps, GPO and large multi-forest estates is not documented on the pages reviewed (as of 2026-10-02). Fit is strongest in small, cloud-first estates (opinion). AD auditing, recovery and ITDR are not documented. |

### 2.12 Okta ("replace/abstract AD" play)
| Field | Detail |
|---|---|
| Positioning | Universal Directory "centralize user profiles from the source—AD, LDAP, HR apps, and more", with AD connected via the Okta AD agent ([pricing](https://www.okta.com/pricing/)). |
| Products relevant here | **Identity Security Posture Management (ISPM)**: finds shadow admins, MFA gaps and dormant identities, including NHIs. The page names "Azure Active Directory and Microsoft 365"; on-prem AD coverage is not confirmed ([ISPM](https://www.okta.com/products/identity-security-posture-management/)). **Identity Threat Protection (ITP) with Okta AI** is "now generally available". It "continuously assesses user risk throughout user sessions", detects session hijacking, and ingests partner signals through the Shared Signals Framework (CrowdStrike, Zscaler, Palo Alto Networks, Jamf). On-prem AD coverage is not stated ([ITP](https://www.okta.com/products/identity-threat-protection/)). Okta Privileged Access was extended through the Axiom Security acquisition (Sep 2025, §4.8). Okta revenue: **$2.92B, FY2026** (ended 31 Jan 2026) ([Wikipedia](https://en.wikipedia.org/wiki/Okta,_Inc.)). |
| Pricing (public) | Workforce: **Starter $6**, **Core Essentials $14**, **Essentials $17** per user/month; Professional and Enterprise quoted; **$1,500 annual contract minimum** ([pricing](https://www.okta.com/pricing/), accessed 2026-10-02). |
| vs ME | Okta is a cloud IdP that sits on top of AD. AD management, auditing, GPO and recovery are not documented in its product scope (as of 2026-10-02). In ME accounts it competes with ADSelfService Plus (SSPR/MFA/SSO) more than with ADManager Plus (opinion). |

### 2.13 Open source and free tools
| Tool | State (2026) | Relevance |
|---|---|---|
| **BloodHound CE** (SpecterOps) | Latest release **v9.7.1** (17 Sep; GitHub omits the year for current-year dates, so 2026). Recent features: multi-destination pathfinding, AD site visualization, zone-protected asset scoring, findings prioritization. ([releases](https://github.com/SpecterOps/BloodHound/releases)) | De facto attack-path standard used by both attackers and defenders. Buyers expect "Tier-0 attack path" views (opinion). |
| **PingCastle** | Owned by **Netwrix since 1 Aug 2024**. v4.0 (11 Aug 2026). Licensing has tightened: Enterprise-only new features; per-user Enterprise licensing from $30/identity/yr; ambiguous "free for personal use" wording; build expiry (§2.2). | Free AD health and risk score, widely used for audits. Sets the bar for posture-assessment UX, and its commercialization opens room for a free alternative. |
| **Samba AD DC** | Latest major **4.25.0** (24 Sep 2026); 4.23.x and 4.24.x still maintained ([history](https://www.samba.org/samba/history/)). 4.25 defaults the KDC to AES enctypes (addresses CVE-2026-20833) ([notes](https://www.samba.org/samba/history/samba-4.25.0.html)). | Niche AD-compatible DC for Linux shops. Functional-level parity with current Windows Server not verified `[UNVERIFIED]`. Enterprise-scale replacement of Windows DCs is not documented by the project (opinion: limited fit for ME's enterprise accounts). |
| Purple Knight / Forest Druid (Semperis, free) | See §2.3. | Free assessment tools used as lead-gen. |

### 2.14 Adjacent ITDR / identity-resilience players (not AD-management competitors, but share the budget)
AD coverage below is per vendor pages (vendor claims). Analyst positions are from KuppingerCole's ITDR Leadership Compass, 6 Nov 2025 ([KC](https://www.kuppingercole.com/research/lc81209/identity-threat-detection-and-response-itdr)).

| Vendor / product | AD coverage (one line) | KC ITDR 2025 position | Source |
|---|---|---|---|
| CrowdStrike Falcon Identity Protection | "Unified" ITDR across on-prem AD and Entra ID, with context-aware MFA enforcement | Overall Leader | [CrowdStrike](https://www.crowdstrike.com/en-us/platform/next-gen-identity-security/identity-protection/) |
| SentinelOne Singularity Identity | AD plus Entra, Okta and Ping; identity deception; continuous posture | Innovation Leader | [SentinelOne](https://www.sentinelone.com/platform/singularity-identity/) |
| Silverfort | Inline, agentless enforcement; MFA for legacy AD protocols; service-account protection | Product/Innovation Leader | [Silverfort](https://www.silverfort.com/) |
| Tenable Identity Exposure | Agentless, no privileged credentials needed; IoE/IoA for AD and Entra ID | — | [Tenable](https://www.tenable.com/products/identity-exposure) |
| Proofpoint Identity Threat Defense | Agentless scanning of AD, Entra and endpoints; "75+ decoy types" | — | [Proofpoint](https://www.proofpoint.com/us/products/identity-threat-defense) |
| Varonis | Identity posture plus ITDR plus data-centric behaviour analytics (AD/Entra) | — | [Varonis](https://www.varonis.com/) |
| Vectra AI | Behaviour analytics for human, machine and AI-agent identities; AD detail not confirmed | — | [Vectra](https://www.vectra.ai/) |
| BeyondTrust, CyberArk (Palo Alto), Delinea, Saviynt | PAM/IGA-led ITDR | Overall Leaders | [KC](https://www.kuppingercole.com/research/lc81209/identity-threat-detection-and-response-itdr) |
| Microsoft Defender for Identity | See §2.10 | Overall Leader (Microsoft) | — |
| **ManageEngine (AD360, PAM360, Log360)** | See sibling files | **"Market Leader"** | [KC](https://www.kuppingercole.com/research/lc81209/identity-threat-detection-and-response-itdr) |
| Semperis, Quest, Netwrix, Cayosoft | See §2 | Rated vendors | same |
| Backup-led identity resilience: Commvault, Cohesity (powered by Semperis), Rubrik `[UNVERIFIED: rubrik.com blocked]` | AD forest recovery as part of cyber-recovery suites | — | §1 S4 |

## 3. Comparison matrix

Legend: ● full · ◐ partial · ○ none found · ? unknown. `*` = rating from prior knowledge, not verified this pass. Price tier is relative to ManageEngine ($) and is an analyst estimate unless a public list price is cited in §2. Ratings describe each vendor's **AD-relevant portfolio as a whole**, often several SKUs; evidence is in §2. ME row sources: [RecoveryManager Plus](https://www.manageengine.com/ad-recovery-manager/), [ADSelfService Plus release notes](https://www.manageengine.com/products/self-service-password/release-notes.html), [AD360](https://www.manageengine.com/active-directory-360/), [ADManager Plus release notes](https://www.manageengine.com/products/ad-manager/release-notes.html). Everything else is deferred to the sibling ME files.

| Vendor (portfolio) | Mgmt | Deleg./workflow | Reporting | Auditing | SSPR/MFA | Backup/recovery | ITDR/posture | Hybrid Entra | M365 | Google WS | Deployment | Price tier |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **ManageEngine AD360** (reference; see sibling files) | ●* | ●* | ●* | ●* | ● (passkeys incl. machine logins) | ◐ (RecoveryManager Plus: DC recovery and attribute-level restore across AD, Entra, M365, Exchange, Google Workspace; automated *forest* recovery not stated) | ◐ ("UBA-driven") | ●* | ● | ◐ (RMP backs up Google Workspace; admin depth: see sibling) | Self-hosted (cloud variants: see sibling) | $ |
| **Quest / One Identity** | ● (Active Roles; Active Administrator) | ● (Active Roles workflows; GPOADmin approvals) | ● (Enterprise Reporter) | ● (Change Auditor incl. blocking; On Demand Audit) | ◐ (One Identity Password Manager + bundled cloud 2FA; Defender/Starling status unclear) | ● (RMAD + DRE standby forest; Identity Recovery; managed recovery) | ● (Identity Defense, Identity Insights; BloodHound Enterprise resale) | ● | ◐ (audit, recovery, migration; day-to-day admin depth unverified) | ○ | Self-hosted + SaaS (incl. FedRAMP High) + managed; BYOL VMs | $$$ (est.; quote-only) |
| **Netwrix** | ◐ (Directory Manager; no computer objects) | ● | ● | ● | ◐ (SSPR in Directory Manager; no endpoint MFA found) | ● (Identity Recovery: AD forest, Entra, Okta) | ● (PingCastle, Threat Manager/Prevention, 1Secure ITDR) | ● | ◐ (audit/data security; no tenant admin) | ◐ (Directory Manager, Identity Manager) | Self-hosted + SaaS (1Secure) + MSP | $$$ (stacked per-user list prices) |
| **Semperis** | ○ | ◐ (ACL delegation only) | ◐ | ● | ○ | ● | ● | ● | ◐ (Entra objects only) | ○ | Self-hosted + SaaS | $$$$ (est.) |
| **Cayosoft** | ● | ● | ● | ● | ? | ● (incl. standby forest) | ◐ | ● | ● (incl. Intune/Teams) | ○ | Self-hosted; SaaS announced, GA unverified | $$–$$$ (est.) |
| **Softerra Adaxes** | ● | ● | ● | ◐ (own ops log) | ◐ (SSPR) | ○ | ○ | ● | ◐ | ○ | Self-hosted, perpetual | $–$$ (public) |
| **Lepide** | ◐ (permissions) | ○ | ● | ● | ○ | ? | ◐ (Detect, AI) | ● | ● | ○ | Self-hosted* | ? (quote) |
| **SolarWinds ARM** | ◐ | ◐ (data-owner portal) | ● | ◐ | ○ | ○ | ○ | ◐ | ◐ | ○ | Self-hosted* | ? |
| **Specops** | ○ | ○ | ◐* | ○ | ●* | ○ | ◐* (breached pwd) | ◐* | ○ | ?* | Cloud + on-prem components* | ? |
| **tenfold** | ● | ● | ● | ◐ | ◐ | ○ | ◐ (claimed) | ● | ● | ? | **On-prem only** | $ (public) |
| **Microsoft native** (in-box + Entra + MDI) | ◐ | ◐ | ◐ | ◐ | ● (P1 for writeback) | ◐ (Recycle Bin; manual forest recovery*) | ● (MDI; Defender Suite / E5) | ● | ● | ◐* | In-box + SaaS | Bundled ($7–$12/user/mo add-ons) |
| **JumpCloud** | ● (cloud directory) | ◐ | ◐ | ◐ (Directory Insights) | ● | ○ | ○ | ◐ | ◐* | ●* | SaaS | $$ ($9–$13/user/mo) |
| **Okta** | ◐ (Universal Directory; AD agent) | ◐* | ◐ | ◐* (System Log) | ● | ○ | ● (ITP, ISPM; cloud-side) | ◐ | ◐* | ●* | SaaS | $$–$$$ ($6–$17/user/mo + $1.5k min) |
| **Open source** (BloodHound CE, PingCastle, Samba) | ◐ (Samba DC tooling) | ○ | ◐ (PingCastle reports) | ○ | ○ | ○ | ◐ (assessment and attack paths; no real-time detection) | ◐ (BloodHound covers Entra*) | ○ | ○ | Self-hosted | Free |

**Reading the matrix (analysis):**
- Only ME, Cayosoft and the big two (Quest/One Identity, Netwrix) span management, auditing **and** recovery. On SSPR/MFA:
  - ME documents the deepest coverage, incl. FIDO2 passkeys for machine logins.
  - Netwrix has SSPR in Directory Manager but no endpoint MFA was found.
  - Cayosoft's SSPR is undocumented.
  - Quest/One Identity has SSPR via One Identity Password Manager with bundled cloud 2FA, now on the One Identity side of the split.
- **Breadth plus SSPR depth is the entry ticket** for displacing ME.
- **Google Workspace** is weak almost everywhere except the cloud-IdP plays. Treat it as an "only if the warm accounts need it" feature.
- **ITDR/posture** is crowded at the top end (Semperis, MDI, Okta, CrowdStrike et al., §2.14). activeDIQ should deliver posture plus auto-revert for AD and integrate detections outward, not try to out-detect MDI.

## 4. Trends 2024–2026

### 4.1 Hybrid identity and Entra adoption
| Signal | Source / date |
|---|---|
| Entra ID is used by "more than 720,000 organizations" (undated product page) | [Microsoft](https://www.microsoft.com/en-us/security/business/identity-access/microsoft-entra-id), accessed Oct 2026 |
| Paid M365 commercial seats grew **6% YoY**; 30M+ paid M365 Copilot seats. Absolute seat count not stated `[UNVERIFIED]` | [MSFT FY26 Q4 earnings](https://www.microsoft.com/en-us/investor/events/fy-2026/earnings-fy-2026-q4), 29 Jul 2026 |
| "Over 40% of ransomware attacks today involve hybrid components. Two years ago, less than 5% did." | [MDDR 2025](https://aka.ms/Microsoft-Digital-Defense-Report-2025), 16 Oct 2025 (vendor telemetry) |
| **Group SOA conversion GA Oct 2025; user SOA conversion GA Jan 2026** (previews Jul and Sep 2025) | [Entra what's new archive](https://learn.microsoft.com/en-us/entra/fundamentals/whats-new-archive) |
| Microsoft is "beginning the transition from Microsoft Entra Connect Sync to the cloud-native Microsoft Entra Cloud Sync" (phased) | [Entra what's new](https://learn.microsoft.com/en-us/entra/fundamentals/whats-new), Apr 2026 |
| Hybrid join via **Entra Kerberos** "without waiting for Entra Connect sync or requiring AD FS" (preview) | same, Mar 2026 |
| **Entra Backup and Recovery GA**: cloud tenant objects only, **does not cover AD**. AD group enforcement via Cloud Sync in preview | same, Jun 2026 |
| Entra Connect Sync must be upgraded to **2.6.84.0+ with app-based authentication "by April 7, 2027"** | [Learn prerequisites](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-install-prerequisites), updated 29 Sep 2026 |

**So what (analysis):**
- Microsoft is moving the *authoring* of users and groups, the sync engine, and cloud-object backup into Entra. A pure on-prem AD tool shrinks with that trend. activeDIQ must know the source of authority (AD or Entra) for every object and work through Cloud Sync.
- The **7 Apr 2027 Connect Sync deadline** forces every hybrid estate to touch its sync layer in the next six months. That is a natural "hybrid health check" entry point for warm ME accounts.
- Entra Backup and Recovery leaves **AD forest and DC recovery to third parties**.

### 4.2 AD as the prime ransomware / identity-attack target
**Headline correction for messaging.** Stolen-credential *initial access* is **falling** in 2026 data, while post-compromise identity abuse, help-desk vishing and attacks on identity and recovery infrastructure are rising. Lead with **Tier-0 blast radius and recovery**, not "identity is the #1 way in".

| Stat (exact wording abbreviated) | Population | Publisher (bias) | Date | Source |
|---|---|---|---|---|
| Valid-account intrusions: "Over half… (52.2%) involved follow-on credential theft"; "the majority of follow-on activity lands on domain controllers"; RMM intrusions concentrate on "domain controllers, identity-synchronization servers, and management infrastructure" | Defender Experts, Jul 2025–Jun 2026 | Microsoft MDDR 2026 (vendor telemetry) | 1 Oct 2026 | [MDDR 2026](https://aka.ms/Microsoft-Digital-Defense-Report-2026) |
| +15.8% YoY ransom detonations against enterprises; password attacks "down 26%"; AiTM/token-theft share "more than doubled" in H1 2026 | Defender telemetry | Microsoft MDDR 2026 | 1 Oct 2026 | same |
| "More than 97% of identity attacks are password spray or brute force"; identity-based attacks +32% in H1 2025 | Entra/Defender alerts | Microsoft MDDR 2025 | 16 Oct 2025 | [MDDR 2025](https://aka.ms/Microsoft-Digital-Defense-Report-2025) |
| 7,000 password attacks per second in 2024 (more than double 2023) | Microsoft telemetry | Microsoft | 1 May 2025 | [blog](https://www.microsoft.com/en-us/security/blog/2025/05/01/pushing-passkeys-forward-microsofts-latest-updates-for-simpler-safer-sign-ins/) |
| In many ransomware incidents attackers "exploited misconfigured Active Directory (AD) Certificate Services templates" to create or impersonate admins. Ransomware operators "actively targeted backup infrastructure, identity services, and virtualization management planes" | 500k+ IR hours, 2025 | Mandiant M-Trends 2026 (IR vendor) | 24 Mar 2026 | [M-Trends 2026](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026) |
| Stolen credentials **9%** of initial vectors (from 16% in 2024); exploits 32%; voice phishing 11% (#2); median dwell time 14 days | Same | Mandiant | 24 Mar 2026 | [PDF](https://www.gstatic.com/security-marketing/m-trends-2026-en.pdf) |
| Exploitation **31%**; credential abuse down to **13%**; ransomware in 48% of breaches | 19,905 breaches with known vector | Verizon DBIR 2026 (multi-contributor) | 2026 | [DBIR 2026](https://www.verizon.com/business/resources/executivebriefs/2026-dbir-executive-summary.pdf) |
| 82% of detections malware-free; average eCrime breakout **29 min** (fastest 27 s) | CrowdStrike telemetry | CrowdStrike GTR 2026 (vendor) | 24 Feb 2026 | [PR](https://www.crowdstrike.com/en-us/press-releases/2026-crowdstrike-global-threat-report/) |
| 67% said the ransomware incident was the same event as their most significant identity attack | 2,158 ransomware victims (n=5,000), 100–5,000 employees | Sophos State of Ransomware 2026 (vendor-commissioned) | 2026 | [PDF](https://assets.sophos.com/X24WTUEQ/at/jbww7pmb8n3gp99wr6hfq4/sophos-state-ransomware-report-2026.pdf) |
| 83% of attacks compromised identity infrastructure | 1,500 orgs | Semperis 2025 (**high vendor bias**) | 30 Jul 2025 | [Semperis](https://www.semperis.com/ransomware-risk-report/) |
| BadSuccessor (Windows Server 2025 dMSA privilege escalation): "In 91% of the environments we examined… users outside the domain admins group… had the required permissions" | Akamai-examined environments | Akamai (vendor research) | 21 May 2025 | [Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory) |

**Help-desk social engineering is now a Tier-0 path:**
- CISA AA23-320A (Scattered Spider, updated **29 Jul 2025**): actors posed as employees to get IT/help desk to "reset the employee's password, and transfer the employee's MFA" ([CISA](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a)).
- Microsoft (16 Jul 2025): Octo Tempest service-desk impersonation, NTDS.dit dumping, DCSync, and pivot via "the critical Entra Connect server" ([Microsoft](https://www.microsoft.com/en-us/security/blog/2025/07/16/protecting-customers-from-octo-tempest-attacks-across-multiple-industries/)).
- MDDR 2026: "93% of voice phishing attacks kept the victim on the line long enough to begin social engineering".
- Disclosed impact: M&S guided **c.£300m** impact on 2025/26 operating profit before mitigation and insurance ([FY25 results](https://corporate.marksandspencer.com/sites/marksandspencer/files/05-2025/fy25-rns.pdf)). MGM disclosed ~**$100M** hit to Adjusted Property EBITDAR ([8-K](https://www.sec.gov/Archives/edgar/data/789570/000119312523251667/d461062d8k.htm)). The help-desk vector at MGM is press-reported only `[UNVERIFIED]`.

**Recovery:** no neutral survey of AD *forest* recovery time was found `[TODO]`. Use Microsoft's guidance instead: after DC compromise "your Active Directory forest can never be considered trustworthy again, unless you can recover it by using a known good backup" ([Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack), 9 Jul 2025).

### 4.3 How entrenched on-prem AD still is
- The ubiquitous **"~90% of the Global Fortune 1000 use AD"** traces to a **Frost & Sullivan** "Frost Perspectives" piece (20 Mar 2020) with **no methodology disclosed** ([Frost](https://www.frost.com/frost-perspectives/active-directory-holds-the-keys-to-your-kingdom-but-is-it-secure/)). Cite it with that caveat, or drop it from investor material.
- Microsoft is still investing in AD DS. **Windows Server 2025** brought a new domain/forest functional level (10), an optional 32k database page size, LDAP encryption by default and LDAP over TLS 1.3, no RC4 TGTs from the KDC, and delegated Managed Service Accounts ([Learn](https://learn.microsoft.com/en-us/windows-server/get-started/whats-new-windows-server-2025), dated 15 Jan 2026). NTLM was deprecated in Jun 2024, and NTLMv1 is removed in Windows 11 24H2 / Windows Server 2025 ([Learn](https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features)).
- No credible survey on organizations planning to **retire** AD was found `[TODO]`. Current Entra MAU and the share of tenants syncing from AD are not publicly stated `[UNVERIFIED]`.
- **Net (analysis):** on-prem AD is being *minimized*, not retired. The Kerberos/LDAP/GPO estate, service accounts and DCs persist, while object authoring migrates to Entra (§4.1). The durable product is **hybrid**: AD + Entra + M365 under one control plane.

### 4.4 ITDR and ISPM
- **Origin.** Gartner introduced "identity threat detection and response" (ITDR) in its top trends for 2022, on 7 Mar 2022 ([Gartner](https://www.gartner.com/en/newsroom/press-releases/2022-03-07-gartner-identifies-top-security-and-risk-management-trends-for-2022)). Gartner's 2026 top trends include "Identity and Access Management Adapts to AI Agents" (5 Feb 2026) ([Gartner](https://www.gartner.com/en/newsroom/press-releases/2026-02-05-gartner-identifies-the-top-cybersecurity-trends-for-2026)). Gartner's ISPM definition and 2025 Hype Cycle placement are paywalled `[TODO]`.
- **KuppingerCole Leadership Compass ITDR, 6 Nov 2025** ([KC](https://www.kuppingercole.com/research/lc81209/identity-threat-detection-and-response-itdr)):
  - Overall Leaders: **BeyondTrust, CrowdStrike, CyberArk, Delinea, Microsoft, Okta, Saviynt**.
  - **ManageEngine (AD360, PAM360, Log360) is rated a "Market Leader"**.
  - Silverfort is a Product/Innovation Leader; Segura is a Product/Market Leader; SentinelOne, Acalvio and Sharelock are Innovation Leaders.
  - Semperis, Quest, Netwrix and Cayosoft are rated vendors.
  - The prior edition (22 Apr 2024) had BeyondTrust, CrowdStrike, Delinea, Gurucul, Microsoft, Securonix and SentinelOne as Overall Leaders ([KC 2024](https://www.kuppingercole.com/research/lc80828/identity-threat-detection-and-response-itdr-iam-meets-the-soc)).
- **So what (analysis):**
  - ITDR leadership has shifted to **PAM and identity-platform vendors**, consistent with §4.8 platformization.
  - **ME already has analyst-recognized ITDR market presence.** activeDIQ cannot dismiss ITDR, but should differentiate on AD-specific depth (AD CS template abuse, DCSync/DCShadow, dMSA/BadSuccessor delegation paths, Tier-0 ACLs) plus auto-revert and recovery, which platform vendors cover thinly.

### 4.5 AI copilots and agents for IT / identity admins
| Vendor | What ships | Scope for AD/identity admins | Status · date | Pricing | Source |
|---|---|---|---|---|---|
| **ManageEngine ADManager Plus** | **"Zia – AI assistant"** to "perform AD management tasks and generate reports using simple natural language input"; **"Zia Insights"** in AD Explorer for "AI-powered group membership analysis, including anomaly detection" | On-prem AD management and reporting | GA in Build 8030 · **30 Oct 2025** | Included in product `[UNVERIFIED]` | [release notes](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ManageEngine ADManager Plus | ML **"Access Recommendations"** during provisioning and access certification | Provisioning / certification | Build 8000 · 26 Dec 2024 | — | same |
| ManageEngine AD360 | Markets "UBA-driven identity threat protection" | Auditing / ITDR-lite | Live (accessed 2026-10-02) | — | [AD360](https://www.manageengine.com/active-directory-360/) |
| ManageEngine ADSelfService Plus | No AI/ML features in release notes through Build 7001 (21 Aug 2026). Its innovation is in authentication: FIDO passkeys for MFA (Build 6403, 12 Feb 2024); **FIDO2 passkeys for machine logins** (Build 6517, 21 Jul 2025); smart-card/YubiKey for VPN and Windows logins (Build 6513, 3 Apr 2025) | SSPR/MFA | — | — | [release notes](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| **Microsoft Security Copilot (Entra)** | Conditional Access Optimization Agent (needs Entra ID P1); Identity Risk Management Agent (Preview); Ignite 2025 added "a dozen new agents" across Defender, Entra, Intune and Purview | Cloud identity only. No on-prem AD admin agent found | CA agent available; risk agent Preview · doc 21 Jan 2026 | **Included with M365 E5 and E7**. Rollout from **18 Nov 2025**: 400 SCUs/month per 1,000 paid users (cap 10,000); announced $6/SCU pay-as-you-go overage | [Entra agents](https://learn.microsoft.com/en-us/entra/security-copilot/entra-agents), [E5 inclusion](https://learn.microsoft.com/en-us/copilot/security/security-copilot-inclusion) |
| JumpCloud | **AI Assistant**: natural-language queries; actions (MFA reset, unlock, remote access); bulk operations via chat; human-in-the-loop approval; audit in Directory Insights | Cloud directory/devices | Stated GA (accessed 2026-10-02) | In platform | [page](https://jumpcloud.com/platform/jumpcloud-ai-assistant) |
| Lepide | **Lepide AI** (directory and data security analytics); "AI-led" Lepide Protect | AD/Entra auditing, permissions | 26 Feb 2025; 9 Jul 2025 | Quote | [news](https://www.lepide.com/news/) |
| Softerra Adaxes | None. AI absent from public roadmap | — | accessed 2026-10-02 | — | [roadmap](https://www.adaxes.com/info_roadmap.htm) |
| tenfold | None found on homepage or pricing page | — | accessed 2026-10-02 | — | [tenfold](https://www.tenfold-security.com/en/) |
| Specops | Unknown (site blocked automated fetch) `[TODO]` | | | | |
| Semperis | Lightning Platform markets "agentic and conventional attack prevention, detection, and response" with "generative assistance". Lightning Intelligence feeds custom **Security Copilot agents** via the Security Store | ITDR/posture across AD, Entra, Okta | Platform live; Copilot integration described as "field-ready" (blog 23 Jun 2026); GA `[UNVERIFIED]` | Quote | [Lightning](https://www.semperis.com/lightning/), [blog](https://www.semperis.com/blog/semperis-microsoft-sentinel-copilot-integration/) |
| Cayosoft | **Change controls for AI agent identities**: Guardian v7.2 monitors and rolls back Entra Agent ID objects. "Ask Otto" AI assistant heading on the Administrator page. AI patent *filing* (Jun 2025) | Admin + change control | v7.2 · 17 Mar 2026; Otto status `[UNVERIFIED]` | Quote | [PR](https://www.cayosoft.com/news/cayosoft-debuts-agentic-ai-identity-change-controls-and-new-incident-response-offering-at-rsa-2026/), [Administrator](https://www.cayosoft.com/products/administrator/) |
| Netwrix | **MCP servers** for Access Analyzer (free; 8 Apr 2025), Auditor, Privilege Secure and Threat Manager; AI remediation guidance in 1Secure (Apr 2025); **Neo AI assistant** (beta); AI-agent identity inventory in Entra (Aug 2026) | Audit, ITDR, data security | MCP GA 2025; Neo beta · 23 Jun 2026 | In product / 1Secure tiers | [PR](https://netwrix.com/en/resources/news/netwrix-introduces-agentic-ai-integration/), [1Secure](https://netwrix.com/en/products/1secure/) |
| Quest | Security Copilot plugin for Security Guardian (2024); gen-AI assistant and summaries in Identity Defense; AI assistant for AD migrations (May 2025); **Agentic AI Defense** auto-isolation (Sep 2026); **Secure Replay** AI-assisted clean forest restore (private preview, Sep 2026). One Identity: no Active Roles-specific AI found | ITDR, recovery, migration | Agentic AI Defense GA Sep 2026; Secure Replay preview | Quote | [blog](https://blog.quest.com/product-post/autonomous-identity-threat-response-with-quest/), [blog](https://blog.quest.com/product-post/the-disaster-recovery-trade-off-is-over-introducing-secure-replay/) |
| Okta | **Identity Threat Protection with Okta AI**: continuous session-risk scoring, automated session termination, Shared Signals Framework partners | Cloud IdP sessions. No on-prem AD admin | GA (date not shown) | Add-on `[UNVERIFIED]` | [ITP](https://www.okta.com/products/identity-threat-protection/) |

**Takeaways (analysis):**
- **Natural-language AD administration is already table stakes.** ME shipped it in ADManager Plus in Oct 2025, so "we have an AI assistant" will not differentiate activeDIQ.
- Microsoft's agents are cloud-scoped (Conditional Access, risk, governance) and now come at no extra cost with M365 E5/E7, within SCU allowances. Competing head-on with Microsoft on Entra-side AI is a losing fight.
- **AI agents as identities** is now a product category:
  - Microsoft Entra Agent ID launched at Ignite 2025.
  - Cayosoft added change control for Agent ID objects (Mar 2026).
  - Semperis Lightning reports "agent identity exposures".
  - Gartner lists "IAM adapts to AI agents" as a 2026 top trend (§4.4).
  - Vendor survey: 93% of 1,100 orgs use or plan AI agents for password resets and VPN tasks, but only 32% are "very confident" they could regain control if AI exposed admin credentials (Semperis/Censuswide, May 2026, high bias) ([PR](https://www.semperis.com/press-release/new-semperis-study-reveals-ais-effects-on-the-identity-attack-surface/)).
  - activeDIQ's own agents must be **governed identities** too: scoped, auditable, revocable.
- The open lane is **safe agentic execution against on-prem AD/Tier-0**. That means plan → diff preview → approval → execute → one-click rollback, with full audit, least-privilege service identities, and a self-hosted/private model option for Tier-0. JumpCloud's human-in-the-loop pattern is the reference UX.

### 4.6 Passwordless, passkeys, Zero Trust
| Signal | Source (bias) / date |
|---|---|
| "68% of organizations have deployed or are actively deploying passkeys for employee sign-ins"; 28% have achieved fully passwordless; an estimated 5 billion passkeys in use. Sapio survey of 1,400 decision-makers and 11,000 consumers | [FIDO Alliance](https://fidoalliance.org/fido-alliance-reports-accelerating-global-passkey-adoption-on-world-passkey-day-2026/) (advocacy body), 7 May 2026 |
| Passkey Index (consumer services): 93% of accounts eligible, 36% enrolled, 26% of sign-ins by passkey; 81% fewer login-related help-desk incidents | [FIDO Alliance](https://fidoalliance.org/fido-alliance-launches-passkey-index-revealing-significant-passkey-uptake-and-business-benefits/), 14 Oct 2025 |
| New Microsoft consumer accounts "passwordless by default"; passkey sign-in success 98% vs 32% for passwords | [Microsoft](https://www.microsoft.com/en-us/security/blog/2025/05/01/pushing-passkeys-forward-microsofts-latest-updates-for-simpler-safer-sign-ins/), 1 May 2025 |
| Entra: synced passkeys and passkey profiles GA Mar 2026; passkeys on Windows (preview) Mar 2026; registration campaigns GA May 2026 | [Entra what's new](https://learn.microsoft.com/en-us/entra/fundamentals/whats-new) |
| **ME ADSelfService Plus already supports FIDO passkeys for MFA (Feb 2024) and FIDO2 passkeys for machine logins (Jul 2025)** | [release notes](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| Zero Trust baselines: CISA ZTMM v2.0 (Apr 2023; Optimal identity = continuous validation with phishing-resistant MFA); NIST SP 800-207 (Aug 2020); OMB M-22-09 (centralized identity, phishing-resistant MFA, no forced rotation or special-character rules); NSA pillar guidance 2023–2024 plus implementation guidelines Jan 2026 | [CISA](https://www.cisa.gov/sites/default/files/2023-04/zero_trust_maturity_model_v2_508.pdf), [NIST](https://csrc.nist.gov/pubs/sp/800/207/final), [OMB](https://www.whitehouse.gov/wp-content/uploads/2022/01/M-22-09.pdf), [NSA](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Tag/197598/zero-trust/) |
| 63% of organizations have fully or partially implemented zero trust, typically covering "half or less" of the environment (n=303, Q4 2023) | Gartner, 22 Apr 2024 (via archived copy) |

**So what (analysis):**
- Passkeys are landing in **Entra and endpoints, not AD**. AD keeps passwords for Kerberos/NTLM, service accounts and legacy apps. Password hygiene (breached-password lists, NTLM/RC4 inventory, service-account rotation) stays sellable through the decade.
- **Enrollment and recovery are the weak link** in every passkey rollout; this is the help-desk vishing path in §4.2. Verified enrollment and reset flows are the SSPR product's future.
- ME already ships passkeys in ADSelfService Plus, so for activeDIQ **passkey support is parity, not differentiation**.

### 4.6a Gaps still open in this subsection
- Okta "State of Zero Trust" latest edition and its stats `[TODO]`.

### 4.7 Regulatory drivers (status as of 2026-10-02)
| Regulation | Status | AD / identity-relevant obligations | Source |
|---|---|---|---|
| **EU NIS2** | Transposition deadline 17 Oct 2024. On **8 Jul 2026** the Commission referred **Ireland, Spain, France and the Netherlands** to the CJEU for failing to notify transposition. | Implementing Reg. **(EU) 2024/2690** (17 Oct 2024), covering DNS, cloud, data-centre, MSP/MSSP, marketplace and trust-service providers. Annex points: access control incl. **MFA** (pt 11), **privileged access** (3.2.3(e)), **monitoring and logging** (3.2), **backup and redundancy** (4.2). | [EC NIS2](https://digital-strategy.ec.europa.eu/en/policies/nis2-directive), [EUR-Lex 2024/2690](https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj/eng) |
| **EU DORA** | Applies from 17 Jan 2025 (Reg. (EU) 2022/2554). | RTS **(EU) 2024/1774** (13 Mar 2024): **Art. 20** unique identity per staff member. **Art. 21** need-to-know; privileged access "need-to-use or ad-hoc"; **access-right review "at least every 6 months"** for systems supporting critical or important functions; strong authentication for remote and privileged access. **Art. 12** logging. **Art. 8(2)(b)(i)** backup/restore. | [EUR-Lex 2024/1774](https://eur-lex.europa.eu/eli/reg_del/2024/1774/oj/eng) |
| **US SEC cyber disclosure** | Adopted 26 Jul 2023. 8-K Item 1.05 due **4 business days** after the materiality determination; Reg S-K Item 106 annual disclosure of risk management and governance. In force since Dec 2023 (SRCs +180 days for 8-K). No 2025–2026 amendment found in this pass `[UNVERIFIED]`. | Forensic-grade AD change history to scope incidents quickly; board-level reporting. | [SEC 2023-139](https://www.sec.gov/newsroom/press-releases/2023-139) |
| **US CMMC** | Phase 1 (self-assessments) began **Nov 2025**. On **13 Jul 2026** DoD **halted Phase 2** (third-party C3PAO assessments due 10 Nov 2026), citing cost and assessor shortage; a CMMC Reform Task Force was given 60 days to report. DoD will keep enforcing **NIST SP 800-171 Rev 2** through self-assessments and select government-led assessments. | 800-171 Access Control (3.1) and Identification & Authentication (3.5) families: MFA, least privilege, audit (3.3). The demand driver is weaker than expected in 2026. | [DefenseScoop 13 Jul 2026](https://defensescoop.com/2026/07/13/dod-halts-cmmc-cybersecurity-requirements-phase-2/), [Wikipedia](https://en.wikipedia.org/wiki/Cybersecurity_Maturity_Model_Certification) |
| **PCI DSS v4.x** | Future-dated requirements mandatory since **31 Mar 2025**; v3.2.1 retired 31 Mar 2024. | From the standard's text (not re-fetched this pass) `[UNVERIFIED]`: 8.4.2 MFA for all CDE access; 8.3.6 12-character minimum passwords; 7.2.4 user-account reviews every 6 months; 8.6.x system/application account controls. | [PCI SSC blog](https://blog.pcisecuritystandards.org/now-is-the-time-for-organizations-to-adopt-the-future-dated-requirements-of-pci-dss-v4-x) |
| **India DPDP Act 2023** | Phased commencement: **13 Nov 2025** (Data Protection Board, core provisions), **13 Nov 2026** (s.6(9) and related), **13 May 2027** (remaining provisions). | DPDP Rules 2025 security safeguards (access control, logging, 1-year log retention) `[UNVERIFIED]`. | [Wikipedia (citing Gazette)](https://en.wikipedia.org/wiki/Digital_Personal_Data_Protection_Act,_2023) |
| **CERT-In Directions** | Dated **28 Apr 2022**, in force. | Report incidents **within 6 hours**; keep ICT system logs for a **rolling 180 days within Indian jurisdiction**. | [CERT-In PDF](https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf) |
| **RBI IT Governance Master Direction** | Dated 7 Nov 2023, effective **1 Apr 2024**. Covers SCBs, SFBs, payments banks, NBFCs (top/upper/middle layer), CICs and AIFIs. | Access "only where a valid business need exists"; **MFA for privileged users** of critical systems; audit trails sufficient for forensics. | [RBI](https://www.rbi.org.in/Scripts/BS_ViewMasDirections.aspx?id=12562) |
| **SEBI CSCRF** | Circular SEBI/HO/ITD-1/ITD_CSC_EXT/P/CIR/2024/113 dated **20 Aug 2024**, for SEBI-regulated entities. | IAM/PAM/log-retention specifics and the current deadline schedule were not extracted `[TODO]`. | [SEBI](https://www.sebi.gov.in/legal/circulars/aug-2024/cybersecurity-and-cyber-resilience-framework-cscrf-for-sebi-regulated-entities-res-_85964.html) |

**What RFPs will ask for as a result (analysis):**
1. **Six-monthly access recertification with exportable evidence** (DORA RTS Art. 21; PCI 7.2.4), including privileged AD groups.
2. **MFA in front of privileged AD operations**, including the management console itself (RBI, DORA, PCI 8.4.2, NIS2 Annex pt 11).
3. **Log retention and data locality controls**: 180 days in-country for India (CERT-In). This favours a self-hosted or in-region deployment.
4. **Fast incident scoping**: SEC 4-business-day disclosure clock and CERT-In 6-hour reporting both need searchable who/what/when AD change history.
5. **Tested recovery**: DORA backup/restore requirements and NIS2 Annex 4.2 call for documented, rehearsed AD forest-recovery evidence.

### 4.8 Consolidation and M&A (2023–2026)
| Announced | Acquirer → Target | Value | Status | Relevance | Source |
|---|---|---|---|---|---|
| 2021–2022 | Netwrix → Stealthbits, ANIXIS, NNT, PolicyPak, Usercube, MATESO, Imanami, Remediant | n/d | Closed | Source of today's rename map and number of separate consoles | §2.2 |
| Dec 2023 | Okta → Spera Security | ~$100–130M (reported) | Closed | Became Okta ISPM | [Wikipedia: Okta](https://en.wikipedia.org/wiki/Okta,_Inc.) |
| 1 Feb 2024 | Netwrix → CoSoSys | n/d | Closed | Endpoint DLP added to the Netwrix roll-up | [PR](https://netwrix.com/en/resources/news/netwrix-acquires-cososys/) |
| 7 Mar 2024 | Centana Growth Partners → Cayosoft (minority) | $22.5M | Closed | Funds the "instant forest recovery" challenger | [PR](https://markets.financialcontent.com/postgazette/article/gnwcq-2024-3-7-cayosoft-secures-225-million-to-make-instant-active-directory-recovery-an-industry-standard) |
| 20 May 2024 | CyberArk → Venafi | $1.54B | Closed Oct 2024 | Machine identity | [Wikipedia: CyberArk](https://en.wikipedia.org/wiki/CyberArk) |
| 20 Jun 2024 | J.P. Morgan and Hercules → Semperis (growth financing) | $125M | Closed | Pre-IPO-style financing | [PR](https://www.semperis.com/press-release/semperis-secures-growth-financing/) |
| 1 Aug 2024 | **Netwrix → PingCastle** | n/d | Closed | The most-used free AD assessment tool is now commercialized (licence tightening, §2.2) | [PR](https://netwrix.com/en/resources/news/netwrix-acquires-pingcastle/) |
| 7 Feb 2025 | Turn/River Capital → SolarWinds (incl. ARM) | ~$4.4B ($18.50/sh) | Closed 18 Apr 2025 | PE ownership of an AD-permissions tool | [Wikipedia: SolarWinds](https://en.wikipedia.org/wiki/SolarWinds) |
| Feb 2025 | CyberArk → Zilla Security | Up to $175M | Closed | IGA | [Wikipedia: CyberArk](https://en.wikipedia.org/wiki/CyberArk) |
| 21 Feb 2025 | Cayosoft → Petri IT Knowledgebase | n/d | Closed | Owns a top AD admin media channel (bias flag for its surveys) | [PR](https://www.cayosoft.com/news/cayosoft-acquires-the-petri-it-knowledgebase-strengthening-its-commitment-to-the-it-professional-community/) |
| 30 May 2025 / Aug 2025 | Clearlake-owned Quest: debt transactions ($350M new term loans; second exchange creating a "3.5-out" loan) | $350M (May) | Closed | Financial pressure on a major AD-tools vendor (S&P downgrade Mar 2025) | [PR](https://www.prnewswire.com/news-releases/quest-software-announces-new-350-million-capital-infusion-to-accelerate-ai-innovation-and-growth-302469848.html), [PE Wire](https://privateequitywire.co.uk/clearlakes-quest-software-unveils-second-debt-restructuring/) |
| 30 Jul 2025 | **Palo Alto Networks → CyberArk** | ~$25B | **Completed Feb 2026** | Identity security absorbed into a platform vendor | [Wikipedia: CyberArk](https://en.wikipedia.org/wiki/CyberArk) |
| Sep 2025 | Okta → Axiom Security | n/d | Closed | Folded into Okta Privileged Access | [Wikipedia: Okta](https://en.wikipedia.org/wiki/Okta,_Inc.) |
| 17 Sep 2025 | Cohesity × Semperis (partnership/OEM) | — | Live | "Cohesity Identity Resilience, powered by Semperis": backup incumbent resells AD forest recovery | [PR](https://www.semperis.com/press-release/cohesity-semperis-offering-unifies-data-identity-resilience/) |
| Jan 2026 | **CrowdStrike → SGNL** | ~$750M | Announced; close `[UNVERIFIED]` | Identity / authorization into XDR | [Wikipedia: CrowdStrike](https://en.wikipedia.org/wiki/CrowdStrike) |
| 4 Feb 2026 | **Semperis → MightyID** | n/d | Closed | Identity resilience extends to Okta and Ping (beyond Microsoft) | [PR](https://www.semperis.com/press-release/semperis-acquires-identity-resilience-provider-mightyid/) |
| 17 Jun 2026 | Quest → Anetac | n/d | Closed | Human, non-human and AI-agent identity observability (now "Identity Insights") | [PR](https://www.globenewswire.com/news-release/2026/06/17/3313367/0/en/clearlake-backed-quest-software-acquires-anetac-to-advance-identity-security-for-the-agentic-ai-era.html) |
| 24 Jun 2026 | **One Identity separates from Quest** (independent, HQ Cork) | n/d; new ownership undisclosed | In progress through 2026 | Active Roles and Password Manager move to an IGA/PAM-focused company | [ITPro](https://www.itpro.com/business/business-strategy/one-identity-spins-out-as-independent-company-relocates-global-hq-to-ireland) |
| ongoing | Backup vendors move into AD forest recovery | — | Live | **Commvault Cloud Backup & Recovery for Active Directory**: forest-recovery automation with auto-generated runbooks, granular object restore, Entra ID; list **$0.75 (Standard) / $1.25 (Enterprise) per enabled user/month** | [Commvault](https://www.commvault.com/platform/active-directory) |

All Wikipedia-sourced rows are secondary; confirm against primary press releases before using them in an RFP `[TODO]`.

**Patterns (analysis):**
- **Platformization.** Identity security is being folded into XDR and network-security platforms (PANW–CyberArk, CrowdStrike–SGNL). Identity detections increasingly land in the SOC platform, so a standalone AD tool should **feed** those platforms (Sentinel, Splunk, CrowdStrike, Defender) rather than try to beat them at detection.
- **PE roll-ups and carve-outs in AD tooling** bring renames, multiple consoles and pricing changes:
  - Netwrix: 11 acquisitions 2021–2024.
  - Quest under Clearlake: two 2025 debt transactions.
  - **One Identity separating from Quest** (announced 24 Jun 2026).
  - SolarWinds under Turn/River.
  - Each opens a **switching window**. Active Roles customers in particular face a vendor-transition question in 2026–27 (analysis).
- **Recovery is commoditizing.** Commvault lists AD forest recovery at $0.75–1.25 per enabled user/month, Cohesity resells Semperis, and Microsoft covers Entra-side backup natively (§2.10). Recovery is becoming a feature activeDIQ needs, not a product to build the company on.

### 4.9 On-prem vs SaaS for Tier-0 tooling
| Guidance / incident | Source / date |
|---|---|
| Microsoft enterprise access model: "Tier 0 expands to become the control plane", which is "based on centralized enterprise identity system(s)" | [Learn](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model), dated 6 May 2026 |
| "The Microsoft Entra Connect server must be treated as a Tier 0 component" (Control Plane asset) | [Learn](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-install-prerequisites), Jan 2026 |
| Protect virtualized DCs from "fabric administrators (including virtualization, network, storage and backup administrators)" | [Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack), 9 Jul 2025 |
| "When hosting Tier-0 services like Active Directory…, the underlying virtualization environment must be hardened as a Tier-0 asset" | Mandiant M-Trends 2026, 24 Mar 2026 |
| Supply-chain/SaaS trust shocks: SolarWinds (forged SAML, new federation trusts; CISA AA20-352A, Dec 2020). Okta support-system breach (files for "134 Okta customers", 3 Nov 2023). Microsoft Midnight Blizzard (password spray on a legacy test tenant; 8-K 19 Jan 2024). Storm-0558 (CSRB: "Microsoft's security culture was inadequate", 20 Mar 2024) | [CISA](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a), [Okta](https://sec.okta.com/articles/2023/11/unauthorized-access-oktas-support-case-management-system-root-cause), [MSFT 8-K](https://www.sec.gov/Archives/edgar/data/789019/000119312524011295/d708866d8k.htm) |
| **ManageEngine AD-adjacent CVEs listed in CISA's Known Exploited Vulnerabilities (KEV) catalog.** **CVE-2021-40539**: CVSS 3.1 **9.8**; "ADSelfService Plus version 6113 and prior… REST API authentication bypass with resultant remote code execution"; NVD published 7 Sep 2021; fix build per ME advisory `[UNVERIFIED]`; CISA reports exploitation "as early as August 2021", including exfiltration of the "Active Directory database (NTDS.dit)"; added to KEV 3 Nov 2021. **CVE-2022-47966**: CVSS 3.1 **9.8**; RCE via Apache Santuario xmlsec 1.4.1 in multiple on-prem products, exploitable "only… if SAML SSO has ever been configured"; affected AD360 before 4310, ADAudit Plus before 7081, ADManager Plus before 7162 (so fixed in those builds); NVD published 18 Jan 2023; added to KEV 23 Jan 2023. Full history in sibling file `manageengine-ad-customer-voice-and-security.md` | [NVD API 40539](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-40539), [NVD API 47966](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-47966), [CISA AA21-259A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-259a), [CISA AA23-250A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-250a) |
| Survey data on on-prem vs SaaS preference for Tier-0 / identity tools in regulated sectors | **None found** `[TODO]` |

**Observed vendor delivery models (2026):** Semperis is mixed (customer-hosted DSP/ADFR, SaaS DRET/Ready1/Lightning Intelligence). Cayosoft is self-hosted, with Guardian SaaS announced but GA unconfirmed. tenfold is **on-prem only**. Adaxes is self-hosted. Microsoft MDI uses on-prem sensors with cloud analytics. Okta and JumpCloud are SaaS (§2).

**So what (analysis):**
- By Microsoft's own definition, any tool with **write access to AD is Tier 0 / control plane**. For that write path, buyers in regulated sectors (and India, given CERT-In log-locality) will favour a **self-hosted control plane**.
- Optional cloud services fit the **read-only** side: analytics, posture benchmarking, AI inference with redaction.
- **Recommended architecture stance:** self-hosted core with no inbound internet exposure, an outbound-only optional cloud, signed updates, and a published threat model.
- ME's exploited CVEs are citable facts. Present them **factually** (CISA links) and avoid comparative "we're more secure" claims in RFPs.

## 5. Market sizing

**All figures are third-party estimates or analyst arithmetic. None is a measured market.** Research-firm scopes differ and often overlap. Gartner's IAM spending forecast was not retrievable (HTTP 403) `[TODO]`. No credible AD-management-specific sizing was retrievable: report-mill pages failed or were unreachable `[TODO]`.

### 5.1 Published segment estimates
| Segment | Publisher (credibility) | Value | Forecast | CAGR | Published | Source |
|---|---|---|---|---|---|---|
| IAM (global) | MarketsandMarkets (mid) | **$23.37B (2024)**; $25.96B (2025) | $42.61B (2030) | 10.4% (2025–30) | Nov 2025 (TC 3138) | [M&M IAM](https://www.marketsandmarkets.com/Market-Reports/identity-access-management-iam-market-1168.html) |
| IAM (US) | MarketsandMarkets (mid) | $7.34B (2025) | $11.09B (2030) | 8.6% | 2026 | [M&M search listing](https://www.marketsandmarkets.com/search.asp?search=identity%20governance) |
| IAM (APAC) | MarketsandMarkets (mid) | $5.29B (2025) | $9.55B (2030) | 12.5% | 2026 | same |
| ITDR (global) | MarketsandMarkets (low for this use) | $12.8B (2024) | $35.6B (2029) | 22.6% | May 2024 (TC 9016) | [M&M ITDR](https://www.marketsandmarkets.com/Market-Reports/identity-threat-detection-and-response-itdr-market-259116012.html) |
| MFA (global) | MarketsandMarkets (low for this use) | — | $34.8B (2028) | 18.0% | Oct 2023 | [M&M search listing](https://www.marketsandmarkets.com/search.asp?search=multi-factor%20authentication) |
| Passwordless auth | MarketsandMarkets (low) | — | $21.2B (2027) | 26.2% | Nov 2022 | same |

**Credibility note.** The same publisher sizes ITDR (2024) at **55% of all IAM** (2024), and MFA alone above total IAM. These numbers are not mutually consistent. Do **not** use the ITDR, MFA or passwordless figures in investor or RFP material. Use IAM totals only as context.

### 5.2 Price anchors for bottom-up math (public list prices, accessed 2026-10-02)
| Offering | List price | Annualized per user | Source |
|---|---|---|---|
| Adaxes (S1/S3) | $1,600 perpetual / 100 users → $10,800 / 2,000 users; ~30% annual maintenance | ~$1.6–4.8/user/yr maintenance after year 1 (analyst arithmetic) | [Adaxes](https://www.adaxes.com/purchase.htm) |
| tenfold (S1, IGA-lite) | $0.90–$1.25 / identity / month | $10.80–$15.00 | [tenfold](https://www.tenfold-security.com/en/tenfold-pricing/) |
| Commvault AD recovery (S4) | $0.75–$1.25 / enabled user / month | $9–$15 | [Commvault](https://www.commvault.com/platform/active-directory) |
| Entra ID P1 / P2 / ID Governance | $7 / $10 / +$7 per user / month | $84 / $120 / +$84 | [Microsoft](https://www.microsoft.com/en-us/security/business/microsoft-entra-pricing) |
| Microsoft Defender Suite (incl. MDI) | $12 / user / month | $144 | [Microsoft](https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-for-identity) |
| Okta Workforce | $6–$17 / user / month; $1,500 minimum | $72–$204 | [Okta](https://www.okta.com/pricing/) |
| JumpCloud | $9–$13 / user / month (annual) | $108–$156 | [JumpCloud](https://jumpcloud.com/pricing) |

### 5.3 Vendor revenue signals
| Vendor | Metric | Value | Period | Type | Source |
|---|---|---|---|---|---|
| Okta | Revenue | $2.92B | FY2026 (to 31 Jan 2026) | Filing via secondary | [Wikipedia](https://en.wikipedia.org/wiki/Okta,_Inc.) |
| Semperis | ARR | "surpassed $100M" | Jan 2025 | Vendor claim | [PR](https://www.semperis.com/press-release/100m-arr/) |
| Semperis | Customers | "1,200+" | Apr–Sep 2026 | Vendor claim | [PR](https://www.semperis.com/press-release/semperis-takes-center-stage-at-black-hat-usa/) |
| Cayosoft | ARR growth | "76% YoY" (no absolute figure) | FY2025 | Vendor claim | [PR](https://markets.financialcontent.com/postgazette/article/gnwcq-2026-2-19-cayosoft-captures-record-market-momentum-in-2025-amid-rising-demand-for-operational-resilience-and-modernization) |
| Netwrix | Customers | "more than 13,000 … nearly 25% of the Fortune 500"; ARR grew "23x" through acquisitions under prior CEO (no absolute) | 2024–2026 | Vendor claim | [PR](https://netwrix.com/en/resources/news/netwrix-announces-ceo-transition/) |
| Quest | Customer-count boilerplate | "130,000+" (May 2025) → "more than 28,000" (Sep 2026), unexplained | 2025–2026 | Vendor claim | [PR Sep 2026](https://www.prnewswire.com/news-releases/quest-software-takes-aim-at-rogue-ai-agents-as-identity-security-threats-drive-90-of-cyber-incidents-302879876.html) |
| Quest (all products) | Median annual contract | ~$14.3K/yr (36 purchases) | Data as of Feb 2026 | Third-party estimate (Vendr) | [Vendr](https://www.vendr.com/marketplace/quest-software) |

### 5.4 Install-base proxies
| Proxy | Value | Source |
|---|---|---|
| Organizations using Entra ID | "more than 720,000" (includes cloud-only orgs) | [Microsoft](https://www.microsoft.com/en-us/security/business/identity-access/microsoft-entra-id), accessed Oct 2026 |
| Paid M365 commercial seats | +6% YoY (absolute not disclosed) | [MSFT FY26 Q4](https://www.microsoft.com/en-us/investor/events/fy-2026/earnings-fy-2026-q4), 29 Jul 2026 |
| Large enterprises on AD | "approximately 90% of the Global Fortune 1000" (no methodology; 2020) | [Frost & Sullivan](https://www.frost.com/frost-perspectives/active-directory-holds-the-keys-to-your-kingdom-but-is-it-secure/) |
| Hybrid share of tenants; Entra MAU; count of enterprises ≥1,000 employees running AD | Not found | `[TODO]` |

### 5.5 Triangulated estimate (ANALYST ESTIMATE, low confidence)
**A. Top-down share of IAM.** IAM 2025 ≈ $25.96B (M&M). Assume AD-centric third-party tooling (S1–S5 in §1, excluding Microsoft licences, IdP/SSO, PAM and full IGA) is **3–6%** of IAM spend. That gives **≈ $0.8–1.6B (2025)**. The 3–6% share is an assumption, not a sourced figure.

**B. Vendor anchor check.** Semperis alone claims >$100M ARR across ~1,000–1,200 customers (§2.3), roughly **$100K ARR per customer** for S4/S5 at large enterprises. Ten-odd specialists sell into this niche (ME AD line, Quest/One Identity, Netwrix, Semperis, Cayosoft, Specops, Lepide, Adaxes, tenfold, SolarWinds ARM), most with undisclosed AD revenue. If they average **$50–150M** of AD-relevant revenue, that is **≈ $0.5–1.5B**, consistent with A. Netwrix and Quest figures to be added `[TODO]`.

**C. Per-enterprise ARPU anchors (10,000 users, public list prices).**

| Segment | Basis | Annual cost |
|---|---|---|
| IGA-lite (S1) | tenfold Essentials 365 | ≈ $150K/yr |
| AD recovery (S4) | Commvault | ≈ $90–150K/yr |
| ITDR/resilience (S4/S5) | Semperis-type, average | ≈ $100K ARR |

A full S1–S5 stack at specialist list prices is therefore **≈ $150–400K/yr, or $15–40 per user per year**. ME pricing is far lower per user (see the sibling commercials file), which is the price floor in §7.2.

Bottom-up TAM = (# AD-using enterprises by size band) × ARPU. The enterprise counts are `[TODO]` (US Census SUSB / Eurostat / India MCA data).

**Working view:** the AD-centric tooling market is **~$1–2B per year globally (2025–26)**. It grows at roughly the IAM rate (M&M: 10.4% CAGR) overall, with S4/S5 (resilience and ITDR) growing faster than S1–S3 (operations), consistent with the §4 trends. **SAM** for activeDIQ = ME AD-product customers in launch geographies; ME customer counts are in the sibling files. **SOM** = the CEO's warm accounts × users × target ARPU, to be built from the account list `[TODO]`.

## 6. Buyer personas & buying criteria

Analysis. Primary research (interviews with the CEO's warm accounts) is `[TODO]`; validate these hypotheses there first.

| Persona | Owns / feels pain on | Top buying criteria | How they evaluate | What ME wins on today | Where activeDIQ can win |
|---|---|---|---|---|---|
| **AD / systems admin** (daily user) | JML tickets, bulk changes, group sprawl, stale objects, GPO drift, hybrid sync issues | Speed of common tasks; bulk CSV/templates; PowerShell/API escape hatch; Entra + Exchange Online in one place; safe undo | Hands-on trial: replicate 10 routine tasks; count clicks and time; test bulk import, scheduled reports, delegation scoping | Breadth of canned reports and actions; familiar; cheap per domain/technician (see sibling ME pricing file) | Modern, fast, keyboard-friendly UI; one console for AD, Entra and M365; diff preview and one-click rollback; safe NL/agentic actions (§4.5); SOA-aware hybrid management |
| **Help-desk lead** | Password-reset volume, lockouts, MFA enrolment, social-engineering risk | Ticket deflection (SSPR adoption), caller verification, scoped delegation for tier-1, simple audit | Pilot with one site: reset/unlock volume before vs after; enrolment rate; tier-1 usability | ADSelfService Plus maturity: enrolment, login-screen reset, broad MFA options incl. FIDO2 passkeys for machine logins since Jul 2025 ([release notes](https://www.manageengine.com/products/self-service-password/release-notes.html)) | Built-in help-desk identity verification (the Specops Secure Service Desk pattern); push MFA approval for resets; no separate product to deploy |
| **Security / SOC / identity security** | AD as attack path; Tier-0 exposure; ransomware recovery; detections | Tier-0 hygiene and attack paths; real-time detection of AD attacks; automated rollback of malicious changes; recovery RTO; SIEM/XDR integration; the tool's own security posture | Run PingCastle / Purple Knight / BloodHound and compare findings; red-team the POC; review vendor CVE history and architecture (service accounts, agents on DCs, internet exposure) | Bundle price; UBA-based "identity threat protection" included in AD360 | Hardened-by-design Tier-0 tool (no internet-exposed portal by default, MFA on console, signed updates, least privilege); posture plus auto-undo plus forest recovery in one place; Sentinel/Splunk/Defender export |
| **Compliance / internal audit / GRC** | Evidence for SOX, PCI, DORA, NIS2, RBI/SEBI, CERT-In | Six-monthly access reviews with evidence (DORA RTS Art. 21; PCI 7.2.4); privileged-group change history; retention and locality (CERT-In 180 days in India); tamper-evident logs | Sample audit request ("show every change to Domain Admins in Q2, approver and evidence"); report export formats; retention settings | Large library of pre-built compliance reports | Evidence packs mapped to control IDs (DORA/PCI/NIS2/RBI); immutable audit store; reviewer UX that non-IT managers will actually complete |
| **IT manager / CIO / CISO** (economic buyer) | Cost, vendor risk, consolidation, cyber-insurance and regulator pressure, Entra roadmap | TCO vs ME; one vendor/one console; migration risk; vendor viability; roadmap alignment with Entra (SOA, Agent ID); support quality | Reference calls; 3-year TCO model; security questionnaire; analyst presence (Gartner/KuppingerCole) | Low licence price and an incumbent footprint across AD360 and ME's wider IT stack | Migration program (ME config import, parallel run); price parity at bundle level with a sharper ROI story (help-desk deflection, audit hours saved, recovery RTO); a young vendor offset by CEO relationships and escrow/self-host option |

**ROI anchor for the help-desk persona.** Microsoft's account-recovery cost estimator assumes **$60 per help-desk recovery** ("industry average", no source given) and 60 minutes of lost productivity, versus **$2 and 5 minutes** for self-service (doc dated 2 Apr 2026) ([Learn](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-account-recovery-cost-savings-estimator)). Use it as a defaults-only anchor and replace it with each customer's own ticket data.

**Cross-persona evaluation tests activeDIQ should script and win in every POC (analysis):**
1. 20-user bulk onboarding across AD, Entra and M365 with approval, in under 5 minutes end to end.
2. Malicious change to a Tier-0 group detected, alerted and **auto-reverted**, with the evidence trail.
3. Help-desk password reset with **verified caller identity**, completed by a tier-1 agent who has no AD rights.
4. Auditor request ("all privileged-group changes last quarter, with approvers") answered in under 1 minute.
5. Object-level restore plus a documented **forest-recovery rehearsal** plan.

## 7. Whitespace for activeDIQ

Analysis. It builds on §2–§6; ME-specific facts live in the sibling `manageengine-*.md` files.

### 7.1 Where activeDIQ can win against ManageEngine
| # | Wedge | Evidence / rationale | Priority for warm ME accounts |
|---|---|---|---|
| 1 | **One product, one data model, one console** across admin, audit and self-service (S1–S3), with recovery and posture (S4–S5) inside the same object timeline | ME delivers these as separately installed products (ADManager Plus, ADAudit Plus, ADSelfService Plus, RecoveryManager Plus, M365 Manager Plus) unified by AD360. ADManager Plus is licensed per domain plus technicians ([get-quote](https://www.manageengine.com/products/ad-manager/get-quote.html)). Only Quest/One Identity and Netwrix (both delivered as many separately installed products, §2.1–2.2) and Cayosoft (no documented SSPR, §2.4) come close on breadth. | **P0** |
| 2 | **Measurably faster, modern UX** on the top-20 admin and help-desk tasks | The CEO's thesis. Prove it with timed POC scripts (§6). Adaxes still lists a web-based admin console as a roadmap item ([roadmap](https://www.adaxes.com/info_roadmap.htm)), so UI modernity is not solved in this category. | **P0** |
| 3 | **Guard-railed agentic AI for on-prem AD**: plan → diff preview → approval → execute → one-click rollback, on a self-hostable model | ME already ships NL tasks and reports (Zia, Oct 2025), so parity is assumed. Microsoft's agents cover cloud identity only (§4.5). Nobody found ships rollback-native agentic changes for AD. Netwrix's MCP servers (2025) point to a second pattern: expose activeDIQ data and actions to customers' own agents via MCP, behind the same approval guardrails. | **P0** (differentiator) |
| 4 | **Change → revert in one click** (object and attribute rollback inside the audit view) | Semperis and Cayosoft sell this as a premium. ME splits auditing (ADAudit Plus) from restore (RecoveryManager Plus). | P1 |
| 5 | **Secure-by-design Tier-0 tooling**: no internet-exposed admin plane by default, MFA on the console, least-privilege service identities, signed updates, SBOM, public security whitepaper | Security buyers vet a tool that has write access to Tier 0. ME's exploited-CVE history is documented in the sibling `manageengine-ad-customer-voice-and-security.md`. SolarWinds ARM shows the same risk (CVE-2024-28991, §2.7). | P0 for SOC/CISO persona |
| 6 | **Hybrid, SOA-aware management** that shows who authors each object (AD vs Entra) and plans "AD DS minimization" safely | Group SOA has been GA since Oct 2025 and user SOA since Jan 2026. Connect Sync must be upgraded by **7 Apr 2027**, and Microsoft is steering customers to Cloud Sync (§4.1). This positions activeDIQ as the bridge to Entra rather than a legacy tool. A "hybrid health check" ahead of the 2027 deadline is a timely door-opener. | P1 (narrative and health check now; full SOA-aware management on roadmap) |
| 7 | **Help-desk identity verification** built into reset/unlock flows | Help-desk vishing is now a top vector: voice phishing is Mandiant's #2 initial vector at 11% in 2025, and CISA AA23-320A was updated Jul 2025. M&S guided c.£300m of impact (§4.2). Specops sells verification as a separate SKU (§2.8). | **P0** for SSPR displacement |
| 7b | **Delegation and Tier-0 ACL hygiene** (who can write what, including dMSA/BadSuccessor-style paths) | Akamai found non-admins with the required rights in **91%** of examined environments (§4.2). Semperis sells Delegation Manager separately (§2.3). This is a natural extension of help-desk delegation. For ME's coverage of AD ACL/permission risk, see the sibling files `[verify]`. | P1 |
| 8 | **Regulator-mapped evidence packs**: DORA RTS Art. 21 six-monthly reviews, PCI 7.2.4, NIS2 Annex, RBI MFA for privileged users, CERT-In 180-day in-country logs | §4.7. A self-hosted or in-region deployment is a feature for Indian BFSI (RBI/SEBI/CERT-In). | P1 (India BFSI P0) |
| 9 | **Free posture scan as door-opener** (the PingCastle / Purple Knight model) aimed at ME estates | Free assessment tools are the category's proven lead-gen motion (§2.13). Netwrix's tightening of PingCastle licensing (Enterprise-only features, build expiry, "free for personal use" wording; §2.2) leaves room for a genuinely free, modern scanner. Turns the CEO's warm intros into quantified risk findings. | P1 |
| 10 | **ME migration kit**: import delegation roles, templates, workflows, report schedules and SSPR enrolment; run in parallel with ME | The switching cost is configuration, not data. Removing it is the single biggest lever for warm accounts. | **P0** |

### 7.2 Where not to fight
| Don't fight on | Why | Instead |
|---|---|---|
| **List price per seat or per domain** | The floor is very low: ME domain/technician licensing; Adaxes **$1,600 perpetual for 100 users** ([purchase](https://www.adaxes.com/purchase.htm)); tenfold **$0.90/identity/month** ([pricing](https://www.tenfold-security.com/en/tenfold-pricing/)); Commvault AD recovery **$0.75/enabled user/month** ([Commvault](https://www.commvault.com/platform/active-directory)); Microsoft bundles MDI in the Defender Suite and Security Copilot in E5/E7 (§2.10, §4.5). | Match ME bundle cost for warm accounts (switching credit or co-term), then win on TCO: help-desk deflection, audit hours saved, recovery RTO. |
| **Detection breadth (SIEM/XDR/ITDR analytics)** | MDI, CrowdStrike and Palo Alto (CyberArk) own the SOC, and KuppingerCole's 2025 ITDR Overall Leaders are platform/PAM vendors (§4.4). Platformization is accelerating (§4.8). Note that **ME is a KC ITDR "Market Leader"**, so ITDR cannot be skipped entirely. | Ship AD-specific, high-fidelity detections (AD CS abuse, DCSync/DCShadow, dMSA/BadSuccessor delegation paths, Tier-0 ACL drift) plus auto-revert, and stream everything to Sentinel, Defender, Splunk and CrowdStrike. |
| **Full IGA** | SailPoint, Saviynt, One Identity Manager and Entra ID Governance own cross-app SoD and role mining. | Stay IGA-lite (AD/Entra/M365 recertification and JML) with SCIM/API hand-offs. |
| **Backup storage and immutability** | Backup incumbents own storage, immutability and clean rooms (Commvault, Cohesity). | Own AD-aware orchestration and object-level UX; integrate with their storage. |
| **Being an IdP / SSO** | Okta ($6–$17/user/month) and Entra own SSO and passkeys. | Integrate MFA providers and passkeys; don't build an IdP. |

### 7.3 Competitor strengths worth borrowing
| From | Borrow | Why it matters |
|---|---|---|
| Semperis | **Point-in-time auto-undo** of Tier-0 changes; staged "Minimum Viable Company" forest recovery; free **Purple Knight** and **Forest Druid** as lead-gen; a threat-research brand (named CVE research) | Converts AD tooling from an ops cost into a security and resilience budget line, where budgets are larger. |
| Cayosoft | **Rollback across AD, Entra, Intune, Teams and Exchange Online**; free-forever **Guardian Protector** tier; "no per-admin/server fees" licensing; the **Replace-ManageEngine** program as a sales motion (study it, don't copy it) | Proves demand for a single ME replacement. Their free tier and rollback breadth set the bar activeDIQ must meet. |
| Quest / One Identity | Active Roles' **policy-based delegation and approval workflows**; GPOADmin's **GPO check-out/approval and protected Tier-0 GPOs**; DRE's **standby-forest provisioning** and **managed recovery** with DR drills; Change Auditor's **change blocking**; FedRAMP High SaaS | Enterprise-grade governance of AD changes is what large ME accounts will ask for next. GPO change control is a gap as Microsoft AGPM reaches end of life (per Quest, Apr 2026). Managed recovery is a services revenue line. |
| Netwrix | **Real-time blocking** of Tier-0 changes at source (Threat Prevention); MCP servers exposing product data to customer AI agents; **public self-service SaaS pricing** ($24–$39/identity/yr) and an MSP channel (Pax8) | Prevention beats detection for Tier 0. MCP is a cheap way to be "AI-native" for customers' own agents. Self-service pricing serves the low end without sales cost. |
| Softerra Adaxes | Rules engine and PowerShell extensibility; **public price list**; frequent dated releases | Power users want escape hatches; transparent pricing shortens procurement. |
| Specops | Breached-password protection and help-desk caller verification | Directly addresses the two most common identity initial-access paths (credentials and help-desk social engineering). |
| tenfold | No-code IGA, **free Community Edition up to 150 users**, published per-identity pricing | Bottom-up adoption and trust. |
| JumpCloud | Human-in-the-loop AI actions with audit trail | The right trust pattern for agentic admin. |
| Microsoft | **Security Store** in the Entra admin center lists Microsoft and partner-built agents. SCU costs for partner agents are currently included for E5/E7 customers "until further notice" ([E5 inclusion FAQ](https://learn.microsoft.com/en-us/copilot/security/security-copilot-inclusion); [Entra agents](https://learn.microsoft.com/en-us/entra/security-copilot/entra-agents)) | A potential distribution channel for an activeDIQ Entra-side agent `[validate partner requirements — TODO]`. |
| BloodHound CE | Tier-0 attack-path graph with zones and prioritization | Security buyers expect it; it reframes AD admin as security. |

## 8. Method, source quality and open gaps

- **Method.** Primary vendor pages, docs, release notes, pricing pages and press releases, plus regulator and government pages, all accessed 2026-10-02. Secondary sources (Wikipedia, trade press) are labelled as such. The session's web-search budget ran out early, so research continued by fetching known primary URLs directly. That is why some items remain `[UNVERIFIED]`/`[TODO]`.
- **Vendor-sponsored statistics** are flagged inline: Semperis, Cayosoft/Petri, Lepide, Sophos, Microsoft and CrowdStrike telemetry, the FIDO Alliance, and the Forrester TEI commissioned by Semperis.
- **Blocked or unreachable sources:**
  - HTTP 403: specopssoft.com, outpost24.com, Gartner newsroom, Grand View Research, rubrik.com, dodcio.defense.gov, meity.gov.in, the Microsoft Marketplace web pages (Netwrix prices were retrieved via the Azure catalog API instead).
  - federalregister.gov redirected to a block page; GSA Advantage could not be reached.
- **Some primary pages were read via Internet Archive copies** because the live pages blocked access: Gartner press releases, NSA, and the CSRB report (per research notes).
- **Biggest open gaps:**
  1. **Specops** profile is entirely from prior knowledge (site blocked): ownership, products, pricing `[UNVERIFIED]`.
  2. **Pricing** for Semperis, Cayosoft, Lepide and SolarWinds ARM is not public. Marketplace/GSA listings could not be reached `[TODO]`.
  3. **AD-specific market sizing.** No credible third-party figure. The §5.5 estimate rests on an assumed 3–6% share of IAM. Enterprise counts for a bottom-up model are missing `[TODO]`.
  4. **Gartner** ISPM definition, Hype Cycle placement and IAM spending forecast are paywalled or blocked `[TODO]`.
  5. **No neutral data** on AD forest-recovery time, AD retirement plans, or on-prem vs SaaS preference for Tier-0 tools `[TODO]`. Run a short survey of the CEO's warm accounts.
  6. **Secondary-sourced M&A rows** (Wikipedia) need primary confirmation before RFP use: PANW–CyberArk close date, CrowdStrike–SGNL, Okta–Axiom.
  7. **SEBI CSCRF** control specifics and current deadlines; DPDP Rules security-safeguard text `[TODO]`.

## Changelog
- **2026-10-02:** v0.1 draft (market-analyst). All sections researched and sources checked on 2026-10-02; `sources_last_checked` reflects §1–§8.
  - Competitor facts for Quest/One Identity come from Internet Archive snapshots (vendor sites block automated fetches) and the live Azure Marketplace catalog.
  - Specops is unverified (site blocked).
  - The comparative-claim pass followed `competitive-intel` §4: neutral wording, absence phrased as "not documented", and CVE rows with ID, CVSS, affected and fixed builds where available.
