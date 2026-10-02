---
title: "ManageEngine AD360 Suite, Adjacent Products & Commercial Model"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: heramb
sources_last_checked: 2026-10-02
---

# ManageEngine AD360 Suite, Adjacent Products & Commercial Model

> **Scope.** AD360 (the suite shell), RecoveryManager Plus, M365 Manager Plus, Exchange Reporter Plus, adjacent products, ManageEngine as a company, its commercial model, 2025–2026 roadmap signals, and what all of this means for activeDIQ. The ADManager Plus (ADMP), ADAudit Plus (ADAP) and ADSelfService Plus (ADSSP) feature inventories are in sibling files (`manageengine-admanager-plus.md`, `manageengine-adaudit-plus.md`, `manageengine-adselfservice-plus.md`). This file covers those three products only as AD360 components and for pricing.
>
> **Conventions.**
> - All prices are **USD list** as published on 2026-10-02.
> - Store prices come from the public JSON endpoint that store.manageengine.com pages render on the client (`https://store.manageengine.com/api/public/json/productdetails/<id>.js`). The store script labels these prices "US$" (https://store.manageengine.com/js/indc-store-subscription-admp.js). UK buyers are redirected to a UK sales page, and SE/IS/JP/CN buyers to local contact pages (https://store.manageengine.com/js/check-country.js), so regional prices may differ.
> - Tags: `[UNVERIFIED]` means not confirmed. `[TODO]` means not researched. **Estimate** marks derived numbers, and their arithmetic is shown.
> - Absence of evidence is never stated as absence of a feature.

---

## Executive summary: the decision-relevant findings

1. **AD360 is an integration shell, not a unified product.**
   - The shell has its own installer, its own Tomcat web server (8082/8445) and its own PostgreSQL DB (port 33305).
   - It registers **seven separately installed, separately versioned products**, each with its own database and port, by host:port.
   - It then adds SSO, settings sync over REST, and report aggregation from three of them.
   - Full-suite sizing guidance adds up to **98 GB RAM (108 GB on VMs)**, with "no more than two components on a single machine".
   - The shell shipped **one build in 2026** (4504, 2026-01-30).
   - The inter-product SSO had a **ticket-prediction account-takeover bug (CVE-2026-11374, fixed June 2026)**. (§1.3)
2. **There is no bundle discount at list.** AD360 component SKUs cost exactly what the standalone SKUs cost. The shell itself is free ("integrate them with AD360 at no extra cost"), and pricing "starts @ $595". (§1.4)
3. **List prices are very low.**
   - **Estimate:** ADMP + ADAP + ADSSP at list runs **$5.0k–$8.8k/yr for 1,000 users** ($0.42–$0.73 per user per month), **$12.8k–$20.1k for 5,000**, and **$22.8k–$51.7k for 20,000** (Standard to Professional; arithmetic in §6.3).
   - activeDIQ cannot win on licence price alone. It has to win on all-in TCO, consolidation, and UX. (§6, §8)
4. **Perpetual pricing follows a fixed formula.** A perpetual licence is **2.5× the annual subscription**, and **AMS (annual maintenance and support) is 20% of the licence per year, with year-1 AMS mandatory**. That makes the two options break even at **year 5**. ADSSP and AD360 are sold subscription-only in the store. Core ADAP DC prices have been **flat since at least Jan 2021** (Wayback). (§6.4–6.5)
5. **Licensing is meter-heavy and full of surprise points.**
   - ADAP alone has 6+ meters: DCs, member servers, Windows file servers, NAS counted in vendor-specific units, workstations, Entra tenants, TB, and users.
   - ADMP counts every child domain plus named technicians.
   - ADSSP consumes a licence on a user's first action. Above the licence count, **endpoint MFA is silently skipped** for the extra users. (§6.6)
6. **The same capability is sold in several SKUs.** AD object rollback alone exists in RMP, ADMP (add-on and "Advanced Recovery"), ADAP (add-on and "Advanced Recovery"), Log360 and an AD360 backup add-on. M365 auditing is in M365MP, M365 Security Plus, ADAP and Log360. (§4.7)
7. **Where ManageEngine is heading:**
   - It is consolidating in **Log360 first**. "Unified Log360" has had a migration path since June 2026.
   - It is building **Identity360 (SaaS)** as the cloud successor. Its roadmap lists GPO management, domain migration and AD auditing, all undated.
   - Identity360 was **repriced 2.6–4.5× in Aug 2026**.
   - On AI: the ADMP Zia assistant needs the customer's own Azure OpenAI key. Agentic AI shipped in Log360. No AD or Identity360 MCP server is listed. (§1.5, §7)
8. **Analyst standing in identity is "presence", not "product leadership".**
   - KuppingerCole rates ManageEngine **Market Leader** (a market-presence axis) in IGA 2026, ITDR 2025 and PAM 2026, but not Product or Innovation Leader.
   - Gartner lists it as an IGA Market Guide Representative Vendor. PAM360 is a Gartner PAM MQ Challenger (2023–2025). Log360 is a Gartner SIEM MQ **Niche Player** (2025). (§5.3)

---

## 1. AD360

### 1.1 What it is

- **Marketing:** a "unified identity and access management (IAM) solution" and "One Converged Identity Platform" (https://www.manageengine.com/active-directory-360/). ME's IAM portfolio page tags AD360 as **"On-premises"** (https://www.manageengine.com/identity-access-management.html).
- **Mechanically:** a Java web application (Ember.js client, Jakarta Servlet server, Tomcat, JDBC) with a bundled PostgreSQL database. That database stores "admin credentials, domain configuration settings, reverse proxy settings". The shell "make[s] a REST API call to the other components" to sync settings and fetch reports (AD360 Solution Architecture PDF, last modified 2024-05-26: https://info.manageengine.com/active-directory-360/ad360-solution-architecture.pdf).
- **Latest build:** 4504, released 2026-01-30. It updated the Duo Universal JAR to v1.3.1 ahead of Duo's legacy sunset on 2026-02-02 (https://www.manageengine.com/active-directory-360/release-notes.html).
- **Shell release history:**
  - 2025: 4408 (Mar 17, stability), 4500 (May 14: per-technician 2FA toggle, SAML encryption/signing; Tomcat 9.0.99, JRE 1.8.432, PostgreSQL 15.8), 4501 (Aug 25, OOM fix), 4503 (Dec 10: Tomcat 9.0.112, HA across subnets).
  - 2026: 4504 only.
  - Same source as above. The shell is in maintenance mode; feature work happens in the components.

### 1.2 Components

AD360 "contains seven components" (QSG, https://download.manageengine.com/active-directory-360/ad360-quick-start-guide.pdf, PDF modified 2025-04-02; help: https://manageengine.com/active-directory-360/help/admin/administration/AD360-integration.html). Entry prices are annual subscriptions from the store JSON, shown as Standard / Professional.

| Component | Role in AD360 | Licence meter(s) | Entry list price (annual, Std / Pro) | Perpetual in store? | Latest build (date) | Default ports HTTP/HTTPS |
|---|---|---|---|---|---|---|
| ADManager Plus | AD, M365, Exchange and Google Workspace management, reporting, automation and workflows (see sibling file) | domains (every child domain counted) + named help-desk technicians | $595 / $1,795 for 1 domain + 2 techs; Pro admin-only 1 domain $795 | Yes | 8043 (2026-07-06) ([RN](https://www.manageengine.com/products/ad-manager/release-notes.html)) | 8080/8443 |
| ADAudit Plus | AD, Entra, file, server and workstation auditing; UBA; attack and posture analysis (see sibling file) | DCs + Windows servers + file servers (Windows/NAS) + workstations + Entra tenants + add-ons | $595 / $945 for 2 DCs | Yes | 9000 (2026-09-30) ([RN](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html)) | 8081/8444 |
| ADSelfService Plus | SSPR, MFA, SSO, password sync (see sibling file) | users, consumed on first action | $595 / $1,195 for 500 users | **No** (subscription only) | 7001 (2026-08-21) ([RN](https://www.manageengine.com/products/self-service-password/release-notes.html)) | 8888/9251 |
| Exchange Reporter Plus | Hybrid Exchange and Skype for Business reporting, auditing, monitoring (§3.2) | mailboxes | $345 / $595 for 100 mailboxes | Yes | 5802 (2026-03-19) | 8181/8887 |
| M365 Manager Plus | M365 management, reporting, auditing, automation (§3.1) | users/mailboxes (1 technician included) | $345 / $595 for 100 | Yes | 4821 (2026-07-30) | 8365/9365 |
| RecoveryManager Plus | Backup and restore for AD, Entra ID, Exchange/EXO, SPO, OneDrive, Teams, Google Workspace, Zoho WorkDrive (§2) | per workload: enabled AD users, Entra users, mailboxes, sites, users | $475 for 250 AD users (Standard only) | Yes | 6330 (2026-09-29) | 8090/8558 |
| SharePoint Manager Plus | SharePoint on-prem and Online reporting, auditing, management, migration (§4.1) | farms / M365 tenants (+ technicians) | $945 / $1,195 for 1 farm/tenant | Yes | 4601 (2026-09-22) | 8085/8086 |

- Ports come from the architecture PDF above. Prices come from the store JSON (AD360: https://store.manageengine.com/api/public/json/productdetails/990c23d46bb61f80ccca0e76faf358aa.js).
- **Not AD360 components**, despite frequent assumption:
  - **DataSecurity Plus** is "the data visibility and data leak prevention component of Log360" (https://www.manageengine.com/data-security/).
  - **Log360**, **PAM360** and **Identity360** are separate products. AD360's ITDR marketing page pulls in Log360 for detection (§1.6, §7).

### 1.3 How integrated is it really?

Evidence table. QSG = quick start guide PDF; Arch = solution architecture PDF.

| Dimension | Finding | Evidence |
|---|---|---|
| Installation | AD360 has its own installer (`ManageEngine_AD360.exe`) with three modes. **Standard** "downloads and installs all the components along with AD360". **Minimal** installs AD360 alone. **Custom** installs selected components. Otherwise components are downloaded and installed "one-by-one". Each remains a separate Windows application/service with its own web server. | QSG pp. 4–7 |
| Registration | Admin › Administration › AD360 Integration. "Enter the Server Name or IP and Port Number… Select the connection Protocol… Click Integrate Now", once per component. Since build 4406 (2024-11-12), super-admin credentials are required to integrate. | QSG p. 8; [RN](https://www.manageengine.com/active-directory-360/release-notes.html) |
| Topology guidance | "If you plan on integrating more than two components with AD360, we recommend you install no more than two components on a single machine." | QSG p. 1 |
| RAM / disk guidance | RAM: AD360 4 GB, ADMP 6 GB (8 GB VM), ADAP 16, ADSSP 16, ERP 16, M365MP 16, RMP 16, SPMP 8 (16 VM). Disk: AD360 10 GB, ADMP 50, ADAP 100, ADSSP 200, ERP 200, M365MP 500, SPMP 50, RMP variable. | QSG pp. 1–3 |
| Databases | The AD360 DB holds shell settings. Database migration and auto-backup are configured **per component** ("Select AD360 under Component Name"; "Choose AD360 or an integrated product for which you want to schedule auto backup"). That means N+1 databases. PostgreSQL is the default and MS SQL optional; the QSG lists PostgreSQL 9.2–9.5 for migration and backup (older doc; the shell now bundles 15.8). | QSG pp. 21–24; Arch; RN 4500 |
| Settings sync | "Domain settings, component integration, mail server, proxy server… will be automatically synchronized". However: "A domain can be added only in the individual components". A manual **Sync Now** exists. The shell syncs by REST calls to each component. | QSG p. 9; Arch |
| Unified reporting | AD360 fetches reports from **ADAudit Plus, Exchange Reporter Plus and M365 Manager Plus** by REST and shows them "in a single console". ADMP, ADSSP, RMP and SPMP are not named in that aggregation (absence noted, not confirmed). | Arch |
| Navigation / UI | "You will be presented with the dashboards of the individual components… access the individual components using the applications panel on the left-hand side". This is a launcher with embedded component UIs. | QSG p. 8 |
| SSO | NTLM (NTLMv2) or SAML (Okta, OneLogin, Ping, ADFS, Entra, custom) into AD360 "and the products integrated with it", chosen per component. NTLM needs browser trusted-site configuration. | [SSO help](https://www.manageengine.com/active-directory-360/help/admin/administration/single-sign-on.html) |
| SSO security | **CVE-2026-11374**: "SSO tickets used in the inter-product CustomSSO workflow… could be predicted by an unauthenticated user, potentially exposing user identity and role information and, under certain conditions, leading to account takeover." Fixed in M365MP 4817 (2026-06-10), RMP 6321 (2026-06-05), ADSSP 6529 and ADAP 8703. | [M365MP RN](https://www.manageengine.com/microsoft-365-management-reporting/release-notes.html); [RMP RN](https://www.manageengine.com/ad-recovery-manager/release-notes.html); [ADSSP RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| RBAC / technicians | "Centralized technician management" arrived in build 4402 (Apr 2024). It supports ADMP ≥7232, ADAP ≥8002, ADSSP ≥6404, ERP ≥5716 and RMP ≥6200. M365MP was added in 4405 (Aug 2024) and SPMP only in SPMP build 4508 (2025-12-29). AD360-level roles are just Admin/Operator; "each component of AD360 has its own technician management settings". "Existing product-authenticated technicians in the AD360 components will not be synced." | [Help](https://manageengine.com/active-directory-360/help/admin/administration/technician-management.html); [RN](https://www.manageengine.com/active-directory-360/release-notes.html); [SPMP RN](https://www.manageengine.com/sharepoint-management-reporting/release-notes.html) |
| Licence | One AD360 licence file, but it "can be applied to other products by following the above steps **in the respective product's console**". | [FAQ](https://www.manageengine.com/active-directory-360/faq.html) |
| Lifecycle ops | Starting AD360 starts the integrated components. Optional "single shutdown". Auto-update and DB backup are scheduled per component from the AD360 UI. AD360 can act as a reverse proxy for the components. HA is supported. | QSG pp. 6, 18, 23–26 |
| Version skew | Components run different runtimes and cadences: shell on JRE 1.8 (4500); M365MP moved Java 8→11 (4821); RMP to JRE 17 (6330); PAM360 to 17 (8700). | Respective RNs |
| Seam bugs | Examples: M365MP DBSync/backup failures under AD360/Log360 (4532); M365MP SSO login failures in AD360 (4523); ERP failing to install alongside ADAudit Plus (5707). | [M365MP RN](https://www.manageengine.com/microsoft-365-management-reporting/release-notes.html); [ERP RN](https://www.manageengine.com/products/exchange-reports/release-notes.html) |

**Verdict.** AD360 is a **launcher plus config sync plus SSO plus partial report aggregation** sitting over seven separately installed, patched and databased products. It has no shared identity data model, no single policy/workflow engine, no single audit store and no single RBAC model.

**Deployment footprint (Estimate).**
- Full suite RAM: 4 + 6 + 16 + 16 + 16 + 16 + 16 + 8 = **98 GB** physical. On VMs: 4 + 8 + 16 + 16 + 16 + 16 + 16 + 16 = **108 GB**.
- Disk before backup data: 10 + 50 + 100 + 200 + 200 + 500 + 50 = **1,110 GB**.
- Servers: ≥ ⌈7 components ÷ 2 per machine⌉ = **≥4 Windows servers**.
- Core trio (AD360 + ADMP + ADAP + ADSSP): 4 + 8 + 16 + 16 = **44 GB** RAM on ≥2 servers.

### 1.4 AD360 licensing and pricing

- **The shell is free; you pay per component.** "Pricing starts @ $595… Pay only for the component(s) you choose" (https://www.manageengine.com/active-directory-360/license-renewal.html). "Existing customers of any of the ADSolutions products can integrate them with AD360 at no extra cost" (https://www.manageengine.com/active-directory-360/license-upgrade.html).
- **Editions.** "AD360 Standard" and "AD360 Professional" simply select each component's edition. **RecoveryManager Plus is "available only in the Standard Edition of AD360"** (https://www.manageengine.com/active-directory-360/compare-editions.html). AD360 build 4407 (2024-12-03): "M365 Manager plus will now come bundled with AD360".
- **No bundle discount at list.** Every AD360 component SKU in the store JSON matches the standalone SKU price:

| Item | AD360 SKU | Standalone SKU |
|---|---|---|
| ADMP Pro, 1 domain + 10 techs | $5,995 | $5,995 |
| ADAP Std, 10 DCs | $2,145 | $2,145 |
| ADSSP Pro, 5,000 users | $6,995 | $6,995 |
| ERP Std, 1,000 mailboxes | $1,545 | $1,545 |
| M365MP Pro, 1,000 users | $2,395 | $2,395 |
| RMP, 1,000 AD user objects | $1,195 | $1,195 |
| SPMP Pro, 1 farm/tenant | $1,195 | $1,195 |

- Store JSON sources: AD360 (https://store.manageengine.com/api/public/json/productdetails/990c23d46bb61f80ccca0e76faf358aa.js) vs the standalone product JSONs listed in §6.2.
- **Promotions.** The only promotion seen is conditional: the ERP store advertises "Save up to 50%*" when bought with ADAudit Plus (https://store.manageengine.com/exchange-reports/). Negotiated enterprise discounts are not public. The only quantified source found (2026-10-02) is **Vendr**, a buyer-side procurement platform that publishes aggregates from its own transaction data: for **ManageEngine as a whole, not AD products**, it reports a median annual spend of $9,648 (range $2,391 to $28,810) over 50 anonymised purchases (page last updated February 2026), "15–30% off list pricing" for 2–3 year commitments and "10–25% lower per-unit pricing" for volume deployments of 500+ devices or 50+ technicians; it names ADManager Plus only as "$1,000–$2,000 annually for small environments" ([Vendr buyer guide](https://www.vendr.com/buyer-guides/zoho-manageengine), third-party, peer-data rank). Representativeness is low: the sample is small, mixes ManageEngine's endpoint, ITSM and monitoring lines, and the discount bands are Vendr's summary, not deal quotes. Use it as a hypothesis for the CEO's warm-account discovery, not as a fact in a battlecard. `[UNVERIFIED]` for AD products specifically.
- **Subscription only.** The store catalogue has an "AD360 Subscription" category but **no AD360 perpetual category**. ADMP, ADAP, RMP, ERP, M365MP and SPMP each have perpetual categories (https://store.manageengine.com/js/indc-newstorecatglist.js).
- **Minimums conflict across ME's own collateral.**
  - AD360 get-quote page: ADSSP minimum **500** users; ADAP 2 DCs / 2 file servers / **5** Windows servers / 100 workstations; RMP base packs of 250 AD users, 100 mailboxes, 25 SPO sites, 100 OneDrive sites, 100 Google users, 10 Zoho users (https://www.manageengine.com/active-directory-360/get-quote.html).
  - ME's "License Components Explained" PDF (reseller-hosted, Feb 2026): ADSSP minimum **100** users; ADAP **10** Windows servers; SPO **5** sites; OneDrive **25** sites; Google **25** users (https://kidan.com/wp-content/uploads/2026/02/manageengine_ad360_license_components_explained.pdf).
- **AD360 Backup add-on.** "Purchasing a license for (x) users will allow you to back up (x) AD users, (x) Entra ID users, and (x) Google Workspace users" (same PDF). The get-quote page says it enables AD/Entra backup in ADMP, AD backup in ADAP and M365 mailbox backup in M365MP. This overlaps RMP (§4.7).
- **Catalogue oddities** (signals of commercial complexity):
  - AD360 JSON lists "Additional 1 help desk Technician" at **$10 (Pro) / $5 (Std)**. No such SKU appears in the standalone ADMP store, and its purchasability is `[UNVERIFIED]`.
  - It has two different AD360 RMP mailbox SKUs: 25 mailboxes at $195 and at $95. The $95 one matches RMP's PST-export price, so it is probably mislabelled `[UNVERIFIED]`.
- **Paid onboarding** (AD360 Onboarding JSON, https://store.manageengine.com/api/public/json/productdetails/b47fe3c2b381f12f46ca0946486b56c4.js):
  - Standard Onboarding and Implementation (online): **$6,995**.
  - Advanced Onboarding: **$11,495** online, **$14,995** onsite.
  - Training add-on (up to 4 participants): $495 online, $995 onsite. 4-hour online training: $995.
  - Task services at $295 each: HA, help-desk integration, server configuration, reverse proxy, MFA configuration, removable-storage auditing.
  - HRMS integration and customization: $195/hour.

### 1.5 AD360 Cloud, Identity360 and Identity Access

**AD360 Cloud: no such product was found as of 2026-10-02.** This is not proof that none exists.
- Candidate URLs (`/active-directory-360/cloud/`, `/ad360-cloud/`, etc.) return 404.
- ME's IAM portfolio page tags AD360 "On-premises" and Identity360/Identity Access "Cloud" (https://www.manageengine.com/identity-access-management.html).
- The AD360 help site has an On-prem/Cloud toggle, but every nav entry is tagged `"platform": "common"` (https://www.manageengine.com/active-directory-360/help/assets/script/lhs-tree.js).
- **ME's SaaS answer to AD360 is Identity360.**

**Identity360: overview**
- **What it is:** a "cloud-based IAM platform for enterprises" covering Universal Directory, lifecycle, MFA, SSO, access management, delegation and reports (https://www.manageengine.com/identity-360/).
- **Launch:** 2023-10-02 (https://www.manageengine.com/news/manageengine-launches-cloud-native-identify-platform-address-workforce-iam-challenges.html). "Identity Manager Plus has been re-engineered and relaunched as Identity360" (https://www.manageengine.com/identity-360/release-notes.html). Identity Manager Plus had launched in Apr 2019 at "$1 per user, per year" (https://www.manageengine.com/news/manageengine-launches-cloud-based-single-sign-on-solution-for-enterprises.html).
- **Hosting:**
  - Runs at `id360.manageengine.com` with Zoho Accounts login.
  - Data centres in India, US, UK and EU. Data is AES-256 encrypted with a per-customer key.
  - Zoho claims ISO 27001/27017/27018 and SOC 2 Type II.
  - Sources: architecture PDF (modified Jul 2025) https://download.manageengine.com/identity-360/identity360-solution-architecture.pdf; https://www.manageengine.com/identity-360/access-management/
- **Directories:**
  - On-prem AD needs the **Identity360ADAgent** "installed and running on a server in the domain". Entra ID connects through a Graph app.
  - Only AD and Entra can be directories. "HCM and CRM systems are connected as applications".
  - Write-back to AD is `[UNVERIFIED]`.
  - Source: https://www.manageengine.com/identity-360/help/admin-guide/universal-directory/directory-services-integration/directory-management.html
- **Aug 2026 split.** **Identity Access** is now a separate access-only SKU (SSO, adaptive/conditional access, endpoint MFA, passwordless). "Identity360 now offers edition-based pricing" (https://www.manageengine.com/identity-360/access-management/release-notes.html; https://pitstop.manageengine.com/portal/en/community/topic/meet-manageengine-identity-access-a-cloud-native-access-management-solution).

**Identity360 pricing (annual billing only; >5,000 users by quote)**

| Users | I360 Professional | I360 Enterprise | Identity Access Pro | Identity Access Ent |
|---|---|---|---|---|
| 100 | $1,150 | $1,275 | $850 | $975 |
| 500 | $4,625 | $5,250 | $3,375 | $4,000 |
| 1,000 | $7,250 | $8,750 | $5,250 | $6,750 |
| 2,000 | $12,500 | $15,000 | $9,000 | $11,500 |
| 5,000 | $25,000 | $31,250 | $18,750 | $25,000 |

- Sources: https://www.manageengine.com/identity-360/pricing-details.html (Last-Modified 2026-08-27, verified by direct fetch); https://www.manageengine.com/identity-360/access-management/pricing-details.html
- **Enterprise-only features:** MFA for RDP, offline MFA, device authentication, and desktop passwordless (Windows/macOS/Linux). The homepage also lists "Risk-based authentication" as Enterprise-only, which conflicts with the comparison table `[UNVERIFIED]`.
- **SMS credits** are perpetual: 2,000 for $595, 100,000 for $20,395.
- **Trial:** 30 days. Whether the free tier still exists is `[UNVERIFIED]`: the live pricing page, re-read 2026-10-02, contains no mention of a free tier or trial ([pricing](https://www.manageengine.com/identity-360/pricing-details.html)), while a search-engine summary attributed to ManageEngine pages says the product is "free for 10 users only" after the trial; we could not find the page that says so, so we do not rely on it.

**Aug 2026 repricing.** Archived pricing pages from 2024-12-07 and 2025-12-05 show module pricing (https://web.archive.org/web/20251205093347/https://www.manageengine.com/identity-360/pricing-details.html):
- 1,000 users: Life Cycle Management $1,995, MFA+SSO $1,195, All-inclusive $2,795.
- 5,000 users: $4,995 / $3,495 / $6,995.
- 100,000 users: $12,995 / $9,995 / $19,995.

**Estimate of the increase:**
- 1,000 users: All-inclusive $2,795 → Professional $7,250 = **2.6×**; → Enterprise $8,750 = **3.1×**.
- 5,000 users: $6,995 → $25,000 = **3.6×**; → $31,250 = **4.5×**.
- MFA+SSO $1,195 → Identity Access Professional $5,250 at 1,000 users = **4.4×**.
- Whether existing customers are grandfathered is `[UNVERIFIED]`.

**Identity360 feature inventory (condensed)**

| ID | Area | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| I360-001 | Directory | Universal Directory | Cloud identity store, "single source of truth" | Pro, Ent | https://www.manageengine.com/identity-360/pricing-details.html |
| I360-002 | Directory | AD sync via agent | Identity360ADAgent syncs users, groups and members on a schedule or on demand | Pro, Ent | https://www.manageengine.com/identity-360/help/admin-guide/universal-directory/directory-services-integration/directory-management.html |
| I360-003 | Directory | Entra ID sync | Graph API app (consent or manual) | Pro, Ent | same as above |
| I360-004 | Lifecycle | Smart templates | Rule-based attribute population at provisioning | Pro, Ent | https://www.manageengine.com/identity-360/pricing-details.html |
| I360-005 | Lifecycle | Identity orchestration | Automates provisioning, deprovisioning and access | Pro, Ent | https://www.manageengine.com/identity-360/release-notes.html |
| I360-006 | Lifecycle | SCIM provisioning | Provisions and deprovisions SaaS app accounts | Pro, Ent | https://www.manageengine.com/identity-360/pricing-details.html |
| I360-007 | Lifecycle | HR integrations | BambooHR, Sage HR, UKG Pro, Zoho People (lifecycle). Workday is listed for SSO/MFA only | Pro, Ent | https://www.manageengine.com/identity-360/integrations/workday.html |
| I360-008 | Lifecycle | Entra session termination | Kills Azure AD sessions at offboarding (Sep 2024) | `[UNVERIFIED]` | https://www.manageengine.com/identity-360/release-notes.html |
| I360-009 | SSO | SAML/OAuth/OIDC SSO | Custom and bookmark apps, PKCE (Jun 2025), multi-value attributes | Pro, Ent | https://www.manageengine.com/identity-360/release-notes.html |
| I360-010 | SSO | SSO into ME on-prem apps | SAML SSO into ADManager Plus, ADAudit Plus, ServiceDesk Plus, AD360 | Pro, Ent | https://www.manageengine.com/identity-360/integrations/ad360.html |
| I360-011 | MFA | Adaptive MFA (apps and portal) | Context-aware MFA | Pro, Ent | https://www.manageengine.com/identity-360/pricing-details.html |
| I360-012 | MFA | Endpoint MFA | Windows, macOS and Linux login, unlock, UAC, sudo, SSH | Pro, Ent | https://www.manageengine.com/identity-360/release-notes.html |
| I360-013 | MFA | Remote-access MFA | VPN, RADIUS, Wi-Fi, RDWeb, OWA/IIS | Pro, Ent | https://www.manageengine.com/identity-360/pricing-details.html |
| I360-014 | MFA | MFA for RDP | Remote desktop MFA | **Ent** | https://www.manageengine.com/identity-360/pricing-details.html |
| I360-015 | MFA | Offline MFA | Through the IDSecurity Agent, with Emergency Access Codes | **Ent** | https://www.manageengine.com/identity-360/release-notes.html |
| I360-016 | Auth | Desktop passwordless | FIDO2 and PIV/CAC smart cards | **Ent** | https://www.manageengine.com/identity-360/release-notes.html |
| I360-017 | Auth | Device authentication | Cloud identity as the desktop credential; BYOD and workgroup enrolment | **Ent** | https://www.manageengine.com/identity-360/pricing-details.html |
| I360-018 | Auth | Conditional access | Rules on user, device, department, role, IP, geo, hours and OS (Aug 2026) | `[UNVERIFIED]` | https://www.manageengine.com/identity-360/release-notes.html |
| I360-019 | Auth | 12 authenticator types | Email, SMS, Google/Microsoft Authenticator, Q&A, Zoho OneAuth, TOTP, smart card, Duo, FIDO, among others | Pro, Ent | https://www.manageengine.com/identity-360/pricing-details.html |
| I360-020 | Admin | Help-desk delegation | Custom technician roles | Pro, Ent | https://www.manageengine.com/identity-360/pricing-details.html |
| I360-021 | Reports | Built-in reports | Login activity, SSO usage, MFA audit, technician actions | Pro, Ent | https://download.manageengine.com/identity-360/identity360-datasheet.pdf |
| I360-022 | Platform | REST API | OAuth 2.0 API for single-user lifecycle actions (Nov 2024) | `[UNVERIFIED]` | https://www.manageengine.com/identity-360/release-notes.html |
| I360-023 | Integrations | App catalogue | Marketing claims "500+ prebuilt" SSO apps; the integration hub shows **168 cards** (98 third-party, 49 Zoho, 20 ME), counted 2026-10-02 | — | https://www.manageengine.com/identity-360/integrations.html |
| I360-024 | Roadmap | AD-management and governance parity | **In development:** group/computer/mailbox management, JIT, access certification, SoD, entitlements, PAM, GPO management, domain migration, AD auditing with real-time alerts, custom report builder. **In pipeline:** password self-service, NIST risk assessment, attack path analyzer, M365 auditing, workflows. **All undated.** | Roadmap | https://www.manageengine.com/identity-360/roadmap.html (modified 2026-09-22) |

**Identity360 releases 2025–2026:**
- 2025-03-14: passwordless portal login and VPN/RADIUS passwordless.
- 2025-04 and 2025-05: HR and app integrations.
- 2025-06-05: PKCE.
- 2025-10-30: 100+ SSO apps.
- 2026-05-14: agent and NPS updates.
- **2026-08-25 major release:** directory-independent access security, conditional access, endpoint MFA including sudo, BYOD/workgroup protection, offline MFA, PIV/CAC.
- Source: https://www.manageengine.com/identity-360/release-notes.html

### 1.6 Relation to Log360

- Log360 integrates "separately installed" ADAudit Plus, ADManager Plus, DataSecurity Plus, Exchange Reporter Plus, Cloud Security Plus and PAM360, all "from a single Log360 console" (https://www.manageengine.com/log-management/help/setting-up/log360-components/overview.html). Its evaluator FAQ lists EventLog Analyzer, ADAP, Cloud Security Plus, ERP, M365MP, ADMP, DSP and UEBA (https://www.manageengine.com/log-management/evaluator-faq.html).
- **The same ADAudit Plus engine is sold inside both AD360 and Log360.**
- **Log360 is consolidating before AD360.** Build 13000 (2025-09-16) re-engineered detection. Legacy build 5570 (2026-06-30) added migration to **"Unified Log360"**, which brings ADAP, ADMP, M365MP, ERP, DSP, PAM360 and UEBA "into a single interface" (https://www.manageengine.com/log-management/readme.html; https://www.manageengine.com/log-management/help/migration/migrating-configurations-from-standalone-log360-to-unified-log360.html). Old DB backups are incompatible. Treat this as the template for a possible "Unified AD360" `[UNVERIFIED — no AD360 announcement found]`.

---

## 2. RecoveryManager Plus (RMP)

### 2.1 Overview

- **What it is:** web-based backup and recovery for AD, Entra ID, M365 (Exchange Online, SharePoint Online, OneDrive, Teams), on-prem Exchange, Google Workspace and Zoho WorkDrive, from one console (https://www.manageengine.com/ad-recovery-manager/). The home page claims "Trusted by over 1300+ worldwide companies".
- **Deployment:** on-prem Windows only.
  - Stack: Tomcat (8090/8558), bundled PostgreSQL or MS SQL, plus a bundled Elasticsearch index for AD/Entra backup data.
  - AD objects are read agentlessly over LDAP; DC image backup needs a pushed agent.
  - Architecture PDF dated Dec 2025, modified Feb 2026: https://download.manageengine.com/ad-recovery-manager/recoverymanager-plus-architecture.pdf
  - No Linux or SaaS edition is documented.
- **Latest build: 6330 (2026-09-29).** It moved Exchange Online from EWS to Microsoft Graph, added SAML SSO, and upgraded to JRE 17. 6322 (2026-08-18) and 6321 (2026-06-05, CVE-2026-11374) precede it (https://www.manageengine.com/ad-recovery-manager/release-notes.html, verified by direct fetch).
- **2026 security fix:** CVE-2026-2740 (build 6313, 2026-03-24) "The RemCom service used for deploying an agent for domain controller backups has been hardened to prevent unauthorized access."
- **Editions:** Evaluation (30 days), Free, and **Standard (the only paid edition)** (https://www.manageengine.com/ad-recovery-manager/pricing-details.html).
- **Free edition limits:** AD/Entra unlimited users but one domain, with no bulk restore, instant backup, rollback or multi-domain. Exchange 10 mailboxes; Google 10 users; SharePoint/Teams 2 sites; OneDrive 1; Zoho 1 (https://www.manageengine.com/ad-recovery-manager/compare-editions.html).
- **Capability timeline** (same RN source):

| Year | Builds and changes |
|---|---|
| 2014 | 4000 (Sep): first listed build |
| 2018 | 5351 (Jun): Windows Server/VM backup withdrawn from new sale |
| 2021 | 6030 (Feb): Entra ID backup. 6041 (Jun): Google Workspace |
| 2024 | 6100 (Jan): Zoho WorkDrive. 6201 (Apr): DC backup |
| 2025 | 6220 (Jan): immutable backups. 6300 (Apr): Teams. 6311 (Nov): SIEM forwarding |
| 2026 | 6312 (Jan): S3-compatible storage. 6320 (May): sites/subnets and Entra LAPS |

### 2.2 Feature inventory

Edition key: **All** = Eval, Free and Standard per the compare-editions page. **Std** = Standard/Eval only. **n/s** = not stated.

| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| RMP-001 | AD | Object coverage | Users, groups, GPOs, OUs/containers, computers, contacts, DNS, group membership, Exchange attributes, dynamic distribution groups | All | https://www.manageengine.com/ad-recovery-manager/compare-editions.html |
| RMP-002 | AD | Schema and custom attributes | Backs up schema attributes. Up to 2,000 custom attributes can be imported by CSV (build 5351) | All | https://www.manageengine.com/ad-recovery-manager/release-notes.html |
| RMP-003 | AD | Incremental/full schedules | Incremental hourly, daily or weekly; full weekly or monthly. Changes are found by LDAP query and stored as versions | Std (Free: weekly only) | https://www.manageengine.com/ad-recovery-manager/help/settings/backup-settings.html |
| RMP-004 | AD | Instant backup | On-demand backup | Std | https://www.manageengine.com/ad-recovery-manager/compare-editions.html |
| RMP-005 | AD | Backup scoping | All or selected OUs, "Exclude Child OU(s)", custom attribute selection, force replication before backup | n/s | https://www.manageengine.com/ad-recovery-manager/help/settings/backup-settings.html |
| RMP-006 | AD | Attribute-level restore | "Simple" mode shows current vs backup value. "Granular" mode compares against all prior values in a time range. Includes schema objects | All | https://www.manageengine.com/ad-recovery-manager/help/backup-recovery/restore.html |
| RMP-007 | AD | Version management | Per-object versions with change counts and timestamps; compare versions; restore all or part of a version. "Who changed it" is not documented here (that lives in ADAudit Plus) | n/s | https://www.manageengine.com/ad-recovery-manager/active-directory-version-management.html |
| RMP-008 | AD | Change undo | "Reverse even the smallest attribute value change" | n/s | https://www.manageengine.com/ad-recovery-manager/features.html |
| RMP-009 | AD | Backup explorer / diff | Current vs backup values. Tracks Modified, Created, Deleted, Moved, Renamed, Recycled and Re-added | n/s | https://www.manageengine.com/ad-recovery-manager/help/backup-recovery/backup-explorer.html |
| RMP-010 | AD | Recycle bin | Restores deleted objects with all attributes, memberships and last-set passwords (users and computers). Linked objects are auto-recovered. Can restore to a different OU (5321) | All | https://www.manageengine.com/ad-recovery-manager/restore-active-directory-objects-recycle-bin.html |
| RMP-011 | AD | Bulk restore | Restores many objects at once | Std | https://www.manageengine.com/ad-recovery-manager/compare-editions.html |
| RMP-012 | AD | Point-in-time rollback | Rolls back the whole AD, OUs or objects. Re-creates deleted objects, deletes objects created later, reverses moves, membership and GPO-link changes. Preview first | Std | https://www.manageengine.com/ad-recovery-manager/active-directory-rollback.html |
| RMP-013 | AD | Restart-free recovery | Restores "without having to restart or shut down your DCs" | n/s | https://www.manageengine.com/ad-recovery-manager/active-directory-rollback.html |
| RMP-014 | AD | GPO backup/restore | Per-setting GPO versions, individual setting restore, GPO links, GPO rollback. GPP added in 5430, custom GPOs in 5321. Security and WMI filters not documented | All | https://www.manageengine.com/ad-recovery-manager/active-directory-group-policy-object-backup-recovery.html |
| RMP-015 | AD | DNS backup/restore | Forest and domain zones, forward and reverse. Record types A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT. Restores tombstoned records; versioned; no DC restart | All | https://www.manageengine.com/ad-recovery-manager/active-directory-dns-backup-recovery.html |
| RMP-016 | AD | Group/membership recovery | Membership add/remove and permission changes; restores a deleted user's memberships | All | https://www.manageengine.com/ad-recovery-manager/features.html |
| RMP-017 | AD | Computer and OU restore | Computer last-set password; one-click OU backup with delegation permissions | All | https://www.manageengine.com/ad-recovery-manager/features.html |
| RMP-018 | AD | Sites and subnets | Back up and restore AD sites/subnets (6320, May 2026) | n/s | https://www.manageengine.com/ad-recovery-manager/release-notes.html |
| RMP-019 | AD | BitLocker keys (AD) | Backs up keys stored in AD; retrieval UI added in 6300 | n/s | https://www.manageengine.com/ad-recovery-manager/kb/bitlocker-recovery-keys-with-recoverymanager-plus.html |
| RMP-020 | AD/DC | DC image backup | Agent pushed via RemCom takes VSS snapshots of system state, boot volume and AD database. Scheduling, encryption, retention | Std (blocked when over licence) | https://www.manageengine.com/ad-recovery-manager/restore-domain-controllers-using-manageengine-recoverymanager-plus.html |
| RMP-021 | AD/DC | DC / bare-metal restore | Boots RMP.iso (needs Windows ADK). Bare-metal, volume or file restore; non-authoritative then optional authoritative; same, different or P2V hardware | Std | https://www.manageengine.com/ad-recovery-manager/help/windows-server/restore.html |
| RMP-022 | Entra ID | Object backup | Users, groups, devices, app registrations, service principals, directory roles, admin units, licences (SKUs), domains. Incremental through Graph delta tokens | All | https://www.manageengine.com/ad-recovery-manager/azure-ad-backup.html |
| RMP-023 | Entra ID | Policy backup | Conditional Access, Authentication Method, Device Registration, Authentication Strength, Named Locations, Registration Campaign (6320) | n/s | https://www.manageengine.com/ad-recovery-manager/release-notes.html |
| RMP-024 | Entra ID | BitLocker keys and LAPS | Entra BitLocker keys (6310); Entra-managed LAPS passwords (6320) | n/s | https://www.manageengine.com/ad-recovery-manager/release-notes.html |
| RMP-025 | Entra ID | App role assignments | Backup and restore (6310) | n/s | https://www.manageengine.com/ad-recovery-manager/release-notes.html |
| RMP-026 | Entra ID | Restore and recycle bin | Object- or attribute-level restore to any version. Own recycle bin beyond Microsoft's 30 days, so it can restore objects "permanently removed" from Entra | All | https://www.manageengine.com/ad-recovery-manager/help/azure-active-directory/instant-and-effortless-recovery-in-azure-ad-recoverymanager-plus.html |
| RMP-027 | Entra ID | Rollback and multi-tenant | Tenant, group or object rollback to a backup point; multiple tenants | Std | https://www.manageengine.com/ad-recovery-manager/azure-active-directory-rollback.html |
| RMP-028 | Exchange | Mailbox backup | Mail, calendar, contacts, journals, notes, posts, tasks. EXO includes archive, group and shared mailboxes. Public folders not documented | All (Free: 10) | https://www.manageengine.com/ad-recovery-manager/exchange-online-backup-software.html |
| RMP-029 | Exchange | Restore modes | Full mailbox or item; to another user, tenant or organisation; on-prem↔EXO; preview | All | https://www.manageengine.com/ad-recovery-manager/features.html |
| RMP-030 | Exchange | PST export | Mailbox, folder or filtered items; split large PSTs; cheaper PST-only licence | All | https://www.manageengine.com/ad-recovery-manager/pricing-details.html |
| RMP-031 | Exchange | Advanced search | Search across backups by date, subject, from and to | n/s | https://www.manageengine.com/ad-recovery-manager/ |
| RMP-032 | M365 | SharePoint Online | Site collections, subsites, lists, libraries (including OneNote), metadata and share permissions. Site, item or version restore; zip download; option to skip version history (6320) | All (Free: 2 sites) | https://www.manageengine.com/ad-recovery-manager/sharepoint-online-backup-solution.html |
| RMP-033 | M365 | OneDrive | Files, folders, metadata; item, version or whole-site restore preserving structure | All (Free: 1) | https://www.manageengine.com/ad-recovery-manager/onedrive-for-business-backup-solution.html |
| RMP-034 | M365 | Teams | Channel posts, replies, files, hosted content, Loop components; view or export as JSON. Restoring posts into Teams, chats and private channels are not documented | All | https://www.manageengine.com/ad-recovery-manager/backup-microsoft-teams.html |
| RMP-035 | Google | Google Workspace | Gmail, calendar, contacts, notes, tasks, user Drive, personal accounts; multi-domain; item-level and cross-user restore. Shared Drives not documented | All (Free: 10) | https://www.manageengine.com/ad-recovery-manager/google-workspace-backup-and-recovery-solution.html |
| RMP-036 | Zoho | Zoho WorkDrive | Team and personal folders; item restore; restore to a different folder; download | All (Free: 1) | https://www.manageengine.com/ad-recovery-manager/release-notes.html |
| RMP-037 | Cross | Storage targets | Local, NAS/share, Azure Blob, Azure Files, AWS S3, Wasabi, S3-compatible (6312). Azure Gov, China and Germany regions. Extra Elasticsearch nodes | n/s | https://download.manageengine.com/ad-recovery-manager/recoverymanager-plus-architecture.pdf |
| RMP-038 | Cross | Immutable backups | Azure Blob (time-based retention, legal hold), S3 Object Lock, Wasabi Object/Bucket Lock | n/s | https://www.manageengine.com/ad-recovery-manager/backup/immutability-for-backup-files-recoverymanager-plus.html |
| RMP-039 | Cross | Retention and archive | Retention **counts full backups, not days**. The AD default keeps everything. Old data moves from the index to an archive store and is re-indexed on demand | All | https://www.manageengine.com/ad-recovery-manager/kb/default-backup-retention-count.html |
| RMP-040 | Cross | Compression and encryption | About 1/3 compression. AES-256 for workload backups; password encryption for DC backups; Elasticsearch encrypted at rest and in transit (5440) | All | https://www.manageengine.com/ad-recovery-manager/features.html |
| RMP-041 | Cross | File-type exclusion | SPO, OneDrive, Teams, Google, Zoho (6310) | n/s | https://www.manageengine.com/ad-recovery-manager/release-notes.html |
| RMP-042 | Admin | Technician roles | Admin, Operator, Auditor and custom roles; assigned to AD users or groups; scoped per domain or tenant; does not raise AD rights | n/s | https://www.manageengine.com/ad-recovery-manager/help/admin/technician.html |
| RMP-043 | Admin | Audit trail and SIEM | Logs every action with technician, module, time, object and status. Syslog forwarding (6311) | n/s | https://www.manageengine.com/ad-recovery-manager/release-notes.html |
| RMP-044 | Admin | Login and authentication | AD login via LDAP bind; 2FA (Duo, Microsoft Authenticator); smart card; SAML (6330); AD360 inter-product SSO | n/s | https://www.manageengine.com/ad-recovery-manager/release-notes.html |
| RMP-045 | Admin | Operations | Email alerts; workload dashboard (6302); stop running jobs (6302); custom branding (6310) | n/s | https://www.manageengine.com/ad-recovery-manager/release-notes.html |
| RMP-046 | Admin | Self-maintenance | Scheduled backup of its own DB; automatic patch updater (6050); bundled PostgreSQL 15.4 | n/s | https://download.manageengine.com/ad-recovery-manager/recoverymanager-plus-architecture.pdf |
| RMP-047 | Admin | API / mobile | No REST API or mobile app found in help navigation or release notes. Not found ≠ absent `[UNVERIFIED]` | — | https://www.manageengine.com/ad-recovery-manager/release-notes.html |

### 2.3 Licensing basis and pricing

- **What is counted** (https://www.manageengine.com/ad-recovery-manager/pricing-details.html; https://www.manageengine.com/active-directory-360/get-quote.html):
  - AD: **enabled** user objects. Disabled users are still backed up; groups and computers are unlimited.
  - Entra: "pure" Entra users, excluding users synced from AD.
  - Exchange: "user mailboxes" per the pricing page vs "user and shared mailboxes" per the home page `[UNVERIFIED which applies]`.
  - SharePoint/Teams: "sites **and sub-sites**" (a likely surprise).
  - Google: per user (mailbox + Drive).
  - Zoho: per user, and backing up a Team Folder needs a licence for every member.
- **When over licence, these are blocked:** editing backup settings, manual backups, weekly DC backups, DC backup on more than one DC per domain, scheduled full AD backups, bulk restore, rollback, and adding domains or tenants (pricing FAQ, same URL).
- **Promotion:** a free 6-month Standard licence for "ManageEngine customers"; eligibility is not stated (https://www.manageengine.com/ad-recovery-manager/free-active-directory-backup-recovery-tool-for-manageengine-customers.html).

**List prices, annual subscription, Standard edition** (store JSON https://store.manageengine.com/api/public/json/productdetails/fe00d2df68aa08cc4511ac17905b9d81.js):

| Workload | Meter | Entry | Mid | Top published tier |
|---|---|---|---|---|
| Active Directory | enabled user objects | 250: $475 | 1,000: $1,195 | 5,000: $4,995 |
| Entra ID ("Azure Backup") | user objects | 250: $475 | 1,000: $1,195 | 5,000: $4,995 |
| Exchange / M365 mailboxes | mailboxes | 25: $195 | 100: $495 | 500: $1,995 |
| PST export | mailboxes | 25: $95 | 100: $295 | 500: $795 |
| SharePoint Online | sites incl. subsites | 25: $495 | 100: $995 | 200: $1,495 |
| OneDrive | sites | 100: $495 | — | 200: $745 |
| Google Workspace | users | 100: $595 | — | 200: $995 |
| Zoho WorkDrive | users | 10: $95 | 100: $495 | 200: $995 |

- **Perpetual** (store JSON https://store.manageengine.com/api/public/json/productdetails/788ee42f365d46c7fc299de718731466.js): 2.5× the subscription price plus 20% AMS. Example: AD 1,000 users is $2,988 licence + $598/yr AMS, against $1,195/yr subscription. The pricing page itself presents subscription only.
- **Services:** standard online onboarding $3,495; 4-hour training $995; "Web-based Installation, Setup & Training" $995.
- **Mismatches:**
  - The RMP home page's "starts at" prices ($145 for 5 SPO sites, $95 for 25 OneDrive sites, $195 for 25 Google users) don't match current subscription SKUs.
  - The subscription mailbox minimum is 25 in the store vs a "base pack 100 mailboxes" on the AD360 quote page.

### 2.4 Documented limits

- Windows-only host.
- DC restore depends on a RemCom-pushed agent (subject of CVE-2026-2740) and on Windows ADK boot media.
- AD backup is an LDAP attribute snapshot, so change attribution has to come from ADAudit Plus.
- Count-based retention, plus an AD default of keep-all, means storage grows without bound.
- Teams post restore, Google Shared Drives and Exchange public folders are not documented.
- File-server and VM backup modules have been closed to new customers since 2018 (build 5351).
- Source: https://www.manageengine.com/ad-recovery-manager/release-notes.html

### 2.5 AD360 fit and overlap

- RMP is an optional AD360 component, Standard edition only, with the same minimum packs as standalone.
- It keeps its own Tomcat, database and Elasticsearch.
- Point-in-time AD recovery now also ships in **ADManager Plus "Advanced Recovery"** (build 8030, 2025-10-30, AD + Entra) and **ADAudit Plus "Advanced Recovery"** (build 8710, 2026-07-30). Backup add-ons are sold for ADMP, ADAP, Log360 and AD360 as well (§4.7). ManageEngine is converging recovery into the management and audit products, which makes RMP's standalone value proposition overlap heavily with them.

---

## 3. M365 Manager Plus & Exchange Reporter Plus

### 3.1 M365 Manager Plus (M365MP)

- **What it is:** reporting, management, auditing, monitoring, alerting, automation and delegation across Exchange Online, Entra ID, OneDrive, SharePoint Online, Teams, Power BI and Power Platform. Claims "700+" reports (https://www.manageengine.com/microsoft-365-management-reporting/).
- **Deployment:** on-prem Windows only ("Linux is not supported"), with PostgreSQL 15.7 or MS SQL 2012–2022 (https://www.manageengine.com/microsoft-365-management-reporting/system-requirements.html). No SaaS edition was found on the product or store pages, which is not proof of absence.
- **Latest build:** 4821 (2026-07-30), which moved Java 8→11 and added a "License Quota Used (%)" column. 13 builds shipped from Apr 2025 to Jul 2026 (https://www.manageengine.com/microsoft-365-management-reporting/release-notes.html).
- **Editions:**
  - Free: all features, 25 users.
  - Standard: reports, management, delegation.
  - Professional: adds auditing and alerts, automation, monitoring, content search.
  - Exchange Online Backup is an add-on.
  - Source: https://www.manageengine.com/microsoft-365-management-reporting/pricing-details.html
- **Licensing:** per user/mailbox managed, 1 technician included. **Shared, guest and resource mailboxes are free since build 4820 (2026-07-13).** More than 5,000 users or extra technicians go through sales. Multi-tenant counting is `[UNVERIFIED]` (https://www.manageengine.com/microsoft-365-management-reporting/help/getting-started/licensing-microsoft-365-manager-plus.html).

| ID | Area | Capability | What it does | Edition | Source |
|---|---|---|---|---|---|
| M365-001 | Reporting | 700+ prebuilt reports | EXO, Entra, OneDrive, Teams, SPO reports with custom filters | Std+ | https://www.manageengine.com/microsoft-365-management-reporting/features.html |
| M365-002 | Reporting | Schedule, export, embed | Scheduled reports; CSV/PDF/XLSX/HTML export; embed dashboards | Std+ | https://www.manageengine.com/microsoft-365-management-reporting/features.html |
| M365-003 | Reporting | Licence and MFA hygiene | Licence details with quota %, inactive users, MFA registration details (4700, Apr 2025) | Std+ | https://www.manageengine.com/microsoft-365-management-reporting/release-notes.html |
| M365-004 | Management | Bulk user lifecycle | CSV/template create and modify, reset, block, delete/restore, creation rules, duplicate prevention (4811) | Std+ | https://www.manageengine.com/microsoft-365-management-reporting/features.html |
| M365-005 | Management | Licence management | Bulk assign and remove M365 licences | Std+ | https://www.manageengine.com/microsoft-365-management-reporting/features.html |
| M365-006 | Management | EXO mailbox tasks | Enable/disable, SMTP, forwarding, auto-reply, litigation hold, delegation, address book policies | Std+ | https://www.manageengine.com/microsoft-365-management-reporting/features.html |
| M365-007 | Management | Groups | M365 groups, distribution lists, mail-enabled security groups; template-rule membership (4820) | Std+ | https://www.manageengine.com/microsoft-365-management-reporting/release-notes.html |
| M365-008 | Management | MFA administration | Allowed methods, reset methods, Temporary Access Pass (4811, Jan 2026) | Std+ | https://www.manageengine.com/microsoft-365-management-reporting/release-notes.html |
| M365-009 | Management | Teams | Bulk create, update, archive; channels, members, owners via CSV | Std+ | https://www.manageengine.com/microsoft-365-management-reporting/microsoft-teams-management-tool.html |
| M365-010 | Delegation | Help-desk RBAC | Custom roles; "virtual tenants" segmented by domain, group or attribute; cross-tenant scopes; technician audit | Std+ (granular in Pro per the AD360 compare page) | https://www.manageengine.com/microsoft-365-management-reporting/microsoft-365-delegation.html |
| M365-011 | Auditing | Cross-workload audit | EXO (owner, non-owner, admin), Entra, OneDrive, SPO, Teams, Power BI, Power Apps/Automate, eDiscovery, DLP, sensitivity labels | Pro | https://www.manageengine.com/microsoft-365-management-reporting/features.html |
| M365-012 | Auditing | Long-term retention | "Audit data can be stored for indefinite period" (Elasticsearch archive/restore, 4527) | Pro | https://www.manageengine.com/microsoft-365-management-reporting/microsoft-365-with-manageengine-m365-manager-plus-comparison.html |
| M365-013 | Alerting | 75+ alert profiles | Severity, actor, time; email delivery | Pro | https://www.manageengine.com/microsoft-365-management-reporting/microsoft-365-alerts.html |
| M365-014 | Monitoring | Service and endpoint health | Per-service health; endpoint response and status; history beyond 30 days; outage alerts | Pro | https://www.manageengine.com/microsoft-365-management-reporting/microsoft-365-monitoring-tool.html |
| M365-015 | Automation | No-code automation policies | Scheduled and event-driven task chains (JML: licences, groups, MFA, mailbox). No approval workflow documented | Pro | https://www.manageengine.com/microsoft-365-management-reporting/microsoft-365-automation-and-management.html |
| M365-016 | Content search | Mailbox pattern search | Keyword/pattern search (PII, phishing); scheduled profiles; alerts | Pro | https://www.manageengine.com/microsoft-365-management-reporting/pricing-details.html |
| M365-017 | Backup | Exchange Online backup | Full and incremental, versioned; point-in-time mailbox, folder or item restore including cross-tenant; PST export. EXO only (launched 4529, 2023-05-15) | Add-on | https://www.manageengine.com/microsoft-365-management-reporting/help/backup/backup-exchange-online-data.html |
| M365-018 | Security | Product access security | Technician 2FA (TOTP, Duo). App-registration-only Entra connection since 4700 (Apr 2025); earlier builds needed a service account with MFA disabled | All | https://www.manageengine.com/microsoft-365-management-reporting/release-notes.html |
| M365-019 | Integration | AD360 / Log360 | Plugs into both consoles. The "REST API" setting is outbound Graph; no inbound product API was found `[UNVERIFIED]` | — | https://www.manageengine.com/microsoft-365-management-reporting/kb/microsoft-365-rest-api-configuration.html |

**Pricing** (USD annual subscription; store JSON https://store.manageengine.com/api/public/json/productdetails/21c3be7dce214345cdab1c223525459f.js; perpetual https://store.manageengine.com/api/public/json/productdetails/9c96683ff28f6cdb444b1e3e0275bfaf.js)

| Users/mailboxes | Standard | Professional | EXO Backup add-on |
|---|---|---|---|
| 100 | $345 | $595 | $145 |
| 1,000 | $1,545 | $2,395 | $495 |
| 5,000 | $5,995 | $7,995 | $1,295 |

- Perpetual examples: Professional 1,000 users is $5,985 licence + $1,197/yr AMS; Professional 5,000 is $17,488 + $3,498.
- Onboarding: $3,495.

### 3.2 Exchange Reporter Plus (ERP)

- **What it is:** reporting, auditing, monitoring and content search for Exchange Server 2003 through SE, Exchange Online, and Skype for Business Server (https://www.manageengine.com/products/exchange-reports/).
- **Deployment:** on-prem Windows; no SaaS edition found.
- **Latest build: 5802 (2026-03-19)**, which fixed eight stored-XSS CVEs. No later build is listed (https://www.manageengine.com/products/exchange-reports/release-notes.html).
- **Cadence (inference):** maintenance mode. 2024–2026 builds are mostly security fixes and adaptations to Microsoft cmdlet retirements. The last substantive features were EXO content search (5711, Jul 2023) and on-prem→EXO migration (5713, Sep 2023).
- **Editions:** Free (25 mailboxes); Standard (reports, content search); Professional (adds auditing, monitoring, full migration) (https://www.manageengine.com/products/exchange-reports/edition-comparison.html).
- **Licensing:** per mailbox, with Manage/Unmanage toggles to control the count; 60-day trial (https://www.manageengine.com/products/exchange-reports/help/getting-started/licensing.html).

| ID | Area | Capability | What it does | Edition | Source |
|---|---|---|---|---|---|
| ERP-001 | Reporting | On-prem mailbox and infrastructure | Size, status, inactive mailboxes, permissions, DLs, public folders, retention, growth, NDRs | Free(25)/Std/Pro | https://www.manageengine.com/products/exchange-reports/features.html |
| ERP-002 | Reporting | Traffic analytics | Mailbox, org, internet, DL, department, user-to-user traffic | Std+ | https://www.manageengine.com/products/exchange-reports/features.html |
| ERP-003 | Reporting | Client access | OWA, ActiveSync, mailbox logon; 8 Outlook-access reports (5708) | Std+ | https://www.manageengine.com/products/exchange-reports/release-notes.html |
| ERP-004 | Reporting | Exchange Online | Sizes, archives, hidden mailboxes, ActiveSync | Std+ | https://www.manageengine.com/products/exchange-reports/features.html |
| ERP-005 | Reporting | Skype for Business | Conferences, IM, A/V, file transfers | Std+ | https://www.manageengine.com/products/exchange-reports/features.html |
| ERP-006 | Compliance | Regulation packs | SOX, HIPAA, PCI DSS, GLBA, GDPR, FISMA | `[UNVERIFIED]` | https://www.manageengine.com/products/exchange-reports/features.html |
| ERP-007 | Content search | Hybrid mailbox search | Attribute, keyword, RegEx/PII search on-prem and EXO (5711); scheduled profiles | Free/Std/Pro | https://www.manageengine.com/products/exchange-reports/exchange-mailbox-content-search.html |
| ERP-008 | Auditing | Exchange Server change audit | Non-owner logons, permission/property changes, DB changes, admin audit log, connector/transport config | Pro | https://www.manageengine.com/products/exchange-reports/exchange-server-auditing-and-alerting.html |
| ERP-009 | Auditing | Exchange Online audit | Same categories for EXO | Pro | https://www.manageengine.com/products/exchange-reports/edition-comparison.html |
| ERP-010 | Alerting | Alert profiles | 3 prebuilt profiles plus custom severity; pattern-in-window detection | Pro | https://www.manageengine.com/products/exchange-reports/exchange-server-auditing-and-alerting.html |
| ERP-011 | Monitoring | Server, DAG and DB health | Services, replication, DB mount and backup status, MAPI, search health, CPU and memory | Pro | https://www.manageengine.com/products/exchange-reports/exchange-server-monitoring-tool.html |
| ERP-012 | Monitoring | Mail flow and connectivity | Queues, internal and external mail flow, OWA/ActiveSync/EWS/POP/IMAP | Pro | https://www.manageengine.com/products/exchange-reports/exchange-server-monitoring-tool.html |
| ERP-013 | Migration | On-prem→EXO mailbox migration | Exchange 2013/16/19 mail, contacts, calendar, tasks; filters; schedules. Non-Pro capped at 25 mailboxes | Pro (full) | https://www.manageengine.com/products/exchange-reports/migrate-from-exchange-on-premises-to-exchange-online.html |
| ERP-014 | Delegation | Technician RBAC | Admin/Operator/custom roles scoped by org, tenant or forest. Docs say product-auth passwords are stored as an "MD5" hash | Paid | https://www.manageengine.com/products/exchange-reports/help/admin/utilities/user-management.html |
| ERP-015 | Scheduling | Report delivery | Daily, weekly, monthly or one-time email schedules; multi-format export | Std+ | https://www.manageengine.com/products/exchange-reports/help/admin/scheduling/report-scheduling.html |
| ERP-016 | Integration | Log360 / Log360 Cloud | Technicians managed from the Log360 console (5706); syslog forwarding to Log360 Cloud (5718, Jul 2024) | — | https://www.manageengine.com/products/exchange-reports/release-notes.html |
| ERP-017 | Security | Hardening | HTTPS, 2FA, LDAPS tab (5700). EXO app-registration-only from 5800 (2025-12-26); before that, a service account with MFA disabled was required | All | https://www.manageengine.com/products/exchange-reports/release-notes.html |

**Pricing** (USD annual subscription; store JSON https://store.manageengine.com/api/public/json/productdetails/238caaa6758e2e83f4cb5fa3e72022f2.js; perpetual https://store.manageengine.com/api/public/json/productdetails/a7dca92c95120a0d25adac63359c819a.js)

| Mailboxes | 100 | 200 | 500 | 1,000 | 2,000 | 3,000 | 5,000 |
|---|---|---|---|---|---|---|---|
| Standard | $345 | $595 | $945 | $1,545 | $1,795 | $2,395 | $3,595 |
| Professional | $595 | $945 | $1,545 | $2,395 | $2,745 | $3,595 | $5,395 |

- Perpetual: Standard 100 mailboxes is $863 + $173/yr AMS; Professional 1,000 is $5,988 + $1,198/yr AMS.

### 3.3 Overlap notes

- **ADManager Plus** already covers M365 provisioning, MFA, bulk licensing, EXO and shared-mailbox settings, and M365 groups (https://www.manageengine.com/products/ad-manager/office365-management-reporting-tools.html). It also covers on-prem Exchange provisioning and migration (https://www.manageengine.com/products/ad-manager/active-directory-exchange-management.html). That overlaps M365-004 to -008 and ERP-013.
- **ADAudit Plus** audits Entra sign-ins and changes through a per-tenant add-on. Since build 8700 (2026-05-20) it also has EXO, SharePoint and OneDrive reports (https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html), which overlaps M365-011.
- **M365MP vs ERP:** both do EXO reporting, auditing and content search, so customers can pay twice for EXO coverage. Only ERP covers on-prem Exchange and DAG monitoring.
- **M365 Security Plus** (launched 2020-08-13) is a separate security-only SKU with auditing, alerts, monitoring, content search and delegation. It costs **$495 for 100 → $6,495 for 5,000 users/yr** plus an EXO backup add-on (https://store.manageengine.com/api/public/json/productdetails/1806b19307c76bcfb3980a54e5979ead.js). That makes four SKUs touching the same M365 audit data.

---

## 4. Other adjacent products

### 4.1 SharePoint Manager Plus (SPMP)

| Item | Finding | Source |
|---|---|---|
| Scope | Reporting, auditing, management, migration and backup for SharePoint 2013/2016/2019/SE and SharePoint Online. "No server-side installation" | https://www.manageengine.com/sharepoint-management-reporting/ |
| Editions | **Standard:** reports (50+), audit reports (70+), alerts, log archival, basic delegation, backup/restore. **Professional:** adds permission, group and user management, migration (on-prem↔SPO, file shares, OneDrive), multi-farm delegation | https://www.manageengine.com/sharepoint-management-reporting/pricing-details.html |
| Licence | Per **farm or M365 tenant**, annual, 1 technician included. Extra technicians: $95 (Std) / $195 (Pro) each (AD360 JSON) | pricing-details; AD360 store JSON |
| Price (annual, Std / Pro) | 1: $945 / $1,195. 2: $1,545 / $2,145. 3: $2,145 / $2,995. 5: $3,595 / $4,795. Perpetual Std 1 farm $2,363 + $473 AMS | https://store.manageengine.com/api/public/json/productdetails/2541015445dc06a423679a91878b04a3.js |
| Builds | 4601 (2026-09-22). 4600 (2026-08-12): HA standby server. 4508 (2025-12-29): technicians manageable from the AD360 console | https://www.manageengine.com/sharepoint-management-reporting/release-notes.html |

### 4.2 DataSecurity Plus (DSP), a Log360 component

| Module | What it does | Licence unit and annual list price |
|---|---|---|
| File Server Auditing | Real-time file access and change audit, integrity monitoring, ransomware detection with automated response | $745 for 2 Windows file servers ($6,295 for 20); NAS (NetApp/Nutanix) $595 for 1 server |
| File Analysis | ROT data, storage, permission hygiene | $145 per 2 TB ($1,495 for 50 TB) |
| Data Risk Assessment | PII/ePHI/PCI discovery and classification | $395 per 2 TB ($2,295 for 20 TB) |
| Data Leak Prevention | USB, email and cloud exfiltration control; application control | $345 per 100 workstations ($2,095 for 1,000) |
| Cloud Protection | Shadow-IT and upload tracking | Included with DLP |

- Product: https://www.manageengine.com/data-security/. Pricing: https://www.manageengine.com/data-security/pricing-details.html and store JSON https://store.manageengine.com/api/public/json/productdetails/147d90b67acf8f7a9633927572ab6d0e.js
- **Latest build:** 6320 (Sep 2026, TAA-compliant federal build). 6310 (Aug 2026) added a DLP incident console. FSx (May 2026) and Isilon (Jul 2026) auditing were also added (https://www.manageengine.com/data-security/release-notes.html).
- **Overlap:** ADAudit Plus does file-server auditing on a *broader* NAS list and, since build 8600 (2026-01-08), sells **File Analysis as a licensed add-on** at the same $145 per 2 TB. A separate **Endpoint DLP Plus** SKU ($795 for 100 workstations, store JSON) overlaps DSP's DLP module.

### 4.3 Log360 (SIEM), where AD auditing overlaps SIEM

- **Positioning:** an "AI-powered unified SIEM" with UEBA, SOAR, "2000+… MITRE-mapped detections", Vigil IQ TDIR, Ask Zia, and built-in DLP and CASB (https://www.manageengine.com/log-management/). Build 13050 (2026-04-17) added an LLM "Alert Investigation Agent".
- **Latest build:** 13073 (2026-09-17). 13071 (2026-08-25) fixed authentication-bypass CVEs CVE-2026-16900 and CVE-2026-12263 (https://www.manageengine.com/log-management/release-notes.html).
- **Licensing:** a single "Professional" edition metered by DCs, log sources, file servers, endpoints, cloud accounts, plus an AD-backup add-on per DC (https://www.manageengine.com/log-management/help/overview/log360-licensing.html). Build 13025 (2026-03-30) "Introduced a new licensing model" (https://www.manageengine.com/log-management/readme.html).
- **Annual prices** (store JSON https://store.manageengine.com/api/public/json/productdetails/feb2230e374e0397745fc0ba2f3cb14c.js):
  - DCs: $945 (2) → $6,595 (20). This matches **ADAP Professional** DC pricing exactly.
  - Log sources: $795 (10) → $13,995 (250).
  - Windows file servers: $495 (2) → $3,595 (20).
  - Cloud accounts: $995 (1) → $3,995 (5).
  - Endpoints: $245 (100) → $1,795 (1,000).
  - "Backup" (AD): $245 (2 DCs) → $1,345 (20 DCs).
  - Standard onboarding $6,995; advanced $8,995.
- **Perpetual:** about 3× annual (e.g., $2,866 vs $945 for 2 DCs) (https://www.manageengine.com/log-management/manageengine-log360-pricing.html).
- **Log360 Cloud:**
  - About +40% vs on-prem annual: $1,345 vs $945 for 2 DCs.
  - Search storage $10–13 per GB per year; archive $0.25 per GB per year.
  - It moved to per-infrastructure licensing in May 2026 (https://www.manageengine.com/cloud-siem/pricing-details.html).
- **Analyst:** Gartner SIEM MQ 2025 (dated 2025-10-08), **Niche Player**, "Recognized for 8 years" (https://www.manageengine.com/log-management/analyst-recognitions-and-reports.html).

### 4.4 PAM360 and Password Manager Pro (PMP)

| | PAM360 | Password Manager Pro |
|---|---|---|
| What | Unified PAM: vault, JIT/PEDM, endpoint privilege management, CIEM, NHI governance, SSL/SSH keys, sessions with AI/ML anomaly detection ([page](https://www.manageengine.com/privileged-access-management/)) | On-prem vault: rotation, A-to-A, session recording, HA ([page](https://www.manageengine.com/products/passwordmanagerpro/)) |
| Editions | Enterprise only. Free: 1 admin, 10 resources | Free / Standard / Premium / Enterprise |
| Licence | **Administrators + keys; unlimited users and resources** ([pricing](https://www.manageengine.com/privileged-access-management/pricing.html)) | Administrators (+ keys in Enterprise) |
| Annual list | $7,995 (10 admins / 25 keys) → $12,995 (20/50) → $24,995 (50/200) → $49,995 (200/1,000). Multilingual is about 20% more ([store JSON](https://store.manageengine.com/api/public/json/productdetails/1e748db4d4d77d93735bc69248fd0b73.js)) | Std $595 (2 admins) → $10,795 (200). Premium $1,395 (5) → $16,195 (200). Enterprise $3,995 (10 admins + 10 keys) → $24,395 (200) ([store JSON](https://store.manageengine.com/api/public/json/productdetails/727ceca83c7a45be7523d879bbdfbb9c.js)) |
| Perpetual | $19,995 + $3,999/yr AMS (10 admins), i.e. 2.5× and 20% | Available |
| AD integration | AD/Entra user import; privileged domain-account discovery (7100); SCIM (8600); Kerberos reset (8600); JIT for LDAP resources (8710). **Domain-account JIT runs through ADManager Plus and requires ADMP Professional** ([help](https://manageengine.com/privileged-access-management/help/integration_admanagerplus.html)) | AD/Azure AD sync in all editions; privileged-account discovery in Enterprise |
| Builds | 8710 (2026-09-19). CVE-2026-18199 RCE (8601, 2026-07-30). CVE-2026-14828 SQLi (8561, 2026-07-07). AI: multi-provider and self-hosted LLMs (8540, 2026-04-21) ([RN](https://www.manageengine.com/privileged-access-management/release-notes.html)) | `[TODO]` |
| Relationship | ME publishes a PMP→PAM360 migration pack covering PMP builds 11002–13221 ([migration](https://www.manageengine.com/privileged-access-management/migrationpack.html)) | Still marketed as an entry vault. **No end-of-sale notice found** `[UNVERIFIED]` |
| Analyst | Gartner PAM MQ **Challenger** 2023, 2024, 2025 (2025-10-13) ([page](https://www.manageengine.com/privileged-access-management/analyst-opinion/gartner-magic-quadrant-pam.html)). KuppingerCole PAM LC 2026 Market Leader | — |

Training and onboarding SKUs (store JSON):
- Online course access: $995 / $1,495 / $1,995.
- Online onboarding: 4, 8 or 12 hours at $2,495 / $3,495 / $4,495.
- Onsite onboarding: 2, 3 or 5 days at $4,999 / $6,999 / $9,999.

### 4.5 ADManager Plus vs Identity360 overlap

| Capability | ADManager Plus (on-prem) | Identity360 (SaaS) |
|---|---|---|
| Deployment | On-prem Windows; MSP edition | SaaS (IN/US/UK/EU); on-prem agent needed for AD |
| AD object management | Core | Users synced by agent; group, computer and mailbox management "in development" |
| GPO management / domain migration | GPO yes | Roadmap (undated) |
| M365 / Entra management | Users, licences, mailboxes, groups | Entra sync, licence assignment, session termination |
| Provisioning | Templates, automation, orchestration, webhooks | Templates, orchestration, SCIM, HR connectors |
| Approval workflows | Multi-level | "Business workflows" in pipeline |
| Access certification / risk | Yes: certification (since Oct 2023), risk exposure management (Jul 2025) | Roadmap |
| SSO / MFA / passwordless | Not in ADMP (that's ADSSP) | Core strength |
| Backup | Add-on (AD, Entra, Google) | None listed |

- Sources: https://www.manageengine.com/products/ad-manager/ ; https://www.manageengine.com/identity-360/roadmap.html
- **No ME migration tool, licence-conversion programme or messaging for ADMP/AD360 → Identity360 was found** `[UNVERIFIED]`. Identity360's ADMP integration page offers only SSO and MFA (https://www.manageengine.com/identity-360/integrations/admanager-plus.html).
- Reading: ME runs **two tracks**. Governance and ITDR features ship on-prem first, and Identity360's development list is effectively ADMP + ADAP + ADSSP being re-built as SaaS.

### 4.6 Other identity-adjacent products (existence verified)

| Product | One line | Note / source |
|---|---|---|
| Access Manager Plus | Web-based privileged session management with recording and jump box | Per user. $495/yr for 5 users per Capterra `[UNVERIFIED]`. https://www.manageengine.com/privileged-session-management/ |
| Key Manager Plus | SSL/TLS certificate and SSH/PGP key lifecycle; on-prem and SaaS | https://www.manageengine.com/key-manager/ |
| M365 Security Plus | M365 audit, alerts, monitoring, content search | See §3.3 |
| Endpoint DLP Plus | Standalone endpoint DLP | Overlaps DSP DLP. Store JSON https://store.manageengine.com/api/public/json/productdetails/53197fd6f5802171b1e5c4238341cffc.js |
| ServiceDesk Plus ↔ ADMP | Ticket-driven AD provisioning from the ITSM tool | https://manageengine.com/active-directory-360/marketplace/admanager-plus/servicedesk-plus-active-directory-integration-with-admanager-plus.html |
| ADManager Plus MSP | Multi-tenant ADMP licensed "based on the total number of domain users and technicians" | https://www.manageengine.com/active-directory-manager-msp/faq.html |

### 4.7 Capability-overlap matrix (SKU sprawl)

| Capability | Sold in (separately licensed) |
|---|---|
| AD object backup / point-in-time rollback | RMP; ADMP Backup & Recovery add-on; ADMP "Advanced Recovery" (8030); ADAP AD Backup & Recovery add-on; ADAP "Advanced Recovery" (8710); Log360 "Backup" (per DC); AD360 Backup add-on |
| M365 user, licence and mailbox management | ADMP; M365MP; Identity360 (partial) |
| M365 / Entra auditing and alerting | M365MP Pro; M365 Security Plus; ADAP (Entra tenant add-on; M365 reports since 8700); Log360 "Cloud Accounts"; Log360 Cloud |
| Exchange Online reporting and content search | ERP; M365MP |
| EXO mailbox backup | RMP; M365MP EXO backup add-on; M365 Security Plus EXO backup add-on |
| File-server auditing / file analysis | ADAP (file-server and NAS add-ons; File Analysis add-on since 8600); DSP; Log360 "File Servers" |
| AD change auditing | ADAP; Log360 (DC licence); Log360 Cloud |
| MFA / SSO / passwordless | ADSSP; Identity360; Identity Access |
| Endpoint DLP | DSP DLP module; Endpoint DLP Plus |
| Privileged accounts | PAM360; PMP; Access Manager Plus; (ADMP for domain-account JIT) |

---

## 5. ManageEngine as a company

### 5.1 Corporate

| Item | Finding | Source |
|---|---|---|
| Structure | "The enterprise IT management division of Zoho Corp", in IT management "since 2002" | https://www.manageengine.com/about-us.html |
| Parent | Zoho Corp, founded 1996 as AdventNet and renamed 2009. HQ Chennai. Founders: Sridhar Vembu, Tony Thomas, Shailesh Kumar Davey | https://en.wikipedia.org/wiki/Zoho_Corporation |
| Ownership | "Private and bootstrapped". Zoho: "we have never taken money from investors" | https://download.manageengine.com/sites/meweb/images/news/images/pr-factsheet.pdf (modified 2026-09-16); https://www.zoho.com/aboutus.html |
| Leadership | From 2025-01-27: Sridhar Vembu became Chief Scientist and **Shailesh Kumar Davey Group CEO**. Press kit: "Rajesh Ganesan – CEO, ManageEngine" | https://www.cxtoday.com/crm/sridhar-vembu-steps-down-as-zoho-ceo-shailesh-kumar-davey-takes-his-place/ ; https://www.manageengine.com/news/press-kit.html |
| Zoho FY25 (year to Mar 2025) | Operating revenue ₹12,313 cr (+~18%); net profit ₹3,191.5 cr; North America 41% of revenue | https://www.medianama.com/2026/04/223-zoho-revenue-crosses-rs-12000-crore-fy25-profit-slips |
| ManageEngine FY25 | Segment revenue **₹4,863 cr = 39.5% of Zoho** (4,863 ÷ 12,313). **Estimate:** ÷ ~₹84.6/US$ (approximate FY25 average) ≈ **US$575M** | same |
| Build philosophy | "We do not acquire products or features from third parties"; "We do not use third-party data centers" | https://www.manageengine.com/about-us.html |

### 5.2 Scale claims (wording as seen 2026-10-02; inconsistent across pages)

- **PR factsheet (modified 2026-09-16):** "300+ channel partners worldwide", "Offices in 30+ locations", "60+ products", "190 countries served", "20 data centers globally", "6,000+ employees". **It gives no customer count.**
- **Other pages:**
  - AD360 page: "200,000+ organizations in 180+ countries" (https://www.manageengine.com/active-directory-360/).
  - Log360 page: "Over 280,000 organizations across 190 countries" (https://www.manageengine.com/log-management/).
  - Oct 2024 PR: "nine of every 10 Fortune 100 organizations" (https://www.manageengine.com/news/manageengine-iam-solutions-industry-analyst-firms-gartner-kuppingercole.html).
- About page: "over 4,000 employees" (stale).
- **RFP rule:** quote the dated factsheet. Treat the 200k/280k and Fortune 100 claims as vendor claims `[UNVERIFIED as current]`.

### 5.3 Analyst recognition (identity and security first, 2023–2026)

| Analyst | Report | Date | Product | Placement | Source |
|---|---|---|---|---|---|
| KuppingerCole | Leadership Compass IGA | 2026-05-19 | AD360 | **Market Leader** (not Product or Innovation Leader) | https://www.kuppingercole.com/research/lc80864/identity-governance-and-administration-iga |
| KuppingerCole | LC Identity & Access Governance | 2026-08-13 | AD360 | Market Leader. The report says "SailPoint leads the IAG market by a clear margin" | https://www.kuppingercole.com/research/lc81005/identity-and-access-governance |
| KuppingerCole | LC PAM | 2026-05-18 | PAM360 | Market Leader only | https://www.kuppingercole.com/research/lc81007/privileged-access-management-pam |
| KuppingerCole | LC Passwordless Authentication for Enterprises | 2026-03-10 | AD360 | Market Leader | https://www.kuppingercole.com/research/lc80894/passwordless-authentication-for-enterprises |
| KuppingerCole | LC ITDR | 2025-11-06 (ME blog 2025-11-21) | AD360 + PAM360 + Log360 | Market Leader. Product Leaders were Segura and Silverfort | https://www.kuppingercole.com/research/lc81209/identity-threat-detection-and-response-itdr ; https://www.manageengine.com/active-directory-360/blog/manageengine-named-a-market-leader-in-the-kuppingercole-leadership-compass-2025-for-identity-threat-detection-and-response-itdr.html |
| KuppingerCole | LC Access Management | 2025-06-12 | AD360, Identity360 | No leader badge. ME's wording: "Challenger" | https://www.kuppingercole.com/research/lc80867/access-management |
| KuppingerCole | LC IGA 2024 | 2024-08-06 | AD360, Identity360 | Market Leader | https://www.manageengine.com/news/manageengine-iam-solutions-industry-analyst-firms-gartner-kuppingercole.html |
| Gartner | Market Guide for IGA | 2025-10 | AD360 | Representative Vendor ("third consecutive year") | https://www.manageengine.com/active-directory-360/blog/manageengine-has-been-positioned-as-a-representative-vendor-in-the-2025-gartner-market-guide-for-identity-governance-and-administration.html |
| Gartner | Peer Insights Customers' Choice, IGA | 2023 | AD360 | Customers' Choice | https://www.manageengine.com/awards.html |
| Gartner | MQ PAM | 2025-10-13 (also 2024, 2023) | PAM360 | Challenger | https://www.manageengine.com/privileged-access-management/analyst-opinion/gartner-magic-quadrant-pam.html |
| Gartner | MQ SIEM | 2025-10-08 | Log360 | **Niche Player** | https://www.manageengine.com/log-management/analyst-recognitions-and-reports.html |
| Gartner | MQ Endpoint Management Tools | PR 2026-01-15 | Endpoint Central | Challenger | https://www.manageengine.com/news/endpoint-management-gartner-magic-quadrant-2026.html |
| IDC | MarketScape WW Integrated Solutions for Identity Security 2025 | blog 2025-10-29 | AD360 | Major Player | https://www.manageengine.com/active-directory-360/blog/zoho-corp-manageengine-named-a-major-player-in-the-idc-marketscape-worldwide-integrated-solutions-for-identity-security-2025-vendor-assessment.html |
| Forrester | Workforce Identity Security Platforms Landscape | Q4 2025 `[UNVERIFIED quarter]` | AD360 | Listed among 32 vendors (a Landscape report, not a Wave) | https://www.manageengine.com/active-directory-360/blog/manageengine-in-the-workforce-identity-security-platforms-landscape.html |
| Forrester | Wave PIM | Q4 2023 | PAM360 | Contender | https://www.manageengine.com/awards.html |
| ISG | Provider Lens | 2024 | AD360 | Leader (US Public Sector) / Rising Star (US) | https://www.manageengine.com/active-directory-360/ |

**Read-across:**
- In identity, ME's KuppingerCole recognition is consistently on the **market-presence** axis.
- No Gartner identity MQ placement is claimed (absence of evidence only).
- Gartner Peer Insights ratings are `[TODO]` (gartner.com returned 403).

### 5.4 Go-to-market

- **Direct:** public online store with list prices (https://store.manageengine.com/ad-manager/), plus inside sales and a US government line (https://www.manageengine.com/contact.html).
- **Offices:**
  - US: Pleasanton CA; Del Valle, New Braunfels and McAllen TX.
  - India: Chennai and others.
  - Also: UK, NL, UAE, Singapore, JP, CN, AU, MX, BR, CO.
- **Partners:**
  - **PACE** programme: Alliance (resellers, distributors, MSPs, SIs, ISVs), OEM, and Affiliate ("15% commissions", "$100 minimum per deal") (https://www.manageengine.com/pace/).
  - Tiers are not published by ME. Distributors run their own, e.g. Climb's Registered/Silver/Gold (https://www.climbcs.com/ie/manageengine-partner-program/).
  - The factsheet claims "300+ channel partners".
- **MSP:** separate MSP editions (e.g., ADMP MSP).
- **Field:**
  - UserConf 2026: Orlando 8–9 Oct, Shenzhen, Switzerland, Tokyo (https://www.manageengine.com/events/).
  - "ShieldNxG" identity and threat roadshows (US cities in Nov 2026; South Africa in Oct) (https://www.manageengine.com/log-management/seminars/shieldnxg-seminar-2026-usa.html).

### 5.5 Support model

| Service | Classic (included with AMS/subscription) | Premium |
|---|---|---|
| Acknowledgement | within 8 hours | within 3 hours |
| Email | regional business hours | Mon–Fri, 24 hours |
| Chat | ✓ | ✓ |
| Remote session | high-priority issues only | ✓ |
| Telephone | — | ✓ |
| 24×7 | high-impact issues only | high-impact issues only |
| Single point of contact, global escalation, portal | — | ✓ |
| Health check; 4-hour online training; "custom product support" (DB queries, scripts) | — | ✓ |

- Source: https://www.manageengine.com/support.html
- **Only acknowledgement targets are published.** No severity-based response or resolution SLAs were found.
- **Premium price is not public.** Re-checked 2026-10-02: the central support page lists no prices and says to email sales ([support](https://www.manageengine.com/support.html)); the ADManager Plus support page mentions a "Premium support" option without terms ([support](https://www.manageengine.com/products/ad-manager/support.html)); the ADSelfService Plus help says "Classic Support is available 24/5 ... For prioritized, 24/7 help, purchase the Premium Support package" and gives only a sales address ([help](https://www.manageengine.com/products/self-service-password/help/admin-guide/Admin/Support.html)). The store pricing pages for ADMP carry no support SKU ([pricing](https://www.manageengine.com/products/ad-manager/pricing-details.html)). So it is **quote-only**; price and whether it is a percentage of licence value are `[UNVERIFIED]`.
- **TAM offering:** the only Technical Account Manager programme found is "Enterprise Business Solutions" for **Endpoint Central** (aimed at 2,000+ computers, no price stated) ([EBS](https://www.manageengine.com/products/desktop-central/ebs.html)). Not found for the AD products as of 2026-10-02.
- **Phone conflict:** product pages list toll-free numbers (e.g., ADMP/AD360 US +1 844 245 1108), but the table above makes phone Premium-only `[UNVERIFIED in practice]` (https://www.manageengine.com/products/ad-manager/support.html).
- **EULA:**
  - Perpetual licences exclude "technical support, including… product updates, upgrades, service packs, email and phone support", so AMS is required for updates.
  - Renewal is due "at least 10 days before the expiry".
  - Zoho may audit on "seven (7) days prior written notice".
  - Source: https://www.manageengine.com/eula.html (undated)

### 5.6 Professional services, training, certification, community

- **OnboardPro** (formerly Custom Onboarding) covers AD360, ADMP, ADSSP, ADAP, EventLog Analyzer and Log360. It is delivered by "in-house implementation experts" (https://www.manageengine.com/onboarding/manageengine-onboardpro-iam-and-siem-professional-service.html).
  - Standard tier caps include AD360 "up to 5 domains", 5 templates, 5 workflows, and ADAP "up to 10 devices".
  - Advanced adds AD migration, PostgreSQL→MS SQL, HA, SSO, hardening, HCM/ITSM integration, UAT.
  - Active "up to 6 months". "A refund can't be processed after the service has been purchased."
  - Claims "500+ Organizations across 25+ countries".
  - Store prices: §1.4 and §6.7.
- **Certification (MECP):**
  - Exam fees per product: **Associate $49, Professional $99, Expert $149** (AD360, ADAP, ADMP, ADSSP, ERP and Log360 at Associate/Professional; Expert for ADAP, ADMP, ADSSP, ERP; PAM360 at Professional) (store JSON https://store.manageengine.com/api/public/json/productdetails/2d0c11f975430385e0b2ba09be81c052.js).
  - Format: proctored over WebEx, open book, 70% pass (60% Associate), valid 1–2 years (https://www.manageengine.com/training/certification.html).
  - **Free four-day online workshop series** (AD/Exchange/M365); attending all sessions earns a free MECPA exam (https://www.manageengine.com/products/ad-manager/free-online-workshop.html).
- **Community:** Pitstop forums on Zoho Desk carry build announcements and bug threads; no member counts are visible (https://pitstop.manageengine.com/portal/en/community/ad360).
- **Docs:** multilingual help with no "last updated" dates. Several system-requirement pages are stale (e.g., RMP lists Windows Server 2008–2022 hosts).

---

### 5.7 Certifications and attestations (T-0001, checked 2026-10-02)

Source kind: vendor compliance centre ([compliance](https://www.manageengine.com/compliance.html)). Scope wording is the vendor's.

| Attestation | Stated scope | Valid to / type |
|---|---|---|
| ISO/IEC 27001 | "All cloud services and on-premise products of ManageEngine" | to 21-Aug-2028 |
| ISO/IEC 27701 | All business units, cloud services and on-premise products of ManageEngine and Site24x7 | to 21-Aug-2028 |
| ISO/IEC 27017, 27018 | All cloud services of ManageEngine | to 21-Aug-2028 |
| ISO 9001:2015 | All cloud services and on-premise products | to 02-Feb-2029 |
| ISO 22301 | Cloud services and on-premise products, plus support/NOC/DC functions | to 20-Nov-2026 |
| SOC 2 | "All cloud services and on-premise products of ManageEngine" | Type II |
| SOC 2 + HIPAA | ServiceDesk Plus, ServiceDesk Plus Cloud, Endpoint Central, **ADManager Plus**, Endpoint Central MSP | Type 2, audit 01-Dec-2023 to 30-Sep-2024 |
| TX-RAMP | ServiceDesk Plus Cloud (Level 1); Endpoint Central Cloud and Site24x7 (Level 2) | to 20-Jun-2027 |
| CSA STAR | All cloud services | Self-assessment |
| ENS (Spain), Saudi NCA CST (Class B), Cyber Essentials Plus | as stated on the page | various |

- **FedRAMP: not listed.** No FedRAMP authorisation appears on the compliance centre or on ADManager Plus's certification page ([ADMP help](https://www.manageengine.com/products/ad-manager/help/compliance/standards-and-certifications.html)). This is "not found as of 2026-10-02", not proof that no product has one; a third-party summary claiming ADSelfService Plus is "FedRamp compliant" is unsupported by those pages. For a US-federal customer, ask the vendor.
- **Among the AD products only ADManager Plus is named in a product-level attestation.** ADAudit Plus, ADSelfService Plus, AD360, RecoveryManager Plus and M365 Manager Plus are covered only by the company-wide "all on-premise products" wording. In a battlecard say exactly that; do not say "ADAudit Plus is SOC 2 certified".
- **Implication:** activeDIQ will need its own ISO 27001 and SOC 2 Type II to match the "Tier-0 vendor" bar (customer-voice file §6.2). That is a roadmap and cost item for the CEO, not a research finding.

## 6. Commercial-model analysis

### 6.1 Pricing philosophy (observed)

1. **Low, public, self-serve list prices** with small entry tiers ("starts at $595"). Prices rise in **infrastructure units and admin seats** (domains, DCs, servers, technicians, farms, admins + keys) more than per end user. ADSSP, M365MP, ERP, RMP and Identity360 are the per-user exceptions.
2. **Fixed perpetual formula.** Licence = **2.5× annual subscription**; AMS = **20% of licence per year**; year-1 AMS is a required line item.

   | Product | Annual subscription | Perpetual licence | AMS/yr |
   |---|---|---|---|
   | ADMP Std 1 domain + 2 techs | $595 | $1,485 | $297 |
   | ADAP Std 2 DCs | $595 | $1,488 | $298 |
   | RMP 250 users | $475 | $1,188 | $238 |
   | ERP Std 100 mailboxes | $345 | $863 | $173 |
   | SPMP Std 1 farm | $945 | $2,363 | $473 |
   | PAM360 10 admins | $7,995 | $19,995 | $3,999 |

   - Source: store JSON (§6.2).
   - Log360's perpetual runs about 3×. M365MP's runs 2.1–2.6×.
3. **A shift to subscription-only.** ADSSP and AD360 have no perpetual SKU in the store. ADMP's pricing page says "Annual subscriptions", though the store still sells ADMP perpetual. Identity360 is "annual billing only".
4. **Modular upsell.** Editions plus add-ons (GRC, backup, Endpoint MFA, SMS, failover, File Analysis, Entra tenants, NAS). Std→Pro at the same tier adds +59% (ADAP, 2 DCs: $595→$945) up to +202% (ADMP, 1 domain + 2 techs: $595→$1,795). ADSSP 500 users is +101%; ERP and M365MP at 100 are +72%.
5. **No suite discount at list** (§1.4). Bundles are negotiated `[UNVERIFIED]`.

### 6.2 List-price reference for the core trio (USD, annual subscription)

**ADManager Plus** (https://store.manageengine.com/api/public/json/productdetails/271df144c01e92cc3a126bdcbeb072fc.js; perpetual https://store.manageengine.com/api/public/json/productdetails/bb1ae90104fd94db40376ccf2d696d06.js)

| 1 domain + technicians | Standard | Professional | Perpetual Std / Pro (licence + AMS/yr) |
|---|---|---|---|
| 0 (admin only) | — | $795 | — / $1,985 + $397 |
| 2 | $595 | $1,795 | $1,485 + $297 / $4,485 + $897 |
| 5 | $1,195 | $3,345 | $2,988 + $598 / $8,385 + $1,677 |
| 10 | $2,295 | $5,995 | $5,738 + $1,148 / $14,988 + $2,998 |
| 20 | $4,395 | $10,595 | $10,988 + $2,198 / $26,488 + $5,298 |
| Additional domain | $345 | $595 | $900 + $180 / $1,500 + $300 |

- Add-ons: GRC $495 (Pro only). Backup & Recovery: $195 for 250 user objects → $2,295 for 5,000.
- **Technicians are the price driver.** In Pro, going from 0 to 2 technicians adds $1,000/yr (~$500 per technician per year). Objects per domain are unlimited.

**ADAudit Plus** (https://store.manageengine.com/api/public/json/productdetails/a4e670c116c71e630f623a894e884aaa.js; https://www.manageengine.com/products/active-directory-audit/pricing-details.html)

| Meter | Tiers (Std / Pro where they differ) |
|---|---|
| Domain controllers | 2: $595 / $945 · 5: $1,195 / $1,795 · 10: $2,145 / $3,495 · 15: $3,395 / $5,095 · 20: $4,395 / $6,595 (>20 by quote) |
| Windows member servers | 5: $345 · 10: $595 · 20: $945 · 50: $1,995 · 100: $3,295 (>100 by quote) |
| Windows file servers | 2: $495 · 5: $1,045 · 10: $1,995 · 15: $2,845 · 20: $3,595 |
| NAS file servers | 1: $595 · 2: $995 · 3: $1,395 · 5: $2,195 |
| Workstations (Windows/Mac) | 100: $245 · 250: $595 · 500: $945 · 1,000: $1,795 |
| Entra ID tenants | 1: $995 · 2: $1,695 · 3: $2,295 · 5: $3,495 |
| AD Backup & Recovery | 250 users: $195 → 5,000: $2,245 |
| File Analysis | 2 TB: $145 → 50 TB: $1,495 |

**ADSelfService Plus** (https://store.manageengine.com/api/public/json/productdetails/8456ab1a3c1b977fe84a44505c8dc85e.js; https://www.manageengine.com/products/self-service-password/pricing-details.html)

| Users | 500 | 1,000 | 1,500 | 2,000 | 3,000 | 5,000 |
|---|---|---|---|---|---|---|
| Standard | $595 | $1,195 | $1,745 | $2,195 | $3,145 | $4,995 |
| Professional | $1,195 | $2,195 | $2,895 | $3,495 | $4,695 | $6,995 |
| Endpoint MFA (Std / Pro) | $495 / $995 | $995 / $1,895 | $1,445 / $2,695 | $1,795 / $3,395 | $2,495 / $4,695 | $3,495 / $6,795 |

- More than 5,000 users is by quote.
- Other add-ons: Failover & Secure Gateway $395/yr. SMS credits (perpetual): $595 for 2,000 → $20,395 for 100,000.
- The store still lists a legacy edition-agnostic "Endpoint MFA" SKU running to **20,000 users at $3,995** and **Unlimited at $9,995**. That is the only public data point showing how steeply ME prices compress at enterprise scale.

### 6.3 Estimated typical spend: ADMP + ADAP + ADSSP (Estimate)

**Assumptions (illustrative, not customer data):**

| Scenario | Users | AD domains | ADMP technicians | DCs (licensed tier) | Member servers audited | Windows file servers | Workstations audited |
|---|---|---|---|---|---|---|---|
| A | 1,000 | 1 | 5 | 4 (5-DC tier) | 20 | 2 | none (optional) |
| B | 5,000 | 2 | 10 | 10 | 50 | 5 | none |
| C | 20,000 | 3 | 20 | 20 | 100 | 10 | none |

**ADSSP at 20,000 users is unpublished, so it is extrapolated as a range:**
- **Low:** 5,000-user price × 1.60. The 1.60 ratio is the legacy Endpoint MFA SKU's 20k/5k step ($3,995 ÷ $2,495). Std $4,995 × 1.60 ≈ $7,998; Pro $6,995 × 1.60 ≈ $11,200.
- **High:** 5,000-user price × 4 (no volume discount). Std $19,980; Pro $27,980.

**Results (annual subscription, list):**

| Scenario | Edition | ADMP | ADAP (DCs + servers + file servers) | ADSSP | **Total/yr** | Per user/yr | Per user/month |
|---|---|---|---|---|---|---|---|
| A 1k | Std | $1,195 | $1,195 + $945 + $495 = $2,635 | $1,195 | **$5,025** | $5.03 | $0.42 |
| A 1k | Pro | $3,345 | $1,795 + $945 + $495 = $3,235 | $2,195 | **$8,775** | $8.78 | $0.73 |
| B 5k | Std | $2,295 + $345 = $2,640 | $2,145 + $1,995 + $1,045 = $5,185 | $4,995 | **$12,820** | $2.56 | $0.21 |
| B 5k | Pro | $5,995 + $595 = $6,590 | $3,495 + $1,995 + $1,045 = $6,535 | $6,995 | **$20,120** | $4.02 | $0.34 |
| C 20k | Std | $4,395 + 2×$345 = $5,085 | $4,395 + $3,295 + $1,995 = $9,685 | $7,998–$19,980 | **$22,768–$34,750** | $1.14–$1.74 | $0.09–$0.14 |
| C 20k | Pro | $10,595 + 2×$595 = $11,785 | $6,595 + $3,295 + $1,995 = $11,885 | $11,200–$27,980 | **$34,870–$51,650** | $1.74–$2.58 | $0.15–$0.22 |

**Pro with common add-ons:** 1 Entra tenant audit $995, ADSSP Pro Endpoint MFA, and ADMP GRC $495.
- A: $8,775 + $995 + $1,895 + $495 = **$12,160/yr** ($12.16 per user/yr).
- B: $20,120 + $995 + $6,795 + $495 = **$28,405/yr** ($5.68 per user/yr).
- C: tier-dependent, all by quote.

**ME full-stack equivalent:** Pro trio + add-ons + RMP AD backup + M365MP Pro. This is the right anchor for an activeDIQ "Complete" tier.
- A: $12,160 + RMP 1,000 users $1,195 + M365MP Pro 1,000 users $2,395 = **$15,750/yr** ($15.75 per user/yr).
- B: $28,405 + RMP 5,000 users $4,995 + M365MP Pro 5,000 users $7,995 = **$41,395/yr** ($8.28 per user/yr).
- Exchange Reporter Plus, Entra backup, SharePoint and endpoint workstation auditing would add more.

**5-year subscription totals:**
- A: Std $25,125; Pro $43,875.
- B: Std $64,100; Pro $100,600.
- C: Std $113,840–$173,750; Pro $174,350–$258,250.

**Cross-check against ME's own SaaS price:** Identity360 Pro is $7,250 at 1,000 users and $25,000 at 5,000 users per year (§1.5). That is roughly the same per user as the on-prem trio in Pro, with far less AD-management and audit depth. ME's cloud pricing therefore sets a ceiling activeDIQ can benchmark against.

**Caveats:**
- At 20,000 users nearly every meter is "by quote", so real enterprise deals will be negotiated below list `[UNVERIFIED discount levels]`.
- Workstation auditing (≥1,000 workstations is by quote), NAS, extra tenants, HA and SMS can each add 5–30%.
- Infrastructure is not included (§6.7).

### 6.4 Perpetual vs subscription maths (Professional, ADMP + ADAP only; ADSSP is subscription-only)

| Scenario | Perpetual licence | AMS/yr (20%) | Year-1 cost | 5-yr perpetual (licence + 5 × AMS) | 5-yr subscription | Licence ÷ annual subscription |
|---|---|---|---|---|---|---|
| A | $16,474 | $3,296 | $19,770 | $32,954 | $32,900 | 2.50× |
| B | $32,827 | $6,567 | $39,394 | $65,662 | $65,625 | 2.50× |
| C | $59,202 | $11,842 | $71,044 | $118,412 | $118,350 | 2.50× |

**General rule:**
- Perpetual year 1 = 2.5S + 0.5S = **3.0S**, and each later year = **0.5S** (S = annual subscription).
- Cumulative cost equals subscription at year 5 (3.0 + 0.5 × 4 = 5.0) and is cheaper from year 6.
- **Implication:** long-tenured perpetual customers pay only ~50% of the subscription price each year in AMS. That is the hardest base to displace on price, so the pitch to them is TCO, risk and UX, timed to the AMS renewal.

### 6.5 Renewal dynamics

- **Subscription renews at list unless negotiated.**
  - ADAP DC tiers are unchanged from **Jan 2021 → Feb 2023 → Apr 2025 → Oct 2026**: 2 DCs $595/$945 and 5 DCs $1,195/$1,795 in every snapshot (https://web.archive.org/web/20210119131228/https://www.manageengine.com/products/active-directory-audit/pricing-details.html ; https://web.archive.org/web/20230202140504/https://www.manageengine.com/products/active-directory-audit/pricing-details.html ; https://web.archive.org/web/20250430193019/https://www.manageengine.com/products/active-directory-audit/pricing-details.html).
  - **Add-ons move.** The 10-tenant Azure AD tier went $3,595 (2021) → $5,995 (2023), and 20 tenants $5,995 → $9,995. The live page now lists only up to 5 tenants.
- **Cloud SKUs reprice sharply.** Identity360 went up 2.6–4.5× in Aug 2026 (§1.5). Log360 has a "new licensing model" (Mar 2026), and Log360 Cloud moved to per-infrastructure licensing (May 2026) (§7).
- **Tier cliffs.**
  - ADMP Pro 10→20 technicians: $5,995 → $10,595 (+77%).
  - Beyond 20 DCs, 100 servers, 20 file servers, 1,000 workstations, 5 tenants, or 5,000 ADSSP/M365MP/RMP users, pricing goes to quote.
- **Licence enforcement:**
  - ADSSP blocks the portal for users beyond the licence and **skips machine-logon MFA** for them.
  - RMP blocks rollback, bulk restore and settings edits when over licence.
  - Log360 13073 "automatically restricts monitored devices once the licence limit is reached".
- **AMS lapse.** Per the EULA, perpetual licences get no updates or support without AMS. Reinstatement fees are not public `[UNVERIFIED]`. Renewal is due ≥10 days before expiry.

### 6.6 How licensing is counted, and where customers get surprised

| Product | Counting rule (quoted or paraphrased) | Surprise risk | Source |
|---|---|---|---|
| ADMP | Licensed by domains, technicians and edition. "Necessary to purchase separate licenses for child domains." Technician licence is **named**: "consumed when a user account is configured in the product." Unlimited objects. Admin included | Multi-domain forests; named-seat creep; Pro needed for workflows, automation, GPO/OU/group management, HCM, AD migration | https://www.manageengine.com/products/ad-manager/licensing-faq.html ; https://www.manageengine.com/products/ad-manager/pricing-details.html |
| ADAP | Per server, DC and device. NAS counted per CIFS server, zone (Isilon), FSx file system, vStore (Huawei), storage account (Azure), Nutanix Files, or Edge Filer (CTERA) | **Standard lacks GPO-settings audit, old/new value attribute audit, AD permission-change audit, DNS auditing and MS SQL support**, so enterprises effectively need Pro (+59% on DC tiers). 6+ separate meters | https://www.manageengine.com/products/active-directory-audit/pricing-details.html (edition table parsed 2026-10-02) |
| ADSSP | "A whole license is consumed" when a user first initiates an action: reset, unlock, portal or endpoint logon with MFA, logon-script enrolment, admin quick-enrolment, or technician creation. Global, not per-feature, licensing | Over the limit, users see "license limit has been exceeded". **Machine-logon MFA is skipped for the extra users** (a security gap). Endpoint MFA, SMS and failover are separate add-ons | https://www.manageengine.com/products/self-service-password/licensing-faq.html |
| M365MP | Users/mailboxes. Shared, guest and resource mailboxes free since 4820. 1 technician included | Extra technicians and >5,000 users by quote | §3.1 |
| ERP | Mailboxes, with Manage/Unmanage toggles | Paying twice for EXO coverage alongside M365MP | §3.2 |
| RMP | Enabled AD users; pure Entra users; mailboxes; SPO "sites and sub-sites"; Zoho team folders need every member licensed | Subsite counting; Zoho; count-based retention growth | §2.3 |
| AD360 | Sum of components; one licence file applied in each product console | No bundle discount; minimums conflict across collateral | §1.4 |
| Backup (cross-product) | Sold in RMP, ADMP, ADAP, Log360 and AD360 add-ons | **Double-buying** | §4.7 |

### 6.7 Hidden TCO (beyond licences)

- **Infrastructure (customer-borne, not priced here):**
  - Windows Server hosts, with ≥2 servers for the trio and ≥4 for the full suite, 44–108 GB RAM (§1.3).
  - MS SQL licences if moving off bundled PostgreSQL. This is needed for ADAP MS SQL support, which is Pro-only.
  - Storage for audit and backup data.
  - An HA node (ADSSP failover $395/yr; HA configuration services $295).
- **Services:**
  - Per-product onboarding: $3,495 (Standard online) / $4,995–$6,995 (Advanced online) / $9,995 (Advanced onsite).
  - AD360 onboarding: $6,995 / $11,495 / $14,995.
  - Training: $995 per 4 hours (≤5 people).
  - Custom work: $195/hour.
  - The ADMP store shows Advanced online at $4,995 in one SKU and $6,995 in another `[inconsistent]`.
  - Sources: ADMP onboarding JSON https://store.manageengine.com/api/public/json/productdetails/0a54c22a516b00024109597321bab729.js ; AD360 JSON §1.4.
- **Operations:** customers patch 3–7 products on independent cadences. Security-fix load in 2025–2026 was material: ADAP 8511 (8 SQLi + auth bypass), ADSSP 7001 (RCE, SAML XSW bypass), ADMP 8043 (RCE via CSV), CVE-2026-11374 across the suite (§7). This is admin time that ME's list price does not show.

---

## 7. Roadmap signals 2025–2026

Status: **[S]** shipped (release notes) · **[A]** announced · **[M]** marketing/analyst · **[E]** event · **[R]** vendor roadmap, undated.

| Date | Signal | Product(s) | Theme | Source |
|---|---|---|---|---|
| 2026-10-08/09 | [E] UserConf Orlando: "product roadmap sessions", identity and AI tracks. **Next catalyst to watch** | All | Roadmap | https://www.manageengine.com/blog/general/manageengine-userconf-2026-is-heading-to-orlando.html |
| 2026-09-30 | [S] **ADAP build 9000:** Attack Analyzer (wider coverage, whitelists, real-time alerts); **non-human identity auditing** (service accounts, gMSA, certificate auth); Access Analyzer (attack paths, effective permissions); Attack Surface Analyzer for **Cloud (CSPM: Azure/AWS/GCP)** and **SaaS (SSPM: Microsoft)**; tracks identities "used by AI agents and automation". Verified by direct fetch | ADAP | ITDR, ISPM, NHI | https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html |
| 2026-09-16/18 | [E/A] GISEC Dubai: Zia Agents ("access reviews, alert correlation, investigations"); "Identity Access" newest addition to Identity360 | Identity360, Zia | Cloud IAM, AI | https://securitymea.com/?p=68562 |
| 2026-08-25 | [S] Identity360 major release: directory-independent access, conditional access, endpoint MFA (incl. sudo), offline MFA, PIV/CAC; **Identity Access SKU** and edition repricing | Identity360 | Cloud, passwordless | https://www.manageengine.com/identity-360/release-notes.html |
| 2026-08-21 | [S] ADSSP 7001: fixes for logon-agent RCE and privilege escalation, SAML XSW auth bypass, REST API auth bypass; drops 32-bit and TLS 1.0/1.1 | ADSSP | Security debt | https://www.manageengine.com/products/self-service-password/release-notes.html |
| 2026-07-30 | [S] ADAP 8710 **Advanced Recovery** (agentless point-in-time AD object restore) | ADAP | Recovery convergence | ADAP RN (above) |
| 2026-07-06 | [S] ADMP 8043: fix for RCE via CSV with embedded PowerShell (latest ADMP build) | ADMP | Security | https://www.manageengine.com/products/ad-manager/release-notes.html |
| 2026-06-30 | [S] Log360 5570: migration to **"Unified Log360"** (ADAP, ADMP, M365MP, ERP, DSP, PAM360, UEBA in "a single interface") | Log360 | **Platform consolidation** | https://www.manageengine.com/log-management/readme.html |
| 2026-06-30 | [A] ManageEngine Marketplace launched with Zia Agents (17+ partner developers, 170+ extensions); no identity product named | Suite | Ecosystem, AI | https://www.manageengine.com/news/manageengine-marketplace-launch.html |
| 2026-06-13 | [S] ADSSP 7000: **Microsoft Entra ID support**, with SSPR "without requiring a Microsoft Entra ID P1 or P2 license", phishing-resistant MFA, conditional access | ADSSP | Cloud, price attack on Microsoft | ADSSP RN (above) |
| 2026-06 | [S] CVE-2026-11374 (AD360 SSO ticket prediction → account takeover) fixed across components | AD360 seam | Security | §1.3 |
| 2026-05-22 | [A] **Zia Agents** across the suite: Agent Studio, multi-agent orchestration, MCP support; "customer data is never used to train any AI model". **No identity-specific agents named** | Suite | Agentic AI | https://securitybrief.co.uk/story/manageengine-rolls-out-autonomous-ai-agents-across-suite |
| 2026-05-20 | [S] Log360 Cloud: Ask Zia, Zia Agent Studio, **MCP via the Zoho MCP Server** (usable from Copilot, Claude, Cursor). ADAP 8700: M365 and Entra risk reports | Log360 Cloud, ADAP | AI, MCP | https://www.manageengine.com/log-management/cloud/features-new.html |
| 2026-05-16 | [S] Log360 Cloud moves to infrastructure-based licensing | Log360 Cloud | Pricing | same |
| 2026-04-14/17 | [S] **Alert Investigation Agent** ("LLM-driven reasoning to autonomously investigate") in Log360 Cloud and on-prem 13050 | Log360 | Agentic SOC | https://www.manageengine.com/log-management/readme.html |
| 2026-04-21 | [S] PAM360 8540: Azure OpenAI, Anthropic, Google, DeepSeek, SiliconFlow and **self-hosted LLMs** | PAM360 | AI (BYO-LLM) | https://www.manageengine.com/privileged-access-management/release-notes.html |
| 2026-03-30 | [S] Log360 13025 "Introduced a new licensing model" | Log360 | Pricing | Log360 readme |
| 2026-01-30 | [S] AD360 4504 (Duo library). **Latest AD360 shell build** | AD360 | Shell in maintenance | https://www.manageengine.com/active-directory-360/release-notes.html |
| 2026-01-21 | [S] ADMP 8034 Marketplace Extensions (third-party connectors) | ADMP | Ecosystem | ADMP RN |
| 2026-01-08 | [S] ADAP 8600: File Analysis becomes a **licensed add-on** | ADAP | Add-on monetization | ADAP RN |
| 2026-01-06 | [M] Identity Security Outlook 2026: machine-to-human identities 100:1; 36% consolidating IAM vendors; "True consolidation is not about stitching together acquired tools" | Suite | NHI, consolidation messaging | https://www.manageengine.com/news/manageengine-enterprise-identity-security-2026-study.html |
| 2025-11-21 | [M] KuppingerCole ITDR Market Leader, **evaluated on AD360 + PAM360 + Log360** | 3 products | ITDR | §5.3 |
| 2025-10-30 | [S] **ADMP 8030:** Zia AI assistant (natural-language actions and reports) and Zia Insights (membership anomalies). **Advanced Recovery** for AD and Entra. Zia **requires the customer's own Azure OpenAI endpoint and key** | ADMP | AI, recovery convergence | https://www.manageengine.com/products/ad-manager/help/admin-settings/zia-configuration.html |
| 2025-09-16 | [S] Log360 13000: re-engineered detection architecture | Log360 | SIEM, ITDR overlap | Log360 readme |
| 2025-08-26 | [S] Log360 Cloud v7.9: 94 AD/Windows correlation actions, 32 new AD reports, LDAP/Netlogon/replication audits. **The SIEM is absorbing AD auditing** | Log360 Cloud | Overlap with ADAP | https://www.manageengine.com/log-management/cloud/features-new.html |
| 2025-07-22 | [A] AD360 PR: **Identity Risk Exposure Management** (graph-based privilege-escalation and lateral-movement paths), **Local User MFA**, ML access recommendations, wider access certification | AD360 (ADMP, ADSSP) | ITDR, ISPM | https://www.manageengine.com/news/ad360-identity-security.html |
| 2025-07-21 | [S] ADSSP 6517: FIDO2 passkeys for machine logon (Windows, macOS offline, Linux) | ADSSP | Passwordless | ADSSP RN |
| 2025-07-17 | [A] Zoho launches **Zia LLM** (1.3B/2.6B/7B, hosted in Zoho DCs), Agent Studio and an MCP server; ManageEngine not mentioned | Zoho | AI platform | https://www.zoho.com/news/zoho-launches-zia-llm-and-deepens-ai-portfolio-with-prebuilt-agents-custom-agent-builder-mcp-and-marketplace.html |
| 2025-07-02 | [S] ADMP 8020: Risk Exposure Management; **Governance tab** (risk, access certification); 48 risk indicators; dynamic groups | ADMP | ISPM, IGA | ADMP RN |
| 2025-05-08 | [A] PAM360: AI least-privilege policies (CIEM), AI session summaries, Qntrl-based JIT | PAM360 | AI, JIT | https://itwire.com/business-it-news/enterprise-solutions/manageengine-adds-native-intelligence-and-advanced-automation-capabilities-to-its-unified-pam-platform |
| 2025-04-03 | [S] ADSSP 6513: PIV/YubiKey smart-card auth for VPN, OWA, Windows | ADSSP | Phishing-resistant MFA | ADSSP RN |
| 2025-03-25 | [A] AD360: 100+ prebuilt integrations | AD360 | Ecosystem | https://www.manageengine.com/news/ad360-iam-integrations.html |
| 2025-01-31 | [S] ADAP 8500: Attack Surface Analyzer (GPO misconfiguration), Intune and Windows LAPS auditing | ADAP | ISPM | ADAP RN |

**Undated roadmaps and current-state checks**
- [R] **Identity360 roadmap** is effectively ADMP + ADAP + ADSSP rebuilt as SaaS: GPO management, domain migration, AD auditing with real-time alerts, access certification, SoD, JIT, PAM, attack paths (https://www.manageengine.com/identity-360/roadmap.html).
- [R] **PAM360 roadmap:** AI Assistant and "Contextual MCP Security Connectors" in progress; "Privileged Threat Detection & Response" yet to start (https://www.manageengine.com/privileged-access-management/roadmap.html).
- **MCP servers page** lists ServiceDesk Plus, Endpoint Central, Site24x7, MDM Plus, CloudSpend, Log360 Cloud and Analytics Plus. **There is no AD, AD360 or Identity360 MCP server** (https://www.manageengine.com/mcp-servers.html). That is absence on the page, not a commitment.
- No public roadmap pages exist for ADMP, ADAP, ADSSP or AD360 (guessed URLs return 404).
- **CISA KEV:** no ManageEngine CVEs were added in 2025–2026. Older KEV entries include ADSSP CVE-2021-40539, CVE-2022-28810 and multi-product CVE-2022-47966 (https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json).

**Synthesis**
1. **There are two identity tracks.** Deep features ship on-prem first (ADAP 9000 is the biggest release in the window). Identity360 is the SaaS successor, but its AD-parity items are undated. Expect a "move to Identity360" pitch to AD360 customers. Today it is roadmap, not product.
2. **ITDR and ISPM are real and shipped, but split across products.** Risk graphs are in ADMP. Attack, access and surface analyzers are in ADAP. Detection and response are in Log360. Analyst ITDR credit needs **three products**.
3. **AI in the AD line is assistive and BYO-key.** Agentic capabilities ship in Log360, cloud first. No identity agents or AD MCP server yet. This is an opening for activeDIQ.
4. **Cloud:** ADSSP now covers Entra and undercuts Entra P1/P2 on SSPR. Identity360 adds directory-independent MFA. There is **no AD360 SaaS signal**.
5. **Consolidation starts with Log360.** "Unified Log360" is the template; the AD360 shell is barely evolving.
6. **Monetization tightens.** New Log360 licensing, per-infrastructure cloud meters, File Analysis as an add-on, Identity360 repricing.
7. **Feature convergence drives SKU overlap.** AD rollback is now in ADMP, ADAP and RMP. AD auditing is in ADAP, Log360 and Log360 Cloud.
8. **Security debt is a factual sales angle.** 2025–2026 brought multiple RCE, SQLi and auth-bypass fixes, and CVE-2026-11374 sits at the suite seam. None are KEV-listed in that window.

---

## 8. Implications for activeDIQ

### 8.1 Pricing and packaging: how to beat them

**Facts the model must respect**
- ME's licence price is very low: ADMP + ADAP + ADSSP list is $0.42–$0.73 per user per month at 1k users and $0.21–$0.34 at 5k (§6.3).
- ME's own SaaS (Identity360) sits at $0.60–$0.73 per user per month at 1k users.
- We will not win a pure licence-price comparison against perpetual customers paying 20% AMS (~0.5× subscription per year).

**Recommended model: one platform SKU, per-identity, no infrastructure meters.**
1. **Meter only enabled human identities.** Include unlimited domains, child domains, DCs, servers, file servers, tenants and technicians. That removes the 6+ meters behind ME's surprises (§6.6). Do not meter non-human identities, or price them at a nominal rate, so NHI growth (100:1 per ME's own study) never becomes a bill shock.
2. **Use 2–3 tiers that map to ME's product lines, so procurement can compare line by line:**
   - **Core:** replaces ADMP + ADSSP. Lifecycle, delegation, workflows, reports, SSPR/unlock, MFA for SSPR.
   - **Complete:** Core + ADAP + RMP + M365MP/ERP equivalents. Auditing/ITDR, AD/Entra rollback, M365/Exchange.
   - **Enterprise:** Complete + governance (certification, SoD, risk), endpoint/offline MFA, long audit retention, premium support.
   - Include in tier everything ME sells as an add-on: Endpoint MFA, HA, GRC, Entra tenant audit, backup.
3. **Price corridor (proposal, to validate with the CEO's accounts).**
   - Price **Complete** at or below ME's *trio* fully-loaded Pro list, which is well below ME's *full-stack* equivalent (§6.3).
   - At 1k users: ~$12 per user/yr, against ME's trio at $12.16 and full stack at $15.75.
   - At 5k users: ~$5.5–6 per user/yr, against ME's trio at $5.68 and full stack at $8.28.
   - Volume tiers fall toward ~$2–3 per user/yr at 20k, where ME is all by quote.
   - Then win on TCO, which our price excludes for ME: hosts, SQL, onboarding, patching.
   - Use Identity360's Aug 2026 list ($7.25 per user/yr Pro at 1k; $5.00 at 5k) as ME's own valuation of cloud IAM, which has less AD depth than our Complete tier.
4. **Displacement terms:**
   - Co-term credit for remaining ME subscription.
   - **Migration included** (ME charges $3,495–$14,995 onboarding).
   - 90-day parallel run at no cost.
   - **3-year price lock**, citing Identity360's 2.6–4.5× repricing (§1.5) as the risk being removed.
5. **Perpetual-base play:** time outreach to the AMS renewal date. Show a 3-year TCO that includes Windows/SQL hosts, patching effort across 3–7 products, onboarding and HA. Offer a self-hosted or sovereign option for buyers who chose ME for on-prem reasons.
6. **Avoid ME's nickel-and-dime patterns:** SMS at cost pass-through, failover included, no named-technician seats, no per-NAS-vendor counting units.

### 8.2 Switching-cost reducers (build these, not just sell them)

- **Config importers:** ADMP user-creation templates, workflows, automation policies, help-desk roles/OU scopes; ADAP alert profiles and report schedules; ADSSP policies (OU/group scope, enabled features); M365MP virtual tenants. ME stores these in per-component PostgreSQL/MS SQL databases (§1.3). Plan read-only DB/export adapters `[TODO: confirm export formats with a customer instance]`.
- **Audit-history continuity:** import or federate historical ADAP and M365MP audit data for the compliance retention period, or provide a read-only "legacy archive" view. Otherwise customers keep ME running just for retention.
- **MFA re-enrolment is the biggest end-user switching cost.** Support the same authenticator families (TOTP apps, Microsoft/Google Authenticator, Duo, YubiKey/FIDO2, smart cards), use enrol-on-next-login nudges, and offer coexistence where ADSSP's agent and ours do not conflict on endpoints `[TODO: test credential-provider coexistence]`.
- **Agent swap kit:** ADAP agents on DCs, servers and workstations, the ADSSP logon agent, and the RMP DC agent. Ship MSI/GPO deployment and a removal checklist.
- **Report-parity pack:** map ME's top reports (ADMP "200+", ADAP, M365MP "700+") to activeDIQ equivalents for RFP checklists.
- **SSO cut-over:** re-point SAML apps from ADSSP or Identity360 with bulk metadata import.

### 8.3 Where a unified product wins (from AD360's integration seams)

| ME seam (evidence) | Unified activeDIQ advantage |
|---|---|
| 7 products, 8 web servers/ports, N+1 databases, ≥4 servers, ~98 GB RAM (§1.3) | One deployment: SaaS or a single self-hosted service with lightweight connectors. Days, not an onboarding project |
| AD360 aggregates reports from only 3 components over REST; launcher UI with embedded component dashboards | One identity graph (AD + Entra + M365 + Exchange + Google) answers "who has access, how did they get it, what changed, roll it back" on one screen |
| "Who changed it" in ADAP, "restore it" in RMP/ADMP/ADAP, "approve it" in ADMP workflows (§2.4, §4.7) | A closed loop: detect → attribute → roll back → open a workflow, as one action with one audit trail |
| Per-component technician settings; AD360-level roles only Admin/Operator; SPMP joined Dec 2025 (§1.3) | One RBAC and delegation model across every object type and tenant, no seat licences |
| Inter-product "CustomSSO" tickets → CVE-2026-11374 account takeover | No cross-product trust boundary to attack. Single session and authorization model |
| 3–7 independent patch cadences; recurring RCE/SQLi/auth-bypass fixes (§7) | One release train, continuous delivery. Security posture becomes a differentiator, stated factually |
| ITDR credit needs AD360 + Log360 + PAM360 (§5.3) | ITDR, ISPM and response native in one product and one licence |
| Zia assistant needs the customer's Azure OpenAI key; no AD MCP server (§7) | An AI assistant and agent over the unified identity graph, with an MCP server for AD/Entra operations, shipped as first-class features |
| Same capability in up to 7 SKUs (§4.7) | One licence, so "already paid for" is never a blocker for using a feature |

### 8.4 Guardrails for sales and RFP use

- **Don't overclaim ME gaps.** ADAP 9000 (CSPM/SSPM, NHI, attack paths), ADSSP (Entra, FIDO2, offline MFA) and Identity360 (Aug 2026) are current and capable. Compare against those dates.
- **Cite CVEs factually** (number, build, date, vendor text). Don't characterize ME as "insecure".
- **Use ME's list prices with the date** (2026-10-02) and "list". Enterprise deals are discounted `[UNVERIFIED]`.
- **Respect where ME is strong:** price, breadth, on-prem and offline support, many authenticators, analyst market presence, 300+ partners, perpetual option, MSP editions.

---

## Appendix A: Gaps (resolved and remaining)

### Resolved in T-0001 (2026-10-02)

- **Premium Support price / TAM:** confirmed not public, quote-only; TAM exists only for Endpoint Central (§5.5).
- **Discount levels:** one third-party aggregate for ManageEngine overall (§1.4); PACE partner terms are not public beyond the 15% affiliate commission and $100 minimum (re-read 2026-10-02: [PACE](https://www.manageengine.com/pace/) lists no Alliance or OEM discount levels).
- **Config and audit export formats (importer feasibility):** none of ADMP, ADAP or ADSSP documents an export of configuration to an open format. All three use a proprietary password-protected `.ezip` database backup restored with `restoreDB.bat`; ADAP and ADSSP require the same build on restore; ADSSP's KB does not mention exporting enrollment data. Details: ADMP file (ADM-158 and "Resolved gaps"), ADAP file §7a option 6, ADSSP file §9. M365 Manager Plus was **not** checked in this pass `[TODO]`.
- **Credential-provider coexistence (ADSSP agent):** the vendor's Sept 2025 guide says the ADSSP login agent is "an extension of the standard credential provider from Microsoft", warns that "some of these extensions may not be compatible with others", and supports six named third-party providers (ZENworks Endpoint Security Agent, Parallels Client, Toshiba Logon Provider, Cisco NAC Agent, OneX Credential Provider, RSA SecurID) by passing the other provider's GUID to the MSI at install time or editing registry settings ([guide](https://download.manageengine.com/products/self-service-password/integration-with-third-party-winlogon-extensions.pdf)). It also states prerequisites: Endpoint MFA is required for MFA on Windows logons, and the Professional edition for password reset on the logon screen. So coexistence with a third-party CP is **supported by procedure, per ManageEngine**, but nothing says it has been tested with an activeDIQ provider. A lab test is needed before we promise OU-by-OU coexistence `[TODO: lab]`.
- **Certifications / FedRAMP:** §5.7.
- **Peer-review ratings:** Gartner Peer Insights for AD360 shows 4.6 from 281 ratings in a 2026-10-02 search snippet (the earlier Wayback figure was 275); the page itself still returns 403 `[UNVERIFIED: snippet]`. Capterra shows 4.6 from 35 reviews, fetched live 2026-10-02 ([Capterra](https://www.capterra.com/p/268487/ManageEngine-AD360/)).

### Remaining gaps

- `[TODO]` Real-world enterprise discount ranges for AD products and partner (PACE Alliance/OEM) margins. Needs customer quotes or a partner conversation; the CEO's warm accounts are the best source, and any vendor or partner contact needs CEO approval.
- `[TODO]` Premium Support price. Quote-only; requires contacting sales.
- `[UNVERIFIED]` Identity360 grandfathering for pre-Aug-2026 customers, Identity360 free tier (conflict described in §1.4), AD write-back from Identity360, whether "Unified Log360" is a template for AD360, PMP end-of-sale, M365MP multi-tenant counting, RMP "user vs shared mailbox" counting, the AD360 $5/$10 "additional technician" SKUs. None can be settled from public pages; each needs a quote or vendor answer.
- `[TODO]` M365 Manager Plus config and audit export formats; credential-provider lab test (above).
- `[TODO]` Gartner Peer Insights for RMP: no source reachable.

## Appendix B: Method notes

- **Store prices** were read from `store.manageengine.com/api/public/json/productdetails/<category-id>.js`. Category IDs come from https://store.manageengine.com/js/indc-newstorecatglist.js. Pages checked include ADMP, ADAP, ADSSP, AD360, RMP, ERP, M365MP, SPMP, DSP, Log360, PAM360, PMP, M365 Security Plus, EDLP, MECP, and onboarding SKUs.
- **Price history:** Wayback snapshots of the ADAP pricing page (2021–2025) and Identity360 pricing (2024–2025).
- **PDFs:** text was extracted locally from the AD360 QSG and solution-architecture PDFs. Page references (QSG pp.) use the PDF's own page numbering.
- **Research split:** work was done across parallel research threads. Every claim carries a primary URL. Release-note claims for AD360, RMP (6330/6321/6313), M365MP (4817), ADAP (9000/8710/8600) and Identity360 pricing were re-verified by direct fetch on 2026-10-02.

## Changelog

- **2026-10-02 (T-0001):** Added §5.7 certifications; closed support, discount, export-format, credential-provider and rating gaps where public sources allow; re-tagged the rest in Appendix A.
