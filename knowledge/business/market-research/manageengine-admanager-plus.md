---
title: "Competitive Benchmark: ManageEngine ADManager Plus"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: heramb
sources_last_checked: 2026-10-02
---

# Competitive Benchmark: ManageEngine ADManager Plus

> **Scope.** ManageEngine ADManager Plus ("ADMP"): the on-prem Active Directory (AD), Microsoft 365, Exchange and Google Workspace management, reporting, automation and identity-governance product. Researched 2026-10-02.
> **Latest build:** 8043, released 2026-07-06 ([release notes](https://www.manageengine.com/products/ad-manager/release-notes.html)). The public demo reports product version **8.0.0, build 8041 (64-bit)** ([demo](https://demo.admanagerplus.com/), observed 2026-10-02).
> **Tags:** `[UNVERIFIED]` means a primary source did not confirm it. `[TODO]` means it was not researched. **n/s** means the vendor does not say which edition includes the feature. "Std" = Standard edition, "Pro" = Professional edition.

## Key takeaways

All facts as of 2026-10-02; prices are list prices before discounts.

1. **Breadth and platform.** ADMP spans 11 top-level areas: vendor-claimed 200+ reports, workflow, automation/orchestration, GRC (governance, risk and compliance) and backup. It runs on Windows only.
   - Server stack: Java (Zulu JRE 11) on Apache Tomcat 9, Struts 1.3.11, bundled PostgreSQL. Browser UI: Ember.js and jQuery ([architecture PDF](https://download.manageengine.com/products/ad-manager/solution-architecture.pdf), [third-party list](https://www.manageengine.com/products/ad-manager/help/third-party-software.html), [release notes](https://www.manageengine.com/products/ad-manager/release-notes.html)).
   - The Microsoft 365 tab loads as a separate Ember app in an iframe (`/ompemberapp/ompindex.html`) with its own navigation layout ([demo](https://demo.admanagerplus.com/) observation).
2. **Price structure (USD).**
   - Standard starts at US$595/yr (1 domain + 2 help-desk technicians). Professional starts at US$795/yr (1 domain, admin only) and is US$10,595/yr with 20 technicians.
   - Every extra domain costs US$345/yr (Std) or US$595/yr (Pro), **including child domains**.
   - Above 20 technicians, pricing is by quote only.
   - Add-ons: GRC is US$495/yr (Pro only). Backup is US$195–2,295/yr depending on user count.
   - Sources: [pricing](https://www.manageengine.com/products/ad-manager/pricing-details.html), [licensing FAQ](https://www.manageengine.com/products/ad-manager/licensing-faq.html).
3. **Licensing terms that matter in deals.**
   - **API metering:** the REST API allows 50 successful calls per technician license per day. Extra calls are sold at US$1 per call/day ([KB, updated 2026-06-14](https://www.manageengine.com/products/ad-manager/admanager-kb/fix-daily-api-limit-exceeded.html)). ServiceNow and ServiceDesk Plus actions use the same REST APIs ([ServiceNow doc](https://www.manageengine.com/products/ad-manager/help/admin-settings/third-party-integrations/servicenow.html)).
   - **Standard edition scope:** excludes group, OU, contact and GPO management, report scheduling, OU-based delegation, workflow and automation ([edition table](https://www.manageengine.com/products/ad-manager/pricing-details.html)).
4. **Security defaults and CVE history, as documented.**
   - Defaults: the console runs on HTTP unless HTTPS is configured ([data-security PDF](https://download.manageengine.com/products/ad-manager/encryption-and-data-storage-in-admanager-plus-database.pdf)). First login uses admin/admin ([help](https://www.manageengine.com/products/ad-manager/help/getting_started/starting_admanager_plus.html)). The built-in admin can skip 2FA ([help](https://www.manageengine.com/products/ad-manager/help/admin-settings/two-factor-authentication.html)). TLS 1.0 and 1.1 remain selectable until an admin enforces secure TLS ([help](https://www.manageengine.com/products/ad-manager/help/admin-settings/security-and-privacy-settings-admanager-plus.html)).
   - **Attribution:** with "Impersonate as Admin", domain-controller logs record the service account, not the technician ([help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/group-based-delegation.html)).
   - **CVEs:** 6 CVEs published 2024–2026 cite ADMP (5 on NVD, plus CVE-2024-0252, which ADMP's release notes list as fixed in build 7223). Build 8042 fixed three more (ZVE-2026 IDs) and build 8043 fixed a remote-code-execution issue. The CISA KEV-listed CVE-2022-47966 affected ADMP before build 7162 (details in §2.10).
5. **Usability evidence** (details in §4).
   - The Management › User Management landing page shows about 64 action links.
   - The console mixes Ember routes with full-page server-rendered `.do` forms.
   - In the demo, the Create Single User page was 10.4 MB of HTML and took about 20 s to DOMContentLoaded (indicative).
   - CSV import needs LDAP attribute names as headers and DN-formatted `memberOf`/manager values.
   - In 2026 Capterra reviews, users cite the interface's look and the learning curve (attributed in §4).
6. **AI scope.**
   - Zia (build 8030, Oct 2025) offers four chat actions (enable, disable, unlock, reset password) plus object reports. It requires the customer's own Azure OpenAI key ([Zia help](https://www.manageengine.com/products/ad-manager/help/admin-settings/zia-configuration.html)).
   - Also: ML access recommendations, anomaly detection on technician activity, and Zia Insights in AD Explorer.
7. **Release pace.**
   - 2025: 15 releases, with roughly quarterly feature releases (risk exposure management, dynamic groups, rollback recovery, Zia, marketplace).
   - 2026: 6 releases Jan–Jul, mostly fixes and security updates. No release between 2026-07-06 and 2026-10-02 ([release notes](https://www.manageengine.com/products/ad-manager/release-notes.html)).
8. **Deployment model.**
   - No vendor-hosted SaaS edition is documented on the product, store or help pages. ADMP is installed on-prem or self-hosted on Azure/AWS VMs.
   - ManageEngine's cloud-native IAM is a separate product, Identity360 ([Identity360](https://www.manageengine.com/identity-360/)).
   - This is a positioning opening for activeDIQ (§7c).

## Method and confidence

- **Primary sources:**
  - manageengine.com product and feature pages, release notes, KB articles and API docs.
  - The help docs, whose navigation tree lists 390 topics ([help](https://www.manageengine.com/products/ad-manager/help/)).
  - The public JSON price feeds behind store.manageengine.com, and vendor PDFs.
- **Public demo:** logged in through the demo's one-click "Administrator Login" (Professional, build 8041). Navigation was walked and page loads measured with the browser's Navigation Timing API. Timings are **indicative only**: the demo is shared, and timings include network distance.
- **Secondary sources:** Capterra (4.6/5, 111 reviews) and PeerSpot (4.0/5, 16 reviews).
  - G2, TrustRadius and Gartner Peer Insights returned HTTP 403, and Reddit blocked automated access. Their sentiment is **[TODO]** and needs a manual pass.
  - The session's web-search budget ran out mid-research, which limited discovery of third-party commentary.
- **Copyright:** review and vendor text is paraphrased. There is one short direct quote.

---

## 1. Overview, editions and pricing

### 1.1 Positioning

- **Headline positioning:** ADMP sells itself as a unified AD + Microsoft 365 management and reporting tool ([product page](https://www.manageengine.com/products/ad-manager/)). The store page now describes it as an enterprise **IGA** (identity governance and administration) product: AD management plus access certification, risk assessment, risk exposure management, identity lifecycle management, workflow orchestration and integrations ([store](https://store.manageengine.com/ad-manager/get-quote.html)).
- **Vendor claims:** over 100,000 technicians use ADMP, and it ships 200+ prebuilt reports ([product page](https://www.manageengine.com/products/ad-manager/)).
- **Place in the ManageEngine portfolio:**
  - ADMP is a component of the AD360 suite. Since build 7232, AD360 can manage ADMP technicians centrally ([release notes](https://www.manageengine.com/products/ad-manager/release-notes.html)).
  - Sister products cover adjacent needs:
    - ADAudit Plus: auditing.
    - ADSelfService Plus: self-service password reset (SSPR) and MFA.
    - RecoveryManager Plus: backup.
    - M365 Manager Plus: Microsoft 365.
    - SharePoint Manager Plus: SharePoint.
    - Log360: SIEM.
  - ManageEngine says it was named a Market Leader in KuppingerCole's 2024 IGA Leadership Compass and appears in Gartner's 2024 Market Guide for IGA ([Identity360 page](https://www.manageengine.com/identity-360/)). These are vendor claims and are not independently verified here.

### 1.2 Editions

| Edition | What it is | Limits / notes | Source |
|---|---|---|---|
| **Free** | Standard-edition features | 100 domain objects. Default domain only. No GPO settings report. | [licensing help](https://www.manageengine.com/products/ad-manager/help/getting_started/licensing_admanager_plus.html), [pricing](https://www.manageengine.com/products/ad-manager/pricing-details.html) |
| **Evaluation** | Full Professional edition for 30 days, add-ons included | 2 domains and 2 technicians. Turns into Free after 30 days. | [licensing FAQ](https://www.manageengine.com/products/ad-manager/licensing-faq.html) |
| **Standard** | AD user and computer management, 200+ reports, multi-domain, help-desk delegation, M365 and Exchange management/reporting, ITSM and SIEM integrations | **No:** file-server management; group, OU, contact or GPO management; report scheduling; OU-based administration; workflow; automation/orchestration; HCM integration; load balancing; AD migration. GRC add-on not available. | [edition comparison](https://www.manageengine.com/products/ad-manager/pricing-details.html) |
| **Professional** | Everything in Standard plus the items above | OU-, group-based, cross-domain and multi-domain delegation; M365 and Google Workspace delegation; technician-specific templates. AD migration is capped at 500 objects (support can raise the cap). | [pricing footnotes](https://www.manageengine.com/products/ad-manager/pricing-details.html) |
| **MSP** (separate SKU) | Multi-tenant edition for service providers | Priced by domain users + help-desk technicians | [store JSON](https://store.manageengine.com/api/public/json/productdetails/5134984a9b1cf47b2bbd69cfb0c36a08.js) |
| *"Premium"* | **Signal only** | The get-quote page's HTML contains a commented-out "Premium" column with a tick on every feature row, including GRC and Backup (inference: a planned or retired all-inclusive tier). **[UNVERIFIED]** whether this tier exists or will ship. | [get-quote page source](https://store.manageengine.com/ad-manager/get-quote.html) |

**Add-ons**

- **Backup and Recovery** (Std or Pro): licensed by enabled user objects. Buying for X users covers X AD **and** X Entra ID **and** X Google Workspace users.
  - Without the add-on, AD and Entra ID backup still runs with limits: weekly backups only, one domain, no full backup, no bulk restore, no manual incremental backups, and settings cannot be edited.
  - Without the add-on, Google Workspace backup is capped at 5 users ([licensing FAQ](https://www.manageengine.com/products/ad-manager/licensing-faq.html)).
- **Governance, Risk and Compliance (GRC)** (Pro only): identity risk assessment, risk exposure management, access certification campaigns, and a central entitlements overview ([licensing FAQ](https://www.manageengine.com/products/ad-manager/licensing-faq.html)).

### 1.3 List prices before discounts (USD, US store, as of 2026-10-02)

Prices come from the public JSON feeds behind the store pages and cross-check against the pricing page:

- Subscription: [feed](https://store.manageengine.com/api/public/json/productdetails/271df144c01e92cc3a126bdcbeb072fc.js), [store](https://store.manageengine.com/ad-manager/).
- Perpetual: [feed](https://store.manageengine.com/api/public/json/productdetails/bb1ae90104fd94db40376ccf2d696d06.js), [store](https://store.manageengine.com/ad-manager/perpetual.html).
- Cross-check: [pricing page](https://www.manageengine.com/products/ad-manager/pricing-details.html).

Outside the US, prices include a currency-purchase margin, according to the pricing page.

**Annual subscription** (includes support and maintenance)

| 1 domain, unlimited objects | Standard | Professional |
|---|---|---|
| Admin only (no help-desk technicians) | not offered | **$795** |
| + 2 help-desk technicians | **$595** | $1,795 |
| + 5 technicians | $1,195 | $3,345 |
| + 10 technicians | $2,295 | $5,995 |
| + 20 technicians | $4,395 | $10,595 |
| Each additional domain | $345 | $595 |
| GRC add-on | not offered | $495 |
| More than 20 technicians | quote | quote |

**Perpetual license + annual maintenance and support (AMS)**

The perpetual license is about 2.5× the annual subscription price. AMS is 20% of the license per year, and the first year of AMS is included.

| Configuration | Std license | Std AMS/yr | Pro license | Pro AMS/yr |
|---|---|---|---|---|
| Admin only | — | — | $1,985 | $397 |
| 2 technicians | $1,485 | $297 | $4,485 | $897 |
| 5 technicians | $2,988 | $598 | $8,385 | $1,677 |
| 10 technicians | $5,738 | $1,148 | $14,988 | $2,998 |
| 20 technicians | $10,988 | $2,198 | $26,488 | $5,298 |
| Additional domain | $900 | $180 | $1,500 | $300 |
| GRC add-on | — | — | $1,238 | $248 |

**Backup and Recovery add-on** (same price for Std and Pro)

| Users | Subscription/yr | Perpetual + AMS/yr |
|---|---|---|
| 250 | $195 | $488 + $98 |
| 500 | $295 | $738 + $148 |
| 1,000 | $495 | $1,238 + $248 |
| 2,000 | $995 | $2,488 + $498 |
| 3,000 | $1,445 | $3,613 + $723 |
| 5,000 | $2,295 | $5,738 + $1,148 |

**Services** ([onboarding feed](https://store.manageengine.com/api/public/json/productdetails/0a54c22a516b00024109597321bab729.js))

- Standard onboarding, online: $3,495.
- Advanced onboarding, online: listed at $4,995 on the onboarding listing but $6,995 on the subscription page's add-on list (**inconsistent**).
- Advanced onboarding, onsite: $9,995.
- 4-hour online training: $995. Training add-on: $495.
- HA configuration: $295. Help-desk integration: $295.
- HRMS integration, custom scripts and custom features: $195/hour.

**MSP edition (annual)** ([feed](https://store.manageengine.com/api/public/json/productdetails/5134984a9b1cf47b2bbd69cfb0c36a08.js))

- Domain users: 500 for $995; 1,000 for $1,795; 2,000 for $3,195; 5,000 for $6,995.
- Help-desk technicians: 1 for $195; 5 for $995; 10 for $1,495.
- Backup uses the same tiers as above. GRC is $495.

### 1.4 Price at several sizes (annual list price, computed from the tables above)

| Scenario | Configuration | ADMP list price/yr | Daily API quota¹ |
|---|---|---|---|
| Small, single domain | Std, 1 domain, 2 technicians | $595 | 100 calls |
| SMB service desk | Pro, 1 domain, 5 technicians | $3,345 | 250 calls |
| Mid-market | Pro, 1 domain, 10 technicians + GRC + Backup (1,000 users) | $5,995 + $495 + $495 = **$6,985** | 500 calls |
| Multi-domain enterprise | Pro, 3 domains (root + 2 child), 20 technicians + GRC + Backup (5,000 users) | $10,595 + 2×$595 + $495 + $2,295 = **$14,575** | 1,000 calls |
| Large help desk | > 20 technicians | quote only | 50 × technicians |

¹ 50 successful API calls per technician license per day ([KB](https://www.manageengine.com/products/ad-manager/admanager-kb/fix-daily-api-limit-exceeded.html)).

**5-year total cost of ownership, Pro, 1 domain, 10 technicians**

- Subscription: 5 × $5,995 = $29,975.
- Perpetual: $14,988 + 4 × $2,998 AMS = $26,980.
- Cumulative costs cross in year 4: $23,980 subscription vs $23,982 perpetual.

### 1.5 Licensing gotchas (useful for sales)

| # | Gotcha | Source |
|---|---|---|
| 1 | Licensed **per domain**. Child domains need their own licenses, and there is no forest-wide license. | [licensing FAQ](https://www.manageengine.com/products/ad-manager/licensing-faq.html) |
| 2 | Technician licenses are **named**. A license is used up as soon as a user account is configured as a technician. With group-based delegation, members are configured at login ([architecture PDF](https://download.manageengine.com/products/ad-manager/solution-architecture.pdf)); that each member then consumes a license at first login is an inference **[UNVERIFIED]**. | [licensing FAQ](https://www.manageengine.com/products/ad-manager/licensing-faq.html) |
| 3 | **Single-installation license**: one server only. One license cannot cover installs in several locations. | [licensing FAQ](https://www.manageengine.com/products/ad-manager/licensing-faq.html), [license terms](https://www.manageengine.com/products/ad-manager/license.html) |
| 4 | Features cannot be bought individually; you buy a whole edition even if you need one feature. | [licensing FAQ](https://www.manageengine.com/products/ad-manager/licensing-faq.html) |
| 5 | Standard excludes group, OU, contact and GPO management, scheduling, workflow, automation and OU delegation. Moving to Pro costs about 3× at the 2-technician tier ($595 → $1,795). | [pricing](https://www.manageengine.com/products/ad-manager/pricing-details.html) |
| 6 | **API metering**: 50 successful calls per technician per day. Extra calls cost US$1 per call/day for the rest of the license term. ITSM integrations draw from the same quota. | [KB](https://www.manageengine.com/products/ad-manager/admanager-kb/fix-daily-api-limit-exceeded.html), [SDP doc](https://www.manageengine.com/products/ad-manager/help/admin-settings/third-party-integrations/servicedeskplus.html) |
| 7 | GRC is Pro-only. Backup is a separate per-user add-on; without it, backup has documented limits (weekly only, one domain, no bulk restore). | [licensing FAQ](https://www.manageengine.com/products/ad-manager/licensing-faq.html) |
| 8 | AD migration is capped at 500 objects unless support raises the cap. | [pricing footnote](https://www.manageengine.com/products/ad-manager/pricing-details.html) |
| 9 | Licenses must be renewed at least 10 days before expiry. Evaluation licenses convert to the Free edition (100 objects) after 30 days. Expired paid licenses may also fall back to Free: in-product UI string keys suggest it, but it is **[UNVERIFIED]**. | [license terms](https://www.manageengine.com/products/ad-manager/license.html), [licensing help](https://www.manageengine.com/products/ad-manager/help/getting_started/licensing_admanager_plus.html), [demo](https://demo.admanagerplus.com/) |
| 10 | More than 20 technicians, or counts between price tiers, require a quote. Non-US prices carry a currency margin. | [pricing](https://www.manageengine.com/products/ad-manager/pricing-details.html) |

### 1.6 On-prem vs cloud

- **On-prem only:** ADMP ships as a Windows EXE and installs on any Windows machine in the domain ([install help](https://www.manageengine.com/products/ad-manager/help/getting_started/installing_admanager_plus.html)).
- **Cloud = self-hosting on IaaS VMs:** ManageEngine documents running ADMP yourself on Azure or AWS ([AWS](https://www.manageengine.com/products/ad-manager/access-admanager-plus-from-aws.html), [Azure](https://www.manageengine.com/products/ad-manager/host-manageengine-admanager-plus-on-microsoft-azure.html)). No vendor-hosted SaaS edition is documented on the product, store or help pages as of 2026-10-02.
- **Signal only:** the help site has an "On Premises / Cloud" toggle, but all 390 help topics are tagged "common" and no cloud-only topics appear in the help navigation as of 2026-10-02 ([help](https://www.manageengine.com/products/ad-manager/help/)). **[UNVERIFIED]** whether a cloud edition is coming.
- **ManageEngine's cloud play is Identity360**, a separate cloud-native IAM product with a Universal Directory, SCIM provisioning, MFA and SSO ([Identity360](https://www.manageengine.com/identity-360/)).

---

## 2. Deployment architecture and technology

### 2.1 Platform and runtime

| Area | Detail | Source |
|---|---|---|
| Server OS | Windows Server 2008 R2 through 2025 (2025 supported since build 8010). Windows client OSes (7–11) are also listed. 64-bit only since build 8001. | [system requirements](https://www.manageengine.com/products/ad-manager/help/getting_started/system_requirements.html), [release notes](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| Hardware | Minimum: 2 cores / 4 GB RAM / 5 GB disk on physical hardware, or 4 vCPU / 6 GB on a VM. Recommended: 4 cores / 6 GB / 50 GB, or 6 vCPU / 8 GB on a VM. More is needed when many scheduled reports and automations run in parallel, or with the Backup add-on. | [system requirements](https://www.manageengine.com/products/ad-manager/help/getting_started/system_requirements.html) |
| Install modes | Runs as a desktop application (with the logged-on user's privileges) or as a Windows service (runs as the system account) | [install help](https://www.manageengine.com/products/ad-manager/help/getting_started/installing_admanager_plus.html) |
| Front end | HTML/CSS/JS, jQuery plugins, **Ember.js**. The demo also mixes full-page server-rendered `.do` forms (e.g., `ExecuteForm.do`) with Ember routes. | [architecture PDF](https://download.manageengine.com/products/ad-manager/solution-architecture.pdf), [demo](https://demo.admanagerplus.com/) |
| Back end | Java plus native C and C#, with JSP server-side rendering. The bundled third-party list includes **Struts 1.3.11**, DWR 2.0.2, Velocity, JasperReports, OpenSAML 2.6.1 and Bootstrap 3.x. Runtime is **Zulu JRE 11.86.19** (JRE 1.8 before build 8040) and **Apache Tomcat 9.0.x** (9.0.118 as of build 8043). | [architecture PDF](https://download.manageengine.com/products/ad-manager/solution-architecture.pdf), [third-party list](https://www.manageengine.com/products/ad-manager/help/third-party-software.html), [release notes](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| Directory access | LDAP/LDAPS via ADSI/native Windows APIs. PowerShell (including remoting on 5985/5986) for Exchange and for actions that run commands on DCs. Microsoft Graph for M365 (MSOnline module retired in build 8012). Google Admin SDK for Google Workspace. | [architecture PDF](https://download.manageengine.com/products/ad-manager/solution-architecture.pdf), [release notes](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| Database | Bundled **PostgreSQL** (15.18 in build 8043; port 33306, reachable from localhost only) or **MS SQL Server 2005–2022**, including Always On availability groups and failover cluster instances (since build 7240). Also supported: external PostgreSQL and Azure SQL / AWS / Cloud SQL. | [system requirements](https://www.manageengine.com/products/ad-manager/help/getting_started/system_requirements.html), [help: database migration](https://www.manageengine.com/products/ad-manager/help/migration/migrating-from-existing-postgresql-microsoft-sql-database-to-azure-sql-or-aws-sql.html), [data-security PDF](https://download.manageengine.com/products/ad-manager/encryption-and-data-storage-in-admanager-plus-database.pdf) |
| Search/backup store | Embedded **Elasticsearch** (port 9280), secured with Search Guard certificates. It stores backup data and search indexes; older backups are moved to local or NAS archives. | [architecture PDF](https://download.manageengine.com/products/ad-manager/solution-architecture.pdf), [data-security PDF](https://download.manageengine.com/products/ad-manager/encryption-and-data-storage-in-admanager-plus-database.pdf) |
| Data freshness | ADMP keeps a cached copy of AD in its database. **AD sync runs every 10 minutes and the dashboard refreshes daily**; reports read from the database. | [architecture PDF](https://download.manageengine.com/products/ad-manager/solution-architecture.pdf) |
| Browsers | IE 10+, Edge, Chrome, Firefox. Minimum resolution 1366×768. | [system requirements](https://www.manageengine.com/products/ad-manager/help/getting_started/system_requirements.html) |
| Supported targets | Exchange 2016+. Lync 2010/2013 and Skype for Business 2015+. Microsoft 365. Google Workspace. NAS: NetApp, Isilon, Huawei OceanStor. | [system requirements](https://www.manageengine.com/products/ad-manager/help/getting_started/system_requirements.html) |
| Upgrades | Manual service-pack installs. Optional automatic hotfix install (checks daily at 11 pm; not available with HA). | [security hardening help](https://www.manageengine.com/products/ad-manager/help/admin-settings/security-and-privacy-settings-admanager-plus.html) |

### 2.2 Ports

| Port | Purpose | Source |
|---|---|---|
| 8080 / 8443 | Web console over HTTP / HTTPS. **HTTPS is not enabled by default.** | [architecture PDF](https://download.manageengine.com/products/ad-manager/solution-architecture.pdf), [data-security PDF](https://download.manageengine.com/products/ad-manager/encryption-and-data-storage-in-admanager-plus-database.pdf) |
| 389/636, 3268/3269, 88, 135, 139, 445, 464, 49152–65535, 5985/5986 | LDAP/LDAPS, Global Catalog, Kerberos, RPC, NetBIOS, SMB, password change, dynamic RPC, PowerShell remoting | [system requirements](https://www.manageengine.com/products/ad-manager/help/getting_started/system_requirements.html), [architecture PDF](https://download.manageengine.com/products/ad-manager/solution-architecture.pdf) |
| 25; 80/443 | SMTP; Exchange (80); Microsoft 365 and Google Workspace (80/443) | [system requirements](https://www.manageengine.com/products/ad-manager/help/getting_started/system_requirements.html) |
| 33306, 9280, 9380, 7800+ | Bundled PostgreSQL, Elasticsearch, cluster traffic between nodes, load-balancer service | [architecture PDF](https://download.manageengine.com/products/ad-manager/solution-architecture.pdf), [load-balancer help](https://www.manageengine.com/products/ad-manager/help/admin-settings/enterprise-essentials/active-directory-load-balancing.html) |

### 2.3 Service accounts and privileges

- **AD:** ManageEngine recommends a Domain Admins account. The alternative is a least-privilege service account set up by hand with Delegation of Control steps, documented operation by operation in a PDF guide ([permissions PDF](https://download.manageengine.com/products/ad-manager/permissions-required-for-the-ad-account-configured-in-admanager-plus.pdf), [architecture PDF](https://download.manageengine.com/products/ad-manager/solution-architecture.pdf)).
  - Restoring deleted objects requires manual `dsacls` grants on the Deleted Objects container.
  - When ADMP is configured with a non-admin service account, restore operations prompt for write credentials ([backup help](https://www.manageengine.com/products/ad-manager/help/backup-restore/active-directory.html)).
- **Microsoft 365:**
  - A Global Admin consent flow auto-creates an Entra app registration; a manual app registration is also possible.
  - A separate M365 **service account** is still required for bulk MFA changes and for Teams policy packages ([tenant config](https://www.manageengine.com/products/ad-manager/help/directory-application-settings/microsoft-365-tenant-configuration.html)).
- **Google Workspace:** needs a Google Cloud project, Admin SDK, a service account with domain-wide delegation and a **P12 key**, set up by a Super Admin ([GWS settings](https://www.manageengine.com/products/ad-manager/help/directory-application-settings/google-apps-active-directory-management-tool.html)).
- **Exchange mailbox export:** needs the Mailbox Import Export role, plus share permissions for Exchange Trusted Subsystem ([delete policy help](https://www.manageengine.com/products/ad-manager/help/admin-settings/windows-active-directory-delete-policy.html)).

### 2.4 High availability, load balancing, scale and multi-site

- **High availability (HA):** active-passive. Two service instances share one database behind a virtual IP and must be on the **same subnet**. MS SQL is recommended, and HA can only be disabled from the standby server ([HA help](https://www.manageengine.com/products/ad-manager/help/admin-settings/high-availability.html)).
- **Load balancer with failover** (Pro, since build 8011):
  - A primary node plus secondary nodes share one database; scheduled jobs are pinned to one node.
  - All nodes must run the same build, protocol, time zone and permissions.
  - Turning on load balancing **disables HA and smart-card login**.
  - Sources: [load-balancer help](https://www.manageengine.com/products/ad-manager/help/admin-settings/enterprise-essentials/active-directory-load-balancing.html), [release notes](https://www.manageengine.com/products/ad-manager/release-notes.html).
- **Multi-site:** a single installation serves all sites. "Site-based delegation" only sets which domain controller is tried first for each OU ([help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/site-based-delegation.html)). Distributed collectors or agents are not documented in the help as of 2026-10-02.
- **DMZ / internet exposure:** open LDAP 389, RPC 135 and the dynamic RPC ports, and use SSL ([deployment scenarios](https://www.manageengine.com/products/ad-manager/help/getting_started/deployment_scenarios.html)).

### 2.5 Console sign-in security (SSO and MFA)

- **SAML SSO:** Okta, OneLogin, Ping Identity, AD FS, Entra ID or custom SAML. "Force SAML login" is available ([SSO help](https://www.manageengine.com/products/ad-manager/help/admin-settings/single-sign-on-authentication.html)).
- **NTLMv2 SSO:** since build 7162, the customer must download the **Jespa JAR** and place it in the product's `lib` folder (same source).
- **2FA:**
  - Methods: Duo (Web v4 SDK / Universal Prompt), Google Authenticator, Microsoft Authenticator, RSA SecurID (SDK or REST), email OTP, SMS.
  - "Trust this browser" for N days; selected technicians can be allowed to skip 2FA.
  - **The help states that the built-in admin is the only user with the option to skip 2FA.** A separate setting lets selected technicians skip it as well.
  - Source: [2FA help](https://www.manageengine.com/products/ad-manager/help/admin-settings/two-factor-authentication.html).
- **Other sign-in controls:**
  - Smart card / PKI certificate login ([help](https://www.manageengine.com/products/ad-manager/help/admin-settings/smart-card-authentication.html)).
  - CAPTCHA, IP allow/deny lists and lockout after failed logins ([help index](https://www.manageengine.com/products/ad-manager/help/)).
  - Concurrent-login restriction ([release notes, build 8033](https://www.manageengine.com/products/ad-manager/release-notes.html)).
  - FIDO2/passkey sign-in to the console is not documented in the 2FA or SSO help pages as of 2026-10-02.

### 2.6 Access control (RBAC) and delegation model

ADMP uses a **"non-invasive" proxy model**. Roles live inside ADMP and do not change the technician's rights in AD; ADMP checks each action, domain, OU, group and file server against the role before acting ([architecture PDF](https://download.manageengine.com/products/ad-manager/solution-architecture.pdf)).

- **Help-desk roles:**
  - Built from task-level and attribute-level privileges.
  - Optional flags: deny bulk modification, deny CSV import.
  - Report categories can be restricted per role.
  - Source: [delegation help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/active-directory-help-desk-delegation.html).
- **Scope:** by domain, OU, include/exclude groups, or by assigning a role to an AD group (group-based delegation) ([group-based help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/group-based-delegation.html)).
- **Built-in technicians:** Admin, Help desk and HR Associate. The Super Admin role cannot be changed ([architecture PDF](https://download.manageengine.com/products/ad-manager/solution-architecture.pdf)).
- **"Impersonate as Admin":** the technician's actions run under the configured service account. **Domain-controller security logs show the service account, not the technician**; per-technician attribution exists only in ADMP's own audit report ([help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/group-based-delegation.html), [architecture PDF](https://download.manageengine.com/products/ad-manager/solution-architecture.pdf)).
  - CVE-2025-11670 (NTLM hash exposure) was exploitable only by technicians with this option enabled ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-11670)).
- **Workflow roles** sit alongside delegation: requester, reviewer, approver and executor, plus requester roles (§3 module M).
- **Native AD "Security Roles"** are also available: ACL-based delegation written directly into AD ([help](https://www.manageengine.com/products/ad-manager/help/managing_security_roles/pre-defined_security_roles.html)).

### 2.7 REST API

- **v1 ("classic") endpoints:**
  - Users: search, create, delete, enable/disable, modify, move, reset password, unlock, add/remove groups.
  - Groups: list members, search, create, delete, move.
  - Computers: search, group membership, delete, enable/disable, move.
  - OUs: search, create, delete.
  - Also: list domains, update domain settings, remove authtokens, create workflow requests.
  - Source: [API index](https://www.manageengine.com/products/ad-manager/active-directory-api/).
- **v2:**
  - Root: `http://<host>:8080/api/v2`, with a downloadable **OpenAPI document**.
  - Methods: GET, POST, PATCH, DELETE. Offset pagination and a filter grammar.
  - Coverage: users and groups (list, update); computers (list, create, update, disable); contacts (full create/read/update/delete); OUs (list, update); orchestration (list templates, execute, get status); admin settings (environment variables and organization attributes).
  - Sources: [API v2 intro](https://www.manageengine.com/products/ad-manager/active-directory-api/v2/introduction/), [release notes, build 8030](https://www.manageengine.com/products/ad-manager/release-notes.html).
- **Limits:**
  - 100 GET requests/minute; 50 POST/PATCH/DELETE requests/minute ([API v2 intro](https://www.manageengine.com/products/ad-manager/active-directory-api/v2/introduction/)).
  - **Daily quota:** 50 successful calls per technician license ([KB](https://www.manageengine.com/products/ad-manager/admanager-kb/fix-daily-api-limit-exceeded.html)).
- **Auth:** per-technician authtokens with scope and expiry. Admins can create tokens for technicians, and each token records who created it ([authtoken help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/authtoken-management-in-admanager-plus.html)). The older Generate Authtoken API has been deprecated since January 2025 ([release notes](https://www.manageengine.com/products/ad-manager/release-notes.html)).
- **Not documented in the API v2 reference as of 2026-10-02:** endpoints for GPOs, Exchange, M365, workflow approvals, report export or backup.

### 2.8 Integrations

| Category | Integrations | Edition | Source |
|---|---|---|---|
| ITSM / help desk | ServiceNow (Store app, MID Server, several ADMP servers per instance), ServiceDesk Plus on-prem and Cloud, Zendesk, Jira (Atlassian Marketplace app), Freshservice, Zoho Desk, HaloITSM | Std+Pro | [integrations](https://www.manageengine.com/products/ad-manager/admanager-plus-integrations.html), [ServiceNow help](https://www.manageengine.com/products/ad-manager/help/admin-settings/third-party-integrations/servicenow.html) |
| HCM / HRMS | Workday, BambooHR, UKG Pro, SAP SuccessFactors, ADP Workforce, HiBob, Paycom, Dayforce (Ceridian), Personio, Zoho People, Oracle PeopleSoft, Darwinbox, Sage HR, TriNet Zenefits, Factorial HR, Replicon, AFAS, JazzHR, Calamari, Grove HR. Oracle HCM Cloud is not listed **[UNVERIFIED]**. A PeerSpot reviewer reports SAP HCM is not supported. | Pro | [HCM page](https://www.manageengine.com/products/ad-manager/hcm-integration.html), [integrations](https://www.manageengine.com/products/ad-manager/admanager-plus-integrations.html), [PeerSpot](https://www.peerspot.com/products/manageengine-admanager-plus-reviews) |
| Identity sources / other identity providers | JumpCloud, Okta Workforce Identity Cloud (listed alongside the HCM connectors) | n/s | [integrations](https://www.manageengine.com/products/ad-manager/admanager-plus-integrations.html) |
| Databases as identity sources | MS SQL, Azure SQL, Oracle, AWS SQL. Reads and write-back through scheduled queries; also usable for duplicate checks. | Pro **[UNVERIFIED]** | [integrations](https://www.manageengine.com/products/ad-manager/admanager-plus-integrations.html), [architecture PDF](https://download.manageengine.com/products/ad-manager/solution-architecture.pdf) |
| CSV / files | CSV files on a path as an automation data source, with an option to process only appended rows | Pro | [automation help](https://www.manageengine.com/products/ad-manager/help/automation/configuring-automation.html) |
| Custom apps | Any REST, SOAP or Graph API: inbound and outbound webhooks; auth via none, API key, Basic, Bearer or OAuth 2.0; pagination; dependent endpoints; JSON-path conditions. Predefined connectors: 60+ added Dec 2024, +50 in Oct 2025. | n/s | [custom apps help](https://www.manageengine.com/products/ad-manager/help/directory-application-settings/third-party-integrations/custom-applications.html), [release notes](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| Marketplace | `.ext` extensions (build 8040+). Only 5 are listed: Hubstaff, Admina, Classe365, Backlog, Clockify. | n/s | [extensions](https://www.manageengine.com/products/ad-manager/help/admin-settings/extensions.html), [supported list](https://www.manageengine.com/products/ad-manager/help/admin-settings/extensions/supported-extensions.html) |
| SIEM / logs | Syslog (TCP/UDP; RFC 3164, RFC 5424 or raw), Splunk, Rapid7, Log360 (including a SOAR workflow since build 7224), Power BI streaming dataset | Std+Pro | [syslog help](https://www.manageengine.com/products/ad-manager/help/admin-settings/third-party-integrations/syslog.html), [Power BI help](https://www.manageengine.com/products/ad-manager/help/admin-settings/third-party-integrations/power-BI-integration.html) |
| ManageEngine products | ADSelfService Plus (self-service approval workflow), PAM360, AD360, Log360 | n/s | [ADSSP help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/admp-and-adssp-integration.html), [PAM360 help](https://www.manageengine.com/products/ad-manager/help/admin-settings/third-party-integrations/pam360-integration.html) |
| Low-code | Zoho Flow for codeless HCM integration | n/s | [HCM page](https://www.manageengine.com/products/ad-manager/hcm-integration.html) |

### 2.9 Multi-domain and multi-forest

- **Domains:** child domains and domains in the same or other forests are all added the same way. Domain controllers can be auto-discovered and prioritized, and "DC sort intelligence" picks the fastest DC ([domain settings help](https://www.manageengine.com/products/ad-manager/help/directory-application-settings/connecting-to-a-domain.html)).
- **Microsoft 365 tenants:** domain-to-tenant links are many-to-many since build 8020 ([release notes](https://www.manageengine.com/products/ad-manager/release-notes.html)).
- **Cross-domain caveats:**
  - Templates support cross-domain `memberOf` only when the value comes from CSV ([templates help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_user_templates.html)).
  - The 2025–2026 release notes repeatedly fix cross-domain bugs: queued add/remove for cross-domain users, cross-domain managers, and clearing cross-domain memberships ([release notes](https://www.manageengine.com/products/ad-manager/release-notes.html)).
- **Forest migrations** across trusted forests are supported (Pro), capped at 500 objects (§3 module U).

### 2.10 Security posture

- **Encryption at rest:** AES-256-CBC for secrets (domain, mail and SMS credentials; tokens; M365 credentials). bcrypt with salt for built-in technician passwords ([data-security PDF](https://download.manageengine.com/products/ad-manager/encryption-and-data-storage-in-admanager-plus-database.pdf)).
- **End-user passwords in audit data:** the same PDF lists "End users password – Audit data" among items stored with AES-256 encryption. Inference: passwords set through ADMP are kept in audit data in recoverable form.
- **Passwords in notifications:** reset passwords can be sent by SMS or email notification. Build 8040 fixed an empty password field in the reset-password SMS ([release notes](https://www.manageengine.com/products/ad-manager/release-notes.html)).
- **Hardening:**
  - A security-hardening score covers HTTPS, the default admin password, 2FA, CAPTCHA, lockout, LDAPS, TLS, folder permissions and alerts ([help](https://www.manageengine.com/products/ad-manager/help/admin-settings/security-and-privacy-settings-admanager-plus.html)).
  - The demo instance scored **40%** in its license dialog ([demo](https://demo.admanagerplus.com/)).
  - Installs before build 7210 granted Authenticated Users access to the install folder in some cases; `SecureDeployment.exe` remediates this ([secure deployment help](https://www.manageengine.com/products/ad-manager/help/getting_started/deploying_admanager_plus_securely.html)).

**CVE history (2024–2026)**

| CVE / ID | Published | CVSS | Affected builds | Fixed in | Issue | Advisory / source |
|---|---|---|---|---|---|---|
| CVE-2024-0252 | 2024-01-11 | 8.8 (CNA) | ADMP < 7223 (inferred from release notes); the NVD record names ADSelfService Plus ≤ 6401 | ADMP 7223 (2024-01-22) | Authenticated remote code execution in the load-balancer component | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-0252), [ADMP release notes](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| CVE-2024-24409 | 2024-11-08 | 8.8 (CNA and NVD) | ≤ 7203 | 7210 | Privilege escalation: misconfigured built-in Modify Computers help-desk role | [vendor advisory](https://www.manageengine.com/products/ad-manager/admanager-kb/cve-2024-24409.html), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-24409) |
| CVE-2024-48878 | 2024-11-04 | 8.3 (CNA) / 8.8 (NVD) | ≤ 7241 | 7250 | Authenticated SQL injection in the Archived Audit Report | [vendor advisory](https://www.manageengine.com/products/ad-manager/admanager-kb/cve-2024-48878.html), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-48878) |
| CVE-2025-10020 | 2025-10-21 | 8.5 (CNA) / 8.8 (NVD) | < 8024 | 8024 | Authenticated command injection in the Custom Script component | [vendor advisory](https://www.manageengine.com/products/ad-manager/admanager-kb/cve-2025-10020.html), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-10020) |
| CVE-2025-11670 | 2025-12-15 | 6.4 (CNA) / 4.3 (NVD) | ≤ 8022 (vendor) / < 8025 (NVD) | 8025 | Service-account NTLM hash exposed to technicians with "Impersonate as Admin" | [vendor advisory](https://www.manageengine.com/products/ad-manager/admanager-kb/cve-2025-11670.html), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-11670) |
| CVE-2025-9435 | 2026-01-13 | 5.5 (CNA) | < 7230 | 7230 | Authenticated path traversal in User Management | [vendor advisory](https://www.manageengine.com/products/ad-manager/admanager-kb/cve-2025-9435.html), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-9435) |
| ZVE-2026-1924, -1941, -1981 | 2026-04-22 | not published | < 8042 | 8042 | Path traversal in report download; SQL execution via Orchestration Template; command execution while testing custom functions | [release notes](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| (no ID published) | 2026-07-06 | not published | < 8043 | 8043 | Remote code execution via CSV input containing embedded PowerShell (Microsoft 365 tab) | [release notes](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| CVE-2022-47966 (context) | 2023-01-18; CISA KEV since 2023-01-23 | 9.8 (NVD) | ADMP < 7162 (one of 24 ManageEngine products NVD lists); exploitable only where SAML SSO had ever been configured | 7162 | Unauthenticated remote code execution via Apache Santuario xmlsec 1.4.1 | [vendor advisory](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-47966) |

NVD returns 49 CVEs in total for the keyword "ADManager Plus" (NVD API query, 2026-10-02).

---

## 3. Feature inventory

**How to read this table**

- **Edition column:** "Std+Pro" and "Pro" follow the vendor's [edition comparison](https://www.manageengine.com/products/ad-manager/pricing-details.html). "+GRC" is the Governance, Risk and Compliance add-on (Pro only). "Backup add-on" is the per-user Backup and Recovery add-on. "n/s" means the vendor does not say which edition includes it, so treat it as **[UNVERIFIED]**.
- **Report counts** were taken from the Professional demo (build 8041) on 2026-10-02.
- **IDs** are stable: ADM-001 to ADM-213.

### A. Console and navigation
The web console itself: tabs, dashboard, search and object explorer.

| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADM-001 | Console | Tabbed web console | 11 top tabs (Home, Management, Reports, Microsoft 365, Governance, Delegation, Workflow, Automation, Admin, Backup, Support). Header: Zia, License, notifications, AD Explorer, TalkBack, global search, Directory/Application Settings. | Std+Pro (contents vary) | [demo](https://demo.admanagerplus.com/) |
| ADM-002 | Console | Home dashboard | Charts of AD statistics, key help-desk reports and canned reports; custom tabs, widgets and quick links; summary of workflow tickets | n/s | [help](https://www.manageengine.com/products/ad-manager/help/introduction/active-directory-dashboard-view.html) |
| ADM-003 | Console | Global object search | Search box in the header for users, groups, computers and other objects | n/s | [help](https://www.manageengine.com/products/ad-manager/help/user_management/searching_active_directory_users_groups_computers.html) |
| ADM-004 | Console | AD Explorer | Tree view of AD, like Windows Explorer; Properties, Security, Entitlements, Objects and History tabs for each object | n/s | [help](https://www.manageengine.com/products/ad-manager/help/introduction/exploring_active_directory_services.html) |
| ADM-005 | Console | Object change history | History tab lists attribute changes made through ADMP, plus decisions from access-certification campaigns | n/s | [help](https://www.manageengine.com/products/ad-manager/help/introduction/exploring_active_directory_services.html) |
| ADM-006 | Console | Employee (people) search | Corporate directory lookup on the login page; scope and attributes configurable; can be turned off | n/s | [help](https://www.manageengine.com/products/ad-manager/help/getting_started/deploying_admanager_plus_securely.html) |
| ADM-007 | Console | Localization | Help docs in English, Arabic, French and German. Release notes mention non-English UIs, including Japanese. | n/s | [help](https://www.manageengine.com/products/ad-manager/help/), [release notes](https://www.manageengine.com/products/ad-manager/release-notes.html) |

### B. User management
Creating and changing AD users, including mailbox and cloud accounts at creation time.

| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADM-008 | Users | Create single user | One form creates the AD account and, optionally, M365, Exchange, Google Workspace and Skype/Lync/OCS accounts | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_a_windows_user.html) |
| ADM-009 | Users | Cloud-only accounts | Creates M365 or Google Workspace accounts without an AD user | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_a_windows_user.html) |
| ADM-010 | Users | Bulk user creation wizard | 3 steps (add details → choose container → creation status); enter users manually or import CSV | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_multiple_windows_users.html), [demo](https://demo.admanagerplus.com/) |
| ADM-011 | Users | CSV import (create/modify) | Column headers must be LDAP attribute names; `memberOf` and manager as DNs; a `templateName` column applies a template | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_multiple_windows_users.html), [templates help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_user_templates.html) |
| ADM-012 | Users | User creation templates | Drag-and-drop form designer: per field, set visible, editable, mandatory, read-only or hidden; rename tabs. Assigning templates to specific technicians is Pro only. | Std+Pro (technician templates: Pro) | [help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_user_templates.html), [pricing footnote](https://www.manageengine.com/products/ad-manager/pricing-details.html) |
| ADM-013 | Users | Creation rules | Conditional rules that fill or update fields; hidden from technicians | n/s | [help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_user_templates.html) |
| ADM-014 | Users | Template bulk-edit and copy | Changes many templates at once; clone a template | n/s | [help](https://www.manageengine.com/products/ad-manager/help/user_management/active-directory-bulk-modify-user-creation-templates.html) |
| ADM-015 | Users | User modification templates | Rule-based attribute and group changes, e.g., add to "approvers" when title = manager | n/s | [help](https://www.manageengine.com/products/ad-manager/help/user_management/active-directory-user-modification-template.html), [automation help](https://www.manageengine.com/products/ad-manager/help/automation/active-directory-automation.html) |
| ADM-016 | Users | Copy user attributes | Pre-fills a new user (or a template) from an existing user | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/active-directory-copy-user.html) |
| ADM-017 | Users | Naming formats | Builds names from attribute parts (first/last/Nth character, word), letter case, random numbers, literal text and custom functions | n/s | [help](https://www.manageengine.com/products/ad-manager/help/admin-settings/active-directory-cutomize-naming-format.html) |
| ADM-018 | Users | Advanced (conditional) naming | Picks a different format depending on conditions, e.g., a fallback when the first name is empty | n/s | [help](https://www.manageengine.com/products/ad-manager/help/admin-settings/active-directory-cutomize-naming-format.html) |
| ADM-019 | Users | Custom functions | Script-based functions usable in naming formats, webhooks and automation macros | n/s | [help](https://www.manageengine.com/products/ad-manager/help/admin-settings/how-to-create-and-manage-custom-functions.html), [release notes, build 8020](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-020 | Users | Duplicate prevention | Checks logon name and full name for duplicates at domain level, forest level, in external MS SQL/Oracle databases and in Entra ID | n/s | [templates help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_user_templates.html), [release notes, builds 8031–8032](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-021 | Users | Random password policy | Sets length, character classes, characters to exclude, first character and dictionary words for generated passwords | n/s | [help](https://www.manageengine.com/products/ad-manager/help/admin-settings/active-directory-customize-password.html) |
| ADM-022 | Users | Password options | Random, typed, same as logon name, or blank. Flags: must change at next logon, cannot change, never expires. | Std+Pro | [demo](https://demo.admanagerplus.com/), [help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_a_windows_user.html) |
| ADM-023 | Users | Home and profile folders | Creates home and profile folders with NTFS permissions; paths can use LDAP macros (e.g., `%LogonName%`) | n/s | [help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_user_templates.html) |
| ADM-024 | Users | Account controls | Account expiry, logon hours grid, allowed logon workstations, UAC flags, protect from accidental deletion | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_a_windows_user.html), [demo](https://demo.admanagerplus.com/) |
| ADM-025 | Users | Kerberos AES flags | Turns on Kerberos AES 128/256 encryption when creating or modifying users | n/s | [release notes, build 8033](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-026 | Users | Exchange at creation | Mailbox-enabled user, mail-enabled user or no mail; picks mail server and store; remote mailbox | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_a_windows_user.html) |
| ADM-027 | Users | M365 at creation | Licenses and service plans, groups, roles, Exchange Online alias, litigation hold, archive, quotas, protocols | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_a_windows_user.html) |
| ADM-028 | Users | Teams at creation | Adds the user to teams and channels and applies one of 12 predefined Teams policy packages | n/s | [help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_a_windows_user.html) |
| ADM-029 | Users | Google Workspace at creation | Creates the Google Workspace account with groups and OU | n/s | [help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_a_windows_user.html) |
| ADM-030 | Users | Skype for Business / Lync / OCS | Enables, disables or deletes these accounts and sets their policies | n/s | [templates help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_user_templates.html), [demo](https://demo.admanagerplus.com/) |
| ADM-031 | Users | Terminal Services attributes | Profile, home folder, session limits, remote control, environment, dial-in/VPN | n/s | [feature page](https://www.manageengine.com/products/ad-manager/active-directory-terminal-services.html), [demo](https://demo.admanagerplus.com/) |
| ADM-032 | Users | Custom attributes and scripts | Custom attributes with input validation; runs a custom script after a user is created | n/s | [templates help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_user_templates.html), [release notes, build 8020](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-033 | Users | Modify single user | Tabbed attribute editor, including M365 fields (manager, employee type, extension attributes 1–15); view of the user's entitlements | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/active-directory-modify-single-user.html), [release notes, builds 7230 and 8032](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-034 | Users | Bulk user modification | Reset password, unlock, enable/disable, delete, restore, move; change group, profile, naming, contact and address attributes; workstations, logon hours, inheritable permissions, home folders | Std+Pro | [demo](https://demo.admanagerplus.com/) (Management tab) |
| ADM-035 | Users | User photos | Upload, crop, replace or remove photos, one at a time or in bulk | n/s | [features](https://www.manageengine.com/products/ad-manager/features.html) |
| ADM-036 | Users | Delayed tasks queue | Holds follow-up actions (e.g., litigation hold) until the mailbox exists, then runs them | n/s | [help](https://www.manageengine.com/products/ad-manager/help/user_management/office-365-management/active-directory-delayed-management-actions.html) |
| ADM-037 | Users | Organization attribute lists | Managed pick lists for department, title, office and company | n/s | [API v2 admin settings](https://www.manageengine.com/products/ad-manager/active-directory-api/v2/admin-settings/) |
| ADM-038 | Users | Restore deleted users | Restores users from AD's deleted objects | Std+Pro | [demo](https://demo.admanagerplus.com/), [KB](https://www.manageengine.com/products/ad-manager/admanager-kb/how-to-restore-deleted-active-directory-users.html) |

### C. User lifecycle (joiner, mover, leaver)
Automating account creation, changes and removal when people join, move or leave.

| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADM-039 | Lifecycle | HR-driven joiners | HCM app data comes in through inbound webhooks and feeds scheduled automations that create AD, Exchange and M365 accounts | Pro | [HCM page](https://www.manageengine.com/products/ad-manager/hcm-integration.html), [edition table](https://www.manageengine.com/products/ad-manager/pricing-details.html) |
| ADM-040 | Lifecycle | Database-driven provisioning | Detects new or changed rows in MS SQL, Azure SQL, Oracle or AWS SQL and provisions or modifies accounts; can write back | Pro **[UNVERIFIED]** | [integrations](https://www.manageengine.com/products/ad-manager/admanager-plus-integrations.html) |
| ADM-041 | Lifecycle | CSV-drop provisioning | Watches a CSV file on a path; can process only newly appended rows | Pro | [help](https://www.manageengine.com/products/ad-manager/help/automation/configuring-automation.html) |
| ADM-042 | Lifecycle | Movers | Modification templates/rules and "modify using template or CSV"; can run on a schedule | Std+Pro (manual) / Pro (automated) | [help](https://www.manageengine.com/products/ad-manager/help/user_management/active-directory-modify-users-using-template.html) |
| ADM-043 | Lifecycle | Disable policy (leaver preset) | When a user is disabled: delete or move home/profile folders; disable mailbox and hide from the address list; revoke M365 licenses; remove from all Teams and M365 groups; disable Google Workspace; move to an OU; remove all groups; run a script | n/s | [help](https://www.manageengine.com/products/ad-manager/help/admin-settings/windows-active-directory-delete-policy.html) |
| ADM-044 | Lifecycle | Delete policy | When a user is deleted: delete home/profile folders; delete the mailbox; export the mailbox first with export tracking (deletion is skipped if the export fails); run a script | n/s | [help](https://www.manageengine.com/products/ad-manager/help/admin-settings/windows-active-directory-delete-policy.html) |
| ADM-045 | Lifecycle | Offboarding orchestration blocks | Remove direct reports; remove from all groups; remove all NTFS or ACE permissions; convert to shared mailbox; revoke license; remove inbox rules; invalidate a technician's tokens | Pro | [help](https://www.manageengine.com/products/ad-manager/help/orchestration/new-orchestration-template.html) |
| ADM-046 | Lifecycle | Sync user to another domain | Orchestration block that copies AD or non-AD users from a source domain to a target domain | Pro | [release notes, build 8030](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-047 | Lifecycle | Password-expiry reminders | Automation that notifies users before their passwords expire | Pro | [help](https://www.manageengine.com/products/ad-manager/help/automation/usecase6-automation.html) |

### D. Groups
Group management is **Pro only**, per the edition table.

| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADM-048 | Groups | Group create, modify, delete | Single, bulk or CSV; security and distribution groups | Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/active-directory-groups-management.html) |
| ADM-049 | Groups | Group templates | Creation and modification templates with drag-and-drop layout and creation rules | Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/active-directory-creating-group-creation-template.html), [release notes, build 8020](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-050 | Groups | Membership management | Add or remove members, including across domains; clear all memberships | Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/windows-active-directory-group-management.html), [release notes, build 8040](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-051 | Groups | Copy group attributes | Clones a group's settings into a new group | Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/active-directory-copy-group.html) |
| ADM-052 | Groups | Dynamic (rule-based) membership | Security and distribution groups whose members update automatically from rules | n/s (likely Pro) | [release notes, build 8020](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-053 | Groups | Time-bound membership | Sets how long a member stays in a group (just-in-time access) | n/s | [release notes, builds 7230 and 8020](https://www.manageengine.com/products/ad-manager/release-notes.html), [JIT use cases PDF](https://download.manageengine.com/products/ad-manager/dynamic-group-membership-and-jit-access-use-cases.pdf) |
| ADM-054 | Groups | Exchange dynamic distribution groups | Create and modify them; creation templates | n/s | [help](https://www.manageengine.com/products/ad-manager/help/user_management/active-directory-exchange-dynamic-distribution-list-creation.html) |

### E. Computers
Computer-object management is in both editions.

| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADM-055 | Computers | Create computers | Single or CSV; creation templates with drag-and-drop layout | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/bulk-computer-modification/active-directory-create-single-computer.html) |
| ADM-056 | Computers | Bulk computer modification | Enable/disable, move, delete, group membership, general and custom attributes, CSV | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/bulk-computer-modification/active-directory-enable-disable-computers.html) |
| ADM-057 | Computers | Reset and restore | Resets computer account passwords; restores deleted computers | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/bulk-computer-modification/active-directory-reset-computer-account-passwords.html), [release notes, build 7240](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-058 | Computers | Computer modification templates | Templates with modification rules | n/s | [release notes, build 8020](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-059 | Computers | Domain-join permissions | Sets who may join a computer object to the domain | n/s | [release notes, build 8030](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-060 | Computers | BitLocker and LAPS | Looks up and reports BitLocker recovery keys; shows Microsoft Legacy LAPS and Windows LAPS passwords with history; "LAPS Role" for technicians; control over exporting LAPS passwords | n/s | [backup help](https://www.manageengine.com/products/ad-manager/help/backup-restore/active-directory.html), [release notes, build 8020](https://www.manageengine.com/products/ad-manager/release-notes.html), [privacy help](https://www.manageengine.com/products/ad-manager/help/admin-settings/security-and-privacy-settings-admanager-plus.html) |

### F/G. Contacts and OUs
Both are **Pro only**.

| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADM-061 | Contacts | Contact lifecycle | Create, modify, move or delete (single, bulk or CSV); templates; restore deleted contacts | Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/active-directory-create-single-contact.html) |
| ADM-062 | OUs | OU lifecycle | Create (single, bulk or CSV), modify, move or delete OUs; OU templates | Pro | [help](https://www.manageengine.com/products/ad-manager/help/ou-management/create-single-active-directory-organizational-unit.html) |

### H. Exchange Server (on-prem)
Mailbox management for on-prem Exchange 2016 and later.

| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADM-063 | Exchange | Mailbox lifecycle | Create or archive, disable or delete mailboxes, in bulk | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/exchange_attributes/create_mail_box_in_exchange_server.html) |
| ADM-064 | Exchange | Mailbox rights | Full Access, Send As and Send on Behalf, set by template; optional Outlook auto-mapping | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/exchange_attributes/set-mailbox-rights.html), [release notes, build 8020](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-065 | Exchange | Mailbox migration | Moves mailboxes in bulk between databases or servers | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/exchange_attributes/exchange-mailbox-migration.html) |
| ADM-066 | Exchange | Mailbox conversion | Converts mailboxes in bulk to regular, room, equipment or shared | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/exchange_attributes/steps-to-convert-mailbox-in-admanager-plus.html) |
| ADM-067 | Exchange | Features and policies | Turns OWA, OMA, ActiveSync, POP and IMAP on or off; applies sharing, role-assignment, retention, UM and ActiveSync policies | Std+Pro | [features page](https://www.manageengine.com/products/ad-manager/microsoft-exchange-policy-management.html) |
| ADM-068 | Exchange | Delivery and limits | Delivery options and restrictions, storage limits, SMTP and proxy addresses, naming attributes, offline address book | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/exchange_attributes/modify_exchange_server_delivery_options.html) |
| ADM-069 | Exchange | Automatic replies | Configures out-of-office replies | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/exchange_attributes/auto-reply-settings.html) |
| ADM-070 | Exchange | Remote mailbox (hybrid) | Enables a remote mailbox; picks the mail server in templates | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/exchange_attributes/enable-remote-mailbox.html) |
| ADM-071 | Exchange | Shared, room, equipment and linked mailboxes | Creation and modification, plus templates, on-prem and in Exchange Online | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/exchange_attributes/active-directory-exchange-office365-shared-mailbox-creation.html) |

### I. Group Policy (GPO) management
GPO management is **Pro only**. GPO *reports* are in K.

| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADM-072 | GPO | GPO create, edit, delete, enable/disable | Edits Administrative Templates, security settings and preference items; turns user/computer configuration on or off; syncs ADMX files | Pro | [help](https://www.manageengine.com/products/ad-manager/help/gpo-management/manage-group-policy.html) |
| ADM-073 | GPO | Link management | Link, unlink, enable, disable or enforce links; block or unblock inheritance; set link order | Pro | [help](https://www.manageengine.com/products/ad-manager/help/gpo-management/manage-gpo-links.html) |
| ADM-074 | GPO | Force GPO update | Triggers a Group Policy refresh on target computers | Pro | [help](https://www.manageengine.com/products/ad-manager/help/gpo-management/force-group-policy-update.html) |
| ADM-075 | GPO | Copy GPOs | Copies GPOs between domains in the same forest | Pro | [help](https://www.manageengine.com/products/ad-manager/help/gpo-management/copy-gpo-between-domains.html) |
| ADM-076 | GPO | Merge GPOs | Combines several GPOs into one | Pro | [help](https://www.manageengine.com/products/ad-manager/help/gpo-management/steps-to-merge-gpo.html) |
| ADM-077 | GPO | Scope and delegation | Shows where a GPO is linked; manages GPO delegation | Pro | [help](https://www.manageengine.com/products/ad-manager/help/gpo-management/manage-group-policy.html) |

### J. File servers and NTFS permissions
Managing permissions is **Pro only**. Permission reports are in K.

| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADM-078 | File servers | Manage file systems | Registers Windows file servers, DFS namespaces and NAS (NetApp, Isilon, Huawei OceanStor) | Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/file-server-management/active-directory-manage-file-servers.html), [system requirements](https://www.manageengine.com/products/ad-manager/help/getting_started/system_requirements.html) |
| ADM-079 | File servers | NTFS permissions | Changes or removes folder permissions in bulk | Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/file-server-management/active-directory-modify-and-remove-ntfs-permissions.html) |
| ADM-080 | File servers | Share permissions | Changes or removes share permissions | Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/file-server-management/active-directory-modify-and-remove-share-permissions.html) |
| ADM-081 | File servers | Remove all of a user's permissions | Strips a user's permissions across a whole file server (for offboarding) | Pro | [supported tasks](https://www.manageengine.com/products/ad-manager/help/automation/supported-management-tasks-in-automation.html) |
| ADM-082 | File servers | CSV permission changes | Bulk folder-permission changes from CSV, including in automations | Pro | [supported tasks](https://www.manageengine.com/products/ad-manager/help/automation/supported-management-tasks-in-automation.html) |

### K. Reports
- **Vendor claim:** "200+" prebuilt reports.
- **Counted in the demo:** about 166 AD reports across 9 AD categories, about 91 M365 reports (plus M365 security reports), Google Workspace reports (ADM-095), 49 compliance-mapped entries, and a custom report builder.

| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADM-083 | Reports | Prebuilt report library | Vendor claims 200+. The demo has 12 report categories in the Reports tab, plus a separate M365 report tree. | Std+Pro | [product page](https://www.manageengine.com/products/ad-manager/), [demo](https://demo.admanagerplus.com/) |
| ADM-084 | Reports | User reports (35) | All, inactive, never logged on, real last logon, empty or duplicate attributes, managers, logon hours, nested membership, Terminal Services and more | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-user-reports.html) |
| ADM-085 | Reports | Password reports (8) | Expired, soon to expire, never expires, cannot change, must change, changed, unchanged, recent logon failures | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/reports/active-directory-password-reports.html) |
| ADM-086 | Reports | Group reports (16) | Members (nested), detailed members, top-N largest, empty, unmanaged, by type and scope, users or computers not in groups | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-group-reports.html) |
| ADM-087 | Reports | Computer reports (18) | By OS, workstations, domain controllers, trusted for delegation, inactive, BitLocker enabled/disabled and recovery keys | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-computer-reports.html) |
| ADM-088 | Reports | Exchange reports (31) | Mailbox and mail-enabled objects, distribution lists, delivery and size limits, protocol features | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-exchange-reports.html) |
| ADM-089 | Reports | Contact and OU reports (13) | Contacts; empty OUs, user-only and computer-only OUs, OUs with linked GPOs or blocked inheritance | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/reports/how-to-get-active-directory-contact-and-ou-report.html) |
| ADM-090 | Reports | GPO reports (28) | GPO settings, Resultant Set of Policy, GPO modeling, GPO comparison, AD vs SYSVOL version compare, delegation, unlinked, empty and disabled GPOs | Std+Pro (no GPO settings report in Free) | [help](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-gpo-reports.html), [pricing footnote](https://www.manageengine.com/products/ad-manager/pricing-details.html) |
| ADM-091 | Reports | NTFS and Security reports (12) | Shares, folder permissions, folders an account can reach, non-inheriting folders; who can access AD objects, servers and subnets; permission search; object permissions | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/reports/how-to-generate-active-directory-ntfs-and-security-reports.html), [release notes, build 8030](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-092 | Reports | Other reports (5) | Password policy, account lockout policy, printers, DC replication status, lingering objects | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/reports/active-directory-other-reports.html) |
| ADM-093 | Reports | Compliance report sets | SOX, HIPAA, PCI DSS, GLBA, FISMA, GDPR (the help adds SOC 2 + HIPAA). These are existing reports mapped to each mandate; the demo shows 49 entries. | Std+Pro | [compliance page](https://www.manageengine.com/products/ad-manager/compliance-reports.html), [demo](https://demo.admanagerplus.com/) |
| ADM-094 | Reports | Microsoft 365 reports (about 91) | In the demo: Entra ID users 42, groups 9, contacts 9, licenses 3; Exchange Online mailboxes 23, OWA 5; plus security reports (mailbox and user security, admin and user activity) | Std+Pro | [demo](https://demo.admanagerplus.com/), [Entra ID reports help](https://www.manageengine.com/products/ad-manager/help/office365/reports/azure-active-directory-reports.html), [security reports help](https://www.manageengine.com/products/ad-manager/help/office365/reports/security-reports.html) |
| ADM-095 | Reports | Google Workspace reports | Users (all, active, suspended, archived, MFA status, MFA enforced, inactive); groups; OUs | n/s | [help](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-google-apps-reports.html) |
| ADM-096 | Reports | Report from CSV | Reports on the objects listed in a CSV file; several domains allowed since build 8034 | Std+Pro | [release notes, build 8034](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-097 | Reports | Custom report builder | LDAP filter or raw LDAP query; filtering on database fields (e.g., bad-password count, days since password set); column picker including custom attributes; attach management actions; categories; copy, share and delegate | n/s | [help](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-custom-reports.html) |
| ADM-098 | Reports | Act on report results | Runs management actions (delete, move, disable, …) on the rows of a report | Std+Pro | [features](https://www.manageengine.com/products/ad-manager/features.html), [reports list](https://www.manageengine.com/products/ad-manager/active-directory-reports-list.html) |
| ADM-099 | Reports | Scope and filters | Several domains at once, OU scope, time-period presets, result filters, add or remove columns | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-user-reports.html) |
| ADM-100 | Reports | Export | CSV, PDF, XLSX, HTML and CSVDE; optional password protection; logo and serial number in exports | Std+Pro | [scheduled reports help](https://www.manageengine.com/products/ad-manager/help/reports/active-directory-scheduled-reports.html), [privacy help](https://www.manageengine.com/products/ad-manager/help/admin-settings/security-and-privacy-settings-admanager-plus.html) |
| ADM-101 | Reports | Scheduled reports | Hourly, daily, weekly, monthly or custom. Delivered by email as attachment, ZIP, link or in the body, or saved to a path; "notify only if data"; an advanced scheduler for custom reports. | **Pro** | [help](https://www.manageengine.com/products/ad-manager/help/reports/active-directory-scheduled-reports.html), [edition table](https://www.manageengine.com/products/ad-manager/pricing-details.html) |
| ADM-102 | Reports | Report-level delegation | Each role can be limited to certain report categories or reports | n/s | [delegation help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/active-directory-help-desk-delegation.html) |
| ADM-103 | Reports | Custom-report dashboard widgets | Adds custom reports to dashboard widgets | n/s | [release notes, build 7240](https://www.manageengine.com/products/ad-manager/release-notes.html) |

### L. Automation and orchestration
Automation is **Pro only**.

| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADM-104 | Automation | Scheduled automation | Takes objects from a built-in report, a CSV location or an external app; runs hourly to monthly or on a custom schedule; can skip objects changed by its last run | Pro | [help](https://www.manageengine.com/products/ad-manager/help/automation/configuring-automation.html) |
| ADM-105 | Automation | Automation policies | Ordered multi-step task sequences with delays, e.g., disable → move after x days → delete after y days | Pro | [overview](https://www.manageengine.com/products/ad-manager/help/automation/active-directory-automation.html), [help](https://www.manageengine.com/products/ad-manager/help/automation/configuring-automation-policy.html) |
| ADM-106 | Automation | Controlled automation | Sends automated tasks through a business workflow for approval before they run | Pro | [help](https://www.manageengine.com/products/ad-manager/help/automation/configuring-automation.html) |
| ADM-107 | Automation | Automatable tasks | About 30 AD user tasks and about 30 M365 tasks (licenses, block, MFA, litigation hold, mailbox conversion, revoke refresh token, remove roles, …), plus computer, group and contact tasks | Pro | [supported tasks](https://www.manageengine.com/products/ad-manager/help/automation/supported-management-tasks-in-automation.html) |
| ADM-108 | Automation | Event-driven automation | Fires on an action type (create, modify, delete, …), on success, failure or every occurrence, with attribute filters; runs orchestration templates or webhooks | Pro | [help](https://www.manageengine.com/products/ad-manager/help/orchestration/orchestration-profile.html), [release notes, build 8030](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-109 | Automation | Orchestration templates | No-code drag-and-drop flow. Block types: logic, time delay, custom script, webhook, notification, database operations; AD, Exchange, cloud and other actions. Success and failure branches; outputs passed between blocks as macros; stops after 15 loop iterations. | Pro | [help](https://www.manageengine.com/products/ad-manager/help/orchestration/new-orchestration-template.html) |
| ADM-110 | Automation | Outbound webhooks | Calls REST or SOAP APIs as an action in orchestration, automation and workflow | Pro | [help](https://www.manageengine.com/products/ad-manager/help/orchestration/webhook-template.html), [release notes, build 8030](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-111 | Automation | Inbound-webhook triggers | Starts an orchestration when an external system calls in | Pro | [release notes, build 7230](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-112 | Automation | Custom scripts | Runs scripts (e.g., PowerShell) in templates, automation and orchestration | n/s | [orchestration help](https://www.manageengine.com/products/ad-manager/help/orchestration/new-orchestration-template.html) |
| ADM-113 | Automation | Environment variables and macros | Reusable variables and macros; custom functions inside webhooks and automations | n/s | [help](https://www.manageengine.com/products/ad-manager/help/admin-settings/environmental-variable.html), [release notes, build 8000](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-114 | Automation | History and audit | Execution history and audit history for automations; consolidated reports; failure notifications | Pro | [help](https://www.manageengine.com/products/ad-manager/help/automation/automation-history.html), [release notes, build 7230](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-115 | Automation | On-demand orchestration ("Advanced Management") | Runs a chosen orchestration template on selected objects or a CSV | Pro | [help](https://www.manageengine.com/products/ad-manager/help/user_management/advanced-management.html) |

### M. Workflow (request → review → approve → execute)
Workflow is **Pro only**.

| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADM-116 | Workflow | Business workflows | Requester → reviewers (up to 5) → approvers (up to 5) → executor; any number of workflows | Pro | [help](https://www.manageengine.com/products/ad-manager/help/workflow/configuring-ad-workflow.html) |
| ADM-117 | Workflow | Workflow technicians and requester roles | Requesters can be help-desk technicians or any domain users, groups or OUs; scoped by OU, template and file server | Pro | [help](https://www.manageengine.com/products/ad-manager/help/workflow/configuring-ad-workflow-agents.html) |
| ADM-118 | Workflow | Assigning rules | Routes requests by criteria; sets priority and notifications; `%manager%` and `%ManagerOfRequester%` macros with a fallback approver | Pro | [help](https://www.manageengine.com/products/ad-manager/help/workflow/workflow-assigning-rules.html) |
| ADM-119 | Workflow | SLAs | Up to 3 escalation levels: reassign, change priority, close or cancel, notify | Pro | [help](https://www.manageengine.com/products/ad-manager/help/workflow/service-level-agreement.html) |
| ADM-120 | Workflow | Requests tab | Create requests, track their progress, edit and resend failed requests | Pro | [demo](https://demo.admanagerplus.com/), [release notes, builds 7230/7240](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-121 | Workflow | Managers as reviewers/approvers | Automatically assigns all managers as reviewers or approvers | Pro | [release notes, build 7250](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-122 | Workflow | Scheduled execution | Per-object execution time (`executionTime`) for approved tasks | Pro | [release notes, build 8030](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-123 | Workflow | Failed-object notifications | Alerts when individual objects fail during a workflow run | Pro | [release notes, build 8020](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-124 | Workflow | ADSelfService Plus approvals | Sends end-user self-service updates to ADMP's help desk for approval | n/s | [help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/admp-and-adssp-integration.html) |

### N. Delegation and console security
Who can do what in ADMP, how it is audited, and how people sign in.

| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADM-125 | Delegation | Help-desk roles | Task- and attribute-level privileges; optional deny-bulk and deny-CSV flags; report restrictions | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/active-directory-help-desk-role-creation.html) |
| ADM-126 | Delegation | Built-in technicians and roles | Admin, Help desk and HR Associate accounts; the Super Admin role cannot be changed; sample help-desk logins on first install | Std+Pro | [architecture PDF](https://download.manageengine.com/products/ad-manager/solution-architecture.pdf) |
| ADM-127 | Delegation | OU-based delegation | Limits each technician to selected OUs | **Pro** | [help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/ou-based-delegation.html), [edition table](https://www.manageengine.com/products/ad-manager/pricing-details.html) |
| ADM-128 | Delegation | Group-based delegation | Gives roles to an AD group; members lose rights automatically when removed or disabled | **Pro** | [help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/group-based-delegation.html) |
| ADM-129 | Delegation | Include/exclude groups | Narrows the set of groups a technician can manage | n/s | [help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/active-directory-help-desk-delegation.html) |
| ADM-130 | Delegation | Cross- and multi-domain delegation | One technician with different roles in different domains | **Pro** | [pricing footnote](https://www.manageengine.com/products/ad-manager/pricing-details.html) |
| ADM-131 | Delegation | M365 and Google Workspace delegation | Delegates cloud management tasks | **Pro** | [pricing footnote](https://www.manageengine.com/products/ad-manager/pricing-details.html) |
| ADM-132 | Delegation | Technician-specific templates | Restricts each technician to chosen templates | **Pro** | [pricing footnote](https://www.manageengine.com/products/ad-manager/pricing-details.html) |
| ADM-133 | Delegation | Site-based delegation | Sets which domain controllers are contacted first for each OU | n/s | [help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/site-based-delegation.html) |
| ADM-134 | Delegation | Impersonate as Admin | Technician actions run as the service account; domain controllers log the service account, not the technician | n/s | [help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/group-based-delegation.html) |
| ADM-135 | Delegation | Native AD security roles | Writes ACL-based delegation (reset password, unlock, group members, move, create) directly into AD | n/s | [help](https://www.manageengine.com/products/ad-manager/help/managing_security_roles/pre-defined_security_roles.html) |
| ADM-136 | Delegation | Help Desk Reset Password Console | User grid with one pop-up per user for reset, must-change flag and unlock | n/s | [demo](https://demo.admanagerplus.com/), [help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/active-directory-reset-password.html) |
| ADM-137 | Audit | Help-desk audit report | Who did what, to which object, and when; filters; archives; scheduled delivery; CSV, PDF, XLSX or HTML | n/s | [help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/help-desk-technician-audit-report.html), [scheduled audit help](https://www.manageengine.com/products/ad-manager/help/reports/active-directory-audit-logs.html) |
| ADM-138 | Audit | Admin audit report | Changes to ADMP configuration: technicians, roles, templates, automations, schedules, custom reports, webhooks, orchestration | n/s | [help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/help-desk-admin-audit-report.html) |
| ADM-139 | Audit | Technician logon report and technicians report | When technicians log in; inventory of technicians and their permissions | n/s | [help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/Active-Directory-Help-Desk-Technician-Logon-Report.html) |
| ADM-140 | Audit | Anomaly report | Machine learning flags unusual technician activity by pattern, time or volume; alerts in the notification bell | n/s | [help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/help-desk-anomaly-report.html) |
| ADM-141 | Access | Authtoken management | API tokens per technician with scope and expiry; admin oversight; records who created each token | n/s | [help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/authtoken-management-in-admanager-plus.html) |
| ADM-142 | Access | Console 2FA | Duo v4, Google Authenticator, Microsoft Authenticator, RSA SecurID, email OTP, SMS; "trust this browser"; per-technician skip | n/s | [help](https://www.manageengine.com/products/ad-manager/help/admin-settings/two-factor-authentication.html) |
| ADM-143 | Access | Console SSO | SAML 2.0 (Okta, OneLogin, Ping, AD FS, Entra ID, custom), optionally forced; NTLMv2 SSO (Jespa JAR supplied by the customer) | n/s | [help](https://www.manageengine.com/products/ad-manager/help/admin-settings/single-sign-on-authentication.html) |
| ADM-144 | Access | Smart card / PKI login | Maps a certificate attribute to an AD attribute; turned off when load balancing is on | n/s | [help](https://www.manageengine.com/products/ad-manager/help/admin-settings/smart-card-authentication.html) |
| ADM-145 | Access | Login hardening | CAPTCHA, IP allow/deny, lockout after failed logins, session expiry, concurrent-login limits | n/s | [help](https://www.manageengine.com/products/ad-manager/help/admin-settings/captcha.html), [release notes, build 8033](https://www.manageengine.com/products/ad-manager/release-notes.html) |

### O. AD cleanup
Finding and removing stale objects.

| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADM-146 | Cleanup | Clean up from reports | Disable, move or delete inactive, disabled or never-logged-on users and computers straight from a report | Std+Pro | [feature page](https://www.manageengine.com/products/ad-manager/cleanup-your-active-directory.html) |
| ADM-147 | Cleanup | Automated cleanup policy | Runs a staged sequence on a schedule: disable → move → delete | Pro | [automation help](https://www.manageengine.com/products/ad-manager/help/automation/usecase2-automation.html) |
| ADM-148 | Cleanup | Other stale objects | Finds empty groups and OUs, unused, empty or unlinked GPOs, and lingering objects | Std+Pro | [reports list](https://www.manageengine.com/products/ad-manager/active-directory-reports-list.html) |

### P. Backup and recovery
Most capabilities need the per-user **Backup add-on**; the base product's backup is limited (ADM-157).

| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADM-149 | Backup | AD backup | Monthly full backup plus daily or weekly incremental; choose OUs, object types and attributes; GPOs via PAExec; optional disabled objects; force replication before backup | Backup add-on | [help](https://www.manageengine.com/products/ad-manager/help/backup-restore/backup-settings.html) |
| ADM-150 | Backup | Backup Explorer | Timeline of backups, types of change, before/after attribute values, restore | Backup add-on | [help](https://www.manageengine.com/products/ad-manager/help/backup-restore/active-directory.html) |
| ADM-151 | Backup | Quick Recovery | Per-object history in version view or attribute view; restore individual attributes | Backup add-on | [help](https://www.manageengine.com/products/ad-manager/help/backup-restore/active-directory.html) |
| ADM-152 | Backup | Restore deleted objects | Restore to an alternate location; set a default password or keep the old one; recover objects past tombstone expiry | Backup add-on | [help](https://www.manageengine.com/products/ad-manager/help/backup-restore/backup-settings.html) |
| ADM-153 | Backup | Advanced Recovery (rollback) | Rolls AD and Entra ID objects back to a point in time, with filters | Backup add-on | [release notes, build 8030](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-154 | Backup | Entra ID backup | Users, groups, devices, apps, service principals and roles, using Graph delta queries | Backup add-on | [architecture PDF](https://download.manageengine.com/products/ad-manager/solution-architecture.pdf), [features](https://www.manageengine.com/products/ad-manager/features.html) |
| ADM-155 | Backup | Google Workspace backup | Gmail, Calendar, Drive, contacts and more; restore; retention periods | Backup add-on | [features](https://www.manageengine.com/products/ad-manager/features.html), [help](https://www.manageengine.com/products/ad-manager/help/google-workspace/backup-settings.html) |
| ADM-156 | Backup | Backup repositories | Local or NAS/shared storage; archive and re-index older backups | Backup add-on | [architecture PDF](https://download.manageengine.com/products/ad-manager/solution-architecture.pdf), [release notes, build 8032](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-157 | Backup | Backup without the add-on | Weekly only, one domain, no full backup or bulk restore; Google Workspace limited to 5 users | Std+Pro | [licensing FAQ](https://www.manageengine.com/products/ad-manager/licensing-faq.html) |
| ADM-158 | Backup | Product database backup | ADMP's own database is backed up automatically each month; can be restored or migrated | Std+Pro | [architecture PDF](https://download.manageengine.com/products/ad-manager/solution-architecture.pdf) |

### Q. Microsoft 365, Entra ID, Exchange Online and Teams
The M365 module runs as a separate embedded app (iframe). SharePoint site and permission management is not documented in ADMP help as of 2026-10-02; ManageEngine sells SharePoint Manager Plus separately.

| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADM-159 | M365 | Tenant onboarding | Global-admin consent creates the app automatically, or use a manual app registration; several tenants; many-to-many links between domains and tenants | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/directory-application-settings/microsoft-365-tenant-configuration.html) |
| ADM-160 | M365 | Bulk user create/modify | Cloud-only and synced users; bulk guest-user creation | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/office365/management/office-365-user-management.html) |
| ADM-161 | M365 | License management | Add, replace or remove licenses; group-based license changes; CSV by ObjectId or UPN; filter by AD domain or OU | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/office365/management/license-management.html) |
| ADM-162 | M365 | Account actions | Reset password, block or unblock, delete, hard delete, restore; change UPN or domain; set manager; revoke refresh tokens | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/office365/management/office-365-user-management.html) |
| ADM-163 | M365 | MFA settings | Turns per-user MFA on or off. Some methods were removed after Microsoft deprecations (build 8012); bulk changes need a service account. | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/office365/management/office-365-user-management.html), [release notes, build 8012](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-164 | M365 | Groups | M365, distribution, mail-enabled security and dynamic distribution groups; security-group changes; templates | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/office365/management/office-365-group-management.html), [release notes, build 8036](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-165 | M365 | Exchange Online mailboxes | Features, permissions, delegation, forwarding, size limits, litigation hold, archive, extra addresses, auto-reply, address book policy, conversion, retention policy | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/office365/mailbox-management/mailbox-management.html) |
| ADM-166 | M365 | Shared mailboxes, calendars and contacts | Shared mailbox management, calendar management, M365 contacts | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/office365/mailbox-management/calendar-management.html), [help](https://www.manageengine.com/products/ad-manager/help/office365/contact/contact-management.html) |
| ADM-167 | M365 | Microsoft Teams | Add to teams and channels with policy packages during provisioning; remove from all Teams | n/s | [creation help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_a_windows_user.html), [supported tasks](https://www.manageengine.com/products/ad-manager/help/automation/supported-management-tasks-in-automation.html) |
| ADM-168 | M365 | Roles and Conditional Access | Remove M365 roles; orchestration blocks to assign or remove Conditional Access policies | Pro | [release notes, builds 8020 and 8021](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-169 | M365 | Hybrid handling | Remote mailboxes; filter cloud users by AD domain or OU; orchestration's cloud actions work only on users synced by DirSync | Std+Pro | [license help](https://www.manageengine.com/products/ad-manager/help/office365/management/license-management.html), [orchestration help](https://www.manageengine.com/products/ad-manager/help/orchestration/new-orchestration-template.html) |
| ADM-170 | M365 | M365 risk assessment | M365 risk indicators with fix-it actions | Pro +GRC | [release notes, builds 7230 and 8020](https://www.manageengine.com/products/ad-manager/release-notes.html) |

### R. Google Workspace
Managing Google Workspace users alongside AD.

| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADM-171 | Google Workspace | Connection | Service account with domain-wide delegation and a P12 key; Admin SDK scopes | n/s | [help](https://www.manageengine.com/products/ad-manager/help/directory-application-settings/google-apps-active-directory-management-tool.html) |
| ADM-172 | Google Workspace | User lifecycle | Create (with or without an AD user), groups, OUs, licenses, roles, suspend or enable, delete, reset password | n/s | [creation help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_a_windows_user.html), [orchestration help](https://www.manageengine.com/products/ad-manager/help/orchestration/new-orchestration-template.html) |
| ADM-173 | Google Workspace | Extra profile fields | Mobile, title, department, employee type, recovery email and phone | n/s | [release notes, build 7250](https://www.manageengine.com/products/ad-manager/release-notes.html) |

### S. Governance (GRC add-on, Pro only)
Risk assessment, attack-path analysis and access reviews.

| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADM-174 | Governance | Identity Risk Assessment | Risk score for AD and M365 based on NIST SP 800-30; remediation guidance; tile and dashboard views; score trend; scheduled runs. Added 34 indicators in Dec 2024 and 48 more plus a "Misconfigurations" category in Jul 2025. | Pro +GRC | [help](https://www.manageengine.com/products/ad-manager/help/reports/identity-risk-assessment-report.html), [release notes](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-175 | Governance | Risk Exposure Management | Graph of possible attack paths to privileged entities; risk-exposure queries | Pro +GRC | [help](https://www.manageengine.com/products/ad-manager/help/governance/how-to-manage-risk-exposure-using-admanager-plus.html) |
| ADM-176 | Governance | Privileged entities | Defines which groups count as privileged for risk scoring | Pro +GRC | [help](https://www.manageengine.com/products/ad-manager/help/governance/steps-to-add-privileged-entities-in-admanager-plus.html) |
| ADM-177 | Governance | Access certification campaigns | Reviews AD group membership, NTFS permissions and Exchange mailbox rights, plus M365 group membership, roles, app assignments, Teams channels and Exchange Online mailbox rights. Default action when reviewers don't respond; reminders; schedules; progress tracking. | Pro +GRC | [help](https://www.manageengine.com/products/ad-manager/help/automation/access-certification-campaign.html) |
| ADM-178 | Governance | Certifier assigning rules | Rules that pick the reviewer for each item | Pro +GRC | [help](https://www.manageengine.com/products/ad-manager/help/automation/certifier-assigning-rule.html) |
| ADM-179 | Governance | Entitlements overview | Group memberships, file-system permissions, delegated permissions, access graph and M365 entitlements, all in AD Explorer | Pro +GRC | [licensing FAQ](https://www.manageengine.com/products/ad-manager/licensing-faq.html), [AD Explorer help](https://www.manageengine.com/products/ad-manager/help/introduction/exploring_active_directory_services.html) |
| ADM-180 | Governance | Governance tab | Central console for risk and certification | Pro +GRC | [release notes, build 8020](https://www.manageengine.com/products/ad-manager/release-notes.html) |

### T. AI and machine learning
Zia (chat assistant) and ML-based suggestions and anomaly detection.

| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADM-181 | AI | Zia AI assistant | Natural-language chat for 4 actions (enable, disable, unlock, reset to a random password, each confirmed first) and reports on users, groups, contacts and computers. Needs the customer's own Azure OpenAI endpoint, deployment and key; shows a disclaimer that answers may be wrong. | n/s | [help](https://www.manageengine.com/products/ad-manager/help/admin-settings/zia-configuration.html), [use-case PDF](https://download.manageengine.com/products/ad-manager/zia-ai-assistant-use-cases-in-admanager-plus.pdf) |
| ADM-182 | AI | Zia Insights | In AD Explorer: flags unusual or privileged group memberships and shows a peer-comparison percentile | n/s | [AD Explorer help](https://www.manageengine.com/products/ad-manager/help/introduction/exploring_active_directory_services.html) |
| ADM-183 | AI | Access Recommendations | Machine learning suggests group access during provisioning and certification | n/s | [creation help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_a_windows_user.html), [release notes, build 8000](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-184 | AI | Technician anomaly detection | Machine learning over ADMP's own logs (see ADM-140) | n/s | [help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/help-desk-anomaly-report.html) |

### U. AD migration
Migration is **Pro only** and capped at 500 objects.

| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADM-185 | Migration | Cross-forest migration | Moves users, groups, computers, contacts and GPOs across trusted forests, with or without Microsoft's ADMT | Pro | [help](https://www.manageengine.com/products/ad-manager/help/migration/active-directory-migration.html), [pricing footnote](https://www.manageengine.com/products/ad-manager/pricing-details.html) |
| ADM-186 | Migration | Password and suffix handling | Copies passwords, keeps password settings, "same as source" UPN suffix, account transition | Pro | [release notes, build 8030](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-187 | Migration | Computer migration | Moves computers between or within forests | Pro | [release notes, build 8020](https://www.manageengine.com/products/ad-manager/release-notes.html) |

### V. Integrations and API
Built-in connectors, the integration framework and the REST API.

| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADM-188 | API | REST API v1 | Users, groups, computers, OUs, domains, authtokens, workflow-request creation | n/s | [API index](https://www.manageengine.com/products/ad-manager/active-directory-api/) |
| ADM-189 | API | REST API v2 | OpenAPI document; users and groups (list, update); computers (list, create, update, disable); contacts (full CRUD); OUs; orchestration (list, execute, status); admin settings | n/s | [API v2 intro](https://www.manageengine.com/products/ad-manager/active-directory-api/v2/introduction/) |
| ADM-190 | API | Limits and quotas | 100 GET and 50 write requests per minute; 50 successful calls per technician per day; extra calls cost US$1 per call/day | n/s | [API v2 intro](https://www.manageengine.com/products/ad-manager/active-directory-api/v2/introduction/), [KB](https://www.manageengine.com/products/ad-manager/admanager-kb/fix-daily-api-limit-exceeded.html) |
| ADM-191 | Integrations | ServiceNow | Store app with user-creation form and catalog, MID Server, several ADMP servers per instance, plugin roles | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/admin-settings/third-party-integrations/servicenow.html) |
| ADM-192 | Integrations | ServiceDesk Plus | On-prem and cloud; "tight integration" for AD and Exchange actions from inside ServiceDesk Plus; only the built-in admin can turn it on | Std+Pro | [help](https://www.manageengine.com/products/ad-manager/help/admin-settings/third-party-integrations/servicedeskplus.html) |
| ADM-193 | Integrations | Other ITSM tools | Zendesk, Jira (Atlassian Marketplace app), Freshservice, Zoho Desk, HaloITSM | Std+Pro | [integrations](https://www.manageengine.com/products/ad-manager/admanager-plus-integrations.html), [Jira help](https://www.manageengine.com/products/ad-manager/help/admin-settings/third-party-integrations/jira-integration-settings.html) |
| ADM-194 | Integrations | HCM/HRMS connectors | 20+ named HR systems (list in §2.8) | Pro | [HCM page](https://www.manageengine.com/products/ad-manager/hcm-integration.html) |
| ADM-195 | Integrations | Custom app framework | REST, SOAP or Graph; 5 auth types; inbound and outbound webhooks; pagination; dependent endpoints; JSON conditional parsing; XML through path-mapping CSVs; response-parser functions | n/s | [help](https://www.manageengine.com/products/ad-manager/help/directory-application-settings/third-party-integrations/custom-applications.html) |
| ADM-196 | Integrations | Predefined app connectors | 60+ added Dec 2024; 50 more in Oct 2025; user and group templates can be mapped to these apps | n/s | [release notes, builds 8000 and 8030](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-197 | Integrations | Marketplace extensions | Installable `.ext` packages (build 8040+); 5 listed today | n/s | [help](https://www.manageengine.com/products/ad-manager/help/admin-settings/extensions.html) |
| ADM-198 | Integrations | SIEM and log forwarding | Syslog (TCP/UDP; RFC 3164, RFC 5424 or raw), Splunk, Rapid7, Log360 with a SOAR workflow | Std+Pro | [syslog help](https://www.manageengine.com/products/ad-manager/help/admin-settings/third-party-integrations/syslog.html), [release notes, build 7224](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-199 | Integrations | Power BI | Pushes management logs to a Power BI streaming dataset | n/s | [help](https://www.manageengine.com/products/ad-manager/help/admin-settings/third-party-integrations/power-BI-integration.html) |
| ADM-200 | Integrations | ManageEngine products | ADSelfService Plus, PAM360 (manages PAM360 technicians' group memberships), AD360 (central technician management), Zoho Flow | n/s | [PAM360 help](https://www.manageengine.com/products/ad-manager/help/admin-settings/third-party-integrations/pam360-integration.html), [release notes, build 7232](https://www.manageengine.com/products/ad-manager/release-notes.html), [HCM page](https://www.manageengine.com/products/ad-manager/hcm-integration.html) |

### W. Mobile apps
iOS and Android apps that connect to the on-prem server.

| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADM-201 | Mobile | Mobile management | Create users (with templates), enable or disable, unlock, delete, reset password (random), set account expiry; reset, enable, disable or delete computers; group membership. Needs network access to the on-prem server, and deny-bulk must be off for the technician. | n/s | [help](https://www.manageengine.com/products/ad-manager/help/mobile/ad-management/ad-management.html) |
| ADM-202 | Mobile | Mobile reports | Users (all, locked, disabled, enabled, password expired, inactive) and computers (all, disabled, inactive), with bulk actions | n/s | [help](https://www.manageengine.com/products/ad-manager/help/mobile/ad-reporting/ad-reporting.html) |
| ADM-203 | Mobile | Mobile workflow and sign-in | Review, approve, reject or execute requests; push notifications; 2FA and Face ID; SAML SSO and MDM-pushed configuration in v2.5.1 | n/s | [workflow help](https://www.manageengine.com/products/ad-manager/help/mobile/workflow.html), [mobile release notes](https://www.manageengine.com/products/ad-manager/help/mobile/release-notes.html) |

### X. Administration and platform
Settings, security hardening and deployment options.

| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADM-204 | Admin | Notifications | Email and SMS notification profiles and templates with macros; notification history | n/s | [help](https://www.manageengine.com/products/ad-manager/help/admin-settings/notification-profile.html) |
| ADM-205 | Admin | Mail, SMS and proxy | SMTP or API-mode email (Microsoft or Google), SMS gateway, proxy server | n/s | [release notes, build 8030](https://www.manageengine.com/products/ad-manager/release-notes.html), [SMS help](https://www.manageengine.com/products/ad-manager/help/admin-settings/sms-settings.html) |
| ADM-206 | Admin | Retention and archiving | How long audit data is kept and where archives go | n/s | [help](https://www.manageengine.com/products/ad-manager/help/admin-settings/retention-settings.html) |
| ADM-207 | Admin | Privacy controls | Anonymize data on deletion (GDPR/HIPAA), password-protected exports and ZIPs, hide passwords in the UI, usage statistics opt-out | n/s | [help](https://www.manageengine.com/products/ad-manager/help/admin-settings/security-and-privacy-settings-admanager-plus.html) |
| ADM-208 | Admin | Security hardening score | Scores the deployment on HTTPS, default admin password, 2FA, CAPTCHA, lockout, LDAPS, TLS, install-folder permissions, shared-path credentials and alerts | n/s | [help](https://www.manageengine.com/products/ad-manager/help/admin-settings/security-and-privacy-settings-admanager-plus.html) |
| ADM-209 | Admin | Automatic hotfixes | Checks daily at 11 pm; restart now, later or at a set time; not available with HA | n/s | [help](https://www.manageengine.com/products/ad-manager/help/admin-settings/security-and-privacy-settings-admanager-plus.html) |
| ADM-210 | Platform | High availability and load balancing | Active-passive HA; load balancer with failover (Pro) | HA n/s; LB Pro | [HA help](https://www.manageengine.com/products/ad-manager/help/admin-settings/high-availability.html), [LB help](https://www.manageengine.com/products/ad-manager/help/admin-settings/enterprise-essentials/active-directory-load-balancing.html) |
| ADM-211 | Platform | Database options | Bundled PostgreSQL; MS SQL (Always On availability groups, failover clusters); external PostgreSQL; Azure, AWS or Cloud SQL | n/s | [help](https://www.manageengine.com/products/ad-manager/help/migration/migrating-to-microsoft-sql-alwayson-availability-group.html), [release notes, build 7240](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| ADM-212 | Platform | Domain connection settings | Discovers and prioritizes DCs; DC sort intelligence picks the fastest; LDAPS; custom LDAP attributes | n/s | [help](https://www.manageengine.com/products/ad-manager/help/directory-application-settings/connecting-to-a-domain.html) |
| ADM-213 | Platform | Diagnostics and upgrades | Diagnostic tools for network, URL, Exchange and Entra ID; disk-space analysis; manual service-pack upgrades | n/s | [release notes, build 8010](https://www.manageengine.com/products/ad-manager/release-notes.html), [service pack help](https://www.manageengine.com/products/ad-manager/help/getting_started/installing_service_packs.html) |

---

## 4. UX and workflow

All observations come from the public demo (Professional, build 8041) on 2026-10-02 unless another source is cited. The demo is shared by all visitors, so its data (custom dashboards, automations, requests) is user-generated.

### 4.1 Console navigation

- **Header:** app switcher, Zia, License, notification bell, AD Explorer, TalkBack and the account menu. Below them sit the global "Search AD Objects" box and the "Directory/Application Settings" button. The dashboard also has a "Create Request" button.
- **11 top tabs:** Home, Management, Reports, Microsoft 365, Governance, Delegation, Workflow, Automation, Admin, Backup, Support.
- **Three levels of navigation inside a tab:**
  1. A horizontal sub-menu bar. Management's bar: User Management, Bulk User Modification, Computer Management, Bulk Computer Modification, Group Management, Contact Management, Mailbox Management, More.
  2. A left pane. Management's pane: User, Computer, Group, Contact, Mailbox, OU, File Server and GPO Management; CSV Import; Migration; Advanced Management.
  3. Landing pages that list actions as grouped links.
- **Link counts:** the Management › User Management landing page shows about 64 action links (81 clickable labels including the header and tabs, counted by DOM script). They are grouped under User Creation, User Modification, User Templates, CSV Import, Bulk User Modification, Exchange Tasks, Exchange Mailbox Tasks, Exchange Limits and Terminal Services.
- **Reports:** 12 categories in the left pane plus a "Schedule Reports" button. Reports per category: User 35, Password 8, Group 16, Computer 18, Exchange 31, Contact & OU 13, GPO 28, NTFS & Security 12, Other 5, Compliance 49. The Google Workspace landing page showed 3 entries; the help lists 7 user reports plus group and OU reports. Custom reports are separate.
- **Microsoft 365 tab:** an iframe app (`/ompemberapp/ompindex.html`) with its own Reports/Management toggle and left pane. The pane is still labelled "Azure Active Directory" (User, Group, Contact and License Reports), then Exchange Online (Mailbox and OWA Reports) and Other Services (Security Reports).
- **Other tabs:**
  - Governance: Access Certification (Campaigns, Certifier Assigning Rule) and Risk Management (Identity Risk Assessment, Risk Exposure Management).
  - Workflow: Requests; Workflow Delegation (Technicians, Assigning Rules, Requester Roles); Configuration (Business Workflow, SLAs).
  - Automation: Automation and Event-driven Automation; Configuration (Automation Policy, Orchestration Template, Application Integrations).
  - Admin: Custom Settings (Naming Formats, Organization Attributes, Password Policy, LDAP Attributes, Delete/Disable Policy, Custom Functions), Marketplace, System Settings and Employee Preferences.
- **Naming formats** appear to admins as macro strings, e.g., `%givenName%1[L]()%sn%2[L]()%rand%3[905-999]`, alongside a builder dialog ([help](https://www.manageengine.com/products/ad-manager/help/admin-settings/active-directory-cutomize-naming-format.html)).
- **Two page types:** Ember single-page routes (`#/mgmt`, `#/reports`, `#/governance/...`) and full-page server-rendered forms (`ExecuteForm.do`, `BulkExecuteForm.do`). Opening Create Single User or Create Bulk Users reloads the whole page.

### 4.2 Page weight and load time (demo, indicative)

| Screen | Metric | Value |
|---|---|---|
| Login → dashboard rendered | wall clock (screenshots) | ≈ 24 s |
| Create Single User (`ExecuteForm.do`) | HTML size: uncompressed / transferred | 10.4 MB / 3.1 MB |
| Create Single User | DOMContentLoaded / load events | 20.4 s / 22.9 s; 88 sub-resources (1.4 MB) |
| Logged-in shell (`/`) | inline UI-string bundle | ≈ 5.2 MB of inline script, holding 44,228 UI strings (many prefixed `o365.*`) |
| Microsoft 365 tab | time to render | ≈ 26 s |

**Caveats:** single session, shared demo, and network distance to the demo host. Treat these numbers as directional. Re-measure on a local evaluation install before using them externally **[TODO]**.

### 4.3 Typical flows

| Flow | Path in ADMP | Screens / clicks (approx.) | Notes |
|---|---|---|---|
| **Bulk-create users from CSV** | Management → Create Bulk Users → pick domain, M365 tenant and template → **step 1** Import CSV, review the grid → **step 2** choose container (OU tree or new OU) → **step 3** creation and status | 3 wizard steps; about 8–10 clicks plus preparing the CSV (inference from demo and help) | CSV headers must be LDAP attribute names. `memberOf` and manager must be DNs (or sAMAccountName for manager); `ouName` is a quoted DN; a `templateName` column applies a template. M365 licenses and Teams come from the template ([help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_multiple_windows_users.html), [demo](https://demo.admanagerplus.com/)). |
| **Reset password + unlock** | Home → Help Desk Reset Password Console → find the user in the grid → Reset Password → pop-up: generate or type a password, "must change at next logon", tick "Account is locked out" → OK | 2 screens; about 5–6 clicks plus typing | The console grid listed system and Exchange arbitration mailboxes alongside people (demo). The other path, Management → Reset Password, preselected "Same as logonname" as the password option in the demo, and unlock there is a separate action (Unlock Users). Zia chat or the mobile app can also do it. |
| **Offboard a leaver** | One-time setup: Admin → Custom Settings → Delete/Disable Policy (mailbox, licenses, Teams and M365 groups, Google Workspace, OU move, group removal, folders, script). Then per leaver: Management → Enable/Disable Users → find → Disable. | Per leaver about 5–7 clicks after setup (inference; not timed) | Automating it (Pro) needs an HCM/CSV data source plus a scheduled automation or policy (disable → move → delete), optionally with approval workflow and event-driven orchestration blocks ([delete policy help](https://www.manageengine.com/products/ad-manager/help/admin-settings/windows-active-directory-delete-policy.html), [orchestration help](https://www.manageengine.com/products/ad-manager/help/orchestration/new-orchestration-template.html)). A single offboarding screen that previews every change across AD, M365, Google Workspace and file servers is not documented in the help as of 2026-10-02. |

### 4.4 What reviewers and docs say about usability

- **Capterra:** 4.6/5 from 111 reviews; ease of use 4.5/5; customer service 4.5/5, as displayed on 2026-10-02 ([Capterra](https://www.capterra.com/p/143496/ADManager-Plus/reviews/)).
  - Praise centers on bulk changes, fast reporting and delegating without domain-admin rights.
  - 2026 critical reviews mention:
    - the interface's look;
    - a learning curve from the many settings;
    - functions buried in sub-menus;
    - reporting that is hard to work through;
    - a complex upgrade process;
    - limited depth in file-server/NTFS governance.
  - Representative quote: "The interface feels outdated and clunky" — Hendra I., Senior System Administrator, Retail, Capterra, 2026-06-23 ([Capterra, lowest-rated sort](https://www.capterra.com/p/143496/ADManager-Plus/reviews/?sort=lowest_rated)).
- **PeerSpot:** 4.0/5 from 16 reviews; 94% would recommend.
  - Reviewers report some features are not intuitive and needed support calls.
  - They report API integrations do not exist for every HR tool (SAP HCM named), and limits when integrating beyond Microsoft.
  - They report no tablet-optimized layout. Setup took 15 minutes to 2 days ([PeerSpot](https://www.peerspot.com/products/manageengine-admanager-plus-reviews)).
- **Setup steps outside the UI** (from the docs):
  - add the Jespa JAR for NTLM SSO ([SSO help](https://www.manageengine.com/products/ad-manager/help/admin-settings/single-sign-on-authentication.html));
  - copy RSA SecurID JARs and `sdconf.rec` ([2FA help](https://www.manageengine.com/products/ad-manager/help/admin-settings/two-factor-authentication.html));
  - edit the Windows `hosts` file for NetApp/Isilon ([file server help](https://www.manageengine.com/products/ad-manager/help/user_management/file-server-management/active-directory-manage-file-servers.html));
  - grant least privilege by hand with Delegation of Control ([permissions PDF](https://download.manageengine.com/products/ad-manager/permissions-required-for-the-ad-account-configured-in-admanager-plus.pdf));
  - create a Google P12 key ([GWS help](https://www.manageengine.com/products/ad-manager/help/directory-application-settings/google-apps-active-directory-management-tool.html)).
- **Still to do:** G2, TrustRadius, Gartner Peer Insights and Reddit/Spiceworks sentiment **[TODO]** (access blocked during this pass).

---

## 5. Release velocity (2024–2026)

Source for every row: [release notes](https://www.manageengine.com/products/ad-manager/release-notes.html), checked 2026-10-02.

| Build | Date | Notable additions |
|---|---|---|
| 7223 | 2024-01-22 | Security fixes, including CVE-2024-0252 (remote code execution in the load-balancer component) |
| 7224 | 2024-02-19 | Log360 ↔ ADMP SOAR workflow integration |
| 7230 | 2024-03-06 | M365 risk assessment. Access certification for NTFS, M365 groups, roles and apps. Copy GPOs across domains. Orchestration triggered by inbound webhooks. Group-membership duration. ServiceDesk Plus integration upgrades. Redesigned workflow requests. |
| 7232 | 2024-04-16 | Central technician management from AD360 |
| 7240 | 2024-07-19 | MS SQL Always On availability groups and failover clusters. Database migration to Azure/AWS SQL. Windows LAPS in AD Explorer. Reset and delete computers. Custom-report dashboard widgets. Technicians can edit and resend failed requests. |
| 7250/7251 | 2024-10-04 | All managers as reviewers/approvers. DFS permissions view. Orchestration time delays. Google Workspace profile fields. CVE-2024-48878 fixed. |
| 8000 | 2024-12-26 | ML Access Recommendations. +34 risk indicators and risk-score trend. Integration-framework upgrades. 60+ predefined app configurations. |
| 8001 | 2025-02-03 | 32-bit support discontinued; jQuery 3.7.1 |
| 8010 | 2025-03-31 | Windows Server 2025. M365 without a mandatory service account. Diagnostic tools. Redesigned Backup tab with Quick Recovery. |
| 8011 | 2025-04-10 | Load balancer with failover |
| 8012 | 2025-05-20 | MSOnline replaced by Microsoft Graph; some MFA methods removed after Microsoft deprecations |
| 8020 | 2025-07-02 | Risk Exposure Management. Governance tab. +48 risk indicators and a misconfigurations category. Dynamic group membership. Computer migration. Mailbox conversion. Merge GPOs. SQL Server 2022. Domain ↔ tenant linking. Conditional Access blocks. LAPS role. |
| 8021 | 2025-07-18 | "Remove Microsoft 365 Roles" action |
| 8022–8025 | 2025-08-01 → 10-13 | Fixes; CVE-2025-10020 fixed in 8024; CVE-2025-11670 fixed in 8025 |
| 8030 | 2025-10-30 | Zia AI assistant and Zia Insights. Advanced Recovery (AD + Entra ID rollback). BitLocker key retrieval. +50 apps. More REST API v2 coverage. Orchestration success/failure flows, Database Operations and sync-to-domain blocks. CSP headers. |
| 8031–8033 | 2025-11-17 → 12-16 | M365 fields (manager, employee type, extension attributes 1–15). Custom backup repository (local/NAS). Kerberos AES flags. |
| 8034 | 2026-01-21 | Marketplace Extensions; reports from CSV across several domains |
| 8035–8036 | 2026-01-28 → 02-06 | Fixes; M365 security-group modification |
| 8040/8041 | 2026-03-09 | Runtime moves to JRE 11.86.19 |
| 8042 | 2026-04-22 | Fixes; three ZVE-2026 security fixes |
| 8043 | 2026-07-06 | Fixes; RCE fix for CSV input with embedded PowerShell; PostgreSQL 15.18, Tomcat 9.0.118, Log4j 2.25.4 |

**Cadence**

- Release entries: 10 in 2024, 15 in 2025, 6 in 2026 to date (Jan–Jul).
- Feature-bearing releases came roughly every quarter through Jan 2026: 7230, 7240, 7250, 8000, 8010, 8020, 8030, 8034.
- Since 8034, releases have been mostly fixes, security updates and a runtime upgrade; 8036 added one minor M365 enhancement.
- No release between 2026-07-06 and 2026-10-02.
- Mobile app: v2.5.0 shipped 2024-07-20; v2.5.1 is listed without a date ([mobile release notes](https://www.manageengine.com/products/ad-manager/help/mobile/release-notes.html)).

---

## 6. Weaknesses and gaps (factual, sourced, as of 2026-10-02)

| # | Area | Finding | Source |
|---|---|---|---|
| W1 | Deployment | Windows-only server. One installation per license. HA needs both nodes in the same subnet, and HA can only be disabled from the standby. Turning on the load balancer disables HA and smart-card login. Automatic hotfixes are not available with HA. | [system requirements](https://www.manageengine.com/products/ad-manager/help/getting_started/system_requirements.html), [license terms](https://www.manageengine.com/products/ad-manager/license.html), [HA help](https://www.manageengine.com/products/ad-manager/help/admin-settings/high-availability.html), [LB help](https://www.manageengine.com/products/ad-manager/help/admin-settings/enterprise-essentials/active-directory-load-balancing.html), [hardening help](https://www.manageengine.com/products/ad-manager/help/admin-settings/security-and-privacy-settings-admanager-plus.html) |
| W2 | Platform | Bundled components include Struts 1.3.11, OpenSAML 2.6.1 and DWR 2.0.2. Release notes show recurring component upgrades (Tomcat, PostgreSQL, JRE, Log4j, 7-Zip, POI). Struts 1.x end-of-life status was not checked in this pass **[UNVERIFIED]**. | [third-party list](https://www.manageengine.com/products/ad-manager/help/third-party-software.html), [release notes](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| W3 | Security defaults | HTTP on 8080 unless HTTPS is configured. First login uses admin/admin. The built-in admin can skip 2FA. TLS 1.0/1.1 stay available until "enforce secure TLS" is set. The demo's hardening score was 40%. | §2.10 sources, [demo](https://demo.admanagerplus.com/) |
| W4 | Audit attribution | With "Impersonate as Admin", domain-controller logs show the service account. CVE-2025-11670 (NTLM hash exposure, fixed in 8025) was tied to this mode. | [help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/group-based-delegation.html), [advisory](https://www.manageengine.com/products/ad-manager/admanager-kb/cve-2025-11670.html) |
| W5 | Password handling | The reset page offers "same as logon name" and "leave blank". The data-security guide lists end-user passwords in audit data as stored with AES-256 (reversible). Reset passwords can be sent by SMS or email. | [demo](https://demo.admanagerplus.com/), [data-security PDF](https://download.manageengine.com/products/ad-manager/encryption-and-data-storage-in-admanager-plus-database.pdf), [release notes, build 8040](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| W6 | Data freshness | Reports read a database cache synced from AD every 10 minutes; the dashboard refreshes daily. | [architecture PDF](https://download.manageengine.com/products/ad-manager/solution-architecture.pdf) |
| W7 | Licensing | Per domain, child domains included. Named technician licenses. API quota of 50 calls per technician per day, with paid overage. Standard excludes group/OU/contact/GPO management, scheduling, workflow and automation. GRC is Pro-only. Backup is a per-user add-on, and the base product's backup is limited. Migration is capped at 500 objects. | §1.5 |
| W8 | Usability | About 64 action links on one landing page. Mixed SPA and full-page forms. 10.4 MB Create User page in the demo. The M365 iframe app has its own layout and still uses the label "Azure Active Directory". CSV needs LDAP and DN syntax. Naming formats appear as macro strings. Some setup happens outside the UI. | §4 |
| W9 | Integrations | Custom integrations are configured at the API level: JSON-path conditions, pagination, dependent endpoints, XML path CSVs. The marketplace lists 5 extensions. Oracle HCM Cloud is not on the HCM list. A PeerSpot reviewer reports SAP HCM is not supported. | [custom apps help](https://www.manageengine.com/products/ad-manager/help/directory-application-settings/third-party-integrations/custom-applications.html), [extensions list](https://www.manageengine.com/products/ad-manager/help/admin-settings/extensions/supported-extensions.html), [HCM page](https://www.manageengine.com/products/ad-manager/hcm-integration.html), [PeerSpot](https://www.peerspot.com/products/manageengine-admanager-plus-reviews) |
| W10 | Event triggers | Event-driven automation is configured on action types performed through ADMP. Triggers on AD changes made outside ADMP (e.g., in ADUC or PowerShell) are not documented in the automation help as of 2026-10-02 (inference: native change monitoring sits in ADAudit Plus). | [help](https://www.manageengine.com/products/ad-manager/help/orchestration/orchestration-profile.html) |
| W11 | AI | Zia covers 4 actions plus object reports, needs the customer's Azure OpenAI deployment, and shows an in-product disclaimer that responses may contain mistakes. | [Zia help](https://www.manageengine.com/products/ad-manager/help/admin-settings/zia-configuration.html) |
| W12 | Documentation drift | **(a)** Known Issues still says the DC Replication report cannot be scheduled, but build 8030 added scheduling. **(b)** The load-balancer page still says to install the MSOnline module, which build 8012 retired. **(c)** The deployment page says ADMP talks to AD over plain LDAP, with LDAPS planned, while the hardening page offers LDAPS. **(d)** The templates page still asks for the Windows Azure module. | [known issues](https://www.manageengine.com/products/ad-manager/help/misc/known_issues.html), [release notes](https://www.manageengine.com/products/ad-manager/release-notes.html), [LB help](https://www.manageengine.com/products/ad-manager/help/admin-settings/enterprise-essentials/active-directory-load-balancing.html), [deployment help](https://www.manageengine.com/products/ad-manager/help/getting_started/deployment_scenarios.html), [hardening help](https://www.manageengine.com/products/ad-manager/help/admin-settings/security-and-privacy-settings-admanager-plus.html), [templates help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_user_templates.html) |
| W13 | Templates | Changing a template does not update users already created from it. Cross-domain `memberOf` in templates works only through CSV. | [templates help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_user_templates.html) |
| W14 | Governance | GRC is a paid add-on, Pro only. A segregation-of-duties (SoD) rule engine is not documented; ManageEngine's SoD article (2026-03-19) maps SoD to delegation, workflow and certification. Compliance mappings cover SOX, HIPAA, PCI DSS, GLBA, FISMA and GDPR (plus a SOC 2 + HIPAA help page); ISO 27001, NIST 800-53, CMMC and NIS2 mappings are not documented on the compliance page as of 2026-10-02. | [licensing FAQ](https://www.manageengine.com/products/ad-manager/licensing-faq.html), [SoD blog](https://www.manageengine.com/products/ad-manager/blog/what-is-segregation-of-duties.html), [compliance page](https://www.manageengine.com/products/ad-manager/compliance-reports.html) |
| W15 | Cloud coverage | SharePoint management is not documented in ADMP (sold separately as SharePoint Manager Plus). Orchestration cloud actions apply only to DirSync-synced users. MFA management options shrank after Microsoft deprecations (8012). | [orchestration help](https://www.manageengine.com/products/ad-manager/help/orchestration/new-orchestration-template.html), [release notes](https://www.manageengine.com/products/ad-manager/release-notes.html) |
| W16 | Mobile | The app must reach the on-prem server (same LAN or exposed server settings). It covers basic user/computer actions, reports and workflow. Two mobile releases since mid-2024. | [mobile help](https://www.manageengine.com/products/ad-manager/help/mobile/getting-started/getting-started.html), [mobile release notes](https://www.manageengine.com/products/ad-manager/help/mobile/release-notes.html) |
| W17 | Delivery model | No vendor-hosted SaaS edition is documented. ManageEngine markets Identity360 (cloud-native IAM) as a separate product. | §1.6 |
| W18 | Release activity | 6 releases in 2026 to date, mostly fixes and security; none between 2026-07-06 and 2026-10-02. | §5 |

---

## 7. Parity vs leapfrog

These are recommendations for activeDIQ scoping, not product commitments. Where a call depends on a specific prospect's usage, confirm it in discovery.

### 7a. Must-have on day one for a switching ADMP customer

| Capability | ADMP IDs | Why switchers expect it |
|---|---|---|
| Single and bulk user create/modify, CSV import, templates, naming formats, password generation, home folders | ADM-008–024, 033–034 | Core daily work for every ADMP edition |
| Help-desk reset + unlock with "must change at next logon" | ADM-022, 136 | Highest-volume help-desk task |
| Enable, disable, delete, move and restore users and computers; BitLocker/LAPS lookup | ADM-034, 038, 055–057, 060 | Standard-edition baseline |
| Group membership management, including nested and cross-domain | ADM-048–050 | Pro baseline; also needed for joiner/leaver |
| Delegation: roles with task- and attribute-level rights, OU and group scope, group-based technicians | ADM-125, 127–130 | Core reason ADMP is bought (non-invasive delegation) |
| Complete audit of console actions and config changes; exportable and schedulable | ADM-137–139 | Compliance and RFP requirement |
| The most-used reports with CSV/PDF/XLSX export and scheduled email: inactive users/computers, real last logon, locked-out, password expiry, nested group membership, empty groups, OS-based computers | ADM-084–088, 100–101 | Replaces daily and monthly report routines |
| Act on report results, plus AD cleanup | ADM-098, 146–148 | Widely used ADMP workflow |
| Leaver policy: disable → revoke M365 licenses → remove groups → move OU → hide/convert mailbox | ADM-043–045 | Offboarding is a key compliance control |
| Scheduled automation from reports, CSV or HR feeds; staged cleanup policies | ADM-039–041, 104–106 | Pro customers depend on it |
| Request → review → approve → execute workflow with manager routing | ADM-116–119 | Pro customers with SOX or change control |
| M365 provisioning: licenses, groups and mailbox basics at creation; remote mailbox | ADM-026–027, 070, 159–163 | Most ADMP customers run hybrid |
| Multi-domain and multi-forest support | §2.9 | Enterprise baseline (and an ADMP licensing pain point) |
| ITSM integration (ServiceNow, ServiceDesk Plus) and REST API | ADM-188–192 | Ticket-driven operations |
| Console SSO (SAML/Entra ID) and MFA for admins | ADM-142–143 | Security baseline in RFPs |
| HA option | ADM-210 | Enterprise baseline |
| Compliance report packs (SOX, HIPAA, PCI DSS, GDPR) and a custom LDAP report builder | ADM-093, 097 | RFP checklist items |

### 7b. Can be deferred (phase 2+, unless a target customer depends on it)

| Capability | ADMP IDs | Why it can wait |
|---|---|---|
| Skype for Business / Lync / OCS attributes | ADM-030 | Older Microsoft UC platform (inference); check whether prospects still use it |
| Terminal Services attribute editing | ADM-031 | Niche; check usage |
| AD migration (users, computers, GPOs) | ADM-185–187 | Project-based; capped at 500 objects even in ADMP |
| Deep GPO editing (admin templates, preferences, merge) | ADM-072, 076 | GPMC is still the native tool. GPO reports and link management may be needed sooner; verify |
| Advanced on-prem Exchange (mailbox migration, OAB, UM/ActiveSync policies) | ADM-065, 067–068 | Depends on remaining on-prem Exchange footprint (verify per customer) |
| Google Workspace management and backup | ADM-155, 171–173 | Only for Google Workspace customers |
| NAS file servers (NetApp, Isilon, Huawei) | ADM-078 | Start with Windows and DFS |
| Native mobile apps | ADM-201–203 | A responsive web console covers the urgent cases first |
| Power BI push, Zoho Flow, marketplace extensions | ADM-197, 199–200 | Low effect on switching |
| Risk exposure graph and identity risk assessment | ADM-174–176 | Paid GRC add-on in ADMP; only needed for customers who license it |
| Full backup and recovery (AD, Entra ID, Google Workspace) | ADM-149–156 | Paid add-on in ADMP; many shops use separate backup tools (inference). See 7c for a lighter undo. |
| MSP multi-tenant edition | §1.3 | Separate go-to-market |

### 7c. Where activeDIQ can leapfrog

| Opportunity | ADMP baseline (sourced) | activeDIQ approach (proposal) | Why it matters |
|---|---|---|---|
| **Task-first UX** | Three navigation levels; about 64 links on one landing page; full-page server-rendered forms; 10.4 MB form page in the demo (§4) | Command palette plus universal search that runs actions inline; single-page flows. Set targets, e.g., reset+unlock in ≤ 3 interactions. | Directly addresses the CEO's "far easier to use" requirement; measurable in demos |
| **Preview, then undo** | Rollback needs the per-user Backup add-on (ADM-153); no single offboarding preview is documented (§4.3) | Show an impact diff (AD + M365 + file servers) before running; one-click undo for any change made through activeDIQ | Lowers fear of bulk changes; replaces a paid add-on for the common case |
| **Fresh data and native-change triggers** | Reports read a cache synced every 10 minutes; event triggers fire on ADMP actions (W6, W10) | Near-real-time change tracking (e.g., DirSync/USN polling) driving reports and automations for **any** AD change | Correct, current data; cleaner joiner/mover/leaver |
| **Smart CSV / HR import** | LDAP attribute headers and DN syntax required (ADM-011) | Auto-map columns, accept group names instead of DNs, preview validation row by row, save mappings | Removes the most common bulk-import errors |
| **Unmetered API and events** | 50 calls per technician per day; US$1 per extra call/day (ADM-190) | Generous or unmetered API, webhooks/event stream, PowerShell module and Terraform provider | ITSM and HR integrations without quota planning |
| **Simple licensing** | Per domain including child domains; named technicians; add-ons for backup and GRC (§1.5) | Per-user (or per-tenant) pricing covering all domains in a forest; no per-technician metering | Easy to quote in RFPs; removes ADMP cost drivers |
| **Secure by default** | HTTP by default, admin/admin first login, admin may skip 2FA, TLS 1.0/1.1 selectable (W3) | HTTPS and first-run admin setup; MFA required for every admin including break-glass; FIDO2/passkeys; TLS 1.2+ only | Tier-0 tool; security reviewers will check |
| **True per-technician attribution** | DC logs show the service account under "Impersonate as Admin" (W4) | Per-request identity correlation (e.g., audit IDs stamped on changes, signed audit log, SIEM streaming) | Meets auditors' "who changed what" in AD's own logs |
| **Least-privilege setup wizard** | Domain Admin recommended, or a manual Delegation-of-Control guide (§2.3) | Generate, apply and verify least-privilege ACLs per enabled feature (gMSA where possible) | Removes the Domain-Admin service-account objection |
| **Cloud control plane + light on-prem connectors** | Single Windows server; same-subnet HA; ME's SaaS is a different product (W1, W17) | SaaS (or self-hosted) control plane with redundant per-site connectors | Multi-site resilience; no server to patch |
| **AI copilot with guardrails** | Zia: 4 actions + reports; customer's own Azure OpenAI (ADM-181) | Natural-language access to any permitted action, dry-run preview, explanations, approval routing, policy-scoped by role | Visible differentiator on top of the UX gains |
| **Policy-bound templates with drift detection** | Template edits don't update existing users (W13) | Templates and roles bound to users; detect and fix drift | Ongoing compliance, not one-time provisioning |
| **SoD rules** | No SoD rule engine documented (W14) | Toxic-combination rules checked at request time and in certifications | IGA-grade control without a GRC add-on |
| **ADMP migration assistant** | Configuration reachable via REST API v2 and the product database (ADM-189, §2.1) | Import ADMP templates, naming formats, roles, technicians and automations (feasibility **[UNVERIFIED]**) | Cuts switching cost for the CEO's warm accounts |
| **One console for AD + Entra ID + M365** | M365 is a separate iframe app with its own navigation (§4.1) | One object model and UI across directories | Consistency; fewer clicks in hybrid tasks |

---

## Open items

- **[TODO]** G2, TrustRadius, Gartner Peer Insights, Reddit and Spiceworks sentiment (blocked: HTTP 403 / no automated access).
- **[TODO]** Confirm edition placement for every "n/s" row, through a 30-day evaluation install or the vendor's sales team.
- **[TODO]** Confirm how technician licenses are counted under group-based delegation, and whether HA standby or load-balancer nodes need extra licenses.
- **[TODO]** Confirm whether event-driven automation can trigger on AD changes made outside ADMP.
- **[TODO]** Re-measure page weight and load times on a local evaluation install (build 8043).
- **[TODO]** Get non-US list prices. AD360 bundle pricing belongs in `manageengine-ad360-suite-and-commercials.md`.

## Key sources

- Product page: https://www.manageengine.com/products/ad-manager/
- Release notes: https://www.manageengine.com/products/ad-manager/release-notes.html
- Help docs: https://www.manageengine.com/products/ad-manager/help/
- Pricing: https://www.manageengine.com/products/ad-manager/pricing-details.html
- Store: https://store.manageengine.com/ad-manager/ and https://store.manageengine.com/ad-manager/perpetual.html
- Licensing FAQ: https://www.manageengine.com/products/ad-manager/licensing-faq.html
- Solution architecture PDF: https://download.manageengine.com/products/ad-manager/solution-architecture.pdf
- Data-security PDF: https://download.manageengine.com/products/ad-manager/encryption-and-data-storage-in-admanager-plus-database.pdf
- REST API v2: https://www.manageengine.com/products/ad-manager/active-directory-api/v2/introduction/
- API daily-quota KB: https://www.manageengine.com/products/ad-manager/admanager-kb/fix-daily-api-limit-exceeded.html
- Public demo: https://demo.admanagerplus.com/ (observed 2026-10-02, build 8041)
- Reviews: https://www.capterra.com/p/143496/ADManager-Plus/reviews/ and https://www.peerspot.com/products/manageengine-admanager-plus-reviews

## Changelog

- **2026-10-02:** Initial draft. All sections researched against the sources above on 2026-10-02 (`sources_last_checked` covers the whole file). Feature IDs ADM-001 to ADM-213 assigned. Review-site sentiment beyond Capterra and PeerSpot is open **[TODO]**.
