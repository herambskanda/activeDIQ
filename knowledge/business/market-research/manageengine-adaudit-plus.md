---
title: "Competitive Benchmark: ManageEngine ADAudit Plus"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: heramb
sources_last_checked: 2026-10-02
---

# Competitive Benchmark: ManageEngine ADAudit Plus

**What it is:** ManageEngine (Zoho Corp) calls it a "UBA-driven change auditor" for Active Directory, Microsoft Entra ID, Windows file servers, NAS, Windows servers and workstations ([product home](https://www.manageengine.com/products/active-directory-audit/), [datasheet, Jul 2026](https://download.manageengine.com/products/active-directory-audit/adaudit-plus-datasheet.pdf)).
**Current version:** ADAudit Plus **9.0, build 9000, released 2026-09-30** ([release notes](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html), [service-pack page](https://www.manageengine.com/products/active-directory-audit/service-pack.html)). The public demo still ran **build 8703** on 2026-10-02 (asset URLs `?v=8703` on [demo.adauditplus.com](https://demo.adauditplus.com/)), so we could not try the 9.0 UI ourselves.

Tags: `[UNVERIFIED]` = could not confirm from a primary source. `[TODO]` = not researched yet. If we found no evidence of a feature, we say so. We do not treat that as proof the feature is missing.

---

## 1. Overview, editions & pricing

### 1.1 Delivery model
| Item | Finding | Source |
|---|---|---|
| Deployment | Software you install yourself on Windows (Server 2008 to 2025, or a Windows Vista to 11 client). It ships with PostgreSQL; MS SQL is optional. | [System requirements](https://www.manageengine.com/products/active-directory-audit/help/quickstart/system-requirements.html) |
| SaaS | We found no SaaS edition of ADAudit Plus. ManageEngine's cloud option for AD auditing is the separate **Log360 Cloud** SIEM, which advertises "Real time AD auditing". | [Log360 Cloud](https://www.manageengine.com/cloud-siem/) |
| Suites | Integrates with **AD360** (IAM suite; SSO, per the build 8703 notes) and **Log360** (SIEM). Build 8700 requires Log360 build 13025+ for the Log360 integration to keep working. Whether ADAudit Plus is also sold as an AD360 module `[TODO]` (see the AD360 benchmark). | [pricing page nav](https://www.manageengine.com/products/active-directory-audit/pricing-details.html), [release notes 8700](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| Scale claims | Demo landing page: "20,000+ customers, 190 countries". Gartner Peer Insights Customers' Choice for **SIEM**, 4 years in a row (vendor claim). | [demo](https://demo.adauditplus.com/), [UBA page](https://www.manageengine.com/products/active-directory-audit/user-behavior-analytics.html) |

### 1.2 Editions
| Edition | What you get | Source |
|---|---|---|
| **Free** | Never expires. Audits 25 workstations. "No fresh data will be collected after 30 days (excludes Workstations)". "Reports generation from event log data collected during evaluation / license period." | [Licensing help](https://www.manageengine.com/products/active-directory-audit/help/quickstart/adaudit-plus-license-and-edition-details.html) |
| **Trial** | 30 days of Professional, capped at 5 DCs, 2 file servers, 1 NetApp filer, 10 member servers and 100 workstations. After that it falls back to Free. | same |
| **Standard** (from $595/yr) | AD logon monitoring. User/group/computer/OU/GPO change auditing. Admin and help-desk activity auditing. Scheduled reports and threshold email alerts. Compliance reports. LAPS auditing. Account lockout **reports**. | [Compare editions](https://www.manageengine.com/products/active-directory-audit/pricing-details.html) |
| **Professional** (from $945/yr) | Everything in Standard, plus: **Account Lockout Analyzer**, **GPO setting-level audit**, **all attribute changes**, **old/new (before/after) values** (WS2008+), **AD permission change audit**, **DNS server auditing**, **schema, contacts & configuration auditing**, **MS SQL back end**. | same |

> **Gotcha:** before/after values, GPO setting diffs and ACL changes all require **Professional**. A Standard-edition customer only gets "who changed what object", without the old and new values ([compare editions](https://www.manageengine.com/products/active-directory-audit/pricing-details.html)).

### 1.3 Licensing units
The base license is counted per **domain controller**, with an "unlimited number of objects" ([licensing help](https://www.manageengine.com/products/active-directory-audit/help/quickstart/adaudit-plus-license-and-edition-details.html)). Everything else is a paid add-on, and the add-on prices are the same for Standard and Professional (verified on the [store API](https://store.manageengine.com/api/public/json/productdetails/a4e670c116c71e630f623a894e884aaa.js)):

| Add-on | License unit | Notes | Source |
|---|---|---|---|
| Microsoft Entra ID ("Azure AD audit") | Tenant | | [pricing](https://www.manageengine.com/products/active-directory-audit/pricing-details.html) |
| Windows file servers | Server | Failover-cluster auditing is part of the same add-on. Whether clusters count per node or per cluster is `[UNVERIFIED]`. | same |
| NAS file servers | Varies by vendor: **CIFS server** (NetApp, EMC, Synology, Hitachi, QNAP, FSx for ONTAP), **zone** (EMC Isilon), **FSx file system** (FSx for Windows), **vStore** (Huawei), **storage account** (Azure Files), **Nutanix Files instance**, **Edge Filer** (CTERA), **self-managed file system** (Qumulo) | Hard for buyers to count ahead of time | same |
| Windows member servers | Server | Includes local logon, FIM, printer, RADIUS/NPS, ADFS, AD LDS | same |
| Workstations | Workstation (Windows and Mac) | Includes work hours, FIM, USB, local logon, local accounts, startup/shutdown, Mac logon | same |
| AD Backup & Recovery | Enabled AD user objects | Groups, computers etc. are not counted. Without the add-on, backups are weekly only and limited to one domain. | [AD B&R FAQ](https://www.manageengine.com/products/active-directory-audit/help/usecase/ad-backup-and-recovery-overview.html) |
| File Analysis | TB of data analyzed | Licensed add-on since build 8600 (Jan 2026). Agent required. | [release notes 8600](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html), [File Analysis help](https://www.manageengine.com/products/active-directory-audit/help/usecase/file-analysis-overview.html) |
| Attack Surface Analyzer, CSPM/SSPM, Access Analyzer, Cloud File Transfer Monitoring (build 9000) | **Not listed** on the pricing page or store as of 2026-10-02 | Licensing unclear `[UNVERIFIED]` | [pricing](https://www.manageengine.com/products/active-directory-audit/pricing-details.html) |

### 1.4 List prices: annual subscription (USD)
Source: [pricing-details](https://www.manageengine.com/products/active-directory-audit/pricing-details.html), cross-checked against the [store API (subscription)](https://store.manageengine.com/api/public/json/productdetails/a4e670c116c71e630f623a894e884aaa.js).

| Domain controllers | Standard | Professional |
|---|---|---|
| 2 | $595 | $945 |
| 5 | $1,195 | $1,795 |
| 10 | $2,145 | $3,495 |
| 15 | $3,395 | $5,095 |
| 20 | $4,395 | $6,595 |
| >20 | quote | quote |

| Add-on tiers (annual) | Prices |
|---|---|
| Entra ID tenants | 1: $995 · 2: $1,695 · 3: $2,295 · 5: $3,495 · >5: quote |
| Windows file servers | 2: $495 · 5: $1,045 · 10: $1,995 · 15: $2,845 · 20: $3,595 · >20: quote |
| NAS file servers | 1: $595 · 2: $995 · 3: $1,395 · 5: $2,195 · >5: quote |
| Windows member servers | 5: $345 · 10: $595 · 20: $945 · 50: $1,995 · 100: $3,295 · >100: quote |
| Workstations | 100: $245 · 250: $595 · 500: $945 · 1,000: $1,795 · >1,000: quote |
| AD Backup & Recovery (users) | 250: $195 · 500: $295 · 1k: $495 · 2k: $995 · 3k: $1,445 · 5k: $2,245 · >5k: quote |
| File Analysis (TB) | 2: $145 · 5: $295 · 10: $495 · 15: $645 · 20: $745 · 40: $1,295 · 50: $1,495 · >50: quote |

**Perpetual licenses are still sold.** The store has a "Subscription / Perpetual" toggle ([store](https://store.manageengine.com/active-directory-audit/)). Examples from the [store API (perpetual)](https://store.manageengine.com/api/public/json/productdetails/83f31b4bf780a2bbe86cb62bd2bb1659.js), shown as license fee + annual maintenance & support (AMS):

| SKU | Perpetual license | AMS/yr |
|---|---|---|
| Standard, 2 DCs | $1,488 | $298 |
| Standard, 10 DCs | $5,363 | $1,073 |
| Professional, 2 DCs | $2,363 | $473 |
| Professional, 10 DCs | $8,738 | $1,748 |
| Professional, 20 DCs | $16,488 | $3,298 |
| Entra ID, 1 tenant | $2,488 | $498 |
| NAS, 1 server | $1,488 | $298 |
| Workstations, 1,000 | $4,488 | $898 |

A perpetual license costs about 2.5× the annual subscription, and AMS is about 20% of the license fee per year.

**Paid services** ([store API (onboarding)](https://store.manageengine.com/api/public/json/productdetails/1bee5be03b03fb35c883fd4a9e6db18d.js)):
- Standard onboarding (online): $3,495
- Advanced onboarding: $4,995 online, $9,995 onsite
- Training for up to 4 people: $495 (add-on to onboarding). Standalone online training, 4 hours, up to 5 people: $995 ([store API (subscription)](https://store.manageengine.com/api/public/json/productdetails/a4e670c116c71e630f623a894e884aaa.js))
- À-la-carte configuration help: $295 each

The onboarding scope listed on the store includes "Historic EVT/EVTX file import", "Database migration (PGSQL to MSSQL)" and "Rebranding" ([store](https://store.manageengine.com/active-directory-audit/)).

### 1.5 Sample annual bills (Professional, list price, before discounts)
Computed from the list prices above.

| Profile | Components | Annual list price |
|---|---|---|
| **Small**: 1 domain | Pro 2 DCs + 1 Entra tenant + 2 Windows file servers + 10 member servers + 250 workstations | **$3,625** (Standard: $3,275) |
| **Mid** | Pro 10 DCs + 2 tenants + 10 file servers + 2 NAS + 50 servers + 1,000 workstations | **$11,970** (Standard: $10,620) |
| **Large** (top of published tiers) | Pro 20 DCs + 5 tenants + 20 file servers + 5 NAS + 100 servers + 1,000 workstations | **$20,970**. Add AD B&R for 5k users: **$23,215**. Anything bigger is a custom quote. |

### 1.6 Licensing gotchas
1. **Feature gating by edition:** before/after values, GPO setting diffs, ACL auditing, DNS/schema auditing, the lockout analyzer and the MS SQL back end are Professional-only ([compare](https://www.manageengine.com/products/active-directory-audit/pricing-details.html)).
2. **Add-on maze:** DCs are the only base unit. Entra ID, file servers, NAS, member servers, workstations, backup and File Analysis are all separate SKUs, each with its own price tiers (same source).
3. **Inconsistent NAS units** (CIFS server / zone / vStore / storage account …) make quoting error-prone (same source).
4. **Quote required above** 20 DCs, 20 file servers, 5 NAS, 100 servers, 1,000 workstations or 5 tenants. (same source).
5. **Only "enabled" machines are collected**, up to the purchased count. Computers beyond the license limit are skipped ([licensing help](https://www.manageengine.com/products/active-directory-audit/help/quickstart/adaudit-plus-license-and-edition-details.html)).
6. **Entra depth depends on the customer's Microsoft licensing.** Geolocation, MFA details, old/new values, sign-in risk and Intune need an Entra ID **Premium** license. The Microsoft 365-license mode lacks them ([methods comparison](https://www.manageengine.com/products/active-directory-audit/help/data-source/methods-to-configure-azure-ad.html)).
7. **Services are extra:** onboarding costs $3.5k to $10k (see 1.4).
8. **Licensing for build 9000 modules is not published** (see 1.3).

---

## 2. Architecture

### 2.1 Components & stack
| Layer | Detail | Source |
|---|---|---|
| Server | A single Java web application (Apache **Tomcat 9.0.122**, **Zulu OpenJDK 11.0.32.1** in build 9000) that installs on one Windows host. Web UI on 8081 (HTTP) / 8444 (HTTPS). | [release notes 9000](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html), [ports](https://www.manageengine.com/products/active-directory-audit/help/quickstart/ports.html) |
| Engines | **Event processing engine** filters and normalizes raw logs. **Alerts engine** sends email/SMS. **Analytics engine** builds baselines and flags anomalies. | [architecture](https://www.manageengine.com/products/active-directory-audit/help/quickstart/architecture.html) |
| AD access | ADSI (COM) for directory reads, LDAP/GC for object sync, Windows **EventLog API** for log collection | same |
| Front end | **Ember.js** single-page app plus jQuery 3.5.1 and jquery-migrate 1.4.1. The UI calls about 495 internal `/api/json/...` endpoints, none of which are publicly documented. | [demo page source](https://demo.adauditplus.com/) (inspected 2026-10-02) |

### 2.2 Data collection
| Mode | How it works | Notes | Source |
|---|---|---|---|
| **Agentless** (default) | The server pulls Security and other event logs remotely over RPC/SMB. Four fetch modes: **Real-time**, **Native**, **EvtQuery**, **WMI**. Real-time and EvtQuery encrypt the traffic. Native and WMI do not encrypt by default (WMI can be set to). | Needs TCP 135, 137–139, 445 and dynamic RPC 49152–65535 open on every monitored host | [hardening guide §9](https://www.manageengine.com/products/active-directory-audit/help/general-config/security-hardening.html), [ports](https://www.manageengine.com/products/active-directory-audit/help/quickstart/ports.html) |
| **Agent** (Windows) | Lightweight service running as Local System that pushes data over **HTTPS 8555**, falling back to 8444/8081. Typical load: 1–2% CPU, 65–75 MB RAM, about 2 GB disk. Caches events locally in an EventData folder (2 GB by default, up to 10 GB). **When the cache is full, collection stops.** | Recommended for WAN/geo-distributed sites or more than 1,000 workstations. Supports VDI and AVD. Build 9000 moved transport to Protobuf and encrypts agent secrets with DPAPI. | [agent overview](https://www.manageengine.com/products/active-directory-audit/help/general-config/agent-configuration-overview.html), [prereqs](https://www.manageengine.com/products/active-directory-audit/help/general-config/agent-configuration-installation-prerequisites.html), [sysreq](https://www.manageengine.com/products/active-directory-audit/help/quickstart/system-requirements.html), [RN 9000](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| Agent timing | Audit data streams continuously. Config sync and job polling every 60 min. Health report every 30 min. Self-upgrade check daily, retried every 6 h. RPC from the server is optional, only for push management. | Deploy via GPO, Intune, SCCM or Endpoint Central to avoid needing Domain Admin and RPC | [agent architecture](https://www.manageengine.com/products/active-directory-audit/help/general-config/agent-configuration-architecture.html) |
| macOS agent | Logon/logoff only (macOS Catalina 10.15+) | Added in build 7250 (Sep 2023) | [sysreq](https://www.manageengine.com/products/active-directory-audit/help/quickstart/system-requirements.html), [RN](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| NAS | Vendor-specific: NetApp (audit-policy sync over the NetApp REST API for ONTAP 9.6+ since build 8510); syslog listeners for EMC Isilon, Synology and QNAP; Azure Files via Event Hubs or Log Analytics | | [NAS overview](https://www.manageengine.com/products/active-directory-audit/help/data-source/nas-overview.html), [notifications](https://www.manageengine.com/products/active-directory-audit/help/admin-settings/notification-settings.html), [RN 8510/9000](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| Entra ID / M365 | Two configuration methods: one for customers with an Entra ID Premium license, one for a Microsoft 365 license. Release notes mention both the Microsoft Graph API and the Office 365 API as collection paths. The SSPM module also uses the Exchange and Teams PowerShell modules. | | [methods](https://www.manageengine.com/products/active-directory-audit/help/data-source/methods-to-configure-azure-ad.html), [RN 7215 and older](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html), [SSPM architecture](https://www.manageengine.com/products/active-directory-audit/help/usecase/attack-surface-analyzer-for-saas-architecture.html) |
| Real time vs scheduled | Each source can run in **Real-time** or **Scheduled** (interval) mode. Real-time collection needs Windows Server 2008 or later. The default schedule interval is not documented `[UNVERIFIED]`. | Print auditing has a third mode, "Print Listener" | [known issues](https://www.manageengine.com/products/active-directory-audit/help/troubleshooting/known-issues.html), [print fetch modes](https://www.manageengine.com/products/active-directory-audit/help/usecase/print-audit-configure-event-fetch-mode.html) |
| Historic import | Can import EVT/EVTX backup files into the working database, including on a schedule | Relevant for migrations | [restore archived events](https://www.manageengine.com/products/active-directory-audit/help/admin-settings/archive-and-restore.html) |

### 2.3 Required Windows audit configuration
The product can push these settings through GPO automatically if its account has the rights, or the admin can apply them by hand. Sources: [audit policies](https://www.manageengine.com/products/active-directory-audit/help/data-source/ad-audit-configure-audit-policies-manually.html), [object-level SACLs](https://www.manageengine.com/products/active-directory-audit/help/data-source/ad-audit-configure-object-level-auditing-manually.html), [event log settings](https://www.manageengine.com/products/active-directory-audit/help/data-source/ad-audit-configure-event-log-settings.html).

| Setting | Requirement |
|---|---|
| Advanced audit policy (Default Domain Controllers Policy or an equivalent GPO) | Kerberos Authentication Service: Success+Failure. Computer, Distribution Group and Security Group Management: Success. User Account Management: Success+Failure. Process Creation/Termination: Success. DS Changes and DS Access: Success. Logon and Network Policy Server: Success+Failure. Logoff and Other Logon/Logoff: Success. Other Object Access: Success. Authentication/Authorization Policy Change: Success. Security State Change: Success. Also **"Force audit policy subcategory settings"** = Enabled. |
| SACLs at the domain root | Principal *Everyone*, Success, on OU / GPO / User / Group / Computer / Contact objects. Rights: create/delete, write all properties, delete, modify permissions, and all extended rights (users). |
| Security log | 1,024 MB on DCs (WS2008+), overwrite as needed, keep at least 12 h of events |
| NTLM | NTLM auditing is a hidden toggle under *Support → Support Info → More → Enable/Disable Configuration settings* |
| File servers | SACLs on each share. A daily SACL check can be skipped since build 9000. Shares missing SACLs trigger notifications. ([RN 9000](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html), [notifications](https://www.manageengine.com/products/active-directory-audit/help/admin-settings/notification-settings.html)) |

### 2.4 Storage engines
| Store | Use | Facts | Source |
|---|---|---|---|
| **PostgreSQL** (bundled) | Main audit and configuration database, port 33307 | Upgraded to **17.5** in build 8520 (Sep 2025). Customers still on PostgreSQL 9.4 cannot apply 8520 until they upgrade the database by hand. | [RN 8520](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html), [architecture](https://www.manageengine.com/products/active-directory-audit/help/quickstart/architecture.html) |
| **MS SQL Server** (2008 R2 to 2025) | Alternative back end, Professional only | Named instances only. SQL Express is capped at 4 GB / 10 GB. Driver moved from jTDS to Microsoft JDBC 12.10.2 in build 9000. | [sysreq](https://www.manageengine.com/products/active-directory-audit/help/quickstart/system-requirements.html), [known issues](https://www.manageengine.com/products/active-directory-audit/help/troubleshooting/known-issues.html), [RN 9000](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| **DataEngine ("XNode")** | High-volume categories: file audit, account logon, PowerShell, Sysmon, AD replication, advanced DNS, threat data, cloud activity. Since build 8700 also Entra logon, management and Intune reports. | Separate Windows service on port 29118. **About 15 MB per 100,000 log entries.** Build 7054 (Feb 2022) claimed it can query more than 2 billion records in one search. The third-party license list includes elasticsearch-rest-high-level-client 6.5.4 and Lucene 7.5.0; whether XNode itself is built on Lucene/Elasticsearch is `[UNVERIFIED]`. | [DataEngine privileges](https://www.manageengine.com/products/active-directory-audit/help/quickstart/privileges-required-for-dataengine.html), [archive search](https://www.manageengine.com/products/active-directory-audit/help/admin-settings/archive-events-search.html), [RN](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html), [third-party list](https://www.manageengine.com/products/active-directory-audit/help/support/third-party-software.html) |
| **Elasticsearch** | AD Backup & Recovery add-on only | Ports 9270 (HTTP) and 9370 (cluster) | [ports](https://www.manageengine.com/products/active-directory-audit/help/quickstart/ports.html) |

### 2.5 Archiving & retention
- **Three tiers, set per report category** ([archive overview](https://www.manageengine.com/products/active-directory-audit/help/admin-settings/archive-events-overview.html)):
  - **Hot:** searchable.
  - **Cold:** compressed and indexed, about 50% smaller, **not searchable**. Only available for DataEngine categories.
  - **Frozen:** compressed raw data, about 80% smaller, **not searchable**. Kept indefinitely by default.
- **Retention clocks:** set in days, months or years, where a month counts as 31 days and a year as 366. Archive location can be local or a UNC share. Deleted archives can be recovered for 20 days by default (30 max) ([archive config](https://www.manageengine.com/products/active-directory-audit/help/admin-settings/archive-events-configuration.html)).
- **Getting old data back:**
  - "Restore Archived Events" loads archives back into the working database. Restored data is re-archived automatically after 48 h ([restore](https://www.manageengine.com/products/active-directory-audit/help/admin-settings/archive-and-restore.html)).
  - "Search Archived Events" indexes archive files without restoring them. Limits: **50 files per category**, and each indexed file uses 40–70 MB ([archive search](https://www.manageengine.com/products/active-directory-audit/help/admin-settings/archive-events-search.html)).
  - Archives and exports are password-protected ZIPs ([hardening §11–12](https://www.manageengine.com/products/active-directory-audit/help/general-config/security-hardening.html)).
- **Pitch against native retention:** Entra and M365 keep logs for 30 to 90 days natively. ADAudit Plus advertises any custom retention period ([Entra retention](https://www.manageengine.com/products/active-directory-audit/help/data-source/log-retention-settings-in-azure-ad.html), [vs Azure portal](https://www.manageengine.com/products/active-directory-audit/help/data-source/adaudit-plus-vs-azure-portal.html)).

### 2.6 Sizing & scale
| Item | Value | Source |
|---|---|---|
| Hardware (min / recommended) | Minimum: 2.4 GHz, 4 cores, 8 GB RAM, 50 GB disk. Recommended: 3 GHz, 8 cores, 16 GB, 100 GB. With AD B&R for 100k users: 200 GB. "Use a machine with 16 cores and 32 GB RAM for best performance." | [sysreq](https://www.manageengine.com/products/active-directory-audit/help/quickstart/system-requirements.html) |
| Disk planning | "Run the product for a month" and read the in-product disk-usage graph. Older rule of thumb: about 15 KB per user per day for AD (10k users × 90 days ≈ 13 GB) and about 4 KB per user per file per day for file auditing. Archives compress about 10:1. | [sysreq](https://www.manageengine.com/products/active-directory-audit/help/quickstart/system-requirements.html), [disk-space page](https://www.manageengine.com/products/active-directory-audit/hard-disk-space-management.html) |
| Throughput | **No published events-per-second figure found** `[UNVERIFIED]`. Build 7113 capped agent requests at 1,000 events to prevent server out-of-memory errors. | [RN 7113](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |

### 2.7 High availability & DR
- **HA model is hot standby.** It needs three machines: a primary app server, a standby app server, and a separate database/DataEngine server. The vendor recommends at least 16 GB RAM and 4 cores for each. Health is checked through a database heartbeat. Files are replicated with **robocopy**, and failover uses a virtual IP ([workflow](https://www.manageengine.com/products/active-directory-audit/help/general-config/high-availability-workflow.html), [prereqs](https://www.manageengine.com/products/active-directory-audit/help/general-config/high-availability-prerequisites.html)).
- **HA setup is entirely manual** ([setup](https://www.manageengine.com/products/active-directory-audit/help/general-config/high-availability-setup.html)):
  - edit `pg_hba.conf`, `database_params.conf`, `fos.conf`, `wrapper.conf` and the XNode configs by hand;
  - copy executables between folders;
  - run `INSERT INTO adshaconfiguration ...` through the in-product DB Query page;
  - rename the install folder and share it.
- **The shared database is a single point of failure** unless the customer clusters it themselves (inference from the topology).
- **DR:** vendor guides exist for Hyper-V Replica and Veeam. The Hyper-V guide quotes RPO of 30 s, 5 min or 15 min and RTO of 10–30 min ([Hyper-V DR](https://www.manageengine.com/products/active-directory-audit/help/general-config/dc-dr-hyper-v-intro.html)).

### 2.8 Required privileges
- **Default setup asks for Domain Admin:** "ADAudit Plus instantly starts to audit activities upon providing Domain Admin credentials" ([AD privileges](https://www.manageengine.com/products/active-directory-audit/help/quickstart/privileges-required-for-ad-windows-server-workstation-audit.html)).
- **Least-privilege setup** (same source) requires a dedicated user plus:
  - a permission group and a domain-level GPO;
  - the *Manage auditing and security log* right;
  - membership in *Event Log Readers*;
  - read access on the `EventLog\Security` registry key;
  - optionally a `wevtutil` channel ACL;
  - for automatic configuration: *Edit settings* on the Default Domain Controllers Policy, *Group Policy Creator Owners* membership, and create/delete group plus write-members rights.
- **On the ADAudit Plus server:** local admin to manage the DataEngine service, full control of the install folder, and antivirus exclusions for the pgsql, DataEngine, eventdata and other folders ([DataEngine privileges](https://www.manageengine.com/products/active-directory-audit/help/quickstart/privileges-required-for-dataengine.html), [startup privileges](https://www.manageengine.com/products/active-directory-audit/help/quickstart/privileges-required-for-product-startup.html)).
- **Agents:** pushing from the console needs Domain Admin. Agents deployed via GPO/Intune/SCCM do not, and run as Local System ([agent prereqs](https://www.manageengine.com/products/active-directory-audit/help/general-config/agent-configuration-installation-prerequisites.html)).
- **gMSA service accounts:** support is unclear. A forum thread asks about it `[UNVERIFIED]` ([forum](https://pitstop.manageengine.com/portal/en/community/adaudit-plus)).

### 2.9 Ports
Source: [port guide](https://www.manageengine.com/products/active-directory-audit/help/quickstart/ports.html), [agent architecture](https://www.manageengine.com/products/active-directory-audit/help/general-config/agent-configuration-architecture.html).

| Direction | Ports |
|---|---|
| On the product server | 8081 HTTP, 8444 HTTPS (UI), 33307 PostgreSQL, 29118 DataEngine, 9270/9370 Elasticsearch (backup add-on), 8555 agent HTTPS |
| Server → monitored hosts (agentless) | 135, 137–139, 445, 49152–65535 (dynamic RPC) |
| Server → DCs | 389/636 LDAP, 3268/3269 GC, 88 Kerberos |
| Server → mail | 25/465/587 SMTP |
| Azure AD DS | 443 for REST and AMQP-over-WebSockets ([AAD DS](https://www.manageengine.com/products/active-directory-audit/help/usecase/azure-ad-ds-audit-overview.html)) |

---

## 3. Complete feature inventory

**Edition column key:**
- **Std+Pro**: in both editions.
- **Pro**: Professional only.
- **Add-on (unit)**: needs that add-on.
- **n/s**: the pricing/compare page does not say which edition `[UNVERIFIED]`.
- **n/s (platform)**: a platform capability we assume is in every edition, but the compare page does not list it `[UNVERIFIED]`.

Edition mapping comes from the [compare-editions table](https://www.manageengine.com/products/active-directory-audit/pricing-details.html).

**"Demo nav" rows** are report-tree entries we pulled from the public demo (build 8703) on 2026-10-02 at [demo.adauditplus.com](https://demo.adauditplus.com/). We logged in with the technician account the demo page itself offers and only read the report tree. Report counts are de-duplicated by name and ID within each tab.

### 3.1 Active Directory change auditing
| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADA-001 | AD change | User management auditing | Create, delete, enable, disable, move, rename, undelete; attribute changes; password resets. 25 "User Management" + 30 "User Modification" reports. | Std+Pro (old/new values: Pro) | [cmp](https://www.manageengine.com/products/active-directory-audit/pricing-details.html), demo nav |
| ADA-002 | AD change | Group & membership auditing | Security/distribution group lifecycle, member add/remove, before/after membership picture | Std+Pro | [AD page FAQ](https://www.manageengine.com/products/active-directory-audit/active-directory-auditing.html) |
| ADA-003 | AD change | Computer management auditing | Computer object create, delete, enable, disable, move, attribute changes | Std+Pro | [cmp](https://www.manageengine.com/products/active-directory-audit/pricing-details.html) |
| ADA-004 | AD change | OU management auditing | OU create, delete, move, rename, undelete | Std+Pro | [revert doc](https://www.manageengine.com/products/active-directory-audit/help/usecase/revert-ad-changes.html) |
| ADA-005 | AD change | GPO object auditing | GPO create, delete, modify, link changes; GPO change history | Std+Pro | [datasheet](https://download.manageengine.com/products/active-directory-audit/adaudit-plus-datasheet.pdf) |
| ADA-006 | AD change | **GPO setting-level changes** | Old/new value per setting: password/lockout policy, user/computer config, admin templates, GPO permissions. Needs GPMC on the server; collected via agent or SYSVOL share. | **Pro** | [GPO settings help](https://www.manageengine.com/products/active-directory-audit/help/usecase/gpo-audit-configure-gpo-settings-changes.html), [known issues](https://www.manageengine.com/products/active-directory-audit/help/troubleshooting/known-issues.html) |
| ADA-007 | AD change | **All-attribute tracking with old/new values** | Before/after for any attribute of users, computers, groups and OUs (WS2008+) | **Pro** | [cmp](https://www.manageengine.com/products/active-directory-audit/pricing-details.html), [lic](https://www.manageengine.com/products/active-directory-audit/help/quickstart/adaudit-plus-license-and-edition-details.html) |
| ADA-008 | AD change | **AD permission (ACL) change auditing** | Domain, OU, group, container, user and GPO ACL changes, including **AdminSDHolder**, with old/new values | **Pro** | [alerts page](https://www.manageengine.com/products/active-directory-audit/active-directory-change-alerts.html), [lic](https://www.manageengine.com/products/active-directory-audit/help/quickstart/adaudit-plus-license-and-edition-details.html) |
| ADA-009 | AD change | Schema, configuration & contacts | Schema changes (custom attributes), configuration partition (sites, subnets), FSMO role changes, contacts | **Pro** | [AD page](https://www.manageengine.com/products/active-directory-audit/active-directory-auditing.html), [cmp](https://www.manageengine.com/products/active-directory-audit/pricing-details.html) |
| ADA-010 | AD change | DNS auditing | AD-integrated DNS node/zone add, modify, delete, plus "Advanced DNS Server Audit" (10 reports, stored in DataEngine) | **Pro** | [cmp](https://www.manageengine.com/products/active-directory-audit/pricing-details.html), [datasheet](https://download.manageengine.com/products/active-directory-audit/adaudit-plus-datasheet.pdf), demo nav |
| ADA-011 | AD change | Advanced AD objects audit | Other object classes such as WMI filters (22 reports) | n/s | demo nav, [RN 7100](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-012 | AD change | Admin / help-desk activity trail | "Administrative User Actions": everything privileged and delegated users changed | Std+Pro | [cmp](https://www.manageengine.com/products/active-directory-audit/pricing-details.html), [compliance page](https://www.manageengine.com/products/active-directory-audit/active-directory-compliance-reports.html) |
| ADA-013 | AD change | User-based consolidated audit trail | One timeline of a single user's activity | n/s | [features](https://www.manageengine.com/products/active-directory-audit/features.html) |
| ADA-014 | AD change | LAPS auditing (legacy + Windows LAPS) | Password reads, expiry changes, DSRM password reads (5 reports) | Std+Pro | [LAPS help](https://www.manageengine.com/products/active-directory-audit/help/usecase/laps-auditing-reporting-capabilities.html) |
| ADA-015 | AD change | AD CS auditing | Certificate activity on **Enterprise** CAs only (standalone CAs not supported). 11 reports. | n/s | [AD CS help](https://www.manageengine.com/products/active-directory-audit/help/usecase/adcs-audit-overview.html) |
| ADA-016 | AD change | AD replication audit | Replication events (7 reports, DataEngine) | n/s | demo nav, [archive search](https://www.manageengine.com/products/active-directory-audit/help/admin-settings/archive-events-search.html) |
| ADA-017 | AD change | LDAP query auditing | "Recent LDAP Queries" and related reports | n/s | [RN 7201/7202](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-018 | AD change | Entra Password Protection (on-prem DC agent) audit | 9 reports on password-filter events | n/s | demo nav |
| ADA-019 | AD change | Netlogon vulnerable Schannel audit | Clients and trusts using RPC signing instead of sealing; RC4 usage | n/s | [RN 7220](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-020 | AD change | Managed AD services | **AWS Managed Microsoft AD** (build 8110) and **Azure AD DS** (logons need NTLM auditing on) | n/s | [RN 8110](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html), [AAD DS help](https://www.manageengine.com/products/active-directory-audit/help/usecase/azure-ad-ds-audit-overview.html) |
| ADA-021 | AD change | Domain policy change auditing | Password and lockout policy changes with old/new thresholds | Std+Pro `[UNVERIFIED]` | [lockout page](https://www.manageengine.com/products/active-directory-audit/windows-ad-user-account-lockout-analyzer.html) |
| ADA-022 | AD change | Revert AD changes from a report | Roll back creates, deletes, moves, renames, membership and attribute changes directly from report rows. Some attributes cannot be reverted. | Probably AD B&R add-on `[UNVERIFIED]` | [revert help](https://www.manageengine.com/products/active-directory-audit/help/usecase/revert-ad-changes.html) |

### 3.2 Logon, logoff & sessions
| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADA-023 | Logon | Domain logon activity | Success and failure by user, DC or IP; first/last logon by computer (21 report entries) | Std+Pro | [cmp](https://www.manageengine.com/products/active-directory-audit/pricing-details.html), demo nav |
| ADA-024 | Logon | Logon failure analysis | Failure reasons (bad password, bad user name…) and a "Logon Failure Summary" | Std+Pro | [RN 7200](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-025 | Logon | Logon history, currently logged-on users, logon duration | Who is on where and since when; users logged on to multiple machines | Std+Pro | [AD page](https://www.manageengine.com/products/active-directory-audit/active-directory-auditing.html), [datasheet](https://download.manageengine.com/products/active-directory-audit/adaudit-plus-datasheet.pdf) |
| ADA-026 | Logon | Local logon/logoff on servers and workstations | Interactive, remote, local and network logons on member hosts | Add-on (servers / workstations) | [cmp](https://www.manageengine.com/products/active-directory-audit/pricing-details.html) |
| ADA-027 | Logon | RDP / Terminal Services / RD Gateway | Remote sessions and RDG logons | Add-on `[UNVERIFIED]` | [features](https://www.manageengine.com/products/active-directory-audit/features.html) |
| ADA-028 | Logon | RADIUS / NPS logons | RADIUS logons, failures, history | Add-on (servers) | [cmp](https://www.manageengine.com/products/active-directory-audit/pricing-details.html), [datasheet](https://download.manageengine.com/products/active-directory-audit/adaudit-plus-datasheet.pdf) |
| ADA-029 | Logon | AD FS auditing | Federation logon success/failure, extranet lockout | Add-on (servers) | [ADFS help](https://www.manageengine.com/products/active-directory-audit/help/usecase/adfs-audit-overview.html) |
| ADA-030 | Logon | Wi-Fi logon reports | Wireless logon activity of AD users | n/s | [RN 7200](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-031 | Logon | macOS logon/logoff | Via macOS agent | Add-on (workstations) | [RN 7250](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-032 | Logon | NTLM authentication activity | Legacy NTLM usage, for hardening and migration planning (build 9000) | n/s | [RN 9000](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-033 | Logon | Non-human identity logons | gMSA and service-account logon success/failure; certificate-based auth (build 9000) | n/s | same |
| ADA-034 | Logon | Employee work hours / productivity | Active vs idle time per user, including Entra-joined devices since 9000 | Add-on (workstations) | [cmp](https://www.manageengine.com/products/active-directory-audit/pricing-details.html), [RN 9000](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-035 | Logon | Startup / shutdown tracking | Boot and shutdown times and type | Add-on (workstations) | [cmp](https://www.manageengine.com/products/active-directory-audit/pricing-details.html) |
| ADA-036 | Logon | User session video recording | Screen recording on servers. The admin has to copy ffmpeg.exe into the product's bin folder by hand. | Add-on `[UNVERIFIED]` | [session recording help](https://www.manageengine.com/products/active-directory-audit/help/usecase/user-session-recording-overview-and-steps.html) |

### 3.3 Account lockout
| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADA-037 | Lockout | Lockout reports and default alert | Recently locked/unlocked users and logon attempts by locked-out users, with source machine and IP | Std+Pro | [lockout page](https://www.manageengine.com/products/active-directory-audit/windows-ad-user-account-lockout-analyzer.html) |
| ADA-038 | Lockout | **Account Lockout Analyzer** (root cause) | Checks services, scheduled tasks, mapped drives, processes, RDP sessions and mobile devices. ActiveSync/OWA lockouts need IIS logging enabled on Exchange CAS servers. | **Pro** | [ALA help](https://www.manageengine.com/products/active-directory-audit/help/usecase/account-lockout-analyzer-overview.html), [datasheet](https://download.manageengine.com/products/active-directory-audit/adaudit-plus-datasheet.pdf) |
| ADA-039 | Lockout | Lockout anomaly detection | ML baseline of domain lockout volume and time | n/s | [lockout page](https://www.manageengine.com/products/active-directory-audit/windows-ad-user-account-lockout-analyzer.html) |
| ADA-040 | Lockout | Hybrid lockout and password-spray views | Entra "Account Locked Out Users", "Hybrid Logon Activity", "Login by PasswordSpray Account" | Add-on (Entra) | same |

### 3.4 Password & privileged-user monitoring
| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADA-041 | Privileged | Password change/reset auditing | Who reset or changed whose password, when and from where (on-prem and Entra) | Std+Pro | [alerts page](https://www.manageengine.com/products/active-directory-audit/active-directory-change-alerts.html), [datasheet](https://download.manageengine.com/products/active-directory-audit/adaudit-plus-datasheet.pdf) |
| ADA-042 | Privileged | Privileged group monitoring | Domain, Enterprise and Schema Admins membership alerts | Std+Pro | [alerts page](https://www.manageengine.com/products/active-directory-audit/active-directory-change-alerts.html) |
| ADA-043 | Privileged | First-time privilege use, dormant admins | UBA flags the first exercise of a right and admins with no activity | n/s | [UBA page](https://www.manageengine.com/products/active-directory-audit/user-behavior-analytics.html) |
| ADA-044 | Privileged | Admin activity anomalies | Unusual volume or time of user-management actions per admin | n/s | same |
| ADA-045 | Privileged | Elevated process execution | Privilege-escalated processes (build 9000) | n/s | [RN 9000](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |

### 3.5 Microsoft Entra ID / Microsoft 365
Base license unit is the tenant. Full depth needs an Entra **Premium** license on the customer side ([methods](https://www.manageengine.com/products/active-directory-audit/help/data-source/methods-to-configure-azure-ad.html)). The demo's Cloud Directory tab shows 171 report entries in 20 categories.

| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADA-046 | Entra | Sign-in auditing | Interactive, non-interactive, service principal and managed identity sign-ins; MFA details; geolocation; world map (9000) | Add-on (tenant) | [RN 8500/9000](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-047 | Entra | Directory change auditing | Users, groups, roles, devices, applications/OAuth consents, licenses, directory settings and Conditional Access changes. Old/new values need Premium. | Add-on | [Entra overview](https://www.manageengine.com/products/active-directory-audit/help/data-source/azure-ad-audit-overview.html), [methods](https://www.manageengine.com/products/active-directory-audit/help/data-source/methods-to-configure-azure-ad.html) |
| ADA-048 | Entra | Risk detection | Risk detected/resolved reports, risky sign-ins, impossible travel | Add-on (Premium) | [RN 8700](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html), [alerts page](https://www.manageengine.com/products/active-directory-audit/active-directory-change-alerts.html) |
| ADA-049 | Entra | Hybrid correlation | On-prem SID/GUID/DN shown next to cloud identity; flags whether a change came from the cloud or from sync | Add-on | [vs Azure portal](https://www.manageengine.com/products/active-directory-audit/help/data-source/adaudit-plus-vs-azure-portal.html) |
| ADA-050 | Entra | Intune auditing | Device enrollments, device and app changes, policy creation | Add-on (Premium) | [RN 8500](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-051 | Entra | M365 workload reports | Exchange Online, SharePoint Online, OneDrive (build 8700) | Add-on `[UNVERIFIED]` | [RN 8700](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-052 | Entra | Non-human identity activity | Service principals and managed identities, "including the identities used by AI agents"; sign-ins and create/update/delete (9000) | n/s | [RN 9000](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-053 | Entra | Entra-joined device auditing | Logons, work hours and startup/shutdown on Windows devices, via agent. Supported: Entra-joined (with or without Intune) and Entra-registered + Intune-managed. Not supported: devices managed only by Intune. | Add-on `[UNVERIFIED]` | [Entra device help](https://www.manageengine.com/products/active-directory-audit/help/usecase/entra-id-joined-device-auditing-overview.html) |
| ADA-054 | Entra | Long-term retention of cloud logs | Retention beyond Entra's native 30–90 days | Add-on | [retention](https://www.manageengine.com/products/active-directory-audit/help/data-source/log-retention-settings-in-azure-ad.html) |

### 3.6 Windows file servers & NAS
| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADA-055 | File | Windows file server auditing | Create, delete, modify, read, copy-paste, move, rename, owner/permission/SACL changes; failed read/write/delete. Covers SMB, CIFS, DFS, DFSR and mounted/SAN/junction volumes. | Add-on (file server) | [supported systems](https://www.manageengine.com/products/active-directory-audit/help/data-source/windows-file-audit-supported-systems.html) |
| ADA-056 | File | Failover cluster auditing | Windows failover file clusters, with automatic share discovery | Add-on | [cmp](https://www.manageengine.com/products/active-directory-audit/pricing-details.html), [RN 7210](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-057 | File | NTFS and share permission changes | Old/new values | Add-on | [datasheet](https://download.manageengine.com/products/active-directory-audit/adaudit-plus-datasheet.pdf) |
| ADA-058 | NAS | NetApp | 7-Mode/vFiler (ONTAP 7.2+), C-Mode/SVM (8.2.1+), REST API for 9.6+, FSx for ONTAP | Add-on (NAS: CIFS server) | [NAS matrix](https://www.manageengine.com/products/active-directory-audit/help/data-source/nas-overview.html), [RN 8510](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-059 | NAS | Dell / EMC | Celerra, VNX, VNXe, Unity, Isilon OneFS 7.0+, PowerScale (9.10 since 8700), PowerStore, Unity XT | Add-on (CIFS server; Isilon: zone) | [NAS matrix](https://www.manageengine.com/products/active-directory-audit/help/data-source/nas-overview.html), [RN 8700](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-060 | NAS | Long-tail vendors | Synology DSM 5+, Hitachi NAS 13.2+, Huawei OceanStor (V5, 9000 V5, Dorado, Pacific, HyperMetro), QNAP, Nutanix Files, CTERA Edge Filers series 7, Qumulo Core 6.2.2+ | Add-on (vendor unit) | [NAS matrix](https://www.manageengine.com/products/active-directory-audit/help/data-source/nas-overview.html) |
| ADA-061 | NAS | Cloud file shares | Amazon FSx for Windows, Azure Files (via Event Hubs, or Log Analytics workspace for cross-region since 9000) | Add-on | same, [RN 9000](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-062 | File | Ransomware / mass-change detection | Alerts on spikes in file activity; can shut down the infected device automatically | n/s | [features](https://www.manageengine.com/products/active-directory-audit/features.html) |
| ADA-063 | File | Server-, user-, share- and profile-based file reports | 93 file-audit report entries | Add-on | demo nav |
| ADA-064 | File | File Analysis | Redundant/obsolete/trivial (ROT), duplicate and hidden files; over-permissioned files and broken inheritance; files owned by former users; storage analytics. Agent required. | Add-on (TB) | [File Analysis help](https://www.manageengine.com/products/active-directory-audit/help/usecase/file-analysis-overview.html), [datasheet](https://download.manageengine.com/products/active-directory-audit/adaudit-plus-datasheet.pdf) |
| ADA-065 | File | Access Analyzer for Data | Effective permissions per user, file or server; group-removal simulator; most-exposed shares; remediation (9000) | n/s | [RN 9000](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |

Known NAS gaps: no file copy reports on NetApp/EMC, and no permission-change or failed-attempt auditing on Synology ([known issues](https://www.manageengine.com/products/active-directory-audit/help/troubleshooting/known-issues.html)).

### 3.7 Windows servers, workstations & endpoint
| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADA-066 | Server/WS | File integrity monitoring | System and program files: create, modify, delete, move, rename, permission/SACL/owner changes, copy, failed writes/deletes | Add-on (servers / workstations) | [FIM help](https://www.manageengine.com/products/active-directory-audit/help/usecase/fim-overview.html) |
| ADA-067 | Server/WS | Removable storage (USB) | Plug-in events, file read/modify/copy-paste. Agent mode adds the USB device name; real-time listener since 8500. | Add-on | [USB help](https://www.manageengine.com/products/active-directory-audit/help/usecase/removable-storage-audit-overview.html), [RN 8500](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-068 | Server | Printer auditing | Print jobs with file name, user, copies, pages; branch-office direct printing | Add-on (servers) | [print help](https://www.manageengine.com/products/active-directory-audit/help/usecase/print-audit-overview.html) |
| ADA-069 | Server/WS | Process tracking | Process start/stop with command line (Event 4688) | Add-on `[UNVERIFIED]` | [datasheet](https://download.manageengine.com/products/active-directory-audit/adaudit-plus-datasheet.pdf), [RN 8700](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-070 | Server | Scheduled task auditing | Task create, delete, modify | Add-on | [datasheet](https://download.manageengine.com/products/active-directory-audit/adaudit-plus-datasheet.pdf) |
| ADA-071 | Server | PowerShell auditing | PowerShell processes and the commands run in them (PS 4.0/5.0) | Add-on `[UNVERIFIED]` | [PowerShell help](https://www.manageengine.com/products/active-directory-audit/help/usecase/powershell-audit-overview.html) |
| ADA-072 | Server/WS | Local accounts and groups | Local user and admin-group changes, local lockouts | Add-on | [datasheet](https://download.manageengine.com/products/active-directory-audit/adaudit-plus-datasheet.pdf) |
| ADA-073 | Server | Policy, user-rights and system events | User rights and local policy changes; security log cleared; system events | Add-on | [datasheet](https://download.manageengine.com/products/active-directory-audit/adaudit-plus-datasheet.pdf), [alerts page](https://www.manageengine.com/products/active-directory-audit/active-directory-change-alerts.html) |
| ADA-074 | Server | AD LDS auditing | AD Lightweight Directory Services changes (7 reports) | Add-on (servers) | [cmp](https://www.manageengine.com/products/active-directory-audit/pricing-details.html), demo nav |
| ADA-075 | Server | Network share and Sysmon auditing | Share access on member servers; Sysmon events (12 reports) | n/s | [RN 8000](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html), demo nav |
| ADA-076 | Server | Registry auditing | Registry changes, with the path included in the message since 8700 | n/s | [RN 8700/8123](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-077 | Endpoint | Cloud file transfer monitoring | Agent component ADAPNetMon.exe performs **SSL inspection on the endpoint** using a CA certificate the customer uploads. Logs uploads and downloads to any HTTPS destination (metadata only). Build 9000. | n/s | [CFT help](https://www.manageengine.com/products/active-directory-audit/help/usecase/cloud-file-transfer-monitoring-overview.html) |
| ADA-078 | Endpoint | Process and network attack detection | 21 "Process Attacks" (e.g., MSDT command execution, Rundll32, InstallUtil) and 18 "Network attacks" (e.g., Ngrok tunneling, Certutil connections). Marketed as "15+ network / 20+ process attacks" with MITRE ATT&CK mapping. | n/s | demo nav, [ASA page](https://www.manageengine.com/products/active-directory-audit/attack-surface-analyzer.html) |
| ADA-079 | Endpoint | VDI, AVD and DirectAccess support | Agent auto-registers non-persistent VDI and AVD hosts | Agent (all editions) | [RN 7000](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html), [agent prereqs](https://www.manageengine.com/products/active-directory-audit/help/general-config/agent-configuration-installation-prerequisites.html) |

### 3.8 Threat detection, UBA & posture
| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADA-080 | Threat | **Attack Surface Analyzer for AD: 28 named detections** | Pass-the-ticket, pass-the-hash, DCShadow, DCSync, AdminSDHolder ACL tampering, RID hijacking, AS-REP roasting, Kerberoasting, recent default-admin use, shadow admin, Primary Group ID, Golden Ticket, Silver Ticket, Security Log Killer, PowerShell script-block logging, constrained and unconstrained delegation, password extraction, password spray, reversible encryption, plaintext password in GPO, brute-force password, brute-force username, DSRM password change, DNS-admin escalation, suspicious process, remote thread, ransomware | n/s | [ASA-AD help](https://www.manageengine.com/products/active-directory-audit/help/usecase/attack-surface-analyzer-for-active-directory.html), demo nav |
| ADA-081 | Threat | Threat dashboard, investigation, briefs | "Threat Search" renamed "Threat Investigation". Build 9000 adds expanded coverage, **whitelist rules**, real-time threat alerts with script response, privileged vs non-privileged markers and richer briefs. | n/s | [RN 9000](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-082 | Threat | Attack forensic timeline | Attacker actions before and after each detection | n/s | [alerts page](https://www.manageengine.com/products/active-directory-audit/active-directory-change-alerts.html) |
| ADA-083 | UBA | **User behavior analytics: 31 reports** | Per-user and per-host baselines for logon volume/time, first-time host access and remote access, user-management volume/time, lockout volume/time, new process on server, file activity/modify/delete/failed-access volume and time, plus "normal behavior" reports | n/s | [UBA page](https://www.manageengine.com/products/active-directory-audit/user-behavior-analytics.html), demo nav |
| ADA-084 | UBA | UBA alert filters | Filter by users, computers and business hours (build 8510) | n/s | [RN 8510](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-085 | Posture | System security misconfigurations | Pulls RSoP (planning or logging mode) from DCs, servers and workstations and scores it against **CIS** benchmarks (WS2012R2–2022 v2.0.0, WS2025 since 8710, Win10/11). Hosts are graded as highly, moderately or mildly exposed. | n/s | [ASA servers/endpoints](https://www.manageengine.com/products/active-directory-audit/help/usecase/attack-surface-analyzer-for-servers-and-endpoints.html), [RN 8710](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-086 | Posture | Cloud posture (CSPM) | Azure, AWS and GCP inventory and misconfiguration checks mapped to ISO, NIST, CIS, HIPAA, SOX, Azure Security Benchmark, FedRAMP and CSA CCM (9000; AWS/GCP directories since 8110) | n/s | [RN 9000/8110](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-087 | Posture | SaaS posture (SSPM) | M365 (Entra, Exchange, SharePoint, Intune, Teams): **144 policies**, risk scores, alerts, script or ticket response, SOC 2/GDPR/HIPAA mapping. Collects read-only via Graph and PowerShell. | n/s | [RN 9000](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html), [SSPM help](https://www.manageengine.com/products/active-directory-audit/help/usecase/attack-surface-analyzer-for-saas-overview.html) |
| ADA-088 | Access | Access Analyzer for AD | Visual attack paths from user to object; effective permissions marked used, unused or excessive; per-object remediation (9000) | n/s | [RN 9000](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-089 | Access | Access Analyzer for Cloud (CIEM) | Effective Azure roles and how each was granted; usage from the Activity Log; redundant-role detection (9000) | n/s | same |

### 3.9 Backup & recovery (add-on)
| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADA-090 | Recovery | AD Backup & Recovery | Full and incremental backups of users, computers, groups and memberships, OUs, containers, contacts, GPOs and links, schema, BitLocker keys, Exchange and custom attributes, DNS. Can preserve passwords (by changing the schema), force replication, and recover tombstone-expired objects. | Add-on (users) | [AD B&R help](https://www.manageengine.com/products/active-directory-audit/help/usecase/ad-backup-and-recovery-overview.html), [recovery settings](https://www.manageengine.com/products/active-directory-audit/help/usecase/ad-recovery-settings.html) |
| ADA-091 | Recovery | Advanced Recovery | Point-in-time restore filtered by object, OU, type or attribute, with preview; agentless and no downtime (build 8710) | Add-on | [RN 8710](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |

### 3.10 Alerting & automated response
| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADA-092 | Alerts | Alert profiles | **50+ built-in profiles**. Custom profiles are built on report profiles. Severities: Attention, Trouble, Critical. | Std+Pro | [alerts page](https://www.manageengine.com/products/active-directory-audit/active-directory-change-alerts.html), [alert help](https://www.manageengine.com/products/active-directory-audit/help/general-config/default-alert-profiles.html) |
| ADA-093 | Alerts | Thresholds, business hours, filters, throttling | Count-in-window thresholds, business-hour filters and email throttling | Std+Pro | [custom alerts](https://www.manageengine.com/products/active-directory-audit/help/general-config/custom-alert-configuration.html) |
| ADA-094 | Alerts | Email and SMS delivery | Recipients can be resolved from the user's `mail` attribute; emails include a "View Alerts" deep link (8700) | Std+Pro | same, [RN 8700](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-095 | Response | Script execution | Runs PowerShell, VBScript, batch or exe with event variables, e.g. to disable an account, end a session or shut down a host | n/s | [custom alerts](https://www.manageengine.com/products/active-directory-audit/help/general-config/custom-alert-configuration.html), [datasheet](https://download.manageengine.com/products/active-directory-audit/adaudit-plus-datasheet.pdf) |
| ADA-096 | Response | ITSM auto-ticketing | ServiceNow, ServiceDesk Plus (on-prem, OnDemand, MSP; request templates), Zendesk, Freshservice, Jira SD (cloud and on-prem), Kayako | n/s | [ticketing help](https://www.manageengine.com/products/active-directory-audit/help/general-config/ticketing-tool-integration-overview.html), [RN 8520](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-097 | Ops | Product health notifications | Event-collection failures (threshold- or time-based), shares missing SACLs, SIEM forwarding failures, disk usage, outdated agents, audit-policy status | n/s (platform) | [notifications](https://www.manageengine.com/products/active-directory-audit/help/admin-settings/notification-settings.html) |

### 3.11 Reporting, compliance, search & dashboards
| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADA-098 | Reports | Prebuilt reports | Vendor counts disagree: "250+" ([home](https://www.manageengine.com/products/active-directory-audit/), [datasheet](https://download.manageengine.com/products/active-directory-audit/adaudit-plus-datasheet.pdf)), "over 300" ([AD page](https://www.manageengine.com/products/active-directory-audit/active-directory-auditing.html)), "200+" ([compliance page](https://www.manageengine.com/products/active-directory-audit/active-directory-compliance-reports.html)). The demo report tree has about 1,000 entries: AD 438, Cloud 171, Server 142, File 93, Endpoint about 92, UBA 31, ASA 30, File Analysis 19. Many overlap. | Std+Pro | as cited, demo nav |
| ADA-099 | Compliance | Compliance report packs | SOX, HIPAA, PCI DSS, GLBA, FISMA, GDPR, ISO 27001; FERPA appears in the education use case. **No NIS2, DORA or CMMC page found** `[UNVERIFIED absence]`. | Std+Pro | [compliance page](https://www.manageengine.com/products/active-directory-audit/active-directory-compliance-reports.html), [features](https://www.manageengine.com/products/active-directory-audit/features.html) |
| ADA-100 | Reports | Scheduled reports | Run once, hourly, daily, weekly, monthly or custom. Output as PDF, XLS, HTML or CSV; email attachment or published link. A "Before N days" range covers everything since the product was installed. | Std+Pro | [schedule help](https://www.manageengine.com/products/active-directory-audit/help/general-config/schedule-reports-configuration.html) |
| ADA-101 | Reports | Custom, aggregate and profile reports | Custom reports (including Entra events since 7200), aggregate reports, report profiles | n/s | [RN 7200](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html), demo nav |
| ADA-102 | Search | Report search and archive global search | Advanced AND/OR search inside reports; cross-category archive search with wildcards | n/s (platform) | [archive search](https://www.manageengine.com/products/active-directory-audit/help/admin-settings/archive-events-search.html) |
| ADA-103 | Search | **Activity Explorer** | Unified search across AD, file and cloud data, by user or by action, with inline Access Analyzer (9000) | n/s | [RN 9000](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-104 | Dashboards | Dashboards | Home dashboard (graphical and summary views), threat dashboard, UBA summary, SSPM dashboard. Redesigned in 9000. | n/s (platform) | same, demo nav |
| ADA-105 | Reports | Export protection | Password-protected exports and archives; header removal for PDF, HTML and XLS (9000) | n/s (platform) | [hardening](https://www.manageengine.com/products/active-directory-audit/help/general-config/security-hardening.html), [RN 9000](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |

### 3.12 Integrations, API & mobile
| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADA-106 | Integrations | SIEM forwarding | Real-time syslog (UDP/TCP), Splunk HEC and ArcSight CEF. Covers every data category except printer and advanced-GPO reports, plus alerts and technician audit. Ships a LogRhythm key map. | n/s | [SIEM help](https://www.manageengine.com/products/active-directory-audit/help/admin-settings/siem-integration.html) |
| ADA-107 | Integrations | ManageEngine suite | Log360 integration; AD360 SSO (an account-takeover CVE in it was fixed in 8703); ADManager Plus integration (release notes mention an "integrated ADManager Plus login account", CVE-2022-24978) | n/s | [RN 8700/8703](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-108 | API | **Public REST API: none documented** | No API section in the help index. The UI uses about 495 internal `/api/json/*` endpoints. Third parties such as Sophos and Hunters ingest through syslog or SIEM export. | — | [help index](https://www.manageengine.com/products/active-directory-audit/help/), [demo](https://demo.adauditplus.com/), [Sophos](https://docs.sophos.com/central/customer/help/en-us/ManageYourProducts/ThreatAnalysisCenter/Integrations/Manageengine/index.html), [Hunters](https://docs.hunters.ai/docs/manageengine-adaudit-plus.md) |
| ADA-109 | Mobile | **Mobile app: none found** | Not in the help index or release notes. ADManager Plus does have one. `[UNVERIFIED absence]` | — | [help index](https://www.manageengine.com/products/active-directory-audit/help/) |

### 3.13 Platform & administration
| ID | Module | Feature | What it does | Edition | Source |
|---|---|---|---|---|---|
| ADA-110 | Admin | Technician delegation | Admin and Operator roles plus custom roles (read/write/no access/full control), scopable to domain or OU | n/s (platform) | [technicians](https://www.manageengine.com/products/active-directory-audit/help/admin-settings/technicians-and-roles-configuration.html), [security specs](https://download.manageengine.com/products/active-directory-audit/adaudit-plus-security-specifications.pdf) |
| ADA-111 | Admin | 2FA and SSO | 2FA via email, SMS, Google Authenticator, RSA SecurID, Duo or RADIUS, with backup codes. SAML (ADFS, Okta, OneLogin, Ping, custom), NTLM SSO, and "Force SAML" (8500). | n/s (platform) | [2FA](https://www.manageengine.com/products/active-directory-audit/help/admin-settings/configure-2fa-in-adaudit-plus.html), [RN 8500](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| ADA-112 | Admin | Technician audit trail | Log of actions taken by ADAudit Plus users | n/s (platform) | [hardening](https://www.manageengine.com/products/active-directory-audit/help/general-config/security-hardening.html) |
| ADA-113 | Admin | Automatic configuration | Adds and removes servers, workstations and shares automatically by OU or group filter, optionally with agent install | n/s (platform) | [auto-config](https://www.manageengine.com/products/active-directory-audit/help/general-config/automatic-configuration-overview-and-steps.html) |
| ADA-114 | Admin | Global exclusions (noise filters) | Built-in and custom exclude rules by event ID and field | n/s (platform) | [global exclude](https://www.manageengine.com/products/active-directory-audit/help/general-config/global-exclude-configuration.html) |
| ADA-115 | Admin | Agent management | Fleet status, upgrade/reinstall, config sync; agent self-upgrade (8500) | n/s (platform) | [agent mgmt](https://www.manageengine.com/products/active-directory-audit/help/general-config/agent-management.html) |
| ADA-116 | Admin | Hardening and misc | Security Hardening page (8520), SSL via UI (8500), LDAPS, GDPR privacy settings, rebranding, proxy/NAT | n/s (platform) | [RN](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html), [store scope](https://store.manageengine.com/active-directory-audit/) |
| ADA-117 | Data | Archive tiers and retention | Hot/Cold/Frozen per category; restore; archive search; deletion recovery window | n/s (platform) | §2.5 |
| ADA-118 | Data | EVT/EVTX import | Import Windows log backups, optionally on a schedule | n/s (platform) | [restore help](https://www.manageengine.com/products/active-directory-audit/help/admin-settings/archive-and-restore.html) |
| ADA-119 | Data | HA and DR | Hot standby (manual setup); Hyper-V Replica and Veeam DR guides | n/s (platform) | §2.7 |
| ADA-120 | Data | Back-end database choice | PostgreSQL (bundled) or MS SQL | MS SQL: **Pro** | [cmp](https://www.manageengine.com/products/active-directory-audit/pricing-details.html) |

## 4. UX notes

### 4.1 Console structure
Observed in the public demo (build 8703, technician login) on 2026-10-02 via [demo.adauditplus.com](https://demo.adauditplus.com/). Admin-only tabs come from the help docs.

| Level | Structure |
|---|---|
| Top tabs | Dashboard · Active Directory · Cloud Directory · File Audit · Server Audit · Endpoint · Analytics · Alerts |
| Admin-only tabs | Configuration · Admin · Support · AD Backup (referenced throughout the [help docs](https://www.manageengine.com/products/active-directory-audit/help/), e.g. [revert](https://www.manageengine.com/products/active-directory-audit/help/usecase/revert-ad-changes.html), [schedule reports](https://www.manageengine.com/products/active-directory-audit/help/general-config/schedule-reports-configuration.html)) |
| Sub-tabs | **AD:** Auditing / Attack Surface Analyzer. **File Audit:** File Auditing / File Analysis. **Server Audit:** Auditing / Attack Surface Analyzer. **Cloud Directory:** Auditing / Risk. **Analytics:** User Behaviour Analytics / Custom Report / Aggregate Reports. **Endpoint:** Endpoint Analytics / Process / File / Network. |
| Navigation | Left tree of categories leading to individual reports. **AD › Auditing alone has 43 categories and 438 report entries.** It mixes object-based groups ("User Management") with older "report-profile" groups ("User Modification", "Account Creation") that cover the same ground. |
| Build 9000 changes | ([RN 9000](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html)) Admin and Configuration tabs renamed and reorganized; report categories and names renamed. New paths look like "Identity → AD Auditing → Logon Activity → …". Redesigned dashboard and summary pages, color coding by module, drawer-style config dialogs, one unified Cloud Directory config screen, the new **Activity Explorer**, and "Add to Favorite Reports" removed. **We have not seen the 9.0 UI firsthand.** |
| Front-end stack | Ember.js SPA, jQuery 3.5.1, jquery-migrate 1.4.1 (demo page source) |

### 4.2 Configuration friction (from the docs)
- **Many tasks happen outside the UI:**
  - HA setup means editing config files and running SQL inserts ([HA setup](https://www.manageengine.com/products/active-directory-audit/help/general-config/high-availability-setup.html)).
  - Changing the DataEngine port means editing two config files ([DataEngine](https://www.manageengine.com/products/active-directory-audit/help/quickstart/privileges-required-for-dataengine.html)).
  - Restricting TLS ciphers means editing `server.xml` ([hardening](https://www.manageengine.com/products/active-directory-audit/help/general-config/security-hardening.html)).
  - Session recording requires copying `ffmpeg.exe` by hand ([help](https://www.manageengine.com/products/active-directory-audit/help/usecase/user-session-recording-overview-and-steps.html)).
- **Settings are hidden in odd places.** The NTLM auditing switch sits under *Support → Support Info → More* ([audit policies](https://www.manageengine.com/products/active-directory-audit/help/data-source/ad-audit-configure-audit-policies-manually.html)). The new "skip daily SACL check" option lives on the **DB Query page** ([RN 9000](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html)).
- **Setup is either insecure or laborious.** The fast path is Domain Admin credentials. The least-privilege path is a long, multi-step procedure across GPOs, groups, registry and channel ACLs ([privileges](https://www.manageengine.com/products/active-directory-audit/help/quickstart/privileges-required-for-ad-windows-server-workstation-audit.html)).
- **Upgrades are chained service packs.** Example path: 7000–7251 → 7260 → 8500 → 8701 → 9000, exiting the Update Manager after each step ([service pack](https://www.manageengine.com/products/active-directory-audit/service-pack.html)).
- **The vendor claims easy deployment:** download to reports and alerts "in under 30 minutes" ([UBA page](https://www.manageengine.com/products/active-directory-audit/user-behavior-analytics.html)).

### 4.3 What reviewers say
**[Capterra](https://www.capterra.com/p/210774/ADAudit-Plus/reviews/)** (as rendered 2026-10-02): **4.5/5 from 104 reviews**; Ease of Use 4.5; Customer Service 4.4. Quotes are verbatim and were confirmed by two separate fetches:
- "The interface can also feel a bit dated and occasionally sluggish when pulling larger reports or filtering across longer date ranges." (Network Support Technician, financial services, 2026-06-22)
- "you really have to spend some time fine-tuning the alerts, otherwise your inbox will get absolutely flooded with routine notifications and false alarms." (SecOps Manager, 5k–10k employees, 2026-06-22)
- "There's also a bit of a learning curve when you're just getting started, so it's not the most beginner-friendly." (Senior SysAdmin, retail, 2026-06-23)
- "The upgrade process is very fiddly and can be time consuming, with several manual steps…" (Infrastructure Services Manager, 2026-06-25)

**[PeerSpot](https://www.peerspot.com/products/manageengine-adaudit-plus-reviews):** **4.4/5 from 15 reviews**.
- "graphical reporting, as currently, it's limited with old school bar charts" (2025-09-16)
- "The interface could be improved" (2025-02-24)
- "One problem with ADAudit is that it has too many configurations" (2025-01-21)

**Positives that come up again and again:** auditor-ready reports, broad coverage, price, and quick time to first report (vendor testimonials such as "active in less then 1 hour" on the [AD page](https://www.manageengine.com/products/active-directory-audit/active-directory-auditing.html)).

`[TODO]` G2, Gartner Peer Insights and TrustRadius all returned HTTP 403 to automated fetch. Reddit and Spiceworks were not covered.

---

## 5. Release velocity
Source for everything in this section: [release notes](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html).

**Cadence:**
- 2024: 10 builds
- 2025: 7 builds
- 2026 up to Sep 30: 14 builds

About 4 releases a year add features (2024: 8000, 8100, 8110, 8120; 2025: 8500, 8510, 8520, 8530; 2026: 8600, 8700, 8710, 9000). The rest are security or bug fixes.

**Direction:** the product is moving from an "AD change auditor" toward **identity threat detection and response (ITDR) plus identity, cloud and SaaS security posture management (ISPM/CSPM/SSPM), cloud entitlement analysis (CIEM) and data-access analytics**. That puts it in the same space as Netwrix, Semperis, Varonis and Tenable Identity.

| Build | Date | Notable additions |
|---|---|---|
| 8000 | 2024-03-01 | **Attack Surface Analyzer** for AD, cloud and hybrid. Sysmon reports moved under Server Audit. 6 SQL injection CVEs fixed. |
| 8100 | 2024-05-20 | **AD Backup & Recovery** and **Revert AD changes** |
| 8110 | 2024-06-14 | **AWS Managed Microsoft AD** auditing; **FSx for NetApp ONTAP**; Attack Surface Analyzer for AWS and GCP directories |
| 8120 | 2024-07-18 | New **Archive** feature (tiered retention); **Zendesk** and **ServiceDesk Plus** ticketing; Huawei HyperMetro |
| 8121 / 8123 | 2024-08-19 / 2024-11-08 | Security fixes: 5 SQL injection CVEs plus XSS |
| 8500 | 2025-01-31 | Attack Surface Analyzer for **servers and endpoints (CIS)**, **Intune** auditing, **Nutanix** and **CTERA**, **Windows LAPS**, agent management console, SSL via UI, **agent self-upgrade**, real-time USB monitoring, Force SAML |
| 8510 | 2025-03-14 | UBA alert filters; **NetApp REST API** for ONTAP 9.6+; "Alert Me" renamed "Notifications" |
| 8511 | 2025-05-09 | **8 SQL injection CVEs** fixed, plus an authentication bypass |
| 8520 | 2025-09-10 | Security Hardening page; **PostgreSQL 17.5** (drops 9.4); Kayako, Freshservice and Jira ticketing; SDP request templates |
| 8530 | 2025-10-09 | **Qumulo** NAS |
| 8600 | 2026-01-08 | **File Analysis** becomes a licensed add-on |
| 8606 / 8607 | 2026-04-17 / 04-22 | **Critical** unauthenticated RCE chain in agent APIs fixed (CVE-2026-6516); CSRF fixes |
| 8700 | 2026-05-20 | DataEngine now backs Entra reports; **Exchange Online, SharePoint and OneDrive** reports; Entra risk and role reports; Dell PowerScale 9.10 |
| 8703 | 2026-06-12 | SQL injection CVE-2026-12062 and AD360 SSO account-takeover CVE-2026-11374 fixed; agent TLS validation |
| 8710 | 2026-07-30 | **Advanced Recovery** (point-in-time, granular); CIS Windows Server 2025 benchmark |
| 8711 / 8712 | 2026-08-24 / 09-02 | Second-order SQL injection CVE-2026-76981; access-control fixes in 8 modules |
| **9000 (v9.0)** | **2026-09-30** | Expanded AD Attack Analyzer with **whitelisting** and real-time threat alerts. **Non-human identity** auditing (gMSA, service accounts, certificate auth). NTLM and elevated-process reports. **Access Analyzer** for AD, Cloud and Data (attack paths, effective permissions, group-removal simulator). Attack Surface Analyzer for **cloud (CSPM)** and **SaaS (SSPM, 144 policies)**. **Entra-joined device** auditing. **Cloud file transfer monitoring** (endpoint SSL inspection). **Activity Explorer**. UI redesign. Protobuf agent transport. MSSQL moved to the JDBC driver. Fixes for a deserialization RCE and a SAML authentication bypass. |

---

## 6. Weaknesses & gaps

| # | Weakness | Evidence |
|---|---|---|
| W1 | **Single-server architecture you scale by buying a bigger box.** One Windows/Java/Tomcat app with PostgreSQL. For best performance the vendor says "Use a machine with 16 cores and 32 GB RAM". There is no published EPS benchmark and no documented horizontal scale-out. | [sysreq](https://www.manageengine.com/products/active-directory-audit/help/quickstart/system-requirements.html), [architecture](https://www.manageengine.com/products/active-directory-audit/help/quickstart/architecture.html) |
| W2 | **HA is bolted on and manual.** Hot standby needs three servers, file replication via robocopy, a virtual IP, and SQL inserts typed into the DB Query page. The shared database is a single point of failure. | [HA setup](https://www.manageengine.com/products/active-directory-audit/help/general-config/high-availability-setup.html), [workflow](https://www.manageengine.com/products/active-directory-audit/help/general-config/high-availability-workflow.html) |
| W3 | **No SaaS.** Customers must patch the box themselves (see W6). ManageEngine's cloud AD-auditing offer is a different product, Log360 Cloud. | [Log360 Cloud](https://www.manageengine.com/cloud-siem/) |
| W4 | **Agentless collection is sensitive to network conditions.** It needs dynamic RPC ports 49152–65535 open on every host, and the vendor's troubleshooting guide blames failures on packet loss over unstable WAN links and suggests installing an agent instead. When the agent cache fills up (2–10 GB), collection stops. | [ports](https://www.manageengine.com/products/active-directory-audit/help/quickstart/ports.html), [troubleshooting](https://www.manageengine.com/products/active-directory-audit/help/troubleshooting/event-collection-troubleshooting-general-errors.html), [agent prereqs](https://www.manageengine.com/products/active-directory-audit/help/general-config/agent-configuration-installation-prerequisites.html) |
| W5 | **Upgrades are painful.** Service packs must be applied in sequence. Build 8520 was incompatible with PostgreSQL 9.4 installs until the database was upgraded by hand. The Log360 integration breaks unless both products are on matching builds. A Capterra reviewer called upgrades "very fiddly". Forum thread titles include "Can't upgrade ADAudit+ from Build 8701 to 8702" and antivirus software flagging RemCom.exe during the 8600 patch `[UNVERIFIED details]`. | [service pack](https://www.manageengine.com/products/active-directory-audit/service-pack.html), [RN 8520/8700](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html), [Capterra](https://www.capterra.com/p/210774/ADAudit-Plus/reviews/), [forum](https://pitstop.manageengine.com/portal/en/community/adaudit-plus) |
| W6 | **Security track record of the tool itself.** **28 CVE IDs** appear in the release notes from Jan 2024 to Sep 2026, and **26 of them are SQL injection.** Others: a **critical unauthenticated RCE** in the agent APIs (CVE-2026-6516; every build below 8606 was affected); a SAML SSO authentication bypass and a deserialization RCE (both fixed in 9000); an AD360 SSO account takeover (8703). The built-in admin password used to be identical on every install, and a change at first login was only forced from build 8121. This matters because the product holds Domain-Admin-level credentials. | [RN](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html), [CVE-2026-6516](https://www.manageengine.com/products/active-directory-audit/cve-2026-6516.html), [hardening §2](https://www.manageengine.com/products/active-directory-audit/help/general-config/security-hardening.html) |
| W7 | **Alert noise and false positives.** Capterra reviewers say inboxes get "flooded with routine notifications and false alarms". Build 9000 fixed false positives in Pass-the-Ticket, Golden Ticket, Silver Ticket, Primary Group ID and RID hijack detection, and only then added whitelisting. A forum thread title asks for customizable Attack Surface Analyzer alert settings to suppress false positives `[UNVERIFIED details]`. | [Capterra](https://www.capterra.com/p/210774/ADAudit-Plus/reviews/), [RN 9000](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html), [forum](https://pitstop.manageengine.com/portal/en/community/adaudit-plus) |
| W8 | **Storage grows fast and old data is hard to reach.** Reviewer: "a bit of a storage hog". DataEngine uses about 15 MB per 100k events. Past bugs caused sudden disk growth (7053) and database bloat from noisy logon events (7212). Cold and Frozen archives are **not searchable**: data must be restored to the database (re-archived after 48 h) or indexed, at most 50 files per category. | [Capterra](https://www.capterra.com/p/210774/ADAudit-Plus/reviews/), [DataEngine](https://www.manageengine.com/products/active-directory-audit/help/quickstart/privileges-required-for-dataengine.html), [RN](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html), [archive](https://www.manageengine.com/products/active-directory-audit/help/admin-settings/archive-events-overview.html) |
| W9 | **Stability.** A forum report on build 8511 says java.exe hits 100% CPU every 2–3 days and the product stops collecting until it is killed or rebooted. Release notes also fix high CPU (7111, 7202), out-of-memory errors (7113, 7210) and frequent DataEngine restarts (8120, 8601). | [forum thread](https://pitstop.manageengine.com/portal/en/community/topic/java-exe-100-cpu-consumption), [RN](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html) |
| W10 | **Licensing complexity and edition gating.** Before/after values are Professional-only. There are 7 or more add-on SKUs, NAS units differ by vendor, and the new build 9000 modules have no published price. | §1.3, §1.6 |
| W11 | **Entra and M365 coverage is shallower than on-prem.** Full depth depends on the customer having Entra Premium. A CIO on Capterra wants better M365 reporting. Exchange Online, SharePoint and OneDrive reports only arrived in May 2026. Forum thread title: "Azure Auditing - initial sync - too many requests, token expiry" `[UNVERIFIED details]`. | [methods](https://www.manageengine.com/products/active-directory-audit/help/data-source/methods-to-configure-azure-ad.html), [Capterra](https://www.capterra.com/p/210774/ADAudit-Plus/reviews/), [RN 8700](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html), [forum](https://pitstop.manageengine.com/portal/en/community/adaudit-plus) |
| W12 | **Dated UI with too many reports.** Ember.js and jQuery front end. Roughly 1,000 report entries in the nav, with overlapping groupings. Many settings live outside the UI. Reviewers say "dated", "old school bar charts", "too many configurations" and mention a learning curve. | §4 |
| W13 | **Hard to integrate with.** There is no documented public API and no webhooks. Chat-tool alerting (Slack, Teams) was not found `[UNVERIFIED absence]`; a forum user asks how to send alerts to Telegram. | §3.12, [forum](https://pitstop.manageengine.com/portal/en/community/adaudit-plus) |
| W14 | **Coverage limits.** Standalone CAs are not audited. Intune-only devices are not supported. The Mac agent covers logon/logoff only. PowerShell auditing lists only versions 4.0/5.0 (PowerShell 7 not listed `[UNVERIFIED]`). Synology has no permission or failed-access auditing. NetApp and EMC have no copy reports. GPMC must be installed on the server. MSSQL only works with named instances. | [AD CS](https://www.manageengine.com/products/active-directory-audit/help/usecase/adcs-audit-overview.html), [Entra devices](https://www.manageengine.com/products/active-directory-audit/help/usecase/entra-id-joined-device-auditing-overview.html), [PowerShell](https://www.manageengine.com/products/active-directory-audit/help/usecase/powershell-audit-overview.html), [known issues](https://www.manageengine.com/products/active-directory-audit/help/troubleshooting/known-issues.html) |
| W15 | **Inconsistent marketing.** Report counts are given as 200+, 250+ and 300+ on different pages. "Skeleton Key" is named on the UBA page but is not among the 28 documented detections. | §3.11, [UBA page](https://www.manageengine.com/products/active-directory-audit/user-behavior-analytics.html), [ASA-AD](https://www.manageengine.com/products/active-directory-audit/help/usecase/attack-surface-analyzer-for-active-directory.html) |
| W16 | **Scope creep into employee monitoring** (our inference). Work-hours tracking, session video recording and endpoint SSL interception may worry works councils or privacy officers, especially in the EU. It also dilutes the product's focus. `[inference — not sourced]` | §3.2, §3.7 |

---

## 7. Parity vs leapfrog

### 7a. Table stakes for a switching customer
| Area | What we must match on day one | Why |
|---|---|---|
| AD change auditing | Who, what, when and where for users, groups, computers, OUs, GPOs, contacts, schema, configuration and DNS. **Old/new values for every attribute.** **GPO setting-level diffs.** **ACL/AdminSDHolder diffs.** | Pro-edition customers use these daily (ADA-001…010). Anything less is a downgrade. |
| Logon & lockout | DC, server and workstation logons; failure reasons; logon history and duration; RDP/RDG and NPS logons; **lockout root cause** (services, tasks, mapped drives, mobile) | Help-desk workflows depend on these (ADA-023…040) |
| Entra ID | Sign-ins (including non-interactive and service-principal), directory changes, roles, Conditional Access, risk, Intune; hybrid view; long retention | Most targets will be hybrid (our assumption; ADA-046…054) |
| File and NAS | Windows file servers and clusters, plus **whatever NAS each lead actually runs**, at least NetApp and Dell/EMC | Licensed per lead; check during discovery |
| Server and workstation | Local logon and accounts, process, scheduled tasks, USB, PowerShell, FIM, printer (if the lead uses it) | ADA-066…076 |
| Alerting & response | Profiles shipped out of the box, thresholds, business hours, email/SMS, **ITSM tickets** (ServiceNow, Jira, SDP), script or automated containment | ADA-092…096 |
| Compliance reporting | SOX, HIPAA, PCI DSS, GLBA, FISMA, GDPR, ISO 27001 packs; scheduled PDF/XLS/CSV delivery; **report names auditors recognize** | Auditors know specific ADAudit Plus reports such as "Administrative User Actions", "Logon Failures" and "All File or Folder Changes" ([compliance page](https://www.manageengine.com/products/active-directory-audit/active-directory-compliance-reports.html)) |
| SIEM | Syslog, CEF and Splunk HEC with **field mappings compatible with existing SIEM parsers** | Avoid breaking SOC content (ADA-106) |
| Collection | Agent **and** agentless options; least-privilege service account | ADA-079, §2.2 |
| Retention | Multi-year retention with tiered storage and **search over history** | PCI DSS v4.0 req. 10.5.1 (12 months, 3 immediately available) `[UNVERIFIED — confirm against PCI SSC text]`; customer policies are often longer |
| Admin | Delegated roles, 2FA, SAML SSO, an audit trail of the tool's own users | ADA-110…112 |

#### Historical audit data during the switch (critical table stake)
Customers will not throw away years of audit history. The bridging options below are ordered from cheapest to most effort.

1. **Keep ADAudit Plus running as a read-only viewer.** The Free edition "never expires" and allows "Reports generation from event log data collected during evaluation / license period" ([licensing help](https://www.manageengine.com/products/active-directory-audit/help/quickstart/adaudit-plus-license-and-edition-details.html)). That should let a customer stop paying and still answer auditors.
   - **What the vendor documents (checked 2026-10-02).** The licensing page says only: "When you install the product, the Professional Edition is installed, and will work for 30 days. After 30 days, it will automatically revert to Free Edition, unless the Standard or Professional Edition license is purchased" ([licensing page](https://www.manageengine.com/products/active-directory-audit/help/getting-started/licensing-ad-audit-plus.html)). The edition-details page describes the Free edition: "Free edition never expires. Complimentary 25 Workstations audit", "No fresh data will be collected after 30 days (excludes Workstations)", and "Reports generation from event log data collected during evaluation / license period" ([edition details](https://www.manageengine.com/products/active-directory-audit/help/quickstart/adaudit-plus-license-and-edition-details.html)). Both are vendor docs.
   - **That is trial-end behaviour.** Nothing we found says what happens when a **paid** Standard/Professional licence or subscription lapses. `[UNVERIFIED]` that a lapsed paid ADAudit Plus reverts to Free and keeps its history viewable. This needs a lab test or a vendor answer. The pitstop topic ["drop-back-to-free-version"](https://pitstop.manageengine.com/portal/en/community/topic/drop-back-to-free-version) shows the question, but no answer was visible when fetched on 2026-10-02. Do not promise this route to a customer until it is tested.
   - Downside: the server still has to be patched (W6).
2. **Dual-run during the overlap.** Point ADAudit Plus's real-time SIEM forwarding (syslog/CEF/Splunk HEC; every category except printer and advanced GPO) at an **activeDIQ syslog/CEF receiver** ([SIEM help](https://www.manageengine.com/products/active-directory-audit/help/admin-settings/siem-integration.html)).
   - This gives continuous history plus side-by-side validation.
   - It does **not** backfill data from before the cutover.
3. **Bulk export through scheduled reports.** The "Before N days" range covers everything since the product was installed, and output can be CSV or XLS ([schedule help](https://www.manageengine.com/products/active-directory-audit/help/general-config/schedule-reports-configuration.html)).
   - Build **importers for the top roughly 30 ADAudit Plus compliance reports**, so old evidence can be searched in activeDIQ.
   - Effort: moderate. Formats are per-report and undocumented.
4. **EVTX backfill.** If the customer kept raw Security logs, import them and rebuild history. ADAudit Plus already does this, and ManageEngine sells "Historic EVT/EVTX file import" as an onboarding service ([restore](https://www.manageengine.com/products/active-directory-audit/help/admin-settings/archive-and-restore.html), [store](https://store.manageengine.com/active-directory-audit/)). We need at least this capability.
5. **Read the database directly** (PostgreSQL on 33307, or MSSQL). The data is the customer's, but the schema is undocumented, the DataEngine (XNode) store is proprietary, and archives are password-protected ZIPs ([hardening §11](https://www.manageengine.com/products/active-directory-audit/help/general-config/security-hardening.html)).
   - `[UNVERIFIED feasibility]`; `[TODO]` legal/EULA review.
6. **Carry over configuration.** Alert profiles, scheduled reports, technician roles, exclusions, and the audit-policy and SACL GPOs ADAudit Plus created (e.g. "ADAudit Plus Permission GPO", Default Domain Controllers Policy edits) ([privileges](https://www.manageengine.com/products/active-directory-audit/help/quickstart/privileges-required-for-ad-windows-server-workstation-audit.html)).
   - activeDIQ should **detect and reuse the existing audit policy** rather than re-push it.
   - Ship a **report crosswalk from ADAudit Plus to activeDIQ**.
   - **Configuration export (resolved as "no open format documented").** The vendor's backup-and-restore KB produces a password-protected `OfflineBackup_<timestamp>.ezip` (database and event tables) plus copied folders, and requires "Both installations must be on the same build version"; the steps use `StartDB.bat`, `BackupDB.bat`, `RestoreDB.bat` and `RestoreEventTables.bat`. The KB names a **default backup password** when none is configured ([KB, 2025-11-24](https://pitstop.manageengine.com/portal/en/kb/articles/how-to-migrate-adaudit-plus-data-from-an-older-build-to-a-new-server-using-the-backup-and-restore-method-24-11-2025)). We did not find an export of alert profiles, schedules or roles to CSV/JSON/XML in the docs as of 2026-10-02 (not proof that none exists). The `.ezip` is a proprietary dump; plan to rebuild configuration, not import it.

**Discovery checklist per warm lead:**
- build number and edition
- add-ons and counts
- database (PostgreSQL or MSSQL) and archive settings and size
- number of custom alert profiles and scheduled reports
- SIEM targets
- NAS vendors
- Entra license tier
- use of AD Backup, File Analysis or Attack Surface Analyzer
- agents vs agentless
- HA in use or not

### 7b. Can be deferred (confirm per lead)
- Employee work-hours tracking and **session video recording**. Privacy-sensitive and not core to identity.
- **Cloud file transfer monitoring** (endpoint SSL interception, brand new in 9000) and process/network attack detection (EDR territory).
- CSPM for AWS/GCP. SSPM breadth beyond Entra and Conditional Access.
- File Analysis (unused, outdated or trivial data cleanup), printer auditing, Wi-Fi logon, macOS logon.
- Long-tail NAS: QNAP, CTERA, Nutanix, Qumulo, Huawei, Hitachi, Synology. Add only when a lead needs it.
- AWS Managed AD and Azure AD DS. AD CS deep auditing in phase 2. **But** the AD CS attack surface matters for ITDR, so plan for it.
- Full AD backup and recovery. activeDIQ's management side may cover object rollback anyway (see 7c).

### 7c. Where activeDIQ can leapfrog
1. **Change auditing and remediation in one product.** activeDIQ is a management product, so a "who changed X → see the diff → one-click revert or approve" loop can be native. ManageEngine splits this across ADAudit Plus, its AD Backup add-on and ADManager Plus/AD360 (W10, ADA-022/090).
2. **Investigation-first UX instead of ~1,000 reports.** Offer a handful of flexible views: an object timeline, a user timeline, and diffs. Add natural-language search ("who added anyone to Domain Admins last quarter?"). ManageEngine only shipped Activity Explorer on 2026-09-30, so this is a narrow window (W12, ADA-103).
3. **No edition gating on core audit depth.** Before/after values, GPO diffs and ACL diffs in every tier. Simple, transparent licensing with no NAS unit maze (W10).
4. **Cloud-native or hybrid architecture.** A SaaS console with light collectors, scale-out storage, every tier searchable (no restore-to-query), HA by default, and zero-touch upgrades. This directly answers W1–W5 and W8.
5. **Credible security posture.** Parameterized data access, least-privilege defaults (gMSA, no Domain Admin), signed agents, SOC 2 and published pen tests. Compare against the 26 SQL injection CVEs in ADAudit Plus (W6). In RFPs, **state our own facts; do not disparage.**
6. **Noise reduction by design.** Correlate detections into incidents, tune alerts suggested from feedback, whitelist from day one, and put privileged context on every alert (W7).
7. **Open platform.** A documented REST API, webhooks, Slack/Teams actions, and exports to customer data lakes (W13).
8. **Audit-readiness automation.** Continuous checks on audit policy and SACL health, drift alerts and guided fixes. ADAudit Plus only emails notifications about these (ADA-097). Map evidence packs to specific control IDs, including **NIS2/DORA**, for which we found no ADAudit Plus compliance page (ADA-099).
9. **Painless migration as a product feature.** Ship the ADAudit Plus history bridge from 7a (syslog receiver, CSV report importers, EVTX import, report crosswalk). It removes the biggest objection to switching.

---

## Resolved gaps (T-0001, 2026-10-02)

- **Configuration export:** no open export format documented; proprietary `.ezip` backup, same-build restore (§7a option 6).
- **Read-only DC licensing:** the licensing page says ADAudit Plus "is licensed based on the number of Domain Controllers" and collects only from DCs "in an enabled state"; it does **not** say how read-only DCs are counted ([licensing page](https://www.manageengine.com/products/active-directory-audit/help/getting-started/licensing-ad-audit-plus.html), 2026-10-02). Not found in docs, so still unconfirmed.
- **Certifications:** ADAudit Plus is **not named** in ManageEngine's compliance centre, which lists SOC 2 Type II and ISO 27001 as covering "all cloud services and on-premise products of ManageEngine" and names only ADManager Plus among the AD products in the SOC 2 + HIPAA Type 2 scope ([compliance centre](https://www.manageengine.com/compliance.html), 2026-10-02). Say "covered by the company-wide ISO 27001 and SOC 2 Type II scope statements", never "ADAudit Plus is SOC 2 certified".
- **Peer-review rating, Gartner Peer Insights:** 4.5 of 5 from 294 ratings, 62% five-star and 37% four-star, in the SIEM market. Source: a search-engine snippet of [the Gartner page](https://www.gartner.com/reviews/product/manageengine-adaudit-plus) on 2026-10-02; the live page returns 403 to our fetcher, so treat as `[UNVERIFIED: snippet]` and re-check in a browser. Peer-review rank, and many 2026 reviews are vendor-solicited (customer-voice file §1.1).

## Remaining gaps

- `[UNVERIFIED]` **Paid-licence lapse → Free edition:** the vendor documents only trial-end reversion to Free (§7a option 1). What a lapsed paid licence does, and whether history stays viewable, is not documented. Needs a lab test or a vendor answer (the latter needs CEO approval to contact the vendor).
- `[TODO]` G2 and TrustRadius refreshes, Reddit r/sysadmin and Spiceworks sentiment: blocked or not reachable. The Gartner figure above is a snippet only.
- `[TODO]` Hands-on look at the build 9000 UI (the public demo is still on 8703) and licensing of the 9000 modules (Attack Surface Analyzer cloud/SaaS, Access Analyzer, cloud file transfer): not listed on the pricing page or store as of 2026-10-02; needs a lab or a vendor answer.
- `[TODO]` Default scheduled-collection interval and events-per-second limits: not found in the docs (only the 1,000-event agent request cap in build 7113).
- `[TODO]` Read-only DC licence counting (above).
- `[TODO]` Whether the first year of AMS is bundled with a perpetual purchase or billed on top. The store lists them as separate line items; needs a quote.
- `[TODO]` Database schema accessibility for a direct-read migration, plus the EULA review (§7a option 5).

Scratch evidence (demo report tree, store price extracts) was kept in the session scratchpad only and is not committed.

## Changelog

- **2026-10-02 (T-0001):** Closed the config-export and certification gaps; Free-edition fallback documented for trial end only, paid-licence lapse left `[UNVERIFIED]`; re-tagged the rest in "Remaining gaps".
