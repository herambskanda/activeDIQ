---
title: "Competitive Benchmark: ManageEngine ADSelfService Plus"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: heramb
sources_last_checked: 2026-10-02
---

# Competitive Benchmark: ManageEngine ADSelfService Plus

> Status: draft complete (2026-10-02). Open items are tagged `[TODO]` and summarized in §9.
>
> Conventions: `[UNVERIFIED]` = could not confirm from a primary source; `[TODO]` = not researched yet; "(computed)" = arithmetic on published list prices. Absence of evidence is never stated as absence of a feature. Vendor marketing counts (authenticators, apps) are quoted as the vendor states them and are inconsistent across pages; noted where relevant.

## 0. Key findings (decision summary)
1. **Current state:** v7.0 build 7001 (2026-08-21). Customer-hosted Java/Tomcat app on Windows. Entra ID support arrived only in build 7000 (2026-06-13), and many features remain "AD only" (§1.1, §6).
2. **Real price is about 2× the headline.** SSO, JIT, adaptive MFA and all endpoint/VPN/OWA MFA sit in a separate per-user "Endpoint MFA" SKU. At 5,000 users, Pro plus Endpoint MFA Pro plus the HA add-on is $14,185/yr ($2.84/user) versus a $6,995 headline (computed, §1.3). Over-limit endpoint MFA **fails open** (§1.4).
3. **Breadth is real.** 138 inventoried features (§3), including:
   - 20 authenticator types;
   - logon-screen reset on Windows, macOS and Linux;
   - offline MFA;
   - cached-credential update without VPN;
   - 100+ SSO apps;
   - about 17 named password-sync targets.

   Parity is a significant build.
4. **Security record is a sales lever.** There are 3 CISA KEV entries, including 2021's APT-exploited REST API bypass, and 7 CVEs published in 2026 to date (auth bypass, MFA bypass, logon-screen RCE as SYSTEM). The UI tier is still Struts 1 (EOL), Ember 2.18 and Bootstrap 3 (§2.1, §4).
5. **UX is the weak flank.** Reviewers call the admin UI "dated" and hard to navigate (2026 reviews). The iOS app is rated 2.1/5. Enrollment relies on a desktop-blocking HTA popup (§5).
6. **Switching cost is enrollment.** Email/SMS, AD-attribute questions, Duo/RSA/RADIUS/Entra and PIV can migrate with zero user effort. Security answers are one-way hashed (MD5/SHA-512), so plaintext export is impossible. TOTP seed and passkey export is undocumented, so assume re-enrollment unless a lab test proves otherwise. A migration kit plus progressive enrollment is P0 (§8a).
7. **ADSSP's own public roadmap lists its gaps:** custom admin roles, a REST API, device trust, UBA-based conditional access, passwordless endpoints and non-GUI MFA. activeDIQ can ship these as leapfrogs (§6, §8c).

## 1. Overview, editions & pricing

### 1.1 What it is (as of 2026-10-02)
- **Product:** ManageEngine (Zoho Corp) ADSelfService Plus ("ADSSP"). Self-described as "a unified MFA, SSO, and SSPR solution to bolster identity security" ([product page](https://www.manageengine.com/products/self-service-password/)). It is the self-service/MFA/SSO member of the AD360 suite.
- **Current build:** **7.0 Build 7001**, released **2026-08-21**, 64-bit Windows installer, 273 MB ([download page](https://www.manageengine.com/products/self-service-password/download.html); [release notes](https://www.manageengine.com/products/self-service-password/release-notes.html)). 7001 is mostly a security build (9 fixes). It also drops 32-bit installs and TLS 1.0/1.1 ([release notes](https://www.manageengine.com/products/self-service-password/release-notes.html)).
- **Directory scope:** Active Directory, plus **Microsoft Entra ID since build 7000 (2026-06-13)**. Build 7000 added SSPR, MFA, SSO, password sync, conditional access and the password policy enforcer for Entra ID ([what's new](https://www.manageengine.com/products/self-service-password/whats-new.html); [release notes](https://www.manageengine.com/products/self-service-password/release-notes.html)). Many capabilities are still marked "(AD only)" in the June 2026 licensing guide: account unlock, expiry notifications, directory self-service, login-screen reset on macOS/Linux, cached credentials, VPN/OWA MFA ([licensing guide PDF](https://download.manageengine.com/products/self-service-password/how-adselfservice-plus-licensing-works.pdf)).
- **Delivery:** customer-hosted software only. It is also listed on Azure Marketplace and AWS Marketplace, which still means customer-run, plus a separate TAA-compliant build ([download page](https://www.manageengine.com/products/self-service-password/download.html)). I found no vendor-hosted SaaS edition of ADSSP. The admin-guide header has an "On Premises / Cloud" toggle, but its links are JavaScript placeholders and say nothing about an ADSSP cloud edition ([admin guide](https://www.manageengine.com/products/self-service-password/help/admin-guide/index.html)). ManageEngine's cloud IAM product, Identity360, was not researched `[TODO]`.

### 1.2 Editions
Source for this table: [licensing guide PDF, June 2026](https://download.manageengine.com/products/self-service-password/how-adselfservice-plus-licensing-works.pdf) and [licensing FAQ](https://www.manageengine.com/products/self-service-password/licensing-faq.html).

| Edition | Price / term | User limit | Scope |
|---|---|---|---|
| Free | $0, never expires | 50 users | "Basic self-service features". Includes 10 Endpoint MFA Standard licenses |
| Evaluation | 30 days | Unlimited | All Professional features and add-ons except Failover & Secure Gateway. Converts to Free on expiry |
| Standard | From $595 / 500 users / yr | As purchased | Web SSPR, web unlock (AD only), **basic authenticators** (8), expiry notifications (AD only), Password Policy Enforcer, real-time password sync, mobile app/mobile browser reset, directory self-update, employee search, org chart, group self-service (AD only) |
| Professional | From $1,195 / 500 users / yr | As purchased | Standard plus: login-screen reset (Windows; macOS/Linux AD-joined only), **advanced authenticators** (13 more), conditional access, cached-credential update (AD only), policy enforcement on Ctrl+Alt+Del and ADUC (AD only) |
| **Endpoint MFA** (separate module) | Std from $495 / 500 users; Pro from $995 / 500 users | As purchased | **Std:** SSO for applications, MFA for application logins, Windows workstation MFA, macOS/Linux workstation MFA (AD only). **Pro adds:** Windows Server MFA, VPN and OWA MFA, RDP and UAC MFA, offline MFA, adaptive MFA, device-based MFA, passwordless login (portal and cloud apps), adaptive SSO. Must match the base edition (Std with Std, Pro with Pro) |

Basic authenticators are security Q&A, email, SMS, Google Authenticator, Microsoft Authenticator, AD security questions, Zoho OneAuth TOTP and custom hardware TOTP. The advanced ones are listed in §3.3 ([identity verification help](https://www.manageengine.com/products/self-service-password/help/admin-guide/Configuration/Self-Service/Identity-Verification-Steps.html)).

### 1.3 Published list prices (USD, annual subscription)
Source: [pricing-details page](https://www.manageengine.com/products/self-service-password/pricing-details.html); the India and global pages show the same figures. "All-in" columns are computed and include Endpoint MFA of the matching edition plus the $395 Failover & Secure Gateway add-on.

| Users | ADSSP Std | ADSSP Pro | Endpoint MFA Std | Endpoint MFA Pro | **All-in Std** (computed) | **All-in Pro** (computed) | All-in Pro $/user/yr (computed) |
|---|---|---|---|---|---|---|---|
| 500 | 595 | 1,195 | 495 | 995 | 1,485 | 2,585 | 5.17 |
| 1,000 | 1,195 | 2,195 | 995 | 1,895 | 2,585 | 4,485 | 4.49 |
| 1,500 | 1,745 | 2,895 | 1,445 | 2,695 | 3,585 | 5,985 | 3.99 |
| 2,000 | 2,195 | 3,495 | 1,795 | 3,395 | 4,385 | 7,285 | 3.64 |
| 3,000 | 3,145 | 4,695 | 2,495 | 4,695 | 6,035 | 9,785 | 3.26 |
| 5,000 | 4,995 | 6,995 | 3,495 | 6,795 | 8,885 | 14,185 | 2.84 |
| >5,000 | Quote only ("contact sales") | | | | | | |

**Add-ons**

| Add-on | Price | Notes |
|---|---|---|
| Failover & Secure Gateway Services | $395/yr flat | HA failover, load balancing and reverse proxy. Not available on Free, and not included in Evaluation by default. Failover deployment is *only* available through this add-on ([HA guide PDF, June 2026](https://download.manageengine.com/products/self-service-password/adselfservice-plus-high-availability-configuration-guide.pdf)) |
| SMS add-on (Clickatell gateway) | 2k credits $595; 5k $1,195; 10k $2,145; 20k $4,195; 50k $10,195; 100k $20,395 (perpetual credits) | **Not sold in the US.** US customers must bring their own SMS provider ([licensing FAQ](https://www.manageengine.com/products/self-service-password/licensing-faq.html); [licensing guide](https://download.manageengine.com/products/self-service-password/how-adselfservice-plus-licensing-works.pdf)). The product home page says "from $395 for 2,000 credits", which conflicts with the $595 on the pricing page |
| Onboarding / training | Standard and Advanced Onboarding & Implementation (online); 4-hour online training | Prices are not shown in the static store page ([store](https://store.manageengine.com/self-service-password/)) |

- **Perpetual licensing** exists for both editions, with annual maintenance (AMS) bought separately. Perpetual prices are not published `[UNVERIFIED]`.
- The license is an XML file delivered by email and applied offline ([licensing FAQ](https://www.manageengine.com/products/self-service-password/licensing-faq.html)).

### 1.4 Licensing gotchas (sales ammunition; verify before quoting in an RFP)
1. **Counted per user across all features, never per feature.** "you cannot purchase user licenses for a specific feature … you need to purchase … Standard or Professional Edition as a whole for all users" ([licensing FAQ](https://www.manageengine.com/products/self-service-password/licensing-faq.html)).
2. **Users can consume a license without ever touching the portal.** With the Password Sync Agent installed on DCs, a license is consumed when an admin resets a user's password in native tools or the user changes it with Ctrl+Alt+Del ([licensing guide](https://download.manageengine.com/products/self-service-password/how-adselfservice-plus-licensing-works.pdf)). Other consumption triggers:
   - first successful identity verification;
   - first MFA-based reset or unlock using methods that need no enrollment;
   - admin CSV or database enrollment;
   - technician creation.
3. **Two SKUs per user for a "full" deployment.** SSO, JIT provisioning, adaptive MFA and all endpoint/VPN/OWA MFA sit in the separately priced Endpoint MFA module, not the base product ([licensing FAQ](https://www.manageengine.com/products/self-service-password/licensing-faq.html)). At 5,000 users, Pro plus Endpoint MFA Pro roughly doubles the headline price: $6,995 becomes $13,790 before the HA add-on (computed).
4. **Over-limit behavior differs by surface.**
   - Portal users are blocked ("license limit has been exceeded").
   - For Endpoint MFA, "MFA is simply skipped for those extra users". That is **fail-open MFA** on machine logons ([licensing FAQ](https://www.manageengine.com/products/self-service-password/licensing-faq.html)).
5. **Reclaiming licenses deletes enrollment data.**
   - Licenses come back via "Restrict Users": expired, disabled, inactive, deleted (90-day window), service-account or smart-card users, manually or on a schedule.
   - A restricted user "will not be able to log in … The enrollment data of the user will be deleted too" ([evaluator guide PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf)).
   - Older reviews complained that licenses were not freed automatically for disabled users `[UNVERIFIED]` (GetApp 2018 review).
6. **HA is a paid add-on with heavy prerequisites.** Failover needs:
   - the $395 add-on;
   - an external PostgreSQL or MS SQL database (the built-in DB "can cause a database connectivity failure");
   - same-domain servers and a shared installation folder;
   - a Domain Admin service account during initial setup ([HA guide PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-high-availability-configuration-guide.pdf)).
7. **Advanced authenticators are Professional-only.** FIDO2/passkeys, YubiKey, Duo, RSA, push, biometrics, QR, smart card, SAML, Entra MFA and RADIUS all require Professional, so the Standard edition cannot offer phishing-resistant MFA ([identity verification help](https://www.manageengine.com/products/self-service-password/help/admin-guide/Configuration/Self-Service/Identity-Verification-Steps.html)).

## 2. Architecture

### 2.1 Server and stack
| Item | Detail | Source |
|---|---|---|
| Runtime | Java application, bundled Azul Zulu OpenJDK 11 (11.0.30 in build 7000; 11.0.32 in 7001), running on **Apache Tomcat 9.0.x** (9.0.118 → 9.0.120 in 7001) | [3rd-party components PDF (build 7000, 2026-07-13)](https://download.manageengine.com/products/self-service-password/adselfservice-plus-third-party-apps-list.pdf); [release notes](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| Web/UI frameworks | **Apache Struts 1.3.11**. Apache declared Struts 1.x end-of-life with "no further security or bug fixes" ([Apache EOL notice](https://struts.apache.org/struts1eol-announcement.html)). The last upstream release was 1.3.10, so "1.3.11" is presumably a vendor-maintained fork `[UNVERIFIED]`. Also **Ember 2.18**, jQuery 3.7.1 plus jquery-migrate 1.4.1, **Bootstrap 3.4.1**, Highcharts 7.2.1, lodash 3.5.0, JasperReports 7.0.6 | [3rd-party components PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-third-party-apps-list.pdf) |
| Protocol libraries | OpenSAML 5.1.4 / xmlsec 3.0.4 (SAML), webauthn4j 0.21.8 (FIDO2), nimbus-jose-jwt (OIDC/JWT), radclient3 (RADIUS client), UnboundID LDAP SDK 7.0.4, jcifs 1.3.18 (NTLM), Duo Universal SDK 1.3.1, pushy (APNs) | same |
| Host OS | Windows Server 2008 R2–2025, or Windows 7–11. Can run on a member server or a DC. Runs as a Windows service (recommended) or a console app | [requirements](https://www.manageengine.com/products/self-service-password/help/admin-guide/requirements.html); [architecture PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-solution-architecture.pdf) |
| Hardware | Minimum 2.4 GHz / 2 cores, 8 GB RAM, 100 GB disk. Recommended 3 GHz / 4 cores, 16 GB, 200 GB SSD | [requirements](https://www.manageengine.com/products/self-service-password/help/admin-guide/requirements.html) |
| Database | Bundled PostgreSQL (15.12 as of build 7000), or external MS SQL (2012+ for builds ≥6500) or PostgreSQL. Legacy MySQL installs are told to migrate. Stores enrollment data, config, AD attribute cache, audit/report data | [best-practices PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-deployment-best-practices.pdf); [3rd-party PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-third-party-apps-list.pdf) |
| AD sync | Scheduled AD synchronization into the DB is required for policies and self-service (needs "Replicate Directory Changes") | [architecture PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-solution-architecture.pdf); [permissions PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-privileges-permissions-requirement-guide.pdf) |
| Portals | Admin and end-user portals share one URL (`http://host:8888`, HTTPS 9251); mobile web is at `/m/home`. **Default admin login is admin/admin** | [starting ADSSP](https://www.manageengine.com/products/self-service-password/help/admin-guide/working.html) |
| Policy model | Everything hangs off **self-service policies**. Each policy picks domains, OUs or groups, the features enabled and the authenticators. Policies have precedence order | [best-practices PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-deployment-best-practices.pdf) |

### 2.2 Distributed components
| Component | Where it runs | Purpose | Source |
|---|---|---|---|
| **Login agent** (Windows GINA/credential provider; macOS and Linux agents) | Endpoints and servers | Reset/unlock from the logon screen. Also required for endpoint MFA (logon, unlock, UAC, RDP), offline MFA and cached-credential update | [architecture PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-solution-architecture.pdf) |
| **Password Sync Agent** | **Every DC** in the domain | Captures native changes (Ctrl+Alt+Del, ADUC resets) for sync to other systems. Enforces ADSSP custom password policy and HIBP on native changes. Forwards the encrypted password to the server over HTTPS | [architecture PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-solution-architecture.pdf); [password sync page](https://www.manageengine.com/products/self-service-password/active-directory-password-synchronizer.html) |
| **NPS extension** (`ADSSPNPSExtension.zip`) | Windows NPS (RADIUS) server | VPN and other RADIUS MFA. The VPN must use RADIUS via Windows NPS | [evaluator guide PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf) |
| **MFA Connector** (IIS module `AdsspOWAIISModule.zip`) | Exchange/IIS server | MFA for OWA and the Exchange Admin Center after primary password auth | [evaluator guide PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf) |
| **Mobile app** (iOS 1.7.6 / Android 1.8.2, June 2026) | User phones | Reset/unlock, enrollment, push/biometric/QR/TOTP authenticator, expiry and enrollment push notifications. Can be pushed to devices from the admin portal (Mobile App Deployment) | [mobile release notes](https://www.manageengine.com/products/self-service-password/mobile-release-notes.html); [best-practices PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-deployment-best-practices.pdf) |
| Remote-exec helpers | Server → endpoints/DCs | `RemoteExecM1.exe` pushes the Windows login agent. `RemoteExecM2.exe` "facilitates remote execution of commands, primarily on domain controllers, to support password changes through PowerShell" | [3rd-party PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-third-party-apps-list.pdf) |

**Login-agent platform coverage:**
- **Windows:** clients Vista–11 and Server 2008–2025. ARM64 Windows agent added in build 6509 ([best-practices PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-deployment-best-practices.pdf); [release notes](https://www.manageengine.com/products/self-service-password/release-notes.html)).
- **macOS:** 10.10–15 per the best-practices PDF; macOS 26 support added in 6527.
- **Linux:**
  - Ubuntu 16.x–20.04.4, Fedora 27–31 and CentOS 7 per the best-practices PDF.
  - RHEL and Rocky 8–9 since 6514; CentOS 8–9 MFA since 6527; SLES/SLED 12/15 and openSUSE Leap 15.6 MFA since 6528.
  - **On RHEL and Rocky the agent gives logon MFA only, not login-screen reset/unlock** ([best-practices PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-deployment-best-practices.pdf)).

**Agent deployment:** push from the admin portal (needs Domain Admin), GPO, SCCM, ManageEngine Endpoint Central, or manual install ([architecture PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-solution-architecture.pdf); [permissions PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-privileges-permissions-requirement-guide.pdf)).

### 2.3 DMZ / internet exposure
- **No dedicated edge or relay component.** The documented patterns are:
  1. Server in the LAN with firewall NAT of 443 → 9251.
  2. Server installed in the DMZ, with firewall holes to DCs and the database.
  3. A **reverse proxy** in the DMZ between two firewalls, using AD360, Apache HTTP Server or IIS.

  Sources: [internet-hosting PDF (2024)](https://download.manageengine.com/products/self-service-password/securely-deploy-adselfservice-plus-over-the-internet-for-remote-users.pdf); [architecture PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-solution-architecture.pdf).
- The "Secure Gateway" (reverse proxy) capability is part of the paid $395 add-on ([licensing FAQ](https://www.manageengine.com/products/self-service-password/licensing-faq.html)).
- **Gotcha:** changing the Access URL after FIDO passkeys are configured changes the RP ID. That causes "loss of enrollment data and disenrollment of all users" ([internet-hosting PDF](https://download.manageengine.com/products/self-service-password/securely-deploy-adselfservice-plus-over-the-internet-for-remote-users.pdf)).
- These portals are commonly internet-facing. That matters given the REST API and authentication-filter CVE history (§4).

### 2.4 HA and load balancing
- **Failover is active/standby.** One primary plus one or more standby nodes share a single external DB. Users reach the active node through a virtual IP (same subnet) or a virtual hostname (different subnets, since build 7000; DNS must be updated manually on failover). Failover service port is 7800. Initial setup needs a Domain Admin service account. All nodes must run the same build, be in the same domain, and share the installation folder ([HA guide PDF, June 2026](https://download.manageengine.com/products/self-service-password/adselfservice-plus-high-availability-configuration-guide.pdf)).
- **Load balancing** uses a primary node that round-robins requests to secondary nodes ([architecture PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-solution-architecture.pdf)). Automatic load-balancer failover between nodes arrived only in build 6527 (May 2026) ([release notes](https://www.manageengine.com/products/self-service-password/release-notes.html)).
- **Unresolved:** the HA guide cites a "product port (default 9854)", which does not match the 8888/9251 defaults elsewhere `[UNVERIFIED]`.

### 2.5 Ports (abridged)
Source: [requirements / ports](https://www.manageengine.com/products/self-service-password/help/admin-guide/requirements.html).

| Direction | Ports |
|---|---|
| Users, login agents, sync agents → ADSSP | 8888/TCP (HTTP), 9251/TCP (HTTPS); both configurable |
| ADSSP → DCs | 53, 88 (Kerberos), 135, 137–139, 389 (LDAP), 445, **464 (Kerberos password change, used for "Password reset")**, 636 (LDAPS), 3268/3269 (GC), **5985/5986 (WinRM / PowerShell remoting)**, 49152–65535 (RPC) |
| ADSSP ↔ ADSSP | 7800 (load-balanced/failover instances) |
| ADSSP → other | 1433/1434 (MS SQL); APNs 443/5223/2197; FCM 443/5228–5230; SMTP |

### 2.6 Required privileges and how resets reach AD
- **Vendor claim:** no Domain Admin needed for self-service. Least-privilege delegation per feature ([permissions PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-privileges-permissions-requirement-guide.pdf)):

  | Feature | Delegated rights |
  |---|---|
  | Reset | Reset password, plus Read/Write `pwdLastSet` |
  | Unlock | Read/Write `lockoutTime` |
  | Self-update | Read/Write on chosen attributes |
  | Show fine-grained policy | Read PSOs |
  | Mail-group subscription | Modify group membership |
  | AD sync | Replicate Directory Changes |
  | NTLMv2 SSO to the portal | Create/read computer objects |
  | Forced enrollment | Read/Write `scriptPath` |

- **Domain Admin is still required** for:
  - the deleted-users report;
  - pushing the login agent from the web console;
  - initial HA setup.
- **The vendor's own best-practices guide contradicts the least-privilege claim.** It says admins "must provide the credentials of a service account that possesses Domain Admin permissions," with least privilege as an opt-out ([best-practices PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-deployment-best-practices.pdf)). In practice many deployments likely run as Domain Admin `[UNVERIFIED]`.
- **Execution path:** the server performs reset and unlock against AD with the configured service account. For Entra ID it uses an Entra application ([starting ADSSP](https://www.manageengine.com/products/self-service-password/help/admin-guide/working.html)).
  - Ports and components point to LDAP/LDAPS writes (`lockoutTime`, `pwdLastSet`), Kerberos password change (464), and PowerShell remoting to DCs via WinRM / `RemoteExecM2.exe`.
  - LDAPS is optional ("Enable LDAP SSL").
  - An older, undated ManageEngine paper says ADSSP "calls for the Windows API responsible for password reset and passes your new password to it," and does not store the password ([password-reset process PDF](https://www.manageengine.cn/products/self-service-password/password-reset-process.pdf)). This is consistent with a Windows-only server.
  - The exact API used today (ADSI `SetPassword`, LDAP `unicodePwd` or PowerShell) is not documented publicly `[UNVERIFIED]`.
- **Credential and data storage** ([encryption KB](https://www.manageengine.com/products/self-service-password/kb/encryption-methods-and-data-storage-type-in-adselfservice-plus.html)):
  - DB encrypted with AES-256-CBC.
  - Service and integration credentials stored with AES-256.
  - **Security answers hashed with MD5 or SHA-512 (admin's choice).**
  - Password history: salted SHA-512.
  - "Users' domain credentials aren't stored."
  - Storage of TOTP seeds, FIDO credentials and phone numbers is not documented `[UNVERIFIED]`.
- **Backup gotcha:** the default password on DB backup files is "the reverse string of the filename" ([best-practices PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-deployment-best-practices.pdf)).

## 3. Complete feature inventory

**Edition column key**
- **Std**: Standard edition. **Pro**: Professional edition.
- **EMFA-Std / EMFA-Pro**: the separately licensed Endpoint MFA module, matched to the base edition (§1.2).
- **Basic / Adv**: basic or advanced authenticator. Advanced authenticators need Pro.

Edition mapping comes from the [licensing guide PDF (Jun 2026)](https://download.manageengine.com/products/self-service-password/how-adselfservice-plus-licensing-works.pdf) unless a row says otherwise. Where edition gating is not documented, the row says `[UNVERIFIED]`.

### 3.1 Self-service password reset (SSPR) & account unlock
| ID | Module | Feature | What it does | Edition/add-on | Source |
|---|---|---|---|---|---|
| ADSS-001 | SSPR | Web-portal password reset | Reset a forgotten AD password after MFA identity verification | Std+ | [LG](https://download.manageengine.com/products/self-service-password/how-adselfservice-plus-licensing-works.pdf) |
| ADSS-002 | SSPR | Web-portal account unlock | Unlock a locked AD account without resetting the password | Std+ (AD only) | [LG](https://download.manageengine.com/products/self-service-password/how-adselfservice-plus-licensing-works.pdf) |
| ADSS-003 | SSPR | Web-based password change | Change a known or expiring domain password, and enterprise-app passwords, from a browser (remote users) | Std+ `[UNVERIFIED]` | [datasheet](https://download.manageengine.com/products/self-service-password/ad-self-service-plus-data-sheet.pdf) |
| ADSS-004 | SSPR | Mobile-browser portal | Reset, unlock and change via the mobile web UI (`/m/home`) | Std+ | [LG](https://download.manageengine.com/products/self-service-password/how-adselfservice-plus-licensing-works.pdf); [startup doc](https://www.manageengine.com/products/self-service-password/help/admin-guide/working.html) |
| ADSS-005 | SSPR | Native iOS/Android app | Reset, unlock, change password and enroll from the app. App is free in all editions | Std+ | [LG](https://download.manageengine.com/products/self-service-password/how-adselfservice-plus-licensing-works.pdf); [mobile page](https://www.manageengine.com/mobile-apps/adselfservice-plus-mobile-app.html) |
| ADSS-006 | SSPR | Windows logon-screen reset/unlock | Reset-password and unlock-account options on the Windows logon screen via the credential provider (GINA/CP agent) | Pro | [LG](https://download.manageengine.com/products/self-service-password/how-adselfservice-plus-licensing-works.pdf) |
| ADSS-007 | SSPR | macOS logon-screen reset/unlock | Same, via the macOS login agent | Pro (AD-joined only) | [LG](https://download.manageengine.com/products/self-service-password/how-adselfservice-plus-licensing-works.pdf) |
| ADSS-008 | SSPR | Linux logon-screen reset/unlock | Same, via the Linux login agent. **Not available on RHEL/Rocky**, which get MFA only | Pro (AD-joined only) | [LG](https://download.manageengine.com/products/self-service-password/how-adselfservice-plus-licensing-works.pdf); [BP](https://download.manageengine.com/products/self-service-password/adselfservice-plus-deployment-best-practices.pdf) |
| ADSS-009 | SSPR / remote | Cached-credential update over VPN | After a logon-screen reset, the agent opens the VPN and refreshes the cached domain credential. Supported VPNs: Fortinet, Cisco IPSec/AnyConnect, Windows native, SonicWall, Check Point, OpenVPN, custom | Pro (AD only) | [cached-creds page](https://www.manageengine.com/products/self-service-password/update-windows-active-directory-cached-credentials.html) |
| ADSS-010 | SSPR / remote | Cached-credential update **without VPN** | Agent updates the local cache with the new password; no VPN tunnel needed. Windows only; no macOS equivalent documented | Pro (build 6503, 2024-08) | [RN](https://www.manageengine.com/products/self-service-password/release-notes.html); [cached-creds page](https://www.manageengine.com/products/self-service-password/update-windows-active-directory-cached-credentials.html) |
| ADSS-011 | SSPR | Microsoft Entra ID SSPR | SSPR and password change for Entra (cloud and hybrid) users from portal, mobile app and Windows login screen. Multi-group policies, versus Entra's single-group SSPR scoping | Build 7000 (2026-06); edition `[UNVERIFIED]` | [Entra SSPR page](https://www.manageengine.com/products/self-service-password/entra-id-sspr.html); [RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| ADSS-012 | SSPR | Separate authenticators for password reset | A distinct factor set for self-service password resets, separate from other actions | Build 6513 | [RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| ADSS-013 | SSPR security | Self-service rate limits | Cap resets per user per N days | `[UNVERIFIED]` | [BP](https://download.manageengine.com/products/self-service-password/adselfservice-plus-deployment-best-practices.pdf) |
| ADSS-014 | SSPR security | Block user after failed verification | Lock the user out of ADSSP after N failed identity-verification attempts within a time window. Extension to portal and enterprise apps `[UNVERIFIED]` | `[UNVERIFIED]` | [BP](https://download.manageengine.com/products/self-service-password/adselfservice-plus-deployment-best-practices.pdf); [RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| ADSS-015 | SSPR security | CAPTCHA, including audio | On admin and user login, reset and unlock pages; always or after N failures | `[UNVERIFIED]` | [BP](https://download.manageengine.com/products/self-service-password/adselfservice-plus-deployment-best-practices.pdf) |
| ADSS-016 | SSPR security | Anti-enumeration "mock MFA" | Shows fake MFA prompts for invalid usernames so valid accounts aren't revealed | `[UNVERIFIED]` | [BP](https://download.manageengine.com/products/self-service-password/adselfservice-plus-deployment-best-practices.pdf) |
| ADSS-017 | SSPR | Action notifications | Email, SMS or push to the user (and optionally the admin) on enroll, reset, change or unlock | `[UNVERIFIED]` | [BP](https://download.manageengine.com/products/self-service-password/adselfservice-plus-deployment-best-practices.pdf) |
| ADSS-018 | SSPR | Automatic account unlock | Attributed to 6407 in a secondary read of the release notes; not in the verbatim 6407 bullets I could see; trigger semantics undocumented | `[UNVERIFIED]` | [RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| ADSS-019 | SSPR | Site-based DC targeting | Map OUs to specific DCs so resets land on the user's local DC (avoids replication-lag logon failures) | `[UNVERIFIED]` | [scalability PDF](https://download.manageengine.com/products/self-service-password/self-service-password-reset-tool-with-scalability.pdf) |
| ADSS-020 | SSPR | Browser extension for reset | **No evidence found** in vendor feature lists or docs. Not confirmed absent | — | [features](https://www.manageengine.com/products/self-service-password/features.html) |

### 3.2 Enrollment
| ID | Module | Feature | What it does | Edition/add-on | Source |
|---|---|---|---|---|---|
| ADSS-021 | Enrollment | User self-enrollment | Users register authenticators via the web portal, mobile app or mobile web | Std+ | [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf) |
| ADSS-022 | Enrollment | Forced enrollment at Windows logon | Scheduler stamps a logon script (`ADSelfService_Enroll.hta`, placed in SYSVOL) on non-enrolled users. This shows a **non-closable** prompt that blocks the desktop until the user enrolls | `[UNVERIFIED]` | [ROI PDF](https://download.manageengine.com/products/self-service-password/maximizing-return-on-investment-on-password-self-service-using-enrollment.pdf); [force-enrollment help](https://www.manageengine.com/products/self-service-password/help/admin-guide/Configuration/Admin-Tools/Enrollment-Reminder-Steps.html) |
| ADSS-023 | Enrollment | Forced enrollment at portal login | Non-enrolled users must enroll when they sign into ADSSP | `[UNVERIFIED]` | [ROI PDF](https://download.manageengine.com/products/self-service-password/maximizing-return-on-investment-on-password-self-service-using-enrollment.pdf) |
| ADSS-024 | Enrollment | Enrollment reminders | Email or push to non-enrolled users, on demand or scheduled | `[UNVERIFIED]` | [BP](https://download.manageengine.com/products/self-service-password/adselfservice-plus-deployment-best-practices.pdf) |
| ADSS-025 | Enrollment | **Bulk import from CSV** | Pre-enroll **security Q&A** (`sAMAccountName`, questions, answers), **email**, **mobile** and **Duo** (`sAMAccountName` only). Supports overwrite and scheduled re-import | `[UNVERIFIED]` | [ROI PDF](https://download.manageengine.com/products/self-service-password/maximizing-return-on-investment-on-password-self-service-using-enrollment.pdf) |
| ADSS-026 | Enrollment | Bulk import from external DB | Pull enrollment data from MS SQL, PostgreSQL, Oracle or MySQL, with a scheduler for new users | `[UNVERIFIED]` | [ROI PDF](https://download.manageengine.com/products/self-service-password/maximizing-return-on-investment-on-password-self-service-using-enrollment.pdf) |
| ADSS-027 | Enrollment | Pre-populated profile data | Pulls existing AD attributes (e.g., mobile, mail) into enrollment. AD-attribute security questions need no user enrollment | `[UNVERIFIED]` | [SSPR page](https://www.manageengine.com/products/self-service-password/self-service-password-reset.html); [IV](https://www.manageengine.com/products/self-service-password/help/admin-guide/Configuration/Self-Service/Identity-Verification-Steps.html) |
| ADSS-028 | Enrollment | Enrollment reports and export | Enrolled / non-enrolled reports. Since 6527 the export lists each enrolled authenticator as its own column. Formats: CSV, PDF, XLS, HTML, CSVDE | Std+ `[UNVERIFIED]` | [RN](https://www.manageengine.com/products/self-service-password/release-notes.html); [reports page](https://www.manageengine.com/products/self-service-password/reports-and-email-notification.html) |
| ADSS-029 | Enrollment | MFA backup codes | Recovery codes for lost authenticators. Usage is tracked in the Backup Code Usage report | `[UNVERIFIED]` | [reports page](https://www.manageengine.com/products/self-service-password/reports-and-email-notification.html) |
| ADSS-030 | Enrollment | Mobile app push-deployment | Admin pushes the app to devices via a built-in MDM profile or an existing MDM | Std+ `[UNVERIFIED]` | [mobile deployment PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-mobile-app-deployment-guide.pdf) |

### 3.3 Identity-verification methods / authenticators
Count: the vendor's authenticator page lists **20 distinct methods** ([supported authenticators](https://www.manageengine.com/products/self-service-password/help/admin-guide/Configuration/Self-Service/supported-authenticators-for-mfa.html)). The identity-verification page lists **21**, because it splits Custom TOTP into hardware (basic) and software (advanced), for 8 basic + 13 advanced ([IV](https://www.manageengine.com/products/self-service-password/help/admin-guide/Configuration/Self-Service/Identity-Verification-Steps.html)). Marketing elsewhere says 17 (Entra comparison), 19 (SSO/conditional-access page) or "over 20" (datasheet).

| ID | Module | Feature | What it does | Edition/add-on | Source |
|---|---|---|---|---|---|
| ADSS-031 | Authenticator | Security questions & answers | Admin-defined and/or user-defined questions. Answers stored **one-way hashed (MD5 or SHA-512)** | Basic | [IV](https://www.manageengine.com/products/self-service-password/help/admin-guide/Configuration/Self-Service/Identity-Verification-Steps.html); [encryption KB](https://www.manageengine.com/products/self-service-password/kb/encryption-methods-and-data-storage-type-in-adselfservice-plus.html) |
| ADSS-032 | Authenticator | AD security questions | Verifies answers against AD attribute values (e.g., employee ID); no enrollment needed | Basic | [IV](https://www.manageengine.com/products/self-service-password/help/admin-guide/Configuration/Self-Service/Identity-Verification-Steps.html) |
| ADSS-033 | Authenticator | Email verification code | OTP to the enrolled or AD email address | Basic | [IV](https://www.manageengine.com/products/self-service-password/help/admin-guide/Configuration/Self-Service/Identity-Verification-Steps.html) |
| ADSS-034 | Authenticator | SMS verification code | OTP via the SMS add-on (Clickatell; not sold in the US) or the customer's own gateway | Basic | [IV](https://www.manageengine.com/products/self-service-password/help/admin-guide/Configuration/Self-Service/Identity-Verification-Steps.html); [FAQ](https://www.manageengine.com/products/self-service-password/licensing-faq.html) |
| ADSS-035 | Authenticator | Google Authenticator | TOTP; also usable for offline MFA | Basic | [IV](https://www.manageengine.com/products/self-service-password/help/admin-guide/Configuration/Self-Service/Identity-Verification-Steps.html); [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf) |
| ADSS-036 | Authenticator | Microsoft Authenticator | Used as a TOTP app; also usable for offline MFA | Basic | same |
| ADSS-037 | Authenticator | Zoho OneAuth TOTP | Zoho's authenticator app (TOTP); usable for offline MFA | Basic | same |
| ADSS-038 | Authenticator | Custom TOTP (hardware or software token) | Any RFC-TOTP token or app; usable for offline MFA | Hardware = Basic; software = Adv | [IV](https://www.manageengine.com/products/self-service-password/help/admin-guide/Configuration/Self-Service/Identity-Verification-Steps.html) |
| ADSS-039 | Authenticator | ADSSP app TOTP | TOTP generated in the ADSSP mobile app | Adv | same |
| ADSS-040 | Authenticator | Push notification | Approve/deny in the ADSSP mobile app (APNs/FCM) | Adv | same |
| ADSS-041 | Authenticator | Biometric | Fingerprint or face on the phone via the ADSSP app. Android face added in 6502 | Adv | same; [RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| ADSS-042 | Authenticator | QR-code authentication | Scan a QR code with the ADSSP app | Adv | [IV](https://www.manageengine.com/products/self-service-password/help/admin-guide/Configuration/Self-Service/Identity-Verification-Steps.html) |
| ADSS-043 | Authenticator | **FIDO2 passkeys** | WebAuthn. Platform authenticators (Windows Hello, Touch ID/Face ID) and roaming keys (YubiKey, Titan). Public keys stored in the ADSSP DB and bound to the Access-URL RP ID | Adv (6403; OS logons in 6517) | [FIDO2 PDF](https://download.manageengine.com/products/self-service-password/fido2-authentication-with-adselfservice-plus.pdf); [RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| ADSS-044 | Authenticator | YubiKey Authenticator | YubiKey OTP. The OTP vs. FIDO mode split is not clearly documented `[UNVERIFIED]` | Adv | [IV](https://www.manageengine.com/products/self-service-password/help/admin-guide/Configuration/Self-Service/Identity-Verification-Steps.html) |
| ADSS-045 | Authenticator | Smart card / PIV | Certificate-based authentication. USB smart cards (YubiKey/PIV) since 6513. Not supported on macOS/Linux | Adv | [IV](https://www.manageengine.com/products/self-service-password/help/admin-guide/Configuration/Self-Service/Identity-Verification-Steps.html); [RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| ADSS-046 | Authenticator | Duo Security | Duo Universal Prompt as a factor | Adv | [IV](https://www.manageengine.com/products/self-service-password/help/admin-guide/Configuration/Self-Service/Identity-Verification-Steps.html); [3rd-party PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-third-party-apps-list.pdf) |
| ADSS-047 | Authenticator | RSA SecurID | Via the RSA REST API (since 6404), configurable per policy | Adv | [RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| ADSS-048 | Authenticator | RADIUS authentication | Delegates a factor to any RADIUS OTP server | Adv | [IV](https://www.manageengine.com/products/self-service-password/help/admin-guide/Configuration/Self-Service/Identity-Verification-Steps.html) |
| ADSS-049 | Authenticator | Microsoft Entra ID MFA | Uses Entra (Azure AD) MFA as a factor | Adv | same |
| ADSS-050 | Authenticator | SAML authentication | Uses an external IdP (Okta, OneLogin, 1Kosmos and others) as a factor | Adv | [help-desk page](https://www.manageengine.com/products/self-service-password/help-desk-assisted-password-self-service.html); [RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| ADSS-051 | MFA policy | Factor policy | Per policy: number of factors, mandatory factors (asterisk), order. Separate factor sets per surface (reset, machine, VPN, OWA, apps, portal) | Std+ (Adv factors need Pro) | [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf) |
| ADSS-052 | MFA policy | Trusted browsers / machines | Remember-device state, with reports | `[UNVERIFIED]` | [reports page](https://www.manageengine.com/products/self-service-password/reports-and-email-notification.html) |
| ADSS-053 | MFA policy | TOTP replay hardening | 7001 fixed "TOTP code replay weaknesses" (security fix). Earlier reuse-prevention feature `[UNVERIFIED]` | Build 7001 | [RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |

### 3.4 Endpoint MFA (machine logons)
| ID | Module | Feature | What it does | Edition/add-on | Source |
|---|---|---|---|---|---|
| ADSS-054 | Endpoint MFA | Windows workstation logon MFA | MFA in the credential provider after the password | EMFA-Std | [LG](https://download.manageengine.com/products/self-service-password/how-adselfservice-plus-licensing-works.pdf) |
| ADSS-055 | Endpoint MFA | Windows Server logon MFA | Same, for servers | EMFA-Pro (AD only) | same |
| ADSS-056 | Endpoint MFA | macOS logon MFA | Login-agent MFA on macOS | EMFA-Std (AD only) | same |
| ADSS-057 | Endpoint MFA | Linux logon MFA | Ubuntu, Fedora, CentOS 7–9, RHEL/Rocky 8–9, SLES/SLED 12/15, openSUSE 15.6 | EMFA-Std (AD only) | [BP](https://download.manageengine.com/products/self-service-password/adselfservice-plus-deployment-best-practices.pdf); [RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| ADSS-058 | Endpoint MFA | RDP MFA (server and client side) | MFA on incoming RDP to agent hosts and/or outgoing `mstsc` connections | EMFA-Pro | [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf) |
| ADSS-059 | Endpoint MFA | UAC elevation MFA | MFA on UAC credential prompts | EMFA-Pro | same |
| ADSS-060 | Endpoint MFA | Workstation unlock MFA | MFA when unlocking a locked Windows session | `[UNVERIFIED]` | same |
| ADSS-061 | Endpoint MFA | **Offline MFA** | MFA with no server connectivity. Windows (except 1803) and macOS. TOTP factors (Google/Microsoft/Zoho/custom); FIDO2 for offline macOS since 6517. Not for RDP client authentication | Pro + EMFA-Pro | [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf); [RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| ADSS-062 | Endpoint MFA | Machine-based (device-based) MFA | Enforce MFA for *all* users of selected machines; licensed per user | EMFA-Pro | [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf); [FAQ](https://www.manageengine.com/products/self-service-password/licensing-faq.html) |
| ADSS-063 | Endpoint MFA | Local / workgroup user MFA | MFA for non-domain local accounts (logon, unlock, UAC, RDP) | Build 6516; EMFA `[UNVERIFIED edition]` | [WN](https://www.manageengine.com/products/self-service-password/whats-new.html); [RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| ADSS-064 | Endpoint MFA | FIDO2 passkeys at OS logon | Passkeys as a factor on Windows, macOS and Linux logons | Build 6517 | [RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| ADSS-065 | Endpoint MFA | Entra-joined / hybrid-joined Windows MFA | Endpoint MFA for Entra identities | Build 7000 | [Entra MFA page](https://www.manageengine.com/products/self-service-password/entra-id-mfa.html) |
| ADSS-066 | Endpoint MFA | Conditional access on endpoint/RDP logons | **Not documented for machine logons; a narrow RDP case is.** The machine-based MFA help says only: "To protect these connections, configure a conditional access rule with IP restrictions" and that sentence concerns RD Gateway connections over public IPs. The conditional-access page describes rules for self-service policies, not endpoint logons, and lists four conditions (IP, device, business hours, geolocation). The public roadmap lists "Conditional access support for RDP and endpoint logins" as *in pipeline*. The marketing claim of endpoint coverage is therefore **not supported by the docs as of 2026-10-02** (not proof of absence in the product) | `[UNVERIFIED]` (Pro per ADSS-087) | [machine-based MFA help](https://www.manageengine.com/products/self-service-password/help/admin-guide/Configuration/Admin-Tools/GINA/machine-based-mfa.html); [CA page](https://www.manageengine.com/products/self-service-password/conditional-access-policy.html); [WN](https://www.manageengine.com/products/self-service-password/whats-new.html) (checked 2026-10-02) |
| ADSS-067 | Endpoint MFA | Passwordless OS logon; MFA for non-GUI consoles; agentless MFA | **Roadmap "in pipeline"**, not shipped | — | [WN](https://www.manageengine.com/products/self-service-password/whats-new.html) |

### 3.5 VPN / RADIUS and OWA / IIS MFA
| ID | Module | Feature | What it does | Edition/add-on | Source |
|---|---|---|---|---|---|
| ADSS-068 | VPN MFA | RADIUS MFA via NPS extension | Second factor for any RADIUS VPN. Named: Fortinet, Cisco IPSec/AnyConnect, Windows native, SonicWall, Pulse, Check Point, OpenVPN AS, Palo Alto, Juniper. **Requires a Windows NPS server** | EMFA-Pro (AD only) | [VPN page](https://www.manageengine.com/products/self-service-password/multi-factor-authentication-for-secured-vpn.html); [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf) |
| ADSS-069 | VPN MFA | Two prompt modes | (a) VPN-client challenge: TOTP/YubiKey/OneAuth, or one-way push/biometric. (b) "SecureLink" email link: any authenticator, including FIDO2 and smart card. "Any authenticator for VPN" since 6513 | EMFA-Pro | same; [RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| ADSS-070 | VPN MFA | Conditional access for VPN; RADIUS response attributes | Context rules on VPN logons; return RADIUS attributes | Build 6407 | [RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| ADSS-071 | OWA MFA | OWA & Exchange Admin Center MFA | IIS module on the Exchange server adds MFA after password auth. SAML authenticator not supported here | EMFA-Pro (AD only) | [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf); [LG](https://download.manageengine.com/products/self-service-password/how-adselfservice-plus-licensing-works.pdf) |
| ADSS-072 | IIS MFA | MFA for other IIS-based apps | Same connector pattern for IIS-hosted apps | EMFA | [FAQ](https://www.manageengine.com/products/self-service-password/licensing-faq.html) |

### 3.6 SSO, federation & provisioning
| ID | Module | Feature | What it does | Edition/add-on | Source |
|---|---|---|---|---|---|
| ADSS-073 | SSO | SAML 2.0 IdP | IdP- and SP-initiated SSO with AD (or, since 7000, Entra) credentials | EMFA-Std ("SSO for applications") | [SAML page](https://www.manageengine.com/products/self-service-password/saml-sso-integration-active-directory.html); [LG](https://download.manageengine.com/products/self-service-password/how-adselfservice-plus-licensing-works.pdf) |
| ADSS-074 | SSO | OAuth 2.0 / OIDC | SSO to OAuth/OIDC apps; custom endpoints configurable. PKCE since 6518 | EMFA-Std | [OIDC page](https://www.manageengine.com/products/self-service-password/oauth-oidc-single-sign-on-sso.html); [RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| ADSS-075 | SSO | Pre-integrated app catalog | "Out-of-the-box SSO support for more than 100 enterprise applications" (e.g., M365, Google Workspace, Salesforce, ServiceNow, Zendesk, Dropbox, Slack, Workday) | EMFA-Std | [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf); [mobile page](https://www.manageengine.com/mobile-apps/adselfservice-plus-mobile-app.html) |
| ADSS-076 | SSO | Custom apps | Any SAML/OAuth/OIDC app with attribute mapping | EMFA-Std | [SSO page](https://www.manageengine.com/products/self-service-password/enterprise-sso-solution.html) |
| ADSS-077 | SSO | Bookmark apps | Non-SSO apps appear as tiles in the user portal (link to the app's login page). Added in 6513 | EMFA-Std `[UNVERIFIED]` | [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf) |
| ADSS-078 | SSO | MFA for app logins | MFA on SP-initiated access to SSO apps | EMFA-Std | [LG](https://download.manageengine.com/products/self-service-password/how-adselfservice-plus-licensing-works.pdf) |
| ADSS-079 | SSO | Passwordless login (portal and SSO apps) | Username plus MFA factors only; first use needs a password | EMFA-Pro | [passwordless page](https://www.manageengine.com/products/self-service-password/passwordless-authentication.html); [LG](https://download.manageengine.com/products/self-service-password/how-adselfservice-plus-licensing-works.pdf) |
| ADSS-080 | SSO | Adaptive SSO | Conditional-access-driven SSO decisions | EMFA-Pro | [LG](https://download.manageengine.com/products/self-service-password/how-adselfservice-plus-licensing-works.pdf) |
| ADSS-081 | Provisioning | JIT provisioning via SCIM | Creates the app account on first SSO login (e.g., Slack). "More than 10" apps; per-app license-consumption cap. Full SCIM lifecycle (update/deprovision) not documented `[UNVERIFIED]` | EMFA (build 6405) | [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf); [JIT page](https://www.manageengine.com/products/self-service-password/just-in-time-provisioning.html) |
| ADSS-082 | SSO | Windows integrated (NTLMv2) SSO to the portal | Domain-joined users reach the ADSSP portal without re-auth. Conditional access can allow or block it | `[UNVERIFIED]` | [permissions PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-privileges-permissions-requirement-guide.pdf); [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf) |
| ADSS-083 | SSO | SSO into ManageEngine apps | Into Endpoint Central, ADAudit Plus, PAM360 and others (AD360 suite) | Build 6407 | [RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| ADSS-084 | Federation | External IdP | 1Kosmos supported as IdP for SSO and SAML MFA | Build 6515 | [RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| ADSS-085 | SSO | Entra ID SSO | Issues SAML/OIDC tokens for Entra identities | Build 7000 | [Entra SSO page](https://www.manageengine.com/products/self-service-password/entra-id-sso.html) |
| ADSS-086 | SSO | WS-Federation | **Not mentioned** on any SSO page reviewed. Not confirmed absent | — | [SSO page](https://www.manageengine.com/products/self-service-password/enterprise-sso-solution.html) |
| ADSS-137 | SSO | Auto-launch SSO apps at login | Opens assigned SSO apps automatically when the user signs in | Build 6513 | [RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| ADSS-138 | SSO | Multi-valued SAML attribute assertions | Passes multi-valued AD attributes (e.g., group lists) in SAML assertions | Build 6513 | [RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |

### 3.7 Conditional access
| ID | Module | Feature | What it does | Edition/add-on | Source |
|---|---|---|---|---|---|
| ADSS-087 | Conditional access | Conditions | IP (trusted/untrusted), device type, business hours, geolocation, combined with AND/OR/NOT expressions (e.g., `1 AND (2 OR 3)`) | Pro | [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf); [LG](https://download.manageengine.com/products/self-service-password/how-adselfservice-plus-licensing-works.pdf) |
| ADSS-088 | Conditional access | Outcomes | When a rule matches, a *self-service policy* is assigned (features plus authenticators: full, MFA-required, limited or restricted access). Can allow/block NTLM SSO and portal access. Applies to SSPR, SSO and password sync; VPN since 6407 | Pro | [CA page](https://www.manageengine.com/products/self-service-password/conditional-access-policy.html); [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf) |
| ADSS-089 | Conditional access | Risk/UBA signals, device trust | **Roadmap "in pipeline"**: "UBA adoption for conditional access", "Device trust verification" | — | [WN](https://www.manageengine.com/products/self-service-password/whats-new.html) |
| ADSS-090 | Conditional access | Read-only view of other admins' CA policies | Cross-admin visibility | Build 6527 | [RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |

### 3.8 Password & account expiry notifications
| ID | Module | Feature | What it does | Edition/add-on | Source |
|---|---|---|---|---|---|
| ADSS-091 | Notifications | Password-expiry reminders | Email, SMS and/or push. Daily, weekly or specific-day schedules (e.g., 15/10/7/3/1 days). Scoped by domain, OU or group | Std+ (AD only) | [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf); [notifier page](https://www.manageengine.com/products/self-service-password/password-expiration-notifier.html) |
| ADSS-092 | Notifications | Account-expiry reminders | Same channels, for AD account expiration | Std+ (AD only) | [notifier page](https://www.manageengine.com/products/self-service-password/password-expiration-notifier.html) |
| ADSS-093 | Notifications | Manager notifications | Notify reporting managers of their reports' upcoming expirations | `[UNVERIFIED]` | same |
| ADSS-094 | Notifications | Template customization | HTML body, logos, macros, attachments ≤25 MB, priority flag; per-channel character limits | `[UNVERIFIED]` | [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf) |
| ADSS-095 | Notifications | Free email expiry notifications | Vendor: "Send Active Directory password expiration notification emails to all users in your organization at no cost" | Free (vendor claim) | [notifier page](https://www.manageengine.com/products/self-service-password/password-expiration-notifier.html) |
| ADSS-096 | Notifications | Delivery reporting | Notification delivery reports and logs | `[UNVERIFIED]` | [reports page](https://www.manageengine.com/products/self-service-password/reports-and-email-notification.html) |

### 3.9 Password Policy Enforcer
| ID | Module | Feature | What it does | Edition/add-on | Source |
|---|---|---|---|---|---|
| ADSS-097 | Password policy | Custom complexity rules | Special/numeric/Unicode counts, unique characters, min/max length, block specific characters, block embedding of AD attributes (display name, email, department, custom) | Std+ | [PPE page](https://www.manageengine.com/products/self-service-password/password-policy-enforcer.html); [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf) |
| ADSS-098 | Password policy | Pattern/dictionary rules | Keyboard sequences, dictionary words (built-in plus custom list), palindromes, consecutive repeats, substrings of the username or old password, **regex** | Std+ | same |
| ADSS-099 | Password policy | Passphrase override and "N of M" | Waive complexity above a set length (e.g., 20 characters); require compliance with N of M rules | Std+ | [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf) |
| ADSS-100 | Password policy | Breached-password ban (Have I Been Pwned) | Checks every reset/change against HIBP (outbound to `api.pwnedpasswords.com`), including logon-screen agent and ADUC resets via the sync agent. **No offline/on-prem breach corpus documented** | `[UNVERIFIED]` | [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf); [BP](https://download.manageengine.com/products/self-service-password/adselfservice-plus-deployment-best-practices.pdf) |
| ADSS-101 | Password policy | Enforcement on native changes | Applies the policy to Ctrl+Alt+Del changes and ADUC resets via the Password Sync Agent on every DC | Pro (AD only) | [LG](https://download.manageengine.com/products/self-service-password/how-adselfservice-plus-licensing-works.pdf); [ARCH](https://download.manageengine.com/products/self-service-password/adselfservice-plus-solution-architecture.pdf) |
| ADSS-102 | Password policy | Live strength meter and rule display | Real-time pass/fail per rule on reset/change screens | Std+ | [PPE page](https://www.manageengine.com/products/self-service-password/password-policy-enforcer.html) |
| ADSS-103 | Password policy | Policy scoping | Per domain, OU or group; Entra ID enforcement since 7000. Also shows AD fine-grained policy requirements (needs read access to PSOs) | Std+ | [PPE page](https://www.manageengine.com/products/self-service-password/password-policy-enforcer.html); [WN](https://www.manageengine.com/products/self-service-password/whats-new.html); [permissions PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-privileges-permissions-requirement-guide.pdf) |
| ADSS-104 | Password policy | Technician password policy | Advanced policy for product-authenticated admins | `[UNVERIFIED]` | [BP](https://download.manageengine.com/products/self-service-password/adselfservice-plus-deployment-best-practices.pdf) |

### 3.10 Password synchronization
| ID | Module | Feature | What it does | Edition/add-on | Source |
|---|---|---|---|---|---|
| ADSS-105 | Password sync | Real-time sync to cloud apps | Google Workspace, Microsoft 365/Entra (OAuth client credentials since 6505; China tenants since 6515), Salesforce, Zendesk, Dynamics CRM, Zoho, ServiceNow | Std+ | [password sync page](https://www.manageengine.com/products/self-service-password/active-directory-password-synchronizer.html); [RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| ADSS-106 | Password sync | Real-time sync to on-prem systems | IBM i/AS400, Oracle EBS, Oracle DB, HP-UX, OpenLDAP, AD LDS, SAP NetWeaver, 389 DS, MS SQL, PostgreSQL; ADFS is also named | Std+ | [password sync page](https://www.manageengine.com/products/self-service-password/active-directory-password-synchronizer.html); [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf) |
| ADSS-107 | Password sync | AD-to-AD sync across untrusted domains | Same password across multiple AD domains | `[UNVERIFIED]` | [scalability PDF](https://download.manageengine.com/products/self-service-password/self-service-password-reset-tool-with-scalability.pdf) |
| ADSS-108 | Password sync | Native-change capture | The Password Sync Agent on every DC captures Ctrl+Alt+Del and ADUC changes and sends them encrypted over HTTPS. **Consumes licenses** | Std+ (agent) | [ARCH](https://download.manageengine.com/products/self-service-password/adselfservice-plus-solution-architecture.pdf); [LG](https://download.manageengine.com/products/self-service-password/how-adselfservice-plus-licensing-works.pdf) |
| ADSS-109 | Password sync | Account linking | Map AD accounts to app accounts by attribute (automatic) or manually | Std+ | [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf) |

### 3.11 Directory self-service
| ID | Module | Feature | What it does | Edition/add-on | Source |
|---|---|---|---|---|---|
| ADSS-110 | Self-update | Profile self-update | Drag-and-drop layouts over general and custom AD attributes (phone, address, title, photo…), per policy | Std+ (AD only) | [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf); [LG](https://download.manageengine.com/products/self-service-password/how-adselfservice-plus-licensing-works.pdf) |
| ADSS-111 | Self-update | Modification rules | Auto-populate dependent attributes from user-entered values | Std+ | [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf) |
| ADSS-112 | Directory | Employee search | Search users, contacts and groups with configurable columns and criteria. Can be exposed on the login page; hardening guidance recommends hiding it | Std+ | [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf); [hardening](https://www.manageengine.com/products/self-service-password/help/admin-guide/Configuration/Admin-Tools/Security-Center/security-hardening.html) |
| ADSS-113 | Directory | Org chart | Hierarchy view from manager/direct reports | Std+ | [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf) |
| ADSS-114 | Groups | Group self-subscription | Join or leave **distribution and security** groups per policy; optional member visibility; optional MFA gate | Std+ (AD only) | [groups page](https://www.manageengine.com/products/self-service-password/self-service-ad-mail-group-subscription.html) |
| ADSS-115 | Workflow | Approval workflow | Routes reset, unlock, self-update and group requests for approval. **Requires a separate ADManager Plus install**, which hosts the workflow engine | Needs ADManager Plus | [help-desk PDF](https://download.manageengine.com/products/self-service-password/helpdesk-assisted-password-self-service-with-adselfservice-plus.pdf); [help-desk page](https://www.manageengine.com/products/self-service-password/help-desk-assisted-password-self-service.html) |

### 3.12 Help desk, reporting & audit
| ID | Module | Feature | What it does | Edition/add-on | Source |
|---|---|---|---|---|---|
| ADSS-116 | Help desk | Help-desk-assisted reset/unlock | User answers AD-attribute questions → request goes to ADManager Plus → reviewer sees auto-validated answers → on approval, a reset link goes to the user's **secondary email**. No help-desk caller-verification console (e.g., push a code to the caller's phone) found in ADSSP itself `[UNVERIFIED]` | Needs ADManager Plus | [help-desk PDF](https://download.manageengine.com/products/self-service-password/helpdesk-assisted-password-self-service-with-adselfservice-plus.pdf) |
| ADSS-117 | ITSM | ServiceDesk Plus (on-prem and Cloud) tickets | Auto-creates tickets for self-service actions; SSO into SDP Cloud | `[UNVERIFIED]` | [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf); [RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| ADSS-118 | Reports | AD reports | Locked-out users, soon-to-expire passwords, expired passwords | All editions `[UNVERIFIED]` | [reports page](https://www.manageengine.com/products/self-service-password/reports-and-email-notification.html) |
| ADSS-119 | Reports | Self-service audit | Reset and unlock (web and agent), self-update, change password, notification delivery, blocked users | All editions `[UNVERIFIED]` | same |
| ADSS-120 | Reports | MFA reports | 13 named reports: enrolled, non-enrolled, enrollment audit, usage, machines/VPN/OWA usage, mobile usage, failures, trusted browsers, trusted machines, security questions, backup codes, offline-MFA machines, FIDO passkeys | All editions `[UNVERIFIED]` | same |
| ADSS-121 | Reports | Agent and app/license reports | Agent installed/failed; user attempts; licensed users; push-registered devices; application access; JIT provisioning audit | All editions `[UNVERIFIED]` | same |
| ADSS-122 | Reports | Export and schedule | CSV, PDF, XLS, HTML, CSVDE; scheduled email delivery; password-protected exports (6504) | All editions `[UNVERIFIED]` | same; [RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| ADSS-123 | SIEM | Log forwarding | Splunk HTTP Event Collector and Syslog (selectable standard and format) | `[UNVERIFIED]` | [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf) |

### 3.13 Administration, branding & platform
| ID | Module | Feature | What it does | Edition/add-on | Source |
|---|---|---|---|---|---|
| ADSS-124 | Admin | Policy engine | Self-service policies by domain, OU or group define features, authenticators and agent behavior, with precedence order. A default policy is created per discovered domain | All editions `[UNVERIFIED]` | [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf); [BP](https://download.manageengine.com/products/self-service-password/adselfservice-plus-deployment-best-practices.pdf) |
| ADSS-125 | Admin | Technician delegation | **Two roles: Super Admin and Operator**, with toggleable permissions; AD or product authentication. **Custom roles are on the roadmap** | All editions `[UNVERIFIED]` | [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf); [WN](https://www.manageengine.com/products/self-service-password/whats-new.html) |
| ADSS-126 | Admin security | Admin-portal controls | MFA for ADSSP logins, admin login hidden or IP-restricted, session timeout, deny concurrent logins | `[UNVERIFIED]` | [BP](https://download.manageengine.com/products/self-service-password/adselfservice-plus-deployment-best-practices.pdf) |
| ADSS-127 | Admin security | Security Hardening console | 12 checks: HTTPS, TLS 1.2, ciphers, keystore encryption, default-password change, LDAPS, hide search/org chart from login page, mail TLS, mobile SSL pinning, backup password, agent SSL enforcement, security-update registration | All editions `[UNVERIFIED]` | [hardening](https://www.manageengine.com/products/self-service-password/help/admin-guide/Configuration/Admin-Tools/Security-Center/security-hardening.html) |
| ADSS-128 | Platform | HA failover / load balancing / reverse proxy | See §2.4 | $395 add-on | [HA PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-high-availability-configuration-guide.pdf) |
| ADSS-129 | Platform | Backup, server and DB migration | Scheduled DB backups; server-migration utility; DB migration (GUI tool since 6527); MS SQL clustering support. The migration KB: `backupDB.bat` writes a compressed `OfflineBackup_<timestamp>.ezip`; copy the whole `\conf` folder (it holds the DB encryption password); restore needs the **exact same version and build**; the backup password is the reversed filename or an admin-set one (Admin > Product Settings > Security and Privacy). **The KB does not mention exporting enrollment data (TOTP seeds, security answers).** | All editions `[UNVERIFIED]` | [BP](https://download.manageengine.com/products/self-service-password/adselfservice-plus-deployment-best-practices.pdf); [scalability PDF](https://download.manageengine.com/products/self-service-password/self-service-password-reset-tool-with-scalability.pdf); [RN](https://www.manageengine.com/products/self-service-password/release-notes.html); [migration KB](https://www.manageengine.com/self-service-password/kb/adself-service-installation-server-migration.html) (checked 2026-10-02) |
| ADSS-130 | Platform | Dashboard and schedulers | Dashboard refreshed by schedulers (AD sync, locked-out, soon-to-expire, expired) | All editions `[UNVERIFIED]` | [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf) |
| ADSS-131 | Platform | Product-health alerts | License-expiry, downtime and update alerts (email/SMS); SSL-expiry alerts since 6527 | All editions `[UNVERIFIED]` | [BP](https://download.manageengine.com/products/self-service-password/adselfservice-plus-deployment-best-practices.pdf); [RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| ADSS-132 | Agents | Login-agent deployment and customization | Push from the console, GPO, SCCM, Endpoint Central or manual. GINA/Mac/Linux customization, e.g., restricting the agent when the SSL certificate is invalid | Pro (logon-screen features) | [ARCH](https://download.manageengine.com/products/self-service-password/adselfservice-plus-solution-architecture.pdf); [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf) |
| ADSS-133 | Branding | Portal rebranding | Theme color, logo (200×50), browser title and icon, login background, text and order of the login buttons | `[UNVERIFIED]`. Paraphrasing one reviewer: branding and advanced MFA methods need higher-tier licensing ([SourceForge](https://sourceforge.net/software/product/ADSelfService-Plus/)) | [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf) |
| ADSS-134 | Localization | Languages | **19 display languages** per the vendor's list: Finnish, Polish, Italian, Canadian French, German, Japanese, Brazilian Portuguese, Swedish, Russian, Danish, Chinese, French, Norwegian, British English, Arabic, Spanish, Turkish, Dutch, Hebrew. Set under Admin > Customize > Personalize. The page does not say separately whether this covers the end-user portal, mobile app and agent UI `[UNVERIFIED]` | — | [supported languages](https://www.manageengine.com/products/self-service-password/supported-languages.html) (checked 2026-10-02) |
| ADSS-135 | Integrations | Integration tiles | ADManager Plus (workflow), ServiceDesk Plus / SDP Cloud, Splunk, Syslog, HIBP. Mail via Microsoft/Google APIs (6522) | — | [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf); [RN](https://www.manageengine.com/products/self-service-password/release-notes.html) |
| ADSS-136 | API | REST API | Internal REST APIs exist; they are the subject of CVE-2021-40539 and CVE-2026-75791. **"REST API support" is on the public roadmap as in pipeline**, implying no supported, documented customer API today `[UNVERIFIED]` | — | [WN](https://www.manageengine.com/products/self-service-password/whats-new.html); [CVE-2026-75791](https://www.manageengine.com/products/self-service-password/advisory/CVE-2026-75791.html) |

**Inventory gaps** (updated in T-0001, 2026-10-02):
- Resolved: **SMS gateways.** The vendor's gateway page names three methods, GSM modem, Clickatell (built-in) and a custom gateway over HTTP or SMTP, and lists "40+" compatible providers such as Avea, Yakoon, ValueFirst, SMSGlobal, MessageMedia, RouteSMS, Zain and SMSCountry ([SMS gateway integration](https://www.manageengine.com/products/self-service-password/adselfserviceplus-sms-gateway-integration.html)). A vendor forum post documents HTTP gateways such as Twilio via the "Custom" provider ([community post, snippet only](https://pitstop.manageengine.com/portal/en/community/topic/did-you-know-how-to-configure-custom-sms-provider-in-adselfservice-plus)). So a US customer can bring Twilio-style HTTP gateways; no named Twilio built-in.
- Resolved: **languages** (ADSS-134): 19 display languages.
- `[TODO]` exact list of the 100+ catalog apps. The vendor's SSO page gives no count and says only "a wide range of commonly used enterprise applications"; it names SAML, OAuth and OIDC ([SSO page](https://www.manageengine.com/products/self-service-password/enterprise-sso-solution.html), 2026-10-02). The "100+" figure comes from search-engine text, not that page. Needs the in-product catalogue.
- `[TODO]` exact list of the 10+ JIT/SCIM apps: same page gives no count.
- `[TODO]` per-feature Free-edition limits. The Free edition is 50 users (§1 table). The pricing page says it has "limitations" without listing them ([pricing](https://www.manageengine.com/products/self-service-password/pricing-details.html), 2026-10-02).

## 4. Security track record (ADSSP-specific summary; full ManageEngine CVE history is covered elsewhere)

**Headline numbers**
- NVD keyword search "ADSelfService Plus" returns **57 CVEs** (queried 2026-10-02) ([NVD API](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=ADSelfService%20Plus)).
- By year: 2019: 10; 2020: 4; 2021: 15; 2022: 7; 2023: 5; 2024: 1; 2025: 1; **2026 (to date): 7**.
- **3 are in CISA KEV** (catalog version 2026.10.01): CVE-2021-40539, CVE-2022-28810 and CVE-2022-47966 ([CISA KEV feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)).
- 2024–2026 scores below are from Zoho's own CNA unless noted.

| CVE | CVSS | Issue | Fixed build (date) | KEV / exploitation | Source |
|---|---|---|---|---|---|
| CVE-2021-40539 | 9.8 | REST API auth bypass → RCE | 6114 (2021-09) | **KEV 2021-11-03.** Zero-day exploited from Aug 2021 (APT27/TG-3390 per Unit 42; DEV-0322 per Microsoft). Attackers stole `NTDS.dit` | [CISA AA21-259A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-259a); [Unit 42](https://unit42.paloaltonetworks.com/manageengine-godzilla-nglite-kdcsponge/); [Microsoft](https://www.microsoft.com/en-us/security/blog/2021/11/08/threat-actor-dev-0322-exploiting-zoho-manageengine-adselfservice-plus/) |
| CVE-2022-28810 | 6.8 | Admin "custom script" feature → OS command execution as SYSTEM | 6122 (2022-04) | **KEV 2023-03-07**; abuse seen by Rapid7 | [Rapid7](https://www.rapid7.com/blog/post/2022/04/14/cve-2022-28810-manageengine-adselfservice-plus-authenticated-command-execution-fixed/) |
| CVE-2022-47966 | 9.8 | Pre-auth RCE via outdated Apache Santuario (only if SAML SSO was ever configured) | 6211 (2022-10) | **KEV 2023-01-23** (multi-product). Known ransomware use per KEV | [ME advisory](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) |
| CVE-2024-0252 | 8.8 (NVD) | Authenticated RCE in load-balancer/cluster APIs | 6402 (2024-01-10) | No | [ME advisory](https://www.manageengine.com/products/self-service-password/advisory/CVE-2024-0252.html) |
| CVE-2025-1723 | 8.1 | Account takeover via session mishandling | 6511 (2025-02-26) | No | [ME advisory](https://www.manageengine.com/products/self-service-password/advisory/CVE-2025-1723.html) |
| CVE-2025-3833 | — | SQL injection | 6514 (2025-04-22) | No | [ME advisories](https://www.manageengine.com/products/self-service-password/advisory/index.html) |
| CVE-2025-11250 | 9.1 | **Unauthenticated auth bypass** ("improper filter configurations") | 6519 (2025-10-01); CVE published 2026-01-13 | No | [ME advisory](https://www.manageengine.com/products/self-service-password/advisory/CVE-2025-11250.html) |
| CVE-2026-1367 | 8.3 | SQL injection in Reports (technician auth) | 6523 (2026-01-25) | No | [ME advisory](https://www.manageengine.com/products/self-service-password/advisory/CVE-2026-1367.html) |
| CVE-2026-3183 | 7.1 | Broken authentication / MFA bypass | 6524 (2026-01-31); CVE published 2026-07-21 | No | [ME advisory](https://www.manageengine.com/products/self-service-password/advisory/CVE-2026-3183.html) |
| CVE-2026-2740 | 8.4 | Authenticated RCE on login-agent machines (third-party dependency) | 6525 (2026-02-05) | No | [ME advisory](https://www.manageengine.com/products/self-service-password/advisory/CVE-2026-2740.html) |
| CVE-2026-11374 | 9.0 | Predictable SSO tickets → account takeover (AD360-integrated SSO) | 6529 (2026-06-03) | No | [ME advisory](https://www.manageengine.com/products/self-service-password/advisory/CVE-2026-11374.html) |
| CVE-2026-74849 | 9.8 (CNA); vendor label "High" | **RCE as SYSTEM from the Windows logon screen** via the GINA client's embedded browser; needs physical access | 7001 (2026-08-24) | No | [ME advisory](https://www.manageengine.com/products/self-service-password/advisory/CVE-2026-74849.html) |
| CVE-2026-75791 | 8.6 | **REST API authorization bypass** (unauthenticated access to admin-restricted operations) | 7001 (2026-08-24) | No | [ME advisory](https://www.manageengine.com/products/self-service-password/advisory/CVE-2026-75791.html) |

**Patterns relevant to positioning**
1. **REST API and authentication-filter bypasses recur five years apart:** CVE-2021-40539 (2021), CVE-2025-11250 (2025), CVE-2026-75791 (2026). This is a password-reset portal that customers routinely put on the internet (§2.3). CISA's 2021 advisory urged customers to "ensure the application is not directly exposed to the internet" ([AA21-259A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-259a)). That advice is in tension with remote SSPR, which is the product's main use case.
2. **The logon-screen agent is a repeated attack surface.** Examples: CVE-2026-2740, CVE-2026-74849, and the earlier CVE-2023-35719 (GINA reset-portal bypass). The vendor disputed 35719 rather than patching it ([ME response](https://www.manageengine.com/products/self-service-password/kb/our-response-to-CVE-2023-35719.html)).
3. **MFA and session-logic flaws in a product sold as MFA:** CVE-2025-1723, CVE-2026-3183 and CVE-2026-11374. Build 6521 also fixed an endpoint MFA bypass without assigning a CVE ([release notes](https://www.manageengine.com/products/self-service-password/release-notes.html)).
4. **CVE publication lags the fix by months** (about 3.5 months for 11250; about 6 months for 3183, per the NVD publish dates above). Customers who patch from CVE feeds rather than service-pack notices see these late.
5. **Vendor response has improved.** There is now a "Security Hardening" console (HTTPS, TLS ≥1.2, default-password change, LDAPS, mobile SSL pinning) ([help](https://www.manageengine.com/products/self-service-password/help/admin-guide/Configuration/Admin-Tools/Security-Center/security-hardening.html)). After CVE-2022-28810, script entry was removed from the web UI. Most 2025–2026 findings came through Zoho's bug bounty.
6. **Insecure defaults remain:**
   - admin/admin default login ([starting ADSSP](https://www.manageengine.com/products/self-service-password/help/admin-guide/working.html));
   - HTTP 8888 by default;
   - backup-file password defaults to the reversed filename ([best-practices PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-deployment-best-practices.pdf));
   - a legacy Struts 1 web tier (§2.1).
7. No 2024–2026 ADSSP CVE is in KEV, and I found no public reports of in-the-wild exploitation of them. That is not proof that none occurred.

## 5. UX notes

### 5.1 Ratings snapshot (checked 2026-10-02)
| Site | Rating | # ratings | Notes / source |
|---|---|---|---|
| Capterra | 4.6/5; ease of use 4.6; support 4.5 | 63 | Verified. Reviews cluster in 2018 and Jun–Sep 2026, possibly vendor review campaigns (inference) ([Capterra](https://www.capterra.com/p/172556/ADSelfService-Plus/reviews/)) |
| Gartner Peer Insights | 4.5 | 34 | Page returns 403 to our fetcher; re-confirmed on 2026-10-02 from a search snippet that also shows 50% five-star, 38% four-star, 12% three-star (and a comparison table that rounds to 4.4) `[UNVERIFIED: snippet]` ([Gartner](https://www.gartner.com/reviews/product/manageengine-adselfservice-plus)) |
| G2 | 4.5 | 32 | Wayback snapshot 2026-08-03 per the customer-voice file §1; the earlier snippet (4.4 from 18) is superseded ([WB](https://web.archive.org/web/20260803114027/https://www.g2.com/products/manageengine-adselfservice-plus/reviews)) |
| PeerSpot | 4.2; 90% recommend | 9 | ([PeerSpot](https://www.peerspot.com/products/manageengine-adselfservice-plus-reviews)) |
| **iOS App Store (US)** | **2.1/5** | 75 | Verified; v1.7.6 (Jun 17) ([App Store](https://apps.apple.com/us/app/manageengine-adselfserviceplus/id731391592)) |
| Google Play | 3.0/5 | ~1.5K | Snippet only `[UNVERIFIED]` |

**Takeaway:** admin-facing web reviews are positive, driven by ticket reduction and price. The **end-user mobile app is rated poorly**, and end users are the population activeDIQ must win over.

### 5.2 End-user experience
- **Enrollment burden is the core friction.** ManageEngine itself says "Getting end users to enroll … is not an easy task" ([ROI PDF](https://download.manageengine.com/products/self-service-password/maximizing-return-on-investment-on-password-self-service-using-enrollment.pdf)).
  - The vendor's main lever is a **non-closable HTA logon-script popup that blocks the desktop** until the user enrolls (same source). That is coercive UX, and it depends on `mshta`, a binary many security teams restrict (inference).
  - Forum and review reports:
    - users forget security answers (older reviews, [Capterra](https://www.capterra.com/p/172556/ADSelfService-Plus/reviews/));
    - half of one company not enrolled ([forum](https://pitstop.manageengine.com/portal/en/community/topic/force-enrolment));
    - a 14-character backup code with spaces ([forum](https://pitstop.manageengine.com/portal/en/community/topic/mfa-backup-code-usability)).
- **Mobile app.** App Store reviews: "Slow & no watch support" (Sep 8), "so slow, everything takes forever to load" (2023), "Buggy Inconsistent" (2020) ([App Store](https://apps.apple.com/us/app/manageengine-adselfserviceplus/id731391592)).
  - iOS push breaks when the push certificate bundled with the *server* expires. The vendor recommends upgrading "at least once every six months" ([vendor FAQ](https://pitstop.manageengine.com/portal/en/kb/articles/faq-on-the-adselfservice-plus-mobile-app)).
  - Most 2024–2026 app releases are only "performance enhancements" ([mobile release notes](https://www.manageengine.com/products/self-service-password/mobile-release-notes.html)).
- **Logon-screen agent.**
  - Praised for reset at the login screen ("End users can easily reset forgotten passwords or unlock their own accounts in seconds directly from their Windows, macOS, or Linux login screens", Gerald M. S., Sep 2026, [Software Advice](https://www.softwareadvice.com/mobility/manageengine-adselfservice-plus-profile/reviews/)).
  - Reliability threads: on M1 Macs, "after a few days of working correctly it will stop asking for MFA requests and allow the user to sign straight into their machine" until the agent is reinstalled. That is a silent fail-open, from a single forum report ([forum](https://pitstop.manageengine.com/portal/en/community/topic/mfa-not-showing-on-m1-macbook-airs)). Another thread reports the reset link missing for RDP clients ([forum](https://pitstop.manageengine.com/portal/en/community/topic/gina-doesnt-work-on-win-8-and-win10-computers-that-connect-to-virtual-servers-running-the-gina-client)).
  - The Windows agent renders the reset flow in an **embedded browser** at the logon screen, which was the root of CVE-2026-74849 ([advisory](https://www.manageengine.com/products/self-service-password/advisory/CVE-2026-74849.html)).
- **Portal look and feel.**
  - "Customizing the visual design of the end-user self-service portal and specific notification templates can feel somewhat rigid" (Gerald M. S., 2026-09-21, [Capterra](https://www.capterra.com/p/172556/ADSelfService-Plus/reviews/)).
  - Branding is limited to theme color, logo, background and button labels ([EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf)).

### 5.3 Admin experience
- **Dated, hard-to-navigate console** (2026 Capterra reviews, [link](https://www.capterra.com/p/172556/ADSelfService-Plus/reviews/)):
  - "The interface feels dated, and some configuration settings are not always intuitive or easy to find" (Dalton B., 2026-08-28).
  - "buggy and hard to find what you are looking for" (Landon S., 2026-06-23).
- **Forum:** "the layout and design of Self Service seems to have been neglected quite significantly" ([pitstop](https://pitstop.manageengine.com/portal/en/community/topic/adselfservice-plus-ui-design)).
- **The stack explains it.** The web tier is Struts 1, Ember 2.18 and Bootstrap 3 (§2.1).
- **Deep, split navigation (information architecture).** Settings live under two top-level trees, "Configuration" and "Admin", with paths like:
  - `Configuration > Administrative Tools > GINA/Mac/Linux (Ctrl+Alt+Del) > GINA/Mac/Linux Installation > Installed Machines` (machine MFA enforcement);
  - `Admin > Customize > Logon Settings` (CAPTCHA, enumeration protection);
  - `Admin > Product Settings > Connection` (SSL).

  Sources: [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf); [BP](https://download.manageengine.com/products/self-service-password/adselfservice-plus-deployment-best-practices.pdf).
- **Feature setup is a chain of prerequisites.** MFA for endpoints, VPN and OWA needs:
  1. HTTPS enabled;
  2. the Access URL set;
  3. a Windows NPS server plus a PowerShell-installed extension (VPN);
  4. an IIS module installed by PowerShell on Exchange (OWA);
  5. login agents pushed with Domain Admin rights.

  Reviewers echo this: "At times, the initial setup and configuration can be complex, especially when integrating MFA, SSO, and multiple applications" (Shyam A., Jun 2026, [Software Advice](https://www.softwareadvice.com/mobility/manageengine-adselfservice-plus-profile/reviews/)).
- **Hardening is manual.** The post-deployment guide has admins edit Tomcat `server.xml` for ciphers and add security headers and HttpOnly cookies ([post-deployment PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-post-deployment-security-measures.pdf)). Shipping defaults are admin/admin and HTTP 8888 ([startup doc](https://www.manageengine.com/products/self-service-password/help/admin-guide/working.html)).
- **Upgrades:**
  - Sequential service packs (6500 → 6529 → 7000 → 7001) ([service packs](https://www.manageengine.com/products/self-service-password/service-pack.html)).
  - "a tad hard to update, especially when using it to help secure a VPN" (Jacob M., 2026-09-15, [Capterra](https://www.capterra.com/p/172556/ADSelfService-Plus/reviews/)).
  - Regression example: SSO to M365/Entra looped after build 6528 ([forum](https://pitstop.manageengine.com/portal/en/community/topic/build-version-6528-issues-with-sso)).
- **Support and docs are mixed.** "The support articles can be somewhat difficult to find" (Torie F., 2026-08-27, [Capterra](https://www.capterra.com/p/172556/ADSelfService-Plus/reviews/)). Older reviews call support slow.
- **Shallow analytics.** "We need more reports for visualization for top management to understand the IT background" (2022-12-05, [PeerSpot](https://www.peerspot.com/products/manageengine-adselfservice-plus-reviews)). Another PeerSpot reviewer: "The product is not user friendly compared to other solutions on the market" (2023-02-13). Reviewers also want more detail when diagnosing lockouts. ADSSP's reports are list exports; no lockout root-cause tooling is documented ([account unlock page](https://www.manageengine.com/products/self-service-password/self-service-account-unlock.html)).

### 5.4 What reviewers praise (what activeDIQ must not regress)
- Help-desk ticket reduction from self-service reset/unlock. One reviewer claims it "eliminates up to 80% of routine helpdesk tickets" (Gerald M., 2026-09-21, [Capterra UK](https://www.capterra.co.uk/software/172556/adselfservice-plus)).
- Logon-screen reset.
- Breadth of MFA methods.
- Price/value ("It was very budget friendly compared to other products", Landon, 2026-06-23, [Capterra UK](https://www.capterra.co.uk/software/172556/adselfservice-plus)).
- Easy initial install (older reviews).

## 6. Release velocity

**Cadence and numbering**
- 2024: 19 builds (6402–6509). 2025: 13 builds (6510–6522). 2026 to Oct 2: 9 builds (6523–7001). That is roughly one build every 3–4 weeks. Major feature drops come about 1–3 times a year.
- **9 of 41 builds since Jan 2024 were security-driven.**
- Numbering: 64xx = v6.4, 65xx = v6.5, 70xx = v7.0.
- Upgrades must step through major builds in order: 6400–6410 → 6500 → 6529 → 7000 → 7001 ([service packs](https://www.manageengine.com/products/self-service-password/service-pack.html)).
- Primary source for everything below: [release notes](https://www.manageengine.com/products/self-service-password/release-notes.html). Roadmap source: [what's new](https://www.manageengine.com/products/self-service-password/whats-new.html).
- Verification level: 7001, 7000, 6528, 6527, 6521, 6517, 6513, 6509, 6503 and 6407 were re-checked against verbatim release-note bullets. The other rows are summaries of the same page; re-check wording before quoting in an RFP.

| Build | Date | Notable changes |
|---|---|---|
| **7001** | 2026-08-21 | Security build with 9 fixes: login-agent RCE, SAML SSO bypass, path traversal, TOTP replay, REST API auth bypass and others (CVE-2026-74849, CVE-2026-75791). **32-bit support discontinued; TLS 1.0/1.1 removed** |
| **7000** | 2026-06-13 | **Microsoft Entra ID support:** SSPR, MFA with 16+ authenticators, SSO, password sync, conditional access, Password Policy Enforcer. Failover across multiple subnets |
| 6529 | 2026-06-03 | Security: CVE-2026-11374 |
| 6528 | 2026-05-26 | MFA for SUSE (SLES/SLED 12/15, openSUSE Leap 15.6); Tomcat 9.0.118 |
| 6527 | 2026-05-01 | Automatic load-balancer failover; GUI DB-migration tool; SSL-expiry alerts; macOS 26; CentOS 8–9 MFA. **Enrolled Users report export now lists each enrolled authenticator as a column** |
| 6525 / 6524 / 6523 | 2026-02-07 / 01-31 / 01-24 | Security fixes: CVE-2026-2740, CVE-2026-3183, CVE-2026-1367. 6523 also added Windows Server 2025 support. The advisory pages list 02-05 and 01-25 for 6525 and 6523 |
| 6522 | 2025-12-20 | Send mail via Microsoft and Google Mail APIs; Duo SDK 1.3.1 |
| 6521 | 2025-12-12 | Endpoint-MFA bypass fix (no CVE); performance under load |
| 6519 | 2025-10-01 | Security: CVE-2025-11250 (critical) |
| 6518 | 2025-09-24 | PKCE for OAuth flows; hardening |
| **6517** | 2025-07-21 | **FIDO2 passkeys for Windows, macOS (including offline) and Linux machine logins** |
| **6516** | 2025-06-24 | **MFA for Windows local/workgroup users** (logon, unlock, UAC, RDP) |
| 6515 | 2025-05-29 | 1Kosmos as external IdP for SSO and SAML MFA; Entra password sync for China tenants |
| 6514 | 2025-04-22 | MFA for RHEL/Rocky 8–9; security fix CVE-2025-3833 |
| **6513** | 2025-04-03 | Smart-card/PIV via USB (YubiKey/PIV); any authenticator for VPN MFA; separate authenticators for self-service resets; per-policy MFA enforcement on protected Windows resources; auto-launch SSO apps at login; multi-valued SAML attributes; **Bookmark apps** |
| 6511 | 2025-02-26 | Security: CVE-2025-1723 |
| 6509 | 2024-11-15 | Windows login agent on ARM64 |
| 6505 | 2024-10-15 | M365/Entra and Dynamics password sync via OAuth client credentials |
| 6504 | 2024-10-09 | ServiceDesk Plus Cloud integration; password-protected report exports |
| **6503** | 2024-08-05 | **Cached-credential update on Windows without VPN** |
| 6502 | 2024-07-12 | Android face biometrics; Duo Web SDK v4 |
| 6500 | 2024-06-14 | v6.5 base: PostgreSQL 14, Tomcat, JRE and JDBC updates |
| **6407** | 2024-04-16 | "Fourteen new reports"; SSO into ManageEngine apps; RADIUS response attributes; conditional access for MFA-protected VPN; SMS enrollment notifications; granular notification control; admin alerts on unsuccessful access attempts. Automatic account unlock is also attributed to 6407 `[UNVERIFIED]` |
| **6405** | 2024-03-08 | **JIT provisioning (SCIM) for SSO apps** |
| 6404 | 2024-02-19 | RSA SecurID via REST API, per policy |
| **6403** | 2024-02-12 | **FIDO2 passkeys** (Windows Hello, Face ID/Touch ID, YubiKey, Titan) for web MFA |
| 6402 | 2024-01-10 | Security: CVE-2024-0252 |

**Strategic direction**
- The product is moving from SSPR tool toward a lightweight workforce IdP: JIT/SCIM, external IdP federation, PKCE, Entra ID as a managed directory.
- Passwordless and phishing-resistant: FIDO2 on web, then on OS logon, plus PIV.
- Endpoint breadth: local users, ARM64, more Linux distros, VPN-less cached credentials.

**Public roadmap, "In pipeline"** ([what's new](https://www.manageengine.com/products/self-service-password/whats-new.html)):
- UBA for conditional access
- MFA for non-GUI consoles
- Passwordless login for endpoints
- **Custom role creation**
- Conditional access for RDP and endpoint logins
- Device trust verification
- SSO mobile-app enhancements
- **Agentless MFA**
- **REST API support**
- Endpoint MFA API performance
- Security hardening
- Tomcat and PostgreSQL upgrades

What the roadmap implies is missing today (inference, not confirmed absence): custom admin roles, device trust, endpoint conditional access, and a broad public REST API.

**Mobile apps:**
- iOS 1.7.6 (2026-06-17) and Android 1.8.2 (2026-06-14) added Entra ID reset/change and enrollment in up to 15 authenticators.
- Most other 2024–2026 mobile releases are listed only as "performance enhancements" ([mobile release notes](https://www.manageengine.com/products/self-service-password/mobile-release-notes.html)).

**AI and UI:**
- I found no AI/assistant feature in ADSSP for 2024–2026 `[UNVERIFIED]` absence.
- No admin-UI redesign appears in 2024–2026 release notes.
- The UI stack is still Struts 1 / Ember 2.18 / Bootstrap 3 (§2.1).

## 7. Weaknesses & gaps

| # | Weakness | Evidence | Why it matters for activeDIQ |
|---|---|---|---|
| W1 | **Customer-hosted Windows/Java monolith; no vendor-hosted SaaS found** | Windows Server host, Tomcat, bundled PostgreSQL; marketplace listings are still customer-run ([download](https://www.manageengine.com/products/self-service-password/download.html); [ARCH](https://download.manageengine.com/products/self-service-password/adselfservice-plus-solution-architecture.pdf)) | The customer owns patching, HA, certificates and DB. 9 of 41 builds since 2024 were security-driven (§6) |
| W2 | **Legacy web stack** | Struts 1.3.11 (Struts 1 is EOL per Apache), Ember 2.18, Bootstrap 3.4.1, jquery-migrate 1.4.1, lodash 3.5.0 as of build 7000 ([3rd-party PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-third-party-apps-list.pdf); [Apache](https://struts.apache.org/struts1eol-announcement.html)) | Root cause of the "dated UI" complaints and a security-debt signal. A full UI rewrite is a large effort for them |
| W3 | **Recurring critical vulnerabilities in an internet-facing portal** | REST API/auth-filter bypasses in 2021, 2025 and 2026; MFA bypasses; login-agent RCE as SYSTEM; 3 KEV entries (§4) | Security-led buyers (CISO) can be won on architecture: no inbound exposure, modern stack |
| W4 | **Licensing complexity** | Separate Endpoint MFA SKU, which also carries SSO and JIT; edition matching; Professional needed for phishing-resistant factors; Password Sync Agent consumes licenses; over-limit endpoint MFA **fails open**; SMS add-on not sold in the US; HA is a paid add-on (§1.4) | One simple SKU with fail-closed behavior is a clean wedge. RFP language: "no feature-gated phishing-resistant MFA" |
| W5 | **HA is heavy** | Active/standby only; external DB required; same domain; shared installation folder; Domain Admin for setup; manual DNS update across subnets; automatic load-balancer failover only since May 2026 ([HA PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-high-availability-configuration-guide.pdf); [RN](https://www.manageengine.com/products/self-service-password/release-notes.html)) | Multi-region active/active (SaaS) is a clear differentiator |
| W6 | **Privilege posture** | Vendor guide tells admins to supply a Domain Admin service account. DA is required for agent push, HA setup and the deleted-users report ([BP](https://download.manageengine.com/products/self-service-password/adselfservice-plus-deployment-best-practices.pdf); [permissions PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-privileges-permissions-requirement-guide.pdf)) | Ship a least-privilege delegation wizard/script and never ask for DA |
| W7 | **Thin admin RBAC** | Only Super Admin and Operator roles; "Custom role creation" is in the roadmap pipeline ([EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf); [WN](https://www.manageengine.com/products/self-service-password/whats-new.html)) | Large enterprises need delegated, OU-scoped admin |
| W8 | **No supported public REST API** | "REST API support" is listed as in pipeline ([WN](https://www.manageengine.com/products/self-service-password/whats-new.html)) `[UNVERIFIED]` that none exists | API-first plus webhooks enables ITSM and automation use cases |
| W9 | **Approvals and help-desk verification depend on a second product** | Approval workflow and help-desk-assisted reset require ADManager Plus ([help-desk PDF](https://download.manageengine.com/products/self-service-password/helpdesk-assisted-password-self-service-with-adselfservice-plus.pdf)) | activeDIQ can offer this natively in one product. Customers on both ME products will expect parity |
| W10 | **Endpoint coverage gaps** | Not available today:<br>• login-screen reset on RHEL/Rocky<br>• passwordless OS logon (roadmap)<br>• MFA for non-GUI consoles such as SSH/TTY (roadmap; inference that SSH is uncovered)<br>• smart card on macOS/Linux<br>• cached-credential update without VPN on macOS (not documented)<br>Offline MFA is limited to TOTP, plus FIDO2 on macOS ([BP](https://download.manageengine.com/products/self-service-password/adselfservice-plus-deployment-best-practices.pdf); [WN](https://www.manageengine.com/products/self-service-password/whats-new.html); [EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf)) | Concrete leapfrog targets (§8c) |
| W11 | **VPN MFA requires Windows NPS** | "the VPN server should use a Windows Network Policy Server (NPS) to configure RADIUS authentication, and the ADSelfService Plus NPS extension has to be installed in the NPS" ([ARCH](https://download.manageengine.com/products/self-service-password/adselfservice-plus-solution-architecture.pdf)) | A built-in RADIUS service (or cloud RADIUS) removes a Windows server dependency |
| W12 | **Conditional access is static** | IP, device type, business hours and geolocation only. UBA/risk signals and device trust are roadmap items. CA for endpoint/RDP logons is claimed on marketing pages but listed as in pipeline (conflict) ([EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf); [WN](https://www.manageengine.com/products/self-service-password/whats-new.html); [CA page](https://www.manageengine.com/products/self-service-password/conditional-access-policy.html)) | Risk-based step-up and device posture are differentiators |
| W13 | **Breached-password check is online-only** | HIBP integration needs outbound access to `api.pwnedpasswords.com`; no offline corpus documented ([EG](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf)) | Air-gapped and regulated customers need a local corpus; also offers cracked-hash detection |
| W14 | **Poor mobile app** | iOS 2.1/5 (75 ratings); slowness; no watch support; push breaks when the server's bundled APNs certificate expires ([App Store](https://apps.apple.com/us/app/manageengine-adselfserviceplus/id731391592); [vendor FAQ](https://pitstop.manageengine.com/portal/en/kb/articles/faq-on-the-adselfservice-plus-mobile-app)) | End users notice this immediately; easy UX win |
| W15 | **Enrollment UX** | Coercive HTA popup that blocks the desktop; CSV import limited to Q&A, email, SMS and Duo; changing the Access URL disenrolls all FIDO users ([ROI PDF](https://download.manageengine.com/products/self-service-password/maximizing-return-on-investment-on-password-self-service-using-enrollment.pdf); [internet-hosting PDF](https://download.manageengine.com/products/self-service-password/securely-deploy-adselfservice-plus-over-the-internet-for-remote-users.pdf)) | Also defines activeDIQ's migration problem (§8a) |
| W16 | **Reporting is list-based** | Report catalog is exports and schedules; reviewers want visualization and lockout diagnosis; no lockout root-cause tooling documented ([reports page](https://www.manageengine.com/products/self-service-password/reports-and-email-notification.html); [PeerSpot](https://www.peerspot.com/products/manageengine-adselfservice-plus-reviews)) | Lockout analytics is a visible help-desk win |
| W17 | **Insecure defaults; manual hardening** | admin/admin; HTTP 8888; backup password is the reversed filename; employee search can be exposed on the login page; cipher and header hardening done by editing `server.xml` ([startup doc](https://www.manageengine.com/products/self-service-password/help/admin-guide/working.html); [BP](https://download.manageengine.com/products/self-service-password/adselfservice-plus-deployment-best-practices.pdf); [hardening](https://www.manageengine.com/products/self-service-password/help/admin-guide/Configuration/Admin-Tools/Security-Center/security-hardening.html); [post-deployment PDF](https://download.manageengine.com/products/self-service-password/adselfservice-plus-post-deployment-security-measures.pdf)) | "Secure by default" is a credible RFP claim against this |
| W18 | **Load sensitivity** | Vendor advises staggering expiry notifications because 1,000 simultaneous password changes "could negatively impact user performance" ([scalability PDF, 2023](https://download.manageengine.com/products/self-service-password/self-service-password-reset-tool-with-scalability.pdf)) | Elastic scaling is a differentiator for 10k+ user tenants |
| W19 | **Entra ID support is new and partial** | Arrived in build 7000 (June 2026). Many features are still "(AD only)"; the Entra MFA integration mechanism is not documented ([LG](https://download.manageengine.com/products/self-service-password/how-adselfservice-plus-licensing-works.pdf); [Entra MFA page](https://www.manageengine.com/products/self-service-password/entra-id-mfa.html)) | Hybrid AD and Entra customers are the core market. Native hybrid coverage on day one matters |
| W20 | **Disclosure lag and upgrade friction** | CVEs published 3.5–6 months after fixes; sequential service-pack upgrades; SSO regression after 6528 (§4, §5.3) | Continuous delivery plus transparent advisories |

## 8. Parity vs leapfrog

### 8a. Table stakes for a switching ADSSP customer
Priority key: **P0** = must exist at cutover for the pilot accounts; **P1** = needed within the first renewal cycle. Feature IDs refer to §3.

| Capability | ADSSP reference | Priority | Notes |
|---|---|---|---|
| SSPR and unlock on web and mobile web | ADSS-001–004 | P0 | Core ticket-reduction value that reviewers praise |
| Windows logon-screen reset/unlock, plus cached-credential update with and without VPN | ADSS-006, 009, 010 | P0 | Remote workforce; the most-praised end-user feature |
| macOS and Linux logon-screen reset/unlock | ADSS-007, 008 | P1 | Needed for mixed fleets |
| Authenticators the installed base actually uses: TOTP apps (Microsoft/Google/custom), email/SMS OTP, push and biometric (own app), FIDO2/passkeys, AD-attribute questions, Duo, RSA, RADIUS, Entra MFA, smart card/PIV | ADSS-031–050 | P0 for the top 6; P1 for the rest | Survey each target account for its enabled authenticators before building the long tail |
| Endpoint MFA on Windows: logon, unlock, UAC, RDP server/client, offline | ADSS-054–061 | P0 | Endpoint MFA is a separate paid ADSSP SKU, so customers who bought it rely on it |
| Endpoint MFA on macOS/Linux; local-account MFA | ADSS-056, 057, 063 | P1 | |
| VPN (RADIUS) MFA and OWA/IIS MFA | ADSS-068–072 | P0 for VPN, P1 for OWA | Exchange on-prem OWA is declining; VPN is still critical |
| SAML/OIDC SSO with the top apps (M365, Google Workspace, Salesforce, ServiceNow, Zendesk, Slack, Workday), custom apps and MFA on SP-initiated logins | ADSS-073–078 | P1 | The catalog depth claim is "100+" |
| Password Policy Enforcer, including Ctrl+Alt+Del/ADUC enforcement (DC agent) and a breached-password ban | ADSS-097–103 | P0 | Compliance-driven (NIST 800-63B). Needs a DC-side password filter |
| Password and account expiry notifications (email/SMS/push, multi-interval, manager notice) | ADSS-091–094 | P0 | Cheap to build. The free email version makes this a hygiene feature |
| Password sync to M365/Entra and Google Workspace, capturing native changes | ADSS-105, 108 | P1 | The long-tail targets are deferrable (see 8b) |
| Directory self-update, employee search/org chart, group self-subscription with approvals | ADSS-110–115 | P1 | activeDIQ's AD-management core makes approvals native |
| Reports (enrollment, audit, MFA usage) and Syslog/Splunk forwarding | ADSS-118–123 | P0 | Auditors ask for these during migration |
| HA | ADSS-128 | P0 | SaaS control plane plus redundant connectors |
| **Enrollment migration tooling** | — | **P0** | See the analysis below. It is the decisive switching cost |

**Re-enrollment burden: what can and cannot be carried over from ADSSP**

| Enrollment data | Where it lives | Exportable? | Migration approach |
|---|---|---|---|
| Email / mobile number for OTP | ADSSP DB and/or AD `mail`/`mobile` | **Likely yes.** The Enrolled Users report "includes details such as users' email addresses, mobile numbers" ([reports page](https://www.manageengine.com/products/self-service-password/reports-and-email-notification.html)), and export columns list each user's authenticators since 6527 ([RN](https://www.manageengine.com/products/self-service-password/release-notes.html)) | Import the CSV export and AD attributes. Zero user effort |
| AD-attribute security questions | AD | N/A (no enrollment) | Recreate as configuration. Zero user effort |
| Duo, RSA SecurID, RADIUS OTP, Entra MFA, external SAML IdP | Third-party systems | N/A (enrollment held externally) | Map by `sAMAccountName`/UPN. Zero user effort |
| Smart card / PIV | Customer PKI | N/A | Configure trust anchors. Zero user effort |
| Hardware TOTP tokens | ADSSP DB; the customer may still hold the vendor seed files | DB export not documented `[UNVERIFIED]` | Re-import the original seed files if retained; otherwise re-enroll |
| Software TOTP (Microsoft/Google/Zoho/custom apps) | ADSSP DB | **Not documented** `[UNVERIFIED]`; seed storage is undocumented ([encryption KB](https://www.manageengine.com/products/self-service-password/kb/encryption-methods-and-data-storage-type-in-adselfservice-plus.html)) | Assume re-enrollment. Use progressive enrollment (see below) |
| Security Q&A answers | ADSSP DB, **one-way hashed (MD5 or SHA-512)** ([encryption KB](https://www.manageengine.com/products/self-service-password/kb/encryption-methods-and-data-storage-type-in-adselfservice-plus.html); [password-reset process PDF](https://www.manageengine.cn/products/self-service-password/password-reset-process.pdf)) | **Plaintext: no.** Questions and possibly hashes may be exportable. The vendor says its Security Questions Report lists questions "and answers"; given the hashing, that likely means hashes or masked values `[UNVERIFIED]` | (1) Re-enroll; or (2) **hash-compatible import** if the algorithm, salting and normalization can be confirmed `[UNVERIFIED]`; or (3) retire knowledge-based answers for stronger factors. NIST SP 800-63B §5.1.1.2 says verifiers "SHALL NOT prompt subscribers to use specific types of information (e.g., 'What was the name of your first pet?')" ([NIST](https://pages.nist.gov/800-63-3/sp800-63b.html)), which strengthens option 3 |
| FIDO2 passkeys | ADSSP DB (public key and credential ID), **bound to the ADSSP Access-URL RP ID** ([FIDO2 PDF](https://download.manageengine.com/products/self-service-password/fido2-authentication-with-adselfservice-plus.pdf); [internet-hosting PDF](https://download.manageengine.com/products/self-service-password/securely-deploy-adselfservice-plus-over-the-internet-for-remote-users.pdf)) | Export not documented `[UNVERIFIED]` | Possible carry-over only if activeDIQ serves the same RP ID and the public keys can be extracted from the DB (inference). Otherwise re-register; this is cheap for users with platform authenticators |
| Push, biometric, QR, ADSSP-app TOTP | ADSSP mobile app plus DB | No (app-bound) | Re-enroll in the activeDIQ app. Bundle with app rollout via MDM |

**Implications**
- Roughly half of the enrollment surface can migrate with zero user effort: email/SMS, AD questions, Duo/RSA/RADIUS/Entra/SAML, PIV. The hard part is app-based factors and Q&A.
- **Mitigation playbook**
  1. **Coexistence by OU.** Run activeDIQ alongside ADSSP and migrate OU by OU.
  2. **Bootstrap with migrated email/SMS plus AD-attribute questions** on day one, so no user is stranded.
  3. **Progressive enrollment.** Prompt for a passkey or app enrollment at the next successful login, rather than ADSSP-style blocking popups.
  4. **Bulk Graph import** of Entra-registered phone methods where customers use Entra MFA `[UNVERIFIED feasibility per tenant]`.
- **Biggest open question:** whether the ADSSP DB (bundled PostgreSQL, readable by the customer's DBA) exposes TOTP seeds and FIDO public keys in a decryptable form. This needs a lab install of build 7001 `[TODO]`.

### 8b. Deferrable (post-pilot / long tail)
- Long-tail password-sync targets: IBM i/AS400, HP-UX, SAP NetWeaver, Oracle EBS, AD LDS, 389 DS, ADFS (ADSS-106).
- Zoho OneAuth TOTP specifically. Generic TOTP covers it.
- QR-code authentication (ADSS-042) and Entra-MFA-as-a-factor (ADSS-049), unless the target account uses them.
- Bookmark tiles (ADSS-077); CSVDE export; built-in MDM app push (ADSS-030); ServiceDesk Plus integration (ADSS-117), unless the customer uses SDP.
- SSO into ManageEngine apps (ADSS-083). Only relevant while customers keep other ME tools.
- OWA/Exchange Admin Center MFA (ADSS-071) for customers already on Exchange Online.
- Windows Vista/7/8 and Server 2008 login-agent support (ADSSP still lists them, [BP](https://download.manageengine.com/products/self-service-password/adselfservice-plus-deployment-best-practices.pdf)).

### 8c. Leapfrog opportunities
| # | Opportunity | ADSSP gap it exploits | Reasoning |
|---|---|---|---|
| L1 | **SaaS control plane with outbound-only on-prem connectors** (no inbound DMZ/portal exposure); automatic updates | W1, W3, W5, W20 | Removes the internet-exposed portal pattern behind ADSSP's worst CVEs. Also removes sequential service packs and "upgrade every six months to keep push working" |
| L2 | **Low-touch migration kit** (§8a): CSV/report importers, AD-attribute bootstrap, external-factor mapping, optional hash-compatible Q&A import, passkey carry-over research, coexistence routing | W15 | Directly attacks the switching cost the CEO's accounts will raise first |
| L3 | **Consumer-grade end-user UX**: accessible (WCAG 2.1 AA), localized, enrollment in the logon agent itself, wearables, number-matching push | W2, W14, W15 | End users rate ADSSP's app 2.1/5; admins call the UI dated (§5) |
| L4 | **Task-based admin console**: global search, guided setup that checks prerequisites (HTTPS, NPS, IIS), and a policy simulator ("what will user X see on VPN from IP Y?") | W2, §5.3 IA | Reviewers can't find settings; MFA setup is a prerequisite chain |
| L5 | **One SKU, all factors in every tier, fail-closed licensing, US-ready SMS** (bundled or BYO Twilio etc.) | W4 | Simple to quote in RFPs; removes "Professional + Endpoint MFA Pro + HA add-on" stacking |
| L6 | **Secure by default**: no default credentials, HTTPS-only, least-privilege delegation script (never Domain Admin), signed and auto-updating agents, offline breached-password corpus, NIST 800-63B-aligned defaults | W6, W13, W17 | A CISO-friendly story against 3 KEV entries and an admin/admin default |
| L7 | **Native help-desk caller verification and approvals** (push/OTP to the caller's enrolled device, audited reset), no second product | W9 | ADSSP needs ADManager Plus for approvals and help-desk-assisted reset |
| L8 | **Lockout root-cause analytics** (source host/process, stale credentials such as mapped drives, services, mobile mail) with one-click remediation | W16 | Reviewers ask for lockout diagnosis; this is a visible help-desk win |
| L9 | **API-first**: OpenAPI REST, webhooks/event stream, SCIM 2.0 server and client | W8 | ADSSP still has "REST API support" on its roadmap |
| L10 | **Fine-grained RBAC** with OU-scoped delegated admins and an approval matrix | W7 | ADSSP has two roles; custom roles are roadmap only |
| L11 | **Risk-adaptive access**: device trust/posture, impossible travel, UBA signals feeding step-up | W12 | ADSSP lists UBA-based CA and device trust as "in pipeline" |
| L12 | **Passwordless Windows/macOS logon** (passkey or PIV as the primary credential) and SSH/sudo MFA for Linux | W10 | ADSSP's own roadmap items: passwordless endpoints, non-GUI MFA |
| L13 | **Built-in RADIUS service** (no Windows NPS dependency) | W11 | Simplifies VPN MFA deployment |
| L14 | **Elastic scale and active/active multi-region** | W5, W18 | ADSSP's own guidance warns against 1,000 concurrent password changes |
| L15 | **Hybrid AD + Entra parity from day one** (unlock, notifications and self-service also for Entra/hybrid users) | W19 | ADSSP's Entra support is three months old and many features are "AD only" |

## 9. Open gaps & next steps

### Resolved in T-0001 (2026-10-02)

- **Server migration and backup (migration playbook).** The vendor KB backs up with `backupDB.bat` into a compressed `OfflineBackup_<timestamp>.ezip`, requires copying the whole `\conf` folder ("contains all your configuration settings, including the database encryption password"), and requires "the exact same version and build number" on the new server. The restore password is the reversed filename or an admin-set password. The KB **does not mention exporting enrollment data** such as TOTP seeds or security answers ([KB](https://www.manageengine.com/self-service-password/kb/adself-service-installation-server-migration.html)). Consequence: there is no vendor-documented route to move enrollment out of ADSSP. The lab inspection below remains the only way to settle TOTP-seed and FIDO-key exportability.
- **Conditional access on endpoint/RDP logons** (ADSS-066): not documented for machine logons, see the row. The conflict is narrowed, not closed.
- **SMS gateways, languages:** see "Inventory gaps".
- **Certifications:** ADSSP is **not named** in ManageEngine's compliance centre. ISO 27001 and SOC 2 are stated as covering "all cloud services and on-premise products of ManageEngine", and the SOC 2 + HIPAA Type 2 scope names only ADManager Plus among the AD products ([compliance centre](https://www.manageengine.com/compliance.html), 2026-10-02). A search-index summary on a third-party security-profile site says ADSSP is "FedRamp compliant"; that is **not supported by ManageEngine's compliance centre or ADManager Plus's certification page, which list no FedRAMP authorisation**, so do not repeat it `[UNVERIFIED, likely wrong]`. The compliance centre lists TX-RAMP for ServiceDesk Plus Cloud, Endpoint Central Cloud and Site24x7 only.
- **Free tier and default admin credential:** the Free edition is 50 users and never expires (§1 table), and the default admin login is admin/admin (§2 table; CVE-2022-28810 write-up) — already sourced in this file.

### Still open

- `[TODO]` **Lab install of build 7001 (Free or Evaluation)**:
  - inspect the bundled PostgreSQL schema to confirm TOTP-seed and FIDO-credential storage/exportability;
  - confirm the security-answer hash format (salt, normalization) for a hash-compatible Q&A import;
  - capture screenshots of the admin and end-user UI for the design team.
- `[TODO]` Full list of the 100+ SSO catalogue apps and the 10+ SCIM/JIT apps (see Inventory gaps).
- `[TODO]` Perpetual licence prices (ADSSP is subscription-only per the AD360 file §6.4, so likely moot); per-feature Free-edition limits; edition gating for rows marked `[UNVERIFIED]` in §3.
- `[TODO]` Identity360 (cloud IAM) overlap and its roadmap relationship to ADSSP. The AD360 file covers Identity360 pricing.
- `[UNVERIFIED]` G2 and Google Play ratings (snippets or Wayback only) and the Gartner figure (snippet only).
- `[UNVERIFIED]` Customer accounts of migrating off ADSSP: Reddit and Spiceworks were not reachable.
- `[UNVERIFIED]` Whether the end-user portal, mobile app and agent all use the 19 display languages.

## Changelog

- **2026-10-02 (T-0001):** Closed migration/backup, SMS gateway, language and certification gaps; narrowed the ADSS-066 conflict; re-tagged the rest in §9.
