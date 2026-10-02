---
title: "ManageEngine AD Products: Customer Voice, Switching Drivers & Security Track Record"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: heramb
sources_last_checked: 2026-10-02
---

# ManageEngine AD Products: Customer Voice, Switching Drivers & Security Track Record

**Scope:** ADManager Plus (ADMP), ADAudit Plus (ADAP), ADSelfService Plus (ADSSP), AD360, RecoveryManager Plus (RMP), plus cross-product issues that hit them. **As of:** 2026‑10‑02. Internal research.

**House rules:** follows `.claude/skills/competitive-intel`.
- Customer adjectives appear only as attributed quotes.
- Anything that leaves the building is a CEO decision, `ceo-decisions` category 6.

## Key takeaways

1. **Star ratings won't separate us from them.** ManageEngine scores 4.0–4.8/5 and 9.0–9.3/10 wherever there are enough reviews (§1). Many recent reviews were solicited by the vendor: all 10 reviews on G2's first page for ADSSP and 8 of 10 for ADAP are tagged "Seller invite" (§1.1).
2. **What keeps customers is low price plus hundreds of canned compliance reports** (SOX, HIPAA, GDPR, PCI). We need report parity on day one. We should not try to win on price (§2.1, §5.2).
3. **The most frequent complaint is the UI and navigation** (≈28 of ~150 coded reviews; reviewers use "dated", "clunky" and "cluttered"). After that come limits on report customization (≈17) and manual, multi-step upgrades, some of which reviewers say failed (≈16). All three appear even in the vendor-solicited 2026 reviews (§2.2).
4. **Reviewers report per-module updates, separate logins across AD360 and ADSSP, and extra products needed for cloud/M365.** This is a structural opening for one unified console (§2.2 X5).
5. **Security record (from NVD, CISA KEV catalog 2026.10.01, and ManageEngine's advisory feed):**
   - **CISA KEV lists 3 CVEs** affecting these products: CVE‑2021‑40539, CVE‑2022‑47966 and CVE‑2022‑28810. KEV marks the first two "Known" for ransomware-campaign use.
   - CVE‑2021‑40539 was exploited by APT actors before a fix existed (joint advisory AA21‑259A). The ICRC breach entered through this CVE while it was still unpatched (ICRC, 2022).
   - **2026 advisories include:**
     - ADAP unauthenticated RCE (CNA CVSS 10.0).
     - ADSSP GINA-client RCE (CNA 9.8) and a REST API authentication bypass (CNA 8.6), both fixed in build 7001 on 2026‑08‑24.
     - Predictable SSO tickets in ADSSP, RMP and ADAP (CNA 9.0).
   - **No in-scope CVE published after March 2023 is in KEV** (§4).
6. **Disclosure follows the fix by a median of 60 days.** That is from the fixed-build date to NVD publication (n = 101), and 30% of cases exceed 90 days. Example: CVE‑2026‑6516 was fixed 2026‑04‑17 and published 2026‑07‑23 (§4.3).
7. **Biggest barriers to switching:**
   - Price (alternatives "two to three times" more, per a 2022 community comment).
   - Compliance-report dependence.
   - Sunk configuration: templates, delegation roles and workflows.
   - Audit-history retention.
   - ADSSP users having to re-enroll in MFA and self-service password reset.

   A migration offer has to neutralize each of these (§5).
8. **Strongest wedges:**
   - Automatic, signed updates.
   - Tier‑0 security we can evidence, framed as our proof and never as claims about ManageEngine.
   - One console for hybrid AD and Entra ID.
   - A flexible report builder.
   - Licensing that doesn't discourage named technician accounts (§6).

## Method & source-access notes (read before reusing in RFPs)

| Source | Access on 2026‑10‑02 | How used |
|---|---|---|
| CISA KEV | JSON feed downloaded, catalog version **2026.10.01**, 1,731 entries ([catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)) | Exploitation status, date added to KEV, ransomware flag |
| NVD | API 2.0, queried by keyword and by CPE (`cpe:2.3:a:zohocorp:manageengine_*`) | CVSS scores and publication dates. Where NVD hasn't scored a CVE, the CNA score (Zohocorp) is used and labeled "CNA" |
| CVE.org | API record lookups | Confirmed the assigning CNA ("Zohocorp") and its CVSS for 2025–26 CVEs |
| ManageEngine advisories | Data feed behind https://www.manageengine.com/security/advisory/ | Fix date, fixed build, vendor severity and advisory date for **104** advisories touching in-scope products |
| PeerSpot | Live | Full review text from the page's structured data (29 reviews) |
| Capterra | Live via WebFetch, which returns model-extracted text, not raw HTML | Ratings and cons. **Every Capterra quote was captured or confirmed in a targeted verbatim pass**; where two passes overlapped, the wording matched |
| G2, TrustRadius, Gartner Peer Insights | **403 live**, both curl and WebFetch | Wayback Machine snapshots, labeled "WB YYYY‑MM‑DD". Gartner review text was not reachable `[TODO]` |
| Reddit | **Blocked live** | Thread snapshots found through the Wayback CDX index (≈25 threads, 2018–2026). Quotes cite the reddit.com permalink, the username as shown, and the thread or comment date |
| Spiceworks Community | Live, via its public search/topic JSON | About 30 threads, 2017–2026 |
| Web search | **The session's WebSearch budget ran out partway through the research.** No claim below rests on a search snippet, so nothing is marked `[snippet]` | — |

Ratings in §1 marked "sub-agent" were collected by a parallel research pass using the same method (live fetch or Wayback snapshot). They were not re-fetched for this document.

---

## 1. Ratings snapshot

| Product | Site | Rating | # reviews | Checked / snapshot | URL | Notes |
|---|---|---|---|---|---|---|
| ADManager Plus | G2 | 4.5/5 | 102 | WB 2026‑07‑25 | [g2.com](https://www.g2.com/products/manageengine-admanager-plus/reviews) | Live page blocked. Figure comes from the competitor panel on the ADAP G2 snapshot ([WB](https://web.archive.org/web/20260725211953/https://www.g2.com/products/manageengine-adaudit-plus/reviews)); ADMP's own page has no 2025+ snapshot |
| ADManager Plus | Gartner PI | 4.6/5 | 399 | WB 2026‑04‑14 (sub-agent) | [gartner.com](https://www.gartner.com/reviews/product/manageengine-admanager-plus) | From the alternatives data on the AD360 Gartner snapshot |
| ADManager Plus | Capterra | 4.6/5 | 111 | 2026‑10‑02 live | [capterra.com](https://www.capterra.com/p/143496/ADManager-Plus/) | Sub-scores (sub-agent): ease of use 4.7, customer service 4.5, features 4.7, value 4.6 |
| ADManager Plus | TrustRadius | 9/10 | 84 reviews & ratings | WB 2026‑07‑22 | [WB](https://web.archive.org/web/20260722164719/https://www.trustradius.com/products/manageengine-admanager-plus/reviews) | Category: Identity Governance & Administration. Sub-agent saw 9.3/10 with 63 ratings at WB 2025‑11‑08 |
| ADManager Plus | PeerSpot | 4.0/5 | 16 | 2026‑10‑02 live | [peerspot.com](https://www.peerspot.com/products/manageengine-admanager-plus-reviews) | 94% willing to recommend; #4 in AD Management; mindshare 8.6%, down from 14.7% a year earlier |
| ADAudit Plus | G2 | 4.6/5 | 59 (48×5★, 10×4★, 1×3★) | WB 2026‑07‑25 | [WB](https://web.archive.org/web/20260725211953/https://www.g2.com/products/manageengine-adaudit-plus/reviews) | G2 categories: SIEM, Log Analysis, UEBA |
| ADAudit Plus | Gartner PI | `[TODO]` | — | blocked | gartner.com (IT Infrastructure Monitoring Tools market, per sub-agent) | No usable 2026 snapshot |
| ADAudit Plus | Capterra | 4.5/5 | 104 | 2026‑10‑02 live | [capterra.com](https://www.capterra.com/p/210774/ADAudit-Plus/) | — |
| ADAudit Plus | TrustRadius | 9.0/10 | 132 | WB 2026‑03‑07 | [WB](https://web.archive.org/web/20260307180844/https://www.trustradius.com/products/manageengine-adaudit-plus/reviews) | Category: System Monitoring |
| ADAudit Plus | PeerSpot | 4.4/5 | 15 | 2026‑10‑02 live | [peerspot.com](https://www.peerspot.com/products/manageengine-adaudit-plus-reviews) | 100% willing to recommend; #5 in AD Management; mindshare 7.1%, down from 11.1% |
| ADSelfService Plus | G2 | 4.5/5 | 32 (23/7/2/0/0) | WB 2026‑08‑03 | [WB](https://web.archive.org/web/20260803114027/https://www.g2.com/products/manageengine-adselfservice-plus/reviews) | G2 AI summary says "support could be improved" |
| ADSelfService Plus | Gartner PI | `[TODO]` | — | blocked | gartner.com (Password Management Tools market, per sub-agent) | No usable snapshot |
| ADSelfService Plus | Capterra | 4.6/5 | 63 | 2026‑10‑02 live | [capterra.com](https://www.capterra.com/p/172556/ADSelfService-Plus/) | — |
| ADSelfService Plus | TrustRadius | 9.2/10 | 18 | WB 2025‑11‑10 | [WB](https://web.archive.org/web/20251110022945/https://www.trustradius.com/products/manageengine-adselfservice-plus/reviews) | Category: Password Management |
| ADSelfService Plus | PeerSpot | 4.2/5 | 9 | 2026‑10‑02 live | [peerspot.com](https://www.peerspot.com/products/manageengine-adselfservice-plus-reviews) | 90% willing to recommend; #23 in Enterprise Password Managers; mindshare 1.1% |
| AD360 | G2 | 4.3/5 | 4 | WB 2026‑04‑18 (sub-agent) | [WB](https://web.archive.org/web/20260418000737/https://www.g2.com/products/manageengine-ad360/reviews) | Category: IAM |
| AD360 | Gartner PI | 4.6/5 | 275 | WB 2026‑04‑14 (sub-agent) | [gartner.com](https://www.gartner.com/reviews/product/manageengine-ad360) | IGA market. 165×5★, 96×4★, 14×3★ (sub-agent) |
| AD360 | Capterra | 4.6/5 | 35 | 2026‑10‑02 live | [capterra.com](https://www.capterra.com/p/268487/ManageEngine-AD360/reviews/) | — |
| AD360 | TrustRadius | 9.2/10 | 8 | WB 2026‑04‑15 (sub-agent) | trustradius.com/products/manageengine-ad360/reviews | — |
| AD360 | PeerSpot | no rated reviews | 0 | 2026‑10‑02 live | [peerspot.com](https://www.peerspot.com/products/manageengine-ad360-reviews) | — |
| RecoveryManager Plus | G2 | 4.8/5 | 4 | WB 2026‑04‑16 (sub-agent) | g2.com/products/manageengine-recoverymanager-plus/reviews | Category: SaaS Backup |
| RecoveryManager Plus | Gartner PI | `[UNVERIFIED]` | — | blocked | — | No archived page found |
| RecoveryManager Plus | Capterra | no rating | 0 | 2026‑10‑02 live (sub-agent) | [capterra.com](https://www.capterra.com/p/187322/RecoveryManager-Plus/) | Listing exists with no reviews |
| RecoveryManager Plus | TrustRadius | `[TODO]` | — | blocked, no archive | — | — |
| RecoveryManager Plus | PeerSpot | no rated reviews | 0 | 2026‑10‑02 live | [peerspot.com](https://www.peerspot.com/products/manageengine-recoverymanager-plus-reviews) | — |

### 1.1 How to read these ratings

- **Scores are uniformly high, so they can't be our point of contrast.** UI complaints show up in review text even where ease-of-use sub-scores are high (Capterra 4.5–4.7).
- **A large share of recent reviews was solicited by the vendor:**
  - G2 ADSSP, first page (WB 2026‑08‑03): **10 of 10** tagged "Source: Seller invite", dated 2026‑06‑22 to 07‑07 ([WB](https://web.archive.org/web/20260803114027/https://www.g2.com/products/manageengine-adselfservice-plus/reviews)).
  - G2 ADAP, first page: **8 "Seller invite"** and 2 "Source: G2 invite" with the "Incentivized" tag ([WB](https://web.archive.org/web/20260725211953/https://www.g2.com/products/manageengine-adaudit-plus/reviews)).
  - TrustRadius ADMP: 3 of 5 displayed reviews (dated 2026‑06‑30 to 07‑13) are "Invited by the Vendor" or "Incentivized" ([WB](https://web.archive.org/web/20260722164719/https://www.trustradius.com/products/manageengine-admanager-plus/reviews)).
  - Many Capterra reviews cluster on 2026‑06‑22/23.
  - **Treat 2026 averages as solicited.** Complaints that still appear in solicited reviews are a stronger signal (inference).
- **Review volume is concentrated in ADMP, then ADAP.** RMP has almost no reviews anywhere, and AD360 has few outside Gartner, so we have little customer voice on backup/recovery `[TODO]`.
- **PeerSpot mindshare for ADMP and ADAP in "AD Management" fell year on year** (8.6% from 14.7%, and 7.1% from 11.1%) ([ADMP](https://www.peerspot.com/products/manageengine-admanager-plus-reviews), [ADAP](https://www.peerspot.com/products/manageengine-adaudit-plus-reviews)). PeerSpot computes mindshare from user engagement; it is not market share. The sub-agent reports that category leaders on that page are Quest Active Roles (11.8%) and Netwrix Auditor (10.2%).
- **Site-generated summaries, not reviewer quotes:**
  - TrustRadius ADMP cons: "User interface design is perceived as outdated and lacking modern aesthetics"; "Installation and upgrade processes can be complex" ([WB 2026‑07‑22](https://web.archive.org/web/20260722164719/https://www.trustradius.com/products/manageengine-admanager-plus/reviews)).
  - PeerSpot ADMP: lists needed improvements as "reporting customization, UI intuitiveness, and better integration with Office 365" ([PeerSpot](https://www.peerspot.com/products/manageengine-admanager-plus-reviews)).

---

## 2. Themes (praise & pain)

### How the frequency signals were produced

- **Pain counts** come from manually coding the "cons", "dislike" or "needs improvement" text of **~152 reviews**:
  - Capterra: ADMP 33, ADAP 24, ADSSP 25, AD360 6
  - PeerSpot: 29
  - G2 snapshots: ADAP 10, ADSSP 10, ADMP 10 (2023 reviews in the WB 2024‑12‑03 snapshot)
  - TrustRadius ADMP: 5

  Each reviewer is counted once per theme, with obvious cross-site duplicates removed.
- **Praise counts** are keyword hits in the "likes", "most valuable" and pricing sections of **59 raw reviews** (PeerSpot 29 + G2 30). Both counts are approximate and directional.

Quote attribution format: site, reviewer as shown (with role where shown), date, link. Each quote is one sentence or part of one.

### 2.1 Praise: why customers buy and stay

| Theme | Frequency signal | Products | Verbatim quotes |
|---|---|---|---|
| **Out-of-box reports & compliance** (SOX, HIPAA, GDPR, ISO 27001) | **High**: 25/59 likes sections. The top G2 tag for ADAP is "Reporting" | ADAP, ADMP | <ul><li>"it has hundreds of built-in reports ready to go for compliance stuff like HIPAA or GDPR" (G2, Jeffrey C., SecOps Manager, 2026‑06‑22, seller-invited, [WB](https://web.archive.org/web/20260725211953/https://www.g2.com/products/manageengine-adaudit-plus/reviews))</li><li>"We don't need any custom reports to be generated because there are so many in-built reports." (PeerSpot, Buddhika Subasinghe, 2025‑08‑13, [link](https://www.peerspot.com/products/manageengine-adaudit-plus-reviews))</li><li>"We mostly use it for compliance reports for SOX." (Spiceworks, SHNOOL, ADMP, 2026‑01‑28, [link](https://community.spiceworks.com/t/ad-management-tools/1248976))</li></ul> |
| **Price & value** | **High**: 21/59. Also the dominant reason in community threads (§3) | All | <ul><li>"Like a 5th or a 10th of the price of similar solutions from other vendors." (r/sysadmin, u/Capable-Hedgehog-819, ADAP + MDM, 2024‑01‑19, [link](https://www.reddit.com/r/sysadmin/comments/19api3h/manageengine_tools_whats_the_catch/))</li><li>"It's incredibly cheap (like $2k/yr for 10 DCs) for that category of product." (r/sysadmin, u/shim_sham_shimmy, ADAP, thread 2022‑06‑20, [link](https://www.reddit.com/r/sysadmin/comments/vgt50o/manageengine_users_what_do_you_think/)). Customer-reported, not list price</li><li>"We switched to ManageEngine ADManager Plus since it's cheaper and has more reports." (PeerSpot, ManishMehta, 2023‑12‑19, [link](https://www.peerspot.com/products/manageengine-admanager-plus-reviews))</li></ul> |
| **Easy initial deployment** | **High**: 25/59 mention ease of use or setup | All | <ul><li>"The installation process is effortless, requiring only one person." (PeerSpot, MUBDIUL ISLAM, ADMP, 2025‑02‑12, [link](https://www.peerspot.com/products/manageengine-admanager-plus-reviews))</li><li>"The initial setup to get it reporting and allowing you to make changes from it are very easy and quick." (G2, Ryan A., Director-IT, ADAP, 2026‑06‑23, seller-invited, [WB](https://web.archive.org/web/20260725211953/https://www.g2.com/products/manageengine-adaudit-plus/reviews))</li></ul> |
| **Bulk operations, templates & automation beyond native AD tools** | **Medium**: 10/59 | ADMP | <ul><li>"ADManager Plus fills all the gaps left by Microsoft." (TrustRadius, Kevin J. Wangler, Director of IT, 2026‑07‑05, vendor-invited, [WB](https://web.archive.org/web/20260722164719/https://www.trustradius.com/products/manageengine-admanager-plus/reviews))</li><li>"It automates seven to eight individual processes that we used to do manually before." (PeerSpot, Jai S, 2023‑07‑18, [link](https://www.peerspot.com/products/manageengine-admanager-plus-reviews))</li></ul> |
| **Delegation without giving technicians DC or Domain Admin access** | **Medium**: 8/59. Also the main answer in the thread "Manager forces the use of ADManager+, instead of AD tools. Why?" (§3) | ADMP | <ul><li>"The solution has helped our organization by reducing risks and not allowing a technician direct access to the servers and the environment." (PeerSpot, Elgin Smith, 2023‑11‑09, [link](https://www.peerspot.com/products/manageengine-admanager-plus-reviews))</li><li>"Don't need to allow access to domain controller(s)" (r/sysadmin, u/HerfDog58, thread 2024‑11‑13, [link](https://www.reddit.com/r/sysadmin/comments/1gqmucw/manager_forces_the_use_of_admanager_instead_of_ad/))</li></ul> |
| **Real-time change alerts and forensics** | **Medium**: 6/59 | ADAP | <ul><li>"In my organization, we get an email immediately if a user gets added to one of those groups." (PeerSpot, William Cochran, 2024‑08‑21, [link](https://www.peerspot.com/products/manageengine-adaudit-plus-reviews))</li><li>"It paid for itself immediately when we had someone delete a critical account and we were able to quickly figure out what happened." (r/sysadmin, u/shim_sham_shimmy, thread 2022‑06‑20, [link](https://www.reddit.com/r/sysadmin/comments/vgt50o/manageengine_users_what_do_you_think/))</li></ul> |
| **Self-service password reset cuts helpdesk tickets** | **Medium**: 11/59, and the top ADSSP benefit | ADSSP | <ul><li>"The good: Password reset call volume dropped." (Spiceworks, donnysaengkio4720, 2018‑06‑05, [link](https://community.spiceworks.com/t/any-experience-with-manageengine-adselfservice-plus/655390))</li><li>"The most valuable feature of ADSelfService Plus is that it allows users to self-service and cuts down on the number of password resets required." (PeerSpot, CarlosPerez7, 2023‑03‑24, [link](https://www.peerspot.com/products/manageengine-adselfservice-plus-reviews))</li></ul> |
| **Low-cost MFA, including Windows logon, RDP/NPS and VPN** | **Low–Medium**: 5/59 | ADSSP | <ul><li>"Price was the deciding factor." (PeerSpot, William Cochran, on adopting ADSSP for server-login MFA, 2022‑10‑14, [link](https://www.peerspot.com/products/manageengine-adselfservice-plus-reviews))</li><li>"They are all great, but really expensive." (Spiceworks, jasonfromit, on Okta, JumpCloud and Duo while evaluating ADSSP, 2024‑05‑02, [link](https://community.spiceworks.com/t/adselfservice-plus-service-providers/1070837))</li></ul> |

### 2.2 Pain

Theme names describe what reviewers report; adjectives are theirs.

| # | Theme | Frequency (of ~152 coded) | Products | Verbatim quotes |
|---|---|---|---|---|
| X1 | **UI and navigation** (reviewers' words: "dated", "clunky", "cluttered") | **≈28, the #1 complaint** | All | <ul><li>"The program itself is somewhat clunky." (Capterra, Seth S., Director of IT, Law Practice, ADMP, 2026‑06‑29, [link](https://www.capterra.com/p/143496/ADManager-Plus/reviews/))</li><li>"It still feels very Windows 2000." (G2, Tyrone O., IT Manager, ADSSP, 2026‑06‑24, seller-invited, [WB](https://web.archive.org/web/20260803114027/https://www.g2.com/products/manageengine-adselfservice-plus/reviews))</li><li>"The interface can also feel a bit dated and occasionally sluggish when pulling larger reports or filtering across longer date ranges." (Capterra, Micah G., Network Support Technician, ADAP, 2026‑06‑22, [link](https://www.capterra.com/p/210774/ADAudit-Plus/reviews/))</li><li>"UI feels slightly outdated compared to modern IAM tools." (Capterra, Anonymous User, IT Infra Manager, AD360, 2025‑12‑13, [link](https://www.capterra.com/p/268487/ManageEngine-AD360/reviews/))</li></ul> |
| X2 | **Report customization and report UX limits** (custom reports, scheduling, sharing, charts) | **≈17** | ADMP, ADAP, AD360 | <ul><li>"The canned reports are great, but the custom reporting is somewhat limited." (Capterra, Russ S., IT Director, ADAP, 2026‑06‑25, [link](https://www.capterra.com/p/210774/ADAudit-Plus/reviews/))</li><li>"if you create a large amount of custom reports, they can overflow from the container" (Capterra, Jacob M., Systems Administrator, ADMP, 2026‑09‑15, [link](https://www.capterra.com/p/143496/ADManager-Plus/reviews/))</li><li>"currently, it's limited with old school bar charts, and having more interactive reports with a better graphical user interface would be beneficial" (PeerSpot, Karthik G, ADAP, 2025‑09‑16, [link](https://www.peerspot.com/products/manageengine-adaudit-plus-reviews))</li></ul> |
| X3 | **Upgrades and patches are manual and multi-step; some reviewers report failed upgrades** | **≈16**, and present in every product | All | <ul><li>"there has been an error during the upgrade and I've had to restore the entire service from backups" (G2, Tyson W., ADMP, 2023‑07‑14, organic, [WB 2024‑12‑03](https://web.archive.org/web/20241203101904/https://www.g2.com/products/manageengine-admanager-plus/reviews))</li><li>"The upgrade process is very fiddly and can be time consuming, with several manual steps that increase the risk of errors" (Capterra, Neil S., Infrastructure Services Manager, ADAP, 2026‑06‑25, [link](https://www.capterra.com/p/210774/ADAudit-Plus/reviews/))</li><li>"Frequent patch updates requiring several, manual steps." (G2, Scott B., Director of IT, ADSSP, 2026‑06‑22, seller-invited, [WB](https://web.archive.org/web/20260803114027/https://www.g2.com/products/manageengine-adselfservice-plus/reviews))</li><li>"I wish all the different modules updated together." (Capterra, Marlo K., Director of IT, AD360, 2025‑10‑31, [link](https://www.capterra.com/p/268487/ManageEngine-AD360/reviews/))</li></ul> |
| X4 | **Learning curve; documentation gaps** (reviewer-reported) | **≈12** reviews, plus strong community signal | All | <ul><li>"It's almost like you need to take a course on how to manoeuvre within it" (PeerSpot, Kimberly Brock, ADMP, 2023‑05‑10, [link](https://www.peerspot.com/products/manageengine-admanager-plus-reviews))</li><li>"There is a bit of a learning curve, and the little bit of documentation that there is leaves a lot to be desired." (Capterra, Verified Reviewer, Director of IT Infrastructure, ADMP, 2019‑01‑24, [link](https://www.capterra.com/p/143496/ADManager-Plus/reviews/))</li><li>"ManageEngine's documentation is awful, welcome to the club." (r/sysadmin, u/Emiroda, ADSSP thread, 2024‑02‑28, [link](https://www.reddit.com/r/sysadmin/comments/1b20du1/manageengine_adselfservice_plus_am_i_stupid_or_is/))</li></ul> |
| X5 | **Hybrid/cloud coverage needs extra products; behavior differs across modules** (AD360 navigation, logins) | **≈11** | ADMP, ADAP, AD360 | <ul><li>"Only covers domain on premises , cloud requires another product." (Capterra, Vladimir B., InfoSec Program Manager, Banking, ADMP, 2026‑06‑22, [link](https://www.capterra.com/p/143496/ADManager-Plus/reviews/))</li><li>"Exchange online reports are limited but they have another product for it." (TrustRadius, Pervaiz Dostiyar, IT Manager, ADMP, 2026‑06‑30, [WB](https://web.archive.org/web/20260722164719/https://www.trustradius.com/products/manageengine-admanager-plus/reviews))</li><li>"if I log into AD360 I use one password, but if I log in directly to Self Service Plus, it is a different password" (Capterra, Marlo K., AD360, 2025‑10‑31, [link](https://www.capterra.com/p/268487/ManageEngine-AD360/reviews/))</li><li>"For reports, we have to go back to ADAudit, which is not ideal." (PeerSpot, Jai S, ADMP, 2023‑07‑18, [link](https://www.peerspot.com/products/manageengine-admanager-plus-reviews))</li></ul> |
| X6 | **ADSSP endpoint and enrollment friction** (GINA/CP agent rollout, VPN cached credentials, user registration, MFA UX) | **≈10** of ~44 ADSSP reviews | ADSSP | <ul><li>"the solution can only be installed or updated on a device if it is physically connected to the local network" (PeerSpot, Bill Lamon, 2020‑03‑15, [link](https://www.peerspot.com/products/manageengine-adselfservice-plus-reviews))</li><li>"It should be easier for users to register for the service." (PeerSpot, CarlosPerez7, 2023‑03‑24, [link](https://www.peerspot.com/products/manageengine-adselfservice-plus-reviews))</li><li>"ADSelfService requires you to open the application and approve the login on the computer." (PeerSpot, Juan José Chamorro Busto, 2023‑02‑15, [link](https://www.peerspot.com/products/manageengine-adselfservice-plus-reviews))</li></ul> |
| X7 | **Support experience varies** (reviewer-reported: slow escalations, long remote sessions) | **≈9** reviews; the **dominant theme in community threads** (§3) | All | <ul><li>"Support is hit or miss too — sometimes you get a fast, helpful response, other times it drags on longer than you'd like" (G2, Arvind K., Senior Consultant, ADAP, 2026‑05‑06, G2-invited and incentivized, [WB](https://web.archive.org/web/20260725211953/https://www.g2.com/products/manageengine-adaudit-plus/reviews))</li><li>"The quality of the support team is insufficient to solve problems of the product and quickly shut down calls." (Capterra, Verified Reviewer, Senior Security Engineer, Banking, ADAP, 2019‑05‑19, [link](https://www.capterra.com/p/210774/ADAudit-Plus/reviews/))</li><li>Counterpoint: "I have always found there support to be good and assist to get issues resolved." (r/ITManagers, u/Research-NRG, thread 2022‑04‑20, [link](https://www.reddit.com/r/ITManagers/comments/u7xfjx/what_do_we_really_think_of_manageengine/))</li></ul> |
| X8 | **Licensing complexity and cost growth** (per DC, server, technician or user; module add-ons) | **≈9** reviews. Price itself is net praise; complexity and renewals are the pain | ADAP, AD360, ADMP | <ul><li>"The pricing and licensing structure has always felt more complicated than it needs to be." (G2, Arvind K., ADAP, 2026‑05‑06, [WB](https://web.archive.org/web/20260725211953/https://www.g2.com/products/manageengine-adaudit-plus/reviews))</li><li>"This tool Licensing Can Get Confusing, Cost Grows as User Count Grows, Reporting is Strong but Sometimes Slow." (Capterra, Goutam D., Manager‑IT, AD360, 2025‑12‑09, [link](https://www.capterra.com/p/268487/ManageEngine-AD360/reviews/))</li><li>"Cost is the only limiting factor here, this tool is seriously expensive" (Capterra, Victor L., System administrator, Banking, ADAP, 2024‑12‑18, [link](https://www.capterra.com/p/210774/ADAudit-Plus/reviews/))</li></ul> |
| X9 | **Performance and resource use** (RAM, UI load time, latency sensitivity) | **≈9** | ADAP, ADMP, ADSSP | <ul><li>"I'd say the only issue I have with any of the products is how much RAM it takes to run the applications." (G2, Ryan A., Director-IT, ADAP, 2026‑06‑23, [WB](https://web.archive.org/web/20260725211953/https://www.g2.com/products/manageengine-adaudit-plus/reviews))</li><li>"Deploy On-Premise it can be complex to maintain overtime and is not always the most responsive product, the interface can take time to load." (G2, Jonathan B., IT Director/CISO, ADAP, 2026‑06‑22, same link)</li><li>"In my own testing from a VM in Sydney I got bored of waiting for it to load after 5 minutes" (r/sysadmin, u/hawkbox1, ADMP over WAN, 2020‑02‑18, [link](https://www.reddit.com/r/sysadmin/comments/f5x4cx/admanager_plus_alternatives_in_2020/))</li></ul> |
| X10 | **Updates or defects reported to affect AD-facing behavior** (Tier‑0 risk) | **≈6** | ADMP, AD360 | <ul><li>"Certain updates have led to compatibility issues in our Active Directory environment, necessitating us to contact customer support for assistance." (G2, Raymund M., Enterprise, ADMP, 2023‑07‑24, organic, [WB](https://web.archive.org/web/20241203101904/https://www.g2.com/products/manageengine-admanager-plus/reviews))</li><li>"Except for that one time when Admanager f*cked up pur AD big time due to a bug." [sic] (r/ITManagers, u/tranceandsoul, thread 2022‑04‑20, [link](https://www.reddit.com/r/ITManagers/comments/u7xfjx/what_do_we_really_think_of_manageengine/))</li></ul> |
| X11 | **Alert volume and false positives; database and storage growth** | **≈4** reviews (about 1 in 10 ADAP reviews). G2 tags include "False Positives", "Data Overload", "Alert Management" and "High Resource Usage" | ADAP | <ul><li>"you really have to spend some time fine-tuning the alerts, otherwise your inbox will get absolutely flooded with routine notifications and false alarms" (G2, Jeffrey C., SecOps Manager, 2026‑06‑22, [WB](https://web.archive.org/web/20260725211953/https://www.g2.com/products/manageengine-adaudit-plus/reviews))</li><li>"audit logs can consume significant storage space in large environments, requiring careful capacity planning" (G2, Naveen K., IT Manager, 2026‑06‑23, same link)</li></ul> |

**Not observed in the coded sample:** explicit "Java/Tomcat" complaints from reviewers. The stack does surface in community threads and advisories:
- "java-fu" during updates (r/sysadmin, u/8poot, 2021‑09‑03, [link](https://www.reddit.com/r/sysadmin/comments/phaalr/thoughts_on_manageengine_admanager_plus_vs_adaxes/)).
- ADSSP's 32-bit build running out of memory (r/sysadmin, u/TrueStoriesIpromise, thread 2022‑06‑20, [link](https://www.reddit.com/r/sysadmin/comments/vgt50o/manageengine_users_what_do_you_think/)).
- Bundled third-party component advisories: Log4j (ME advisory 2021‑12‑13), Apache Tomcat CVE‑2024‑21733 (ADMP/AD360, fixed 2024‑01‑23), the Apache Santuario root cause of CVE‑2022‑47966, and the Cewolf charting library in CVE‑2022‑28219.

Source for the advisories: ManageEngine advisory feed ([portal](https://www.manageengine.com/security/advisory/)) and [Horizon3](https://www.horizon3.ai/attack-research/disclosures/red-team-blog-cve-2022-28219/).

---

## 3. Community sentiment (Spiceworks + Reddit, 2017–2026)

**Sample:**
- **Spiceworks:** ≈30 threads read in full via its topic JSON.
- **Reddit:** ≈25 threads read from Wayback snapshots, because live Reddit was blocked. That covers r/sysadmin, r/msp, r/ITManagers, r/activedirectory and r/cybersecurity.

Many "recommendations" on Spiceworks come from **vendor staff**: ryan‑netwrix, rupesh‑lepide, anton‑softerra (Adaxes), peter/mike‑action1, vidya‑zoho and giridhara‑zoho. They are counted as "named" but excluded from sentiment.

### 3.1 Alternatives sysadmins name

| Alternative | Threads mentioning (sample) | Why it's named (posters' reasons) | Example |
|---|---|---|---|
| **Netwrix Auditor** | ≈11 | Broader audit scope (files, M365, SQL), "SIEM lite", support praised. Cited limits: higher price, a 150-user minimum on its SMB tier (2022 post), sales follow-up | [Spiceworks 2026‑01](https://community.spiceworks.com/t/ad-management-tools/1248976); [Spiceworks 2022‑01](https://community.spiceworks.com/t/alternative-to-ad-audit-plus-netwrix/822065) |
| **Native tools / PowerShell / RSAT / ADAC** (now often scripts written with ChatGPT or Copilot) | ≈7 | Free. Limits: role-based access, and auditors want tamper-evident reports | [Spiceworks 2025‑02](https://community.spiceworks.com/t/netwrix-alternative/1180156); [Spiceworks 2021‑09](https://community.spiceworks.com/t/software-active-directory-user-management/812553) |
| **Lepide** | ≈6 | Interface praised, permissions analysis, cheaper SMB suite | [Spiceworks 2021‑06](https://community.spiceworks.com/t/choosing-an-auditing-tool-adaudit-netwrix-lepide-etc/801244) |
| **Adaxes (Softerra)** | ≈6 | Rule-based automation and a customizable web UI. Seen as pricier, with per-user licensing | [r/sysadmin 2021‑09](https://www.reddit.com/r/sysadmin/comments/phaalr/thoughts_on_manageengine_admanager_plus_vs_adaxes/); [Spiceworks 2018](https://community.spiceworks.com/t/alternative-to-admanager-plus/664883) |
| **EventSentry** | ≈4 | SIEM-style AD monitoring with a perpetual license (mostly one recurring recommender) | [Spiceworks 2021‑12](https://community.spiceworks.com/t/manageengine-ad360-adaudit-plus-admanager-plus-alternatives/818714) |
| **IS Decisions** (UserLock, FileAudit) | ≈3 | Logon monitoring and MFA in one product (one post is vendor-adjacent) | [r/sysadmin 2024‑03](https://www.reddit.com/r/sysadmin/comments/1bpdgya/adaudit_plus_from_manageengine_options_pricing/) |
| **Quest Active Roles (ARS)** | 2 | Enterprise delegation and RBAC; "I would have gone with Quest ARS" (u/AppIdentityGuy) | [r/sysadmin 2023‑10](https://www.reddit.com/r/sysadmin/comments/16y5eo6/manage_engine_vs_cayosoft/); [r/sysadmin 2024‑11](https://www.reddit.com/r/sysadmin/comments/1gqmucw/manager_forces_the_use_of_admanager_instead_of_ad/) |
| **Varonis** | 2 | Higher functionality and much higher cost | [Spiceworks 2025‑02](https://community.spiceworks.com/t/netwrix-alternative/1180156) |
| **Microsoft Entra ID P1 SSPR** (formerly Azure AD Premium) | 2 | No extra server in a DMZ; per-user cost | [Spiceworks 2017](https://community.spiceworks.com/t/would-you-prefer-azure-ad-prem-1-or-adselfservice-plus/597935) |
| Cayosoft; NetIQ/OpenText DRA; Purple Knight; Tenfold; SolarWinds ARM; Okta, Duo or JumpCloud (for MFA) | 1 each | Helpdesk restriction (Cayosoft, DRA); free AD posture checks (Purple Knight); free 150-user community edition (Tenfold); MFA/SSO suites seen as costly | [r/sysadmin 2023‑10](https://www.reddit.com/r/sysadmin/comments/16y5eo6/manage_engine_vs_cayosoft/); [Spiceworks 2026‑07](https://community.spiceworks.com/t/how-do-you-manage-ntfs-access-rights/1255594); [Spiceworks 2024‑05](https://community.spiceworks.com/t/adselfservice-plus-service-providers/1070837) |

**Not seen in this sample:** Specops (an ADSSP alternative), and Semperis DSP or Quest Recovery Manager for AD (RMP alternatives) `[TODO]`.

### 3.2 Key community findings

1. **Price is the main reason for choosing ManageEngine, and the main reason for staying.**
   - "I recall liking Netwrix better but we ended up go with ADAudit Plus because it was much lower cost" (r/sysadmin, u/HDClown, thread 2021‑03‑17, [link](https://www.reddit.com/r/sysadmin/comments/m763kg/netwrix_vs_manageengines_ad_audit_tools_which_is/))
   - "They aren't the best products, but it's damn hard to find on premises alternatives that aren't two to three times at least more expensive." (r/sysadmin, u/Soggy-Camera1270, thread 2022‑11‑09, [link](https://www.reddit.com/r/sysadmin/comments/yqvfg2/manageengine_techs_you_high/))
2. **The UI and licensing complaints go back years.** A 2021 buyer demoed Netwrix, Lepide, EventSentry and IS Decisions against ADAP and chose Lepide (Spiceworks, compgeek89, 2021‑06‑10, [link](https://community.spiceworks.com/t/choosing-an-auditing-tool-adaudit-netwrix-lepide-etc/801244)). They wrote:
   - "Downsides are a crazy confusing and pricey licensing model and a dated and clunky interface."
   - "Seem to be coasting on their success and existing customers."
3. **Security news triggers evaluations.**
   - "Over the past year my boss has seen several security notifications for ManageEngine products, specifically ADSelfService Plus and ServiceDesk Plus" (Spiceworks, bezoid, 2021‑12‑03, [link](https://community.spiceworks.com/t/manageengine-ad360-adaudit-plus-admanager-plus-alternatives/818714))
   - "From a sec standpoint, they're targeted CONSTANTLY due to the privs those platforms get an environment." (r/ITManagers, u/aec_itguy, 2022‑04‑20, [link](https://www.reddit.com/r/ITManagers/comments/u7xfjx/what_do_we_really_think_of_manageengine/))
4. **Customers are actively moving to Netwrix in 2026.**
   - "I use ADAudit by ManageEngine but am moving to netwrix auditor." (Spiceworks, popeyesailzzz, 2026‑01‑29, [link](https://community.spiceworks.com/t/ad-management-tools/1248976))
   - An earlier ADAP user: "it's nice but doesn't really give me enough information on account lock outs or login attempts." (Spiceworks, jgpjgp, 2022‑01‑14, [link](https://community.spiceworks.com/t/alternative-to-ad-audit-plus-netwrix/822065))
5. **ADMP is often inherited and kept for compliance reporting, and described as powerful.**
   - "I didn't pick the tool I inherited it."
   - "The tool is way powerful though and frankly can do significant damage if in the wrong hands."

   Both from Spiceworks, SHNOOL, 2026‑01‑28 ([link](https://community.spiceworks.com/t/ad-management-tools/1248976)).
6. **Mandates come from audit and segregation of duties.**
   - "Made sense because some folks repeatedly messed up on SOX controls and we couldn't prove it that the original change was their's 6 months later." (r/sysadmin, u/BisonST, thread 2024‑11‑13, [link](https://www.reddit.com/r/sysadmin/comments/1gqmucw/manager_forces_the_use_of_admanager_instead_of_ad/))
7. **Large and MSP estates hit both cost and usability limits.**
   - "Got a client with several thousand endpoints who's been using ADMP but unhappy with it for cost and usability issues." (r/msp, u/etherealfocus, 2022‑09‑21, [link](https://www.reddit.com/r/msp/comments/xjx6wg/experiences_with_admanager_plus_alternatives/)). The poster adds that per-seat licensing for many helpdesk users makes both ADMP and Adaxes expensive.
8. **Support and documentation are the loudest community complaints across the ManageEngine portfolio:**
   - "Any support question was a screen takeover, typically for an hour+." (about ADAP; r/sysadmin, u/danfirst, thread 2022‑11‑09, [link](https://www.reddit.com/r/sysadmin/comments/yqvfg2/manageengine_techs_you_high/))
   - "Real nice products but support is horrible and they are crazy with their renewal prices." (ADAP and ADMP; Spiceworks, richlinekid5118, 2019‑03‑04, [link](https://community.spiceworks.com/t/recommended-ad-audit-and-manager-tools/700403))
   - Balance: some users report good support (X7 counterpoint), including "AD Audit seems fairly descent" [sic] (r/sysadmin, u/Bad-Mouse, same thread).
9. **Hardening practice and admin-account concerns.**
   - "A client I work with has ADAudit and ADManager, they are on isolated networks with no external internet access." (r/sysadmin, u/MrGuvernment, thread 2024‑01‑19, [link](https://www.reddit.com/r/sysadmin/comments/19api3h/manageengine_tools_whats_the_catch/))
   - About ADSSP in 2022: "the self service reset web app had an admin account you couldn't disable or add MFA to." (r/ITManagers, u/ycnz, thread 2022‑04‑20, [link](https://www.reddit.com/r/ITManagers/comments/u7xfjx/what_do_we_really_think_of_manageengine/)) `[UNVERIFIED for current builds]`
10. **The licensing model shapes account hygiene.**
    - "so we didn't create named accounts even though that would be safer." (r/sysadmin, u/8poot, 2021‑09‑03, [link](https://www.reddit.com/r/sysadmin/comments/phaalr/thoughts_on_manageengine_admanager_plus_vs_adaxes/)). The context is that ADMP pricing depends on the number of admin accounts.

---

## 4. Security track record 2019–2026

### 4.1 CVE table (selected; complete list and statistics in §4.3)

How to read the table:
- **CVSS:** NVD v3.x base score where NVD has scored the CVE. "CNA" means the score assigned by Zohocorp, ManageEngine's own CVE Numbering Authority ([CVE record example](https://www.cve.org/CVERecord?id=CVE-2026-74849)).
- **Fixed build and date:** from ManageEngine's advisory feed or advisory, unless marked NVD.
- **KEV** status is as of catalog **2026.10.01**.
- **Source:** NVD = `https://nvd.nist.gov/vuln/detail/<CVE>`. ME = ManageEngine advisory.

| CVE | Product(s) | CVSS | Type | Affected → fixed (date) | Exploited? (KEV) | Notes | Source |
|---|---|---|---|---|---|---|---|
| CVE‑2018‑20664 | ADSSP | 9.8 | XXE via uploaded license file | 5.x before 5701 → 5701 (NVD) | No | NVD published 2019‑01‑03 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2018-20664) |
| CVE‑2019‑7161 | ADSSP | 7.5 | Hard-coded encryption keys ("fixed ciphering keys") | 5.x through 5704 (NVD) | No | — | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-7161) |
| CVE‑2019‑12876 | ADMP, ADSSP, Desktop Central | 7.3 | Insecure permissions → SYSTEM | ADMP 6.6.5, ADSSP 5.7 (NVD) | No | Local privilege escalation | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-12876) |
| CVE‑2020‑11518 | ADSSP | 9.8 | Unauthenticated RCE | before 5815 (NVD) | No | — | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-11518) |
| CVE‑2020‑11552 | ADSSP | 9.8 | Privilege escalation from the Windows logon screen (certificate dialog) | before 6003 (NVD) | No | Same component class as CVE‑2026‑74849 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-11552) |
| CVE‑2020‑24786 | AD360, ADSSP, ADAP, ADMP, RMP and others | 9.8 | Unauthenticated `UpdateProductDetails` servlet | AD360 <4228, ADSSP <5817, ADAP <6052, ADMP <7055, RMP <6017 (NVD) | No | NVD: "lead to full ManageEngine suite compromise" | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-24786) |
| CVE‑2021‑28958 / ‑33055 | ADSSP | 9.8 | Unauthenticated RCE (password change; non-English editions) | ≤6101 → 6102 (2021‑03‑20); ≤6102 → 6105 (2021‑05‑26) | No | NVD published 97 and 96 days after the fix | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-28958) |
| CVE‑2021‑37421 / ‑37423 / ‑37424 | ADSSP | 9.8 | Admin-portal access bypass; linked-app takeover; domain-account takeover | ≤6103 / ≤6111 / <6112 → 6112 (2021‑08‑26) | No | — | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-37424) |
| CVE‑2021‑37539, ‑37741, ‑37762 and 14 more | ADMP | 8.8–9.8 | Pre- and post-auth file-upload RCE, SSO signature stripping | ≤7110 → **7111 (2021‑07‑29)** | No | **17 ADMP CVEs fixed in one release** | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-37539) |
| **CVE‑2021‑40539** | **ADSSP** | **9.8** | REST API authentication bypass → RCE | ≤6113 → **6114 (2021‑09‑07)** | **Yes. KEV 2021‑11‑03, ransomware "Known"** | Exploitation "as early as August 2021" (CISA), i.e. before the fix. See §4.2 | [KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-40539), [ME KB](https://www.manageengine.com/products/self-service-password/kb/how-to-fix-authentication-bypass-vulnerability-in-REST-API.html) |
| CVE‑2021‑42002 | ADMP | 9.8 | Filter bypass → file-upload RCE | <7115 → 7115 (2021‑10‑05) | No | — | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-42002) |
| CVE‑2021‑42847 | ADAP | 9.8 | Arbitrary file write and execute | <7006 → 7006 (2021‑10‑23) | No | — | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-42847) |
| Log4Shell (CVE‑2021‑44228) | ADMP, ADAP, RMP and others (ME advisory) | 10.0 (Apache) | Bundled Log4j | ME advisory 2021‑12‑13 | Yes for Log4j itself (KEV 2021‑12‑10) | No evidence found of exploitation via these products | [ME portal](https://www.manageengine.com/security/advisory/) |
| CVE‑2022‑24978 | ADAP | 8.8 | Privilege escalation: password field in a JSON response | <7055 → 7055 (2022‑03‑08) | No | — | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-24978) |
| **CVE‑2022‑28219** | **ADAP** | **9.8** | Unauthenticated XXE + Java deserialization (Cewolf) → RCE, via **unauthenticated agent endpoints** | <7060 → **7060 (2022‑03‑30)** | No | Reported 2022‑03‑28 and patched in 2 days. Horizon3 reports "highly privileged" AD credentials in the product database | [Horizon3](https://www.horizon3.ai/attack-research/disclosures/red-team-blog-cve-2022-28219/) |
| **CVE‑2022‑28810** | **ADSSP** | 6.8 | Admin-authenticated OS command execution ("custom script") | <6122 → 6122 (2022‑04‑09) | **Yes. KEV 2023‑03‑07** | Rapid7 observed abuse in the wild. Rapid7 also documents a default admin password of "admin" | [Rapid7](https://www.rapid7.com/blog/post/2022/04/14/cve-2022-28810-manageengine-adselfservice-plus-authenticated-command-execution-fixed/), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-28810) |
| CVE‑2022‑29457 | ADSSP, ADAP, ADMP, Exchange Reporter | 8.8 | NTLM hash disclosure | ADSSP <6121; ADAP 7060; ADMP 7131 (NVD) | No | — | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-29457) |
| **CVE‑2022‑47966** | **AD360, ADAP, ADMP, ADSSP** + 20 other ME products | **9.8** | Pre-auth RCE through Apache Santuario xmlsec **1.4.1** in SAML handling | AD360 <4310, ADAP <7081, ADMP <7162, ADSSP <6211 → fixed **2022‑10‑28** | **Yes. KEV 2023‑01‑23, ransomware "Known"** | NVD published 2023‑01‑18; Rapid7 saw exploitation from 2023‑01‑17, including ADSSP. Exploitable only "if SAML SSO has ever been configured" (NVD). See §4.2 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-47966), [ME](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html), [Rapid7](https://www.rapid7.com/blog/post/2023/01/19/etr-cve-2022-47966-rapid7-observed-exploitation-of-critical-manageengine-vulnerability/) |
| CVE‑2022‑36413 | ADSSP | 9.1 | OTP brute force → password reset on linked identity-management apps | through 6203 (NVD); fixed 2023‑03‑03 (ME) | No | — | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-36413) |
| CVE‑2023‑35854 | ADSSP | 9.8 (NVD) | Claimed authentication bypass to steal a DC session token | through 6113 (claimed) | No | **Disputed.** Vendor "found no evidence or detail of a security vulnerability." Do not cite without this caveat | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-35854) |
| CVE‑2023‑35785 | AD360, ADAP, ADMP, RMP and others | 8.1 | 2FA bypass with some TOTP authenticators (requires valid password) | AD360 ≤4315, ADAP ≤7202, ADMP ≤7200, RMP ≤6061; fixed 2023‑06‑20 | No | — | [ME](https://www.manageengine.com/security/advisory/CVE/CVE-2023-35785.html) |
| CVE‑2023‑38332 / ‑41904 | ADMP | 6.5 / 5.4 | Account takeover via information disclosure; 2FA bypass for REST API AuthToken | ≤7201 → 7202; <7203 → 7203 (2023) | No | — | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-41904) |
| CVE‑2022‑42904, CVE‑2023‑29084, CVE‑2023‑38743; CVE‑2023‑48646 | ADMP; RMP | 7.2 | Admin command injection (proxy settings and similar) | ADMP → 7160 / 7181 / 7200; RMP → 6070 (2022–23) | No | **Vendor severity "Low"; NVD 7.2** | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-48646) |
| CVE‑2023‑6105 | ADAP, ADMP, ADSSP, RMP, AD360 + ~38 others | 5.5 | Exposed encryption key lets a local user decrypt product database passwords | fixed 2023‑12‑01 (ME) | No | Tenable published (as CNA) on 2023‑11‑15; ME advisory 2024‑06‑26 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-6105) |
| CVE‑2024‑0252 | ADSSP | 8.8 | Authenticated RCE in the load-balancer component | ≤6401 → 6402 (2024‑01‑10) | No | — | [ME](https://www.manageengine.com/products/self-service-password/advisory/CVE-2024-0252.html) |
| CVE‑2023‑48792 … CVE‑2024‑49574 (28 CVEs) | ADAP | 8.8–9.8 (NVD) | SQL injection in reports, dashboards, alerts and exports | various → 7271 … 8123 (2024‑01‑12 to 2024‑11‑08) | No | **28 SQL injection fixes in ADAP in 2024.** The vendor labels most "Authenticated"; NVD scores CVE‑2023‑48792 at 9.8 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-48792) |
| CVE‑2024‑24409 | ADMP | 8.8 | Privilege escalation through "Modify Computers" | ≤7203 → 7210 (2023‑09‑29) | No | Published 2024‑11‑08, **406 days** after the fix | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-24409) |
| CVE‑2024‑21733 (Apache Tomcat) | ADMP, AD360 and others | Vendor: High | Bundled Tomcat information disclosure | fixed 2024‑01‑23 (ME) | No | — | [ME portal](https://www.manageengine.com/security/advisory/) |
| CVE‑2024‑48878 | ADMP | 8.8 | SQL injection in the Archived Audit Report | ≤7241 → 7250 (2024‑10‑04) | No | — | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-48878) |
| CVE‑2025‑1723 | ADSSP | 8.1 CNA | Account takeover via session mishandling (valid account required) | ≤6510 → 6511 (2025‑02‑26) | No | — | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-1723) |
| CVE‑2025‑3834 … CVE‑2025‑41444 (8 CVEs); CVE‑2025‑3833 | ADAP; ADSSP | 8.1–8.3 CNA | Authenticated SQL injection | ADAP ≤8510 → 8511 (2025‑05‑09); ADSSP ≤6513 → 6514 (2025‑04‑22) | No | — | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-3836) |
| CVE‑2025‑10020 | ADMP | 8.8 | Authenticated command injection in Custom Script | ≤8023 → 8024 (2025‑09‑19) | No | — | [ME](https://www.manageengine.com/products/ad-manager/admanager-kb/cve-2025-10020.html) |
| **CVE‑2025‑11250** | **ADSSP** | **9.1 CNA**; vendor "Critical" | Authentication bypass ("improper filter configurations") | ≤6518 → **6519 (2025‑10‑01)** | No | ME advisory 2025‑12‑18; NVD 2026‑01‑13. No technical detail documented in the advisory as of 2026‑10‑02 | [ME](https://www.manageengine.com/products/self-service-password/advisory/CVE-2025-11250.html) |
| CVE‑2025‑11670 | ADMP | 4.3 (NVD) / 6.4 CNA | NTLM hash exposure (technicians with "Impersonate as Admin") | <8025 → 8025 (2025‑10‑13) | No | — | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-11670) |
| CVE‑2026‑1367 | ADSSP | 8.3 CNA | Authenticated SQL injection | ≤6522 → 6523 (2026‑01‑25) | No | — | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-1367) |
| CVE‑2026‑3183 | ADSSP | 7.1 CNA | MFA bypass (attacker needs the user's domain password) | ≤6523 → 6524 (2026‑01‑31) | No | Advisory and NVD 2026‑07‑21, **171 days** after the fix | [ME](https://www.manageengine.com/products/self-service-password/advisory/CVE-2026-3183.html) |
| CVE‑2026‑2740 | ADSSP, RMP, DataSecurity Plus (+ EventLog Analyzer, Log360) | 8.4 CNA | Authenticated RCE on agent machines (vendor: remote agent installation workflow; NVD text cites a third-party dependency) | ADSSP ≤6524 → 6525 (2026‑02‑07); RMP ≤6312 → 6313 (2026‑03‑24) | No | — | [ME](https://www.manageengine.com/products/self-service-password/advisory/CVE-2026-2740.html) |
| **CVE‑2026‑6516** | **ADAP** | **10.0 CNA** | **Unauthenticated RCE** through agent API authentication bypass + path traversal | <8606 → **8606 (2026‑04‑17)** | No | Published 2026‑07‑23, **97 days** after the fix. Windows agents older than 7060 and all Mac agents also need upgrading | [ME](https://www.manageengine.com/products/active-directory-audit/cve-2026-6516.html) |
| **CVE‑2026‑11374** | **ADSSP, RMP, ADAP**, M365 Manager Plus (when deployed in AD360) | **9.0 CNA** | Predictable SSO tickets → unauthenticated account takeover | ADSSP ≤6528 → 6529; RMP ≤6320 → 6321; ADAP ≤8702 → 8703 (2026‑06‑03 to 06‑12) | No | — | [ME](https://www.manageengine.com/products/self-service-password/advisory/CVE-2026-11374.html) |
| **CVE‑2026‑74849** | **ADSSP** (GINA client) | **9.8 CNA** (AV:N); **vendor label "High"** | Code execution as SYSTEM via the Windows logon-screen embedded browser | ≤7000 → **7001 (2026‑08‑24)** | No | Published 2026‑09‑22 | [ME](https://www.manageengine.com/products/self-service-password/advisory/CVE-2026-74849.html), [CVE.org](https://www.cve.org/CVERecord?id=CVE-2026-74849) |
| **CVE‑2026‑75791** | **ADSSP** | **8.6 CNA** | REST API authentication bypass: read config and directory data, change admin settings | ≤7000 → **7001 (2026‑08‑24)** | No | Published 2026‑09‑22 | [ME](https://www.manageengine.com/products/self-service-password/advisory/CVE-2026-75791.html) |

**Not found:** KEV listings or public exploitation reports for any in-scope CVE published after 2023‑03. Exploitation status for the 2025–2026 CVEs is `[UNVERIFIED]` beyond KEV, because web search was unavailable.

### 4.2 Notable campaigns and incidents

| When | What | Products | Evidence |
|---|---|---|---|
| Aug–Oct 2021 | **APT exploitation of CVE‑2021‑40539.** Actors used the Godzilla webshell, NGLite and KdcSponge, stole NTDS.dit, moved laterally over WMI, and targeted 16 critical-infrastructure sectors. CISA advised upgrading to build 6114 and keeping the product off the internet. If NTDS.dit was compromised, it also advised **domain-wide password resets plus a double Kerberos TGT reset** | ADSSP | CISA/FBI/CGCYBER **AA21‑259A**, released 2021‑09‑16 and revised 2021‑11‑22 ([CISA](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-259a)) |
| Sep–Oct 2021 | **Unit 42 campaign** ("TiltedTemple"). At least 9 organizations compromised (technology, defense, healthcare, energy, education); ~370 ManageEngine servers in the US scanned. KdcSponge was injected into LSASS on DCs to harvest credentials. Possible link to TG‑3390/APT27 | ADSSP | Unit 42, 2021‑11‑07 ([link](https://unit42.paloaltonetworks.com/manageengine-godzilla-nglite-kdcsponge/)) |
| From 2021‑09‑22 | **DEV‑0322** (China-based) dumped credentials and deployed custom IIS modules against the defense industrial base, higher education and IT | ADSSP | Microsoft, 2021‑11‑08 ([link](https://www.microsoft.com/en-us/security/blog/2021/11/08/threat-actor-dev-0322-exploiting-zoho-manageengine-adselfservice-plus/)) |
| 2021‑11‑09 compromise; detected 2022‑01‑18 | **ICRC (Red Cross) breach.** Entry was the unpatched CVE‑2021‑40539, about two months after build 6114 shipped. Data on **more than 515,000 people** exposed | ADSSP | ICRC, 2022‑02‑16 ([link](https://www.icrc.org/en/document/cyber-attack-icrc-what-we-know)) |
| April 2022 | **CVE‑2022‑28810 custom-script abuse** using compromised admin credentials | ADSSP | Rapid7 ([link](https://www.rapid7.com/blog/post/2022/04/14/cve-2022-28810-manageengine-adselfservice-plus-authenticated-command-execution-fixed/)) |
| From 2023‑01‑17 | **CVE‑2022‑47966 exploitation** after a public proof of concept: webshells, credential harvesting through Wdigest, coin mining. Rapid7 documented ServiceDesk Plus and ADSSP. ADSSP "requires an attacker to obtain two additional pieces of information" | ADSSP (+ ServiceDesk Plus) | Rapid7 ([link](https://www.rapid7.com/blog/post/2023/01/19/etr-cve-2022-47966-rapid7-observed-exploitation-of-critical-manageengine-vulnerability/)) |
| Early 2023 | **Nation-state actors** used CVE‑2022‑47966 (via ServiceDesk Plus) at an aeronautical-sector organization: Mimikatz, a local admin account named "Azure", lateral movement including to DCs | Cross-product (same CVE affects AD products) | CISA/FBI/CNMF **AA23‑250A**, 2023‑09‑07 ([CISA](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-250a)) |
| 2023 | **Lazarus Group** used CVE‑2022‑47966 against ManageEngine ServiceDesk to hit internet-backbone and healthcare targets in Europe and the US with QuiteRAT. Exploitation began five days after the public proof of concept | Cross-product | Cisco Talos, 2023‑08‑24 ([link](https://blog.talosintelligence.com/lazarus-quiterat/)) |

### 4.3 Patch cadence and advisory practices (computed from ManageEngine's advisory feed, pulled 2026‑10‑02)

**Volume and mix:**
- **104 unique advisories** (by CVE) list at least one in-scope product.
- Fix dates run from 2021‑03 to 2026‑08 (the feed starts in Feb 2022 and back-fills 2021 fixes).
- By primary product: ADAP 44, ADMP 33, ADSSP 22, AD360 2, RMP 1, plus 2 multi-product entries filed under another product (CVE‑2022‑47966, CVE‑2023‑6105).
- Vendor severity: **12 Critical, 72 High**, 8 Medium, 12 Low ([portal](https://www.manageengine.com/security/advisory/)).
- **Bursts:**
  - 17 ADMP CVEs in one release (build 7111, 2021‑07‑29), and 20 ADMP advisories in 2021 overall.
  - **36 SQL injection CVEs in ADAP** fixed across 2024 (28) and 2025 (8). The vendor and NVD describe most of them as authenticated.
  - 6 ADSSP advisories so far in 2026.

**Fix-to-disclosure timing** (fixed-build date to NVD publication, n = 101):
- Median **60 days**, mean 72.
- **69 of 101 (68%) are over 30 days and 30 (30%) are over 90 days**; range −38 to 406 days. The median for fixes from 2024 onward is 59 days.
- From fix to ManageEngine's own advisory posting (advisories posted 2023 onward): median 41 days.
- Examples: CVE‑2026‑6516 (97 days), CVE‑2026‑3183 (171 days), CVE‑2024‑24409 (406 days), CVE‑2025‑11250 (104 days).
- Inference: this ordering gives prompt patchers a head start. Customers who patch on the advisory cycle, or defer service packs because upgrades are laborious (X3), can run affected builds before any advisory exists.

**Researcher reports and the bug bounty:**
- **2-day turnaround** on CVE‑2022‑28219 ([Horizon3](https://www.horizon3.ai/attack-research/disclosures/red-team-blog-cve-2022-28219/)).
- Most 2025–26 findings credit the **Zoho BugBounty program** (e.g., the advisories for [CVE‑2026‑74849](https://www.manageengine.com/products/self-service-password/advisory/CVE-2026-74849.html), [CVE‑2026‑3183](https://www.manageengine.com/products/self-service-password/advisory/CVE-2026-3183.html) and [CVE‑2025‑10020](https://www.manageengine.com/products/ad-manager/admanager-kb/cve-2025-10020.html)).
- Zoho is its own CNA.
- Some of the CVE volume reflects active bug-hunting and transparency (inference).

**Severity labels differ between sources:**
- CVE‑2026‑74849: Zoho's own CVE record says **CVSS 9.8 (AV:N/PR:N)**, while the advisory page says "High".
- Several admin-only RCEs are labeled "Low" by the vendor but scored 7.2 by NVD.

**Advisory content varies.** The CVE‑2025‑11250 advisory (vendor "Critical") documents no technical detail or compromise indicators as of 2026‑10‑02 ([ME](https://www.manageengine.com/products/self-service-password/advisory/CVE-2025-11250.html)).

**Third-party components were the root cause of several advisories:**
- Apache Santuario 1.4.1 (CVE‑2022‑47966).
- Log4j (2021).
- Tomcat CVE‑2024‑21733.
- Cewolf (CVE‑2022‑28219).

**Recurring components:**
- Unauthenticated **agent** endpoints: CVE‑2022‑28219 and CVE‑2026‑6516.
- The **logon-screen client**: CVE‑2020‑11552 and CVE‑2026‑74849.
- **SSO/SAML and MFA logic**: CVE‑2022‑47966, CVE‑2023‑35785, CVE‑2026‑3183 and CVE‑2026‑11374.
- **REST API authentication**: CVE‑2021‑40539 and CVE‑2026‑75791.
- **Report queries**: the ADAP SQL injection cluster.

### 4.4 What this means for a buyer of a Tier‑0 tool

- **These tools hold Tier‑0 credentials.**
  - They operate with privileged AD service accounts and talk to DCs.
  - Horizon3 found "highly privileged" AD credentials in ADAP's database ([link](https://www.horizon3.ai/attack-research/disclosures/red-team-blog-cve-2022-28219/)).
  - CISA's remediation guidance for ADSSP compromise included **domain-wide password resets and a double krbtgt reset** ([AA21‑259A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-259a)).
  - Inference: a compromise of the tool should be scoped as an AD incident, not a single-server incident.
- **SSPR is often deployed internet-facing.** "We published the application over the Internet and our customers around the globe use it" (Capterra, Sayed Munir N., Engineer, ADSSP, 2018‑04‑19, [link](https://www.capterra.com/p/172556/ADSelfService-Plus/reviews/)). CISA advised against direct internet exposure in 2021. Endpoint logon agents and audit agents are separate components with their own 2026 advisories (§4.1).
- **Exposure windows come from three things at once:** exploitation before a fix existed (CVE‑2021‑40539), patch latency on the customer side (the ICRC breach was about two months after the fix), and fix-to-disclosure timing (§4.3). Upgrade effort (X3) makes all three worse (inference).
- **Any vendor in this category, including us, will be asked for:**
  - an SBOM and dependency-patch SLAs
  - same-day advisories with CVSS that matches the CNA record
  - automatic, signed updates
  - no default credentials
  - enforced admin MFA
  - a minimal unauthenticated surface for agents and SSPR
  - a reference deployment that keeps the tool off the internet
  - independent pentest attestation

---

## 5. Switching drivers & barriers

### 5.1 Why customers leave or look

| Driver | Evidence |
|---|---|
| **Security news reaches leadership** | Boss "has seen several security notifications for ManageEngine products" and tasked staff with finding alternatives ([Spiceworks, bezoid, 2021‑12‑03](https://community.spiceworks.com/t/manageengine-ad360-adaudit-plus-admanager-plus-alternatives/818714)). "They had some pretty bad press last year when a load of their on-prem products had vulnerabilities discovered" ([r/sysadmin, deleted user, thread 2024‑01‑19](https://www.reddit.com/r/sysadmin/comments/19api3h/manageengine_tools_whats_the_catch/)) |
| **Usability and UI** (X1, X4) | "unhappy with it for cost and usability issues" ([r/msp, u/etherealfocus, 2022‑09‑21](https://www.reddit.com/r/msp/comments/xjx6wg/experiences_with_admanager_plus_alternatives/)). A former AD360 user: "The main drawback back when we used it was that the user interface felt a bit dated and clunky at times." (Capterra, Drew L., SR SYS Admin, 2026‑07‑30, [link](https://www.capterra.com/p/268487/ManageEngine-AD360/reviews/)) |
| **Upgrade effort and failed upgrades** (X3) | Restores from backup after failed upgrades; modules updated one by one (§2.2) |
| **Support experience** (X7) | "Real nice products but support is horrible and they are crazy with their renewal prices." ([Spiceworks, richlinekid5118, 2019‑03‑04](https://community.spiceworks.com/t/recommended-ad-audit-and-manager-tools/700403)) |
| **Renewal cost and licensing complexity** (X8) | Same poster: "when it came to renewing support for the year they wanted $4195 & $4500 which we can no longer afford." Customer-reported 2019 figures for ADAP and ADMP, not list prices. Also: "the product also goes into “free-mode” with incredible limitations." ([Spiceworks, 2019‑03‑04](https://community.spiceworks.com/t/recommended-ad-audit-and-manager-tools/700403)) |
| **Depth gaps** (lockout forensics, real-time admin-change alerts, custom reports) | "doesn't really give me enough information on account lock outs or login attempts" ([Spiceworks, jgpjgp, 2022‑01‑14](https://community.spiceworks.com/t/alternative-to-ad-audit-plus-netwrix/822065)). Capterra ADAP reviewer wants "an immediate report of changes to Ad admin" (Pete E., Head of IT Services, 2025‑02‑18, [link](https://www.capterra.com/p/210774/ADAudit-Plus/reviews/)) |
| **Hybrid/cloud coverage needs more SKUs** (X5) | "cloud requires another product" ([Capterra, Vladimir B., 2026‑06‑22](https://www.capterra.com/p/143496/ADManager-Plus/reviews/)) |

**Destinations named:** Netwrix (most often), Lepide, Adaxes, Quest Active Roles, EventSentry, native tools plus a SIEM (§3.1).

### 5.2 What keeps them (barriers)

| Barrier | Evidence / implication |
|---|---|
| **Price gap** | Alternatives are "two to three times at least more expensive" ([r/sysadmin, u/Soggy-Camera1270, 2022](https://www.reddit.com/r/sysadmin/comments/yqvfg2/manageengine_techs_you_high/)). One 2018 customer comparison put Adaxes at "$10,000 the first year" against "under $1000" for ADMP ([Spiceworks, bryantetlow](https://community.spiceworks.com/t/alternative-to-admanager-plus/664883)); customer-reported figures, not list prices. **We cannot win as the cheapest option; we have to win on total cost** (upgrade labor, incidents, extra SKUs) |
| **Compliance reports and auditor familiarity** | SOX, HIPAA, GDPR and ISO reports are run monthly (§2.1). In a 2025 Netwrix thread, the poster said management "wants reports that cant be manipulated for auditing" ([Spiceworks, Nics1960](https://community.spiceworks.com/t/netwrix-alternative/1180156)). That pushes buyers away from DIY scripts and raises the bar for us |
| **Sunk configuration** | Templates, OU rules, workflows, technician roles and automations. "We use templates to create/delete users, which make the process fairly simple." ([r/sysadmin, u/8poot, 2021](https://www.reddit.com/r/sysadmin/comments/phaalr/thoughts_on_manageengine_admanager_plus_vs_adaxes/)). Tools are often inherited (§3.2 #5) |
| **Audit-history retention** | Years of ADAP data back investigations and legal holds. One admin had "Legal approved" a purge of inherited data; the replies suggested keeping the old VM for access ([r/sysadmin, u/saltwaffles, 2023‑03‑04](https://www.reddit.com/r/sysadmin/comments/11ho8xn/adaudit_plus_erase_database/)) |
| **End-user enrollment (ADSSP)** | MFA and SSPR enrollment drives take effort (X6). Re-enrolling an entire workforce is a major cost. Logon-screen agents must be redeployed on every endpoint |
| **Suite and ecosystem ties** | ServiceDesk Plus, Endpoint Central and Log360 integrations; AD360 bundles. Reviewers list several ManageEngine products in use ([TrustRadius](https://web.archive.org/web/20260722164719/https://www.trustradius.com/products/manageengine-admanager-plus/reviews)) |
| **Retraining and change risk on Tier‑0** | Teams know the current tool's behavior; a migration touches privileged workflows and service accounts |

### 5.3 What a migration must preserve (requirements for activeDIQ)

| Area | Must preserve or import | Notes |
|---|---|---|
| ADMP provisioning | User-creation templates (attribute rules, naming formats, OU placement, group and license assignment), bulk CSV import formats, HR-driven automations (Workday, BambooHR and SAP HCM come up in reviews) | Reviewers name HR-connector gaps (SAP HCM; BambooHR mapping) on [PeerSpot](https://www.peerspot.com/products/manageengine-admanager-plus-reviews) and [Spiceworks](https://community.spiceworks.com/t/ad-management-tools/1248976) |
| Delegation | Technician and helpdesk roles scoped by OU or object type; approval workflows and approvers | Per-technician pricing means some customers share admin accounts (§3.2 #10), so plan an identity cleanup during migration |
| Automation and scripts | Scheduled automations; custom scripts, re-implemented in a sandboxed form (ADMP's Custom Script component had CVE‑2025‑10020) | — |
| Reports | Scheduled reports, recipients and formats; custom report definitions; compliance report packs | Need side-by-side report parity so auditors see no change |
| ADAP history | Years of audit events, alert profiles and thresholds, file-server audit scope, archived logs | Offer a read-only import or legacy-archive viewer so the old server can be retired |
| ADSSP enrollment | Security Q&A, verified phone and email, authenticator/TOTP, push enrollments; per-group MFA and password policies; password-expiry notifications; synced cloud apps; SSO (SAML) apps | Whether ADSSP can export enrollment or TOTP data is `[UNVERIFIED]`. Plan for low-friction re-enrollment if it can't |
| Endpoint | Windows, macOS and Linux logon-screen agents; VPN cached-credential update | Coexistence period needed |
| RMP | Backup snapshots and retention, restore points for AD, Entra, M365 and Exchange | RMP has thin customer-review evidence `[TODO]` |
| AD360 | Single sign-on across modules and unified roles | Reviewers report differing logins between modules today (X5) |

### 5.4 Procurement realities

- **Licensing units differ by product:**
  - **ADAP:** priced by DCs, file servers and Windows servers monitored ([r/sysadmin 2024](https://www.reddit.com/r/sysadmin/comments/1bpdgya/adaudit_plus_from_manageengine_options_pricing/)).
  - **ADMP:** priced by domains and technicians. A ManageEngine rep in 2019 said "pricing is based on the number of servers for AD auditing and number of domains for AD management" ([Spiceworks, vidya-zoho, 2019‑03‑13](https://community.spiceworks.com/t/recommended-ad-audit-and-manager-tools/700403)).
  - **ADSSP:** priced by users, with a free tier for very small user counts (under 50 per a 2022 [PeerSpot](https://www.peerspot.com/products/manageengine-adselfservice-plus-reviews) review; current threshold `[UNVERIFIED]`).
  - Current list prices, editions and units belong in the sibling product files and `manageengine-ad360-suite-and-commercials.md` `[TODO cross-link]`.
- **Commercial terms:** both subscription and perpetual plus maintenance appear in reviews. Purchases go through resellers or direct; one reseller said flat pricing means no charity discount ([r/sysadmin 2024](https://www.reddit.com/r/sysadmin/comments/1bpdgya/adaudit_plus_from_manageengine_options_pricing/)).
- **Renewal moments are the switching window** (inference from §5.1 renewal posts).
- **Enterprise buyers will run a security review of us.** Expect questionnaires that reference this category's KEV history; see §6 proof points.

---

## 6. Implications for activeDIQ positioning

### 6.1 Strongest wedges (ranked by evidence × our ability to prove)

1. **Upgrades that just happen.** Automatic, signed, zero-downtime updates for every component, with rollback.
   - Hits X3 (≈16 mentions), X10 (updates affecting AD) and the exposure-window risk in §4.4.
   - Easy to demo.
2. **Security you can verify for a Tier‑0 tool.** Positioned as *our* architecture and evidence (6.2), never as statements about ManageEngine.
   - The category's KEV history gives buyers a reason to ask; we have to answer with proof.
3. **One console for hybrid AD and Entra ID** (manage, audit, self-service and recovery), with one login, one role model and one update.
   - Hits X1 (≈28), X5 (≈11) and the AD360 separate-login and separate-update reports.
4. **A report builder that auditors and admins both like.** Canned-report parity plus a flexible builder, bulk sharing, scheduling UX and interactive charts. Hits X2 (≈17).
5. **Low-noise auditing.** Tunable, deduplicated alerts and storage-efficient retention with tiering (X11, X9).
6. **Licensing that rewards account hygiene.** No per-technician cost that pushes teams to share admin accounts (§3.2 #10); transparent bundles (X8).
7. **Migration in a box.** Importers for templates, roles, workflows, scheduled reports and the ADAP archive; a dual-run period; guided ADSSP re-enrollment (§5.3).

**Don't fight on:**
- **Sticker price.** Their price is the #1 praise.
- **Star ratings.** They are uniformly high.
- **Canned-report count.** Hundreds of reports is a strength we must match.

### 6.2 Proof points we will need (evidence, not adjectives)

| Claim we want to make | Evidence required |
|---|---|
| Secure by design for Tier‑0 | Independent pentest report (summary shareable under NDA); SOC 2 Type II and/or ISO 27001; published threat model; no unauthenticated endpoints on agents or the SSPR edge; enforced MFA on admin; no default credentials; least-privilege service accounts (gMSA, scoped delegation); secrets vaulted |
| Transparent disclosure | Public vulnerability disclosure policy and bug bounty; CVE/CNA process; **advisory published the same day as the fix**, with CVSS consistent across advisory and CVE record; security changelog |
| Current dependencies | SBOM per release; dependency SLA (e.g., critical within N days); automated SCA in CI |
| Effortless upgrades | Measured median upgrade time; % of customers on the latest build; rollback demo; signed-update verification |
| Faster to use | Task-time benchmarks against ADMP for 10 common tasks (bulk create, delegate, report, unlock), from customer pilots |
| Safe migration | Import fidelity report (templates, roles, reports); audit-archive import; reference customers |

### 6.3 Messaging do's and don'ts (per competitive-intel §4)

**Do:**
- State facts with ID, date and source, e.g. CISA's KEV catalog (version 2026.10.01) lists CVE‑2021‑40539, CVE‑2022‑28810 and CVE‑2022‑47966 for these products.
- Frame comparisons as **category risk**: AD management tools are Tier‑0, so here are the questions to ask every vendor. Then answer them for activeDIQ first.
- Use customer quotes only internally, attributed and dated, noting when a review was vendor-solicited.
- Acknowledge strengths: price, report breadth, a 2-day fix turnaround on CVE‑2022‑28219, and an active bug bounty.

**Don't:**
- Use adjectives about ManageEngine in anything external. "Clunky" and "outdated" stay inside attributed quotes in this file.
- Characterize CVEs. No "insecure", no "hacked". For the ICRC case, cite ICRC's own statement (an unpatched CVE) and nothing more.
- Compare raw CVE counts. Volume partly reflects ManageEngine's bug bounty and CNA transparency, and our own count will not be zero.
- Cite disputed or unscored items (e.g., CVE‑2023‑35854) or claims marked `[UNVERIFIED]`.
- Repeat community remarks about support staff location or nationality.
- Use superlatives ("fastest", "most secure") without a benchmark we can produce on request.
- Make roadmap claims as if shipped ("available in vX" or "planned" only).
- Let any datasheet, RFP answer or partner battlecard out without CEO approval (`ceo-decisions`, category 6).

---

## Open gaps / TODO

- `[TODO]` Gartner Peer Insights review text and ratings for ADAP, ADSSP and RMP. Live pages return 403 and snapshots are blocked; try an authenticated browser session or the Gartner API.
- `[TODO]` Live (non-archived) G2 and TrustRadius numbers. ADMP's G2 own-page review text exists only in a 2024 snapshot.
- `[TODO]` Customer voice on RMP and AD360. Very few reviews anywhere; consider direct customer interviews through the CEO's warm accounts.
- `[TODO]` Specops, Semperis and Quest Recovery Manager mentions in community threads. Not found in this sample; Reddit search was blocked.
- `[UNVERIFIED]` Exploitation status of the 2025–2026 CVEs beyond KEV (no web search available). Re-check vendor threat intel (Rapid7, Horizon3, watchTowr, Shadowserver) once search is restored.
- `[UNVERIFIED]` Whether ADSSP can export enrollment or TOTP data; current free-tier thresholds; current ADSSP default admin credential behavior.
- `[TODO]` Cross-link to the sibling product benchmarks (`manageengine-{admanager-plus,adaudit-plus,adselfservice-plus}.md`, `manageengine-ad360-suite-and-commercials.md`) and map pain themes to feature IDs (`ADM-`/`ADA-`/`ADSS-`) once those inventories exist.

## Changelog

- **2026‑10‑02:** First full draft. All sections (§1–§6) researched and sources checked on 2026‑10‑02:
  - **Security data:** CISA KEV catalog 2026.10.01, NVD API, CVE.org, and ManageEngine's advisory feed (104 in-scope advisories).
  - **Reviews:** PeerSpot and Capterra live; G2, TrustRadius and Gartner via Wayback snapshots dated as shown.
  - **Community:** Spiceworks live; Reddit via Wayback snapshots.
  - **Limits:** the WebSearch budget ran out during the session, so there are no `[snippet]` claims, and some gaps remain (see above).
